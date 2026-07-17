"""Final merge pass: combine all SARIF + LLM findings into output files.

Produces:
  - security-report.sarif (SARIF 2.1.0 with CWE taxonomy)
  - security-report.md (human-readable summary)
  - triage.json (audit log)
"""
from __future__ import annotations

import copy
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import structlog

from security_review import __version__
from security_review.fingerprint import fingerprint_finding
from security_review.fsio import atomic_write_json
from security_review.models.degradation import Degradation
from security_review.models.findings import Severity
from security_review.models.report import SecurityReport
from security_review.passes.state import PipelineState
from security_review.priority import build_exposure_index, score_finding
from security_review.reporting.common import extract_report_data
from security_review.reporting.dispatcher import write_reports
from security_review.sarif.loader import get_result_location
from security_review.sarif.merger import merge_sarif
from security_review.sarif.tags import extract_cwe_ids_from_sarif, normalise_cwe_tags
from security_review.sarif.taxonomy import inject_taxonomy

logger = structlog.get_logger()


def fingerprint_and_track_findings(
    state: PipelineState, all_results: list[dict], rule_cwe_map: dict[str, str],
) -> None:
    """Record each finding's fingerprint in .scar/graph.db for cross-run tracking.

    Optional and best-effort, mirroring _build_call_graph_if_available in
    pipeline.py: a failure here (e.g. an unwritable target directory) must
    never break report generation, so any exception is logged and swallowed.
    """
    try:
        from code_analysis.store import GraphStore, init_target_gitignore

        init_target_gitignore(state.target_path)
        with GraphStore(state.target_path / ".scar" / "graph.db") as store:
            store.start_run(state.run_id, str(state.target_path), __version__)
            new_count = 0
            for result in all_results:
                cwe_id = rule_cwe_map.get(result.get("ruleId", ""), "")
                locations = result.get("locations", [])
                if not locations:
                    continue
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                message = result.get("message", {}).get("text", "")

                fp = fingerprint_finding(cwe_id, "", file_path, message)
                status = store.record_finding(
                    fp, state.run_id, cwe_id, result.get("level", "warning"),
                    file_path, line, message, confidence=1.0,
                )
                if status == "new":
                    new_count += 1
            store.finish_run(state.run_id)
            store.commit()
        logger.info("merge.findings_tracked", total=len(all_results), new=new_count)
    except Exception as e:
        logger.warning("merge.finding_tracking_failed", error=str(e))


def write_artifacts(state: PipelineState) -> Path:
    """Produce final output files (SARIF, reports, triage.json) synchronously.

    Extracted from run_merge so the CLI's salvage handlers can call this
    directly outside the event loop after an aborted run — write_artifacts
    itself makes no LLM/network calls, so there is nothing to await.
    """

    _MERGE_PASS_NUMBER = {"full": 7, "sast-triage": 4, "sast": 3}
    merge_pass_number = _MERGE_PASS_NUMBER.get(state.config.review.mode, 7)
    logger.info("pipeline.pass_started", pass_number=merge_pass_number, pass_name="merge")

    output_dir = state.work_dir
    sarif_path = output_dir / state.config.review.output_sarif
    triage_path = output_dir / state.config.review.output_triage
    summary_path = output_dir / state.config.review.output_summary

    # Ensure output directories exist
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    triage_path.parent.mkdir(parents=True, exist_ok=True)

    # Start with SAST SARIF
    base_sarif = state.sast_sarif or {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "security-review", "rules": []}}, "results": []}]}

    # Add invocation metadata so the SARIF is self-describing
    base_sarif["runs"][0].setdefault("invocations", [])
    base_sarif["runs"][0]["invocations"].append({
        "executionSuccessful": not state.degradations,
        "commandLine": f"scar review --mode {state.config.review.mode} --target {state.target_path}",
        "properties": {
            "run_id": state.run_id,
            "target": str(state.target_path),
            "mode": state.config.review.mode,
            "provider": state.config.llm.provider_model,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scar_version": __version__,
            "degradations": [d.model_dump() for d in state.degradations],
        },
    })

    # Add holistic + config-review findings, deduplicating against SAST.
    dropped_no_cwe = _merge_llm_findings(base_sarif, state)

    if dropped_no_cwe:
        state.degrade(Degradation(
            pass_name="merge", kind="parse_failed", subject="cwe_id",
            detail=f"{dropped_no_cwe} LLM finding(s) had no parseable CWE ID and were "
                   f"dropped from the report (AGENTS.md rule 5)",
            count=dropped_no_cwe,
        ))

    # Normalise CWE tags on all rules
    for run in base_sarif.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            normalise_cwe_tags(rule)

    # Inject CWE taxonomy
    cwe_ids = extract_cwe_ids_from_sarif(base_sarif)
    if cwe_ids:
        try:
            inject_taxonomy(base_sarif, cwe_ids)
        except Exception as e:
            logger.error("merge.taxonomy_failed", error=str(e), error_type=type(e).__name__)
            state.degrade(Degradation(
                pass_name="merge", kind="taxonomy_failed", subject="sarif",
                detail="CWE taxonomy injection failed — SARIF taxonomies block is missing",
            ))

    # Final scoring: Severity x Confidence x Exposure — overwrites the temporary
    # pre-scores that sast.py set for triage filtering. Triage verdicts are now
    # available in SARIF properties, so confidence scores are accurate here.
    exposure_index = build_exposure_index(state.manifest)
    _score_all_findings(base_sarif, state, exposure_index)

    # Write SARIF
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(base_sarif, f, indent=2)

    # Collect all results for summary and audit log
    all_results = []
    rule_cwe_map: dict[str, str] = {}
    for run in base_sarif.get("runs", []):
        all_results.extend(run.get("results", []))
        # Build rule-id → CWE lookup from rule definitions
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            for tag in rule.get("properties", {}).get("tags", []):
                if tag.startswith("external/cwe/cwe-"):
                    num = tag.split("-")[-1].lstrip("0") or "0"
                    rule_cwe_map[rule["id"]] = f"CWE-{num}"
                    break

    # Cross-run finding tracking (optional, best-effort — see fingerprint_and_track_findings).
    fingerprint_and_track_findings(state, all_results, rule_cwe_map)

    # Write reports — triage counts derived from SARIF properties (single source of truth)
    error_summaries = [
        f"{e.pass_name}: {e.error_type}: {e.error}" for e in state.errors
    ]
    report_data = extract_report_data(
        all_results,
        rule_cwe_map=rule_cwe_map,
        run_id=state.run_id,
        target=str(state.target_path),
        mode=state.config.review.mode,
        provider=state.config.llm.provider_model,
        cost_usd=state.cost_tracker.total_spent,
        errors=error_summaries,
    )

    # Attach coverage data from inventory
    report_data.coverage = state.coverage
    report_data.degradations = list(state.degradations)

    # Store report_data on state so CLI can access it for terminal output
    state.report_data = report_data

    # Write configured report formats. "summary" honours the configured/CLI
    # filename (config.review.output_summary, resolved against work_dir like
    # sarif_path/triage_path above); other formats use fixed names so
    # multiple formats never overwrite each other's file.
    report_formats = state.report_formats
    write_reports(
        report_data, report_formats, sarif_path.parent,
        summary_path=summary_path,
    )

    # Write triage audit log
    triage_data = {
        "run_id": state.run_id,
        "target": str(state.target_path),
        "mode": state.config.review.mode,
        "total_findings": len(all_results),
        "cost": state.cost_tracker.to_audit_log(),
        "evidence": state.evidence.to_dict(),
        "scar_version": __version__,
        "degradations": [d.model_dump() for d in state.degradations],
        "pass_failures": [
            {"pass": e.pass_name, "error_type": e.error_type, "error": e.error, "fatal": e.fatal}
            for e in state.errors
        ],
    }
    if state.triage_result:
        triage_data["triage"] = state.triage_result.model_dump()
    if state.file_selection_telemetry:
        triage_data["file_selection"] = [t.__dict__ for t in state.file_selection_telemetry]

    with open(triage_path, "w", encoding="utf-8") as f:
        json.dump(triage_data, f, indent=2)

    logger.info(
        "pipeline.pass_completed",
        pass_number=merge_pass_number,
        finding_count=len(all_results),
        sarif_path=str(sarif_path),
        pass_failures=len(state.errors),
    )

    return sarif_path


async def run_merge(state: PipelineState) -> Path:
    """Execute merge pass: produce final output files, then clean up run tmp.

    Thin async wrapper around write_artifacts (sync) — kept so pipeline.py's
    pass orchestration (which awaits every pass) does not need a special case
    for merge specifically. Tmp cleanup happens here, NOT in write_artifacts,
    because _salvage() calls write_artifacts directly after an abort and must
    keep var/tmp/<run_id>/ for forensics — only a clean run deletes it.
    """
    path = write_artifacts(state)
    tmp_dir = state.work_dir / "var" / "tmp" / state.run_id
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return path


def _merge_llm_findings(base_sarif: dict, state: PipelineState) -> int:
    """Append holistic + config-review findings to base_sarif, deduplicated.

    Shared by write_artifacts (final merge) and write_partial_sarif
    (--stream). Returns the count of findings dropped for a missing CWE —
    the caller decides whether to record the degradation (the final merge
    does; the streaming path must not double-record).

    Two separate dedup sets with distinct purposes:

    sast_locations — (file, line) pairs from SAST results. Only populated for
      line-level findings (line > 0). Used to suppress LLM findings that
      duplicate a specific SAST location.

    llm_keys — (rule_id, file, line) for already-added LLM findings. Includes
      rule_id so two different file-level findings (line=None → 0) in the same
      file are not incorrectly treated as duplicates of each other.
    """
    target_root = str(state.target_path.resolve())
    sast_locations: set[tuple[str, int]] = set()
    for result in base_sarif["runs"][0].get("results", []):
        uri, line = get_result_location(result, target_root=target_root)
        if uri and line:
            sast_locations.add((uri, line))

    llm_keys: set[tuple[str, str, int]] = set()
    dropped_no_cwe = 0

    llm_findings = []
    if state.holistic_result:
        llm_findings += state.holistic_result.findings
    if state.config_review_result:
        llm_findings += state.config_review_result.findings

    for finding in llm_findings:
        if not finding.cwe_id:
            logger.warning("merge.finding_dropped_no_cwe",
                           rule_id=finding.rule_id, file_path=finding.file_path)
            dropped_no_cwe += 1
            continue
        if finding.line_number and (finding.file_path, finding.line_number) in sast_locations:
            continue
        llm_key = (finding.rule_id, finding.file_path, finding.line_number or 0)
        if llm_key in llm_keys:
            continue
        base_sarif["runs"][0]["results"].append(_finding_to_sarif_result(finding))
        _ensure_rule(base_sarif, finding.rule_id, finding.title, finding.cwe_id)
        llm_keys.add(llm_key)

    return dropped_no_cwe


def write_partial_sarif(state: PipelineState) -> Path:
    """Write the current merged view to security-report.partial.sarif (--stream).

    Called after each LLM pass so a killed run still has a readable partial
    report. Works on a deep copy — repeated calls never mutate live state —
    and reuses the final merge's conversion/dedup/scoring helpers. Records
    no degradations (the final merge records those once).
    """
    base = copy.deepcopy(state.sast_sarif) if state.sast_sarif else {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "security-review", "rules": []}}, "results": []}],
    }

    _merge_llm_findings(base, state)

    for run in base.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            normalise_cwe_tags(rule)

    cwe_ids = extract_cwe_ids_from_sarif(base)
    if cwe_ids:
        try:
            inject_taxonomy(base, cwe_ids)
        except Exception as e:
            logger.warning("stream.taxonomy_failed", error=str(e), error_type=type(e).__name__)

    exposure_index = build_exposure_index(state.manifest)
    _score_all_findings(base, state, exposure_index)

    path = state.output_dir / "security-report.partial.sarif"
    atomic_write_json(path, base)
    logger.info("stream.partial_written", path=str(path),
                results=sum(len(r.get("results", [])) for r in base.get("runs", [])))
    return path


def _finding_to_sarif_result(finding) -> dict:
    """Convert an LLM finding to a SARIF result."""
    level = _severity_to_level(finding.severity)
    result = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": f"{finding.title}: {finding.description}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_number or 1},
                }
            }
        ],
    }

    # Add CWE tag
    if finding.cwe_id:
        cwe_num = finding.cwe_id.replace("CWE-", "")
        result["properties"] = {
            "tags": [f"external/cwe/cwe-{int(cwe_num):03d}", "security"],
        }

    # Propagate the Pass 6 verification verdict so _score_all_findings uses
    # it instead of the CONFIRMED default. Refuted findings stay in the
    # SARIF (scored low) — never dropped (plan 020 §1.7).
    verdict = getattr(finding, "triage_verdict", None)
    if verdict:
        result.setdefault("properties", {})["triage_verdict"] = verdict

    # Add end line for holistic findings
    if hasattr(finding, "end_line") and finding.end_line:
        result["locations"][0]["physicalLocation"]["region"]["endLine"] = finding.end_line

    return result


def _ensure_rule(sarif: dict, rule_id: str, title: str, cwe_id: str | None) -> None:
    """Add a rule entry if it doesn't exist."""
    rules = sarif["runs"][0]["tool"]["driver"].setdefault("rules", [])
    existing_ids = {r["id"] for r in rules}
    if rule_id not in existing_ids:
        rule = {
            "id": rule_id,
            "shortDescription": {"text": title},
            "properties": {"tags": ["security"]},
        }
        if cwe_id:
            cwe_num = cwe_id.replace("CWE-", "")
            rule["properties"]["tags"].append(f"external/cwe/cwe-{int(cwe_num):03d}")
        rules.append(rule)


def _severity_to_level(severity) -> str:
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFORMATIONAL: "note",
    }
    return mapping.get(severity, "warning")


def _score_all_findings(sarif: dict, state, exposure_index: dict[str, float]) -> None:
    """Compute priority score for every finding and add to SARIF properties.

    Priority = Severity x Confidence x Exposure (0.0-1.0).
    Each component is stored in properties for transparency.

    Triage verdicts are read from properties.triage_verdict, which the
    triage pass writes directly onto each SARIF finding. No lookup needed.
    """
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "warning")

            # Extract file path from location
            locations = result.get("locations", [])
            file_path = ""
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")

            # Determine detection method and triage verdict
            rule_id = result.get("ruleId", "")
            is_llm_finding = rule_id.startswith("SR-")
            detection = "llm_only" if is_llm_finding else "sast_only"
            verdict = result.get("properties", {}).get("triage_verdict")

            # A verdict-less LLM finding defaults to CONFIRMED only when
            # verification did NOT run. When Pass 6 is enabled, a finding it
            # couldn't adjudicate must never silently promote to CONFIRMED
            # (plan 020 §1.5.2/§1.7) — belt-and-braces net for §1.5.2's
            # explicit NEEDS_CONTEXT stamps.
            if is_llm_finding and not verdict:
                verdict = "CONFIRMED" if not state.config.verification.enabled else "NEEDS_CONTEXT"
                result.setdefault("properties", {})["triage_verdict"] = verdict

            score = score_finding(
                level=level,
                file_path=file_path,
                exposure_index=exposure_index,
                triage_verdict=verdict,
                detection_method=detection,
            )

            # Update priority in SARIF properties
            props = result.setdefault("properties", {})
            props["priority"] = score.priority
            props["priority_band"] = score.band
            props["priority_components"] = {
                "severity": score.severity_score,
                "confidence": score.confidence_score,
                "confidence_label": score.confidence_label,
                "exposure": score.exposure_score,
            }


