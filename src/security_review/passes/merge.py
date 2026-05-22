"""Final merge pass: combine all SARIF + LLM findings into output files.

Produces:
  - security-report.sarif (SARIF 2.1.0 with CWE taxonomy)
  - security-report.md (human-readable summary)
  - triage.json (audit log)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog

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


async def run_merge(state: PipelineState) -> Path:
    """Execute merge pass: produce final output files."""

    _MERGE_PASS_NUMBER = {"full": 6, "sast-triage": 4, "sast": 3}
    merge_pass_number = _MERGE_PASS_NUMBER.get(state.config.review.mode, 6)
    logger.info("pipeline.pass_started", pass_number=merge_pass_number, pass_name="merge")

    output_dir = state.work_dir
    sarif_path = output_dir / state.config.review.output_sarif
    summary_path = output_dir / state.config.review.output_summary
    triage_path = output_dir / state.config.review.output_triage

    # Ensure output directories exist
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    triage_path.parent.mkdir(parents=True, exist_ok=True)

    # Start with SAST SARIF
    base_sarif = state.sast_sarif or {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "security-review", "rules": []}}, "results": []}]}

    # Add invocation metadata so the SARIF is self-describing
    base_sarif["runs"][0].setdefault("invocations", [])
    base_sarif["runs"][0]["invocations"].append({
        "executionSuccessful": True,
        "commandLine": f"security-review --mode {state.config.review.mode} --target {state.target_path}",
        "properties": {
            "run_id": state.run_id,
            "target": str(state.target_path),
            "mode": state.config.review.mode,
            "provider": state.config.llm.provider_model,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    })

    # Two separate dedup sets with distinct purposes:
    #
    # sast_locations — (file, line) pairs from SAST results. Only populated for
    #   line-level findings (line > 0). Used to suppress LLM findings that
    #   duplicate a specific SAST location.
    #
    # llm_keys — (rule_id, file, line) for already-added LLM findings. Includes
    #   rule_id so two different file-level findings (line=None → 0) in the same
    #   file are not incorrectly treated as duplicates of each other.
    target_root = str(state.target_path.resolve())
    sast_locations: set[tuple[str, int]] = set()
    for result in base_sarif["runs"][0].get("results", []):
        uri, line = get_result_location(result, target_root=target_root)
        if uri and line:
            sast_locations.add((uri, line))

    llm_keys: set[tuple[str, str, int]] = set()

    # Add holistic findings, deduplicating against SAST
    if state.holistic_result:
        for finding in state.holistic_result.findings:
            if finding.line_number and (finding.file_path, finding.line_number) in sast_locations:
                continue
            llm_key = (finding.rule_id, finding.file_path, finding.line_number or 0)
            if llm_key in llm_keys:
                continue
            base_sarif["runs"][0]["results"].append(_finding_to_sarif_result(finding))
            _ensure_rule(base_sarif, finding.rule_id, finding.title, finding.cwe_id)
            llm_keys.add(llm_key)

    # Add config review findings, deduplicating
    if state.config_review_result:
        for finding in state.config_review_result.findings:
            if finding.line_number and (finding.file_path, finding.line_number) in sast_locations:
                continue
            llm_key = (finding.rule_id, finding.file_path, finding.line_number or 0)
            if llm_key in llm_keys:
                continue
            base_sarif["runs"][0]["results"].append(_finding_to_sarif_result(finding))
            _ensure_rule(base_sarif, finding.rule_id, finding.title, finding.cwe_id)
            llm_keys.add(llm_key)

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

    # Write reports — triage counts derived from SARIF properties (single source of truth)
    report_data = extract_report_data(
        all_results,
        rule_cwe_map=rule_cwe_map,
        run_id=state.run_id,
        target=str(state.target_path),
        mode=state.config.review.mode,
        provider=state.config.llm.provider_model,
        cost_usd=state.cost_tracker.total_spent,
    )

    # Attach coverage data from inventory
    report_data.coverage = state.coverage

    # Store report_data on state so CLI can access it for terminal output
    state.report_data = report_data

    # Write configured report formats
    report_formats = state.report_formats
    write_reports(report_data, report_formats, sarif_path.parent)

    # Write triage audit log
    triage_data = {
        "run_id": state.run_id,
        "target": str(state.target_path),
        "mode": state.config.review.mode,
        "total_findings": len(all_results),
        "cost": state.cost_tracker.to_audit_log(),
        "evidence": state.evidence.to_dict(),
    }
    if state.triage_result:
        triage_data["triage"] = state.triage_result.model_dump()

    with open(triage_path, "w", encoding="utf-8") as f:
        json.dump(triage_data, f, indent=2)

    logger.info(
        "pipeline.pass_completed",
        pass_number=merge_pass_number,
        finding_count=len(all_results),
        sarif_path=str(sarif_path),
    )

    return sarif_path


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

            # LLM-discovered findings (holistic pass) are pre-assessed with evidence
            if is_llm_finding and not verdict:
                verdict = "CONFIRMED"
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


