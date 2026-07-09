"""Pass 2: Deterministic SAST tool orchestration.

Resolves applicable tools from the registry, runs them concurrently,
collects SARIF output, converts non-native formats, and merges results.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import structlog

from security_review.errors import SARIFError, ScannerError
from security_review.models.degradation import Degradation
from security_review.priority import build_exposure_index, score_finding
from security_review.sarif.converter import convert_dotnet_vuln_to_sarif, convert_pip_audit_to_sarif, convert_sarif_v1_to_v2
from security_review.sarif.loader import load_sarif, normalize_uri
from security_review.sarif.merger import merge_sarif
from security_review.sarif.normalise import normalise_sarif_levels
from security_review.tools.redactor import redact_sarif
from security_review.tools.registry import (
    OutputFormat,
    SecurityToolSpec,
    load_tool_specs,
    resolve_tools_for_manifest,
)
from security_review.passes.state import PipelineState
from security_review.tools.runner import run_tool

logger = structlog.get_logger()


async def run_sast(state: PipelineState) -> None:
    """Execute Pass 2: run all applicable SAST tools and merge results."""

    logger.info("pipeline.pass_started", pass_number=2, pass_name="sast")

    if state.manifest is None:
        raise ScannerError(
            "Pass 2 requires a file manifest from Pass 1",
            code="SCAN_TOOL_FAILED",
        )

    file_paths = [f.path for f in state.manifest.files]
    all_specs = load_tool_specs()
    applicable_specs = resolve_tools_for_manifest(
        all_specs, file_paths, require_available=True
    )

    progress = state.on_progress

    applicable_any = resolve_tools_for_manifest(all_specs, file_paths, require_available=False)
    missing = [s for s in applicable_any if not s.is_available()]
    for spec in missing:
        state.degrade(Degradation(
            pass_name="sast", kind="tool_missing", subject=spec.name,
            detail=f"binary '{spec.binary}' not found on PATH — {spec.name} did not run",
        ))
        progress(2, "sast", "tool", f"{spec.name}: NOT INSTALLED — skipped")

    if not applicable_specs:
        logger.warning("sast.no_tools", message="No applicable SAST tools found on PATH")
        state.degrade(Degradation(
            pass_name="sast", kind="tool_missing", subject="sast",
            detail="no applicable SAST tools found on PATH — nothing was scanned",
            count=len(applicable_any),
        ))
        state.sast_sarif = merge_sarif([])
        return

    tool_names = [s.name for s in applicable_specs]
    logger.info("sast.tools_resolved", tools=tool_names)
    progress(2, "sast", "tool", f"running {len(tool_names)} tools: {', '.join(tool_names)}")

    # Run tools concurrently
    target = str(state.target_path.resolve())
    tasks = []
    for spec in applicable_specs:
        if spec.target_type == "file":
            # File-targeted tools (e.g. hadolint) run once per matching file
            tasks.append(_run_file_targeted_tool(
                spec, state.manifest, state.target_path, state.work_dir, run_id=state.run_id,
            ))
        else:
            tasks.append(_run_single_tool(spec, target, state.work_dir, run_id=state.run_id))
    sarif_documents = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out None results (failed tools) and exceptions
    valid_docs = []
    for i, doc in enumerate(sarif_documents):
        spec = applicable_specs[i]
        if isinstance(doc, Exception):
            logger.error("sast.tool_exception", error=str(doc))
            state.degrade(Degradation(
                pass_name="sast", kind="tool_failed", subject=spec.name,
                detail=f"{spec.name} produced no usable output — its findings are absent "
                       f"(see var/logs/system.jsonl)",
            ))
            progress(2, "sast", "tool", f"{spec.name}: failed")
        elif doc is not None:
            count = sum(len(r.get("results", [])) for r in doc.get("runs", []))
            progress(2, "sast", "tool", f"{spec.name}: {count} findings")
            valid_docs.append(doc)
        else:
            state.degrade(Degradation(
                pass_name="sast", kind="tool_failed", subject=spec.name,
                detail=f"{spec.name} produced no usable output — its findings are absent "
                       f"(see var/logs/system.jsonl)",
            ))
            progress(2, "sast", "tool", f"{spec.name}: failed — no output")

    # Merge all SARIF documents
    merged = merge_sarif(valid_docs)

    # Normalise severity levels across tools (Bandit, OpenGrep, betterleaks all differ)
    normalise_sarif_levels(merged)

    # Normalize all URIs to relative paths (SAST tools produce absolute paths)
    _normalize_sarif_uris(merged, target)

    # Redact secrets from betterleaks/gitleaks output
    merged = redact_sarif(merged)

    # Pre-score findings so triage can filter by priority threshold (not just severity).
    # These scores are temporary — merge.py overwrites them with the final scores
    # that incorporate triage verdicts. They exist solely to support triage.min_score.
    exposure_index = build_exposure_index(state.manifest)
    _prescore_for_triage_filter(merged, exposure_index)

    state.sast_sarif = merged

    finding_count = sum(
        len(run.get("results", []))
        for run in merged.get("runs", [])
    )

    logger.info(
        "pipeline.pass_completed",
        pass_number=2,
        finding_count=finding_count,
        tools_run=[s.name for s in applicable_specs],
    )


async def _run_file_targeted_tool(
    spec: SecurityToolSpec,
    manifest,
    target_path: Path,
    work_dir: Path,
    *,
    run_id: str,
) -> dict | None:
    """Run a file-targeted tool concurrently across all matching files, merge SARIF outputs."""
    matching_files = [
        f.path for f in manifest.files
        if spec.matches_files([f.path])
    ]
    if not matching_files:
        return None

    tasks = [
        _run_single_tool(
            spec,
            str((target_path / rel_path).resolve()),
            work_dir,
            suffix=rel_path.replace("/", "_"),
            run_id=run_id,
        )
        for rel_path in matching_files
    ]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    sarif_docs = [r for r in results if r is not None]

    if not sarif_docs:
        return None
    if len(sarif_docs) == 1:
        return sarif_docs[0]
    return merge_sarif(sarif_docs)


async def _run_single_tool(
    spec: SecurityToolSpec,
    target_path: str,
    work_dir: Path,
    suffix: str = "",
    *,
    run_id: str,
) -> dict | None:
    """Run a single tool and return its SARIF output, or None on failure.

    Intermediate tool output lives under a run-scoped tmp directory
    (var/tmp/<run_id>/) so two concurrent runs never cross-contaminate
    each other's findings — merge.py's run_merge() deletes this directory
    once the final report is written.
    """
    tmp_dir = work_dir / "var" / "tmp" / run_id
    tmp_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{spec.name}-{suffix}.sarif" if suffix else f"{spec.name}.sarif"
    output_path = str(tmp_dir / filename)

    def _finalize(doc: dict) -> dict:
        """Redact secrets on disk too, not just in the in-memory merged doc."""
        if spec.redact_output:
            doc = redact_sarif(doc)
            Path(output_path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return doc

    result = await run_tool(spec, target_path, output_path)

    if not result.success:
        logger.warning(
            "sast.tool_skipped",
            tool_name=spec.name,
            exit_code=result.exit_code,
            stderr=result.stderr[:200],
        )
        return None

    # Check output file exists, is non-empty, and starts with valid JSON
    output = Path(output_path)
    if not output.exists() or output.stat().st_size == 0:
        logger.warning("sast.empty_output", tool_name=spec.name)
        return None

    first_char = output.read_text(encoding="utf-8", errors="replace").lstrip()[:1]
    if first_char not in ("{", "["):
        logger.warning(
            "sast.non_json_output",
            tool_name=spec.name,
            preview=output.read_text(encoding="utf-8", errors="replace")[:200],
        )
        return None

    # Convert non-SARIF output to SARIF
    try:
        if spec.sarif_native:
            try:
                return _finalize(load_sarif(output_path))
            except SARIFError as e:
                if "version '1.0.0'" in str(e):
                    logger.info("sast.sarif_v1_upgrade", tool_name=spec.name)
                    return _finalize(convert_sarif_v1_to_v2(output_path))
                raise

        if spec.output_format == OutputFormat.JSON:
            if spec.name == "pip-audit":
                return convert_pip_audit_to_sarif(output_path)
            elif spec.name == "dotnet-vuln":
                return convert_dotnet_vuln_to_sarif(output_path)

        # Fallback: try loading as SARIF
        return _finalize(load_sarif(output_path))

    except Exception as e:
        logger.error(
            "sast.parse_failed",
            tool_name=spec.name,
            error=str(e),
            error_type=type(e).__name__,
        )
        return None


def _normalize_sarif_uris(sarif: dict, target_root: str) -> None:
    """Convert all artifact URIs in SARIF from absolute to relative paths.

    SAST tools produce absolute paths. We normalize them immediately so:
    1. Downstream passes (triage, merge) match against manifest relative paths
    2. SARIF output does not leak internal directory structure or usernames
    3. Paths are consistent regardless of where the tool was invoked from
    """
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                phys = location.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                if "uri" in artifact:
                    artifact["uri"] = normalize_uri(artifact["uri"], target_root)


def _prescore_for_triage_filter(sarif: dict, exposure_index: dict[str, float]) -> None:
    """Pre-score SAST findings so triage.py can filter by priority threshold.

    These are temporary scores (severity x sast_only confidence x exposure).
    The merge pass overwrites them with final scores that incorporate triage verdicts.
    They exist only to support the triage.min_score filter in Pass 3.
    """
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "warning")
            locs = result.get("locations", [{}])
            file_path = ""
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")

            score = score_finding(
                level=level,
                file_path=file_path,
                exposure_index=exposure_index,
                detection_method="sast_only",
            )

            props = result.setdefault("properties", {})
            props["priority"] = score.priority
            props["priority_band"] = score.band
