"""Evaluation harness for CWE detection regression testing.

Two test layers:
  Layer 1 (Eval): Per-file .bench sidecars declare ground truth.
  Layer 2 (Application): Baseline manifests declare expected findings for a target repo.

No subprocess calls — imports and calls run_single_check directly.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import structlog
import yaml
from pydantic import BaseModel, Field

from security_review import MODULE_ROOT

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# .bench sidecar schema
# ---------------------------------------------------------------------------


class BenchSpec(BaseModel, extra="forbid"):
    """Ground truth for a single eval file."""

    cwe: str = Field(min_length=1)
    expect: Literal["found", "not_found"]
    severity: str | None = Field(default=None)
    evidence_contains: list[str] = Field(default_factory=list)
    notes: str | None = Field(default=None)


# ---------------------------------------------------------------------------
# Baseline manifest schema (application tests)
# ---------------------------------------------------------------------------


class BaselineExpectedFinding(BaseModel, extra="forbid"):
    file: str = Field(min_length=1)
    evidence_contains: list[str] = Field(default_factory=list)


class BaselineCWE(BaseModel, extra="forbid"):
    cwe: str = Field(min_length=1)
    min_findings: int = Field(ge=0, default=1)
    expected: list[BaselineExpectedFinding] = Field(default_factory=list)


class BaselineManifest(BaseModel, extra="forbid"):
    target: str = Field(min_length=1)
    cwes: list[BaselineCWE] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class BenchResult(BaseModel, extra="forbid"):
    """Result of a single evaluation test case."""

    bench_file: str
    cwe: str
    expect: Literal["found", "not_found"]
    status: Literal["PASS", "FAIL", "FP"]
    finding_count: int = 0
    evidence_matched: bool = True
    elapsed_s: float = 0.0
    detail: str = ""


class EvaluationSummary(BaseModel, extra="forbid"):
    """Aggregate results for a evaluation run."""

    provider: str
    results: list[BenchResult] = Field(default_factory=list)
    passed: int = 0
    failed: int = 0
    false_positives: int = 0
    total: int = 0
    precision: float = 0.0
    recall: float = 0.0


# ---------------------------------------------------------------------------
# .bench file discovery and loading
# ---------------------------------------------------------------------------


def discover_bench_files(
    eval_path: Path,
    *,
    cwe_filter: set[str] | None = None,
) -> list[tuple[Path, BenchSpec]]:
    """Find all .bench files under eval_path and parse them.

    Returns sorted list of (bench_file_path, BenchSpec) tuples.
    """
    results: list[tuple[Path, BenchSpec]] = []
    for bench_file in sorted(eval_path.rglob("*.bench")):
        try:
            raw = yaml.safe_load(bench_file.read_text(encoding="utf-8"))
            spec = BenchSpec.model_validate(raw)
        except Exception as e:
            logger.warning("evaluation.bench_parse_failed", path=str(bench_file), error=str(e))
            continue

        if cwe_filter and spec.cwe not in cwe_filter:
            continue

        results.append((bench_file, spec))

    return results


def load_baseline_manifest(path: Path) -> BaselineManifest:
    """Load and validate a baseline manifest YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return BaselineManifest.model_validate(raw)


# ---------------------------------------------------------------------------
# Evaluation logic
# ---------------------------------------------------------------------------


def evaluate_eval_result(
    spec: BenchSpec,
    findings: list,
    elapsed_s: float,
    bench_file: str,
) -> BenchResult:
    """Evaluate a single eval test against its .bench spec.

    findings: list of HolisticFinding objects from run_single_check.
    """
    count = len(findings)

    if spec.expect == "found":
        if count == 0:
            return BenchResult(
                bench_file=bench_file, cwe=spec.cwe, expect="found",
                status="FAIL", finding_count=0, elapsed_s=elapsed_s,
                detail="expected findings but got none",
            )

        # Check severity if specified
        if spec.severity:
            severity_ok = any(
                _severity_meets_minimum(f.severity.value if hasattr(f.severity, 'value') else str(f.severity), spec.severity)
                for f in findings
            )
        else:
            severity_ok = True

        # Check evidence keywords
        evidence_matched = _check_evidence(findings, spec.evidence_contains)

        if not evidence_matched:
            return BenchResult(
                bench_file=bench_file, cwe=spec.cwe, expect="found",
                status="FAIL", finding_count=count, evidence_matched=False,
                elapsed_s=elapsed_s,
                detail=f"{count} findings but evidence keywords not matched",
            )

        return BenchResult(
            bench_file=bench_file, cwe=spec.cwe, expect="found",
            status="PASS", finding_count=count, evidence_matched=True,
            elapsed_s=elapsed_s,
            detail=f"{count} findings, evidence matched",
        )

    else:  # expect == "not_found"
        if count > 0:
            return BenchResult(
                bench_file=bench_file, cwe=spec.cwe, expect="not_found",
                status="FP", finding_count=count, elapsed_s=elapsed_s,
                detail=f"{count} findings on safe code (false positive)",
            )
        return BenchResult(
            bench_file=bench_file, cwe=spec.cwe, expect="not_found",
            status="PASS", finding_count=0, elapsed_s=elapsed_s,
            detail="0 findings, expect=not_found",
        )


def evaluate_baseline_cwe(
    baseline_cwe: BaselineCWE,
    findings: list,
) -> tuple[bool, str]:
    """Evaluate findings against a baseline CWE expectation.

    Returns (passed, detail_message).
    """
    count = len(findings)
    if count < baseline_cwe.min_findings:
        return False, f"expected {baseline_cwe.min_findings}+ findings, got {count}"

    # Check expected file/evidence tuples
    for expected in baseline_cwe.expected:
        file_findings = [f for f in findings if expected.file in getattr(f, 'file_path', '')]
        if not file_findings:
            return False, f"no findings in {expected.file}"
        if expected.evidence_contains and not _check_evidence(file_findings, expected.evidence_contains):
            return False, f"evidence keywords not matched in {expected.file}"

    return True, f"{count} findings, all expectations met"


def compute_metrics(results: list[BenchResult], provider: str) -> EvaluationSummary:
    """Compute precision, recall, and summary counts from test results."""
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    fps = sum(1 for r in results if r.status == "FP")
    total = len(results)

    # Precision = TP / (TP + FP)
    # TP: expect=found AND status=PASS
    # FP: expect=not_found AND status=FP
    tp = sum(1 for r in results if r.expect == "found" and r.status == "PASS")
    fp = fps
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0

    # Recall = TP / (TP + FN)
    # FN: expect=found AND status=FAIL
    fn = sum(1 for r in results if r.expect == "found" and r.status == "FAIL")
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    return EvaluationSummary(
        provider=provider,
        results=results,
        passed=passed,
        failed=failed,
        false_positives=fps,
        total=total,
        precision=round(precision, 2),
        recall=round(recall, 2),
    )


# ---------------------------------------------------------------------------
# Eval test runner (Layer 1)
# ---------------------------------------------------------------------------


async def run_eval_tests(
    eval_path: Path,
    provider_string: str,
    *,
    cwe_filter: set[str] | None = None,
) -> EvaluationSummary:
    """Run all eval .bench tests against a single provider.

    Imports and calls run_single_check directly — no subprocess.
    """
    from security_review.checks import CWECheck, load_cwe_checks
    from security_review.config import load_config
    from security_review.config_schema import SecurityReviewConfig
    from security_review.models.inventory import FileEntry, FileManifest
    from security_review.passes.holistic import run_single_check
    from security_review.passes.inventory import EXTENSION_LANGUAGE
    from security_review.passes.state import PipelineState
    from security_review.providers import build_model
    from security_review.sarif.merger import merge_sarif

    bench_files = discover_bench_files(eval_path, cwe_filter=cwe_filter)
    if not bench_files:
        return EvaluationSummary(provider=provider_string)

    cfg = load_config()
    model = build_model(provider_string, llm_config=cfg.llm)
    all_checks = load_cwe_checks()
    check_map = {c.cwe_id: c for c in all_checks}

    results: list[BenchResult] = []

    for bench_path, spec in bench_files:
        # Resolve the source file from the .bench path
        source_path = bench_path.with_suffix("")  # strip .bench
        if not source_path.exists():
            results.append(BenchResult(
                bench_file=str(bench_path), cwe=spec.cwe, expect=spec.expect,
                status="FAIL", detail=f"source file not found: {source_path.name}",
            ))
            continue

        # Find the matching CWE check
        check = check_map.get(spec.cwe)
        if not check:
            results.append(BenchResult(
                bench_file=str(bench_path), cwe=spec.cwe, expect=spec.expect,
                status="FAIL", detail=f"CWE-{spec.cwe} not in taxonomy checks",
            ))
            continue

        # Build minimal pipeline state with the eval directory as target
        eval_dir = source_path.parent
        rel_path = source_path.name
        entry = FileEntry(
            path=rel_path,
            language=EXTENSION_LANGUAGE.get(source_path.suffix.lower(), "other"),
            size_bytes=source_path.stat().st_size,
            security_weight=5,
            estimated_tokens=max(1, source_path.stat().st_size // 4),
        )
        state = PipelineState(
            config=cfg,
            target_path=eval_dir,
            work_dir=MODULE_ROOT,
        )
        state.manifest = FileManifest(
            files=[entry],
            total_files=1,
            total_tokens=entry.estimated_tokens,
            languages={},
        )
        state.sast_sarif = merge_sarif([])

        t0 = time.monotonic()
        try:
            result = await run_single_check(
                check=check,
                file_paths=[rel_path],
                state=state,
                model=model,
                model_string=provider_string,
            )
        except Exception as e:
            results.append(BenchResult(
                bench_file=str(bench_path), cwe=spec.cwe, expect=spec.expect,
                status="FAIL", elapsed_s=time.monotonic() - t0,
                detail=f"error: {type(e).__name__}: {e}",
            ))
            continue

        elapsed = time.monotonic() - t0

        if result is None:
            findings = []
        else:
            findings, _, _ = result

        test_result = evaluate_eval_result(
            spec, findings, elapsed, str(bench_path.relative_to(eval_path)),
        )
        results.append(test_result)

    return compute_metrics(results, provider_string)


# ---------------------------------------------------------------------------
# Application test runner (Layer 2)
# ---------------------------------------------------------------------------


async def run_application_tests(
    target_path: Path,
    baseline_path: Path,
    provider_string: str,
    *,
    cwe_filter: set[str] | None = None,
) -> EvaluationSummary:
    """Run full holistic pass against a target and compare to baseline.

    Imports and calls run_single_check directly — no subprocess.
    """
    from security_review.checks import load_cwe_checks, select_files_for_check
    from security_review.config import load_config
    from security_review.models.inventory import FileManifest
    from security_review.passes.holistic import run_single_check
    from security_review.passes.inventory import discover_files
    from security_review.passes.state import PipelineState
    from security_review.providers import build_model
    from security_review.sarif.merger import merge_sarif

    manifest = load_baseline_manifest(baseline_path)
    cfg = load_config()
    model = build_model(provider_string, llm_config=cfg.llm)

    # File discovery — same code path as Pass 1 (correct exclusions, size filter, security weights)
    all_entries = discover_files(target_path, cfg.sast.scanner_max_file_size_bytes)
    entries = [e for e in all_entries if e.language in ("python", "csharp")]

    state = PipelineState(
        config=cfg,
        target_path=target_path,
        work_dir=MODULE_ROOT,
    )
    state.manifest = FileManifest(
        files=entries,
        total_files=len(entries),
        total_tokens=sum(e.estimated_tokens for e in entries),
        languages={},
    )
    state.sast_sarif = merge_sarif([])

    all_checks = load_cwe_checks()
    check_map = {c.cwe_id: c for c in all_checks}

    results: list[BenchResult] = []

    for bl_cwe in manifest.cwes:
        if cwe_filter and bl_cwe.cwe not in cwe_filter:
            continue

        check = check_map.get(bl_cwe.cwe)
        if not check:
            results.append(BenchResult(
                bench_file=str(baseline_path), cwe=bl_cwe.cwe,
                expect="found", status="FAIL",
                detail=f"CWE-{bl_cwe.cwe} not in taxonomy checks",
            ))
            continue

        relevant = select_files_for_check(check, entries)
        file_paths = [f.path for f in relevant]
        if not file_paths:
            results.append(BenchResult(
                bench_file=str(baseline_path), cwe=bl_cwe.cwe,
                expect="found", status="FAIL",
                detail="no relevant files found",
            ))
            continue

        t0 = time.monotonic()
        try:
            result = await run_single_check(
                check=check,
                file_paths=file_paths,
                state=state,
                model=model,
                model_string=provider_string,
            )
        except Exception as e:
            results.append(BenchResult(
                bench_file=str(baseline_path), cwe=bl_cwe.cwe,
                expect="found", status="FAIL",
                elapsed_s=time.monotonic() - t0,
                detail=f"error: {type(e).__name__}: {e}",
            ))
            continue

        elapsed = time.monotonic() - t0

        if result is None:
            findings = []
        else:
            findings, _, _ = result

        passed, detail = evaluate_baseline_cwe(bl_cwe, findings)
        results.append(BenchResult(
            bench_file=str(baseline_path), cwe=bl_cwe.cwe,
            expect="found", status="PASS" if passed else "FAIL",
            finding_count=len(findings), elapsed_s=elapsed,
            detail=detail,
        ))

    return compute_metrics(results, provider_string)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def _severity_meets_minimum(actual: str, minimum: str) -> bool:
    """Check if actual severity meets or exceeds the minimum."""
    return _SEVERITY_ORDER.get(actual.upper(), 0) >= _SEVERITY_ORDER.get(minimum.upper(), 0)


def _check_evidence(findings: list, keywords: list[str]) -> bool:
    """Check that at least one keyword appears in any finding's evidence/description/title."""
    if not keywords:
        return True
    for kw in keywords:
        kw_lower = kw.lower()
        for f in findings:
            searchable = " ".join([
                getattr(f, 'evidence', '') or '',
                getattr(f, 'description', '') or '',
                getattr(f, 'title', '') or '',
            ]).lower()
            if kw_lower in searchable:
                break
        else:
            return False
    return True


def print_eval_table(summaries: list[tuple[str, EvaluationSummary]]) -> None:
    """Print evaluation results as a formatted table.

    summaries: list of (layer_name, EvaluationSummary) tuples.
    """
    import click

    for layer, summary in summaries:
        click.echo(f"\nSCAR Eval — {layer} tests")
        click.echo(f"  Provider: {summary.provider}")
        click.echo()

        for r in summary.results:
            short_path = r.bench_file
            if len(short_path) > 50:
                short_path = "..." + short_path[-47:]

            cwe_str = f"CWE-{r.cwe}"
            if r.status == "PASS":
                status = click.style("PASS", fg="green")
            elif r.status == "FP":
                status = click.style("FP  ", fg="yellow")
            else:
                status = click.style("FAIL", fg="red")

            click.echo(f"  {short_path:<52} {cwe_str:<10} {status}   ({r.detail})")

        click.echo()
        click.echo(
            f"  Results: {summary.passed} PASS / {summary.failed} FAIL / "
            f"{summary.false_positives} FP  of {summary.total} tests"
        )
        click.echo(f"  Precision: {summary.precision:.2f}  Recall: {summary.recall:.2f}")
        click.echo()
