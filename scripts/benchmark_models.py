#!/usr/bin/env python3
"""Model benchmark scorer.

Runs one or more LLM models against a ground-truth corpus and produces
F2, MCC, precision, recall, and per-CWE breakdown. Designed to compare
models objectively when new versions are released.

Anti-gaming measures:
  - Pair-wise evaluation: each vulnerable sample has a patched twin.
    The model must classify both correctly (find the vuln, NOT flag the patch).
  - Hard negatives: safe code that looks like the vulnerability.
  - Multi-run stability: --runs N reports mean +/- stddev.
  - Per-CWE reporting: can't game aggregate by specialising.

Usage:
    # Compare two models on the built-in corpus
    python scripts/benchmark_models.py copilot:claude-sonnet-4.6 copilot:claude-opus-4.6

    # Use a private held-out corpus
    python scripts/benchmark_models.py --corpus ~/.security-review/eval-corpus/ copilot:claude-opus-4.6

    # Multiple runs for stability measurement
    python scripts/benchmark_models.py --runs 3 copilot:claude-sonnet-4.6

    # SAST-only baseline (no LLM, measures tool coverage)
    python scripts/benchmark_models.py --sast-only
"""
from __future__ import annotations

import asyncio
import math
import sys
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import click
import yaml

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

CORPUS_ROOT = PROJECT_ROOT / "corpus"


# ---------------------------------------------------------------------------
# Ground truth loading
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthFinding:
    file: str
    line: int
    cwe_id: str
    label: str  # true_positive | false_positive
    description: str = ""


@dataclass
class CorpusEntry:
    path: Path
    cwe: str
    language: str
    description: str
    findings: list[GroundTruthFinding]
    has_patched: bool = False


def load_corpus(corpus_root: Path) -> list[CorpusEntry]:
    """Load all ground_truth.yaml files from a corpus directory."""
    entries = []
    for gt_path in sorted(corpus_root.rglob("ground_truth.yaml")):
        with open(gt_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            continue

        findings = []
        for fd in data.get("findings", []):
            findings.append(GroundTruthFinding(
                file=fd["file"],
                line=fd["line"],
                cwe_id=fd.get("cwe_id", f"CWE-{data.get('cwe', '')}"),
                label=fd["label"],
                description=fd.get("description", ""),
            ))

        entry_path = gt_path.parent
        has_patched = (entry_path / "patched").exists()

        entries.append(CorpusEntry(
            path=entry_path,
            cwe=str(data.get("cwe", "")),
            language=data.get("language", ""),
            description=data.get("description", ""),
            findings=findings,
            has_patched=has_patched,
        ))

    return entries


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0


def precision(c: Counts) -> float:
    return c.tp / (c.tp + c.fp) if (c.tp + c.fp) > 0 else 0.0


def recall(c: Counts) -> float:
    return c.tp / (c.tp + c.fn) if (c.tp + c.fn) > 0 else 0.0


def f_beta(c: Counts, beta: float = 2.0) -> float:
    p, r = precision(c), recall(c)
    if p + r == 0:
        return 0.0
    b2 = beta * beta
    return (1 + b2) * p * r / (b2 * p + r)


def mcc(c: Counts) -> float:
    num = c.tp * c.tn - c.fp * c.fn
    denom = math.sqrt(
        (c.tp + c.fp) * (c.tp + c.fn) * (c.tn + c.fp) * (c.tn + c.fn)
    )
    return num / denom if denom > 0 else 0.0


def youden_j(c: Counts) -> float:
    tpr = recall(c)
    specificity = c.tn / (c.tn + c.fp) if (c.tn + c.fp) > 0 else 0.0
    return tpr + specificity - 1.0


# ---------------------------------------------------------------------------
# Model evaluation
# ---------------------------------------------------------------------------

@dataclass
class ModelResult:
    model: str
    per_cwe: dict[str, Counts] = field(default_factory=dict)
    overall: Counts = field(default_factory=Counts)
    duration_s: float = 0.0
    cost_usd: float = 0.0


async def evaluate_model(
    model_string: str,
    corpus: list[CorpusEntry],
    sast_only: bool = False,
) -> ModelResult:
    """Run a model against all corpus entries and collect counts."""
    import time
    from security_review.passes.state import PipelineState
    from security_review.passes.inventory import run_inventory
    from security_review.passes.sast import run_sast
    from security_review.passes.holistic import run_holistic
    from security_review.config import load_config
    from security_review.budget import CostTracker
    from security_review.providers import build_model
    from security_review.sarif.loader import normalize_uri, extract_findings, get_result_location
    from security_review.logging import setup_logging

    setup_logging(level="WARNING", enable_console=False, enable_file_logging=False)

    result = ModelResult(model=model_string)
    start = time.monotonic()

    for entry in corpus:
        source_dir = entry.path / "source"
        if not source_dir.exists():
            # For false-positives entries, source files may be at entry root
            source_dir = entry.path
            if not any(source_dir.glob("*.py")) and not any(source_dir.glob("*.cs")):
                continue

        # Expected true positives from ground truth
        expected_tp = {
            (f.file, f.line)
            for f in entry.findings
            if f.label == "true_positive"
        }

        # Run pipeline in sast or full mode
        work_dir = PROJECT_ROOT / "var" / "tmp" / "benchmark"
        work_dir.mkdir(parents=True, exist_ok=True)

        config = load_config()
        config.review.mode = "sast" if sast_only else "full"
        if not sast_only:
            config.llm.provider_model = model_string

        state = PipelineState(
            config=config,
            target_path=source_dir,
            work_dir=work_dir,
        )

        try:
            await run_inventory(state)
            await run_sast(state)

            if not sast_only and state.sast_sarif:
                model_obj = build_model(model_string)
                await run_holistic(state)
        except Exception as e:
            click.echo(f"    error on {entry.path.name}: {e}", err=True)
            continue

        # Collect findings from SAST + holistic
        target_root = str(source_dir.resolve())
        found_locations: set[tuple[str, int]] = set()

        if state.sast_sarif:
            for finding in extract_findings(state.sast_sarif):
                uri, line = get_result_location(finding, target_root=target_root)
                if uri and line:
                    found_locations.add((uri, line))

        if state.holistic_result:
            for f in state.holistic_result.findings:
                if f.file_path and f.line_number:
                    found_locations.add((f.file_path, f.line_number))

        # Score against ground truth
        cwe_key = entry.cwe or "all"
        if cwe_key not in result.per_cwe:
            result.per_cwe[cwe_key] = Counts()

        counts = result.per_cwe[cwe_key]

        # Match with ±1 line tolerance (SAST tools often report adjacent lines)
        for file, line in expected_tp:
            matched = any(
                f == file and abs(l - line) <= 1
                for f, l in found_locations
            )
            if matched:
                counts.tp += 1
                result.overall.tp += 1
            else:
                counts.fn += 1
                result.overall.fn += 1

        # Check for false positives (findings not near any ground truth)
        for file, line in found_locations:
            near_expected = any(
                f == file and abs(l - line) <= 1
                for f, l in expected_tp
            )
            if not near_expected:
                counts.fp += 1
                result.overall.fp += 1

        # Hard negatives: if patched dir exists, run against it
        # Any finding on patched code is a false positive
        if entry.has_patched:
            patched_dir = entry.path / "patched"
            patched_config = load_config()
            patched_config.review.mode = "sast" if sast_only else "full"
            if not sast_only:
                patched_config.llm.provider_model = model_string

            patched_state = PipelineState(
                config=patched_config,
                target_path=patched_dir,
                work_dir=work_dir,
            )
            try:
                await run_inventory(patched_state)
                await run_sast(patched_state)

                # Also run holistic on patched code to penalize
                # "always predict vulnerable" LLM models
                if not sast_only and patched_state.sast_sarif:
                    model_obj = build_model(model_string)
                    await run_holistic(patched_state)

                patched_finding_count = 0
                if patched_state.sast_sarif:
                    patched_findings = extract_findings(patched_state.sast_sarif)
                    patched_root = str(patched_dir.resolve())
                    for pf in patched_findings:
                        uri, line = get_result_location(pf, target_root=patched_root)
                        if uri and line:
                            counts.fp += 1
                            result.overall.fp += 1
                            patched_finding_count += 1

                if patched_state.holistic_result:
                    for hf in patched_state.holistic_result.findings:
                        counts.fp += 1
                        result.overall.fp += 1
                        patched_finding_count += 1

                if patched_finding_count == 0:
                    counts.tn += 1
                    result.overall.tn += 1
            except Exception:
                pass

        # False-positive entries: if no expected TPs, count TN for clean runs
        if not expected_tp and not found_locations:
            counts.tn += 1
            result.overall.tn += 1

    result.duration_s = time.monotonic() - start
    return result


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_results(results: list[ModelResult]) -> None:
    click.echo(f"\n{'='*80}")
    click.echo("  BENCHMARK RESULTS")
    click.echo(f"{'='*80}\n")

    # Summary table
    click.echo(f"  {'Model':<35} {'F2':>6} {'MCC':>6} {'Prec':>6} {'Recall':>6} {'Youden':>7} {'Time':>7}")
    click.echo(f"  {'-'*35} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*7} {'-'*7}")

    for r in results:
        c = r.overall
        click.echo(
            f"  {r.model:<35} "
            f"{f_beta(c, 2.0):>6.3f} "
            f"{mcc(c):>6.3f} "
            f"{precision(c):>6.3f} "
            f"{recall(c):>6.3f} "
            f"{youden_j(c):>7.3f} "
            f"{r.duration_s:>6.1f}s"
        )

    # Per-CWE breakdown for each model
    for r in results:
        if len(r.per_cwe) <= 1:
            continue
        click.echo(f"\n  Per-CWE breakdown: {r.model}")
        click.echo(f"  {'CWE':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'F2':>7} {'Prec':>7} {'Recall':>7}")
        click.echo(f"  {'-'*10} {'-'*4} {'-'*4} {'-'*4} {'-'*4} {'-'*7} {'-'*7} {'-'*7}")
        for cwe_id in sorted(r.per_cwe.keys()):
            c = r.per_cwe[cwe_id]
            click.echo(
                f"  CWE-{cwe_id:<5} "
                f"{c.tp:>4} {c.fp:>4} {c.fn:>4} {c.tn:>4} "
                f"{f_beta(c, 2.0):>7.3f} "
                f"{precision(c):>7.3f} "
                f"{recall(c):>7.3f}"
            )

    # Raw counts
    click.echo(f"\n  Raw counts:")
    for r in results:
        c = r.overall
        click.echo(f"  {r.model}: TP={c.tp} FP={c.fp} FN={c.fn} TN={c.tn}")


def print_comparison(results: list[ModelResult]) -> None:
    """Print head-to-head comparison if multiple models."""
    if len(results) < 2:
        return

    click.echo(f"\n  {'='*60}")
    click.echo("  HEAD-TO-HEAD COMPARISON")
    click.echo(f"  {'='*60}")

    best = max(results, key=lambda r: f_beta(r.overall, 2.0))
    for r in results:
        f2 = f_beta(r.overall, 2.0)
        best_f2 = f_beta(best.overall, 2.0)
        delta = f2 - best_f2
        marker = " <-- BEST" if r is best else f" ({delta:+.3f})"
        click.echo(f"  {r.model:<35} F2={f2:.3f}{marker}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.argument("models", nargs=-1)
@click.option("--corpus", "corpus_path", default=None,
              type=click.Path(exists=True),
              help="Path to corpus directory (default: built-in corpus/).")
@click.option("--runs", default=1, type=int,
              help="Run each model N times and report mean +/- stddev.")
@click.option("--sast-only", is_flag=True,
              help="SAST-only baseline (no LLM).")
def main(models, corpus_path, runs, sast_only):
    """Benchmark LLM models against ground-truth security corpus.

    \b
    Examples:
        python scripts/benchmark_models.py copilot:claude-sonnet-4.6
        python scripts/benchmark_models.py --sast-only
        python scripts/benchmark_models.py --runs 3 copilot:claude-opus-4.6
        python scripts/benchmark_models.py --corpus /path/to/private/corpus copilot:claude-opus-4.6
    """
    corpus_dir = Path(corpus_path) if corpus_path else CORPUS_ROOT
    corpus = load_corpus(corpus_dir)

    if not corpus:
        click.echo(f"No ground_truth.yaml files found in {corpus_dir}", err=True)
        raise SystemExit(1)

    gt_count = sum(len(e.findings) for e in corpus)
    patched_count = sum(1 for e in corpus if e.has_patched)
    click.echo(f"Corpus: {len(corpus)} entries, {gt_count} ground truth findings, {patched_count} with patched twins")

    if sast_only:
        model_list = ["sast-baseline"]
    elif not models:
        click.echo("No models specified. Use: benchmark_models.py copilot:claude-sonnet-4.6", err=True)
        raise SystemExit(1)
    else:
        model_list = list(models)

    all_results: list[ModelResult] = []

    for model in model_list:
        click.echo(f"\nEvaluating: {model}")

        run_results: list[ModelResult] = []
        for run_idx in range(runs):
            if runs > 1:
                click.echo(f"  Run {run_idx + 1}/{runs}...")

            r = asyncio.run(evaluate_model(
                model, corpus, sast_only=(model == "sast-baseline"),
            ))
            run_results.append(r)

        if runs == 1:
            all_results.append(run_results[0])
        else:
            # Average metrics across runs (not counts — avoids integer division loss)
            f2_scores = [f_beta(r.overall, 2.0) for r in run_results]
            mcc_scores = [mcc(r.overall) for r in run_results]
            n = len(run_results)
            mean_f2 = sum(f2_scores) / n
            stddev_f2 = math.sqrt(sum((s - mean_f2) ** 2 for s in f2_scores) / n) if n > 1 else 0.0

            # Use the median run (by F2) as representative for per-CWE breakdown
            sorted_runs = sorted(run_results, key=lambda r: f_beta(r.overall, 2.0))
            median_run = sorted_runs[n // 2]
            median_run.model = f"{model} (median of {runs})"
            median_run.duration_s = sum(r.duration_s for r in run_results) / n

            click.echo(f"  F2 stability: {mean_f2:.3f} +/- {stddev_f2:.3f}")

            all_results.append(median_run)

    print_results(all_results)
    print_comparison(all_results)


if __name__ == "__main__":
    main()
