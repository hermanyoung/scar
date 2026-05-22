#!/usr/bin/env python3
"""CWE detection benchmark against the example-target reference target.

Runs `scar.py test-cwe` for each baseline CWE across one or more providers
and prints a pass/fail comparison table.

Baseline: var/output/2026-05-05-example-target-b7eb11f5 (18 holistic findings)

Usage:
    # All default providers (copilot + claude)
    python scripts/benchmark_cwes.py

    # Specific providers
    python scripts/benchmark_cwes.py --providers copilot:claude-opus,claude:claude-opus

    # Single CWE
    python scripts/benchmark_cwes.py --cwes 863,200

    # Different target
    python scripts/benchmark_cwes.py --target /path/to/repo

    # A/B test two SDK versions (multiple runs each)
    python scripts/benchmark_cwes.py --ab-sdk 0.2.2,0.3.0 --runs 3 --providers copilot:claude-opus

    # A/B test specific CWEs only
    python scripts/benchmark_cwes.py --ab-sdk 0.2.2,0.3.0 --runs 3 --cwes 312,522,863

    # Regression tests (uses golden baseline in config/golden/)
    pytest tests/regression/ -v --provider copilot:claude-opus
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Baseline — expected findings from b7eb11f5
# ---------------------------------------------------------------------------

@dataclass
class CWEBaseline:
    cwe_id: str
    description: str
    expected_min: int          # minimum finding count to consider a pass
    expected_findings: list[str]  # brief descriptions of what should be found

BASELINE: list[CWEBaseline] = [
    CWEBaseline("863", "IDOR — Missing Authorization", 2, [
        "DeleteContact: any user can delete any contact",
        "UpdateContact: any user can update any contact",
        "GetContacts/service: no user/tenant filter",
    ]),
    CWEBaseline("200", "Information Exposure", 3, [
        "GetContacts returns all records without ownership filter",
        "GetContactPoem sends full PII to external OpenAI API",
        "AppMetadataController: no [Authorize] attribute",
        "FeaturesController: no [Authorize] attribute",
        "Dockerfile ARG FEED_ACCESSTOKEN persisted in layer",
    ]),
    CWEBaseline("312", "Cleartext Storage of Sensitive Info", 1, [
        "AppAdOptions.ClientSecret stored as plain string",
        "Contact PII stored as plaintext in DB",
    ]),
    CWEBaseline("693", "Protection Mechanism Failure", 1, [
        "No rate limiting on GetContactPoem (external AI call)",
        "AppMetadataController exposes build metadata without auth",
    ]),
    CWEBaseline("116", "Improper Encoding / Output Neutralization", 1, [
        "User-controlled PII concatenated into LLM prompt without escaping",
    ]),
    CWEBaseline("209", "Error Message Information Exposure", 1, [
        "Unhandled exception in GetContactPoem may expose internals",
    ]),
    CWEBaseline("522", "Insufficiently Protected Credentials", 1, [
        "AppAdOptions.ClientSecret plain string property",
    ]),
    CWEBaseline("311", "Missing Encryption of Sensitive Data", 1, [
        "Contact entity PII fields not encrypted at column level",
    ]),
    CWEBaseline("319", "Cleartext Transmission", 1, [
        "APIClientGenerator fetches spec over unencrypted HTTP",
    ]),
    CWEBaseline("400", "Uncontrolled Resource Consumption", 1, [
        "GetContacts fetches all records without pagination",
    ]),
    CWEBaseline("668", "Exposure of Resource to Wrong Sphere", 1, [
        "Health check endpoint exposes internal system state without auth",
    ]),
]

# ---------------------------------------------------------------------------
# Default providers (all use Opus 4.6 via alias)
# ---------------------------------------------------------------------------

DEFAULT_PROVIDERS = [
    "copilot:claude-opus",   # Claude Opus 4.6 via GitHub Copilot (subscription)
    "claude:claude-opus",    # Claude Opus 4.6 via Claude Max/Pro SDK (subscription)
    "anthropic:claude-opus", # Claude Opus 4.6 via Anthropic API (requires ANTHROPIC_API_KEY)
    "openai:gpt",            # GPT-5.5 via OpenAI API (requires OPENAI_API_KEY, different model)
    "codex:gpt",             # GPT-5.5 via Codex app-server (requires ChatGPT Plus, different model)
]

# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    cwe_id: str
    provider: str
    finding_count: int
    findings: list[str]
    elapsed_s: float
    error: str | None = None


def run_test_cwe(
    cwe_id: str,
    target: str,
    provider: str,
    scar_py: Path,
    delay_s: float = 2.0,
    temperature: float | None = None,
) -> TestResult:
    """Run `python scar.py test-cwe --cwe CWE --target TARGET --provider PROVIDER` and parse output."""
    t0 = time.monotonic()
    cmd = [
        sys.executable,
        str(scar_py),
        "test-cwe",
        "--cwe", cwe_id,
        "--target", target,
        "--provider", provider,
    ]
    if temperature is not None:
        cmd.extend(["--temperature", str(temperature)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
        elapsed = time.monotonic() - t0

        if proc.returncode != 0:
            # Extract last meaningful line from stderr
            err_lines = [l for l in proc.stderr.splitlines() if l.strip()]
            err = err_lines[-1] if err_lines else proc.stderr[:200]
            return TestResult(cwe_id, provider, 0, [], elapsed, error=err)

        stdout = proc.stdout

        # Parse finding count
        count_match = re.search(r"Findings:\s*(\d+)", stdout)
        finding_count = int(count_match.group(1)) if count_match else 0

        # Parse individual findings: lines like "  [Severity.HIGH] file:line"
        findings = re.findall(r"\[Severity\.\w+\]\s+(.+)", stdout)

        if delay_s > 0:
            time.sleep(delay_s)

        return TestResult(cwe_id, provider, finding_count, findings, elapsed)

    except subprocess.TimeoutExpired:
        return TestResult(cwe_id, provider, 0, [], time.monotonic() - t0, error="timeout (180s)")
    except Exception as e:
        return TestResult(cwe_id, provider, 0, [], time.monotonic() - t0, error=str(e))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _pass_symbol(found: int, expected_min: int, error: str | None) -> str:
    if error:
        return "ERR"
    if found >= expected_min:
        return f"{found} PASS"
    if found > 0:
        return f"{found} PART"
    return "0 FAIL"


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def print_table(
    results: dict[str, dict[str, TestResult]],
    baselines: list[CWEBaseline],
    providers: list[str],
) -> None:
    short_providers = [p.replace("claude-opus", "opus").replace("claude-sonnet", "sonnet") for p in providers]

    col_w = max(12, max(len(s) for s in short_providers))
    cwe_w = 6
    desc_w = 42
    exp_w = 5

    # Header
    header = f"  {'CWE':<{cwe_w}}  {'Description':<{desc_w}}  {'Exp':>{exp_w}}  "
    header += "  ".join(f"{p:<{col_w}}" for p in short_providers)
    sep = "  " + "-" * (cwe_w + 2 + desc_w + 2 + exp_w + 2 + (col_w + 2) * len(providers))
    print()
    print(sep)
    print(header)
    print(sep)

    passed = 0
    partial = 0
    failed = 0
    errors = 0
    total = 0

    for bl in baselines:
        total += 1
        row = f"  {bl.cwe_id:<{cwe_w}}  {bl.description[:desc_w]:<{desc_w}}  {bl.expected_min:>{exp_w}}  "
        all_pass = True
        any_pass = False
        row_results = []
        for prov in providers:
            r = results.get(bl.cwe_id, {}).get(prov)
            if r is None:
                sym = "---"
                row_results.append(sym)
                all_pass = False
            else:
                sym = _pass_symbol(r.finding_count, bl.expected_min, r.error)
                row_results.append((sym, r.error))
                if "PASS" in sym:
                    any_pass = True
                else:
                    all_pass = False

        # Colorize
        colored_cols = []
        for item in row_results:
            if isinstance(item, tuple):
                sym, err = item
            else:
                sym, err = item, None
            if "PASS" in sym:
                colored_cols.append(_color(f"{sym:<{col_w}}", "32"))
            elif "PART" in sym:
                colored_cols.append(_color(f"{sym:<{col_w}}", "33"))
            elif err:
                colored_cols.append(_color(f"ERR{'':<{col_w-3}}", "31"))
            else:
                colored_cols.append(_color(f"{sym:<{col_w}}", "31"))

        row += "  ".join(colored_cols)
        print(row)

        if all_pass:
            passed += 1
        elif any_pass:
            partial += 1
        elif any(isinstance(r, tuple) and r[1] for r in row_results):
            errors += 1
        else:
            failed += 1

    # Per-provider pass count summary row
    prov_pass = {p: 0 for p in providers}
    prov_total = {p: 0 for p in providers}
    for bl in baselines:
        for prov in providers:
            r = results.get(bl.cwe_id, {}).get(prov)
            if r is not None and not r.error:
                prov_total[prov] += 1
                if r.finding_count >= bl.expected_min:
                    prov_pass[prov] += 1

    short_providers = [p.replace("claude-opus", "opus").replace("claude-sonnet", "sonnet") for p in providers]
    summary_row = f"  {'':>{cwe_w}}  {'Provider score':<{desc_w}}  {'':>{exp_w}}  "
    score_cols = []
    for prov, short in zip(providers, short_providers):
        p = prov_pass[prov]
        t = prov_total[prov]
        sym = f"{p}/{t}"
        if t == 0:
            score_cols.append(f"{sym:<{col_w}}")
        elif p == t:
            score_cols.append(_color(f"{sym:<{col_w}}", "32"))
        elif p > 0:
            score_cols.append(_color(f"{sym:<{col_w}}", "33"))
        else:
            score_cols.append(_color(f"{sym:<{col_w}}", "31"))
    summary_row += "  ".join(score_cols)
    print(summary_row)
    print(sep)
    print(f"\n  CWE results: {passed} all-pass / {partial} partial / {failed} fail / {errors} err  (of {total} CWEs)\n")


def print_details(results: dict[str, dict[str, TestResult]], baselines: list[CWEBaseline]) -> None:
    """Print per-finding details for any non-passing CWE."""
    print("\n=== Finding Details (non-passing) ===\n")
    for bl in baselines:
        cwe_results = results.get(bl.cwe_id, {})
        has_issue = any(
            r.finding_count < bl.expected_min or r.error
            for r in cwe_results.values()
        )
        if not has_issue:
            continue
        print(f"  CWE-{bl.cwe_id} — {bl.description}")
        print(f"    Expected: {bl.expected_min}+ findings")
        for prov, r in cwe_results.items():
            print(f"    [{prov}] {r.finding_count} findings in {r.elapsed_s:.0f}s", end="")
            if r.error:
                print(f"  ERROR: {r.error}", end="")
            print()
            for i, f in enumerate(r.findings[:5]):
                print(f"      {i+1}. {f[:90]}")
        print(f"    Baseline expects:")
        for exp in bl.expected_findings:
            print(f"      - {exp}")
        print()


# ---------------------------------------------------------------------------
# A/B SDK version testing
# ---------------------------------------------------------------------------

def _install_sdk(package: str, version: str) -> bool:
    """pip install package==version, return True on success."""
    print(f"\n  Installing {package}=={version} ...", end="", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "install", f"{package}=={version}", "--quiet"],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        print(f" FAILED: {proc.stderr.strip()[:100]}")
        return False
    print(" ok")
    return True


def _get_sdk_version(package: str) -> str:
    """Return installed version of a package."""
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "show", package],
        capture_output=True, text=True,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def run_ab_sdk(
    versions: list[str],
    runs: int,
    baselines: list[CWEBaseline],
    providers: list[str],
    target: str,
    scar_py: Path,
    delay_s: float,
) -> None:
    """Run benchmark N times per SDK version, print comparison."""
    package = "github-copilot-sdk"
    original_version = _get_sdk_version(package)

    # {version: {cwe_id: {provider: [TestResult, ...]}}}
    all_results: dict[str, dict[str, dict[str, list[TestResult]]]] = {}

    for version in versions:
        if not _install_sdk(package, version):
            print(f"  Skipping version {version}")
            continue

        all_results[version] = {}
        for run_n in range(1, runs + 1):
            print(f"\n  === {package} {version} — run {run_n}/{runs} ===\n")
            for bl in baselines:
                if bl.cwe_id not in all_results[version]:
                    all_results[version][bl.cwe_id] = {p: [] for p in providers}
                for prov in providers:
                    short = prov.replace("claude-opus", "opus")
                    print(f"    CWE-{bl.cwe_id} / {short} ...", end="", flush=True)
                    r = run_test_cwe(bl.cwe_id, target, prov, scar_py, delay_s=delay_s, temperature=args.temperature)
                    all_results[version][bl.cwe_id][prov].append(r)
                    sym = _pass_symbol(r.finding_count, bl.expected_min, r.error)
                    print(f" {sym} ({r.finding_count} findings, {r.elapsed_s:.0f}s)")

    # Restore original version
    _install_sdk(package, original_version)

    # Print comparison table
    _print_ab_table(all_results, versions, baselines, providers, runs)


def _print_ab_table(
    all_results: dict[str, dict[str, dict[str, list[TestResult]]]],
    versions: list[str],
    baselines: list[CWEBaseline],
    providers: list[str],
    runs: int,
) -> None:
    """Print side-by-side A/B comparison with pass rates."""
    print(f"\n{'='*80}")
    print(f"  A/B SDK Comparison — {runs} run(s) per version")
    print(f"{'='*80}\n")

    cwe_w = 6
    desc_w = 36

    for prov in providers:
        short_prov = prov.replace("claude-opus", "opus").replace("claude-sonnet", "sonnet")
        col_w = max(14, max(len(f"v{v}") for v in versions) + 8)

        header = f"  {'CWE':<{cwe_w}}  {'Description':<{desc_w}}  {'Exp':>3}  "
        header += "  ".join(f"{'v' + v:^{col_w}}" for v in versions)
        header += f"  {'Delta':>7}"
        sep = "  " + "-" * (cwe_w + 2 + desc_w + 2 + 3 + 2 + (col_w + 2) * len(versions) + 9)

        print(f"  Provider: {short_prov}")
        print(sep)
        print(header)
        print(sep)

        version_scores: dict[str, tuple[int, int]] = {v: (0, 0) for v in versions}

        for bl in baselines:
            row = f"  {bl.cwe_id:<{cwe_w}}  {bl.description[:desc_w]:<{desc_w}}  {bl.expected_min:>3}  "
            pass_rates: dict[str, float] = {}

            for version in versions:
                results_list = all_results.get(version, {}).get(bl.cwe_id, {}).get(prov, [])
                if not results_list:
                    row += f"{'---':^{col_w}}  "
                    continue

                passes = sum(
                    1 for r in results_list
                    if not r.error and r.finding_count >= bl.expected_min
                )
                total = len(results_list)
                rate = passes / total if total else 0.0
                pass_rates[version] = rate

                p, t = version_scores[version]
                version_scores[version] = (p + passes, t + total)

                label = f"{passes}/{total}"
                if total == 1:
                    # Single run — show finding count too
                    r = results_list[0]
                    if r.error:
                        label = "ERR"
                    else:
                        label = f"{r.finding_count}f {'PASS' if passes else 'FAIL'}"

                if rate == 1.0:
                    row += _color(f"{label:^{col_w}}", "32") + "  "
                elif rate > 0:
                    row += _color(f"{label:^{col_w}}", "33") + "  "
                else:
                    row += _color(f"{label:^{col_w}}", "31") + "  "

            # Delta column
            if len(versions) == 2 and all(v in pass_rates for v in versions):
                delta = pass_rates[versions[1]] - pass_rates[versions[0]]
                if delta > 0.01:
                    row += _color(f"  +{delta:.0%}", "32")
                elif delta < -0.01:
                    row += _color(f"  {delta:.0%}", "31")
                else:
                    row += f"    =="
            else:
                row += f"       "

            print(row)

        # Summary row
        summary = f"  {'':>{cwe_w}}  {'Pass rate':<{desc_w}}  {'':>3}  "
        for version in versions:
            p, t = version_scores[version]
            if t == 0:
                summary += f"{'---':^{col_w}}  "
            else:
                rate = p / t
                label = f"{p}/{t} ({rate:.0%})"
                if rate == 1.0:
                    summary += _color(f"{label:^{col_w}}", "32") + "  "
                elif rate > 0:
                    summary += _color(f"{label:^{col_w}}", "33") + "  "
                else:
                    summary += _color(f"{label:^{col_w}}", "31") + "  "
        print(sep)
        print(summary)
        print(sep)
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark CWE detection across providers")
    parser.add_argument(
        "--target",
        default="../example-target",
        help="Path to the target repository (default: ../example-target)",
    )
    parser.add_argument(
        "--providers",
        default=",".join(DEFAULT_PROVIDERS),
        help=f"Comma-separated provider list (default: {','.join(DEFAULT_PROVIDERS)})",
    )
    parser.add_argument(
        "--cwes",
        default="",
        help="Comma-separated CWE IDs to test (default: all baseline CWEs)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds to wait between calls to avoid rate limiting (default: 2)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=None,
        help="Override LLM temperature (default: use config value). Note: copilot ignores this (hardcoded 0.1).",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Print per-finding detail for non-passing CWEs",
    )
    parser.add_argument(
        "--ab-sdk",
        default="",
        help="A/B test two SDK versions, e.g. --ab-sdk 0.2.2,0.3.0",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of runs per version in A/B mode (default: 3)",
    )
    args = parser.parse_args()

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    if not providers:
        print("No providers specified.")
        sys.exit(1)

    selected_cwes: set[str] = set()
    if args.cwes:
        selected_cwes = {c.strip() for c in args.cwes.split(",") if c.strip()}

    baselines = [b for b in BASELINE if not selected_cwes or b.cwe_id in selected_cwes]
    if not baselines:
        print(f"No baselines match --cwes filter: {args.cwes}")
        sys.exit(1)

    scar_py = Path(__file__).parent.parent / "scar.py"
    if not scar_py.exists():
        print(f"scar.py not found at {scar_py}")
        sys.exit(1)

    target = args.target

    # A/B SDK mode
    if args.ab_sdk:
        versions = [v.strip() for v in args.ab_sdk.split(",") if v.strip()]
        if len(versions) < 2:
            print("--ab-sdk requires two versions, e.g. --ab-sdk 0.2.2,0.3.0")
            sys.exit(1)
        print(f"\nA/B SDK Test: {' vs '.join(versions)}")
        print(f"Runs:      {args.runs} per version")
        print(f"CWEs:      {len(baselines)}")
        print(f"Providers: {', '.join(providers)}")
        print(f"Target:    {target}")
        total_calls = len(baselines) * len(providers) * args.runs * len(versions)
        print(f"Total:     {total_calls} calls")
        run_ab_sdk(versions, args.runs, baselines, providers, target, scar_py, args.delay)
        return

    # Standard benchmark mode
    print(f"\nBenchmark: {len(baselines)} CWEs × {len(providers)} providers")
    print(f"Target:    {target}")
    print(f"Providers: {', '.join(providers)}")
    print(f"Delay:     {args.delay}s between calls\n")

    results: dict[str, dict[str, TestResult]] = {}
    total_calls = len(baselines) * len(providers)
    call_n = 0

    for bl in baselines:
        results[bl.cwe_id] = {}
        for prov in providers:
            call_n += 1
            short = prov.replace("claude-opus", "opus")
            print(f"  [{call_n}/{total_calls}] CWE-{bl.cwe_id} / {short} ...", end="", flush=True)
            r = run_test_cwe(bl.cwe_id, target, prov, scar_py, delay_s=args.delay, temperature=args.temperature)
            results[bl.cwe_id][prov] = r
            sym = _pass_symbol(r.finding_count, bl.expected_min, r.error)
            elapsed_str = f"{r.elapsed_s:.0f}s"
            if r.error:
                print(f" ERR ({r.error[:60]}) [{elapsed_str}]")
            else:
                print(f" {r.finding_count} findings — {sym} [{elapsed_str}]")

    print_table(results, baselines, providers)
    if args.details:
        print_details(results, baselines)


if __name__ == "__main__":
    main()
