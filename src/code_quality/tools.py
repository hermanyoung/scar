"""External tool runners for quality enrichment.

These are optional — scoring works without them (lower confidence).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from code_quality.models import Finding, ToolResult


def _check_installed(command: str) -> bool:
    return shutil.which(command) is not None


def _run_command(
    args: list[str], cwd: Path, timeout: int = 120,
) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except OSError as e:
        return "", str(e), -1


# -- Bandit ------------------------------------------------------------------


class BanditRunner:
    """Run Bandit security linter and produce quality metrics."""

    _TEST_NOISE = {"B101"}

    def run(
        self, root: Path, scope: list[str] | None = None, exclude: list[str] | None = None,
    ) -> ToolResult:
        if not _check_installed("bandit"):
            return ToolResult(tool="bandit", available=False)

        args = ["bandit", "-f", "json", "-r"]
        if scope:
            for s in scope:
                target = root / s
                if target.exists():
                    args.append(str(target))
        else:
            args.append(str(root))

        if exclude:
            # Bandit's --exclude only accepts directory paths, not glob
            # patterns. Non-directory entries (e.g. "*.g.cs" — a C# generated-
            # file pattern that's irrelevant to this Python-only scanner) are
            # silently dropped rather than passed through and rejected.
            bandit_excludes = []
            for exc in exclude:
                exc_path = root / exc.rstrip("/")
                if exc_path.is_dir():
                    bandit_excludes.append(str(exc_path))
            if bandit_excludes:
                args.extend(["--exclude", ",".join(bandit_excludes)])

        stdout, stderr, returncode = _run_command(args, cwd=root)
        if returncode not in (0, 1):
            return ToolResult(
                tool="bandit", available=True,
                error=stderr or f"bandit exited with code {returncode}",
            )

        idx = stdout.find("{")
        raw_json = stdout[idx:] if idx >= 0 else stdout
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ToolResult(tool="bandit", available=True, error=f"Failed to parse bandit JSON: {e}")

        findings: list[Finding] = []
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for r in data.get("results", []):
            sev = r.get("issue_severity", "LOW")
            rule_id = r.get("test_id", "")
            filename = r.get("filename", "")
            if rule_id in self._TEST_NOISE and self._is_test(filename):
                continue
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            findings.append(Finding(
                rule_id=rule_id, severity=sev,
                confidence=r.get("issue_confidence", "LOW"),
                message=r.get("issue_text", ""),
                file=filename, line=r.get("line_number", 0), tool="bandit",
            ))

        raw_metrics = data.get("metrics", {})
        total_loc = sum(v.get("loc", 0) for v in raw_metrics.values() if isinstance(v, dict))
        weighted = severity_counts["HIGH"] * 3 + severity_counts["MEDIUM"] * 2 + severity_counts["LOW"]
        kloc = max(total_loc / 1000, 0.1)

        return ToolResult(
            tool="bandit", available=True, findings=findings,
            metrics={
                "total_findings": len(findings),
                "high_severity": severity_counts["HIGH"],
                "medium_severity": severity_counts["MEDIUM"],
                "low_severity": severity_counts["LOW"],
                "weighted_findings": weighted,
                "weighted_per_kloc": weighted / kloc,
                "total_loc": total_loc,
            },
        )

    @staticmethod
    def _is_test(path: str) -> bool:
        parts = Path(path).parts
        return "tests" in parts or any(p.startswith("test_") for p in parts)


# -- Radon -------------------------------------------------------------------


class RadonRunner:
    """Run Radon complexity analyzer and produce quality metrics."""

    def run(
        self, root: Path, scope: list[str] | None = None, exclude: list[str] | None = None,
    ) -> ToolResult:
        if not _check_installed("radon"):
            return ToolResult(tool="radon", available=False)

        targets = []
        if scope:
            for s in scope:
                target = root / s
                if target.exists():
                    targets.append(str(target))
        targets = targets or [str(root)]

        exclude_args: list[str] = []
        if exclude:
            patterns = [exc.rstrip("/") + "/*" for exc in exclude]
            exclude_args = ["-e", ",".join(patterns)]

        # Cyclomatic complexity
        cc_args = ["radon", "cc", "-j", "-s", "-a"] + exclude_args + targets
        cc_stdout, cc_stderr, cc_rc = _run_command(cc_args, cwd=root)
        cc_data = self._parse_json(cc_stdout, cc_rc, cc_stderr)

        # Maintainability index
        mi_args = ["radon", "mi", "-j", "-s"] + exclude_args + targets
        mi_stdout, mi_stderr, mi_rc = _run_command(mi_args, cwd=root)
        mi_data = self._parse_json(mi_stdout, mi_rc, mi_stderr)

        errors = []
        if isinstance(cc_data, str):
            errors.append(cc_data)
            cc_data = {}
        if isinstance(mi_data, str):
            errors.append(mi_data)
            mi_data = {}

        if errors and not cc_data and not mi_data:
            return ToolResult(tool="radon", available=True, error="; ".join(errors))

        findings: list[Finding] = []
        complexities: list[int] = []
        rank_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0}

        for file_path, functions in cc_data.items():
            if not isinstance(functions, list):
                continue
            for func in functions:
                complexity = func.get("complexity", 0)
                rank = func.get("rank", "A")
                complexities.append(complexity)
                rank_counts[rank] = rank_counts.get(rank, 0) + 1
                if rank not in ("A", "B"):
                    sev = "HIGH" if rank in ("E", "F") else "MEDIUM"
                    findings.append(Finding(
                        rule_id=f"CC:{rank}", severity=sev, confidence="HIGH",
                        message=f"{func.get('type', 'function')} '{func.get('name', '?')}' has CC {complexity} (rank {rank})",
                        file=file_path, line=func.get("lineno", 0), tool="radon",
                    ))

        mi_scores: list[float] = []
        for file_path, mi_info in mi_data.items():
            if isinstance(mi_info, dict):
                mi_scores.append(mi_info.get("mi", 0.0))

        radon_metrics: dict[str, float] = {"total_functions": len(complexities)}
        if complexities:
            sorted_cc = sorted(complexities)
            p90_idx = min(int(len(sorted_cc) * 0.9), len(sorted_cc) - 1)
            radon_metrics["avg_complexity"] = sum(complexities) / len(complexities)
            radon_metrics["max_complexity"] = max(complexities)
            radon_metrics["p90_complexity"] = sorted_cc[p90_idx]
        for rank, count in rank_counts.items():
            radon_metrics[f"rank_{rank}"] = count
        simple = rank_counts.get("A", 0) + rank_counts.get("B", 0)
        radon_metrics["simple_ratio"] = simple / len(complexities) if complexities else 1.0
        if mi_scores:
            radon_metrics["avg_mi"] = sum(mi_scores) / len(mi_scores)
            radon_metrics["min_mi"] = min(mi_scores)

        return ToolResult(
            tool="radon", available=True, findings=findings,
            metrics=radon_metrics, error="; ".join(errors) if errors else "",
        )

    @staticmethod
    def _parse_json(stdout: str, rc: int, stderr: str) -> dict | str:
        if rc != 0:
            return stderr or f"radon exited with code {rc}"
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            return f"Failed to parse radon JSON: {e}"


# -- Runner registry ---------------------------------------------------------


TOOL_RUNNERS: dict[str, type] = {
    "bandit": BanditRunner,
    "radon": RadonRunner,
}


def run_tools(
    tools: list[str],
    root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> dict[str, ToolResult]:
    """Run specified tools and return results."""
    results: dict[str, ToolResult] = {}
    for name in tools:
        runner_cls = TOOL_RUNNERS.get(name)
        if runner_cls:
            results[name] = runner_cls().run(root, scope, exclude)
    return results


def detect_available_tools() -> list[str]:
    """Return list of installed tool names."""
    return [name for name in TOOL_RUNNERS if _check_installed(name)]
