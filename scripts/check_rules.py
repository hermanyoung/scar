#!/usr/bin/env python3
"""Code rules checker — runs automated checks from docs/04-rules/*.jsonl.

Supports two modes:
  --all     Check all source files (CI, manual)
  (default) Check staged files only (pre-commit hook)

Usage:
    python scripts/check_rules.py              # Staged files only
    python scripts/check_rules.py --all        # Full codebase
    python scripts/check_rules.py --rule 002.7 # Run a single rule

Setup (one-time, after cloning):
    git config core.hooksPath .githooks
"""
from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src" / "security_review"


@dataclass
class Violation:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str


# ── Checks ────────────────────────────────────────────────────────────────


def check_relative_imports(path: Path, rel: str) -> list[Violation]:
    """001.1 — No relative imports."""
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"^\s*from\s+\.")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.match(line):
            violations.append(Violation(
                "001.1", "error", rel, i,
                "Relative import — use: from security_review.xxx import ...",
            ))
    return violations


def check_direct_logging(path: Path, rel: str) -> list[Violation]:
    """001.2 — No direct import logging."""
    if not rel.startswith("src/security_review/"):
        return []
    if rel.endswith("logging.py"):
        return []
    violations = []
    pattern = re.compile(r"^import logging\s*$")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.match(line):
            violations.append(Violation(
                "001.2", "error", rel, i,
                "Direct import logging — use: from security_review.logging import get_logger",
            ))
    return violations


def check_init_minimal(path: Path, rel: str) -> list[Violation]:
    """001.3 — __init__.py must be minimal."""
    if not rel.endswith("__init__.py"):
        return []
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if re.match(r"^(class |def [^_])", line):
            violations.append(Violation(
                "001.3", "error", rel, i,
                "Logic in __init__.py — move to a dedicated module",
            ))
    return violations


def check_subprocess_isolation(path: Path, rel: str) -> list[Violation]:
    """001.4 — Only tools/runner.py may call subprocess.

    Exempt: cli/ commands are the user-facing entry-point layer (test-rule
    shells out to opengrep, test-providers shells out to a script). The rule
    protects pipeline internals, not CLI wiring.
    """
    if not rel.startswith("src/security_review/"):
        return []
    if rel.endswith("tools/runner.py"):
        return []
    if "/cli/" in rel:
        return []
    violations = []
    patterns = [
        re.compile(r"create_subprocess_exec"),
        re.compile(r"create_subprocess_shell"),
        re.compile(r"subprocess\.(run|call|Popen|check_output)"),
    ]
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        for pat in patterns:
            if pat.search(line):
                violations.append(Violation(
                    "001.4", "error", rel, i,
                    "Subprocess call outside tools/runner.py — all execution goes through run_tool()",
                ))
    return violations


def check_no_shell_true(path: Path, rel: str) -> list[Violation]:
    """001.5 — Never shell=True."""
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"shell\s*=\s*True")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip().startswith(("#", '"', "'")):
            continue
        if pattern.search(line):
            violations.append(Violation(
                "001.5", "error", rel, i,
                "shell=True — command injection vector. Use list args with create_subprocess_exec.",
            ))
    return violations


def check_tools_no_pydantic_ai(path: Path, rel: str) -> list[Violation]:
    """001.6 — tools/ must not import pydantic_ai."""
    if "security_review/tools/" not in rel:
        return []
    violations = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if "pydantic_ai" in line and not line.strip().startswith("#"):
            violations.append(Violation(
                "001.6", "error", rel, i,
                "pydantic_ai import in tools/ — PydanticAI belongs in agents/",
            ))
    return violations


def check_agents_no_runner(path: Path, rel: str) -> list[Violation]:
    """001.7 — agents/ must not import tools/runner."""
    if "security_review/agents/" not in rel:
        return []
    violations = []
    pattern = re.compile(r"from security_review\.tools\.runner")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(Violation(
                "001.7", "error", rel, i,
                "Agent imports runner directly — use SecurityReviewDeps",
            ))
    return violations


def check_models_no_upward(path: Path, rel: str) -> list[Violation]:
    """001.8 — models/ must not import passes/, agents/, or tools/."""
    if "security_review/models/" not in rel:
        return []
    violations = []
    pattern = re.compile(r"from security_review\.(passes|agents|tools)")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(Violation(
                "001.8", "error", rel, i,
                "Model imports from upper layer — models are leaf dependencies",
            ))
    return violations


def check_file_size(path: Path, rel: str) -> list[Violation]:
    """002.1 — Files must not exceed 1000 lines."""
    if not rel.startswith("src/security_review/"):
        return []
    lines = path.read_text().splitlines()
    if len(lines) > 1000:
        return [Violation(
            "002.1", "error", rel, 1,
            f"File has {len(lines)} lines (limit: 1000)",
        )]
    return []


def check_bare_except(path: Path, rel: str) -> list[Violation]:
    """002.2 — No bare except clauses."""
    violations = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if re.match(r"^\s*except\s*:", line):
            violations.append(Violation(
                "002.2", "warning", rel, i, "Bare except: clause — catch specific exceptions",
            ))
    return violations


def check_todo_markers(path: Path, rel: str) -> list[Violation]:
    """002.3 — No TODO/FIXME/HACK/XXX."""
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(Violation(
                "002.3", "warning", rel, i, "TODO/FIXME marker in production code",
            ))
    return violations


def check_hardcoded_urls(path: Path, rel: str) -> list[Violation]:
    """002.4 — No hardcoded host/port/URL."""
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"(localhost|127\.0\.0\.1|:5432|:6379|:8080)")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            violations.append(Violation(
                "002.4", "error", rel, i, "Hardcoded URL/port — move to config",
            ))
    return violations


def check_sync_blocking(path: Path, rel: str) -> list[Violation]:
    """002.6 — No sync blocking calls in async context."""
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"(time\.sleep|requests\.(get|post)|urllib\.request)")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            violations.append(Violation(
                "002.6", "warning", rel, i, "Sync blocking call — use asyncio equivalent",
            ))
    return violations


def check_silent_exception_swallow(path: Path, rel: str) -> list[Violation]:
    """002.7 — No silent exception swallowing."""
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = node.body
        has_raise = any(isinstance(s, ast.Raise) for s in body)
        has_log = any(
            isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
            and any(kw in ast.dump(s.value) for kw in [
                "logger", "log", "warning", "error", "critical", "debug",
            ])
            for s in body
        )
        has_error_return = any(
            isinstance(s, ast.Return) and s.value and "Error" in ast.dump(s.value)
            for s in body
        )
        if not has_raise and not has_log and not has_error_return:
            violations.append(Violation(
                "002.7", "error", rel, node.lineno,
                "Silent exception swallow — add logging or re-raise",
            ))
    return violations


def check_hardcoded_secrets(path: Path, rel: str) -> list[Violation]:
    """003.1 — No hardcoded secrets."""
    # Skip test fixtures, eval samples, and rule test files — they contain
    # deliberately vulnerable code with hardcoded secrets (that's the point).
    if any(s in rel for s in ("tests/", "eval/", "config/rules/", "scripts/test_")):
        return []
    violations = []
    pattern = re.compile(
        r"""(api_key|password|token|secret)\s*=\s*['"][^'"]{10,}['"]""", re.I
    )
    skip = re.compile(r"(os\.getenv|\.env|Field\(|test_|conftest)")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line) and not skip.search(line):
            violations.append(Violation(
                "003.1", "error", rel, i, "Possible hardcoded secret",
            ))
    return violations


def check_os_getenv_fallback(path: Path, rel: str) -> list[Violation]:
    """003.5 — No os.getenv() with hardcoded fallbacks."""
    if not rel.startswith("src/security_review/"):
        return []
    if "test_" in rel or "conftest" in rel:
        return []
    violations = []
    pattern = re.compile(r"os\.(getenv|environ\.get)\s*\(.+,\s*['\"]")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(Violation(
                "003.5", "error", rel, i,
                "os.getenv() with hardcoded fallback — use Settings or YAML config",
            ))
    return violations


ALL_CHECKS = [
    check_relative_imports,
    check_direct_logging,
    check_init_minimal,
    check_subprocess_isolation,
    check_no_shell_true,
    check_tools_no_pydantic_ai,
    check_agents_no_runner,
    check_models_no_upward,
    check_file_size,
    check_bare_except,
    check_todo_markers,
    check_hardcoded_urls,
    check_sync_blocking,
    check_silent_exception_swallow,
    check_hardcoded_secrets,
    check_os_getenv_fallback,
]


# ── File discovery ────────────────────────────────────────────────────────


def get_staged_py_files() -> list[Path]:
    """Get staged Python files from git."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    return [
        PROJECT_ROOT / f
        for f in result.stdout.strip().splitlines()
        if f.endswith(".py")
    ]


def get_all_source_files() -> list[Path]:
    """Get all Python files under src/security_review/."""
    return sorted(SRC_DIR.rglob("*.py"))


# ── Output ────────────────────────────────────────────────────────────────

RED = "\033[31m"
YEL = "\033[33m"
GRN = "\033[32m"
RST = "\033[0m"
BOLD = "\033[1m"


def main() -> int:
    parser = argparse.ArgumentParser(description="Code rules checker for security-review")
    parser.add_argument("--all", action="store_true", help="Check all source files")
    parser.add_argument("--rule", type=str, default=None, help="Run a single rule (e.g. 002.7)")
    args = parser.parse_args()

    files = get_all_source_files() if args.all else get_staged_py_files()
    if not files:
        if not args.all:
            print("No staged Python files.")
        return 0

    checks = ALL_CHECKS
    if args.rule:
        checks = [c for c in ALL_CHECKS if args.rule in c.__doc__]
        if not checks:
            print(f"No check matches rule {args.rule}")
            return 1

    all_violations: list[Violation] = []
    for path in files:
        if not path.exists():
            continue
        rel = str(path.relative_to(PROJECT_ROOT))
        for check_fn in checks:
            all_violations.extend(check_fn(path, rel))

    errors = [v for v in all_violations if v.severity == "error"]
    warnings = [v for v in all_violations if v.severity == "warning"]

    if errors:
        print(f"\n{RED}{BOLD}Check failed ({len(errors)} errors){RST}\n")
        for v in sorted(errors, key=lambda x: (x.rule_id, x.file, x.line)):
            print(f"  {RED}[{v.rule_id}]{RST} {v.file}:{v.line} — {v.message}")

    if warnings:
        print(f"\n{YEL}Warnings ({len(warnings)}):{RST}")
        for v in sorted(warnings, key=lambda x: (x.rule_id, x.file, x.line)):
            print(f"  {YEL}[{v.rule_id}]{RST} {v.file}:{v.line} — {v.message}")

    if not errors and not warnings:
        print(f"{GRN}All {len(ALL_CHECKS)} rules passed across {len(files)} files.{RST}")

    if errors:
        print(f"\n{RED}Fix errors above.{RST}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
