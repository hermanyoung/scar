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
    """002.3 — No TODO/FIXME/HACK/XXX.

    Excludes the "SR-XXX-NNN" rule-ID placeholder idiom (e.g. in docstrings
    documenting the holistic finding ID format) — that XXX is a category
    placeholder, not a stale-work marker.
    """
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"\b(TODO|FIXME|HACK)\b|(?<!SR-)\bXXX\b")
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


def check_untyped_kwargs(path: Path, rel: str) -> list[Violation]:
    """002.5 — No untyped **kwargs in public functions."""
    if not rel.startswith("src/security_review/"):
        return []
    if rel.endswith("logging.py") or "test_" in rel or "conftest" in rel:
        return []
    violations = []
    pattern = re.compile(r"def [a-z]\w+\(.*\*\*kwargs")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(Violation(
                "002.5", "error", rel, i,
                "Untyped **kwargs in public function — use explicit params or TypedDict",
            ))
    return violations


def check_config_schema_extra_forbid(path: Path, rel: str) -> list[Violation]:
    """003.4 — Config schemas must use extra='forbid' to catch unknown keys."""
    if rel != "src/security_review/config_schema.py":
        return []
    if not re.search(r"extra=.forbid.", path.read_text()):
        return [Violation(
            "003.4", "error", rel, 1,
            "No extra='forbid' found — config schemas must reject unknown YAML keys",
        )]
    return []


def check_hardcoded_pricing(path: Path, rel: str) -> list[Violation]:
    """003.6 — No hardcoded pricing; must come from config/pricing.yaml.

    Matches an actual literal value assigned to a pricing-shaped name (or a
    bare dollar literal), not the mere presence of a field name — Pydantic
    type annotations like `input_per_token: float` in budget.py's
    ModelPricing schema are the correct place pricing is *typed*, not a
    hardcoded value, and must not trip this check.
    """
    if not rel.startswith("src/security_review/"):
        return []
    violations = []
    pattern = re.compile(r"(per_token|cost_per|price_per)\s*[:=]\s*[0-9]|\$[0-9]+\.[0-9]+")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            violations.append(Violation(
                "003.6", "error", rel, i,
                "Hardcoded pricing value — must come from config/pricing.yaml",
            ))
    return violations


def _docstring_line_ranges(tree: ast.AST) -> set[int]:
    """Line numbers covered by any module/class/function docstring in `tree`."""
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            end = first.end_lineno or first.lineno
            lines.update(range(first.lineno, end + 1))
    return lines


# Provider adapters legitimately hardcode a fallback model_id used only when
# the caller doesn't override it — the actual model always comes from
# config/settings/security_review.yaml at call time. model_settings.py's
# adaptive-thinking model-family table is capability detection, not model
# selection. config_schema.py/providers.py are the config layer itself.
_MODEL_STRING_EXEMPT_FILES = (
    "config_schema.py", "copilot_model.py", "claude_model.py",
    "codex_model.py", "model_settings.py", "providers.py",
)


def check_hardcoded_model_strings(path: Path, rel: str) -> list[Violation]:
    """003.7 — No hardcoded model strings; must come from config."""
    if not rel.startswith("src/security_review/"):
        return []
    if any(rel.endswith(f) for f in _MODEL_STRING_EXEMPT_FILES):
        return []
    if "test_" in rel or "conftest" in rel:
        return []

    text = path.read_text()
    try:
        docstring_lines = _docstring_line_ranges(ast.parse(text))
    except SyntaxError:
        docstring_lines = set()

    violations = []
    pattern = re.compile(r"(gpt-[0-9]|claude-|o[0-9]-mini)")
    for i, line in enumerate(text.splitlines(), 1):
        if i in docstring_lines:
            continue
        if line.strip().startswith("#") or "help=" in line or "examples.add(" in line:
            continue
        if pattern.search(line):
            violations.append(Violation(
                "003.7", "error", rel, i,
                "Hardcoded model string — must come from config.llm.provider_model",
            ))
    return violations


def check_cwe_id_validator(path: Path, rel: str) -> list[Violation]:
    """004.1 — cwe_id fields must be normalised to CWE-NNN format.

    findings.py uses a @field_validator (normalise_cwe_id) that auto-repairs
    any input into CWE-NNN format rather than a rigid Field(pattern=...)
    that would reject malformed LLM output — see the architecture overview's
    "auto-repair, not reject" decision. This checks for that validator.
    """
    if rel != "src/security_review/models/findings.py":
        return []
    if not re.search(r'@field_validator\("cwe_id"', path.read_text()):
        return [Violation(
            "004.1", "error", rel, 1,
            "No cwe_id field_validator — findings must normalise cwe_id to CWE-NNN format",
        )]
    return []


def check_output_parser_return_types(path: Path, rel: str) -> list[Violation]:
    """004.2 — output_parser functions must return Pydantic models, not str/dict.

    Agents themselves deliberately use output_type=str (ADR-004/ADR-006) —
    that is correct, not a violation. The actual safeguard is that
    output_parser.py's parse_* functions, which extract structured data
    from that text, are typed to return a Pydantic model (or None).
    """
    if rel != "src/security_review/output_parser.py":
        return []
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("parse_"):
            continue
        if node.returns is None:
            continue
        return_str = ast.unparse(node.returns)
        if re.fullmatch(r"(str|dict)(\s*\|\s*None)?", return_str):
            violations.append(Violation(
                "004.2", "error", rel, node.lineno,
                f"{node.name} returns {return_str} — must return a Pydantic model (or None)",
            ))
    return violations


def check_sarif_version_2_1_0(path: Path, rel: str) -> list[Violation]:
    """004.3 — SARIF output must be version 2.1.0."""
    if rel != "src/security_review/sarif/merger.py":
        return []
    if not re.search(r"version.*2\.1\.0", path.read_text()):
        return [Violation("004.3", "error", rel, 1, "merger.py does not set SARIF version 2.1.0")]
    return []


def check_sarif_uri_forward_slashes(path: Path, rel: str) -> list[Violation]:
    """004.4 — SARIF artifactLocation.uri must use forward slashes, never backslashes.

    Scoped to sarif/ and passes/sast.py, where SARIF URIs are actually
    constructed — a blanket src/security_review/ scope would also match
    unrelated Windows-path-string handling (e.g. cli/tools.py's
    --language matching), which has nothing to do with SARIF output.
    """
    if not (rel.startswith("src/security_review/sarif/") or rel == "src/security_review/passes/sast.py"):
        return []
    violations = []
    pattern = re.compile(r"os\.sep|os\.path\.sep")
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if "replace(" in line:
            continue  # e.g. .replace("\\", "/") is the correct normalisation pattern
        if pattern.search(line):
            violations.append(Violation(
                "004.4", "error", rel, i,
                "os.sep/os.path.sep in SARIF path handling — use forward slashes",
            ))
    return violations


def check_taxonomy_injection_exists(path: Path, rel: str) -> list[Violation]:
    """004.5 — SARIF output must inject CWE taxonomy."""
    if rel != "src/security_review/sarif/taxonomy.py":
        return []
    if "inject_taxonomy" not in path.read_text():
        return [Violation(
            "004.5", "error", rel, 1,
            "No inject_taxonomy() found — CWE taxonomy block would be missing from SARIF",
        )]
    return []


def check_cwe_tag_normalisation_exists(path: Path, rel: str) -> list[Violation]:
    """004.6 — CWE tags must be normalised to external/cwe/cwe-NNN format."""
    if rel != "src/security_review/sarif/tags.py":
        return []
    if "external/cwe/cwe-" not in path.read_text():
        return [Violation(
            "004.6", "error", rel, 1,
            "tags.py does not normalise to the external/cwe/cwe-NNN convention",
        )]
    return []


def check_sarif_uri_normalization_called(path: Path, rel: str) -> list[Violation]:
    """004.9 — SARIF URIs must be normalised to relative paths at SAST output time."""
    if rel != "src/security_review/passes/sast.py":
        return []
    if "_normalize_sarif_uris" not in path.read_text():
        return [Violation(
            "004.9", "error", rel, 1,
            "sast.py does not call _normalize_sarif_uris() — SARIF may leak absolute paths",
        )]
    return []


# ── Repo-level checks (not per-file) ────────────────────────────────────────


def check_env_gitignored() -> list[Violation]:
    """003.2 — .env must be gitignored."""
    gitignore = PROJECT_ROOT / ".gitignore"
    if not gitignore.exists():
        return [Violation("003.2", "error", ".gitignore", 1, ".gitignore file not found")]
    if not re.search(r"^\.env$", gitignore.read_text(), re.MULTILINE):
        return [Violation("003.2", "error", ".gitignore", 1, ".env is not gitignored")]
    return []


def check_yaml_settings_have_headers() -> list[Violation]:
    """003.3 — All YAML config files must have a commented options header."""
    violations = []
    settings_dir = PROJECT_ROOT / "config" / "settings"
    for f in sorted(settings_dir.glob("*.yaml")):
        lines = f.read_text().splitlines()
        if not lines or not lines[0].startswith("#"):
            rel = str(f.relative_to(PROJECT_ROOT))
            violations.append(Violation(
                "003.3", "error", rel, 1, "Missing '#' options header at top of file",
            ))
    return violations


def check_cwe_ids_in_taxonomy() -> list[Violation]:
    """004.7 — All CWE IDs referenced in OpenGrep rules must exist in the taxonomy.

    The taxonomy stores bare numeric YAML keys (e.g. "22":), not literal
    "CWE-22" strings, so CWE numbers are compared numerically rather than
    as literal substrings of the taxonomy file.
    """
    taxonomy_path = PROJECT_ROOT / "config" / "taxonomy" / "cwe.yaml"
    rules_dir = PROJECT_ROOT / "config" / "rules" / "opengrep"
    if not taxonomy_path.exists() or not rules_dir.exists():
        return []

    taxonomy_ids: set[str] = set()
    for line in taxonomy_path.read_text().splitlines():
        m = re.match(r'^"?(\d+)"?:', line)
        if m:
            taxonomy_ids.add(m.group(1))

    violations = []
    reported: set[str] = set()
    for f in sorted(rules_dir.rglob("*.yaml")):
        rel = str(f.relative_to(PROJECT_ROOT))
        for m in re.finditer(r"CWE-(\d+)", f.read_text()):
            cwe_num = m.group(1)
            if cwe_num not in taxonomy_ids and cwe_num not in reported:
                reported.add(cwe_num)
                violations.append(Violation(
                    "004.7", "error", rel, 1,
                    f"CWE-{cwe_num} referenced in rules but missing from config/taxonomy/cwe.yaml",
                ))
    return violations


def check_opengrep_rules_have_tests() -> list[Violation]:
    """004.8 — Every OpenGrep rule must have a matching test file."""
    rules_dir = PROJECT_ROOT / "config" / "rules" / "opengrep"
    if not rules_dir.exists():
        return []
    violations = []
    for f in sorted(rules_dir.rglob("*.yaml")):
        candidates = [f.with_suffix(ext) for ext in (".py", ".cs", ".dockerfile")]
        if not any(c.exists() for c in candidates):
            rel = str(f.relative_to(PROJECT_ROOT))
            violations.append(Violation(
                "004.8", "error", rel, 1,
                "No matching test file (.py/.cs/.dockerfile) with ruleid:/ok: annotations",
            ))
    return violations


REPO_CHECKS = [
    check_env_gitignored,
    check_yaml_settings_have_headers,
    check_cwe_ids_in_taxonomy,
    check_opengrep_rules_have_tests,
]


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
    check_untyped_kwargs,
    check_config_schema_extra_forbid,
    check_hardcoded_pricing,
    check_hardcoded_model_strings,
    check_cwe_id_validator,
    check_output_parser_return_types,
    check_sarif_version_2_1_0,
    check_sarif_uri_forward_slashes,
    check_taxonomy_injection_exists,
    check_cwe_tag_normalisation_exists,
    check_sarif_uri_normalization_called,
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

    per_file_checks = ALL_CHECKS
    repo_checks = REPO_CHECKS
    if args.rule:
        per_file_checks = [c for c in ALL_CHECKS if args.rule in c.__doc__]
        repo_checks = [c for c in REPO_CHECKS if args.rule in c.__doc__]
        if not per_file_checks and not repo_checks:
            print(f"No check matches rule {args.rule}")
            return 1

    if not files and not repo_checks:
        if not args.all:
            print("No staged Python files.")
        return 0

    if not files and not args.all:
        print("No staged Python files — running repo-level checks only.")

    all_violations: list[Violation] = []
    for path in files:
        if not path.exists():
            continue
        rel = str(path.relative_to(PROJECT_ROOT))
        for check_fn in per_file_checks:
            all_violations.extend(check_fn(path, rel))

    # Repo-level checks (config/.gitignore/CWE-taxonomy invariants) always
    # run — they don't depend on which Python files happen to be staged.
    for repo_check_fn in repo_checks:
        all_violations.extend(repo_check_fn())

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
        total_rules = len(per_file_checks) + len(repo_checks)
        print(f"{GRN}All {total_rules} rule(s) passed across {len(files)} files.{RST}")

    if errors:
        print(f"\n{RED}Fix errors above.{RST}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
