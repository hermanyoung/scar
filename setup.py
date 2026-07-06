#!/usr/bin/env python3
"""SCAR — Environment Setup & Health Check.

Idempotent setup script that detects the OS, checks all dependencies
(Python packages + external SAST tools + LLM provider auth), and guides
the user through installing or updating anything that's missing.

Run as often as you like:
    python setup.py           # Full check
    python setup.py --fix     # Auto-install what's missing (non-interactive)
    python setup.py --check   # Exit 0 if ready, 1 if not (CI mode)
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
MIN_PYTHON = (3, 11)

# Python packages: (import_name, pip_name, min_version)
# Must stay in sync with requirements.txt and pyproject.toml [project.dependencies].
PYTHON_PACKAGES: list[tuple[str, str, str]] = [
    ("pydantic", "pydantic", "2.7"),
    ("pydantic_settings", "pydantic-settings", "2.7"),
    ("yaml", "pyyaml", "6.0"),
    ("click", "click", "8.0"),
    ("structlog", "structlog", "24.0"),
    ("rich", "rich", "13.0"),
    ("tree_sitter", "tree-sitter", "0.23"),
    ("tree_sitter_c_sharp", "tree-sitter-c-sharp", "0.23"),
    ("pydantic_ai", "pydantic-ai[openai,anthropic]", "0.2.14"),
    ("json_repair", "json-repair", "0.30"),
    ("bandit", "bandit[sarif]", "1.9.4"),
    ("pytest", "pytest", "8.0"),
    ("pytest_asyncio", "pytest-asyncio", "0.24"),
]

# External SAST tools: (binary, version_cmd, min_version, install_instructions)
# version_cmd returns a string; we extract the first semver-like token.
@dataclass
class ExternalTool:
    name: str
    binary: str
    version_cmd: list[str]
    min_version: str | None
    required: bool
    install: dict[str, str]  # os -> instruction


EXTERNAL_TOOLS: list[ExternalTool] = [
    ExternalTool(
        name="OpenGrep (SAST pattern scanner)",
        binary="opengrep",
        version_cmd=["opengrep", "--version"],
        min_version="1.19.0",
        required=True,
        install={
            "darwin": "brew install opengrep",
            "linux": "pip install opengrep  # or download from github.com/opengrep/opengrep/releases",
            "win32": "pip install opengrep",
        },
    ),
    ExternalTool(
        name="Betterleaks (secret scanner)",
        binary="betterleaks",
        version_cmd=["betterleaks", "version"],
        min_version=None,
        required=True,
        install={
            "darwin": "brew install betterleaks  # or: go install github.com/zricethezav/betterleaks@latest",
            "linux": "go install github.com/zricethezav/betterleaks@latest  # or download binary from releases",
            "win32": "go install github.com/zricethezav/betterleaks@latest",
        },
    ),
    ExternalTool(
        name="Hadolint (Dockerfile linter)",
        binary="hadolint",
        version_cmd=["hadolint", "--version"],
        min_version=None,
        required=False,
        install={
            "darwin": "brew install hadolint",
            "linux": "wget -qO /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint",
            "win32": "scoop install hadolint",
        },
    ),
    ExternalTool(
        name="Trivy (SCA vulnerability scanner)",
        binary="trivy",
        version_cmd=["trivy", "--version"],
        min_version=None,
        required=False,
        install={
            "darwin": "brew install trivy",
            "linux": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
            "win32": "scoop install trivy",
        },
    ),
    ExternalTool(
        name=".NET SDK (Roslyn + dotnet-vuln)",
        binary="dotnet",
        version_cmd=["dotnet", "--version"],
        min_version="8.0.0",
        required=False,
        install={
            "darwin": "brew install dotnet",
            "linux": "See https://learn.microsoft.com/en-us/dotnet/core/install/linux",
            "win32": "winget install Microsoft.DotNet.SDK.8",
        },
    ),
    ExternalTool(
        name="GitHub Copilot SDK",
        binary="github-copilot-sdk",
        version_cmd=["pip", "show", "github-copilot-sdk"],
        min_version=None,
        required=False,
        install={
            "darwin": "pip install github-copilot-sdk==0.2.2",
            "linux": "pip install github-copilot-sdk==0.2.2",
            "win32": "pip install github-copilot-sdk==0.2.2",
        },
    ),
    ExternalTool(
        name="Claude Agent SDK",
        binary="claude-agent-sdk",
        version_cmd=["pip", "show", "claude-agent-sdk"],
        min_version="0.1.63",
        required=False,
        install={
            "darwin": "pip install claude-agent-sdk",
            "linux": "pip install claude-agent-sdk",
            "win32": "pip install claude-agent-sdk",
        },
    ),
    ExternalTool(
        name="Codex CLI (GPT provider)",
        binary="codex",
        version_cmd=["codex", "--version"],
        min_version=None,
        required=False,
        install={
            "darwin": "brew install codex",
            "linux": "See https://github.com/openai/codex/releases",
            "win32": "See https://github.com/openai/codex/releases",
        },
    ),
]


# ---------------------------------------------------------------------------
# Styling helpers (no external deps — works before rich is installed)
# ---------------------------------------------------------------------------

class _C:
    """ANSI colour codes — disabled if NO_COLOR is set or not a terminal."""
    _enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""
    RED = "\033[31m" if _enabled else ""
    GREEN = "\033[32m" if _enabled else ""
    YELLOW = "\033[33m" if _enabled else ""
    BLUE = "\033[34m" if _enabled else ""
    CYAN = "\033[36m" if _enabled else ""


class Status(Enum):
    OK = "ok"
    UPDATE = "update"
    MISSING = "missing"
    ERROR = "error"
    SKIP = "skip"


_STATUS_ICONS = {
    Status.OK: f"{_C.GREEN}OK{_C.RESET}",
    Status.UPDATE: f"{_C.YELLOW}UPDATE{_C.RESET}",
    Status.MISSING: f"{_C.RED}MISSING{_C.RESET}",
    Status.ERROR: f"{_C.RED}ERROR{_C.RESET}",
    Status.SKIP: f"{_C.DIM}SKIP{_C.RESET}",
}


@dataclass
class CheckResult:
    name: str
    status: Status
    current_version: str = ""
    required_version: str = ""
    detail: str = ""
    fix_cmd: str = ""
    required: bool = True


def _print_result(r: CheckResult) -> None:
    icon = _STATUS_ICONS[r.status]
    ver = ""
    if r.current_version:
        ver = f" {_C.DIM}v{r.current_version}{_C.RESET}"
        if r.status == Status.UPDATE and r.required_version:
            ver += f" {_C.YELLOW}(need >={r.required_version}){_C.RESET}"
    req = "" if r.required else f" {_C.DIM}(optional){_C.RESET}"
    print(f"  [{icon}] {r.name}{ver}{req}")
    if r.detail:
        print(f"         {_C.DIM}{r.detail}{_C.RESET}")


def _section(title: str) -> None:
    print(f"\n{_C.BOLD}{_C.CYAN}{'=' * 60}{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}  {title}{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}{'=' * 60}{_C.RESET}\n")


def _subsection(title: str) -> None:
    print(f"\n  {_C.BOLD}{title}{_C.RESET}")
    print(f"  {'-' * 40}")


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, ...]:
    """Parse '1.23.4' into (1, 23, 4). Tolerates pre-release suffixes."""
    import re
    match = re.match(r"(\d+(?:\.\d+)*)", v.strip())
    if not match:
        return (0,)
    return tuple(int(x) for x in match.group(1).split("."))


def _version_gte(current: str, minimum: str) -> bool:
    return _parse_version(current) >= _parse_version(minimum)


def _extract_version_from_output(text: str) -> str:
    """Extract the first semver-like token from command output."""
    import re
    match = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9._-]*))", text)
    return match.group(1) if match else ""


def _run_quiet(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", "not found", 127
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except OSError as e:
        return "", str(e), -1


# ---------------------------------------------------------------------------
# Check: Operating System
# ---------------------------------------------------------------------------

def check_os() -> dict[str, str]:
    _section("Operating System")
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "platform_key": sys.platform,  # darwin, linux, win32
    }
    print(f"  System:   {info['system']} {info['release']}")
    print(f"  Arch:     {info['machine']}")
    print(f"  Platform: {info['platform_key']}")

    if info["platform_key"] not in ("darwin", "linux", "win32"):
        print(f"\n  {_C.YELLOW}Warning: Untested platform. Install commands may need adjustment.{_C.RESET}")

    return info


# ---------------------------------------------------------------------------
# Check: Python version
# ---------------------------------------------------------------------------

def check_python() -> CheckResult:
    _subsection("Python")
    v = sys.version_info
    current = f"{v.major}.{v.minor}.{v.micro}"
    required = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"

    if v >= MIN_PYTHON:
        r = CheckResult("Python", Status.OK, current, required)
    else:
        r = CheckResult(
            "Python", Status.ERROR, current, required,
            detail=f"Python >={required} required. Current: {current}",
        )
    _print_result(r)
    print(f"         {_C.DIM}Executable: {sys.executable}{_C.RESET}")
    return r


# ---------------------------------------------------------------------------
# Check: Python packages
# ---------------------------------------------------------------------------

def _check_one_package(import_name: str, pip_name: str, min_version: str) -> CheckResult:
    """Check if a Python package is installed and meets the minimum version."""
    # Derive the distribution name for importlib.metadata lookup
    dist_name = pip_name.split("[")[0]  # strip extras like [sarif]

    try:
        dist = importlib.metadata.distribution(dist_name)
        installed_version = dist.version
    except importlib.metadata.PackageNotFoundError:
        return CheckResult(
            pip_name, Status.MISSING, "", min_version,
            fix_cmd=f"pip install {pip_name}>={min_version}",
        )

    if _version_gte(installed_version, min_version):
        return CheckResult(pip_name, Status.OK, installed_version, min_version)
    else:
        return CheckResult(
            pip_name, Status.UPDATE, installed_version, min_version,
            detail=f"Installed {installed_version}, need >={min_version}",
            fix_cmd=f"pip install --upgrade {pip_name}>={min_version}",
        )


def check_python_packages() -> list[CheckResult]:
    _subsection("Python Packages")
    results = []
    for import_name, pip_name, min_version in PYTHON_PACKAGES:
        r = _check_one_package(import_name, pip_name, min_version)
        _print_result(r)
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Check: External tools
# ---------------------------------------------------------------------------

def _check_one_tool(tool: ExternalTool, os_key: str) -> CheckResult:
    """Check if an external tool is installed and meets minimum version."""
    # Special handling for pip-based tools checked via `pip show`
    if tool.version_cmd and tool.version_cmd[0] == "pip":
        stdout, stderr, rc = _run_quiet(tool.version_cmd)
        if rc != 0:
            return CheckResult(
                tool.name, Status.MISSING, "", tool.min_version or "",
                detail=tool.install.get(os_key, "See project docs for install instructions"),
                fix_cmd=tool.install.get(os_key, ""),
                required=tool.required,
            )
        version = ""
        for line in stdout.splitlines():
            if line.lower().startswith("version:"):
                version = line.split(":", 1)[1].strip()
                break
        return CheckResult(tool.name, Status.OK, version, tool.min_version or "", required=tool.required)

    # Standard binary check
    binary_path = shutil.which(tool.binary)
    if not binary_path:
        return CheckResult(
            tool.name, Status.MISSING, "", tool.min_version or "",
            detail=tool.install.get(os_key, "See project docs for install instructions"),
            fix_cmd=tool.install.get(os_key, ""),
            required=tool.required,
        )

    # Get version
    stdout, stderr, rc = _run_quiet(tool.version_cmd)
    output = stdout + stderr
    version = _extract_version_from_output(output)

    if not version:
        # Binary exists but version unreadable — still OK
        return CheckResult(tool.name, Status.OK, "?", tool.min_version or "", required=tool.required)

    if tool.min_version and not _version_gte(version, tool.min_version):
        return CheckResult(
            tool.name, Status.UPDATE, version, tool.min_version,
            detail=f"Installed {version}, need >={tool.min_version}",
            fix_cmd=tool.install.get(os_key, ""),
            required=tool.required,
        )

    return CheckResult(tool.name, Status.OK, version, tool.min_version or "", required=tool.required)


def check_external_tools(os_key: str) -> list[CheckResult]:
    _subsection("External SAST Tools")
    results = []
    for tool in EXTERNAL_TOOLS:
        r = _check_one_tool(tool, os_key)
        _print_result(r)
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Check: Project structure
# ---------------------------------------------------------------------------

def check_project_structure() -> list[CheckResult]:
    _subsection("Project Structure")

    paths_to_check = [
        (".project_root", True),
        ("config/settings/security_review.yaml", True),
        ("config/settings/logging.yaml", True),
        ("config/pricing.yaml", True),
        ("config/models.yaml", True),
        ("config/providers.yaml", True),
        ("config/prompts/triage.md", True),
        ("config/prompts/config_review.md", True),
        ("config/taxonomy/cwe.yaml", True),
        ("config/rules/opengrep", True),
        ("config/rules/gitleaks/.gitleaks.toml", True),
    ]

    results = []
    for rel_path, required in paths_to_check:
        full = SCRIPT_DIR / rel_path
        exists = full.exists()
        r = CheckResult(
            rel_path,
            Status.OK if exists else Status.MISSING,
            detail="" if exists else "File or directory not found",
            required=required,
        )
        _print_result(r)
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Check: Git hooks
# ---------------------------------------------------------------------------

def check_git_hooks() -> CheckResult:
    _subsection("Git Hooks")

    hooks_dir = SCRIPT_DIR / ".githooks"
    if not hooks_dir.is_dir():
        r = CheckResult(
            "Git hooks path", Status.SKIP,
            detail=".githooks/ directory not found -- skipping",
            required=False,
        )
        _print_result(r)
        return r

    stdout, stderr, rc = _run_quiet(["git", "config", "core.hooksPath"])
    if rc != 0:
        r = CheckResult(
            "Git hooks path", Status.ERROR, "",
            detail="Not a git repository or git is unavailable",
            required=False,
        )
        _print_result(r)
        return r

    configured = stdout.strip()
    is_wired = configured and (SCRIPT_DIR / configured).resolve() == hooks_dir.resolve()

    if is_wired:
        r = CheckResult(
            "Git hooks path", Status.OK,
            detail=f"core.hooksPath = {configured}",
        )
        _print_result(r)
        return r

    detail = f"core.hooksPath is '{configured}'" if configured else "core.hooksPath is not set"
    r = CheckResult(
        "Git hooks path", Status.MISSING, "",
        detail=(
            f"{detail} -- .githooks/pre-commit and .githooks/commit-msg "
            "never run (structural rules, code map, quality report, commit-msg lint)"
        ),
        fix_cmd="git config core.hooksPath .githooks",
        required=True,
    )
    _print_result(r)
    return r


# ---------------------------------------------------------------------------
# Check: editable install
# ---------------------------------------------------------------------------

def check_editable_install() -> CheckResult:
    _subsection("Package Install")

    r = CheckResult(
        "scar", Status.OK,
        detail="Run with: python scar.py (no pip install needed)",
    )
    _print_result(r)
    return r


# ---------------------------------------------------------------------------
# Shared: configured LLM provider
# ---------------------------------------------------------------------------

def _get_configured_provider() -> str:
    """Read llm.provider_model from config/settings/security_review.yaml.

    Returns the full "provider:model" string. Falls back to the documented
    default if the file is missing or malformed, logging why rather than
    silently swallowing the error.
    """
    settings_path = SCRIPT_DIR / "config" / "settings" / "security_review.yaml"
    default_provider = "copilot:claude-sonnet"
    if not settings_path.exists():
        return default_provider
    try:
        import yaml
        with open(settings_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("llm", {}).get("provider_model", default_provider)
    except (yaml.YAMLError, OSError) as e:
        print(f"  {_C.YELLOW}Warning: could not read {settings_path}: {e}{_C.RESET}")
        return default_provider


# ---------------------------------------------------------------------------
# Check: GitHub Copilot authentication
# ---------------------------------------------------------------------------

def check_copilot_auth(provider: str) -> CheckResult:
    """Only relevant when the configured provider is actually `copilot`.

    Other providers (openai, anthropic, claude, codex) never touch GitHub
    Copilot auth, so requiring `gh auth login` for them was a bug — every
    non-copilot setup was reported as "not ready" regardless of whether it
    actually worked.
    """
    _subsection("GitHub Copilot Authentication")

    if provider != "copilot":
        r = CheckResult(
            "GitHub Copilot Authentication", Status.SKIP,
            detail=f"Configured provider is '{provider}', not copilot -- skipping",
            required=False,
        )
        _print_result(r)
        return r

    # Check if gh CLI is available
    gh_path = shutil.which("gh")
    if not gh_path:
        r = CheckResult(
            "GitHub CLI (gh)", Status.MISSING, "",
            detail="Install GitHub CLI first, then run: gh auth login && gh extension install github/gh-copilot",
            fix_cmd="brew install gh" if sys.platform == "darwin" else "See https://cli.github.com/",
            required=True,
        )
        _print_result(r)
        return r

    # Check gh auth status
    stdout, stderr, rc = _run_quiet(["gh", "auth", "status"])
    output = stdout + stderr
    if rc != 0 or "not logged in" in output.lower():
        r = CheckResult(
            "GitHub CLI auth", Status.MISSING, "",
            detail="Not authenticated. Run: gh auth login",
            fix_cmd="gh auth login",
            required=True,
        )
        _print_result(r)
        return r

    # Extract username
    username = ""
    for line in output.splitlines():
        if "logged in" in line.lower():
            # "Logged in to github.com account username (..."
            import re
            match = re.search(r"account\s+(\S+)", line)
            if match:
                username = match.group(1).rstrip("(").strip()
            break

    r = CheckResult(
        "GitHub CLI auth", Status.OK,
        detail=f"Authenticated as: {username}" if username else "Authenticated",
    )
    _print_result(r)

    return r


# ---------------------------------------------------------------------------
# Check: LLM provider availability
# ---------------------------------------------------------------------------

def check_providers(configured_provider: str) -> list[CheckResult]:
    _subsection("LLM Provider Configuration")
    results = []

    provider, _, model = configured_provider.partition(":")
    print(f"\n  Configured provider: {_C.BOLD}{configured_provider}{_C.RESET}")

    # Check provider-specific auth
    if provider == "copilot":
        # Copilot uses gh auth — already checked above.
        # Verify the SDK is importable.
        try:
            importlib.metadata.distribution("github-copilot-sdk")
            r = CheckResult(
                f"Copilot SDK (model: {model})", Status.OK,
                detail="github-copilot-sdk installed; auth via GitHub CLI",
            )
        except importlib.metadata.PackageNotFoundError:
            r = CheckResult(
                f"Copilot SDK (model: {model})", Status.MISSING, "",
                detail="Required for copilot: provider",
                fix_cmd="pip install github-copilot-sdk",
            )
        _print_result(r)
        results.append(r)

    elif provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if key:
            masked = key[:8] + "..." + key[-4:] if len(key) > 12 else "***"
            r = CheckResult(
                f"OpenAI API key (model: {model})", Status.OK,
                detail=f"OPENAI_API_KEY set ({masked})",
            )
        else:
            r = CheckResult(
                f"OpenAI API key (model: {model})", Status.MISSING, "",
                detail="Set OPENAI_API_KEY in your environment or .env file",
                fix_cmd="export OPENAI_API_KEY='sk-...'",
            )
        _print_result(r)
        results.append(r)

    elif provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if key:
            masked = key[:8] + "..." + key[-4:] if len(key) > 12 else "***"
            r = CheckResult(
                f"Anthropic API key (model: {model})", Status.OK,
                detail=f"ANTHROPIC_API_KEY set ({masked})",
            )
        else:
            r = CheckResult(
                f"Anthropic API key (model: {model})", Status.MISSING, "",
                detail="Set ANTHROPIC_API_KEY in your environment or .env file",
                fix_cmd="export ANTHROPIC_API_KEY=<your-key>",
            )
        _print_result(r)
        results.append(r)

    elif provider == "claude":
        # Claude Agent SDK uses CLAUDE_CODE_OAUTH_TOKEN (Max/Pro subscription)
        token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
        try:
            importlib.metadata.distribution("claude-agent-sdk")
            sdk_ok = True
        except importlib.metadata.PackageNotFoundError:
            sdk_ok = False

        if sdk_ok and token:
            r = CheckResult(
                f"Claude Agent SDK (model: {model})", Status.OK,
                detail="claude-agent-sdk installed; CLAUDE_CODE_OAUTH_TOKEN set",
            )
        elif sdk_ok and not token:
            r = CheckResult(
                f"Claude Agent SDK (model: {model})", Status.OK,
                detail="claude-agent-sdk installed; token resolved at runtime via CLI auth",
            )
        else:
            r = CheckResult(
                f"Claude Agent SDK (model: {model})", Status.MISSING, "",
                detail="Required for claude: provider",
                fix_cmd="pip install claude-agent-sdk",
            )
        _print_result(r)
        results.append(r)

    elif provider == "codex":
        # Codex uses codex_app_server SDK (ChatGPT Plus/Pro subscription)
        try:
            importlib.metadata.distribution("codex_app_server")
            r = CheckResult(
                f"Codex SDK (model: {model})", Status.OK,
                detail="codex_app_server installed; auth via ChatGPT subscription",
            )
        except importlib.metadata.PackageNotFoundError:
            r = CheckResult(
                f"Codex SDK (model: {model})", Status.MISSING, "",
                detail="Required for codex: provider. Install Codex CLI first: brew install codex",
                fix_cmd="brew install codex",
            )
        _print_result(r)
        results.append(r)

    else:
        r = CheckResult(
            f"Provider: {provider}", Status.ERROR, "",
            detail=f"Unknown provider '{provider}'. Supported: copilot, claude, anthropic, openai, codex",
        )
        _print_result(r)
        results.append(r)

    # Check model alias resolution
    models_path = SCRIPT_DIR / "config" / "models.yaml"
    if models_path.exists():
        try:
            import yaml
            with open(models_path, encoding="utf-8") as f:
                registry = yaml.safe_load(f) or {}
            aliases = registry.get("aliases", {})
            resolved = aliases.get(model, model)
            provider_overrides = registry.get("providers", {}).get(provider, {})
            final = provider_overrides.get(resolved, resolved)
            r = CheckResult(
                f"Model resolution", Status.OK,
                detail=f"{model} -> {resolved} -> {provider}:{final}",
            )
        except Exception as e:
            r = CheckResult(
                "Model resolution", Status.ERROR,
                detail=f"Failed to parse models.yaml: {e}",
            )
        _print_result(r)
        results.append(r)

    return results


# ---------------------------------------------------------------------------
# Fix: auto-install missing items
# ---------------------------------------------------------------------------

def _prompt_user(message: str, default_yes: bool = True) -> bool:
    """Prompt Y/n. Returns True for yes."""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"  {message} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default_yes
    return answer in ("y", "yes")


def fix_missing(
    all_results: list[CheckResult],
    auto: bool = False,
    interactive: bool = True,
) -> int:
    """Attempt to fix MISSING and UPDATE items. Returns count of fixes applied."""
    actionable = [r for r in all_results if r.status in (Status.MISSING, Status.UPDATE) and r.fix_cmd]
    if not actionable:
        return 0

    _section("Fixes Available")
    fixed = 0

    for r in actionable:
        req_label = "" if r.required else f" {_C.DIM}(optional){_C.RESET}"
        print(f"\n  {_C.BOLD}{r.name}{_C.RESET}{req_label}")
        print(f"  Command: {_C.CYAN}{r.fix_cmd}{_C.RESET}")
        if r.detail:
            print(f"  Detail:  {_C.DIM}{r.detail}{_C.RESET}")

        if auto or (interactive and _prompt_user("Install/update?")):
            is_pip_cmd = r.fix_cmd.startswith("pip ")
            if is_pip_cmd:
                cmd = [sys.executable, "-m"] + r.fix_cmd.split()
            else:
                cmd = r.fix_cmd

            print(f"  {_C.DIM}Running: {r.fix_cmd}{_C.RESET}")
            try:
                if is_pip_cmd:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                else:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

                if result.returncode == 0:
                    print(f"  {_C.GREEN}Done.{_C.RESET}")
                    fixed += 1
                else:
                    err = result.stderr.strip().splitlines()
                    last_lines = "\n         ".join(err[-3:]) if err else "unknown error"
                    print(f"  {_C.RED}Failed (exit {result.returncode}):{_C.RESET}")
                    print(f"         {last_lines}")
            except subprocess.TimeoutExpired:
                print(f"  {_C.RED}Timed out after 5 minutes.{_C.RESET}")
            except OSError as e:
                print(f"  {_C.RED}OS error: {e}{_C.RESET}")
        else:
            print(f"  {_C.DIM}Skipped.{_C.RESET}")

    return fixed


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(all_results: list[CheckResult]) -> bool:
    """Print summary and return True if environment is ready."""
    _section("Summary")

    ok = [r for r in all_results if r.status == Status.OK]
    updates = [r for r in all_results if r.status == Status.UPDATE]
    missing_req = [r for r in all_results if r.status == Status.MISSING and r.required]
    missing_opt = [r for r in all_results if r.status == Status.MISSING and not r.required]
    errors = [r for r in all_results if r.status == Status.ERROR]

    total = len(all_results)
    print(f"  {_C.GREEN}{len(ok)}/{total} checks passed{_C.RESET}")

    if updates:
        print(f"  {_C.YELLOW}{len(updates)} available updates{_C.RESET}")
        for r in updates:
            print(f"    - {r.name}: {r.current_version} -> >={r.required_version}")

    if missing_opt:
        print(f"  {_C.DIM}{len(missing_opt)} optional tools not installed{_C.RESET}")
        for r in missing_opt:
            print(f"    - {r.name}")

    if missing_req:
        print(f"  {_C.RED}{len(missing_req)} required dependencies missing{_C.RESET}")
        for r in missing_req:
            print(f"    - {r.name}")

    if errors:
        print(f"  {_C.RED}{len(errors)} errors{_C.RESET}")
        for r in errors:
            print(f"    - {r.name}: {r.detail}")

    ready = not missing_req and not errors
    if ready:
        print(f"\n  {_C.GREEN}{_C.BOLD}Environment is ready.{_C.RESET}")
        if missing_opt:
            print(f"  {_C.DIM}Run 'python setup.py --fix' to install optional tools.{_C.RESET}")
    else:
        print(f"\n  {_C.RED}{_C.BOLD}Environment is NOT ready.{_C.RESET}")
        print(f"  Run '{_C.CYAN}python setup.py --fix{_C.RESET}' to install missing dependencies.")

    return ready


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SCAR — Environment Setup & Health Check",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python setup.py           # Interactive check + guided install\n"
            "  python setup.py --fix     # Auto-install everything missing\n"
            "  python setup.py --check   # CI mode: exit 0 if ready, 1 if not\n"
        ),
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Auto-install missing dependencies without prompting",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="CI mode: exit 0 if environment is ready, 1 if not (no prompts)",
    )
    args = parser.parse_args()

    print(f"\n{_C.BOLD}SCAR — Setup & Health Check{_C.RESET}")
    print(f"{_C.DIM}Project root: {SCRIPT_DIR}{_C.RESET}")

    all_results: list[CheckResult] = []

    # 1. OS detection
    os_info = check_os()
    os_key = os_info["platform_key"]

    # 2. Python version
    _section("Dependencies")
    py_result = check_python()
    all_results.append(py_result)
    if py_result.status == Status.ERROR:
        print(f"\n  {_C.RED}Python >={MIN_PYTHON[0]}.{MIN_PYTHON[1]} is required. Aborting.{_C.RESET}")
        return 1

    # 3. Editable install check
    install_result = check_editable_install()
    all_results.append(install_result)

    # 4. Python packages
    pkg_results = check_python_packages()
    all_results.extend(pkg_results)

    # 5. External tools
    tool_results = check_external_tools(os_key)
    all_results.extend(tool_results)

    # 6. Project structure
    struct_results = check_project_structure()
    all_results.extend(struct_results)

    # 7. Git hooks
    hooks_result = check_git_hooks()
    all_results.append(hooks_result)

    # 8. GitHub Copilot auth (only relevant if the configured provider is copilot)
    configured_provider = _get_configured_provider()
    copilot_result = check_copilot_auth(configured_provider.partition(":")[0])
    all_results.append(copilot_result)

    # 9. LLM providers
    provider_results = check_providers(configured_provider)
    all_results.extend(provider_results)

    # Fix phase
    if args.fix:
        count = fix_missing(all_results, auto=True, interactive=False)
        if count:
            print(f"\n  {_C.GREEN}Applied {count} fix(es). Re-running checks...{_C.RESET}")
            # Re-run to show updated status
            return main_recheck(os_key)
    elif not args.check:
        # Interactive mode — offer to fix
        actionable = [r for r in all_results if r.status in (Status.MISSING, Status.UPDATE) and r.fix_cmd]
        if actionable:
            count = fix_missing(all_results, auto=False, interactive=True)
            if count:
                print(f"\n  {_C.GREEN}Applied {count} fix(es). Re-running checks...{_C.RESET}")
                return main_recheck(os_key)

    # Summary
    ready = print_summary(all_results)
    return 0 if ready else 1


def main_recheck(os_key: str) -> int:
    """Re-run all checks after fixes to show updated status."""
    all_results: list[CheckResult] = []

    # Reload metadata cache
    importlib.metadata.packages_distributions.cache_clear() if hasattr(importlib.metadata.packages_distributions, "cache_clear") else None

    _section("Re-checking")

    py_result = check_python()
    all_results.append(py_result)

    install_result = check_editable_install()
    all_results.append(install_result)

    pkg_results = check_python_packages()
    all_results.extend(pkg_results)

    tool_results = check_external_tools(os_key)
    all_results.extend(tool_results)

    struct_results = check_project_structure()
    all_results.extend(struct_results)

    hooks_result = check_git_hooks()
    all_results.append(hooks_result)

    configured_provider = _get_configured_provider()
    copilot_result = check_copilot_auth(configured_provider.partition(":")[0])
    all_results.append(copilot_result)

    provider_results = check_providers(configured_provider)
    all_results.extend(provider_results)

    ready = print_summary(all_results)
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
