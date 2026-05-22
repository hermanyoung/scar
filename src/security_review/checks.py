"""CWE check registry — loads LLM security checks from taxonomy/cwe.yaml.

The taxonomy is the single source of truth. Each CWE declares its detection
method (sast, llm, sast+llm, tool) and, for LLM-checked CWEs, a focused
check prompt. This module loads and filters those checks for Pass 4.
"""
from __future__ import annotations

from dataclasses import dataclass

import structlog
import yaml

from security_review import MODULE_ROOT
from security_review.errors import ConfigurationError
from security_review.models.inventory import FileEntry

logger = structlog.get_logger()


@dataclass(frozen=True)
class CWECheck:
    """A single CWE check to be executed by the LLM agent."""

    cwe_id: str
    name: str
    detection: str
    file_types: list[str]
    check_prompt: str

    @property
    def display_name(self) -> str:
        return f"CWE-{self.cwe_id} {self.name}"

    @property
    def short_name(self) -> str:
        """Short display for progress: 'CWE-862 Missing Authorization'."""
        name = self.name
        # Truncate long CWE names at the parenthetical
        if "(" in name:
            name = name[:name.index("(")].strip()
        if len(name) > 50:
            name = name[:47] + "..."
        return f"CWE-{self.cwe_id} {name}"


def load_cwe_checks() -> list[CWECheck]:
    """Load all CWE checks that require LLM reasoning from the taxonomy.

    Returns checks where detection is 'llm' or 'sast+llm' and a check
    prompt is defined.
    """
    cwe_path = MODULE_ROOT / "config" / "taxonomy" / "cwe.yaml"
    if not cwe_path.exists():
        raise ConfigurationError(
            f"CWE taxonomy not found: {cwe_path}",
            code="SYS_CWE_NOT_FOUND",
        )

    with open(cwe_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"CWE taxonomy is not a YAML mapping: {cwe_path}",
            code="SYS_CWE_NOT_FOUND",
        )

    checks: list[CWECheck] = []
    for cwe_id, entry in data.items():
        if not isinstance(entry, dict):
            continue

        detection = entry.get("detection", "sast")
        check_prompt = entry.get("check")

        if detection in ("llm", "sast+llm") and check_prompt:
            checks.append(CWECheck(
                cwe_id=str(cwe_id),
                name=entry.get("name", ""),
                detection=detection,
                file_types=entry.get("file_types", []),
                check_prompt=check_prompt.strip(),
            ))

    return checks


# File type keywords matched against FileEntry fields
_FILE_TYPE_MATCHERS: dict[str, list[str]] = {
    "controller": ["controller", "views", "endpoints", "api", "routes"],
    "route": ["routes", "urls", "router", "endpoints"],
    "view": ["views", "templates", "pages"],
    "template": ["templates", "views", "pages", "razor", "jinja"],
    "model": ["models", "entities", "domain"],
    "repository": ["repositories", "dal", "data"],
    "service": ["services", "handlers", "managers", "processors"],
    "middleware": ["middleware", "filters", "interceptors"],
    "auth": ["auth", "identity", "login", "oauth", "jwt", "token"],
    "config": ["config", "settings", "appsettings", "startup", "program"],
    "startup": ["startup", "program", "main", "app", "host"],
    "error_handler": ["error", "exception", "handler", "middleware"],
    "file_handler": ["file", "upload", "download", "storage", "blob"],
    "crypto": ["crypto", "cipher", "encrypt", "hash", "key", "cert", "ssl", "tls"],
    "api": ["api", "controller", "endpoints", "routes", "views"],
    "message_handler": ["consumer", "handler", "processor", "worker", "listener"],
    "dockerfile": ["dockerfile", "docker-compose", "containerfile"],
}


def select_files_for_check(
    check: CWECheck,
    files: list[FileEntry],
) -> list[FileEntry]:
    """Select files relevant to a CWE check based on file_types.

    Matches file paths against keywords associated with each file_type.
    Falls back to all source files if no file_types specified or no matches found.
    """
    if not check.file_types:
        return [f for f in files if f.language in ("python", "csharp")]

    keywords: set[str] = set()
    for ft in check.file_types:
        keywords.update(_FILE_TYPE_MATCHERS.get(ft, [ft]))

    matched = []
    for f in files:
        if f.language not in ("python", "csharp"):
            continue
        path_lower = f.path.lower()
        if any(kw in path_lower for kw in keywords):
            matched.append(f)

    # If keyword matching found nothing, fall back to high-security-weight
    # files only — not the entire codebase. Prevents budget exhaustion on
    # large repos when file_types keywords don't match directory names.
    if not matched:
        high_weight = [
            f for f in files
            if f.language in ("python", "csharp") and f.security_weight >= 3
        ]
        logger.debug(
            "checks.keyword_match_fallback",
            cwe_id=check.cwe_id,
            file_types=check.file_types,
            keywords=sorted(keywords),
            high_weight_files=len(high_weight),
        )
        return high_weight if high_weight else []

    return matched
