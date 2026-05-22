"""Dependency injection container for PydanticAI agents."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from security_review import MODULE_ROOT
from security_review.budget import CostTracker
from security_review.config_schema import SecurityReviewConfig
from security_review.errors import ConfigurationError
from security_review.models.inventory import FileManifest


@dataclass
class SecurityReviewDeps:
    """Dependency injection container for PydanticAI agents.

    Passed as RunContext[SecurityReviewDeps]. Agents use this to access
    file contents, SAST findings, inventory, and config without importing
    modules directly or calling subprocess.
    """

    config: SecurityReviewConfig
    manifest: FileManifest
    sast_sarif: dict
    cost_tracker: CostTracker
    target_path: Path
    run_id: str
    batch_id: str = ""


def load_prompt(name: str, variant: str | None = None) -> str:
    """Load a prompt from config/prompts/{name}.md or config/prompts/{name}/{variant}.md.

    Resolves relative to the module's repo root, not the current working directory.
    Missing files raise ConfigurationError.
    """
    base = MODULE_ROOT / "config" / "prompts"
    if variant:
        path = base / name / f"{variant}.md"
    else:
        path = base / f"{name}.md"

    if not path.exists():
        raise ConfigurationError(
            f"Prompt file not found: {path}",
            code="SYS_CONFIGURATION_ERROR",
        )
    return path.read_text(encoding="utf-8")
