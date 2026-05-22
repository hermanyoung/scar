"""Top-level report and tool result models."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Result of running a single external security tool."""

    tool_name: str = Field(min_length=1)
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    success: bool
    duration_ms: int = Field(ge=0, default=0)


class SecurityReport(BaseModel):
    """Top-level output summarising a complete pipeline run."""

    run_id: str = Field(min_length=1)
    target_path: str = Field(min_length=1)
    mode: str
    total_findings: int = Field(ge=0)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_cwe: dict[str, int] = Field(default_factory=dict)
    tools_run: list[str] = Field(default_factory=list)
    total_cost_usd: float = Field(ge=0.0, default=0.0)
    sarif_path: str = ""
    summary_path: str = ""
    triage_path: str = ""
