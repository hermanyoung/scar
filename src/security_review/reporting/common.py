"""Shared data model and utilities for all report renderers.

Every renderer receives a ReportData instance — a clean, pre-processed
view of the scored SARIF results. This ensures consistency across formats
and keeps extraction logic in one place.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from security_review.models.coverage import CoverageReport


@dataclass
class FindingRow:
    """A single finding pre-processed for rendering."""

    priority: float
    priority_band: str        # URGENT / ELEVATED / MODERATE / LOW
    severity: str             # Critical / Medium / Low
    severity_raw: str         # error / warning / note (SARIF internal)
    rule_id: str
    file_path: str
    line: int
    message: str
    cwe: str                  # "CWE-089" or ""
    confidence: float
    confidence_label: str     # confirmed / sast_only / llm_only / etc
    exposure: float
    triage_verdict: str       # "confirmed" / "false_positive" / "needs_context" / "" (not triaged)


@dataclass
class ReportData:
    """Pre-processed report data consumed by all renderers."""

    # Metadata
    run_id: str = ""
    target: str = ""
    mode: str = ""
    provider: str = ""
    timestamp: str = ""
    cost_usd: float = 0.0

    # Findings (sorted by priority descending)
    findings: list[FindingRow] = field(default_factory=list)
    total: int = 0

    # Priority band counts
    urgent: int = 0
    elevated: int = 0
    moderate: int = 0
    low: int = 0

    # Severity counts
    critical: int = 0
    medium: int = 0
    low_severity: int = 0

    # Triage
    has_triage: bool = False
    triage_confirmed: int = 0
    triage_false_positive: int = 0
    triage_needs_context: int = 0

    # CWE breakdown
    top_cwes: list[tuple[str, int]] = field(default_factory=list)

    # Coverage (set from PipelineState.coverage)
    coverage: CoverageReport | None = None


# Triage verdict -> display label (shared by all renderers)
TRIAGE_STATUS_DISPLAY = {
    "CONFIRMED": "Confirmed",
    "FALSE_POSITIVE": "False Pos",
    "NEEDS_CONTEXT": "Needs Ctx",
}


def triage_status(verdict: str) -> str:
    """Map triage verdict to display label."""
    return TRIAGE_STATUS_DISPLAY.get(verdict, "Untriaged")


# SARIF level -> human severity label
_SEVERITY_DISPLAY = {
    "error": "Critical",
    "warning": "Medium",
    "note": "Low",
}


def extract_report_data(
    sarif_results: list[dict],
    *,
    rule_cwe_map: dict[str, str] | None = None,
    run_id: str = "",
    target: str = "",
    mode: str = "",
    provider: str = "",
    cost_usd: float = 0.0,
) -> ReportData:
    """Extract ReportData from scored SARIF results.

    Call this once after the merge pass. Pass the result to any renderer.
    Triage counts are derived from SARIF properties — single source of truth.
    """
    findings: list[FindingRow] = []
    bands = {"URGENT": 0, "ELEVATED": 0, "MODERATE": 0, "LOW": 0}
    severity_counts = Counter()
    cwe_counts: Counter = Counter()
    triage_counts: Counter = Counter()

    for r in sarif_results:
        props = r.get("properties", {})
        comps = props.get("priority_components", {})

        level = r.get("level", "warning")
        severity = _SEVERITY_DISPLAY.get(level, level)

        # Extract location
        locs = r.get("locations", [{}])
        file_path = ""
        line = 0
        if locs:
            phys = locs[0].get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)

        # Extract CWE: check result tags first, then fall back to rule definition
        cwe = ""
        for tag in props.get("tags", []):
            if tag.startswith("external/cwe/cwe-"):
                num = tag.split("-")[-1].lstrip("0") or "0"
                cwe = f"CWE-{num}"
                break
        if not cwe and rule_cwe_map:
            cwe = rule_cwe_map.get(r.get("ruleId", ""), "")
        if cwe:
            cwe_counts[cwe] += 1

        band = props.get("priority_band", "LOW")
        bands[band] = bands.get(band, 0) + 1
        severity_counts[level] += 1

        verdict = props.get("triage_verdict", "")
        if verdict:
            triage_counts[verdict] += 1

        findings.append(FindingRow(
            priority=props.get("priority", 0),
            priority_band=band,
            severity=severity,
            severity_raw=level,
            rule_id=r.get("ruleId", ""),
            file_path=file_path,
            line=line,
            message=" ".join(r.get("message", {}).get("text", "").split()),
            cwe=cwe,
            confidence=comps.get("confidence", 0),
            confidence_label=comps.get("confidence_label", ""),
            exposure=comps.get("exposure", 0),
            triage_verdict=verdict,
        ))

    # Sort by priority descending
    findings.sort(key=lambda f: f.priority, reverse=True)

    has_triage = bool(triage_counts)
    return ReportData(
        run_id=run_id,
        target=target,
        mode=mode,
        provider=provider,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        cost_usd=cost_usd,
        findings=findings,
        total=len(findings),
        urgent=bands.get("URGENT", 0),
        elevated=bands.get("ELEVATED", 0),
        moderate=bands.get("MODERATE", 0),
        low=bands.get("LOW", 0),
        critical=severity_counts.get("error", 0),
        medium=severity_counts.get("warning", 0),
        low_severity=severity_counts.get("note", 0),
        has_triage=has_triage,
        triage_confirmed=triage_counts.get("CONFIRMED", 0),
        triage_false_positive=triage_counts.get("FALSE_POSITIVE", 0),
        triage_needs_context=triage_counts.get("NEEDS_CONTEXT", 0),
        top_cwes=cwe_counts.most_common(10),
    )
