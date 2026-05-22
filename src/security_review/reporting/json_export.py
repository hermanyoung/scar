"""JSON export renderer — machine-readable findings for CI/dashboards.

Produces a JSON array of findings with all scored fields.
Designed for piping to jq, feeding dashboards, or API consumption.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from security_review.reporting.common import ReportData


def render_json(data: ReportData) -> str:
    """Render findings as a JSON document."""
    output = {
        "metadata": {
            "run_id": data.run_id,
            "target": data.target,
            "mode": data.mode,
            "provider": data.provider,
            "timestamp": data.timestamp,
            "cost_usd": data.cost_usd,
            "total_findings": data.total,
        },
        "summary": {
            "priority": {
                "urgent": data.urgent,
                "elevated": data.elevated,
                "moderate": data.moderate,
                "low": data.low,
            },
            "severity": {
                "critical": data.critical,
                "medium": data.medium,
                "low": data.low_severity,
            },
        },
        "findings": [
            {
                "priority": f.priority,
                "priority_band": f.priority_band,
                "severity": f.severity,
                "rule_id": f.rule_id,
                "file": f.file_path,
                "line": f.line,
                "message": f.message,
                "cwe": f.cwe,
                "confidence": f.confidence,
                "confidence_label": f.confidence_label,
                "exposure": f.exposure,
            }
            for f in data.findings
        ],
    }

    if data.has_triage:
        output["triage"] = {
            "confirmed": data.triage_confirmed,
            "false_positive": data.triage_false_positive,
            "needs_context": data.triage_needs_context,
        }

    if data.top_cwes:
        output["cwes"] = {cwe: count for cwe, count in data.top_cwes}

    return json.dumps(output, indent=2)
