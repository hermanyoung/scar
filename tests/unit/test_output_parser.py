"""Unit tests for output_parser.py — the LLM response extraction layer.

This module covers JSON parsing, markdown parsing, and edge cases across
all four parsers: triage, holistic, config_review, and the _extract_json helper.
"""
from __future__ import annotations

import json

import pytest

from security_review.models.config_review import ConfigFinding, ConfigReviewResult
from security_review.models.findings import (
    HolisticFinding,
    HolisticReviewResult,
    TriagedFinding,
    TriageVerdict,
)
from security_review.output_parser import (
    parse_config_review_response,
    parse_holistic_response,
    parse_triage_response,
)


# ---------------------------------------------------------------------------
# parse_triage_response — JSON path
# ---------------------------------------------------------------------------

def test_triage_json_confirmed():
    payload = {
        "original_rule_id": "B307",
        "original_tool": "bandit",
        "file_path": "should_be_overridden.py",
        "line_number": 99,
        "verdict": "CONFIRMED",
        "confidence": 0.9,
        "rationale": "The eval call processes untrusted input directly.",
    }
    text = f"```json\n{json.dumps(payload)}\n```"
    result = parse_triage_response(
        text, file_path="app.py", line_number=42, rule_id="B307", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.CONFIRMED
    assert result.confidence == 0.9
    # Ground-truth identifiers override LLM-echoed values (P13)
    assert result.file_path == "app.py"
    assert result.line_number == 42
    assert result.original_rule_id == "B307"


def test_triage_json_false_positive():
    payload = {
        "original_rule_id": "B603",
        "original_tool": "bandit",
        "file_path": "x.py",
        "line_number": 1,
        "verdict": "FALSE_POSITIVE",
        "confidence": 0.85,
        "rationale": "Arguments are a hardcoded list, not user input.",
    }
    text = json.dumps(payload)
    result = parse_triage_response(
        text, file_path="src/runner.py", line_number=10, rule_id="B603", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.FALSE_POSITIVE


def test_triage_json_needs_context():
    payload = {
        "original_rule_id": "B601",
        "original_tool": "bandit",
        "file_path": "x.py",
        "line_number": 1,
        "verdict": "NEEDS_CONTEXT",
        "confidence": 0.5,
        "rationale": "Cannot determine the source of the template string.",
    }
    text = json.dumps(payload)
    result = parse_triage_response(
        text, file_path="views.py", line_number=55, rule_id="B601", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.NEEDS_CONTEXT


def test_triage_json_confidence_percentage():
    """LLMs sometimes return 95 instead of 0.95 — normalised by model validator."""
    payload = {
        "original_rule_id": "B307",
        "original_tool": "bandit",
        "file_path": "app.py",
        "line_number": 1,
        "verdict": "CONFIRMED",
        "confidence": 95,
        "rationale": "Confirmed.",
    }
    text = json.dumps(payload)
    result = parse_triage_response(
        text, file_path="app.py", line_number=1, rule_id="B307", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.confidence == 0.95


# ---------------------------------------------------------------------------
# parse_triage_response — markdown fallback path
# ---------------------------------------------------------------------------

def test_triage_markdown_confirmed():
    text = (
        "After reviewing the code, the finding is a true positive.\n\n"
        "**Verdict:** CONFIRMED\n"
        "**Confidence:** 0.85\n"
        "**Rationale:** The eval() call receives raw user input from request.args."
    )
    result = parse_triage_response(
        text, file_path="app.py", line_number=12, rule_id="B307", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.CONFIRMED
    assert result.confidence == pytest.approx(0.85)
    assert result.file_path == "app.py"
    assert result.line_number == 12


def test_triage_markdown_false_positive_with_space():
    """'FALSE POSITIVE' (space variant) should also parse."""
    text = "Verdict: FALSE POSITIVE\nConfidence: 0.9\nRationale: Args are hardcoded."
    result = parse_triage_response(
        text, file_path="run.py", line_number=5, rule_id="B603", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.FALSE_POSITIVE


def test_triage_markdown_needs_context_with_underscore():
    text = "**Verdict:** NEEDS_CONTEXT\n**Confidence:** 0.5\n**Rationale:** Missing call graph."
    result = parse_triage_response(
        text, file_path="svc.py", line_number=99, rule_id="B601", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.NEEDS_CONTEXT


def test_triage_markdown_confidence_default_when_absent():
    """When confidence is absent, the configured default_confidence is used."""
    text = "**Verdict:** CONFIRMED\n**Rationale:** Clear true positive."
    result = parse_triage_response(
        text, file_path="app.py", line_number=1, rule_id="X", tool_name="tool",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.confidence == 0.5


def test_triage_markdown_rationale_trimmed():
    """Rationale is truncated to 500 chars."""
    long_rationale = "x" * 600
    text = f"**Verdict:** CONFIRMED\n**Confidence:** 0.9\n**Rationale:** {long_rationale}"
    result = parse_triage_response(
        text, file_path="app.py", line_number=1, rule_id="X", tool_name="tool",
        default_confidence=0.5,
    )
    assert result is not None
    assert len(result.rationale) <= 500


def test_triage_no_verdict_returns_none():
    text = "This code looks fine but I'm not sure."
    result = parse_triage_response(
        text, file_path="app.py", line_number=1, rule_id="X", tool_name="tool",
        default_confidence=0.5,
    )
    assert result is None


# ---------------------------------------------------------------------------
# parse_holistic_response — JSON path
# ---------------------------------------------------------------------------

def test_holistic_json_with_findings():
    payload = {
        "findings": [
            {
                "rule_id": "SR-AUTHZ-001",
                "title": "Missing authorization check",
                "description": "Endpoint lacks auth guard.",
                "severity": "HIGH",
                "file_path": "api.py",
                "cwe_id": "CWE-862",
                "remediation": "Add @login_required.",
                "confidence": "high",
                "evidence": "def get_user(id):",
            }
        ],
        "files_reviewed": ["api.py"],
    }
    text = f"```json\n{json.dumps(payload)}\n```"
    result = parse_holistic_response(text, files_reviewed=["api.py", "auth.py"])
    assert result is not None
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SR-AUTHZ-001"


def test_holistic_json_empty_findings():
    payload = {"findings": [], "files_reviewed": ["app.py"]}
    text = json.dumps(payload)
    result = parse_holistic_response(text, files_reviewed=["app.py"])
    assert result is not None
    assert result.findings == []
    assert result.review_notes is None  # legitimate no-findings, not a parse failure


# ---------------------------------------------------------------------------
# parse_holistic_response — markdown fallback path
# ---------------------------------------------------------------------------

def test_holistic_markdown_single_finding():
    text = (
        "### SR-CRYPTO-001 — Weak hash algorithm\n"
        "**Severity:** HIGH\n"
        "**File:** src/crypto.py\n"
        "**CWE:** CWE-328\n"
        "**Evidence:**\n"
        "```python\nhashlib.md5(data)\n```\n"
        "**Remediation:** Use SHA-256 or better.\n"
    )
    result = parse_holistic_response(text, files_reviewed=["src/crypto.py"])
    assert result is not None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SR-CRYPTO-001"
    assert f.severity.value == "HIGH"
    assert f.file_path == "src/crypto.py"
    assert f.cwe_id == "CWE-328"
    assert result.review_notes is None


def test_holistic_markdown_multiple_findings():
    text = (
        "### SR-IDOR-001 — Missing ownership check\n"
        "**Severity:** HIGH\n"
        "**File:** controllers/user.py\n"
        "**CWE:** CWE-639\n"
        "**Evidence:**\n```\nreturn db.get(user_id)\n```\n"
        "**Remediation:** Verify ownership.\n\n"
        "### SR-AUTHZ-002 — Unauthenticated endpoint\n"
        "**Severity:** CRITICAL\n"
        "**File:** controllers/admin.py\n"
        "**CWE:** CWE-862\n"
        "**Evidence:**\n```\ndef delete_all():\n```\n"
        "**Remediation:** Add auth check.\n"
    )
    result = parse_holistic_response(text, files_reviewed=["controllers/user.py", "controllers/admin.py"])
    assert result is not None
    assert len(result.findings) == 2
    rule_ids = {f.rule_id for f in result.findings}
    assert "SR-IDOR-001" in rule_ids
    assert "SR-AUTHZ-002" in rule_ids


def test_holistic_markdown_no_findings_phrase():
    text = "After reviewing all source files, I found no issues for this CWE. No findings."
    result = parse_holistic_response(text, files_reviewed=["app.py"])
    assert result is not None
    assert result.findings == []
    assert result.review_notes is None  # explicit no-findings — not a parse failure


def test_holistic_markdown_unparseable_sets_review_notes():
    """Non-empty text with no extractable findings signals parse failure via review_notes."""
    text = "I reviewed the code but the format instruction was unclear so here is prose."
    result = parse_holistic_response(text, files_reviewed=["app.py"])
    assert result is not None
    assert result.findings == []
    assert result.review_notes is not None  # parse failure — caller should retry


def test_holistic_empty_text_returns_none():
    result = parse_holistic_response("", files_reviewed=["app.py"])
    assert result is None


def test_holistic_markdown_rule_id_normalised():
    """SR-CRYPTO-1 -> SR-CRYPTO-001 via HolisticFinding validator."""
    text = (
        "### SR-CRYPTO-1 — Weak cipher\n"
        "**Severity:** HIGH\n"
        "**File:** app.py\n"
        "**CWE:** CWE-327\n"
        "**Evidence:**\n```\nDES.new(key)\n```\n"
        "**Remediation:** Use AES-256.\n"
    )
    result = parse_holistic_response(text, files_reviewed=["app.py"])
    assert result is not None
    assert result.findings[0].rule_id == "SR-CRYPTO-001"


# ---------------------------------------------------------------------------
# parse_config_review_response
# ---------------------------------------------------------------------------

def test_config_review_json_with_findings():
    payload = {
        "findings": [
            {
                "rule_id": "SR-CFG-001",
                "title": "Debug mode enabled in production",
                "severity": "HIGH",
                "description": "DEBUG=True exposes stack traces.",
                "file_path": "config/settings.py",
                "cwe_id": "CWE-215",
                "evidence": "DEBUG = True",
                "remediation": "Set DEBUG=False in production.",
            }
        ],
        "files_reviewed": ["config/settings.py"],
    }
    text = f"```json\n{json.dumps(payload)}\n```"
    result = parse_config_review_response(text, files_reviewed=["config/settings.py"])
    assert result is not None
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SR-CFG-001"
    # Ground-truth files_reviewed overrides LLM value (P13)
    assert result.files_reviewed == ["config/settings.py"]


def test_config_review_json_empty():
    payload = {"findings": [], "files_reviewed": []}
    text = json.dumps(payload)
    result = parse_config_review_response(text, files_reviewed=["config/app.yaml"])
    assert result is not None
    assert result.findings == []
    assert result.files_reviewed == ["config/app.yaml"]


def test_config_review_no_json_returns_none():
    text = "No security issues found in the configuration files."
    result = parse_config_review_response(text, files_reviewed=["config/app.yaml"])
    assert result is None


# ---------------------------------------------------------------------------
# _extract_json edge cases (tested indirectly through parse_* functions)
# ---------------------------------------------------------------------------

def test_triage_json_bare_object_without_fences():
    """Bare JSON object without code fences should be extracted."""
    payload = {
        "original_rule_id": "B307",
        "original_tool": "bandit",
        "file_path": "app.py",
        "line_number": 1,
        "verdict": "CONFIRMED",
        "confidence": 0.9,
        "rationale": "True positive.",
    }
    text = f"Here is my assessment: {json.dumps(payload)} Done."
    result = parse_triage_response(
        text, file_path="app.py", line_number=1, rule_id="B307", tool_name="bandit",
        default_confidence=0.5,
    )
    assert result is not None
    assert result.verdict == TriageVerdict.CONFIRMED


def test_holistic_json_fenced_with_findings_list():
    """findings key wrapping a list — standard holistic JSON shape."""
    payload = {
        "findings": [
            {
                "rule_id": "SR-SQLI-001",
                "title": "SQL Injection",
                "description": "Raw query with user input.",
                "severity": "CRITICAL",
                "file_path": "db.py",
                "cwe_id": "CWE-89",
                "remediation": "Use parameterised queries.",
                "confidence": "high",
                "evidence": "cursor.execute(f'SELECT * FROM {table}')",
            }
        ],
        "files_reviewed": ["db.py"],
    }
    text = f"```json\n{json.dumps(payload)}\n```"
    result = parse_holistic_response(text, files_reviewed=["db.py"])
    assert result is not None
    assert result.findings[0].severity.value == "CRITICAL"
