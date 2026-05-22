"""Tests for Pydantic finding models: validators, enums, auto-repair."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_review.models.findings import (
    BaseFinding,
    HolisticFinding,
    HolisticReviewResult,
    Severity,
    TriagedFinding,
    TriageResult,
    TriageVerdict,
)


def test_severity_normalisation():
    """Severity field normalises case."""
    f = BaseFinding(
        rule_id="TEST-001",
        title="Test finding title",
        description="Test description",
        severity="high",
        file_path="app.py",
        remediation="Fix this",
    )
    assert f.severity == Severity.HIGH


def test_severity_rejects_invalid():
    with pytest.raises(ValidationError):
        BaseFinding(
            rule_id="TEST-001",
            title="Test",
            description="Test",
            severity="SUPER_BAD",
            file_path="app.py",
            remediation="Fix",
        )


def test_triaged_finding_strips_rationale():
    f = TriagedFinding(
        original_rule_id="B602",
        original_tool="bandit",
        file_path="app.py",
        line_number=42,
        verdict=TriageVerdict.CONFIRMED,
        confidence=0.95,
        rationale="  This is a valid rationale.  ",
    )
    assert not f.rationale.startswith(" ")


def test_triaged_finding_normalises_confidence_percentage():
    """LLMs sometimes return 95 instead of 0.95."""
    f = TriagedFinding(
        original_rule_id="B602",
        original_tool="bandit",
        file_path="app.py",
        line_number=42,
        verdict=TriageVerdict.CONFIRMED,
        confidence=95,
        rationale="True positive confirmed",
    )
    assert f.confidence == 0.95


def test_triage_result_requires_findings():
    with pytest.raises(ValidationError):
        TriageResult(
            findings=[],
            total_confirmed=0,
            total_false_positive=0,
            total_needs_context=0,
        )


def test_holistic_finding_normalises_rule_id():
    """SR-CRYPTO-1 -> SR-CRYPTO-001."""
    f = HolisticFinding(
        rule_id="SR-CRYPTO-1",
        title="Weak crypto",
        description="Uses MD5",
        severity="HIGH",
        file_path="app.py",
        remediation="Use SHA-256",
        confidence="high",
        evidence="hashlib.md5(data)",
    )
    assert f.rule_id == "SR-CRYPTO-001"


def test_holistic_finding_valid():
    f = HolisticFinding(
        rule_id="SR-AUTHZ-001",
        title="Missing authorization check",
        description="Endpoint lacks auth",
        severity="HIGH",
        file_path="controllers/api.py",
        line_number=42,
        cwe_id="CWE-862",
        remediation="Add @login_required",
        confidence="high",
        evidence="def get_user(request, user_id):",
    )
    assert f.rule_id == "SR-AUTHZ-001"
    assert f.severity == Severity.HIGH
    assert f.cwe_id == "CWE-862"


def test_cwe_id_normalises_bare_number():
    """'89' -> 'CWE-89'."""
    f = BaseFinding(
        rule_id="TEST-001",
        title="Test",
        description="Test",
        severity="HIGH",
        file_path="app.py",
        cwe_id="89",
        remediation="Fix",
    )
    assert f.cwe_id == "CWE-89"


def test_cwe_id_normalises_no_dash():
    """'CWE89' -> 'CWE-89'."""
    f = BaseFinding(
        rule_id="TEST-001",
        title="Test",
        description="Test",
        severity="HIGH",
        file_path="app.py",
        cwe_id="CWE89",
        remediation="Fix",
    )
    assert f.cwe_id == "CWE-89"


def test_line_number_must_be_positive():
    with pytest.raises(ValidationError):
        BaseFinding(
            rule_id="TEST-001",
            title="Test",
            description="Test",
            severity="HIGH",
            file_path="app.py",
            line_number=0,
            remediation="Fix",
        )


def test_holistic_confidence_normalises_numeric():
    """Numeric confidence -> level string."""
    f = HolisticFinding(
        rule_id="SR-TEST-001",
        title="Test",
        description="Test",
        severity="HIGH",
        file_path="app.py",
        remediation="Fix",
        confidence=0.9,
        evidence="code",
    )
    assert f.confidence == "high"


def test_holistic_owasp_normalises_short():
    """A3 -> A03:2021."""
    f = HolisticFinding(
        rule_id="SR-TEST-001",
        title="Test",
        description="Test",
        severity="HIGH",
        file_path="app.py",
        remediation="Fix",
        confidence="high",
        evidence="code",
        owasp_category="A3",
    )
    assert f.owasp_category == "A03:2021"
