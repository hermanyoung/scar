"""Finding models for triage (Pass 3) and holistic review (Pass 4).

Field validators normalise LLM output so the same schemas work across all
providers (native JSON schema, prompted mode, any model). Validators repair
common LLM mistakes rather than rejecting — this keeps the pipeline robust
regardless of which provider or model is used.
"""
from __future__ import annotations

import re
from enum import Enum
from functools import lru_cache

import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def _valid_cwe_ids() -> frozenset[str]:
    """Load the set of valid CWE IDs from taxonomy/cwe.yaml. Cached after first call."""
    try:
        from security_review.sarif.taxonomy import load_cwe_registry
        return frozenset(f"CWE-{k}" for k in load_cwe_registry())
    except Exception as e:
        import structlog
        structlog.get_logger().debug("findings.cwe_registry_load_failed", error=str(e))
        return frozenset()


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Priority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TriageVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_CONTEXT = "NEEDS_CONTEXT"


class TriagedFinding(BaseModel):
    """Output of Pass 3: LLM verdict on a single SAST finding."""

    original_rule_id: str = Field(min_length=1)
    original_tool: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    verdict: TriageVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1)

    @field_validator("rationale", mode="before")
    @classmethod
    def strip_rationale(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v

    @field_validator("confidence", mode="before")
    @classmethod
    def normalise_confidence(cls, v) -> float:
        """Accept percentage or decimal — LLMs sometimes return 95 instead of 0.95."""
        if isinstance(v, str):
            v = float(v.strip().rstrip("%"))
        if isinstance(v, (int, float)) and v > 1.0:
            return v / 100.0
        return float(v)


class TriageResult(BaseModel):
    """Batch output of Pass 3."""

    findings: list[TriagedFinding] = Field(default_factory=list)
    total_confirmed: int = Field(ge=0)
    total_false_positive: int = Field(ge=0)
    total_needs_context: int = Field(ge=0)


class BaseFinding(BaseModel):
    """Common fields shared by all LLM-generated findings (Pass 4 and Pass 5).

    Validators normalise common LLM formatting mistakes so findings are
    accepted regardless of provider (native schema, prompted mode, etc.).
    """

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    severity: Severity
    priority: Priority = Priority.MEDIUM
    file_path: str = Field(min_length=1)
    line_number: int | None = Field(default=None, ge=1)
    cwe_id: str | None = Field(default=None)
    remediation: str = Field(min_length=1)

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: str) -> str:
        return v.upper().strip() if isinstance(v, str) else v

    @field_validator("priority", mode="before")
    @classmethod
    def normalise_priority(cls, v: str | None) -> str:
        """Accept critical/high/medium/low in any case. Default to MEDIUM if missing."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return "MEDIUM"
        v = v.strip().upper()
        if v == "INFORMATIONAL":
            return "LOW"
        if v in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return v
        return "MEDIUM"

    @field_validator("cwe_id", mode="before")
    @classmethod
    def normalise_cwe_id(cls, v: str | None) -> str | None:
        """Accept CWE-89, CWE89, 89 — normalise to CWE-NNN and warn if not in taxonomy."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        v = str(v).strip()
        match = re.search(r"(\d{1,5})", v)
        if not match:
            return v
        normalised = f"CWE-{match.group(1)}"
        valid = _valid_cwe_ids()
        if valid and normalised not in valid:
            logger.warning("finding.unknown_cwe", cwe_id=normalised)
        return normalised


class HolisticFinding(BaseFinding):
    """Output of Pass 4: a new finding discovered by cross-file LLM analysis."""

    rule_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    confidence: str = Field(default="medium")
    owasp_category: str | None = Field(default=None)
    end_line: int | None = Field(default=None, ge=1)
    evidence: str = Field(min_length=1)

    @field_validator("rule_id", mode="before")
    @classmethod
    def normalise_rule_id(cls, v: str) -> str:
        """Normalise rule IDs to SR-CATEGORY-NNN format."""
        v = v.strip().upper()
        # SR-CRYPTO-1 -> SR-CRYPTO-001
        match = re.match(r"^(SR-[A-Z]+-?)(\d+)$", v)
        if match:
            return f"{match.group(1)}{int(match.group(2)):03d}"
        # If it doesn't match SR- prefix at all, prefix it
        if not v.startswith("SR-"):
            v = f"SR-{v}"
        return v

    @field_validator("confidence", mode="before")
    @classmethod
    def normalise_confidence(cls, v) -> str:
        """Accept high/medium/low in any case, or numeric values."""
        if isinstance(v, str):
            v = v.strip().lower()
            if v in ("high", "medium", "low"):
                return v
        # Numeric -> map to level
        try:
            n = float(v)
            if n >= 0.75:
                return "high"
            if n >= 0.4:
                return "medium"
            return "low"
        except (ValueError, TypeError):
            logger.warning(
                "finding.confidence_coerced",
                raw_value=str(v),
                default="medium",
            )
            return "medium"

    @field_validator("owasp_category", mode="before")
    @classmethod
    def normalise_owasp(cls, v: str | None) -> str | None:
        """Accept A03, A03:2021, A3:2021 — normalise to ANN:YYYY."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        v = str(v).strip()
        # A3:2021 -> A03:2021
        match = re.match(r"^A(\d{1,2})(?::(\d{4}))?", v)
        if match:
            num = int(match.group(1))
            year = match.group(2) or "2021"
            return f"A{num:02d}:{year}"
        return v


class HolisticReviewResult(BaseModel):
    """Batch output of Pass 4."""

    findings: list[HolisticFinding] = []
    files_reviewed: list[str] = Field(min_length=1)
    review_notes: str | None = None
