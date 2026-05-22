"""Configuration review models for Pass 5."""
from __future__ import annotations

import re

from pydantic import Field, field_validator

from security_review.models.findings import BaseFinding, BaseModel


class ConfigFinding(BaseFinding):
    """Output of Pass 5: configuration-level security finding."""

    rule_id: str = Field(min_length=1)

    @field_validator("rule_id", mode="before")
    @classmethod
    def normalise_config_rule_id(cls, v: str) -> str:
        """Normalise to SR-CFG-NNN format."""
        v = v.strip().upper()
        match = re.match(r"^(?:SR-CFG-?)(\d+)$", v)
        if match:
            return f"SR-CFG-{int(match.group(1)):03d}"
        if not v.startswith("SR-CFG-"):
            # Extract trailing number if present
            num_match = re.search(r"(\d+)$", v)
            num = int(num_match.group(1)) if num_match else 1
            return f"SR-CFG-{num:03d}"
        return v


class ConfigReviewResult(BaseModel):
    """Output of Pass 5."""

    findings: list[ConfigFinding] = []
    files_reviewed: list[str] = Field(min_length=1)
