"""TypedDict definitions for SARIF 2.1.0 structures.

These cover the subset of SARIF shapes that security-review constructs
and consumes. They enable static type checking without a full SARIF
schema dependency.

Usage:
    from security_review.sarif.types import SarifDocument, SarifResult

    def process(sarif: SarifDocument) -> list[SarifResult]:
        for run in sarif.get("runs", []):
            ...
"""
from __future__ import annotations

from typing import NotRequired, TypedDict


class SarifMessage(TypedDict):
    text: str


class SarifArtifactLocation(TypedDict):
    uri: str


class SarifRegion(TypedDict, total=False):
    startLine: int
    endLine: int
    snippet: SarifMessage


class SarifPhysicalLocation(TypedDict, total=False):
    artifactLocation: SarifArtifactLocation
    region: SarifRegion
    contextRegion: SarifRegion


class SarifLocation(TypedDict, total=False):
    physicalLocation: SarifPhysicalLocation


class SarifProperties(TypedDict, total=False):
    tags: list[str]
    tool_name: str  # Internal: set during merge, identifies the originating tool


class SarifResult(TypedDict, total=False):
    ruleId: str
    level: str
    message: SarifMessage
    locations: list[SarifLocation]
    properties: SarifProperties
    taxa: list[dict]


class SarifRule(TypedDict, total=False):
    id: str
    shortDescription: SarifMessage
    helpUri: str
    properties: SarifProperties
    relationships: list[dict]


class SarifDriver(TypedDict, total=False):
    name: str
    version: str
    semanticVersion: str
    rules: list[SarifRule]


class SarifTool(TypedDict):
    driver: SarifDriver


class SarifTaxonomy(TypedDict, total=False):
    name: str
    version: str
    informationUri: str
    organization: str
    isComprehensive: bool
    taxa: list[dict]


class SarifRun(TypedDict, total=False):
    tool: SarifTool
    results: list[SarifResult]
    taxonomies: list[SarifTaxonomy]


class SarifDocument(TypedDict, total=False):
    version: str
    """Must be "2.1.0"."""
    runs: list[SarifRun]
