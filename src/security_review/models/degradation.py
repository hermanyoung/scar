"""Degradation: a recorded reduction in review coverage or fidelity.

Every event that silently reduced coverage before this model existed
(missing tool, failed check, budget stop, truncated context) must be
recorded as a Degradation and rendered in every report format.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

PassName = Literal[
    "inventory", "sast", "triage", "holistic", "config_review", "verify", "merge", "pipeline",
]

DegradationKind = Literal[
    "tool_missing",        # SAST binary not on PATH — tool never ran
    "tool_failed",         # SAST tool ran but produced no usable output (crash/timeout/parse)
    "check_failed",        # holistic CWE check or config review failed after retry — NOT assessed
    "triage_call_failed",  # one or more triage calls failed — findings remain Untriaged
    "parse_failed",        # LLM responded but output was unparseable
    "budget_exhausted",    # max_budget_usd reached — remaining work skipped
    "files_omitted",       # token budget truncated files out of an LLM prompt
    "taxonomy_failed",     # CWE taxonomy injection failed — SARIF lacks taxonomy block
    "run_aborted",         # pipeline aborted mid-run — artifacts are partial (salvage)
    "pass_failed",         # an entire pass raised uncaught — subsequent passes were skipped
    "location_unresolved",  # LLM finding had no resolvable file path — SARIF result has no location
]


class Degradation(BaseModel, extra="forbid"):
    pass_name: PassName
    kind: DegradationKind
    subject: str                       # tool name, "CWE-NNN", pass name, or "run"
    detail: str                        # one human-readable sentence
    count: int = Field(default=0, ge=0)  # optional quantity (files omitted, calls failed, checks skipped)


def files_omitted_degradation(
    pass_name: PassName, subject: str, omitted: list[str], total: int, *, context: str = "",
) -> Degradation:
    """Build a files_omitted Degradation — shared by holistic.py and
    config_review.py so both token-budget-truncation messages read identically.
    """
    suffix = f" for {context}" if context else ""
    return Degradation(
        pass_name=pass_name, kind="files_omitted", subject=subject,
        detail=f"{len(omitted)} of {total} selected files did not fit the "
               f"token budget and were NOT reviewed{suffix}: "
               f"{', '.join(omitted[:5])}{'…' if len(omitted) > 5 else ''}",
        count=len(omitted),
    )
