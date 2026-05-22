"""Parse LLM text responses into Pydantic models.

Strategy: try JSON first (native providers), fall back to markdown parsing (prompted).
This makes the pipeline robust regardless of whether the provider returns JSON or prose.

The LLM's security analysis is always good — this module extracts structure from it.
"""
from __future__ import annotations

import json
import re

import structlog

from security_review.models.config_review import ConfigReviewResult
from security_review.models.findings import (
    HolisticFinding,
    HolisticReviewResult,
    TriagedFinding,
    TriageResult,
    TriageVerdict,
)

logger = structlog.get_logger()


def parse_triage_response(
    text: str,
    *,
    file_path: str,
    line_number: int,
    rule_id: str,
    tool_name: str,
    default_confidence: float,
) -> TriagedFinding | None:
    """Parse a triage LLM response into a TriagedFinding.

    Tries JSON first, falls back to markdown keyword extraction.
    The caller provides the ground-truth identifiers (P13).
    default_confidence is used when the LLM omits a confidence value.
    """
    # Attempt 1: JSON parse (works for native providers)
    finding = _try_json_triage(text, file_path=file_path, line_number=line_number,
                                rule_id=rule_id, tool_name=tool_name)
    if finding:
        return finding

    # Attempt 2: Markdown keyword extraction (prompted providers)
    return _parse_markdown_triage(text, file_path=file_path, line_number=line_number,
                                   rule_id=rule_id, tool_name=tool_name,
                                   default_confidence=default_confidence)


def parse_holistic_response(text: str, *, files_reviewed: list[str]) -> HolisticReviewResult | None:
    """Parse a holistic LLM response into HolisticReviewResult.

    Tries JSON first, falls back to markdown section extraction.
    """
    # Attempt 1: JSON parse
    result = _try_json_holistic(text, files_reviewed=files_reviewed)
    if result:
        return result

    # Attempt 2: Markdown extraction
    return _parse_markdown_holistic(text, files_reviewed=files_reviewed)


# -- JSON parsers (native providers) -----------------------------------------


def _try_json_triage(text: str, **kwargs) -> TriagedFinding | None:
    """Try to parse text as JSON TriageResult or TriagedFinding."""
    json_str = _extract_json(text)
    if not json_str:
        return None

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.debug("output_parser.json_decode_failed", error=str(e))
        return None

    # Could be a TriageResult wrapper or a direct TriagedFinding
    if isinstance(data, dict):
        if "findings" in data and data["findings"]:
            data = data["findings"][0]

        # Override with ground-truth identifiers (P13)
        data["file_path"] = kwargs["file_path"]
        data["line_number"] = kwargs["line_number"]
        data["original_rule_id"] = kwargs.get("rule_id", data.get("original_rule_id", "unknown"))
        data["original_tool"] = kwargs.get("tool_name", data.get("original_tool", "unknown"))

        try:
            return TriagedFinding.model_validate(data)
        except Exception as e:
            logger.debug("output_parser.triage_validate_failed", error=str(e))
            return None

    return None


def _try_json_holistic(text: str, *, files_reviewed: list[str]) -> HolisticReviewResult | None:
    """Try to parse text as JSON HolisticReviewResult."""
    json_str = _extract_json(text)
    if not json_str:
        return None

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.debug("output_parser.json_decode_failed", error=str(e))
        return None

    if isinstance(data, dict):
        if "files_reviewed" not in data:
            data["files_reviewed"] = files_reviewed
        try:
            return HolisticReviewResult.model_validate(data)
        except Exception as e:
            logger.debug("output_parser.holistic_validate_failed", error=str(e))
            return None

    return None


# -- Markdown parsers (prompted providers) ------------------------------------


def _parse_markdown_triage(text: str, **kwargs) -> TriagedFinding | None:
    """Extract verdict, confidence, rationale from markdown text."""
    text_upper = text.upper()

    # Extract verdict
    if "CONFIRMED" in text_upper:
        verdict = TriageVerdict.CONFIRMED
    elif "FALSE_POSITIVE" in text_upper or "FALSE POSITIVE" in text_upper:
        verdict = TriageVerdict.FALSE_POSITIVE
    elif "NEEDS_CONTEXT" in text_upper or "NEEDS CONTEXT" in text_upper:
        verdict = TriageVerdict.NEEDS_CONTEXT
    else:
        logger.debug("output_parser.no_verdict", text_preview=text[:100])
        return None

    # Extract confidence
    default_conf = kwargs.get("default_confidence", 0.5)
    confidence = default_conf
    conf_match = re.search(r"[Cc]onfidence[*:\s]*([0-9.]+)", text)
    if conf_match:
        try:
            c = float(conf_match.group(1))
            confidence = c / 100.0 if c > 1.0 else c
        except ValueError as e:
            logger.debug("output_parser.confidence_parse_failed", raw=conf_match.group(1), error=str(e))
    if confidence == default_conf:
        logger.debug("output_parser.confidence_missing", using_default=default_conf)

    # Extract rationale (everything after "Rationale" header, or whole text)
    rationale_match = re.search(r"[Rr]ationale[:\s*]*\n?(.*)", text, re.DOTALL)
    rationale = rationale_match.group(1).strip() if rationale_match else text.strip()
    # Trim to first ~500 chars for storage
    rationale = rationale[:500].strip()
    if not rationale:
        rationale = f"Verdict: {verdict.value}"

    return TriagedFinding(
        original_rule_id=kwargs["rule_id"],
        original_tool=kwargs["tool_name"],
        file_path=kwargs["file_path"],
        line_number=kwargs["line_number"],
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
    )


def _parse_markdown_holistic(text: str, *, files_reviewed: list[str]) -> HolisticReviewResult | None:
    """Extract findings from markdown sections."""
    findings: list[HolisticFinding] = []

    # Split on markdown headings containing rule IDs (### SR-XXX-NNN or **SR-XXX-NNN**)
    # Also split on "### Finding N" — the table-format style the LLM uses for most checks.
    sections = re.split(r"(?=#{1,3}\s+SR-|\*\*SR-|#{1,3}\s+Finding\s+\d)", text)

    for section in sections:
        finding = _parse_single_finding_section(section)
        if finding:
            findings.append(finding)

    if not findings and ("no issues" in text.lower() or "no findings" in text.lower()):
        return HolisticReviewResult(findings=[], files_reviewed=files_reviewed)

    if findings:
        return HolisticReviewResult(findings=findings, files_reviewed=files_reviewed)

    # If we can't parse anything but the text isn't empty, return empty
    # (the LLM gave analysis but we couldn't extract structured findings)
    if text.strip():
        logger.warning(
            "output_parser.holistic_unparseable",
            text_length=len(text),
            text_preview=text[:200],
        )
        return HolisticReviewResult(findings=[], files_reviewed=files_reviewed, review_notes=text[:1000])

    return None


def _parse_single_finding_section(section: str) -> HolisticFinding | None:
    """Parse a single finding from a markdown section."""
    if not section.strip():
        return None

    # Rule ID: SR-XXX-NNN (e.g. SR-CRED-001, SR-522-001, SR-AUTHZ-001)
    rule_match = re.search(r"(SR-[A-Z0-9]+-\d+)", section)
    if not rule_match:
        return None
    rule_id = rule_match.group(1)

    # Title: text after rule_id on same line (supports :, ·, |, — separators)
    title_match = re.search(r"SR-[A-Z0-9]+-\d+\s*[·:\|—\-]+\s*(.*?)(?:\n|$)", section)
    title = title_match.group(1).strip(" *|—") if title_match else rule_id

    # Severity
    severity = "MEDIUM"
    if re.search(r"\b(critical|CRITICAL)\b", section):
        severity = "CRITICAL"
    elif re.search(r"\b(high|HIGH)\b", section):
        severity = "HIGH"
    elif re.search(r"\b(low|LOW)\b", section):
        severity = "LOW"

    # File path — try formats in order of specificity:
    # 1. **File:** path  or  **File:** `path`  (bold-colon, most common)
    file_match = re.search(r"\*?\*?[Ff]ile\*?\*?[*:\s]*`?([^\s`\n*]+\.\w+)`?", section)
    if not file_match:
        # 2. Table format: "| File | some/path/file.ext |" — any relative path with a /
        file_match = re.search(r"[Ff]ile[^\n]*?([^\s|`\n*]+/[^\s|`\n*]+\.\w+)", section)
    if not file_match:
        # 3. Standalone backtick path anywhere in section — any relative path with a /
        file_match = re.search(r"`([^\s`]+/[^\s`]+\.\w+)`", section)
    file_path = file_match.group(1) if file_match else "unknown"

    # CWE
    cwe_match = re.search(r"CWE-(\d+)", section)
    cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None

    # Evidence: code block content
    code_match = re.search(r"```\w*\n(.*?)```", section, re.DOTALL)
    evidence = code_match.group(1).strip()[:500] if code_match else section[:300].strip()

    # Description: text between title and code block
    desc = section[:500].strip()
    if not desc:
        desc = title

    try:
        return HolisticFinding(
            rule_id=rule_id,
            title=title if title else rule_id,
            description=desc[:500],
            severity=severity,
            file_path=file_path,
            cwe_id=cwe_id,
            remediation="See finding description for remediation guidance.",
            confidence="medium",
            evidence=evidence if evidence else "See description.",
        )
    except Exception as e:
        logger.debug("output_parser.finding_parse_failed", rule_id=rule_id, error=str(e))
        return None


def parse_config_review_response(
    text: str,
    *,
    files_reviewed: list[str],
) -> ConfigReviewResult | None:
    """Parse a config review LLM response into ConfigReviewResult.

    Tries JSON extraction only — CONFIG_FORMAT_JSON prompts all providers to
    return JSON, so there is no markdown fallback here.
    The caller provides the ground-truth file list (P13).
    """
    json_str = _extract_json(text)
    if not json_str:
        return None

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.debug("output_parser.config_json_decode_failed", error=str(e))
        return None

    if isinstance(data, dict):
        data["files_reviewed"] = files_reviewed  # override with known list (P13)
        try:
            return ConfigReviewResult.model_validate(data)
        except Exception as e:
            logger.debug("output_parser.config_validate_failed", error=str(e))
            return None

    return None


# -- Utilities ----------------------------------------------------------------


def _extract_json(text: str) -> str | None:
    """Extract JSON from text — handles code fences and bare objects."""
    # Try ```json ... ```
    match = re.search(r"```json\s*([\s\S]*?)```", text)
    if match:
        return match.group(1).strip()

    # Try bare { ... }
    first = text.find("{")
    last = text.rfind("}")
    if first >= 0 and last > first:
        return text[first:last + 1]

    # Try bare [ ... ]
    first = text.find("[")
    last = text.rfind("]")
    if first >= 0 and last > first:
        candidate = text[first:last + 1]
        if '"' in candidate:  # likely JSON array, not markdown list
            return candidate

    return None
