"""Provider capability detection for format-aware agent calls.

This is the single source of truth for structured output strategy.

Native JSON providers (anthropic, openai):
  - PydanticAI enforces the JSON schema via tool calling / JSON mode.
  - Pass output_type=<PydanticModel> to agent.run() — result is a validated instance.
  - No format instruction needed in the prompt.

Prompted providers (copilot, claude):
  - Model returns free-form text (markdown or informal JSON).
  - Pass output_type=str to agent.run().
  - Append TRIAGE_FORMAT_MARKDOWN / CONFIG_FORMAT_JSON to the user prompt.
  - output_parser.py extracts the structured data from the response.

Usage in a pass:
    model = build_model(model_string, llm_config=config.llm)
    native = supports_native_json(model)

    result = await agent.run(
        prompt if native else prompt + "\\n\\n" + TRIAGE_FORMAT_MARKDOWN,
        output_type=TriagedFinding if native else str,
    )

    if isinstance(result.output, str):
        verdict = parse_triage_response(result.output, ...)
    else:
        verdict = result.output  # Already a validated Pydantic model
"""
from __future__ import annotations

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Format instructions injected for prompted providers (copilot:, claude:)
#
# These format blocks are output contracts coupled to output_parser.py's
# regexes — deliberately code, not config/prompts/ (P5 exemption, plan 021):
# editing them without updating the parser silently breaks finding extraction.
# ---------------------------------------------------------------------------

TRIAGE_FORMAT_MARKDOWN = """\
**Output format:** State your verdict in this exact format:

```
**Verdict:** CONFIRMED | FALSE_POSITIVE | NEEDS_CONTEXT
**Confidence:** 0.0 to 1.0
**Rationale:** Your reasoning in 1-3 sentences
```

These three fields are mandatory."""

HOLISTIC_FORMAT_MARKDOWN = """\
**Output format:** For each finding use this exact format:

### SR-{CATEGORY}-{NNN} — Title
**Severity:** CRITICAL | HIGH | MEDIUM | LOW
**File:** path/to/file.ext
**CWE:** CWE-{NNN}
**Evidence:**
```
code quote
```
**Remediation:** How to fix it.

If no issues found for this CWE, say "No findings."
"""

CONFIG_FORMAT_JSON = """\
**Output format:** Respond with a JSON object matching this structure:

{
  "findings": [
    {
      "rule_id": "SR-CFG-001",
      "title": "Short title",
      "severity": "HIGH",
      "description": "What the issue is and why it matters.",
      "file_path": "path/to/file.json",
      "cwe_id": "CWE-200",
      "evidence": "The specific line or value that is problematic.",
      "remediation": "How to fix it."
    }
  ],
  "files_reviewed": ["path/to/file.json"]
}

severity must be one of: CRITICAL, HIGH, MEDIUM, LOW.
cwe_id may be null if no CWE applies.
If no issues found: {"findings": [], "files_reviewed": [...]}"""

# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------


def supports_native_json(model) -> bool:
    """Return True if this model enforces JSON schema output natively.

    Native JSON providers (anthropic, openai) use PydanticAI's built-in schema
    injection — output_type=SomePydanticModel produces a validated instance
    directly with no post-processing.

    Prompted providers (copilot, claude) return free-form text and need explicit
    format instructions plus output_parser.py for extraction.
    """
    try:
        return bool(model.profile.supports_json_schema_output)
    except AttributeError as e:
        logger.debug("model_capabilities.no_profile", model=type(model).__name__, error=str(e))
        return False
