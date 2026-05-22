"""Secret pattern redaction in tool output and SARIF documents."""
from __future__ import annotations

import re

from security_review.sarif.types import SarifDocument

# Patterns for common secrets that should be redacted in output
_SECRET_PATTERNS = [
    # API keys, tokens, passwords in various formats
    re.compile(r'(?i)(api[_-]?key|token|password|secret|credential|auth)["\s:=]+["\']?([a-zA-Z0-9_\-./+=]{8,})["\']?'),
    # AWS access keys
    re.compile(r'AKIA[0-9A-Z]{16}'),
    # GitHub tokens
    re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    # Generic base64 secrets (long base64 strings after key-like identifiers)
    re.compile(r'(?i)(key|secret|password)\s*[=:]\s*["\']?([A-Za-z0-9+/]{32,}={0,2})["\']?'),
]

_REDACTED = "***REDACTED***"


def redact_secrets(text: str) -> str:
    """Replace secret patterns in text with redaction markers."""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(
            lambda m: m.group(0)[:len(m.group(1)) + 1] + _REDACTED if m.lastindex and m.lastindex >= 1 else _REDACTED,
            result,
        )
    return result


def redact_sarif(sarif: SarifDocument) -> SarifDocument:
    """Redact secret patterns from SARIF message texts and code snippets."""
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            # Redact message text
            message = result.get("message", {})
            if "text" in message:
                message["text"] = redact_secrets(message["text"])

            # Redact code snippets
            for location in result.get("locations", []):
                phys = location.get("physicalLocation", {})
                snippet = phys.get("region", {}).get("snippet", {})
                if "text" in snippet:
                    snippet["text"] = redact_secrets(snippet["text"])

                context = phys.get("contextRegion", {}).get("snippet", {})
                if "text" in context:
                    context["text"] = redact_secrets(context["text"])

    return sarif
