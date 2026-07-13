"""Error taxonomy for the security review module.

Error codes follow {CATEGORY}_{NOUN}_{STATE} convention (UPPER_SNAKE_CASE).
Categories: SCAN_, SARIF_, LLM_, SYS_
"""


class SecurityReviewError(Exception):
    """Base exception for all security review errors."""

    def __init__(self, message: str, code: str):
        self.code = code
        super().__init__(message)


class ScannerError(SecurityReviewError):
    """Scanner/tool execution errors (SCAN_*)."""
    ...


class SARIFError(SecurityReviewError):
    """SARIF parsing and conversion errors (SARIF_*)."""
    ...


class LLMError(SecurityReviewError):
    """LLM provider and output errors (LLM_*)."""
    ...


class ConfigurationError(SecurityReviewError):
    """System configuration and environment errors (SYS_*)."""
    ...


_OVERFLOW_PATTERNS = (
    "context length", "context_length_exceeded", "maximum context",
    "prompt is too long", "request too large", "token limit",
    "input is too long", "exceeds the maximum",
)


def is_context_overflow_error(exc: Exception) -> bool:
    """True if the exception message indicates the prompt exceeded the model's context window."""
    msg = str(exc).lower()
    return any(p in msg for p in _OVERFLOW_PATTERNS)


def is_fatal_error(exc: Exception) -> bool:
    """Determine if an exception is fatal and should halt the pipeline.

    Fatal errors are auth failures, config errors, and permission issues
    that will fail every subsequent batch identically. Transient errors
    (timeouts, rate limits, single-batch schema mismatches) are non-fatal.
    """
    # Our own config/auth errors
    if isinstance(exc, ConfigurationError):
        return True

    # Provider auth/model errors (OpenAI, Anthropic, Copilot SDKs)
    type_name = type(exc).__name__
    if type_name in ("AuthenticationError", "PermissionDeniedError", "JsonRpcError"):
        return True

    # Check error message for model-not-available patterns
    err_msg = str(exc).lower()
    if "not available" in err_msg or "not supported" in err_msg or "api key" in err_msg:
        return True

    # Missing prompt files, missing config — fail fast
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return True

    return False
