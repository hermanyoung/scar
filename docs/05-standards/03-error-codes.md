# Error Codes

*Applies to: `src/security_review/errors.py` and all modules that raise exceptions*

This document is the registry for all error codes used in the security review module. New error codes must be registered here before use.

---

## Error Code Structure

Format: `{CATEGORY}_{NOUN}_{STATE}` (UPPER_SNAKE_CASE)

| Component | Purpose | Examples |
|-----------|---------|----------|
| Category | Which subsystem | `SCAN_`, `SARIF_`, `LLM_`, `SYS_` |
| Noun | What entity | `TOOL`, `OUTPUT`, `CONFIG`, `PROMPT` |
| State | What went wrong | `FAILED`, `INVALID`, `MISSING`, `TIMEOUT` |

---

## Exception Hierarchy

```
SecurityReviewError (base)
    ScannerError        # SCAN_* codes
    SARIFError          # SARIF_* codes
    LLMError            # LLM_* codes
    ConfigurationError  # SYS_* codes
```

All exceptions carry a `.code` attribute with the registered error code and a human-readable `.message`.

---

## Fatal vs. Transient Classification

`is_fatal_error()` in `errors.py` determines if an error should halt the pipeline:

| Fatal (halt pipeline) | Transient (log, continue) |
|----------------------|--------------------------|
| `ConfigurationError` | `asyncio.TimeoutError` |
| `AuthenticationError` (provider SDK) | Rate limit errors |
| `PermissionDeniedError` (provider SDK) | Single-batch schema mismatch |
| `FileNotFoundError` | `ScannerError` (tool not found) |
| `PermissionError` | Network transient errors |

---

## Registered Error Codes

### SCAN_* -- Scanner Execution

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `SCAN_TOOL_TIMEOUT` | `ScannerError` | Tool exceeded `scanner_timeout_seconds` | Increase timeout in config or reduce target scope |
| `SCAN_TOOL_NOT_FOUND` | `ScannerError` | Binary not on PATH | Run `security-review doctor` to check tool availability |
| `SCAN_TOOL_FAILED` | `ScannerError` | Tool returned unexpected exit code | Check stderr in tool result; may need tool update |
| `SCAN_OUTPUT_MISSING` | `ScannerError` | Tool ran but produced no output file | Check tool spec `output_capture` setting |

### SARIF_* -- SARIF Processing

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `SARIF_PARSE_FAILED` | `SARIFError` | JSON parse error or invalid SARIF structure | Check tool output; may be corrupt or wrong format |
| `SARIF_VERSION_INVALID` | `SARIFError` | SARIF version is not 2.1.0 | Tool may need `--sarif-version` flag |
| `SARIF_CONVERT_FAILED` | `SARIFError` | pip-audit or dotnet-vuln JSON conversion failed | Check raw tool output format |

### LLM_* -- LLM Provider

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `LLM_AUTH_FAILED` | `LLMError` | Provider preflight probe failed (auth/reachability) before Pass 1 — raised by `preflight.probe_provider()`, not just an expired API key | Check `.env` for correct API key, or `gh auth status` / `claude setup-token` for OAuth providers |
| `LLM_OUTPUT_INVALID` | `LLMError` | LLM response failed Pydantic validation after retries | Check prompt; may need output_retries increase |
| `LLM_BUDGET_EXCEEDED` | `LLMError` | UsageLimits token/request limit reached | Increase limits or reduce batch size |
| `LLM_PROVIDER_ERROR` | `LLMError` | Provider returned 5xx or network error | Transient; retry or switch provider |

### SYS_* -- System Configuration

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `SYS_CONFIG_INVALID` | `ConfigurationError` | YAML config failed Pydantic validation | Check config against `config_schema.py` |
| `SYS_CONFIG_MISSING` | `ConfigurationError` | Required config file not found | Ensure `config/settings/` files exist |
| `SYS_CONFIGURATION_ERROR` | `ConfigurationError` | Generic configuration problem | Check error message for specifics |
| `SYS_PROMPT_MISSING` | `ConfigurationError` | Prompt file not found in `config/prompts/` | Ensure prompt markdown files are present |
| `SYS_CWE_REGISTRY_MISSING` | `ConfigurationError` | `taxonomy/cwe.yaml` not found | Ensure taxonomy files are present |

---

## Adding New Error Codes

1. Register the code in this document (table above)
2. Use the appropriate exception class from `errors.py`
3. Pass the code as the `code` parameter: `raise ScannerError("Tool timed out", code="SCAN_TOOL_TIMEOUT")`
4. If the error is fatal, verify `is_fatal_error()` handles it correctly
