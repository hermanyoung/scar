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
| `SCAN_TOOL_FAILED` | `ScannerError` | Tool returned unexpected exit code | Check stderr in tool result; may need tool update |

### SARIF_* -- SARIF Processing

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `SARIF_PARSE_FAILED` | `SARIFError` | JSON parse error or invalid SARIF structure | Check tool output; may be corrupt or wrong format |
| `SARIF_CONVERT_FAILED` | `SARIFError` | pip-audit or dotnet-vuln JSON conversion failed | Check raw tool output format |

### LLM_* -- LLM Provider

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `LLM_AUTH_FAILED` | `LLMError` | Provider preflight probe failed (auth/reachability) before Pass 1 — raised by `preflight.probe_provider()`, not just an expired API key | Check `.env` for correct API key, or `gh auth status` / `claude setup-token` for OAuth providers |

### SYS_* -- System Configuration

| Code | Exception | Meaning | Resolution |
|------|-----------|---------|------------|
| `SYS_CONFIG_INVALID` | `ConfigurationError` | YAML config failed Pydantic validation, or a config/taxonomy/pricing file is missing or malformed | Check config against `config_schema.py`; verify the referenced file exists |
| `SYS_CONFIGURATION_ERROR` | `ConfigurationError` | Generic configuration problem | Check error message for specifics |
| `SYS_CWE_NOT_FOUND` | `ConfigurationError` | `config/taxonomy/cwe.yaml` not found, or not a YAML mapping | Ensure the taxonomy file exists and is valid YAML |
| `SYS_SECRET_MISSING` | `ConfigurationError` | Required API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) not set | Set it in the environment or `config/.env` |
| `SYS_DEPENDENCY_MISSING` | `ConfigurationError` | Required Python package or CLI absent (e.g. `codex-auth`, Codex CLI) | Install the missing dependency (see the error message for the exact command) |
| `SYS_TARGET_NOT_FOUND` | `ConfigurationError` | `--target` path does not exist | Check the path passed to `--target` |

---

## Adding New Error Codes

1. Register the code in this document (table above)
2. Use the appropriate exception class from `errors.py`
3. Pass the code as the `code` parameter: `raise ScannerError("Tool timed out", code="SCAN_TOOL_TIMEOUT")`
4. If the error is fatal, verify `is_fatal_error()` handles it correctly
