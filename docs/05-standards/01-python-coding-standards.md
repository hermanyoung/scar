# Python Coding Standards

*Applies to: all Python code in `src/security_review/`, `scripts/`, `tests/`*

This document defines how we write Python in this project. It complements the reference architecture generic standards (`docs/99-reference-architecture/07-core-python-coding-standards.md`) with project-specific conventions.

Automated enforcement: `python scripts/check_rules.py --all` runs 31 checks from `docs/04-rules/*.jsonl` (2 of the 33 documented rules — 002.8 and 003.8 — are marked for manual review since "no silent fallback" requires human judgment, not a pattern match).

---

## File Organization

### Size Limits

- **Target:** 400 lines per file
- **Hard limit:** 1000 lines (enforced by rule 002.1)
- Split large files by responsibility, not by arbitrary line counts

### Import Conventions

**Absolute imports only.** No relative imports anywhere. (Rule 001.1)

```python
# Correct
from security_review.models.findings import TriagedFinding
from security_review.logging import get_logger

# Wrong
from .models import TriagedFinding
from ..logging import get_logger
```

**No direct `import logging`.** Use the centralized `get_logger()`. (Rule 001.2)

```python
# Correct
from security_review.logging import get_logger
logger = get_logger(__name__)

# Wrong
import logging
logger = logging.getLogger(__name__)
```

### `__init__.py` Files

Minimal -- docstring and re-exports only. No classes or functions. (Rule 001.3)

---

## Configuration

### Secrets

Secrets come from `.env` via `pydantic-settings`. Never hardcode API keys, tokens, or passwords. (Rule 003.1)

### Application Config

Application config comes from `config/settings/*.yaml` via Pydantic schemas with `extra="forbid"`. (Rule 003.4)

```python
# config_schema.py -- extra="forbid" catches YAML typos at load time
class LLMConfig(BaseModel, extra="forbid"):
    provider_model: str = Field(default="openai:gpt-5.5", pattern=r"^(openai|anthropic|copilot):.+$")
```

### No Hardcoded Fallbacks

Never use `os.getenv("KEY", "default_value")` in module code. Secrets come from Settings, config from YAML. (Rule 003.5)

---

## Error Handling

### Fail Fast, Fail Loudly

Every `except` block must either:
1. **Log at WARNING+ and re-raise** (for fatal errors)
2. **Log at WARNING+ and continue** (for batch-level transient errors)
3. **Return a value that communicates the error** (for agent tool functions)

Never: `except: pass`, `except Exception: continue` without logging, or silent fallback to a default value. (Rules 002.7, 002.8)

```python
# Correct: log + re-raise on fatal
except Exception as e:
    logger.error("agent.failed", agent_name="triage", error=str(e), error_type=type(e).__name__)
    if is_fatal_error(e):
        raise

# Correct: agent tool returns error string to LLM
except OSError as e:
    return f"Error reading {file_path}: {e}"

# Wrong: silent swallow
except Exception:
    pass
```

### Fatal vs. Transient Errors

Use `is_fatal_error()` from `errors.py` to distinguish:
- **Fatal** (halt pipeline): `ConfigurationError`, `AuthenticationError`, `PermissionDeniedError`, `FileNotFoundError`
- **Transient** (log, skip batch, continue): timeouts, rate limits, single-batch schema mismatches

### Error Taxonomy

Error codes follow `{CATEGORY}_{NOUN}_{STATE}` convention:
- `SCAN_*` -- Scanner/tool execution errors
- `SARIF_*` -- SARIF parsing and conversion errors
- `LLM_*` -- LLM provider and output errors
- `SYS_*` -- System configuration and environment errors

All errors inherit from `SecurityReviewError` and carry a `.code` attribute.

---

## Logging

### Setup

Use `setup_logging()` from `security_review.logging`. Console output goes to stderr. File output goes to `var/logs/system.jsonl` with daily rotation.

```python
from security_review.logging import setup_logging, get_logger

setup_logging()  # Loads config from config/settings/logging.yaml
logger = get_logger(__name__)
```

### Structured Fields

Every log record includes: `timestamp`, `level`, `logger`, `event`, `func_name`, `lineno`, plus any caller-provided context via kwargs.

```python
logger.info("tool.completed", tool_name="bandit", duration_ms=1523, exit_code=0)
logger.error("agent.failed", agent_name="triage", batch_id="b001", error=str(e), error_type=type(e).__name__)
```

### Pipeline Context

Pipeline passes bind `run_id`, `target`, and `mode` via `structlog.contextvars` so every log entry within a pipeline run includes these fields automatically.

---

## Layer Boundaries

### Module Dependency Rules

| Layer | May import from | Must not import from |
|-------|----------------|---------------------|
| `models/` | stdlib, pydantic | passes, agents, tools |
| `tools/` | models, stdlib | pydantic_ai, agents |
| `agents/` | models, deps | tools/runner |
| `passes/` | agents, tools, models | (no restrictions) |
| `sarif/` | models, stdlib | agents, tools, passes |

(Rules 001.6, 001.7, 001.8)

### Subprocess Isolation

Only `tools/runner.py` calls `asyncio.create_subprocess_exec`. Never `shell=True`. (Rules 001.4, 001.5)

---

## Async Patterns

All pipeline execution is async. No sync blocking calls in async context. (Rule 002.6)

- Use `asyncio.create_subprocess_exec` (not `subprocess.run`)
- Use `asyncio.gather` for concurrent tool execution (with `return_exceptions=True`)
- Use `asyncio.wait_for` for timeouts
- Never `time.sleep()` -- use `asyncio.sleep()` if needed

---

## Type Annotations

All public function signatures should have type annotations for parameters and return values. Use `from __future__ import annotations` for forward references.

Pydantic models validate all external boundaries:
- LLM output: `TriagedFinding`, `HolisticFinding`, `ConfigFinding`
- Config: `SecurityReviewConfig` with `extra="forbid"`
- SARIF: Validated at load time via `sarif/loader.py`
