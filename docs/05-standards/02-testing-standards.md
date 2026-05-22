# Testing Standards

*Applies to: all test code in `tests/`*

This document defines how we write and organize tests. It complements the reference architecture testing standards (`docs/99-reference-architecture/12-core-testing-standards.md`) with project-specific patterns for PydanticAI agents, SARIF processing, and corpus regression testing.

---

## Directory Structure

```
tests/
    __init__.py
    conftest.py                  # Shared fixtures, ALLOW_MODEL_REQUESTS=False
    unit/
        __init__.py
        test_findings_model.py   # Pydantic model validation
        test_inventory.py        # File discovery, security weighting
        test_cwe_taxonomy.py     # CWE registry, tag normalization
        test_sarif_loader.py     # SARIF parsing, version validation
        test_sarif_merger.py     # Deduplication, severity escalation
        test_tool_registry.py    # Tool spec loading, command building
    integration/
        __init__.py
        test_bandit_scan.py      # Requires bandit binary
        test_gitleaks_scan.py    # Requires gitleaks binary
        test_opengrep_scan.py    # Requires opengrep binary
        test_triage_agent.py     # Agent with FunctionModel
        test_full_pipeline.py    # End-to-end pipeline (sast mode)
    corpus/
        __init__.py
        runner.py                # Snapshot regression harness
```

---

## Running Tests

```bash
pytest tests/unit/ -v           # Unit tests (no external tools, no API keys)
pytest tests/integration/ -v    # Integration tests (may require bandit, gitleaks)
python scripts/check_rules.py --all  # Code rules check (16 automated rules)
python scripts/code_quality.py --no-bandit --no-radon  # PQI quality score
```

---

## Core Invariant: No Real LLM Calls

`tests/conftest.py` sets `ALLOW_MODEL_REQUESTS = False` globally:

```python
from pydantic_ai import models as pydantic_ai_models
pydantic_ai_models.ALLOW_MODEL_REQUESTS = False
```

Any test that accidentally makes a real LLM call will fail immediately. This is non-negotiable (Principle P8).

---

## Agent Testing Patterns

### TestModel (Canned Output)

For tests that only need to verify the agent produces valid output:

```python
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

async def test_triage_returns_valid_output():
    result = await triage_agent.run(
        "Triage these findings...",
        deps=mock_deps,
        model=TestModel(),
    )
    assert result.output.total_confirmed >= 0
```

### FunctionModel (Computed Output)

For tests that need realistic agent behavior with tool calls:

```python
from pydantic_ai.models.function import FunctionModel

def mock_triage_response(messages, info):
    return TriageResult(
        findings=[...],
        total_confirmed=1,
        total_false_positive=0,
        total_needs_context=0,
    ).model_dump_json()

async def test_triage_with_function_model():
    result = await triage_agent.run(
        "Triage...",
        deps=mock_deps,
        model=FunctionModel(mock_triage_response),
    )
```

---

## Fixture Hierarchy

### Root Fixtures (`tests/conftest.py`)

Shared across all test types:

| Fixture | Purpose |
|---------|---------|
| `vulnerable_python_app` | CWE-094, CWE-078, CWE-798, CWE-089 test cases |
| `vulnerable_csharp_app` | CWE-089, CWE-502, CWE-862 test cases |
| `clean_python_app` | Zero-finding baseline |
| `clean_csharp_app` | Zero-finding baseline with proper security controls |
| `sample_sarif` | Minimal valid SARIF 2.1.0 with 3 findings across 2 tools |

### Test-Type Fixtures

Integration tests may add fixtures in `tests/integration/conftest.py` for tool-specific setup (temp directories, config overrides).

---

## What to Test

### Unit Tests (fast, deterministic, no I/O)

- **Pydantic model validation:** field constraints, validators, normalization (severity uppercase, CWE pattern, rule ID format)
- **SARIF processing:** loading, parsing, merging, deduplication, CWE tag normalization
- **Inventory:** file exclusion patterns, security weight scoring, batch planning
- **Config:** schema validation with `extra="forbid"`, default values, override merging
- **Error classification:** `is_fatal_error()` for auth, config, transient errors

### Integration Tests (may require external tools)

- **Tool execution:** run bandit/gitleaks/opengrep against corpus fixtures, verify SARIF output
- **Agent integration:** run triage agent with FunctionModel against sample findings
- **Pipeline:** run full pipeline in `--mode sast` against vulnerable corpus

### Corpus Regression Tests

`tests/corpus/runner.py` provides a snapshot regression harness:
- Run SAST tools against `corpus/` vulnerable samples
- Compare output against `expected.sarif` baselines
- Fail if findings change unexpectedly

---

## Coverage Targets

| Category | Target | Rationale |
|----------|--------|-----------|
| Models (findings, inventory, config) | 100% | Data validation is critical path |
| SARIF (loader, merger, tags, taxonomy) | 100% | Output correctness |
| Tools (runner, registry) | 90% | Subprocess boundary |
| Passes (pipeline, orchestrators) | 80% | Orchestration logic |
| Agents (triage, holistic, config) | 70% | LLM output is non-deterministic |

---

## Test Naming

```
test_{module}_{behavior}_{scenario}

# Examples
test_merge_dedup_highest_severity
test_holistic_finding_valid
test_load_sarif_missing_file
test_walk_files_excludes_pycache
```

---

## What NOT to Test

- LLM output quality (non-deterministic -- use prompt evaluation, not unit tests)
- External tool installation (use `doctor` command for that)
- Exact log messages (test behavior, not logging strings)
- Private functions directly (test through public API)
