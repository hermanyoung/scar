# Testing Standards

*Applies to: all test code in `tests/`*

This document defines how we write and organize tests, with project-specific patterns for PydanticAI agents, SARIF processing, and eval/regression testing.

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
        test_betterleaks_scan.py # Requires betterleaks binary
        test_opengrep_scan.py    # Requires opengrep binary
        test_triage_agent.py     # Agent with FunctionModel
        test_full_pipeline.py    # End-to-end pipeline (sast mode)
        test_eval_scorer.py      # Eval corpus scoring
    regression/
        __init__.py
        conftest.py               # Golden-fixture fixtures
        test_golden.py            # Golden-fixture CWE detection regression
    eval/
        __init__.py
        runner.py                 # Snapshot regression harness
```

---

## Running Tests

```bash
pytest tests/unit/ -v           # Unit tests (no external tools, no API keys)
pytest tests/integration/ -v    # Integration tests (may require bandit, gitleaks)
python scripts/check_rules.py --all  # Code rules check (31 automated rules)
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

Agents use `output_type=str` (ADR-004) — even for providers with native JSON
support, `result.output` is always plain text. Parsing into a validated
model (`TriagedFinding`, `HolisticReviewResult`, `ConfigReviewResult`)
happens downstream via `output_parser.py`, not inside the agent. Tests
exercise that two-step contract, not a raw structured return value —
asserting `result.output.total_confirmed` or similar will not work.

Agents are built via factory functions, not imported as fixed singletons —
`build_triage_agent(output_retries)`, `build_holistic_agent(output_retries)`,
`build_config_review_agent(output_retries)` in `security_review.agents.*.agent`.
`output_retries` is a pydantic-ai constructor-only argument, so each pass
builds its agent from `state.config.llm.output_retries` at call time rather
than importing one fixed instance.

### TestModel (Canned Output)

For tests that only need to verify the agent runs and returns text:

```python
from pydantic_ai.models.test import TestModel

from security_review.agents.triage.agent import build_triage_agent

async def test_triage_agent_runs(mock_deps):
    agent = build_triage_agent(output_retries=3)
    result = await agent.run("Triage this finding", deps=mock_deps, model=TestModel())
    assert isinstance(result.output, str)
```

### FunctionModel (Computed Output)

For tests that need a specific response — e.g. to verify `output_parser.py`
extracts it correctly. The function must return a `ModelResponse`, not a
bare string or `.model_dump_json()` output:

```python
import json

from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel

from security_review.agents.triage.agent import build_triage_agent
from security_review.output_parser import parse_triage_response

def mock_triage_response(messages, info):
    return ModelResponse(parts=[TextPart(json.dumps({
        "findings": [{"verdict": "CONFIRMED", "confidence": 0.95, "rationale": "..."}],
    }))])

async def test_triage_with_function_model(mock_deps):
    agent = build_triage_agent(output_retries=3)
    result = await agent.run(
        "Triage...", deps=mock_deps, model=FunctionModel(mock_triage_response),
    )
    finding = parse_triage_response(
        result.output, file_path="app.py", line_number=13,
        rule_id="B602", tool_name="bandit", default_confidence=0.5,
    )
    assert finding.verdict.value == "CONFIRMED"
```

See `tests/integration/test_triage_agent.py` for the full working version of
this pattern, including the P13 identifier-override assertions (the LLM's
echoed `file_path`/`line_number`/`rule_id` must be overridden with the
caller's ground truth, never trusted).

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

- **Tool execution:** run bandit/gitleaks/opengrep against `eval/` fixtures, verify SARIF output
- **Agent integration:** run triage agent with FunctionModel against sample findings
- **Pipeline:** run full pipeline in `--mode sast` against vulnerable eval samples

### Eval Snapshot Regression (deterministic, no LLM)

`tests/eval/runner.py` provides a SAST-only snapshot regression harness:
- Run SAST tools against `eval/` vulnerable samples
- Compare output against each entry's own `expected.sarif` baseline
- Fail if findings change unexpectedly

### Golden Fixture Regression (real LLM calls — run separately)

`tests/regression/test_golden.py` runs live CWE detection against a
reference target and compares results to `config/golden/example-target.yaml`.
These make real LLM calls and must never run alongside `pytest tests/unit/`:

```bash
pytest tests/regression/ -v --provider copilot:claude-opus
```

See `docs/05-standards/04-benchmarking-standards.md` for the full baseline
and update workflow.

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
- External tool installation (use `python scar.py health-check` for that)
- Exact log messages (test behavior, not logging strings)
- Private functions directly (test through public API)
