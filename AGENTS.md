# AGENTS.md — SCAR (Security Code AI Review)

This file provides instructions for AI coding agents (Codex, Copilot, Claude) working on this repository.

## Repository Purpose

This is a security code review module that runs deterministic SAST tools and LLM-powered review passes against C# (.NET) and Python codebases. Output is SARIF 2.1.0 with CWE taxonomy tagging.

## Architecture

The pipeline is: **detect -> scan -> triage -> review -> report**.

- **Pass 1 (Inventory):** File discovery, language detection, security-weight scoring, batch planning.
- **Pass 2 (SAST):** Deterministic tools — OpenGrep, Bandit, betterleaks, Hadolint, Trivy, Roslyn/SecurityCodeScan.
- **Pass 3 (Triage):** LLM confirms/refutes each SAST finding with full-file context.
- **Pass 4 (Holistic):** LLM cross-file analysis — authZ, crypto, deserialization, IDOR, business logic.
- **Pass 5 (Config):** LLM reviews configuration files for security misconfigurations.
- **Merge:** Combine all findings into SARIF + markdown summary + triage.json audit log.

## Critical Rules

1. **Subprocess isolation:** Only `src/security_review/tools/runner.py` calls `asyncio.create_subprocess_exec`. No other module may call subprocess. Never use `shell=True`.
2. **No hardcoded pricing.** All LLM pricing comes from `config/pricing.yaml`.
3. **No hardcoded model strings.** All model strings come from `config/settings/security_review.yaml`.
4. **Budget enforcement** is handled by PydanticAI's `UsageLimits` — do not build custom budget enforcement.
5. **Every finding must have a CWE ID** in the format `CWE-NNN`. Validate against `config/taxonomy/cwe.yaml`.
6. **SARIF output must include CWE taxonomy** in the `taxonomies` block, with `external/cwe/cwe-NNN` tags on every rule.
7. **Agents return `output_type=str`.** All agents use plain text output for provider compatibility. Structured data is extracted by `output_parser.py` (JSON-first, markdown fallback). Do not force Pydantic output models on agents.
8. **File paths in SARIF** always use forward slashes per the SARIF spec.
9. **Never trust LLM-echoed identifiers.** File paths, line numbers, and rule IDs returned by agents must be overridden with the known-correct values from the original data. Bookkeeping is code's job, not the LLM's.
10. **All LLM context is pre-materialized locally.** Agents have zero tools. File content is read locally via `context_builder.py` and inlined in prompts. No `read_file` tool calls through provider SDKs.
11. **No fallbacks — fail fast and loud.** Never silently default to a hardcoded value when config is missing. If a YAML file, config key, or required parameter is absent, raise an error immediately. Pydantic schema fields that must come from config have no `default=` — they are required. Optional fields default to `None` or `0`, never to a "sensible" value that hides a misconfiguration. The YAML is the single source of truth; the schema validates, it does not invent.

## Key Directories

- `src/security_review/` — Python source code
- `config/` — YAML config, prompts, pricing, golden baselines
- `config/golden/` — Golden fixture baselines for regression testing
- `config/rules/` — SAST tool rules (OpenGrep YAML, Gitleaks config, Roslyn props)
- `config/taxonomy/` — CWE registry, tool rule→CWE maps
- `eval/` — Vulnerable code samples for evaluation/regression testing
- `tests/unit/` — Unit tests (no LLM calls, no external tools)
- `tests/regression/` — Golden fixture regression tests (real LLM calls)
- `tests/integration/` — Integration tests (may require external tools)
- `scripts/` — Developer tools (benchmarking, A/B SDK testing)

## Development Conventions

- **Agent prompts** in `config/prompts/` must be kept concise and directive.
- **New OpenGrep rules** must include a matching test file (`.py` or `.cs`) with `ruleid:` and `ok:` annotations.
- **New CWEs:** update `config/taxonomy/cwe.yaml` first, then add rules and tests.
- **Spec:** architectural decisions are documented at `docs/98-research/001-security-code-review-module-spec.md`.

## Testing

```bash
pytest tests/unit/ -v          # Unit tests (no external tools needed)
pytest tests/integration/ -v   # Integration tests (may require bandit, gitleaks, etc.)
python scar.py health-check  # Check tool availability
```

PydanticAI tests use `ALLOW_MODEL_REQUESTS = False` in `tests/conftest.py`. Use `TestModel` or `FunctionModel` for deterministic agent testing.

### Regression Tests (Golden Fixtures)

Golden fixture tests compare live CWE detection results against a known-good baseline stored in `config/golden/example-target.yaml`. They make **real LLM calls** and must be run separately from unit tests.

```bash
# Run regression for one provider
pytest tests/regression/ -v --provider copilot:claude-opus

# Run all providers (55 tests = 11 CWEs × 5 providers)
pytest tests/regression/ -v

# Filter by CWE
pytest tests/regression/ -v -k "CWE-312"

# Update golden baseline after a verified improvement
pytest tests/regression/ -v --provider copilot:claude-opus --save-golden
```

- **PASS → FAIL** = `pytest.fail()` (regression detected)
- **FAIL → FAIL** = `pytest.xfail()` (known gap, not a regression)
- **FAIL → PASS** = improvement (test passes, update golden with `--save-golden`)

### A/B SDK Testing

Use the benchmark script to compare SDK versions before upgrading:

```bash
python scripts/benchmark_cwes.py --ab-sdk 0.2.2,0.3.0 --runs 3 --providers copilot:claude-opus
```

### SDK Version Pinning

The Copilot SDK is pinned to `0.2.2` in `requirements.txt` and `pyproject.toml`. Version `0.3.0` has a confirmed regression (CWE-312/522 fail 100% of the time due to suspected prompt truncation). Always A/B test before upgrading.
