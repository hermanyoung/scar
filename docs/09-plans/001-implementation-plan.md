# Security Code Review Module - Implementation Plan

**Source Spec:** `docs/98-research/001-security-code-review-module-spec.md`
**Created:** 1 May 2026
**Status:** In Progress

---

## Phase 1: Foundation

**Goal:** Project scaffold, package config, error taxonomy, configuration schemas, structured logging.

**Files:**
- `pyproject.toml` — package metadata, dependencies, extras
- `src/security_review/__init__.py` — version export
- `src/security_review/__main__.py` — `python -m security_review` entry point
- `src/security_review/errors.py` — `SecurityReviewError` hierarchy (SCAN_, SARIF_, LLM_, SYS_)
- `src/security_review/config_schema.py` — `LLMConfig`, `SASTConfig`, `TriageConfig`, `ReviewConfig`, `SecurityReviewConfig`
- `src/security_review/config.py` — `Settings` (secrets via .env), `load_config()` (YAML), `get_settings()`
- `src/security_review/logging.py` — structlog setup with `configure_logging(verbose, json_output)`

**Dependencies:** pydantic, pydantic-settings, structlog, typer, pyyaml, click

**Acceptance:** `python -c "from security_review.config_schema import SecurityReviewConfig; print(SecurityReviewConfig())"` succeeds.

---

## Phase 2: Pydantic Models

**Goal:** All typed output models used across the pipeline.

**Files:**
- `src/security_review/models/__init__.py`
- `src/security_review/models/findings.py` — `Severity`, `TriageVerdict`, `TriagedFinding`, `TriageResult`, `BaseFinding`, `HolisticFinding`, `HolisticReviewResult`
- `src/security_review/models/inventory.py` — `FileEntry`, `FileManifest`, `SecurityWeight`, `Batch`, `BatchPlan`
- `src/security_review/models/config_review.py` — `ConfigFinding`, `ConfigReviewResult`
- `src/security_review/models/report.py` — `SecurityReport`, `ToolResult`

**Dependencies:** Phase 1 (errors.py for error codes)

**Acceptance:** All models instantiate with valid data; validators fire on invalid data.

---

## Phase 3: SARIF Processing

**Goal:** Load, merge, convert, deduplicate, and tag SARIF documents.

**Files:**
- `src/security_review/sarif/__init__.py`
- `src/security_review/sarif/loader.py` — `load_sarif()` parses and normalises SARIF 2.1.0
- `src/security_review/sarif/merger.py` — `merge_sarif()` with dedup by `(cwe_id, file_path, line_number)`, highest severity wins
- `src/security_review/sarif/converter.py` — convert JSON/JSONL (pip-audit, dotnet) to SARIF
- `src/security_review/sarif/taxonomy.py` — `build_cwe_taxonomy()` for SARIF taxonomies block
- `src/security_review/sarif/tags.py` — `normalise_cwe_tags()` for `external/cwe/cwe-NNN` format

**Dependencies:** Phase 1 (errors.py), Phase 2 (models for severity enum)

**Acceptance:** Can load a sample SARIF, merge two SARIF docs, verify CWE taxonomy in output.

---

## Phase 4: Tools Infrastructure

**Goal:** Tool registry, subprocess runner, secret redaction, tool spec YAML files.

**Files:**
- `src/security_review/tools/__init__.py`
- `src/security_review/tools/registry.py` — `SecurityToolSpec`, `OutputFormat`, `OutputCapture`, `load_tool_specs()`, `resolve_tools_for_manifest()`
- `src/security_review/tools/runner.py` — `run_tool()` async subprocess execution (only subprocess caller)
- `src/security_review/tools/redactor.py` — secret pattern redaction in tool output
- `src/security_review/tools/specs/opengrep.yaml`
- `src/security_review/tools/specs/bandit.yaml`
- `src/security_review/tools/specs/gitleaks.yaml`
- `src/security_review/tools/specs/roslyn.yaml`
- `src/security_review/tools/specs/security_scan.yaml`
- `src/security_review/tools/specs/pip_audit.yaml`
- `src/security_review/tools/specs/dotnet_vuln.yaml`

**Dependencies:** Phase 1 (errors.py, config_schema.py)

**Acceptance:** `load_tool_specs()` loads all YAML specs; `build_command()` produces correct arg lists; `run_tool()` with a mock binary returns `ToolResult`.

---

## Phase 5: Pass 1 - Inventory & Batching

**Goal:** File discovery, language detection, security-weight scoring, token-aware batch planning.

**Files:**
- `src/security_review/passes/__init__.py`
- `src/security_review/passes/inventory.py` — `run_inventory(state)` discovers files, builds manifest, assigns security weights
- `src/security_review/passes/batching.py` — `plan_batches()` partitions files into token-aware batches

**Dependencies:** Phase 2 (inventory models), Phase 1 (config, logging)

**Acceptance:** Given a test directory, produces a `FileManifest` excluding `obj/`, `bin/`, `__pycache__/` etc. Security weights >= 2 for controller/auth files. Batches respect `max_tokens_per_batch`.

---

## Phase 6: Pass 2 - SAST Orchestration

**Goal:** Run deterministic SAST tools, collect and merge SARIF output.

**Files:**
- `src/security_review/passes/sast.py` — `run_sast(state)` resolves applicable tools, runs them concurrently, merges SARIF

**Dependencies:** Phase 3 (SARIF loader/merger), Phase 4 (tool registry/runner), Phase 5 (inventory for manifest)

**Acceptance:** Given a vulnerable Python app, runs bandit + gitleaks, produces merged SARIF with findings.

---

## Phase 7: LLM Infrastructure

**Goal:** Provider routing, cost tracking, dependency injection container, evidence manifest.

**Files:**
- `src/security_review/providers.py` — `build_model()` with openai/anthropic/copilot routing
- `src/security_review/copilot_model.py` — CopilotModel adapter (stub for optional use)
- `src/security_review/budget.py` — `CostTracker`, `CostEntry`, `ModelPricing`
- `src/security_review/agents/__init__.py`
- `src/security_review/agents/deps.py` — `SecurityReviewDeps`, `load_prompt()`
- `src/security_review/evidence.py` — `EvidenceManifest` (SHA-256, append-only)

**Dependencies:** Phase 1 (config, errors), Phase 2 (models)

**Acceptance:** `build_model("openai:gpt-5.5")` returns an `OpenAIModel`; `CostTracker.record()` computes cost from pricing YAML; `EvidenceManifest` computes SHA-256 and rejects duplicates.

---

## Phase 8: Pass 3 - Triage Agent

**Goal:** LLM agent that confirms/refutes each SAST finding with full-file context.

**Files:**
- `src/security_review/agents/triage/__init__.py`
- `src/security_review/agents/triage/agent.py` — PydanticAI triage agent with output validator
- `src/security_review/passes/triage.py` — `run_triage(state)` orchestration (batching, agent calls, result merge)

**Dependencies:** Phase 7 (providers, deps, budget), Phase 2 (findings models), Phase 5 (batching)

**Acceptance:** With `TestModel`, agent produces valid `TriageResult`; validators enforce T-01 through T-04 invariants.

---

## Phase 9: Pass 4 - Holistic Review Agent

**Goal:** LLM agent for cross-file security analysis (authZ, crypto, deser, IDOR, etc.).

**Files:**
- `src/security_review/agents/holistic/__init__.py`
- `src/security_review/agents/holistic/agent.py` — PydanticAI holistic agent with output validator
- `src/security_review/passes/holistic.py` — `run_holistic(state)` orchestration

**Dependencies:** Phase 7, Phase 2 (HolisticFinding models), Phase 5 (batching)

**Acceptance:** With `TestModel`, agent produces valid `HolisticReviewResult`; validators enforce H-01 through H-04 invariants.

---

## Phase 10: Pass 5 - Config Review Agent

**Goal:** LLM agent for configuration file security review.

**Files:**
- `src/security_review/agents/config_review/__init__.py`
- `src/security_review/agents/config_review/agent.py` — PydanticAI config review agent
- `src/security_review/passes/config_review.py` — `run_config_review(state)` orchestration

**Dependencies:** Phase 7, Phase 2 (ConfigFinding models)

**Acceptance:** With `TestModel`, agent produces valid `ConfigReviewResult`; validators enforce C-01, C-02 invariants.

---

## Phase 11: Pipeline Orchestrator, Merge Pass, CLI

**Goal:** Wire all passes together, final SARIF merge, CLI entry point.

**Files:**
- `src/security_review/passes/pipeline.py` — `PipelineState`, `run_pipeline()`
- `src/security_review/passes/merge.py` — `run_merge(state)` final SARIF + markdown summary + triage.json
- `src/security_review/cli.py` — typer CLI with `review`, `doctor`, `list-rules` commands

**Dependencies:** All previous phases

**Acceptance:** `python -m security_review doctor` runs; `python -m security_review --target . --mode sast` produces SARIF output.

---

## Phase 12: Config Files, Prompts, Taxonomy

**Goal:** All YAML config, markdown prompts, CWE taxonomy, and rule stubs.

**Files:**
- `config/settings/security_review.yaml`
- `config/providers.yaml`
- `config/pricing.yaml`
- `config/prompts/system.md`
- `config/prompts/triage.md`
- `config/prompts/holistic/csharp.md`
- `config/prompts/holistic/python.md`
- `config/prompts/config_review.md`
- `taxonomy/cwe.yaml`
- `taxonomy/cwe-top25-2024.yaml`
- `taxonomy/owasp-top10-2021.yaml`
- `taxonomy/hadolint-cwe-map.yaml`
- `rules/gitleaks/.gitleaks.toml`
- `rules/roslyn/Directory.Build.security.props`
- `rules/roslyn/security.editorconfig`

**Dependencies:** Phase 1 (config_schema validates these)

**Acceptance:** Config loads without validation errors; prompts load via `load_prompt()`.

---

## Phase 13: Tests

**Goal:** Unit and integration test suite with shared fixtures.

**Files:**
- `tests/conftest.py` — shared fixtures, `ALLOW_MODEL_REQUESTS = False`
- `tests/unit/test_sarif_loader.py`
- `tests/unit/test_sarif_merger.py`
- `tests/unit/test_tool_registry.py`
- `tests/unit/test_inventory.py`
- `tests/unit/test_findings_model.py`
- `tests/unit/test_cwe_taxonomy.py`
- `tests/integration/test_triage_agent.py`
- `tests/corpus/runner.py`

**Dependencies:** All previous phases

**Acceptance:** `pytest tests/unit/` passes; structural check P-02 passes.

---

## Execution Order

Phases 1-4 are foundation layers (no LLM dependency).
Phases 5-6 are deterministic pipeline passes.
Phases 7-10 are LLM-powered passes.
Phases 11-13 are integration and delivery.
Phase 12 can run in parallel with phases 8-11.

```
Phase 1 → Phase 2 → Phase 3 → Phase 4
                                  ↓
                   Phase 5 → Phase 6
                                  ↓
              Phase 7 → Phase 8 → Phase 9 → Phase 10
                                                 ↓
                              Phase 11 → Phase 12 → Phase 13
```
