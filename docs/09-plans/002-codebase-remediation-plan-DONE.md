# Codebase Remediation Plan

**Date:** 2 May 2026
**Author:** Herman Young
**Status:** [x] Implemented — residuals closed by plans 018/019
**Scope:** Remediate rule violations, spec divergences, test gaps, and structural issues identified in the codebase review of 2 May 2026.
**Disposition (2026-07-06):** Items 1.1/1.5/3.3/3.5/3.6 done; 1.3→018 WP1, 1.4→018 WP4; 1.6/1.7/1.8/2.1/2.2/3.4→019; 3.1/3.2 obsolete.

---

## 0. Summary

A comprehensive codebase review against the architecture spec (`docs/98-research/001-security-code-review-module-spec.md`), AGENTS.md rules, and the architecture overview (`docs/00-overview/001-architecture-overview.md`) identified **8 critical**, **2 high** (1 already implemented), and **6 medium** issues. This plan addresses each with a specific fix, affected files, acceptance criteria, and priority order.

All changes must pass `pytest tests/unit/ -v` before merge.

---

## 1. Critical Fixes

### 1.1 Remove Hardcoded Pricing Fallbacks in `budget.py`

**Rule violated:** AGENTS.md Rule 2 — *"No hardcoded pricing. All LLM pricing comes from config/pricing.yaml."*
**Spec reference:** Section 2.6 — *"Never hardcode pricing in Python code."*

**Problem:** Three locations in `budget.py` fall back to hardcoded `ModelPricing(input_per_token=0.000003, output_per_token=0.000015)` when `pricing.yaml` is missing or malformed. This means incorrect cost data in the audit log with no visible signal to the operator.

**Files:** `src/security_review/budget.py` (lines 52, 92, 98)

**Fix:**

1. In `_load_pricing()`: if `pricing.yaml` does not exist or is not a valid dict, raise `ConfigurationError` with code `SYS_CONFIG_INVALID`.
2. In `CostTracker.record()`: if the model name is not found in `_pricing` and no `"default"` key exists, log a warning and use zero cost (do not invent pricing). Add a `pricing_miss` field to `CostEntry` so auditors can see unpriced calls.
3. Remove the `pricing: dict | None = None` default on `__init__` — require pricing to be passed explicitly (loaded by `PipelineState` at startup).

**Acceptance criteria:**
- `CostTracker()` with no args raises `TypeError`.
- Missing `pricing.yaml` raises `ConfigurationError` during pipeline init.
- Unknown model in `record()` logs warning, records `cost_usd=0.0`, sets `pricing_miss=True`.
- Unit test covers all three cases.

---

### 1.2 Fix Deduplication Key in `merge.py` to Include CWE

**Problem:** Dedup key is `(file_path, line_number)` but should be `(cwe_id, file_path, line_number)`. Two different CWE findings on the same line are silently dropped.

**Spec reference:** `sarif/loader.py:90` already defines the correct triple via `get_finding_key()`, and `sarif/merger.py:47` already uses it correctly. The bug is only in the merge **pass** (`passes/merge.py`), which has its own parallel dedup logic using the wrong key.

**Files:** `src/security_review/passes/merge.py` (lines 62-76, 84)

**Fix:**

1. Change `existing_keys` type from `set[tuple[str, int]]` to `set[tuple[str, str, int]]`.
2. Use `get_finding_key()` from `sarif/loader.py` to build keys for SAST results.
3. For holistic/config findings, build key as `(finding.cwe_id or "", finding.file_path, finding.line_number or 0)`.

**Acceptance criteria:**
- Two findings on the same line with different CWEs both appear in the final SARIF.
- Duplicate findings (same CWE, same file, same line) are still deduplicated.
- Unit test with a synthetic SARIF containing overlapping findings validates correctness.

---

### 1.3 Replace Custom Budget Guards with Pipeline-Level Budget Handling

**Rule violated:** Spec Section 2.6 anti-pattern — *"Do not build custom budget enforcement. PydanticAI's UsageLimits + UsageLimitExceeded handles this."* and *"Do not silently skip LLM calls when budget is low."*

**Problem:** `would_exceed_budget()` is called in **all three** LLM passes (`holistic.py:60`, `triage.py:63`, `config_review.py:65`), silently short-circuiting work with no indication to the user. However, PydanticAI's `UsageLimits` only enforces per-call token limits — it does NOT enforce cumulative USD budget across 26+ sequential CWE checks. Simply removing the guards would allow unbounded spend.

**Files:** `src/security_review/passes/holistic.py` (line 60), `src/security_review/passes/triage.py` (line 63), `src/security_review/passes/config_review.py` (line 65), `src/security_review/budget.py` (method `would_exceed_budget`), `src/security_review/passes/pipeline.py`

**Fix:**

1. Remove inline `would_exceed_budget()` calls from all three pass modules.
2. Move budget checking to `pipeline.py` — after each pass completes, check cumulative spend and decide whether to continue. This keeps budget logic out of individual passes.
3. When budget is exceeded between passes, log which remaining passes were skipped and proceed to merge.
4. Within a pass (e.g. the 26-check holistic loop), catch `UsageLimitExceeded` per-check and continue the loop — don't halt the entire pass on one failed check.
5. Add the list of skipped/failed checks to `triage.json` and the markdown summary.
6. Rename `would_exceed_budget()` to a pipeline-level helper or remove it — it should not be called from pass code.

**Acceptance criteria:**
- No budget checks in any pass module (`holistic.py`, `triage.py`, `config_review.py`).
- Budget awareness lives in `pipeline.py` only.
- `UsageLimitExceeded` from a single CWE check does not crash the pipeline or skip remaining checks.
- Partial reviews include a "Checks Skipped" section in the markdown summary.
- `triage.json` includes `skipped_checks` array with CWE IDs and failure reasons.

---

### 1.4 Align `CostTracker.record()` with Spec and Fix `model_responded`

**Rules violated:**
- Spec Section 2.6 — *"Always record the exact model version from the API response (result.model_name()), not the requested alias."*
- Spec Section 2.6 — `CostTracker.record()` should accept `RunResult`, not individual fields.

**Problem:** Two intertwined issues:
1. `CostTracker.record()` takes 6 individual params, forcing callers to manually extract usage — leading to `model_responded=model_string` (the alias) instead of the actual API model. This bug exists in all three LLM passes (`holistic.py:129`, `triage.py`, `config_review.py`).
2. The spec says `record(self, result: RunResult, agent_name, batch_id)` — callers pass the result object and `CostTracker` extracts what it needs.

**Files:** `src/security_review/budget.py`, `src/security_review/passes/holistic.py`, `src/security_review/passes/triage.py`, `src/security_review/passes/config_review.py`

**Fix:**

1. Change `CostTracker.record()` to accept the PydanticAI `RunResult` (or at minimum a `Usage` object + model name string).
2. Extract `tokens_in`, `tokens_out`, and `model_responded` inside `record()` — centralize the extraction.
3. Update all callers in the three pass modules to pass `result` directly instead of unpacking fields.
4. Add `model_requested` as a separate parameter so the audit log captures both alias and actual model.

**Acceptance criteria:**
- Callers pass `result` object, not individual fields.
- `model_responded` is always extracted from the result, not the config alias.
- `triage.json` shows distinct `model_requested` and `model_responded` values.
- Unit test validates correct extraction.

---

### 1.5 Remove API Key Environment Leakage in `providers.py`

**Problem:** `providers.py:93` calls `os.environ.setdefault("OPENAI_API_KEY", api_key)`, leaking secrets into the process environment where SAST tool subprocesses can read them. The spec shows `OpenAIModel(model_name, api_key=...)` — direct parameter passing.

**Files:** `src/security_review/providers.py` (lines 82-94, 96-109)

**Fix:**

1. Remove both `os.environ.setdefault(...)` calls.
2. Pass `api_key` directly to `OpenAIModel` and `AnthropicModel` constructors.
3. Verify PydanticAI's current API — if it requires env vars, use a scoped approach (set before model init, clear after) or file an issue upstream.

**Acceptance criteria:**
- `os.environ` is not modified by `build_model()`.
- `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` do not appear in subprocess environments.
- Pipeline still authenticates correctly with both providers.

### 1.6 Normalize URIs in SARIF Dedup Key

**Problem:** `get_finding_key()` in `sarif/loader.py:90-104` extracts `file_path` from the raw SARIF `artifactLocation.uri` without calling `normalize_uri()`. Different SAST tools report the same file in different formats (`src/main.py`, `file:///abs/path/src/main.py`, `src\main.py` on Windows). These produce different dedup keys, so the same finding from two tools is not deduplicated.

**Files:** `src/security_review/sarif/loader.py` (lines 90-104)

**Fix:**

1. Call `normalize_uri(file_path, target_root)` inside `get_finding_key()`.
2. Add an optional `target_root` parameter to `get_finding_key()` so callers can provide the root for relative path resolution.
3. Audit all callers of `get_finding_key()` and `merge_sarif()` to ensure they pass `target_root`.

**Acceptance criteria:**
- Findings with `file:///abs/src/main.py` and `src/main.py` produce the same dedup key.
- Backslash paths on Windows normalize to forward slashes.
- Unit test covers all three URI formats producing identical keys.

---

### 1.7 Create Shared CWE Validation and Fix Hardcoded CWE-1395

**Problem:** `convert_pip_audit_to_sarif()` and `convert_dotnet_vuln_to_sarif()` both hardcode `CWE-1395` in their SARIF output (lines 54, 134). This CWE is not validated against `taxonomy/cwe.yaml`. More broadly, no `cwe_exists()` function exists anywhere in the codebase — items 1.7 and 1.8 both need one.

**Files:** `src/security_review/sarif/converter.py` (lines 54, 134), `src/security_review/sarif/taxonomy.py` (new function)

**Fix:**

1. Add `@lru_cache` to the existing `load_cwe_registry()` in `sarif/taxonomy.py` — it's already called by `build_cwe_taxonomy()` and will be called by the new `cwe_exists()`. Without caching, each call re-reads the YAML file.
2. Add a reusable `cwe_exists(cwe_id: str) -> bool` function that calls `load_cwe_registry()` and checks membership.
3. Call `cwe_exists("1395")` in the converter at first invocation. If missing, raise `ConfigurationError`.
4. Add a comment documenting why CWE-1395 ("Dependency on Vulnerable Third-Party Component") is the correct generic CWE for SCA findings.
5. If the upstream advisory data includes a more specific CWE, prefer that over the generic fallback.
6. Item 1.8 (below) reuses `cwe_exists()` for output validation — no duplication.

**Acceptance criteria:**
- `cwe_exists()` is importable from `sarif/taxonomy.py` and reusable by any module.
- If CWE-1395 is removed from the taxonomy, the converter raises `ConfigurationError`.
- Unit test validates both the `cwe_exists()` function and converter output.

---

### 1.8 Enforce Required CWE ID on LLM Findings

**Rule violated:** AGENTS.md Rule 5 — *"Every finding must have a CWE ID in the format CWE-NNN. Validate against taxonomy/cwe.yaml."*

**Problem:** `BaseFinding.cwe_id` is `str | None = Field(default=None)` in `models/findings.py:80`. Both `HolisticFinding` and `ConfigFinding` inherit this optional field. The LLM can return findings without any CWE classification, violating the invariant and producing SARIF results with no CWE tag.

**Files:** `src/security_review/models/findings.py` (line 80), `src/security_review/models/config_review.py`

**Fix:**

1. On `HolisticFinding` and `ConfigFinding`, override `cwe_id` as required: `cwe_id: str = Field(min_length=1)`.
2. Keep `cwe_id` optional on `BaseFinding` (triage results reference existing SAST findings which already have CWEs).
3. Add an output validator on the holistic and config_review agents that validates each finding's `cwe_id` using `cwe_exists()` from item 1.7. If invalid, log a warning and reject the finding.

**Acceptance criteria:**
- `HolisticFinding(cwe_id=None, ...)` raises `ValidationError`.
- `ConfigFinding(cwe_id=None, ...)` raises `ValidationError`.
- Output validator catches invalid CWE IDs before they reach the merge pass.
- Unit test confirms enforcement.

---

## 2. High Priority Fixes

### 2.1 Add Unit Tests for Untested Critical Modules

**Problem:** 6 unit test files cover ~30% of the critical path. The following modules have zero unit tests:

| Module | Risk | Why it matters |
|--------|------|---------------|
| `priority.py` | HIGH | Determines fix order; threshold logic is invisible |
| `budget.py` | HIGH | Cost tracking and audit log accuracy |
| `merge.py` | HIGH | Final output correctness; dedup logic |
| `checks.py` | HIGH | CWE check loading and file selection |
| `config.py` / `config_schema.py` | MEDIUM | Config validation, override merging |
| `providers.py` | MEDIUM | Provider routing, error handling |

**Files:** New files in `tests/unit/`

**Fix:** Create the following test files:

1. `tests/unit/test_priority.py` — Test all severity/confidence/exposure combinations, band thresholds, edge cases (missing manifest, unknown file, zero weight).
2. `tests/unit/test_budget.py` — Test `CostTracker.record()`, cumulative cost, audit log format, missing pricing key handling.
3. `tests/unit/test_merge.py` — Test dedup logic, finding-to-SARIF conversion, taxonomy injection, summary generation.
4. `tests/unit/test_checks.py` — Test CWE check loading, file selection matching, fallback to high-weight files.
5. `tests/unit/test_config.py` — Test YAML loading, override merging, validation errors, missing file handling.
6. `tests/unit/test_providers.py` — Test model string parsing, alias resolution, error cases. Use `unittest.mock` for SDK imports.

**Acceptance criteria:**
- Each test file has at least 5 test cases covering happy path, edge cases, and error conditions.
- `pytest tests/unit/ -v` passes with all new tests.
- No real LLM calls (conftest `ALLOW_MODEL_REQUESTS = False` enforces this).

---

### 2.2 Fix `TriageResult.findings` to Allow Empty List

**Problem:** `findings: list[TriagedFinding] = Field(min_length=1)` means the LLM cannot return a result where all findings are false positives. The schema forces at least 1 finding.

**Files:** `src/security_review/models/findings.py` (line 61)

**Fix:** Change `min_length=1` to `min_length=0` or remove the constraint entirely (default `[]`).

**Acceptance criteria:**
- `TriageResult(findings=[], total_confirmed=0, total_false_positive=3, total_needs_context=0)` validates successfully.
- Existing tests still pass.

---

### ~~2.3 Fix O(n) Exposure Lookup in `priority.py`~~ — ALREADY IMPLEMENTED

**Status:** `build_exposure_index()` already exists in `priority.py:109`, `score_finding()` already accepts `exposure_index: dict[str, float]`, and `merge.py:102` already calls `build_exposure_index(state.manifest)`. No action needed.

---

## 3. Medium Priority Fixes

### 3.1 Clarify In-Place Mutation Contract in `taxonomy.py` and `tags.py`

**Problem:** `inject_taxonomy()` and `normalise_cwe_tags()` mutate their input SARIF dicts in-place but their signatures and docstrings don't communicate this. Callers must know the input is modified.

**Files:** `src/security_review/sarif/taxonomy.py`, `src/security_review/sarif/tags.py`

**Note:** `merge.py` is the terminal consumer of the SARIF dict — it builds the dict, calls these functions, then writes to disk. In-place mutation is correct here; adding `deepcopy()` on large SARIF dicts would be wasteful. The fix is semantic clarity, not copying.

**Fix:**

1. Rename `inject_taxonomy()` to `inject_taxonomy_inplace()` (or add `-> None` return type and document the mutation contract in the docstring).
2. Same for `normalise_cwe_tags()` — clarify it mutates the rule dict in place.
3. Update callers to match the renamed functions.

**Acceptance criteria:**
- Function names or docstrings explicitly communicate in-place mutation.
- No `deepcopy()` overhead added.
- Existing behavior unchanged.

---

### 3.2 Move Holistic Agent System Prompt to `config/prompts/`

**Problem:** Triage and config review agents load system prompts from markdown files via `load_prompt()`. The holistic agent has its prompt inline as a Python string literal in `agents/holistic/agent.py:17-28`. Inconsistent and harder to tune.

**Files:** `src/security_review/agents/holistic/agent.py`, new file `config/prompts/holistic.md`

**Fix:**

1. Create `config/prompts/holistic.md` with the current system prompt content.
2. Change `holistic_agent` to use a dynamic system prompt via `@holistic_agent.system_prompt` decorator that calls `load_prompt("holistic")`.
3. Follow the same pattern used by triage and config_review agents.

**Acceptance criteria:**
- Holistic system prompt is loaded from `config/prompts/holistic.md`.
- Changing the prompt file changes agent behavior without code modification.

---

### 3.3 Extract Report Builder from `merge.py`

**Problem:** `merge.py` is 318 lines handling SARIF merging, dedup, conversion, scoring, markdown generation, and audit log writing.

**Files:** `src/security_review/passes/merge.py`

**Fix:**

1. Extract `_build_summary()` into a new `src/security_review/passes/report.py`. This is markdown generation — a distinct concern from SARIF merging.
2. Keep `_score_all_findings()` in `merge.py` — it needs pipeline context (triage results, manifest) to build the triage lookup and call `score_finding()`. Moving it to `priority.py` would force `priority.py` to know about `PipelineState`, breaking its clean single-purpose design.
3. Keep `_finding_to_sarif_result()` and `_ensure_rule()` in `merge.py` — these convert agent output to SARIF and are tightly coupled to the merge logic. Do NOT move them to `converter.py`, which handles tool output (pip-audit, dotnet-vuln) — different concern.

**Acceptance criteria:**
- `_build_summary()` is importable from `passes/report.py` and testable independently.
- `merge.py` is under 250 lines.
- No behavior change — all existing tests pass.

---

### 3.4 Remove Default `model_id` from `CopilotModel.__init__`

**Rule violated:** AGENTS.md Rule 3 — *"No hardcoded model strings."*

**Files:** `src/security_review/copilot_model.py` (line 213)

**Fix:** Remove the default value. Make `model_id` a required parameter.

```python
# Before
def __init__(self, model_id: str = "claude-sonnet-4.6") -> None:

# After
def __init__(self, model_id: str) -> None:
```

**Acceptance criteria:**
- `CopilotModel()` with no args raises `TypeError`.
- All existing callers (`providers.py`) already pass `model_id` explicitly — no breakage.

---

### 3.5 Declare `json_repair` as Optional Dependency

**Problem:** `copilot_model.py:39` imports `json_repair` for LLM output repair. The library is gracefully handled if missing (debug log, no crash), but it is not declared in `pyproject.toml` at all — not even as an optional extra. Users of the `copilot` provider will silently get degraded JSON parsing.

**Files:** `pyproject.toml`, `src/security_review/copilot_model.py`

**Fix:**

1. Add `json-repair` to a `[project.optional-dependencies]` extra (e.g. `copilot = ["github-copilot-sdk", "json-repair>=0.30"]`).
2. Document in `README.md` that the `copilot` extra is required for Copilot provider usage.

**Acceptance criteria:**
- `pip install .[copilot]` installs `json-repair`.
- `pip install .` (base) does not require it.
- Existing graceful fallback in `copilot_model.py` is preserved.

---

### 3.6 Fix `run_until_complete()` Deadlock Risk in `copilot_model.py`

**Problem:** `copilot_model.py` uses `asyncio.get_event_loop().run_until_complete()` inside an async context (the PydanticAI agent is already running in an event loop). This can deadlock if the loop is already running. The pattern should use `await` instead.

**Files:** `src/security_review/copilot_model.py`

**Fix:**

1. Audit all `run_until_complete()` calls in `copilot_model.py`.
2. Replace with direct `await` calls since the caller is already async.
3. If synchronous bridging is genuinely needed, use `asyncio.ensure_future()` or `loop.create_task()`.

**Acceptance criteria:**
- No `run_until_complete()` calls in `copilot_model.py`.
- CopilotModel works correctly when called from `agent.run()` (which is async).

---

## 4. Implementation Order

Execute in this order to minimize risk and maximize early value:

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Phase 1: Safety** | 1.5, 1.1, 3.4 | Remove security issues and hardcoded values. No behavior change. |
| **Phase 2a: Correctness (data)** | 1.6 → 1.2, 1.7 → 1.8, 2.2 | Fix dedup bugs, URI normalization, CWE validation/enforcement, schema bug. Order matters: 1.6 before 1.2 (both modify `get_finding_key`), 1.7 before 1.8 (`cwe_exists` dependency). |
| **Phase 2b: Correctness (API)** | 1.4 | Align CostTracker API with spec, fix model_responded across all passes. |
| **Phase 3: Architecture** | 1.3, 3.1, 3.2, 3.3, 3.5, 3.6 | Remove anti-patterns, clarify contracts, restore consistency. |
| **Phase 4: Coverage** | 2.1 | Add unit tests for all modules fixed in phases 1-3. Run last so tests cover the fixed code. |

Each phase should be a separate PR. Run `pytest tests/unit/ -v` at each phase boundary.

---

## 5. Out of Scope

The following were noted during review but are not remediated in this plan:

1. **SARIF TypedDict enforcement** — The TypedDicts in `sarif/types.py` exist but provide no runtime enforcement (everything is `dict`). Migrating to proper typed access is a larger refactor.
2. **`_build_check_prompt` and prompt engineering** — The holistic check prompt template in `holistic.py:168-187` is functional. Prompt tuning is an ongoing concern, not a bug.
3. **`codex` provider** — Already disabled in the working tree (returns `ConfigurationError`). No further action.
4. **Holistic error swallowing** — Non-fatal errors in the CWE check loop are logged but not surfaced in the report. This is partially addressed by 1.3 (adding skipped checks to the summary), but comprehensive error reporting is a separate workstream.
5. **`config/.env` location** — Currently in `config/`, convention is project root. Functional as-is, low risk.
