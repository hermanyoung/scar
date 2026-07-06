# TODO

## Rename: SCAR (Security Code AI Review) — DONE
- [x] Rename entry point to `scar.py`
- [x] Update CLI help text, tree display, and terminal output
- [x] Update report headers ("SCAR — Full Report")
- [x] Update SARIF tool name to "scar"
- [x] Update `pyproject.toml` package name and entry point
- [x] Update AGENTS.md / README references

## Inline Context Architecture (Plan 007) — DONE
- [x] Holistic pass: file contents inlined in prompt, zero tool calls
- [x] Triage pass: file contents inlined in prompt, zero tool calls
- [x] Config review pass: config file contents inlined in prompt
- [x] `context_builder.py` with token-budget-aware file inlining
- [x] `output_parser.py` with JSON-first / markdown-fallback extraction

## Rename: corpus/ → eval/, benchmark → evaluation — DONE
- [x] Rename `corpus/` → `eval/`, `tests/corpus/` → `tests/eval/`
- [x] Rename `benchmark.py` → `evaluation.py`, `test_benchmark.py` → `test_evaluation.py`
- [x] Rename CLI command `benchmark` → `eval`
- [x] Rename `BenchmarkSummary` → `EvaluationSummary`, `run_corpus_tests` → `run_eval_tests`, etc.
- [x] Update `CORPUS_ROOT` → `EVAL_ROOT` in `tests/eval/runner.py`, `test_bandit_scan.py`, `test_opengrep_scan.py`
- [x] Update `scripts/check_rules.py` ignore list
- [x] Update `AGENTS.md`, `README.md`, `TODO.md`

## Refactor: Move taxonomy/ into config/taxonomy/ — DONE
- [x] Move `cwe.yaml` and `bandit-cwe-map.yaml` → `config/taxonomy/`
- [x] Move `owasp-top10-2021.yaml` and `cwe-top25-2024.yaml` → `docs/98-research/` (nothing loads them)
- [x] Update path constants in `checks.py`, `sarif/taxonomy.py`
- [x] Update `setup.py` data file entry
- [x] Update `AGENTS.md` / `CLAUDE.md` / `docs/04-rules/` references
- [x] Delete empty `taxonomy/` directory

## Pipeline
- [ ] Integrate `code_intel` into Pass 1 inventory (replace keyword-based security-weight with PageRank)
- [ ] Add code_analysis IDOR heuristic (deterministic pre-screening for auth-without-authz)
- [ ] Type-safe `PipelineState` transitions — replace the mutable God object with typed per-phase states (`InitialState` → `AfterInventory` → `AfterSAST` → ...) so the type checker prevents pass-ordering bugs. Large surface area: touches every pass function, pipeline orchestrator, `SecurityReviewDeps`, `test-cwe`, and benchmarks. Low urgency — current runtime guards work, no bugs from this. Prioritize when adding custom/pluggable passes.

## Testing
- [x] Complete Python eval suite with `expected.sarif`
- [x] Add CI workflow with subprocess-outside-runner structural check — `.github/workflows/ci.yml` runs `check_rules.py --all` (enforces rules 001.4/001.5 subprocess isolation), `scar.py health-check`, and the full unit + integration suite on every push/PR to `main`.
- [x] End-to-end test: `python scar.py review --target eval/ --mode full` — passed (54 findings, 14m37s, $3.87)
- [x] Automated eval scorer (compare pipeline output against ground_truth.yaml)

## Code Quality Findings (from architecture review 2026-05-08)

### P0 — Fail-Fast Violations
- [x] **#1 `budget.py` hardcoded pricing fallback** — FIXED: raises `ConfigurationError` if `pricing.yaml` missing or model not listed.
- [x] **#2 `providers.py` silent empty registry** — FIXED: raises `ConfigurationError` if `models.yaml` missing/malformed.
- [x] **#3 `config_schema.py` defaults diverge from YAML** — FIXED: removed Pydantic defaults for all YAML-sourced fields (`provider_model`, `concurrency`, `max_budget_usd`, `temperature`, `providers`). These are now required — bare `LLMConfig()` fails. `load_config()` fails fast on missing/empty YAML. `build_model()` requires `llm_config` parameter. Added rule 11 to AGENTS.md and rule 003.8 to docs/04-rules/.

### P1 — Structural Rule Violations
- [x] **#4 `.project_root` marker** — FIXED: created `.project_root`, `__init__.py` and `scar.py` walk up to find it.
- [x] **#5 `scar.py` too large** — FIXED: extracted quality scoring to `code_quality/scoring.py`, display to `code_quality/display.py`, benchmark table to `benchmark.py`. Deleted dead Typer CLI (`cli.py`). Now 1015 lines.
- [x] **#6 `setup.py` in root** — WONTFIX: kept in root intentionally for discoverability. It's the onboarding entry point.
- [x] **#7 `config_schema.py` provider defaults duplicate YAML** — FIXED: removed all Pydantic defaults from `ProviderConfig`, `SASTConfig`, `TriageConfig`, `ReviewConfig`. All fields are required from YAML. Added `backoff_seconds` to every provider in YAML. `SecurityReviewConfig` sections are all required (no bare construction).
- [x] **#8 `output_parser.py` hardcoded confidence=0.8** — FIXED: added `triage.default_confidence` to config schema and YAML (set to 0.5). Parser now receives it as explicit `default_confidence` parameter. Logged when used.

### P2 — Moderate Structural Issues
- [x] **#9 `copilot_model.py` class-level mutable state** — FIXED: moved `_client`, `_started`, `_lock` to `__init__` (per-instance). Lock created lazily in `_ensure_client` (inside async context, not at import time). All `CopilotModel._` references → `self._`.
- [x] **#10 `model_providers.py` `lru_cache` with no invalidation** — FIXED: secret resolution moved to `resolve_api_key()` (single point). Factory functions now take API key as explicit parameter — `lru_cache` keys on the actual credential, invalidates naturally on change. Tests can call `.cache_clear()`.
- [x] **#11 `config.py` dual `.env` search path** — FIXED: now only reads `config/.env`.
- [x] **#12 YAML config files lack option-list header comments** — FIXED: added schema reference blocks to all 5 YAML configs (`pricing.yaml`, `models.yaml`, `providers.yaml`, `security_review.yaml`, `logging.yaml`). Each lists every valid key, type, and constraints.
- [x] **#13 `_run_single_check` private import** — FIXED: renamed to `run_single_check` (public API). Updated all 3 callers (`holistic.py`, `scar.py`, `benchmark.py`).

### P3 — Convention/Style
- [x] **#14 CLI uses subcommands** — FIXED: `reports` subgroup flattened to `--show`/`--compare` options.
- [x] **#15 `test-rule`/`test-cwe` use positional arguments** — FIXED: converted to `--cwe`/`--target` options.
- [x] **#16 `health-check`/`list-rules` lack `--verbose`/`--debug`** — FIXED: added to all commands.
- [x] **#17 Test file naming** — FIXED: renamed `test_gitleaks_scan.py` → `test_betterleaks_scan.py`.
- [x] **#18 Quality logic in CLI entry point** — FIXED: moved to `code_quality/scoring.py` and `code_quality/display.py`.

## Detection Gaps (from benchmark 2026-05-08, example-target reference target)
- [x] **CWE-209** (error info exposure): Strengthened error handling focus area in `csharp.md` to detect missing try/catch on external service calls. `anthropic:claude-opus` now passes (was 0, now 1 finding). `codex:gpt` still fails — GPT model reasoning limitation.
- [x] **CWE-319** (cleartext transmission): Added CWE-319 as focus area #8 in `csharp.md` (URL scheme validation, HttpClient BaseAddress, http:// literals). `claude` and `anthropic` pass (2 findings each). `codex:gpt` still fails — GPT model limitation.
- [x] **CWE-116** (improper encoding / LLM prompt injection): Increased copilot `session_timeout` from 90s → 120s. No more timeouts, but copilot still returns empty responses (SDK reliability issue, not timeout).
- [ ] **CWE-522 codex** (insufficiently protected credentials): `codex:gpt` returns 0; all Claude providers pass. GPT model limitation. Low priority — codex is a comparison baseline.
- [ ] **CWE-116 claude intermittent**: `claude:claude-opus` returned 0 findings for CWE-116 in one benchmark run (passes in others). Temperature variance at 0.2.
- [ ] **Copilot SDK temperature unsupported**: Confirmed via SDK source analysis — `github-copilot-sdk` 0.2.2 and 0.3.0 have NO temperature parameter on `create_session()` or `send_and_wait()`. Runtime hardcodes `temperature=0.1` (issue #932). Our `model_settings.temperature=0.2` is silently ignored. Only exposed knob is `reasoning_effort`. Consider: (a) log a warning when temperature is set for copilot provider, (b) forward `reasoning_effort` if configured, (c) watch issue #932 for future SDK support.
- [ ] **Copilot CWE-116/522 variance**: Returns 0 findings intermittently (passes on re-run). Not systematic — confirmed by trace showing 1 finding on CWE-116 re-run. Multi-run averaging (`--runs 3`) needed for reliable benchmark comparisons.
