# Project Principles

Guiding principles for all architectural decisions, plans, and implementation work in security-review. These are non-negotiable -- every plan and PR should be evaluated against them.

---

## Context

These are **project-specific principles** for the security code review module. They build on top of the **reference architecture core principles** in `docs/99-reference-architecture/02-core-principles.md` (P1-P8: Backend Owns Logic, Stateless Clients, Single Source of Truth, Explicit Over Implicit, Fail Fast, Idempotency, No Hardcoded Values, Secure by Default).

The reference architecture principles are universal software engineering rules. The principles below are specific to how *this project* builds its SAST + LLM security review pipeline.

Automated enforcement: `docs/04-rules/005_principles.jsonl` contains machine-checkable versions of these principles. Run `python scripts/check_rules.py --all` to verify.

---

## Pipeline Architecture

*How the system is built -- structural decisions about tool execution, LLM orchestration, and output format.*

### P1: Deterministic Before Non-Deterministic

**SAST tools run first (Pass 2). LLM reasoning runs after (Passes 3-5). Never use an LLM where a regex, AST pattern, or rule engine produces the same result.**

OpenGrep, Bandit, gitleaks, and Roslyn are deterministic, fast, and reproducible. The LLM adds value only where pattern matching cannot: cross-file reasoning, false-positive filtering, authorization model analysis, and business logic review.

This means:
- If a vulnerability can be detected by an OpenGrep rule, write the rule. Do not rely on the LLM.
- Pass 2 (SAST) always completes before Pass 3 (triage) begins.
- The triage agent receives SAST findings as input -- it confirms or refutes, it does not discover.
- The holistic agent (Pass 4) focuses on what SAST *cannot* detect: authZ closure, IDOR, crypto misuse, deserialization chains.

**Test:** Can you explain why each LLM call cannot be replaced by a deterministic tool? If not, it should be a rule.

---

### P2: Subprocess Isolation

**Only `src/security_review/tools/runner.py` calls `asyncio.create_subprocess_exec`. No other module may call subprocess. Never `shell=True`.**

This is the security boundary of the module. All external tool execution flows through a single chokepoint that handles timeouts, exit codes, output capture, and error reporting. Agents never call subprocess -- they access tool results via `SecurityReviewDeps`.

This means:
- Adding a new tool means adding a YAML spec in `tools/specs/`, not writing subprocess code.
- The runner uses list args (`*cmd`), never shell interpolation.
- Timeout and binary-not-found are handled uniformly.

**Test:** `rg "create_subprocess" src/security_review/ | rg -v "tools/runner.py"` returns zero results.

---

### P3: SARIF Is the Interchange Format

**Every finding, from every source, flows through SARIF 2.1.0. SARIF is the single format between every layer.**

SAST tools produce SARIF (or are converted to SARIF). LLM findings are converted to SARIF results. The merge pass combines all SARIF into a single document with CWE taxonomy. Downstream consumers (GitHub Code Scanning, VS Code SARIF Viewer) read one file.

This means:
- All file paths in SARIF use forward slashes (per SARIF spec, even on Windows).
- Every SARIF result has a CWE tag in `external/cwe/cwe-NNN` format.
- The `taxonomies` block references every CWE used in the run.
- Deduplication happens at the SARIF level: `(cwe_id, file_path, line_number)`.

**Test:** The final `security-report.sarif` passes SARIF schema validation and uploads to GitHub Code Scanning without errors.

---

### P4: Pipeline Is Infrastructure, Not Intelligence

**`pipeline.py` routes, enforces order, and tracks state. It never reasons or calls an LLM directly.**

The pipeline orchestrator is a state machine: inventory -> SAST -> triage -> holistic -> config_review -> merge. It does not make security judgments. LLM reasoning is delegated to agents via pass orchestrators (`triage.py`, `holistic.py`, `config_review.py`).

This means:
- `pipeline.py` has zero imports from `pydantic_ai`.
- Adding a new pass means adding a pass function and calling it from the pipeline -- no changes to orchestration logic.
- Pipeline state (`PipelineState`) carries inter-pass data but does not interpret it.

**Test:** `rg "pydantic_ai" src/security_review/passes/pipeline.py` returns zero results.

---

## Design Principles

*How code is written -- patterns for configuration, error handling, and module design.*

### P5: Scope Is Configuration, Not Code

**Model strings, pricing, prompts, tool specs, and rules are YAML/markdown config. Not hardcoded.**

All behavioral parameters come from files in `config/`, `taxonomy/`, or `rules/`. Python code reads config; it does not contain it.

This means:
- LLM model strings come from `config/settings/security_review.yaml`.
- LLM pricing comes from `config/pricing.yaml`.
- Agent system prompts come from `config/prompts/*.md`.
- Tool command templates come from `tools/specs/*.yaml`.
- CWE metadata comes from `taxonomy/cwe.yaml`.
- Config schemas use `extra="forbid"` to catch typos at load time.

**Test:** Can you change the LLM model, pricing, or prompt without modifying Python code? If not, it is hardcoded.

---

### P6: Fail Fast, Fail Loudly

**Errors surface immediately with clear context. Silent failures are forbidden. No fallback defaults in except blocks.**

This is ref arch P5 applied specifically to our pipeline. A misconfigured API key must halt at the first batch, not silently produce an empty report across 50 batches. A missing prompt file must crash at startup, not run with a vague hardcoded fallback.

This means:
- Every `except` block either logs at WARNING+ or re-raises. No `except: pass`.
- `is_fatal_error()` distinguishes auth/config errors (halt pipeline) from transient errors (log and continue to next batch).
- Agent prompt loading raises `ConfigurationError` on missing files -- no fallback strings.
- The merge pass reports partial failures visibly in the summary.

**Test:** If you delete a prompt file and run the pipeline, does it crash immediately with a clear error? If it silently falls back, the principle is violated.

---

### P7: Separate Implementation from Registration

**Tool specs are YAML declarations. Runner is execution. Agents are reasoning. No layer does another's job.**

This maps to ref arch P4 (Explicit Over Implicit). Each layer has a single responsibility:

| Layer | Responsibility | Must not |
|-------|---------------|----------|
| `tools/specs/*.yaml` | Declare command, args, exit codes | Contain execution logic |
| `tools/runner.py` | Execute subprocess, capture output | Contain security reasoning |
| `agents/*.py` | LLM reasoning, tool calls | Import subprocess or runner |
| `passes/*.py` | Orchestrate batches, record costs | Contain LLM prompts |
| `models/*.py` | Validate data shapes | Import from upper layers |

**Test:** Can you add a new SAST tool by creating only a YAML spec file (no Python changes)? If not, the separation is incomplete.

---

## Process Principles

*How development works -- testing, iteration, and breaking changes.*

### P8: Test Without LLMs

**CI never makes a real LLM call. Tests use `TestModel` and `FunctionModel` with `ALLOW_MODEL_REQUESTS=False`.**

Real LLM calls are slow, expensive, non-deterministic, and require API keys. Unit tests must be fast, free, deterministic, and runnable by anyone.

This means:
- `tests/conftest.py` sets `pydantic_ai_models.ALLOW_MODEL_REQUESTS = False` globally.
- Agent tests use `TestModel` (returns canned output) or `FunctionModel` (returns computed output).
- Integration tests that exercise the full pipeline use `--mode sast` to skip LLM passes.
- Corpus regression tests compare SAST output against expected SARIF baselines.

**Test:** Does `pytest tests/unit/ -v` pass with no network access and no API keys? If not, a test is making real calls.

---

### P9: Breaking Changes Are Free During Dev

**No shims, legacy aliases, or deprecation wrappers while in dev mode.**

The module is pre-1.0. We delete replaced code outright, rename freely, and rewrite broken tests. The cost of carrying backward-compatibility hacks during active development is higher than the cost of a clean break.

This means:
- No `_old_function_name = new_function_name` aliases.
- No `# removed` comments for deleted code.
- No re-exporting renamed types from old locations.
- When a function signature changes, update all callers in the same PR.

---

### P10: Modular, Reusable, Elegant, Robust

**Write once, use everywhere. Extract on second use. Handle edge cases at boundaries.**

Code should be modular enough to reuse across passes, elegant enough to read without comments, and robust enough to handle malformed input at system boundaries (tool output, LLM responses, file I/O).

This means:
- Shared logic lives in a single module (not duplicated across files).
- Functions have clear single responsibility and keyword arguments with sensible defaults.
- Pydantic models validate all external input (LLM output, SARIF, config YAML).
- Internal function calls trust their callers -- no redundant validation deep in the stack.

---

### P11: Budget Enforcement via PydanticAI UsageLimits

**Do not build custom budget enforcement in Python. Use PydanticAI's `UsageLimits` on every `agent.run()` call.**

`CostTracker` in `budget.py` is for audit logging only -- it records what was spent. It does not enforce limits. Enforcement is delegated to PydanticAI, which handles token counting, request limits, and retry budgets natively.

This means:
- Every `agent.run()` call passes `usage_limits=UsageLimits(request_limit=N, total_tokens_limit=N)`.
- `CostTracker.record()` logs the cost after each call for the `triage.json` audit trail.
- `max_budget_usd` in config is informational -- it does not gate execution (PydanticAI gates on tokens).

---

### P12: Accuracy Over Volume -- One CWE, One Agent, One Focused Question

**The goal is high-confidence, actionable findings -- not a long list of maybes. Every LLM security check must be focused on a single vulnerability class.**

A monolithic prompt that says "find authorization issues, crypto problems, SSRF, deserialization, and business logic flaws" forces the LLM to context-switch between unrelated domains in a single call. This produces shallow reasoning, missed findings, and false positives. A focused prompt that says "does this endpoint enforce authorization?" gives the LLM the best chance of accurate, evidenced reasoning.

This means:
- Each CWE in the taxonomy that requires LLM reasoning gets its own check prompt.
- Each check prompt is a single, specific question with clear pass/fail criteria.
- Each check reads only the files relevant to that vulnerability class.
- The Pass 4 orchestrator runs one agent call per CWE, not one call per file batch.
- Progress is reported per CWE: "[3/21] CWE-862 Missing Authorization... 2 findings".
- Results are measurable: recall per CWE can be tested against corpus samples.
- If a CWE check produces bad results, you fix one prompt -- you don't untangle it from 20 others.

**Why not group CWEs?** Grouping is an optimisation. You can always combine later if cost is a problem. But you cannot easily split a grouped prompt that produces mixed-quality results. Start focused, combine only with evidence that grouping does not degrade accuracy.

**Test:** For each CWE check, run it against a corpus file with a known vulnerability of that type. Does it find it? Run it against a clean file. Does it produce zero findings? If either fails, the prompt needs improvement -- and you know exactly which one.

---

## LLM Integration Principles

*How code interacts with LLM agents -- what to trust, what to verify, and where the boundary lies.*

### P13: Never Trust LLM-Echoed Identifiers

**Identifiers (file paths, line numbers, rule IDs, finding indexes) must be tracked deterministically in code. Never rely on an LLM to echo them back correctly.**

LLMs shift line numbers, truncate paths, hallucinate filenames, and silently substitute identifiers. When you ask an LLM "triage this finding at `checks.py:71`", it may return `providers.py:53` in its response. If your code uses the LLM's echoed identifiers to match results back to the original data, the match silently fails and the result is lost.

This means:
- When dispatching one-at-a-time agent calls, the calling code knows which item it sent. Store the mapping in code, not in the LLM response.
- After receiving an agent result, override any echoed identifiers (file_path, line_number, rule_id) with the known-correct values from the original data.
- Use positional tracking (index, dict key) or write results directly onto the source data structure -- never build a lookup from LLM-returned keys.
- The LLM's job is to reason and produce a verdict/analysis. Bookkeeping is code's job.

**Test:** If an LLM returns a completely wrong file path and line number in its structured output, does the verdict still get applied to the correct finding? If not, the principle is violated.

---

### P14: All LLM Context Is Pre-Materialized Locally

**Agents never call external tools for file I/O. All file content, SAST findings, and metadata are read locally and inlined in the prompt before the LLM call.**

Tool calls through LLM provider SDKs (Copilot, OpenAI, Anthropic) are unreliable: rate limits surface as silent timeouts, retries burn seconds per call, and concurrent tool calls compound failures. File reading is a local operation (microseconds) — there is no reason to delegate it to an LLM via a tool call that routes through a remote SDK.

This means:
- `context_builder.py` reads files and builds prompt content. All passes use it.
- Agents have zero tools registered. They receive context in the prompt, reason about it, and return structured output.
- Each agent call is a single LLM request — no multi-turn, no tool calls, no timeouts.
- Adding a new pass means: use `context_builder` to build context → call the agent → process output.
- The `agents/tools.py` module does not exist. There is no `read_file` tool.

**Test:** `rg "\.tool\(" src/security_review/agents/ --type py` returns zero results. No agent has tools registered.
