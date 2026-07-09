# Plan 020 — Adversarial Verification & Pipeline Resilience

**Date:** 2026-07-05
**Status:** Ready for implementation (Phases 1–3 spec-complete, verified against source; Phase 4 design-level, optional)
**Depends on:** None. Compatible with Plan 017 (Harness Extraction) — see [§ Package-layout note](#package-layout-note).
**Blocks:** None.

---

## Origin

These improvements are ported from the Anthropic *defending-code-reference-harness*
(execution-verified C/C++ crash discovery). That harness and SCAR solve different
problems, so **none of its dynamic machinery is adopted** (see [§ Explicitly out of
scope](#explicitly-out-of-scope)). What transfers is its **verification topology**
(the finder never grades its own work; only the artifact crosses the boundary) and
its **failure-resilience** (checkpoint/resume, transport retry-with-backoff,
incremental persistence).

---

## Problem

Two independent weaknesses, bundled because both are cheap, high-leverage, and
share no code.

### P1 — Holistic (Pass 4) and config (Pass 5) findings are never independently verified

- Pass 3 (triage) verifies each SAST finding with one LLM call. That is the *only*
  verification in the pipeline.
- Pass 4 findings are **net-new discoveries by a single LLM call** and go straight
  to output. `merge.py::_score_all_findings` auto-stamps them `CONFIRMED`:

  ```python
  # src/security_review/passes/merge.py:277-280
  is_llm_finding = rule_id.startswith("SR-")
  ...
  if is_llm_finding and not verdict:
      verdict = "CONFIRMED"
      result.setdefault("properties", {})["triage_verdict"] = verdict
  ```

- The holistic agent is even *shown* the SAST findings and told "do not duplicate"
  (`agents/holistic/agent.py:27`, `passes/holistic.py:442-449`). That is anchoring —
  the opposite of an independent second opinion.
- False-positive rate is SCAR's headline quality metric (F2 / MCC in
  `docs/05-standards/04-benchmarking-standards.md`). An unverified discovery pass is
  the single largest uncontrolled FP source.

### P2 — A killed run loses all work and all spend; transport failures are unmanaged

- `PipelineState` is in-memory only (`passes/state.py:33-80`). **`merge.py` is the
  only pass that writes findings to disk, at the very end.** A crash at Pass 4 of a
  ~15-minute / multi-dollar run (`TODO.md`: "54 findings, 14m37s, $3.87") loses
  everything — including budget already spent. There is no `--resume`.
- `output_retries` (`config_schema.py:33`) only retries **output-parse** failures.
  Transport retry is **inconsistent across providers**: `CopilotModel` reads
  `backoff_seconds` and retries once on timeout (copilot_model.py:298-352), but the
  other four providers never receive it and rely on whatever their SDK does. Worse,
  **empty responses are returned as success and never retried** — `CopilotModel` logs
  `copilot.empty_response` then returns the empty `ModelResponse` (copilot_model.py:313-319),
  which fails parsing and loses the finding. This is the "Copilot returns 0 findings
  intermittently" bug in `TODO.md`. There is no uniform, config-driven retry policy.

---

## Design principles (the borrow, stated precisely)

1. **The finder never grades its own work.** Verification runs in a *separate agent*
   with a *fresh* `SecurityReviewDeps` context. It never shares a conversation with
   the holistic/config agent.
2. **Only the artifact crosses the boundary.** The verifier receives the *claim*
   (rule id, CWE, file, line, one-line title) and the **freshly re-read source
   code** — never the finder's `description`, `evidence`, `confidence`, or
   `remediation`. Those are persuasion, not evidence, and cause anchoring.
3. **Default to disbelief.** The verify prompt instructs: return `FALSE_POSITIVE`
   unless the vulnerability is demonstrable in the provided code.
4. **Reuse existing verdict semantics — do not invent a parallel one.** Verification
   emits a `TriageVerdict` (`CONFIRMED | FALSE_POSITIVE | NEEDS_CONTEXT`) written to
   the same `properties.triage_verdict` field triage uses. The existing
   `score_finding` path then scores refuted findings low, exactly like a SAST FP.
   No finding is silently dropped (audit trail preserved; consistent with rule 004).
5. **Resilience is plumbing, not policy.** Checkpoint/resume and retry must not
   change *what* findings are produced — only whether work survives a failure.

---

## Explicitly out of scope

Do **not** implement any of the following as part of this plan (they were considered
and rejected for SCAR's static, memory-safe-language paradigm):

- Any dynamic / DAST / code-execution capability (that is Plan 016; gated behind
  Plan 011/013 per the sequencing agreed separately).
- gVisor / container sandboxing. SCAR executes no target code.
- Tool-using agents (`Read`/`Write`/`Bash`). SCAR's zero-tool, pre-materialised-context
  design (Decisions 003/004) is deliberately stronger for its threat model. **Do not
  give the verify agent tools.** It reads files locally, exactly like the triage pass.

---

## Package-layout note

This plan is written against the current `security_review.*` package. If Plan 017
(Harness Extraction) lands first:
- The new `passes/verify.py`, the verify agent, the prompt, and the finding-model
  change are **SCAR-pipeline concerns** → they belong in `src/scar/`.
- Cost tracking, providers, tracing, output-parsing (Phase 3 touches these) are
  **infrastructure** → `src/harness/`.
- Substitute `scar.` / `harness.` for `security_review.` in the paths below
  accordingly. No design changes.

---

# Phase 1 — Adversarial verification pass (headline; spec-complete)

Add a Pass 6 "verify" between config review and merge that assigns an independent
verdict to every LLM-discovered finding (holistic always; config-review opt-in).

## 1.1 New pass numbers (full mode)

Verification is a real pass. Renumber **full mode only**:

| # | Pass | Change |
|---|------|--------|
| 1 | inventory | — |
| 2 | sast | — |
| 3 | triage | — |
| 4 | holistic | — |
| 5 | config_review | — |
| **6** | **verify** | **NEW** |
| **7** | merge | was 6 |

`sast` and `sast-triage` modes are unchanged (no LLM discovery passes to verify).

**Edits:**
- `passes/pipeline.py` — in the `mode == "full"` branch: `total_passes = 7`; after
  the Pass 5 config-review block, add a Pass 6 verify block (mirror the existing
  `progress(...) / await run_verification(state) / progress(...)` shape); the merge
  call stays but its `merge_pass = total_passes` now resolves to 7 automatically.
- `passes/merge.py:33` — `_MERGE_PASS_NUMBER = {"full": 7, "sast-triage": 4, "sast": 3}`.

## 1.2 Config — new required `verification` section

**`config_schema.py`** — add the model and wire it into `SecurityReviewConfig`
(all four other sections are required; this one is too — honours rule 11 / AGENTS.md
"no silent defaults"):

```python
class VerificationConfig(BaseModel, extra="forbid"):
    """Pass 6: independent adversarial verification of LLM-discovered findings."""
    enabled: bool
    model: str | None = Field(
        default=None,
        pattern=r"^(openai|anthropic|copilot|codex|claude):.+$",
        description="Override model for verification. null = use llm.provider_model.",
    )
    samples: int = Field(ge=1, le=5, description="Skeptic votes per finding. 1 = single; 3 = majority-refute.")
    verify_holistic: bool
    verify_config_review: bool


class SecurityReviewConfig(BaseModel, extra="forbid"):
    llm: LLMConfig
    sast: SASTConfig
    triage: TriageConfig
    review: ReviewConfig
    verification: VerificationConfig   # NEW
```

**`config/settings/security_review.yaml`** — add the block **and** extend the
header-comment option list at the top of the file (rule: every YAML lists its keys):

```yaml
verification:
  enabled: true
  model: null            # null = use llm.provider_model. A cheaper model here is fine.
  samples: 1             # 1 = single skeptic. 3 = majority-refute (higher cost, higher precision).
  verify_holistic: true
  verify_config_review: false
```

**Header comment to add** (under the existing `triage:` block, matching style):

```
# verification:
#   enabled:              bool    # run Pass 6 adversarial verification
#   model:                str?    # override model. null = use llm.provider_model
#   samples:              int     # 1-5 skeptic votes per finding
#   verify_holistic:      bool    # verify Pass 4 findings
#   verify_config_review: bool    # verify Pass 5 findings
```

> **Migration:** any test fixture or golden config that constructs
> `SecurityReviewConfig` or loads a non-default YAML must add this section, or
> Pydantic rejects it at load (intended fail-fast). Grep for
> `SecurityReviewConfig(` and any `*.yaml` under `tests/` and `config/golden/`.

## 1.3 Finding model — carry the verdict

**`models/findings.py`** — add one optional field to `BaseFinding` (inherited by
both `HolisticFinding` and the config-review finding, so merge handles both
uniformly):

```python
class BaseFinding(BaseModel):
    ...
    remediation: str = Field(min_length=1)
    triage_verdict: str | None = Field(default=None)   # NEW: set by Pass 6; None = unverified
```

**No new output model or parser is needed.** Verification's output shape (verdict +
confidence + rationale over a location) is identical to Pass 3's, so the verify pass
**reuses `TriagedFinding`, `parse_triage_response`, and `TRIAGE_FORMAT_MARKDOWN`
verbatim** (verified: `output_parser.py:27`, `model_capabilities.py:40`). Keeps the
change DRY — no parallel model/parser/format-constant to maintain. `ConfigFinding`
extends `BaseFinding` (`models/config_review.py:11`), so the `triage_verdict` field
above is inherited by both Pass 4 and Pass 5 findings.

## 1.4 The verify agent

**New file `agents/verify/agent.py`** (mirror `agents/holistic/agent.py`; zero tools):

```python
"""Pass 6: independent adversarial verification agent.

A SEPARATE agent from holistic/triage. Sees only the claim (CWE, location) and
freshly re-read source — never the finder's rationale/evidence. Defaults to
disbelief. Zero tools; context pre-materialised (Decisions 003/004).
"""
from __future__ import annotations
from pydantic_ai import Agent
from security_review.agents.deps import SecurityReviewDeps

verify_agent = Agent(
    output_type=str,
    system_prompt=(
        "You are an independent security reviewer auditing a claimed vulnerability "
        "found by another tool. You did NOT find it and have no stake in it.\n\n"
        "You receive: the claimed vulnerability class (CWE), its location, and the "
        "actual source code at that location. You do NOT receive the original "
        "finder's reasoning — form your own judgment from the code alone.\n\n"
        "Rules:\n"
        "1. Default to FALSE_POSITIVE. Only return CONFIRMED if the vulnerability is "
        "demonstrable in the code shown.\n"
        "2. If confirming requires code or context not shown, return NEEDS_CONTEXT.\n"
        "3. Do not accept a claim on authority — a confident claim with no supporting "
        "code is a FALSE_POSITIVE.\n"
        "4. Verdict: CONFIRMED | FALSE_POSITIVE | NEEDS_CONTEXT. Confidence: 0.0-1.0. "
        "Rationale: cite the specific line(s) that support your verdict."
    ),
    deps_type=SecurityReviewDeps,
)
```

**New prompt file `config/prompts/verify.md`** (loaded via `load_prompt("verify")`
if you prefer the file-based system prompt like triage; otherwise the inline system
prompt above suffices — pick one, matching triage's `@agent.system_prompt` pattern
if file-based). Keep it directive, ≤ 25 lines, with a "What NOT to do" block mirroring
`config/prompts/triage.md`.

## 1.5 The pass

**New file `passes/verify.py`** — mirror `passes/triage.py`'s batching / budget /
cost / trace / native-json structure exactly. Signature and core:

```python
async def run_verification(state: PipelineState) -> None:
    """Pass 6: assign an independent verdict to each LLM-discovered finding."""
    cfg = state.config.verification
    if not cfg.enabled:
        return
    if state.config.review.mode != "full":
        return

    # Collect findings to verify (holistic always if enabled; config opt-in).
    targets: list[BaseFinding] = []
    if cfg.verify_holistic and state.holistic_result:
        targets += state.holistic_result.findings
    if cfg.verify_config_review and state.config_review_result:
        targets += state.config_review_result.findings
    if not targets:
        return

    model_string = cfg.model or state.config.llm.provider_model
    model = build_model(model_string, llm_config=state.config.llm)
    model_settings = build_model_settings(model_string, state.config.llm)
    native_json = supports_native_json(model)
    target_root = str(state.target_path.resolve())

    # Drive via the SHARED batch helper (see 1.5.1) — do NOT hand-roll the loop.
    # For each finding, run cfg.samples skeptic calls; aggregate (see 1.6);
    # set finding.triage_verdict (see 1.5.2). Record cost + write_trace per call.
    ...
```

### 1.5.1 Reuse the batch loop — do not hand-roll a third copy

The concurrent-batch driver (iterate in `concurrency`-sized batches, budget-gate
each batch, `asyncio.gather`, emit progress/ETA, re-raise on `is_fatal_error`)
**already exists twice**: `triage.py:95-186` and `holistic.py:153-210`. `verify.py`
must **not** add a third copy (violates the no-duplication rule).

Extract it first into `passes/_batch.py`:

```python
async def run_in_batches(
    items: list, *, make_coro, on_result, state: PipelineState,
    pass_number: int, pass_name: str, label: str,
) -> None:
    """Shared concurrent-batch driver for Pass 3/4/6.

    - batches items by state.config.llm.concurrency
    - budget-gates each batch via cost_tracker.would_exceed_budget
    - asyncio.gather(return_exceptions=True); re-raises is_fatal_error
    - emits the standard 'counter' progress/ETA lines
    `make_coro(item, index)` returns the per-item coroutine;
    `on_result(item, index, result)` records it (write-back / collect / mutate).
    """
```

Verify uses it directly. **Retrofit `triage.py` and `holistic.py` onto the same
helper** in the same PR (removes the pre-existing duplication — net negative LOC).
If that retrofit is judged too risky to bundle, verify still uses the helper and a
follow-up ticket migrates the other two; do not ship a third hand-rolled loop.

> **Considered and rejected:** folding verification into `run_triage` (triage-as-a-
> service for both SAST and LLM findings). Rejected — triage writes verdicts into
> SARIF *by index* and uses the non-skeptic `triage_agent`; LLM findings aren't in
> SARIF yet at Pass 3. A separate pass sharing the *loop* (not the pass) is the right
> granularity.

### 1.5.2 An unverified finding must never auto-confirm

`merge.py:278` stamps any `SR-*` finding with no verdict as `CONFIRMED`. Once
verification is enabled, a finding it *couldn't* adjudicate (file unreadable,
`file_path == "unknown"` from the parser fallback, all samples failed, or budget
exhausted mid-pass) would otherwise fall straight through that default — silently
defeating the feature exactly when it matters. Rule:

- If `run_verification` **attempted** a finding but produced no verdict → set
  `finding.triage_verdict = "NEEDS_CONTEXT"` (not `None`). Log `verify.unresolved`
  with the reason (`file_unreadable` / `all_samples_failed` / `budget_exhausted`).
- Resolve `finding.file_path` the same way triage does before reading; if it can't be
  resolved, that is a `NEEDS_CONTEXT`, not a pass.

See § 1.7 for the matching merge-side guard.

Per-finding prompt builder (the anti-anchoring boundary — **only** claim + fresh code):

```python
def _build_verify_prompt(finding: BaseFinding, state: PipelineState, target_root: str) -> str | None:
    file_content = read_file_content(state.target_path, finding.file_path)
    if file_content is None:
        return None
    context = format_context_window(file_content, finding.line_number or 1)
    ext = finding.file_path.rsplit(".", 1)[-1] if "." in finding.file_path else ""
    return (
        f"## Verify claimed vulnerability\n\n"
        f"**Claimed class:** {finding.cwe_id or 'unspecified'} — {finding.title}\n"
        f"**File:** {finding.file_path}\n"
        f"**Line:** {finding.line_number or '(file-level)'}\n\n"
        f"**Source code** (line marked with >>>):\n```{ext}\n{context}\n```\n\n"
        f"**Instructions:**\n"
        f"1. Determine independently whether {finding.cwe_id or 'this vulnerability'} "
        f"is demonstrable in the code above.\n"
        f"2. Default to FALSE_POSITIVE. Cite specific lines in your rationale.\n"
        f"3. Return verdict, confidence, and rationale.\n"
    )
    # NOTE: finding.description / evidence / confidence / remediation are DELIBERATELY
    # excluded. Including them re-introduces anchoring (design principle 2).
```

Reuse exactly, from triage.py's imports:
`read_file_content`, `format_context_window` (`context_builder`);
`supports_native_json` + `TRIAGE_FORMAT_MARKDOWN` (`model_capabilities`);
`parse_triage_response` (`output_parser`); `build_model`, `build_model_settings`;
`write_trace`; `is_fatal_error`;
`UsageLimits(request_limit=2, total_tokens_limit=200_000)`;
`retries=state.config.llm.output_retries`; cost via `state.cost_tracker.record(agent_name="verify", batch_id=f"verify-{i:03d}", ...)`.

Structured output reuses Pass 3's machinery. Native-json branch:
`output_type = TriagedFinding` — then override its identifiers from the finding (P13),
exactly as `triage.py:313-319` does. Prompted branch: `output_type = str`, append
`TRIAGE_FORMAT_MARKDOWN`, then:

```python
verdict = parse_triage_response(
    output,
    file_path=finding.file_path,
    line_number=finding.line_number or 1,   # TriagedFinding requires ge=1; file-level findings use 1
    rule_id=finding.rule_id,
    tool_name="holistic" if isinstance(finding, HolisticFinding) else "config-review",
    default_confidence=state.config.triage.default_confidence,
)
```

Set `finding.triage_verdict = verdict.verdict.value` (or `None` if parsing failed).

## 1.6 Aggregating `samples` votes

- `samples == 1`: verdict is the single call's verdict.
- `samples > 1`: run N calls concurrently per finding. Aggregate conservatively:
  - `CONFIRMED` only if a **strict majority** voted `CONFIRMED`.
  - else if any voted `FALSE_POSITIVE` and no majority-confirm → `FALSE_POSITIVE`.
  - else → `NEEDS_CONTEXT`.
- Store the winning verdict on `finding.triage_verdict`. Record cost for every call.
  A failed sample (exception, non-fatal) counts as a non-vote; if all samples fail,
  leave `triage_verdict = None` (falls through to merge's existing default) and log
  `verify.all_samples_failed`. Re-raise on `is_fatal_error` (match triage.py:154-155).

## 1.7 Merge integration

**`passes/merge.py::_finding_to_sarif_result`** — after building `result["properties"]`,
propagate the verdict so `_score_all_findings` uses it instead of defaulting:

```python
    verdict = getattr(finding, "triage_verdict", None)
    if verdict:
        result.setdefault("properties", {})["triage_verdict"] = verdict
```

A `FALSE_POSITIVE` verdict now flows through `score_finding` and lands the finding at
low priority (same treatment as a SAST FP), preserved in SARIF for audit. **Do not
drop refuted findings.**

**Close the auto-confirm bypass (ties to § 1.5.2).** Today `_score_all_findings`
defaults any verdict-less `SR-*` finding to `CONFIRMED` (merge.py:278). That default
is correct only when verification did **not** run. Guard it:

```python
    if is_llm_finding and not verdict:
        verdict = "CONFIRMED" if not state.config.verification.enabled else "NEEDS_CONTEXT"
        result.setdefault("properties", {})["triage_verdict"] = verdict
```

With § 1.5.2 setting explicit verdicts, this branch should rarely fire when
verification is enabled — it is the belt-and-braces net, and it must not silently
promote an unverified finding to `CONFIRMED`.

## 1.8 Tests (`tests/unit/`)

Follow `tests/conftest.py` (`ALLOW_MODEL_REQUESTS = False`; use `TestModel` /
`FunctionModel` — real LLM calls are forbidden in unit tests).

- `test_verify_pass.py`:
  - `FunctionModel` returning `CONFIRMED` → holistic finding gets
    `triage_verdict == "CONFIRMED"`.
  - returning `FALSE_POSITIVE` → verdict set, finding still present, scored low
    after merge.
  - `samples=3` with votes `[CONFIRMED, FALSE_POSITIVE, FALSE_POSITIVE]` →
    aggregate `FALSE_POSITIVE`.
  - `samples=3` votes `[CONFIRMED, CONFIRMED, FALSE_POSITIVE]` → `CONFIRMED`.
  - `enabled=false` → pass is a no-op, verdicts stay `None`.
  - `verify_config_review=false` → config findings untouched.
  - prompt builder **excludes** `description`/`evidence` (assert those strings are
    not in the built prompt — this guards the anti-anchoring invariant).
  - all samples raise a non-fatal error → `triage_verdict == "NEEDS_CONTEXT"` (never
    `None`), logs `verify.unresolved`, no exception.
  - `file_path` unresolvable (`"unknown"`) → `NEEDS_CONTEXT`, no LLM call made.
  - a `ConfigurationError` sample → `run_verification` re-raises (fatal).
  - merge guard: verification **enabled** + a verdict-less `SR-*` finding → scored as
    `NEEDS_CONTEXT`, **not** `CONFIRMED`; verification **disabled** → old `CONFIRMED`
    default preserved.
  - `run_in_batches` (new shared helper) has its own unit tests: batching, budget
    gate stops dispatch, `is_fatal_error` re-raises, non-fatal error → `None` slot.
- `test_config_schema.py`: `SecurityReviewConfig` without `verification` → raises;
  with it → parses; bad `samples=0`/`6` → raises.
- `test_merge.py`: a `HolisticFinding` with `triage_verdict="FALSE_POSITIVE"` →
  SARIF result carries that verdict and is **not** auto-`CONFIRMED`.

## 1.9 Acceptance criteria (Phase 1)

- [ ] `python scar.py review --target eval/ --mode full` runs Pass 6; terminal shows
      `[6] verify ... done` and merge as `[7]`.
- [ ] Every holistic finding in the output SARIF has an explicit
      `properties.triage_verdict` produced by the verify agent (not the merge default).
- [ ] With a deliberately-planted false holistic finding (add a benign file to a test
      target), verification returns `FALSE_POSITIVE` and it scores below the
      `MODERATE` band.
- [ ] `verification.enabled: false` reproduces exactly today's output (byte-identical
      SARIF minus the new `triage_verdict` values).
- [ ] Regression suite (`pytest tests/regression/ -v --provider copilot:claude-opus`)
      shows **no PASS→FAIL** on the golden CWEs (verification must not suppress true
      positives). Run before/after; if a golden CWE regresses, the verify prompt is
      too aggressive — tune before merging.
- [ ] `pytest tests/unit/ -v` green; `python scripts/check_rules.py --all` clean.

---

# Phase 2 — Checkpoint, resume & incremental persistence

**Goal:** a killed run keeps completed-pass work and spend; `--resume <run-id>`
continues from the first incomplete pass. Streaming falls out for free.

## 2.1 Design (verified against `cli/review.py`, `config.py`, `budget.py`, `state.py`)

**Run directory.** `work_dir = PROJECT_ROOT` (cli/review.py:100); `state.output_dir =
(work_dir / config.review.output_sarif).parent` (state.py:76-79) → the run dir is
`PROJECT_ROOT/var/output/{date}-{name}-{run_id}/`. Checkpoints live in
`state.output_dir / "state"`.

**New module `passes/checkpoint.py`:**
- `save_pass(state, pass_name)` — atomic write of `state/{pass_name}.json` (write
  `.tmp`, `os.replace`). **Grep for an existing atomic-write helper before adding
  one** (`tracing.write_trace` does a plain, non-atomic write — do not copy that);
  if none exists, add a single shared util and use it in both places. Also refreshes
  `state/cost.json = state.cost_tracker.to_audit_log()`.
- `init_run(state)` — at pipeline start (before Pass 1), write `state/meta.json`
  with `{run_id, output_sarif, output_summary, output_triage}` and
  `state/config.json = state.config.model_dump()`. Resume reads `meta.json` for the
  authoritative `run_id` and output paths — **do not parse them from the directory
  name** (target names contain hyphens; the trailing-token heuristic is fragile).
- `completed_passes(run_dir) -> set[str]` — pass names with a valid
  `state/{name}.json`.
- `load_into(state, run_dir)` — rehydrates each present slice:
  - inventory → `manifest` (`FileManifest.model_validate`), `coverage`
  - sast → `sast_sarif` (dict via `json.load`), `tool_results`
    (`[ToolResult.model_validate(x) ...]`)
  - triage → `triage_result` (`TriageResult`) **and** the verdict-annotated
    `sast_sarif` (triage writes verdicts in place into `sast_sarif` properties,
    triage.py:161 — so persisting `sast_sarif` after Pass 3 captures them)
  - holistic → `holistic_result` (`HolisticReviewResult`)
  - config_review → `config_review_result` (`ConfigReviewResult`)
  - verify → re-persist `holistic_result` + `config_review_result` after Pass 6
    (verify mutates their `triage_verdict` in place)
  - cost → `state.cost_tracker.restore(json.load(state/cost.json))`

**`budget.py` — add restore (`CostTracker` has no rehydrate path today):**
```python
def restore(self, entries: list[dict]) -> None:
    """Repopulate from a prior run's audit log (resume). Preserves total_spent + budget guard."""
    self._calls = [CostEntry.model_validate(e) for e in entries]
```

**`pipeline.py`:** compute `completed = completed_passes(run_dir) if resuming else set()`.
Before each pass: `if name in completed: progress(n, name, "done", "restored"); continue`.
After each pass returns: `save_pass(state, name)`.

**`cli/review.py`:** add `@click.option("--resume", type=click.Path(exists=True))`.
When set, **do not** mint a fresh `run_id`/`auto_dir` (cli/review.py:63-73). Instead:
`run_dir = Path(resume).resolve()`; rebuild `cfg` from `state/config.json`
(`SecurityReviewConfig.model_validate(...)`) so the original `--provider`/`--budget`/
`--mode` and output paths are reused verbatim; construct `PipelineState` with the
`run_id` and paths read from `state/meta.json` and call `load_into` before
`run_pipeline`. If `--resume` is combined with conflicting flags (`--provider` etc.),
**error out** rather than silently mixing (fail-loud). Fresh runs unchanged.

**Fail-fast (rule 11):** a present-but-unreadable/schema-invalid `state/*.json` raises
`ConfigurationError` — never silently recompute. A *missing* file just means that
pass has not run.

## 2.2 Streaming (free follow-on)

Because merge is the only consumer, add `--stream` that, after triage/holistic/verify,
writes the current merged SARIF to `security-report.partial.sarif`. Reuse
`merge.py`'s conversion helpers; do not duplicate scoring. This gives the CC-dashboard
workflow ("explain findings as they land") and means a 90%-killed run still has a
readable partial report.

## 2.3 Acceptance criteria (Phase 2)

- [ ] Kill a `--mode full` run during Pass 4 (`kill -9`); re-run with
      `--resume <run-id>` → passes 1–3 log `checkpoint.restored`, spend from the
      cost audit log is preserved, run completes.
- [ ] Same-input fresh run vs. resumed run produce identical final SARIF.
- [ ] Corrupt a `state/*.json` → resume raises a clear `ConfigurationError`-class
      error, does not silently recompute.
- [ ] `--stream` writes `security-report.partial.sarif` after each LLM pass.
- [ ] Unit tests: `save_pass`/`load_into` round-trip every pass model; resume skips
      completed passes; corrupt checkpoint raises.

---

# Phase 3 — Transport retry with backoff (activate a dead knob)

**Goal:** one uniform, config-driven transport-retry policy across all five
providers, and stop treating empty responses as success. Reuses the already-defined
`providers.<name>.backoff_seconds`.

## 3.1 What exists today (verified against `providers.py`, `copilot_model.py`)

- **Copilot** (`copilot_model.py:298-352`): `max_attempts=2`; on `TimeoutError`,
  sleeps `self._backoff_seconds`, retries once with a fresh session. `backoff_seconds`
  is passed in via `providers.py:139-143`. This is the *only* provider that reads it.
- **Anthropic/OpenAI** (`providers.py:132-135`): PydanticAI's `AnthropicModel`/
  `OpenAIModel` — retries are SDK/httpx defaults, not driven by `backoff_seconds`.
- **claude/codex**: custom models (`providers.py:145-151`) — confirm behaviour in
  `claude_model.py`/`codex_model.py`; assume no unified retry.
- **Empty responses are never retried** (`copilot_model.py:313-319`): logged and
  returned as success, then lost at parse time.

Gaps: (a) no uniform config-driven transport retry; (b) empty responses treated as
success.

## 3.2 Design — one `RetryingModel` wrapper in `build_model`

- New `RetryingModel` in `retry_model.py`, subclassing pydantic_ai's **`WrapperModel`**
  (the same base `ConcurrencyLimitedModel` uses — verify the exact import path) so
  delegation of `request`/`request_stream`/`model_name`/`profile` is inherited rather
  than reimplemented. Applied in `build_model` as the **outermost** wrapper (so a
  retry re-acquires the concurrency slot cleanly):
  ```python
  model = ConcurrencyLimitedModel(inner, limiter=limiter)
  model = RetryingModel(model, backoff_seconds=provider_cfg.backoff_seconds, provider=provider)
  ```
- `request()` delegates to the wrapped model; retries when **either**:
  1. a **non-fatal** exception is raised (reuse `errors.is_fatal_error` — never retry
     auth/config/model-not-available), **or**
  2. the `ModelResponse` has no non-empty `TextPart` (the empty-response case).
- Backoff: exponential from `backoff_seconds`, bounded (e.g. 5 attempts, cap 120s —
  mirror the harness's bounded retry budget). Log `model.retry` (attempt, delay,
  reason). On exhaustion: re-raise for the exception case; for the empty case return
  the empty response so existing parse-fail handling (triage.py:143-164, holistic
  `_classify_result`) still runs.
- **Overlap with Copilot's internal 2-attempt timeout loop:** acceptable (bounded
  belt-and-suspenders). Optional cleanup: remove Copilot's internal loop once
  `RetryingModel` covers timeouts — do one or the other, not both silently.
- **Preserve fail-fast:** fatal errors are never retried.
- Composes with Phase 2: a pass that still fails after retries can be resumed.

## 3.2 Acceptance criteria (Phase 3)

- [ ] Unit test: a `FunctionModel`/stub raising `TimeoutError` twice then succeeding →
      wrapper retries with backoff and returns the success; asserts 2 `model.retry`
      logs.
- [ ] Unit test: a stub raising `AuthenticationError` → **no** retry, raises immediately.
- [ ] `backoff_seconds` in `security_review.yaml` demonstrably drives the delay (inject
      a fake clock/sleep and assert the value is read).
- [ ] `RetryingModel` is applied for **all five** providers (not just Copilot); an
      anthropic/openai model demonstrably retries a stubbed transient failure.
- [ ] An empty `ModelResponse` triggers a retry (previously returned as success).

---

# Phase 4 — Semantic dedup grouping (optional; lowest priority)

**Goal:** cluster findings that share a root cause but differ by line/tool, without
violating rule 009 (never trust LLM-echoed identifiers for bookkeeping).

## 4.1 Design

- Today dedup is exact-key only (`merge.py:73-103`: `(file,line)` and
  `(rule_id,file,line)`). Same root cause at adjacent lines = two findings; there is
  no cross-*run* dedup.
- Add a **grouping** layer that assigns a `cluster_id` (SARIF property) to findings
  the model judges to share a root cause — **it groups, it does not delete or
  renumber.** Deterministic identity (rule id, file, line) stays authoritative;
  `cluster_id` is advisory metadata for reporting.
- Keep it deterministic-first: cluster by `(normalised_cwe, file, symbol/function)`
  from `code_analysis` where available (ties into Plan 010/011); use an LLM judge
  only for the residual ambiguous cases, behind a config flag, off by default.
- Reporting (`reporting/`) can then collapse a cluster to one headline finding with
  N occurrences.

## 4.2 Acceptance criteria (Phase 4)

- [ ] Two findings, same CWE + same function, adjacent lines → same `cluster_id`;
      both still present in SARIF with distinct rule/line identity.
- [ ] Dedup remains deterministic by default (LLM judge flag off) — no LLM call added
      to the default path.
- [ ] Unit tests cover the deterministic clustering; no regression to existing
      exact-key suppression.

---

## Sequencing

1. **Phase 1** first — highest precision leverage, self-contained, no dependency on
   the CLI/provider internals. Ship and measure FP-rate change on the eval corpus.
2. **Phase 2** — do before Phase 3; resume makes retry failures recoverable.
3. **Phase 3** — activates `backoff_seconds`; small surface once the model layer is read.
4. **Phase 4** — optional, only if reporting noise from near-duplicate clusters proves
   material after Phases 1–3.

Each phase is independently shippable and independently revertable.

## Rule / convention compliance checklist

- [ ] No hardcoded model strings — verify model comes from `verification.model` or
      `llm.provider_model` (AGENTS.md rule 3).
- [ ] No silent defaults — `verification` section required; corrupt checkpoints raise
      (AGENTS.md rule 11).
- [ ] Verify agent has **zero tools**; context pre-materialised (Decisions 003/004).
- [ ] Identifiers overridden from known-correct values, never LLM-echoed (rule 9) —
      the verifier only *reads* the location, never rewrites it.
- [ ] Every emitted finding still carries a `CWE-NNN` (rule 5) — verification never
      strips CWE; refuted findings keep theirs.
- [ ] No new `subprocess` callers (rule 1).
- [ ] New files stay well under 1000 lines; `verify.py` mirrors `triage.py` size.
- [ ] `check_rules.py --all` and `pytest tests/unit/` green before each phase merges.
