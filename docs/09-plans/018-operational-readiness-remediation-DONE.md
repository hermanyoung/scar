# Plan 018 — Operational Readiness Remediation

**Status:** [x] Implemented (merged to main ~2026-07-14 with plan 019; status line corrected 2026-07-31)
**Date:** 2026-07-05
**Source:** Production Readiness Review (PRR) conducted 2026-07-05 against commit `1786c28` + working-tree fixes
**Depends on:** nothing (self-contained)
**Supersedes:** nothing

---

## 0. Purpose and non-negotiable context

The PRR found one dominant defect class: **SCAR converts partial failures into smaller, greener reports.** Missing SAST tools, failed CWE checks, unparseable LLM output, budget exhaustion, and token-budget file truncation all silently reduce coverage while every operator-facing surface (console, security-report.md, SARIF `executionSuccessful`, `files_reviewed`) claims a complete run. Secondary defects: all paid LLM work lives only in process memory until the final merge (a crash loses everything including the spend ledger), pricing keys crash on canonical model strings, no CI exit-code contract, run-global `var/tmp` paths, and no version traceability.

This plan fixes those. It is written for a fresh agent with no prior context. **Do not improvise. Where this plan says "exact", produce exactly that. Where the current code differs from a cited line number, the cited *code snippet/symbol* is authoritative — re-locate it, don't guess.**

### 0.1 Mandatory reading before writing any code

1. `AGENTS.md` and `CLAUDE.md` (repo root) — binding rules, especially #11 (no fallbacks).
2. `docs/03-principles/01-project-principles.md` — P4 (pipeline has zero `pydantic_ai` imports), P6, P13, P14.
3. `docs/04-rules/*.jsonl` — machine-checked rules. You must pass `python scripts/check_rules.py --all` when done.
4. `docs/05-standards/01-python-coding-standards.md`, `02-testing-standards.md`, `03-error-codes.md`.
5. Every source file you are about to edit — read it fully first. Line numbers below were verified on 2026-07-05 and may have drifted.

### 0.2 Binding constraints (violations = rejected work)

- Absolute imports only. `from security_review.logging import get_logger` — never `import logging` outside `logging.py`. (Pass modules currently use `structlog.get_logger(__name__)` directly — match the idiom of the file you are editing.)
- Only `src/security_review/tools/runner.py` calls subprocess. **None of the work below needs subprocess. Do not add any.**
- `passes/pipeline.py` must keep zero `pydantic_ai` imports (rule P6/005). The LLM preflight therefore lives in the CLI layer, not the pipeline.
- `models/` must not import from `passes/`, `agents/`, `tools/` (rule 001.8).
- No Pydantic defaults that hide missing config (rule 003.8). New YAML keys must be added to `config/settings/security_review.yaml` **and** its commented options header (rule 003.3).
- Every `except` logs at WARNING+ or re-raises (rule 002.7). No new TODO/FIXME markers (002.3). Files ≤ 1000 lines (002.1).
- New error codes must be registered in `docs/05-standards/03-error-codes.md` **before** first use.
- Tests: no real LLM calls (`ALLOW_MODEL_REQUESTS = False` is set globally in `tests/conftest.py`); use `TestModel`/`FunctionModel`.
- Breaking changes are free (P9): update all callers in the same change; delete dead code outright; no compatibility shims.

### 0.3 Prerequisites (do these first, verbatim)

```bash
cd /path/to/scar                       # this checkout
pip install -e '.[all]'               # CRITICAL: a stale editable install of a sibling clone
                                      # (security-code-review) may shadow this checkout
python -c "import security_review, pathlib; print(security_review.__file__)"
                                      # MUST print a path inside THIS checkout. If not, fix before continuing.
pytest tests/unit/ -v                 # must be green before you start (baseline)
python scripts/check_rules.py --all   # must be green before you start (baseline)
git checkout -b ops-readiness-018     # one branch; commit after each work package
```

### 0.4 Out of scope — do NOT do these

- Checkpoint/**resume** of LLM passes (WP3 lays the persistence groundwork only).
- Result caching keyed on file hashes.
- Copilot retry/backoff changes, exponential backoff, run deadlines (`copilot_model.py` is benchmark-canary-protected by ADR-001; separate plan).
- Wiring `session_timeout`/`backoff_seconds` for claude/codex/anthropic/openai adapters.
- Consolidating the duplicate quality/eval surfaces (`scar.py quality` vs `scripts/code_quality.py`, `scar.py eval` vs `scripts/benchmark_*.py`).
- Any change to agent prompts, CWE taxonomy content, OpenGrep rules, or detection logic.
- Any new CLI command (only new *options* on existing commands, plus flags listed below).

---

## 1. Work package overview and order

Implement strictly in this order. WP1 is the foundation; WP2, WP3, WP5, WP6 build on it.

| WP | Title | Files touched (primary) |
|----|-------|------------------------|
| 1 | Degradation ledger — failures become visible state | `models/degradation.py` (new), `passes/state.py`, `passes/sast.py`, `passes/triage.py`, `passes/holistic.py`, `passes/config_review.py`, `passes/merge.py`, `passes/pipeline.py`, `reporting/common.py`, `reporting/summary.py`, `reporting/full.py`, `reporting/terminal.py`, `cli/review.py` |
| 2 | Truthful LLM coverage — `files_reviewed` = files actually in the prompt | `passes/holistic.py`, `passes/config_review.py`, `passes/inventory.py` |
| 3 | Incremental persistence + salvage merge + run manifest | `run_ledger.py` (new), `passes/state.py`, `passes/merge.py`, `cli/review.py`, `budget.py`, passes |
| 4 | Pricing canonicalisation + LLM preflight | `budget.py`, `config/pricing.yaml`, `preflight.py` (new), `cli/review.py` |
| 5 | CI exit-code contract (`--fail-on`) | `cli/review.py`, `README.md` |
| 6 | Console error voice + `--quiet` honesty + live cost display | `logging.py`, `cli/app.py`, `passes/triage.py`, `passes/holistic.py` |
| 7 | Run-scoped var/tmp + on-disk redaction + `--version` + version stamping | `passes/sast.py`, `passes/merge.py`, `cli/app.py`, `reporting/summary.py`, `reporting/full.py`, `CHANGELOG.md` (new) |
| 8 | health-check depth + opengrep required | `cli/tools.py`, `tools/specs/opengrep.yaml` |
| 9 | Inventory: dir-pruned walk + `--exclude`/`--include` | `passes/inventory.py`, `config_schema.py`, `config/settings/security_review.yaml`, `cli/review.py` |
| 10 | reports: compare guard + prune + salvaged status | `cli/reports.py` |
| 11 | Documentation truth pass + CI workflow | `docs/`, `README.md`, `config/.env.example` (new), `.github/workflows/ci.yml` (new) |

After every WP: `pytest tests/unit/ -v` and `python scripts/check_rules.py --all` must pass. Commit with message `WP<n>: <title>`.

---

## 2. WP1 — Degradation ledger

### Problem

`PipelineState` (`src/security_review/passes/state.py`) has no failure field; `ReportData` (`src/security_review/reporting/common.py`) has none either. Consequences, all verified:

- A SAST tool whose binary is missing is dropped inside `resolve_tools_for_manifest` (`tools/registry.py:104-106`) with no message anywhere.
- A tool that crashes/times out returns `None` from `_run_single_tool` (`passes/sast.py:165-216`) and renders as a dim "skipped".
- A CWE check that fails twice increments `checks_failed` (`passes/holistic.py:250-252`) which is then discarded — the report reads as "no findings for that CWE".
- If every triage call fails, `state.triage_result` stays `None` and `pipeline.py:88-89` prints `done — skipped (no findings to triage)`.
- Budget exhaustion `break`s out of triage (`triage.py:96-103`) and holistic (`holistic.py:153-163`) loops with file-only warnings.
- A non-fatal Pass-5 failure logs `agent.failed` (`config_review.py:151-159`) and the console prints `done — 0 config findings`.
- `merge.py:51-61` hardcodes `"executionSuccessful": True`.
- `state.tool_results` (`state.py:50`) is dead code — declared, never written.

### Changes

**2.1 New file `src/security_review/models/degradation.py`** (models are leaf — no imports from passes/agents/tools):

```python
"""Degradation: a recorded reduction in review coverage or fidelity.

Every event that silently reduced coverage before this model existed
(missing tool, failed check, budget stop, truncated context) must be
recorded as a Degradation and rendered in every report format.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

PassName = Literal[
    "inventory", "sast", "triage", "holistic", "config_review", "merge", "pipeline",
]

DegradationKind = Literal[
    "tool_missing",        # SAST binary not on PATH — tool never ran
    "tool_failed",         # SAST tool ran but produced no usable output (crash/timeout/parse)
    "check_failed",        # holistic CWE check or config review failed after retry — NOT assessed
    "triage_call_failed",  # one or more triage calls failed — findings remain Untriaged
    "parse_failed",        # LLM responded but output was unparseable
    "budget_exhausted",    # max_budget_usd reached — remaining work skipped
    "files_omitted",       # token budget truncated files out of an LLM prompt
    "taxonomy_failed",     # CWE taxonomy injection failed — SARIF lacks taxonomy block
    "run_aborted",         # pipeline aborted mid-run — artifacts are partial (salvage)
]


class Degradation(BaseModel, extra="forbid"):
    pass_name: PassName
    kind: DegradationKind
    subject: str                       # tool name, "CWE-NNN", pass name, or "run"
    detail: str                        # one human-readable sentence
    count: int = Field(default=0, ge=0)  # optional quantity (files omitted, calls failed, checks skipped)
```

**2.2 `src/security_review/passes/state.py`:**

- Delete the dead field `tool_results: list[ToolResult] = field(default_factory=list)` and the now-unused `from security_review.models.report import ToolResult` import. (P9 — delete outright; `ToolResult` itself stays in `models/report.py` for `tools/runner.py`.)
- Add field: `degradations: list[Degradation] = field(default_factory=list)` with import `from security_review.models.degradation import Degradation`.
- Add field (used by WP3, declare now): `ledger: "RunLedger | None" = None` — import via `from security_review.run_ledger import RunLedger` (module created in WP3; create a stub in WP1 if you implement WP1 first: the stub is the full class per WP3, just implement WP3's module early — it has no dependencies).
- Add method on `PipelineState`:

```python
def degrade(self, d: Degradation) -> None:
    """Record a coverage degradation and mirror it to the run ledger."""
    self.degradations.append(d)
    if self.ledger is not None:
        self.ledger.append("degradation", **d.model_dump())
```

**2.3 Recording sites.** Add exactly these (import `Degradation` in each pass module):

*`passes/sast.py` — inside `run_sast`:*

- After `applicable_specs = resolve_tools_for_manifest(all_specs, file_paths, require_available=True)` (currently sast.py:46-48), also compute the availability gap. Do **not** change `resolve_tools_for_manifest`:

```python
applicable_any = resolve_tools_for_manifest(all_specs, file_paths, require_available=False)
missing = [s for s in applicable_any if not s.is_available()]
for spec in missing:
    state.degrade(Degradation(
        pass_name="sast", kind="tool_missing", subject=spec.name,
        detail=f"binary '{spec.binary}' not found on PATH — {spec.name} did not run",
    ))
    progress(2, "sast", "tool", f"{spec.name}: NOT INSTALLED — skipped")
```

  Also extend the CLI's tool-line styling (`cli/review.py`, the `status == "tool"` branch, currently `if "failed" in detail: red / elif "skipped": dim`) so `"NOT INSTALLED"` renders red: `if "failed" in detail or "NOT INSTALLED" in detail:` → red.

  Place this after the `if not applicable_specs:` guard's *computation* but ensure the `no_tools` branch (sast.py:50-53) also records one `Degradation(pass_name="sast", kind="tool_missing", subject="sast", detail="no applicable SAST tools found on PATH — nothing was scanned", count=len(applicable_any))` before returning. Note `progress = state.on_progress` is currently assigned at sast.py:55 — move that assignment above your new block.
- In the results loop (sast.py:73-83): the `isinstance(doc, Exception)` branch and the `else:` (None → "skipped") branch each record `Degradation(pass_name="sast", kind="tool_failed", subject=spec.name, detail=f"{spec.name} produced no usable output — its findings are absent (see var/logs/system.jsonl)")`. Change the None-branch progress text from `f"{spec.name}: skipped"` to `f"{spec.name}: FAILED — no output"` and style it red like the exception branch (the styling lives in `cli/review.py:126-131` keyed on the substring `"failed"` / `"skipped"` — lowercase `"FAILED"` will not match `"failed"`; use the literal text `f"{spec.name}: failed — no output"` so the existing red styling applies).

*`passes/triage.py` — inside `run_triage`:*

- In the budget `break` branch (triage.py:96-103), before `break`:

```python
remaining = total_findings - batch_start
state.degrade(Degradation(
    pass_name="triage", kind="budget_exhausted", subject="triage",
    detail=f"budget ${state.config.llm.max_budget_usd:.2f} reached after {batch_start} of "
           f"{total_findings} findings — {remaining} findings remain Untriaged",
    count=remaining,
))
state.on_progress(3, "triage", "tool",
                  f"budget exhausted — {remaining} of {total_findings} findings not triaged")
```

- After the batch loop, before the `if all_triaged:` block (triage.py:188): 

```python
if failed:
    state.degrade(Degradation(
        pass_name="triage", kind="triage_call_failed", subject="triage",
        detail=f"{failed} of {total_findings} triage calls failed — those findings remain Untriaged",
        count=failed,
    ))
```

*`passes/holistic.py` — inside `run_holistic`:*

- Budget `break` (holistic.py:154-163): record `Degradation(pass_name="holistic", kind="budget_exhausted", subject="holistic", detail=f"budget reached — {remaining} of {total_checks} CWE checks never ran: {', '.join('CWE-' + c.cwe_id for c, _ in runnable[batch_start:])}", count=remaining)` and emit `state.on_progress(4, "holistic", "tool", f"budget exhausted — {remaining} CWE checks skipped")` before `break`. (`remaining` is already computed there.)
- Retry-loop budget `continue` (holistic.py:226-229): record per-check `Degradation(pass_name="holistic", kind="budget_exhausted", subject=f"CWE-{check.cwe_id}", detail=f"budget reached before retry — CWE-{check.cwe_id} was NOT assessed", count=1)`.
- Give-up branch (holistic.py:249-252, the `else` after retry): record `Degradation(pass_name="holistic", kind="check_failed", subject=f"CWE-{check.cwe_id}", detail=f"check failed after retry — CWE-{check.cwe_id} ({check.short_name}) was NOT assessed", count=1)`.

*`passes/config_review.py` — inside `run_config_review`:*

- Budget `return` branch (config_review.py:73-80): record `Degradation(pass_name="config_review", kind="budget_exhausted", subject="config_review", detail=f"budget reached — {len(file_paths)} config files were NOT reviewed", count=len(file_paths))` before `return`. NOTE: `file_paths` is defined at line 61, before this guard — verify order after your edit.
- The non-fatal `except` (config_review.py:151-159): after the `logger.error`, before the `is_fatal_error` re-raise check, record `Degradation(pass_name="config_review", kind="check_failed", subject="config_review", detail=f"agent call failed ({type(e).__name__}) — {len(file_paths)} config files were NOT reviewed", count=len(file_paths))`. Only record when NOT fatal (fatal path re-raises; the salvage handler in WP3 covers it): i.e. `if is_fatal_error(e): raise` first, then record.
- Parse failure: after `config_result = parse_config_review_response(...)` (config_review.py:118), if `config_result is None`, record `Degradation(pass_name="config_review", kind="parse_failed", subject="config_review", detail="LLM response was unparseable — config files were NOT reviewed", count=len(file_paths))` and add a `logger.warning("config_review.parse_failed", file_count=len(file_paths))`.

*`passes/merge.py`:*

- Taxonomy `except` (merge.py:113-116): after the `logger.error`, record `state.degrade(Degradation(pass_name="merge", kind="taxonomy_failed", subject="sarif", detail="CWE taxonomy injection failed — SARIF taxonomies block is missing"))`.

**2.4 Rendering — SARIF (`passes/merge.py`):** replace the invocation block (merge.py:50-61):

```python
base_sarif["runs"][0].setdefault("invocations", [])
base_sarif["runs"][0]["invocations"].append({
    "executionSuccessful": not state.degradations,
    "commandLine": f"scar review --mode {state.config.review.mode} --target {state.target_path}",
    "properties": {
        "run_id": state.run_id,
        "target": str(state.target_path),
        "mode": state.config.review.mode,
        "provider": state.config.llm.provider_model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scar_version": __version__,
        "degradations": [d.model_dump() for d in state.degradations],
    },
})
```

(import `from security_review import __version__`; note the `commandLine` binary name fix `security-review` → `scar`.)

**2.5 Rendering — triage.json (`passes/merge.py`, currently lines 169-181):** add to `triage_data`:

```python
"scar_version": __version__,
"degradations": [d.model_dump() for d in state.degradations],
```

**2.6 Rendering — ReportData:** in `reporting/common.py` add to `ReportData`:

```python
# Coverage degradations (set from PipelineState.degradations)
degradations: list = field(default_factory=list)   # list[Degradation]
```

and in `merge.py` next to `report_data.coverage = state.coverage` (line 153) add `report_data.degradations = list(state.degradations)`.

**2.7 Rendering — markdown.** Add a shared helper in `reporting/common.py`:

```python
def render_degradations_md(degradations: list) -> list[str]:
    """Markdown lines for the Coverage Gaps section. Empty list when clean."""
    if not degradations:
        return []
    lines = ["\n## Coverage Gaps & Failures\n",
             "The following parts of this review did NOT complete. "
             "Absence of findings in these areas is NOT evidence of absence.\n"]
    for d in degradations:
        lines.append(f"- **[{d.pass_name}] {d.kind}** — {d.subject}: {d.detail}")
    return lines
```

- `reporting/summary.py`: call it immediately after the Triage section block (after line 42, before the CWEs section) via `lines.extend(render_degradations_md(data.degradations))`. Also add to the header block (after the LLM Cost line): `f"**Coverage Gaps:** {len(data.degradations)}"` — always rendered, `0` when clean.
- `reporting/full.py`: same two additions — header line after `**LLM Cost:**` (line 22), section after the Triage line (line 37).

**2.8 Rendering — terminal (`reporting/terminal.py`):** in `render_terminal` (lines 29-40), degradations must render even when there are zero findings (that is exactly the misleading case). Replace the body with:

```python
if data.degradations:
    _print_degradations(console, data)
if data.total == 0:
    console.print("\n  [dim]No findings.[/dim]")
    return
_print_summary_panel(console, data)
_print_findings_table(console, data, max_findings=max_findings)
_print_coverage(console, data)
```

and add:

```python
def _print_degradations(console: Console, data: ReportData) -> None:
    body = "\n".join(
        f"[red]•[/red] [{d.pass_name}] {d.kind} — {d.subject}: {d.detail}"
        for d in data.degradations
    )
    console.print()
    console.print(Panel(body, title="⚠ Coverage Gaps & Failures", border_style="red"))
```

**2.9 Rendering — pipeline console (`passes/pipeline.py`):** make the misleading "done" lines honest.

- Triage `else` branch (pipeline.py:88-89 and 111-112): replace `"skipped (no findings to triage)"` with a computation: if any `d.pass_name == "triage"` in `state.degradations` → `f"0 triaged — see coverage gaps"`, else keep `"skipped (no findings to triage)"`.
- After each of the four LLM/SAST pass `progress(..., "done", ...)` calls, no change to the detail strings beyond the triage fix above — the end-of-run block covers the rest (2.10). (Rationale: pass-local gap counts require snapshotting; the red panel at the end is the authoritative surface.)

**2.10 Rendering — CLI end-of-run (`cli/review.py`):** `render_terminal` already receives `report_data` (review.py:181-184) and will print the red panel via 2.8. Additionally, in the `--quiet` branch (review.py:204-205), change:

```python
else:
    click.echo(f"Report: {sarif_path}")
    if state.degradations:
        click.echo(click.style(
            f"WARNING: {len(state.degradations)} coverage gap(s) — review is incomplete. "
            f"See 'Coverage Gaps & Failures' in the report.", fg="red"), err=True)
```

### Tests (new file `tests/unit/test_degradations.py` + edits)

- `Degradation` model: valid construction; `extra="forbid"` rejects unknown keys; invalid `kind` rejected.
- `PipelineState.degrade` appends (build a minimal state with a stub config via existing fixtures or `SecurityReviewConfig.model_validate` on a dict copied from `config/settings/security_review.yaml`).
- `render_degradations_md([])` returns `[]`; non-empty renders the header + one bullet per item.
- `render_summary`/`render_full` include `**Coverage Gaps:** 0` when clean and the section when not.
- `render_terminal` with `total=0` and one degradation prints the panel (use `rich.console.Console(record=True)` and assert on `export_text()`).
- Merge invocation: build a minimal `PipelineState` with `sast_sarif=None` and one degradation, run `run_merge` (async — pytest asyncio_mode=auto), load the written SARIF, assert `invocations[0]["executionSuccessful"] is False` and `properties["degradations"]` has 1 entry and `properties["scar_version"] == __version__`. Use `tmp_path` as `work_dir` and set `config.review.output_sarif` etc. to paths under it.
- `tests/unit/test_sast_degradations.py`: monkeypatch `SecurityToolSpec.is_available` to return False for a fabricated spec set, call `run_sast` on a state with a small manifest fixture, assert a `tool_missing` degradation per dropped tool and the `no_tools` degradation when all are missing.
- Fix any existing unit tests referencing `state.tool_results` (search first: `rg "tool_results" tests/ src/`).

### Acceptance criteria

1. `PATH=/usr/bin:/bin python scar.py review --target eval/python --mode sast` (a PATH without bandit/opengrep) prints red `NOT INSTALLED` lines, prints the red Coverage Gaps panel, writes `executionSuccessful: false`, and the summary md contains `## Coverage Gaps & Failures`. *(Adjust PATH so python itself still resolves — e.g. `env PATH="$(dirname $(which python)):/usr/bin:/bin" python scar.py ...`.)*
2. A clean `python scar.py review --target eval/python --mode sast` still shows `executionSuccessful: true`, `**Coverage Gaps:** 0`, and no panel.
3. `pytest tests/unit/ -v` and `python scripts/check_rules.py --all` green.

---

## 3. WP2 — Truthful LLM coverage

### Problem

`context_builder.inline_files` (`context_builder.py:55-116`) already returns `(content, included, omitted)` — but:

- `passes/holistic.py:_build_inline_prompt` (lines 409-469) receives `included, omitted` and **discards them**, returning only the prompt string; `run_single_check` then stamps `files_reviewed=file_paths` — the pre-truncation list (lines 375, 377, 379). The record is falsified.
- `passes/config_review.py:_build_config_review_prompt` (line 198) calls `inline_files(..., reserve_tokens=0)` with the **default** `max_tokens=100_000`, ignoring `llm.max_tokens_per_batch`, and discards omissions with `_, _`. `files_reviewed=file_paths` at line 116-118 is likewise pre-truncation.
- The coverage panel data (`passes/inventory.py:251-284`, `_SEMANTIC_COVERAGE`) claims "Holistic"/"Config Review" per language at Pass-1 time regardless of `review.mode` — a `--mode sast` run still displays LLM coverage.

### Changes

**3.1 `passes/holistic.py`:**

- Change `_build_inline_prompt` return type to `tuple[str, list[str], list[str]]`; final line returns `(header + sast_section + "\n**Source files:**\n" + file_content + instructions, included, omitted)`.
- In `run_single_check` (line 332): `prompt, included, omitted = _build_inline_prompt(...)`.
- Replace both `files_reviewed=file_paths` occurrences (lines 375, 377) and the fallback constructor (line 379) with `files_reviewed=included`.
- After computing `included/omitted`, when `omitted` is non-empty:

```python
if omitted:
    state.degrade(Degradation(
        pass_name="holistic", kind="files_omitted", subject=f"CWE-{check.cwe_id}",
        detail=f"{len(omitted)} of {len(file_paths)} selected files did not fit the "
               f"token budget and were NOT reviewed for CWE-{check.cwe_id}: "
               f"{', '.join(omitted[:5])}{'…' if len(omitted) > 5 else ''}",
        count=len(omitted),
    ))
```

**3.2 `passes/config_review.py`:**

- Change `_build_config_review_prompt(file_paths, target_path)` to `_build_config_review_prompt(file_paths, target_path, max_tokens)` returning `tuple[str, list[str], list[str]]`; call `inline_files(Path(target_path), file_paths, max_tokens=max_tokens, reserve_tokens=0)` and return `(prompt, included, omitted)`.
- Both call sites (lines 85 and 88) pass `max_tokens=state.config.llm.max_tokens_per_batch` and unpack; record a `files_omitted` degradation (subject `"config_review"`) when `omitted` non-empty, same shape as 3.1.
- Replace `files_reviewed=file_paths` (lines 116, 118) with `files_reviewed=included`.

**3.3 `passes/inventory.py` coverage truthfulness:**

- Change `_build_coverage_report(entries, languages)` to `_build_coverage_report(entries, languages, mode: str)` and gate: `sem_passes = _SEMANTIC_COVERAGE.get(lang, []) if mode == "full" else []`.
- Call site (line 166): `state.coverage = _build_coverage_report(entries, languages, state.config.review.mode)`.

**3.4 `cli/test_cwe.py`:** it prints a "Files reviewed" count from the holistic result — after 3.1 that number is automatically truthful. Verify the command still runs (`python scar.py test-cwe --help`) and update any unpacking it does of `run_single_check`/`_build_inline_prompt` if it imports them (search: `rg "_build_inline_prompt|run_single_check" src/ tests/ scripts/`). Update every caller you find — same-PR rule.

### Tests (`tests/unit/test_context_flow.py`)

- `_build_inline_prompt` with a fabricated 3-file target under `tmp_path` and `max_input_tokens` sized to fit only the first file: assert returned `included == [first]`, `omitted == [second, third]`, and the prompt contains the `**Note:** 2 file(s) omitted` marker.
- `run_single_check` via `FunctionModel` returning a fixed markdown response: assert the resulting `files_reviewed` equals `included` (not the full selection) and a `files_omitted` degradation was recorded on the state.
- `_build_coverage_report(..., mode="sast")` yields empty `semantic_passes`; `mode="full"` yields the mapping.

### Acceptance criteria

1. `python scar.py review --target eval/python --mode sast` terminal Coverage section no longer lists `LLM Holistic`/`Config Review`.
2. Unit tests above green; full suite green; rules checker green.

---

## 4. WP3 — Incremental persistence, salvage merge, run manifest

### Problem

Everything (verdicts, findings, cost ledger) lives in `PipelineState` (memory) until `run_merge` writes SARIF → reports → triage.json at the very end (`merge.py:125, 163-181`). `KeyboardInterrupt` is caught in `cli/review.py:206-209` ("Interrupted.", exit 130) and fatal errors at 210-218 ("Failed: {e}", exit 1) — **merge never runs** in either case. A 55-minute LLM run that dies loses all paid work and the only record of spend. Additionally `budget.recorded` is `logger.debug` (`budget.py:77`), so per-call costs aren't even in the INFO file log.

### Changes

**4.1 New file `src/security_review/run_ledger.py`:**

```python
"""Append-only JSONL event ledger for a single run.

One line per event, flushed per call — crash-safe by construction.
The ledger is best-effort: a ledger write failure must never kill the
pipeline (it logs at WARNING and continues).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class RunLedger:
    """Append-only events.jsonl writer for one pipeline run."""

    def __init__(self, path: Path):
        self._path = path

    def append(self, kind: str, **fields) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **fields,
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError as e:
            logger.warning("ledger.write_failed", path=str(self._path), error=str(e))
```

**4.2 `budget.py`:** change `logger.debug("budget.recorded", ...)` (line 77) to `logger.info(...)`. (Signature change comes in WP4 — keep them as separate commits within the branch if you prefer, but WP4 depends on this file too.)

**4.3 Event emission.** In each LLM pass, after each successful `state.cost_tracker.record(...)`:

- `triage.py` (inside `_triage_single_finding`, after the record call at ~line 302, and after `verdict` is resolved): 

```python
if state.ledger is not None and verdict is not None:
    state.ledger.append("triage_verdict", index=index, rule_id=rule_id,
                        file=file_path, line=line, verdict=verdict.verdict.value,
                        cumulative_usd=round(state.cost_tracker.total_spent, 4))
```

Place after the `if verdict:` check that already exists (line ~330) — inside it, before `return verdict`.
- `holistic.py` (in `run_single_check`, after the cost record at ~line 363): `state.ledger.append("holistic_check", cwe_id=check.cwe_id, findings=len(review_result.findings), parse_failed=parse_failed, cumulative_usd=round(state.cost_tracker.total_spent, 4))` guarded by `if state.ledger is not None`.
- `config_review.py` (after cost record ~line 125): `state.ledger.append("config_review", findings=finding_count, cumulative_usd=...)` — note `finding_count` is computed at line 134; move the ledger call after it.
- Degradations are mirrored automatically via `PipelineState.degrade` (WP1).

**4.4 Salvage-capable merge (`passes/merge.py`):** `run_merge` contains **no `await`** — its body is synchronous. Refactor:

- Extract the entire body of `run_merge` into `def write_artifacts(state: PipelineState) -> Path:` (sync, same module, same logic).
- `async def run_merge(state) -> Path:` becomes: `path = write_artifacts(state)`; then tmp cleanup (added in WP7); `return path`.

**4.5 Run manifest + wiring (`cli/review.py`):** right after `Path(output).parent.mkdir(parents=True, exist_ok=True)` (line 101):

```python
out_dir = Path(output).parent
from security_review import __version__
from security_review.run_ledger import RunLedger
run_manifest = {
    "run_id": run_id,
    "target": str(target_path),
    "mode": mode,
    "provider": effective_provider,          # move the effective_provider assignment (line 151) above this block
    "formats": formats,                       # move format parsing (lines 136-139) above this block
    "scar_version": __version__,
    "started_at": datetime.now(timezone.utc).isoformat(),
}
(out_dir / "run.json").write_text(json.dumps(run_manifest, indent=2), encoding="utf-8")
```

(add `import json` and `from datetime import timezone` to the existing imports; reorder the moved blocks carefully — `formats` and `effective_provider` must be computed before the manifest.)
Then when constructing `PipelineState` (line 141): add `ledger=RunLedger(out_dir / "events.jsonl")`.

**4.6 Salvage handlers (`cli/review.py`):** replace the two except blocks (lines 206-218):

```python
except KeyboardInterrupt:
    logger.warning("pipeline.interrupted")
    click.echo("\nInterrupted.", err=True)
    _salvage(state, reason="interrupted by operator (Ctrl-C)")
    raise SystemExit(130)
except Exception as e:
    logger.error("pipeline.failed", error=str(e), error_type=type(e).__name__)
    if debug:
        import traceback
        traceback.print_exc()
    else:
        click.echo(f"\nFailed: {e}", err=True)
        click.echo("Use --debug for full traceback.", err=True)
    _salvage(state, reason=f"pipeline aborted: {type(e).__name__}: {e}")
    raise SystemExit(1)
```

with a module-level helper in `cli/review.py`:

```python
def _salvage(state, *, reason: str) -> None:
    """Best-effort write of partial artifacts after an aborted run."""
    from security_review.logging import get_logger
    logger = get_logger(__name__)
    if state.manifest is None:
        return  # nothing ran — nothing to salvage
    from security_review.models.degradation import Degradation
    state.degrade(Degradation(
        pass_name="pipeline", kind="run_aborted", subject="run",
        detail=f"{reason} — artifacts below are PARTIAL",
    ))
    try:
        from security_review.passes.merge import write_artifacts
        path = write_artifacts(state)
        click.echo(click.style(
            f"Partial results salvaged (spend so far: ${state.cost_tracker.total_spent:.2f}): {path.parent}",
            fg="yellow"), err=True)
    except Exception as salvage_err:
        logger.error("salvage.failed", error=str(salvage_err),
                     error_type=type(salvage_err).__name__)
```

Notes: `state` is in scope in both handlers (constructed at line 141). `asyncio.run` re-raises `KeyboardInterrupt` after cancelling the task, so in-memory state mutated so far is intact. `write_artifacts` is sync — safe to call outside the event loop.

### Tests

- `tests/unit/test_run_ledger.py`: append writes valid JSON lines with `ts` and `kind`; a ledger pointed at an unwritable path (e.g. `tmp_path/"nope"/"x.jsonl"` after `chmod 0o000` on the parent, or monkeypatch `open` to raise `OSError`) logs a warning and does not raise.
- `tests/unit/test_salvage.py`: build a state with a minimal `sast_sarif` (reuse the `sample_sarif` fixture from `tests/conftest.py` if present — verify with `rg "sample_sarif" tests/conftest.py`), call `write_artifacts(state)` directly, assert SARIF + summary + triage.json exist under `tmp_path` and triage.json contains `degradations` and `scar_version`.
- Extend `test_degradations.py` merge test to assert `events.jsonl` receives the degradation line when a ledger is attached.

### Acceptance criteria

1. Start `python scar.py review --target . --mode sast`, Ctrl-C (or SIGINT) mid-Pass-2: stderr shows `Partial results salvaged...`, the run dir contains `run.json`, `events.jsonl`, `security-report.sarif`, `security-report.md`, `triage.json`, and triage.json has a `run_aborted` degradation. Exit code 130 preserved.
2. `run.json` exists immediately after a run starts (verify with a normal run: file present in output dir).
3. Suite + rules green.

---

## 5. WP4 — Pricing canonicalisation + LLM preflight

### Problem

`CostTracker.record` (`budget.py:43-59`) looks up pricing by the **raw** model string. `config/pricing.yaml` keys are a hybrid: alias-form for copilot/claude/codex (`copilot:claude-opus`), wire-form for anthropic/openai (`anthropic:claude-opus-4-6`). Consequences: the README-advertised `--provider copilot:claude-opus-4.6` raises `ConfigurationError` at the **first cost record** (i.e. after the first paid call); `--provider anthropic:claude-opus` (alias) likewise. And nothing validates provider auth or pricing before Pass 1 — an expired token is discovered at Pass 3 after the full SAST wall-clock.

### Changes

**5.1 `budget.py` — canonical pricing keys:**

- Add import: `from security_review.providers import resolve_model_name` (verified acyclic: `providers.py` imports only `structlog`, `yaml`, `MODULE_ROOT`, `ConfigurationError` at module level).
- Change `record` signature — **delete the `model_responded` parameter** (P9; update all three callers):

```python
def record(self, agent_name: str, batch_id: str, model_requested: str,
           tokens_in: int, tokens_out: int) -> CostEntry:
    provider, _, name = model_requested.partition(":")
    resolved = f"{provider}:{resolve_model_name(provider, name)}"
    pricing = self._pricing.get(resolved)
    if pricing is None:
        raise ConfigurationError(
            f"No pricing entry for model '{resolved}' (requested '{model_requested}') "
            f"in config/pricing.yaml. Add an explicit '{resolved}' entry.",
            code="SYS_CONFIG_INVALID",
        )
    ...
    entry = CostEntry(..., model_requested=model_requested, model_responded=resolved, ...)
```

  (`model_responded` stays in `CostEntry` — it now records the resolved wire ID, which is honest.)
- Add a public helper used by preflight:

```python
def pricing_entry_exists(model_string: str) -> bool:
    """True if the resolved form of provider:model has a pricing entry."""
    provider, _, name = model_string.partition(":")
    if not name:
        return False
    resolved = f"{provider}:{resolve_model_name(provider, name)}"
    return resolved in _load_pricing()
```

- Update the three callers to drop `model_responded=`: `passes/triage.py` (~line 302), `passes/holistic.py` (~line 363), `passes/config_review.py` (~line 125). Search to be exhaustive: `rg "model_responded" src/ tests/ scripts/`.

**5.2 `config/pricing.yaml` — migrate keys to resolved/wire form.** Replace the copilot/claude/codex alias keys and add the missing canonical entries. Final key set (keep the header comment block, update its text to say keys are the **resolved** form after `models.yaml` alias + provider-override expansion):

```yaml
# Copilot models ($0 via subscription — token-equivalent monitoring)
copilot:claude-opus-4.6:      {input_per_token: 0.000005, output_per_token: 0.000025}
copilot:claude-sonnet-4.6:    {input_per_token: 0.000003, output_per_token: 0.000015}
copilot:claude-haiku-4.5:     {input_per_token: 0.000001, output_per_token: 0.000005}
copilot:gpt-5.5:              {input_per_token: 0.000002, output_per_token: 0.000010}
# Claude Agent SDK ($0 via Max/Pro)
claude:claude-opus-4-6:       {input_per_token: 0.000005, output_per_token: 0.000025}
claude:claude-sonnet-4-6:     {input_per_token: 0.000003, output_per_token: 0.000015}
claude:claude-haiku-4-5:      {input_per_token: 0.000001, output_per_token: 0.000005}
# Codex ($0 via ChatGPT subscription)
codex:gpt-5.5:                {input_per_token: 0.000002, output_per_token: 0.000010}
# Direct API pricing
openai:gpt-5.5:               {input_per_token: 0.000002, output_per_token: 0.000010}
openai:gpt-5.4-mini:          {input_per_token: 0.0000004, output_per_token: 0.0000016}
openai:o3:                    {input_per_token: 0.000002, output_per_token: 0.000008}
anthropic:claude-opus-4-6:    {input_per_token: 0.000005, output_per_token: 0.000025}
anthropic:claude-sonnet-4-6:  {input_per_token: 0.000003, output_per_token: 0.000015}
anthropic:claude-haiku-4-5:   {input_per_token: 0.000001, output_per_token: 0.000005}
```

(Expand to the multi-line mapping style already used in the file — do not use flow style if the existing file uses block style. Per-token values above are the existing values carried over; haiku/o3 rates: Haiku 4.5 = $1/$5 per MTok, o3 = $2/$8 per MTok.)

**5.3 New file `src/security_review/preflight.py`:**

```python
"""Pre-flight validation for LLM modes: pricing keys + provider auth probe.

Called by the CLI (NOT by passes/pipeline.py — P6 keeps the pipeline free
of pydantic_ai imports) before Pass 1, so an expired token or missing
pricing entry fails in seconds, not after the SAST wall-clock.
"""
from __future__ import annotations

import structlog
from pydantic_ai import Agent, UsageLimits

from security_review.budget import CostTracker, pricing_entry_exists
from security_review.config_schema import SecurityReviewConfig
from security_review.errors import ConfigurationError, LLMError
from security_review.providers import build_model

logger = structlog.get_logger(__name__)


def validate_pricing(config: SecurityReviewConfig) -> None:
    """Fail fast if any configured model lacks a pricing entry."""
    models = {config.llm.provider_model}
    if config.llm.triage_model:
        models.add(config.llm.triage_model)
    missing = sorted(m for m in models if not pricing_entry_exists(m))
    if missing:
        raise ConfigurationError(
            f"No pricing entry for {', '.join(missing)} in config/pricing.yaml. "
            f"Add entries for the resolved model ID(s) before running LLM passes.",
            code="SYS_CONFIG_INVALID",
        )


async def probe_provider(config: SecurityReviewConfig, cost_tracker: CostTracker) -> None:
    """One minimal LLM request to prove auth + reachability. Raises LLMError on failure."""
    model_string = config.llm.provider_model
    model = build_model(model_string, llm_config=config.llm)
    agent = Agent(system_prompt="Reply with the single word OK.", output_type=str)
    try:
        result = await agent.run(
            "ping", model=model,
            usage_limits=UsageLimits(request_limit=1, total_tokens_limit=2_000),
        )
    except Exception as e:
        logger.error("preflight.failed", model=model_string,
                     error=str(e), error_type=type(e).__name__)
        raise LLMError(
            f"Provider preflight failed for '{model_string}': {e}. "
            f"Check auth before re-running (copilot: 'gh auth status'; "
            f"anthropic/openai: API key in config/.env; claude: 'claude setup-token').",
            code="LLM_AUTH_FAILED",
        ) from e
    usage = result.usage()
    cost_tracker.record(
        agent_name="preflight", batch_id="preflight-000",
        model_requested=model_string,
        tokens_in=usage.request_tokens or 0, tokens_out=usage.response_tokens or 0,
    )
    logger.info("preflight.ok", model=model_string)
```

**5.4 Wire into `cli/review.py`:** add option after `--trace` (keep click option order tidy):

```python
@click.option("--no-preflight", is_flag=True,
              help="Skip the pre-run provider auth probe and pricing validation (LLM modes).")
```

(add `no_preflight` to the function signature). Then, immediately before `asyncio.run(run_pipeline(state))` (line 163):

```python
if mode != "sast" and not no_preflight:
    from security_review.preflight import probe_provider, validate_pricing
    validate_pricing(cfg)
    if not quiet:
        click.echo("  Preflight: probing LLM provider... ", nl=False)
    asyncio.run(probe_provider(cfg, state.cost_tracker))
    if not quiet:
        click.echo(click.style("ok", fg="green"))
```

This runs inside the existing `try:` so failures route through the standard error path (and salvage is a no-op because `state.manifest is None`).

**5.5 Docs registration:** `docs/05-standards/03-error-codes.md` — `LLM_AUTH_FAILED` is already registered; update its "Meaning" cell to mention the preflight probe. (Full doc reconciliation is WP11.)

### Tests

- `tests/unit/test_budget_resolution.py`:
  - `CostTracker` with injected pricing `{"copilot:claude-opus-4.6": ModelPricing(...)}`: `record(model_requested="copilot:claude-opus", ...)` succeeds (alias resolved) and `entry.model_responded == "copilot:claude-opus-4.6"`.
  - Unknown model raises `ConfigurationError` whose message contains both the resolved and requested strings.
  - `pricing_entry_exists("anthropic:claude-opus")` is True against the real `config/pricing.yaml` (alias → `claude-opus-4.6` → anthropic override → `claude-opus-4-6`).
- `tests/unit/test_preflight.py`:
  - `validate_pricing` passes on the shipped config; a config with `provider_model="copilot:not-a-model"` raises `ConfigurationError`.
  - `probe_provider` with `TestModel` (`agent.run(..., model=TestModel())` pattern — pass the TestModel by monkeypatching `build_model` to return it) records one cost entry. NOTE: TestModel usage never touches the network; `ALLOW_MODEL_REQUESTS=False` stays satisfied. Monkeypatch `build_model` in the `preflight` namespace: `monkeypatch.setattr("security_review.preflight.build_model", lambda *a, **k: TestModel())`.
  - `probe_provider` where the model raises (FunctionModel whose function raises `RuntimeError("401")`, or monkeypatched `build_model` returning a model that raises) → `LLMError` with `code == "LLM_AUTH_FAILED"`.

### Acceptance criteria

1. `python scar.py review --target eval/python --mode sast` unaffected (no preflight in sast mode).
2. Every README `--provider` example string now resolves to a pricing key: assert in a unit test that each of `copilot:claude-opus-4.6`, `copilot:claude-sonnet-4.6`, `anthropic:claude-sonnet`, `openai:gpt` passes `pricing_entry_exists`.
3. Suite + rules green. **Do not run a real LLM preflight as part of verification** — unit tests only.

---

## 6. WP5 — CI exit-code contract

### Problem

`review` exits 0 regardless of findings (observed: 31 findings incl. Critical → exit 0), while README markets `sast` mode for "CI gating". CI cannot gate without parsing SARIF.

### Changes — `cli/review.py`

- Add options:

```python
@click.option("--fail-on", "fail_on", default=None,
              type=click.Choice(["urgent", "elevated", "moderate", "low"]),
              help="Exit 3 if any finding is at or above this priority band (for CI gating).")
@click.option("--fail-on-degraded", is_flag=True,
              help="Exit 4 if the review completed with coverage gaps (degradations).")
```

- Add a pure module-level helper (unit-testable, no click):

```python
_BAND_AT_OR_ABOVE = {
    "urgent":   ("URGENT",),
    "elevated": ("URGENT", "ELEVATED"),
    "moderate": ("URGENT", "ELEVATED", "MODERATE"),
    "low":      ("URGENT", "ELEVATED", "MODERATE", "LOW"),
}


def resolve_exit_code(report_data, fail_on: str | None, fail_on_degraded: bool) -> int:
    """0 = pass; 3 = findings at/above threshold; 4 = degraded run."""
    if report_data is None:
        return 0
    if fail_on:
        counts = {"URGENT": report_data.urgent, "ELEVATED": report_data.elevated,
                  "MODERATE": report_data.moderate, "LOW": report_data.low}
        if any(counts[b] > 0 for b in _BAND_AT_OR_ABOVE[fail_on]):
            return 3
    if fail_on_degraded and report_data.degradations:
        return 4
    return 0
```

- At the end of the success path (after the quality summary block, before the function returns — both quiet and non-quiet paths must hit it):

```python
exit_code = resolve_exit_code(state.report_data, fail_on, fail_on_degraded)
if exit_code:
    click.echo(click.style(
        f"Exit {exit_code}: " +
        ("findings at or above --fail-on threshold" if exit_code == 3
         else "review completed with coverage gaps"), fg="red"), err=True)
    raise SystemExit(exit_code)
```

- Documented contract (add to the `review` docstring and README — WP11 carries the README edit): `0` pass · `1` crash (partial artifacts salvaged when possible) · `2` CLI usage error (click) · `3` findings ≥ `--fail-on` · `4` degraded and `--fail-on-degraded` · `130` interrupted.

### Tests (`tests/unit/test_exit_codes.py`)

Exercise `resolve_exit_code` directly with fabricated `ReportData` instances: no threshold → 0; `--fail-on elevated` with `elevated=1` → 3; with only `moderate=5` → 0; `fail_on_degraded` + one degradation → 4; findings-threshold wins over degraded when both trigger (assert 3).

### Acceptance criteria

1. `python scar.py review --target eval/python --mode sast --fail-on elevated --quiet; echo $?` → `3` (the eval corpus has ELEVATED findings).
2. Same command with `--fail-on urgent` → `0`.
3. Suite + rules green.

---

## 7. WP6 — Console error voice, `--quiet` honesty, live cost

### Problem

`_setup_logging` (`cli/app.py:26-46`) installs a console log handler only when `verbose or debug or json_logs` — at default verbosity every `logger.error`/`logger.warning` is file-only. `--quiet` help says "Errors only" but delivers errors-nowhere, and sets the root level to WARNING which strips INFO events from the *file* audit trail too. Running cost is invisible (`budget.recorded` was DEBUG — fixed to INFO in WP3; still not on the console by default).

### Changes

**7.1 `src/security_review/logging.py`:** add a `console_level` parameter:

```python
def setup_logging(
    level: str | None = None,
    format_type: str | None = None,
    enable_console: bool | None = None,
    enable_file_logging: bool | None = None,
    console_level: str | None = None,
) -> None:
```

In the console-handler block (lines 157-160), after `console_handler.setFormatter(...)`: `if console_level is not None: console_handler.setLevel(getattr(logging, console_level.upper()))`. The root logger level must remain the *most verbose* of the two sinks so per-handler levels do the filtering — it already is (`effective_level` governs root; console gets its own level).

**7.2 `cli/app.py:_setup_logging`:** replace the body's level logic with this exact behavior matrix (root/file level, console enabled, console level):

| flags | root & file level | console handler | console level |
|---|---|---|---|
| (default) | INFO | **enabled** | WARNING |
| `-v` / `--json-logs` | INFO | enabled | INFO |
| `--debug` | DEBUG | enabled | DEBUG |
| `--quiet` | INFO *(file audit keeps INFO — changed from WARNING)* | enabled | ERROR |

```python
if debug:
    level, console_level = "DEBUG", "DEBUG"
elif quiet:
    level, console_level = "INFO", "ERROR"
elif verbose or json_logs:
    level, console_level = "INFO", "INFO"
else:
    level, console_level = "INFO", "WARNING"

from security_review.logging import setup_logging
setup_logging(
    level=level,
    format_type="json" if json_logs else "console",
    enable_console=True,
    enable_file_logging=not no_file_log,
    console_level=console_level,
)
```

Result: at default verbosity, `logger.warning`/`logger.error` (budget exhaustion, tool skipped, check failed, `sast.no_tools`) now reach stderr; `--quiet` shows errors (as its help text promises) while the file log keeps its full INFO audit trail. `budget.recorded` at INFO appears on console only with `-v` (by design — the counter line below is the default-mode cost surface).

**7.3 Live cost in progress counters:** in `passes/triage.py`, both counter emissions (lines ~117-120 and ~179-186): append `, ${state.cost_tracker.total_spent:.2f}` inside the parenthesised timing segment, e.g. `f"... ({int(elapsed)}s elapsed, {eta}, ${state.cost_tracker.total_spent:.2f})"` and `f"... ({int(elapsed)}s{eta}, ${state.cost_tracker.total_spent:.2f})"`. Same for `passes/holistic.py` counter emissions (lines ~177-180 and ~204-210). Keep formats exactly consistent between the two files.

### Tests

- Extend `tests/unit/test_exit_codes.py` or new `tests/unit/test_logging_setup.py`: after `setup_logging(level="INFO", enable_console=True, console_level="WARNING", enable_file_logging=False)`, assert the root logger has exactly one `StreamHandler` and its `.level == logging.WARNING`, and root `.level == logging.INFO`. (Import `logging` stdlib inside the test — tests are exempt from rule 001.2's scope, which covers `src/security_review/` only.)

### Acceptance criteria

1. `python scar.py review --target /tmp --mode sast` against an empty dir at default verbosity prints the `sast.no_tools`/no-files warnings to stderr (observable), not just the file log.
2. `--quiet` run with a forced warning (missing tools PATH trick from WP1) shows the error lines on stderr.
3. Suite + rules green. NOTE: rule 002.5 greps for `**kwargs` — `RunLedger.append(self, kind, **fields)` from WP3 uses `**fields` on a public method: check `docs/04-rules/002_code_patterns.jsonl` rule 002.5's exact pattern (`def [a-z]\w+\(.*\*\*kwargs`) — it matches the *name* `kwargs` only, and `**fields` passes. Do not rename it to `**kwargs`.

---

## 8. WP7 — Run-scoped tmp, on-disk redaction, cleanup, `--version`, version stamping

### Problem

`_run_single_tool` writes intermediate tool SARIF to the **global** `var/tmp/{tool}.sarif` (`passes/sast.py:158-161`): two concurrent runs cross-contaminate each other's findings, and raw (unredacted) betterleaks output persists forever (redaction happens in-memory on the merged doc only, `sast.py:95`). No `--version` flag; report footers hardcode the literal `*Generated by SCAR v1.0.0*` (`reporting/summary.py:68`, `full.py:73`).

### Changes

**8.1 `passes/sast.py`:**

- Thread `run_id`: `_run_single_tool(spec, target_path, work_dir, suffix="")` → add keyword-only `run_id: str`; tmp dir becomes `work_dir / "var" / "tmp" / run_id`. `_run_file_targeted_tool` gains and forwards `run_id`. Call sites in `run_sast` (lines 63-68) pass `run_id=state.run_id`.
- On-disk redaction: in `_run_single_tool`, in the `sarif_native` success path and the fallback `load_sarif` path, when `spec.redact_output` is true, redact before returning **and** rewrite the file so no raw secrets persist:

```python
doc = load_sarif(output_path)
if spec.redact_output:
    doc = redact_sarif(doc)
    Path(output_path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
return doc
```

  (import `json`; `redact_sarif` is already imported in sast.py. Apply the same treatment in the SARIF-v1-upgrade branch and the generic fallback branch — factor a tiny local helper `_finalize(doc)` inside `_run_single_tool` to avoid triplication. The pip-audit/dotnet JSON conversion branches don't carry secrets — leave them.)
- The in-memory `merged = redact_sarif(merged)` at line 95 stays (defence in depth).

**8.2 Cleanup:** in `passes/merge.py`'s `run_merge` (NOT in `write_artifacts` — salvage must keep forensics): after `path = write_artifacts(state)`:

```python
import shutil
tmp_dir = state.work_dir / "var" / "tmp" / state.run_id
shutil.rmtree(tmp_dir, ignore_errors=True)
```

(Put the `import shutil` at module top per house style.)

**8.3 `--version`:** in `cli/app.py`, decorate the group:

```python
from security_review import MODULE_ROOT, __version__
...
@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="scar")
@click.pass_context
```

**8.4 Footers:** `reporting/summary.py:68` and `reporting/full.py:73` → `f"*Generated by SCAR v{__version__}*"` with `from security_review import __version__` at module top.

**8.5 `CHANGELOG.md`** (repo root, new):

```markdown
# Changelog

## Unreleased
- Operational readiness remediation (plan 018): degradation ledger, salvage merge,
  run-scoped tmp, LLM preflight, --fail-on exit codes, truthful LLM coverage.

## 1.0.0 — 2026-05-22
- Initial public release.
```

### Tests

- `tests/unit/test_tmp_scoping.py`: monkeypatch `run_tool` to write a fixed SARIF and return success; call `_run_single_tool(spec, target, tmp_path, run_id="abc123")`; assert the output file path contains `/var/tmp/abc123/`. With a spec where `redact_output=True` and a monkeypatched `redact_sarif` sentinel, assert the on-disk file was rewritten.
- Footer: assert `render_summary(ReportData())` contains `f"SCAR v{__version__}"`.
- CLI: `from click.testing import CliRunner` → `CliRunner().invoke(cli, ["--version"])` output contains `__version__`.

### Acceptance criteria

1. `python scar.py --version` prints `scar, version 1.0.0`.
2. After a sast run: `var/tmp/` contains no files for that run (cleaned); during the run they live under `var/tmp/<run_id>/`. After a Ctrl-C run: `var/tmp/<run_id>/` retained.
3. `rg "SCAR v1.0.0" src/` returns nothing (no hardcoded version).
4. Suite + rules green.

---

## 9. WP8 — health-check depth + opengrep required

### Problem

`health-check` (`cli/tools.py:13-46`) checks binaries only — a green health-check says nothing about config validity, prompts, taxonomy, pricing, or auth. `tools/specs/opengrep.yaml` marks the **primary pattern engine** `optional: true` while `setup.py` treats it as required.

### Changes

**9.1 `tools/specs/opengrep.yaml`:** `optional: true` → `optional: false`.

**9.2 `cli/tools.py` — extend `health_check`** (keep the existing tool section; append sections; NO subprocess — presence checks only):

```python
# after the tool loop:
click.echo("\n  Configuration")
checks: list[tuple[str, bool, str]] = []   # (label, ok, detail)

from security_review.config import load_config
try:
    cfg = load_config(None)
    checks.append(("config/settings/security_review.yaml", True, f"mode={cfg.review.mode}"))
except Exception as e:
    cfg = None
    checks.append(("config/settings/security_review.yaml", False, str(e)))

from security_review.checks import load_cwe_checks
try:
    cwe_checks = load_cwe_checks()
    checks.append(("config/taxonomy/cwe.yaml", True, f"{len(cwe_checks)} LLM checks"))
except Exception as e:
    checks.append(("config/taxonomy/cwe.yaml", False, str(e)))

from security_review import MODULE_ROOT
for prompt_file in ("triage.md", "config_review.md"):
    p = MODULE_ROOT / "config" / "prompts" / prompt_file
    checks.append((f"config/prompts/{prompt_file}", p.exists(), "" if p.exists() else "missing"))

if cfg is not None:
    from security_review.budget import pricing_entry_exists
    for m in filter(None, {cfg.llm.provider_model, cfg.llm.triage_model}):
        ok = pricing_entry_exists(m)
        checks.append((f"pricing: {m}", ok, "" if ok else "no entry in config/pricing.yaml"))

for label, ok, detail in checks:
    mark = click.style("  [+]", fg="green") if ok else click.style("  [!]", fg="red")
    click.echo(f"{mark} {label:<44} {detail}")
    if not ok:
        all_ok = False
```

Keep the existing summary/exit logic; the final message becomes `"Environment healthy."` / `"Problems found — see above."` with exit 1 on failure. Wrap each check group so one failure doesn't abort the command (the try/excepts above do this — every `except` records the failure, satisfying rule 002.7 via the rendered output; still add `logger.warning("health.check_failed", check=label, error=str(e))` inside each except).

**9.3 Auth presence (no subprocess):** if `cfg` loaded, inspect the provider prefix of `cfg.llm.provider_model`: for `anthropic`/`openai`, check the corresponding key exists via the same mechanism `model_providers.resolve_api_key` uses — **do not** call `resolve_api_key` if it raises on absence; instead `import os` is forbidden-ish (003.5 bans `os.getenv` with defaults — plain `os.environ.get("ANTHROPIC_API_KEY")` without a default is allowed; verify rule 003.5's pattern matches only calls *with* a fallback string — it does: `os\.(getenv|environ\.get)\s*\(.+,\s*['\"]`). For `copilot`, check `shutil.which("gh") is not None` with detail `"gh CLI present (run 'gh auth status' to verify login)"`. For `claude`, check the `claude-agent-sdk` import succeeds. Render as `auth: <provider>` rows in the same checks list.

### Tests

- `tests/unit/test_health_check.py`: `CliRunner().invoke(cli, ["health-check"])` on the repo exits 0 and output contains `config/taxonomy/cwe.yaml` and `pricing:`. (Binaries exist in dev env; if this is fragile in CI, monkeypatch `shutil.which` to return a path.)

### Acceptance criteria

1. `python scar.py health-check` shows Tool + Configuration sections, exit 0 on this machine.
2. Temporarily `mv config/pricing.yaml config/pricing.yaml.bak` → health-check exits 1 with a red pricing row (restore the file!).
3. Suite + rules green.

---

## 10. WP9 — Inventory: pruned walk + `--exclude`/`--include`

### Problem

`_walk_files` (`passes/inventory.py:177-203`) uses `root.rglob("*")` — it *enumerates* every entry inside `.git`, `node_modules`, `venv` and filters afterwards (a 300k-file node_modules is walked in full). `"*.egg-info"` in `EXCLUDE_DIRS` (line 20) is dead — the set is matched by exact `part in EXCLUDE_DIRS`, never globbed. `_compute_security_weight` (line 239) reads entire files to use 4KB. There is no operator-facing exclude/include control — excluding a vendored tree means editing source.

### Changes

**10.1 `passes/inventory.py`:**

- Replace `_walk_files` with an `os.walk`-based implementation that prunes directories in-place and applies user globs (relative POSIX paths, `fnmatch`):

```python
def _walk_files(root: Path, max_size: int,
                exclude: tuple[str, ...] = (), include: tuple[str, ...] = ()) -> list[Path]:
    """Walk the tree with directory pruning and optional user glob filters.

    exclude: fnmatch globs on the relative POSIX path — matching files skipped,
             matching directory names pruned (never descended).
    include: when non-empty, only files whose relative path matches at least
             one glob are kept (applied after exclude).
    """
    import fnmatch
    import os

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDE_DIRS
            and not d.endswith(".egg-info")
            and not any(fnmatch.fnmatch(f"{rel_dir}/{d}".lstrip("./"), pat) or fnmatch.fnmatch(d, pat)
                        for pat in exclude)
        ]
        for name in filenames:
            if any(p.search(name) for p in _EXCLUDE_FILE_PATTERNS):
                continue
            rel = f"{rel_dir}/{name}".lstrip("./") if rel_dir != "." else name
            if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
                continue
            if include and not any(fnmatch.fnmatch(rel, pat) for pat in include):
                continue
            item = Path(dirpath) / name
            try:
                if item.stat().st_size > max_size:
                    continue
            except OSError as e:
                logger.debug("inventory.stat_failed", path=str(item), error=str(e))
                continue
            files.append(item)
    return files
```

  Remove `"*.egg-info"` from `EXCLUDE_DIRS` (the `endswith` handles it).
- `discover_files(target_path, max_size, exclude=(), include=())` — forward to `_walk_files`. Keep defaults so existing callers (`cli/test_cwe.py` — verify with `rg "discover_files" src/ scripts/ tests/`) are unaffected.
- `run_inventory`: pass `exclude=tuple(state.config.review.exclude)`, `include=tuple(state.config.review.include)`.
- `_compute_security_weight` line 239: replace the full read with a bounded read:

```python
with open(file_path, encoding="utf-8", errors="replace") as f:
    content = f.read(4096)
```

**10.2 `config_schema.py` — `ReviewConfig`:** add:

```python
exclude: list[str] = Field(default_factory=list,
                           description="fnmatch globs (relative paths) to exclude from inventory")
include: list[str] = Field(default_factory=list,
                           description="when non-empty, only matching relative paths are reviewed")
```

(Empty-list default is an allowed optional-collection default — it disables the filter, it does not invent behavior.)

**10.3 `config/settings/security_review.yaml`:** under `review:` add `exclude: []` and `include: []`, and document both keys in the commented header block (rule 003.3).

**10.4 `cli/review.py`:** add repeatable options and thread them into overrides:

```python
@click.option("--exclude", "exclude", multiple=True,
              help="Glob (relative path) to exclude, repeatable. e.g. --exclude 'third_party/*'")
@click.option("--include", "include", multiple=True,
              help="Restrict review to matching globs, repeatable.")
```

and in the overrides block: `if exclude: overrides.setdefault("review", {})["exclude"] = list(exclude)` (same for include).

### Tests (`tests/unit/test_inventory_walk.py`)

Fabricate under `tmp_path`: `src/app.py`, `node_modules/dep/index.js`, `pkg.egg-info/x.py`, `vendor/lib.py`. Assert: default walk returns only `src/app.py` and `vendor/lib.py`; `exclude=("vendor/*",)` drops `vendor/lib.py`; `include=("src/*",)` returns only `src/app.py`; node_modules and egg-info never appear. Plus: a file > `max_size` is skipped.

### Acceptance criteria

1. `python scar.py review --target . --mode sast --exclude 'eval/*' --quiet` completes and the SARIF contains no `eval/` URIs (spot-check with `python - <<'EOF'` … or jq).
2. Suite + rules green.

---

## 11. WP10 — reports guards + prune + salvaged status

### Problem

`reports --compare` treats a missing SARIF as an empty finding-set (`cli/reports.py:107-110`) — comparing against a crashed run reports every finding as "only in" the good run. `var/output` grows forever with no prune. After WP3, salvaged runs have a `security-report.md` and would display as green `complete` — misleading.

### Changes — `cli/reports.py`

- In `load_findings`, replace the silent `return set()` with a hard stop:

```python
if not sarif_path.exists():
    click.echo(f"Run {run_dir.name.split('-')[-1]} has no SARIF (incomplete run) — cannot compare.", err=True)
    raise SystemExit(1)
```

- Status column: a run whose `triage.json` contains a `run_aborted` degradation renders `salvaged` in yellow. In the listing loop (lines 54-68), when `security-report.md` exists, additionally read `triage.json` and determine `any(d.get("kind") == "run_aborted" for d in data.get("degradations", []))`. Add `from security_review.logging import get_logger` + module-level `logger = get_logger(__name__)` to `cli/reports.py`; guard the read with `except (OSError, ValueError, KeyError) as e: logger.warning("reports.triage_json_unreadable", run=run_dir.name, error=str(e))` and treat the run as `complete` (rule 002.7 requires the log call — do not use a bare pass or click.echo).
- Add `--prune-incomplete` flag: deletes run directories that have **no** `security-report.md`, after `click.confirm(f"Delete {n} incomplete run dir(s) under var/output?")` (add `--yes` flag to skip confirmation). Use `shutil.rmtree`. Print each deleted dir name.

### Tests (`tests/unit/test_reports_cmd.py`)

With `CliRunner` and a fabricated `var/output` under `tmp_path` (monkeypatch `PROJECT_ROOT` in `security_review.cli.reports` namespace): one complete run (md+sarif), one salvaged (md + triage.json with run_aborted), one incomplete (empty dir). Assert: listing shows `complete`/`salvaged`/`incomplete`; `--compare` against the incomplete run exits 1; `--prune-incomplete --yes` removes only the empty dir.

### Acceptance criteria

1. `python scar.py reports` on this repo shows the WP3-salvaged test run as `salvaged`.
2. `python scar.py reports --prune-incomplete --yes` removes the orphaned `2026-07-05-scar-78430f83` dir (it is empty) and leaves complete runs.
3. Suite + rules green.

---

## 12. WP11 — Documentation truth pass + CI workflow

Every edit below corrects a doc that actively lies to operators or maintainers. Make exactly these changes.

**12.1 `docs/03-principles/01-project-principles.md` — P11 section (lines ~187-197):** replace the P11 body with:

> **Budget enforcement is two-layer.** PydanticAI's `UsageLimits` caps each individual call (request count, per-call tokens). Cumulative USD enforcement across the run is implemented by `CostTracker.would_exceed_budget()` in `budget.py`, checked before every batch in triage, holistic, and config review. `max_budget_usd` in config **is enforced** — when cumulative spend reaches it, remaining batches are skipped and a `budget_exhausted` degradation is recorded and rendered in every report. Overshoot is bounded by one in-flight batch (`llm.concurrency` calls). `CostTracker.record()` also logs each call for the `triage.json` audit trail.

Keep the P11 heading. Update the three "This means" bullets to match (UsageLimits per call; `would_exceed_budget` before each batch; `--budget 0` = unlimited).

**12.2 `docs/05-standards/03-error-codes.md`:**

- Replace both occurrences of `security-review doctor` with `python scar.py health-check` (also fix the same stale command in `docs/05-standards/02-testing-standards.md` line ~179).
- Add rows (SYS table): `SYS_CWE_NOT_FOUND` (ConfigurationError — requested CWE not in taxonomy), `SYS_SECRET_MISSING` (ConfigurationError — required API key absent; resolution: set it in config/.env), `SYS_DEPENDENCY_MISSING` (ConfigurationError — required Python package absent), `SYS_TARGET_NOT_FOUND` (ConfigurationError — --target path does not exist).
- Delete rows for codes that are never raised anywhere (`rg 'code="' src/security_review/ -o | sort -u` is your ground truth) **except** `LLM_AUTH_FAILED` (now raised by preflight, WP4). Expected deletions: `SCAN_TOOL_TIMEOUT`, `SCAN_TOOL_NOT_FOUND`, `SCAN_OUTPUT_MISSING`, `SARIF_VERSION_INVALID`, `LLM_OUTPUT_INVALID`, `LLM_BUDGET_EXCEEDED`, `LLM_PROVIDER_ERROR`, `SYS_CONFIG_MISSING`, `SYS_PROMPT_MISSING`, `SYS_CWE_REGISTRY_MISSING` — verify each against the grep before deleting; if a code IS raised, keep it.

**12.3 `docs/01-architecture/001-system-architecture.md`:** fix the directory layout block (lines ~23-41): `taxonomy/` → `config/taxonomy/`, `rules/` → `config/rules/`, `corpus/` → `eval/`, add `config/golden/`. Fix the layer-1 list if it references `cli.py` as a file (it is `cli/`).

**12.4 `docs/05-standards/02-testing-standards.md`:** fix the directory tree (lines ~11-33): `corpus/runner.py` → `eval/runner.py` (verify actual name with `ls tests/eval/`), add `regression/`, correct `test_gitleaks_scan.py` → the actual filename (`ls tests/integration/`).

**12.5 `README.md`:**

- Setup section: add a `### Provider credentials` subsection documenting `config/.env` (keys `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`), that it is gitignored, and `cp config/.env.example config/.env` as the bootstrap step.
- All review options table: `--budget FLOAT` description → "Max LLM spend in USD (0 = unlimited)". Add rows for `--fail-on`, `--fail-on-degraded`, `--no-preflight`, `--exclude`, `--include`.
- Add an `### Exit codes` subsection under "Running a Security Review" with the WP5 contract table.
- Provider table (~line 424): add the `codex` row (`codex` / ChatGPT Plus OAuth / $0 / `codex` CLI auth).
- Pipeline modes table: the `sast` row's "CI gating" claim now points at `--fail-on` (mention it).

**12.6 New file `config/.env.example`:**

```bash
# Copy to config/.env and fill in only the providers you use.
# copilot: and claude: providers authenticate via OAuth (gh auth login / claude setup-token) — no keys here.
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
```

Verify `config/.env` stays gitignored and `.env.example` is NOT ignored (check `.gitignore` — if its pattern is bare `.env`, `.env.example` is safe; if it's `.env*`, add `!config/.env.example`).

**12.7 `config/settings/security_review.yaml`:** remove the false sentence "Per-provider overrides available under providers.<name>.temperature below." (line ~66) — `ProviderConfig` has no temperature field. Change `concurrency: 1` → `concurrency: 2` with comment `# Effective parallelism = min(this, providers.<name>.max_concurrent).` Add a comment on `session_timeout`/`backoff_seconds` noting they are currently honored by the copilot adapter only.

**12.8 New file `.github/workflows/ci.yml`:**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e '.[dev]'
      - run: python scripts/check_rules.py --all
      - run: pytest tests/unit/ -v
```

(Confirm the `[dev]` extra exists in `pyproject.toml` and includes pytest + pydantic-ai; if the unit suite needs `[all]`, use `[all]`.)

### Acceptance criteria

1. `rg "security-review doctor" docs/` → no hits. `rg "rules/opengrep" README.md docs/01-architecture/` → only `config/rules/opengrep` forms.
2. `python scripts/check_rules.py --all` green (rule 004.7 etc. unaffected).
3. `config/.env.example` exists; `git check-ignore config/.env.example` exits 1 (not ignored).

---

## 13. Global verification protocol (run at the end, in order)

```bash
pip install -e '.[all]'
python -c "import security_review; print(security_review.__file__)"   # this checkout
python scripts/check_rules.py --all                                   # zero violations
pytest tests/unit/ -v                                                  # all green
python scar.py --version                                              # prints version
python scar.py health-check                                            # tools + config sections, exit 0
python scar.py review --target eval/python --mode sast                 # clean run: Coverage Gaps: 0, executionSuccessful true
python scar.py review --target eval/python --mode sast --fail-on elevated --quiet; echo "exit=$?"   # exit=3
env PATH="$(dirname $(which python)):/usr/bin:/bin" python scar.py review --target eval/python --mode sast
                                                                       # degraded run: red panel, gaps in md, executionSuccessful false
python scar.py reports                                                 # statuses incl. salvaged/incomplete
# SIGINT salvage (manual): start `python scar.py review --target . --mode sast`, Ctrl-C during Pass 2,
# confirm "Partial results salvaged" + run dir contains run.json/events.jsonl/triage.json with run_aborted.
```

Do NOT run `--mode full`, `test-cwe`, `test-providers`, `eval`, or any `scripts/benchmark_*` as part of verification — they make real LLM calls. The preflight probe is likewise excluded from automated verification (unit tests cover it with TestModel/FunctionModel).

**Definition of done:** every WP's acceptance criteria met; both checkers green; no `rg "tool_results" src/` hits; no `rg "SCAR v1.0.0" src/` hits; `git log` shows one commit per WP on `ops-readiness-018`. Do not push or open a PR — stop after the final commit and report results per WP.
