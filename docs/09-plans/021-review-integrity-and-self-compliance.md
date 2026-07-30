# Plan 021 — Review Integrity & Self-Compliance Remediation

**Status:** Ready for implementation
**Date:** 2026-07-25
**Source:** Full-context architecture, enforcement-chain, and operability review of 2026-07-25. Every finding below was verified against the code line-by-line (file:line evidence inline). Baseline: all gates green — 31/31 rules, 471 unit tests, 20 integration tests, `health-check` clean.
**Depends on:** none. Plans 018/019/020/014/010 are already merged to main (HEAD `4708336` at time of writing).
**Baseline environment:** `python` is Python 3.12 (anaconda, already on PATH — no `conda activate` needed); installed `pydantic-ai` is **1.63.0**; all 8 SAST tools installed.

---

## 0. Purpose and context

This plan fixes **silent-integrity defects** in the review pipeline (a security scanner must never report "clean" for work it did not do), removes SCAR's undocumented writes into the repositories it scans, repairs a measurement bug in the quality scorer, and closes self-compliance gaps (SCAR violating its own rules in files its own rule-checker does not scan).

It deliberately does **not** include large refactors (see §0.4) — behaviour fixes and refactors must not ride in the same change set.

### 0.1 Mandatory reading before writing any code

1. `AGENTS.md` — the Critical Rules section is binding.
2. `docs/03-principles/01-project-principles.md` — especially P6 (fail fast/loud), P13 (never trust LLM-echoed identifiers), P11 (budget), P14 (pre-materialized context).
3. `docs/05-standards/01-python-coding-standards.md` and `02-testing-standards.md`.
4. `src/security_review/models/degradation.py` — the degradation model this plan extends. Its docstring is the contract: *"Every event that silently reduced coverage or fidelity must be recorded as a Degradation and rendered in every report format."*
5. `docs/09-plans/019-invariant-debt-remediation.md` §0 — the house style for how work packages here are written and committed (this plan follows it).

### 0.2 Binding constraints (recap — violations will fail review)

- Fail fast, fail loud. No silent fallbacks, no hidden defaults, no fallback values in `except` blocks.
- Absolute imports only. `from security_review.logging import get_logger` for logging inside `src/security_review/` (code_analysis/code_quality use `structlog.get_logger()` directly — that is their established pattern, keep it).
- Only `src/security_review/tools/runner.py` executes subprocesses. Never `shell=True`.
- No hardcoded model strings, pricing, or config values in code.
- Every `except` block logs at WARNING+ or re-raises. No new bare/broad swallows.
- One work package = one commit, message format `P021-<letter>: <imperative summary>`. The commit-msg hook prepends a timestamp and strips Co-authored-by lines — let it.
- **Never commit broken code.** Before every commit: `python scripts/check_rules.py --all && pytest tests/unit/ -q` must both pass.
- Do not touch: `eval/` corpus, `config/prompts/*.md` content, `config/taxonomy/`, provider adapter internals (`copilot_model.py`, `claude_model.py`, `codex_model.py`) except where a WP explicitly says so.
- No time estimates anywhere.
- Line numbers in this plan are anchors from HEAD `4708336` (+ the WP-0 edits). **Re-locate by content before editing** — do not apply blind offsets.

### 0.3 Prerequisites (verbatim, in order)

```bash
cd <repo-root>   # contains .project_root
git status --short
```

**Case 1 — the following four files show as modified** (Herman's in-flight rule-scope widening):
`scripts/check_rules.py`, `scripts/code_map.py`, `scripts/code_quality.py`, `src/code_analysis/__init__.py`

```bash
python scripts/check_rules.py --all      # must print: All 31 rule(s) passed across 102 files.
pytest tests/unit/ -q                    # must be green (471 passed at baseline)
git add scripts/check_rules.py scripts/code_map.py scripts/code_quality.py src/code_analysis/__init__.py
git commit -m "P021-0: widen rule-checker file discovery to all of src/"
```

**Case 2 — working tree is clean:** verify the widening is already committed:
`grep -n 'SRC_DIR = PROJECT_ROOT / "src"' scripts/check_rules.py` must match. If it does not: **STOP** and report — the baseline this plan was written against is absent.

Then:

```bash
git checkout -b review-integrity-021
python scar.py health-check              # must end: Environment healthy.
pytest tests/integration/ -q             # must be green (20 passed at baseline)
```

If any prerequisite fails: **STOP. Do not improvise.** Report the failure.

### 0.4 Out of scope — do NOT do these

Deferred to a future plan (do not start them, do not "improve while you're in there"):

1. **Consolidating `scripts/code_intel.py` / `scripts/code_map.py`** into `src/code_analysis` (large refactor; rule 002.1 stays src-scoped until then — WP-H documents this).
2. **Extracting a shared base class** for the three provider `Model` adapters. SDK-sensitive; requires A/B benchmarking per ADR-001 before touching.
3. **Splitting `merge.write_artifacts` / `holistic.run_holistic`** monoliths (pure refactor).
4. **Run lockfile / orphaned-run detection** (needs design).

Reviewed and **deliberately retained as-is** (documented decisions — do not "fix" these):

5. `TRIAGE_FORMAT_MARKDOWN` / `HOLISTIC_FORMAT_MARKDOWN` / `CONFIG_FORMAT_JSON` stay in `src/security_review/model_capabilities.py`. They are output-contract text coupled to `output_parser.py` regexes; making them config-editable would invite silent parse breakage. WP-C adds a comment documenting this exemption from P5.
6. The markdown parser's `severity = "MEDIUM"` default (`output_parser.py:225`) stays — documented "auto-repair, not reject" policy (architecture overview, Key Design Decision 3).
7. `fingerprint_and_track_findings` failure (`passes/merge.py:72-73`) stays WARNING-log-only — it is cross-run telemetry with zero impact on the current run's coverage or report. WP-C adds a comment stating this decision.

---

## 1. Work packages — summary and order

Implement strictly in this order. Letters = commits.

| WP | Theme | Files (primary) |
|----|-------|-----------------|
| 0 | Commit in-flight rule-scope widening (prereq, §0.3) | scripts/check_rules.py et al. |
| A | Holistic empty-response false-clean fix | passes/holistic.py, tests |
| B | Holistic file-path validation + SARIF location integrity | passes/holistic.py, passes/merge.py, models/degradation.py, tests |
| C | Silent failure paths become operator-visible | passes/pipeline.py, cli/review.py, models/degradation.py, model_capabilities.py, passes/merge.py |
| D | SCAR never writes into the target repo | code_analysis/store.py, call_graph_csharp.py, passes/pipeline.py, passes/merge.py, tests |
| E | Quality scorer: one file-set resolution for AST + tools | code_quality/score.py, code_quality/tools.py, tests |
| F | Single PQI implementation (delete the duplicate) | scripts/code_quality.py (delete), .githooks/pre-commit, README |
| G | setup.py: remove shell=True | setup.py |
| H | Rule-checker scopes: subprocess chokepoint, init-minimal, documented exemptions | scripts/check_rules.py, code_quality/tools.py, code_analysis/__init__.py + new analysis.py, docs/04-rules/*.jsonl |
| I | pydantic-ai exact pin + deprecated-API migration + limiter reset hook | requirements.txt, pyproject.toml, 6 source files, providers.py |
| J | Documentation drift | README.md, docs/09-plans/010 & 014 headers, CHANGELOG.md |

WP-A/B/C are the point of this plan. If you run out of budget, stop cleanly after any WP boundary — never mid-WP.

---

## 2. WP-A — Holistic empty-response false-clean (Pass 4 integrity)

### Problem

`parse_holistic_response()` returns `None` **only** when the response text is empty/whitespace (`output_parser.py:206` — every non-empty-unparseable response returns an empty result with `review_notes` set, `output_parser.py:198-204`). In `run_single_check` (`passes/holistic.py:416-418`) that `None` is replaced with `HolisticReviewResult(findings=[], files_reviewed=included)` — whose `review_notes` defaults to `None` — so the guard

```python
parse_failed = not review_result.findings and review_result.review_notes is not None   # holistic.py:428
```

evaluates **False**. `_classify_result` then returns `COMPLETED` ("LLM explicitly found no issues", `holistic.py:92-94`), the check counts as covered, and **no degradation is recorded**. A CWE check the model never answered is indistinguishable from a verified-clean check. Empty responses are a real, documented provider behaviour (TODO.md: copilot "returns 0 findings intermittently"; `RetryingModel` retries empties 5× but returns the empty response on exhaustion, by design — `retry_model.py`).

The correct pattern already exists in this codebase: `passes/config_review.py:134-140` records a `parse_failed` degradation stating the files were **NOT** reviewed.

### Changes

**A.1** In `run_single_check` (`passes/holistic.py`, currently lines ~412-428), replace the output-normalisation block so an empty response is flagged as a parse failure:

```python
    output = result.output
    empty_response = False
    if isinstance(output, HolisticReviewResult):
        review_result = output.model_copy(update={"files_reviewed": included})
    else:
        review_result = parse_holistic_response(output, files_reviewed=included)
        if review_result is None:
            # parse_holistic_response returns None ONLY for an empty/whitespace
            # response — the model never answered this check. Flag it as a
            # parse failure so _classify_result routes it to RETRY and, if it
            # persists, a check_failed degradation ("NOT assessed"). It must
            # never be recorded as a clean COMPLETED check.
            empty_response = True
            logger.warning(
                "holistic.empty_response",
                cwe_id=check.cwe_id,
                files_in_prompt=len(included),
            )
            review_result = HolisticReviewResult(findings=[], files_reviewed=included)
```

and replace the `parse_failed` computation (and its two-line comment above it, currently ~426-428):

```python
    # parse_failed=True when the response was empty (never answered) or when
    # the LLM gave a non-empty response we could extract nothing from
    # (review_notes is set by the parser exactly in that second case).
    parse_failed = empty_response or (
        not review_result.findings and review_result.review_notes is not None
    )
```

No other logic changes. The existing machinery already does the right thing from here: first pass → `_Outcome.RETRY` (`holistic.py:84-90`) → sequential retry → on second failure → `check_failed` degradation "CWE-NNN … was NOT assessed" (`holistic.py:280-285`).

**A.2** Update the `_Outcome.COMPLETED` docstring comment (`holistic.py:47`) to: `# findings extracted, or the LLM explicitly answered "no findings"` (it must not imply empty responses land here).

### Tests

New file `tests/unit/test_holistic_empty_response.py`, following the fixture pattern of `tests/unit/test_overflow.py` (PipelineState + `FunctionModel` + `ModelProfile`; `ALLOW_MODEL_REQUESTS=False` comes from conftest):

1. `test_parse_holistic_response_empty_returns_none` — `parse_holistic_response("", files_reviewed=["a.py"]) is None` and same for `"   \n\t"`. (Put in `tests/unit/test_output_parser.py` if an equivalent doesn't already exist — check first.)
2. `test_empty_response_is_parse_failure` — drive `run_holistic` with a `FunctionModel` that always returns `""`: assert `checks_completed` behaviour via state — specifically `state.degradations` contains at least one `kind="check_failed"` entry per runnable check, and **no** check contributed to a clean result (`state.holistic_result` is `None` or has zero findings AND degradations prove non-assessment).
3. `test_no_findings_answer_still_completes_clean` — `FunctionModel` returning `"No findings."`: assert zero degradations of kind `check_failed`/`parse_failed` and the run completes (the legitimate clean path must not regress; `output_parser.py:190-191` handles this phrase).
4. `test_unparseable_nonempty_still_retries` — `FunctionModel` returning `"I looked at the code, seems fine I guess"` (no findings, no "no findings" phrase): unchanged behaviour — `review_notes` set → parse_failed → retry → `check_failed` degradation. Guards against regressing the pre-existing path.

### Acceptance

```bash
pytest tests/unit/test_holistic_empty_response.py -v   # all pass
pytest tests/unit/ -q                                   # green, no regressions
python scripts/check_rules.py --all                     # green
```

Commit: `P021-A: empty holistic response is a parse failure, never a clean check`

---

## 3. WP-B — Holistic file-path validation + SARIF location integrity

### Problem

Holistic findings are the one place an LLM-echoed identifier survives unvalidated (partial P13 gap — holistic is a discovery pass, so the LLM must *name* the file, but we can still *validate* the name against the files we actually put in the prompt). The markdown fallback also defaults `file_path="unknown"` (`output_parser.py:242`), and `merge._finding_to_sarif_result` (`passes/merge.py:339-354`) emits that as a SARIF `artifactLocation.uri: "unknown"` — garbage in the interchange format (P3, rule 004.9 spirit). Note `passes/verify.py:385` already special-cases `file_path == "unknown"` → prompt unbuildable → NEEDS_CONTEXT, so `"unknown"` is the established sentinel — keep it.

### Changes

**B.1** `passes/holistic.py` — add a module-level helper (place near `_classify_result`):

```python
def _resolve_finding_path(raw: str, included: list[str]) -> str:
    """Resolve an LLM-echoed file path against the files actually inlined in
    the prompt (P13: validate echoed identifiers against known-correct data).

    Exact match wins; else a unique suffix match; else a unique basename
    match; else "unknown" (the established sentinel — verify.py maps it to
    NEEDS_CONTEXT and merge omits the SARIF location).
    """
    if not raw or raw == "unknown":
        return "unknown"
    candidate = raw.lstrip("./")
    if candidate in included:
        return candidate
    matches = [p for p in included if p.endswith("/" + candidate) or candidate.endswith("/" + p)]
    if len(matches) == 1:
        return matches[0]
    basename = candidate.rsplit("/", 1)[-1]
    matches = [p for p in included if p.rsplit("/", 1)[-1] == basename]
    if len(matches) == 1:
        return matches[0]
    return "unknown"
```

**B.2** In `run_single_check`, fold path resolution into the existing P13 CWE-stamp `model_copy` block (`holistic.py:420-424`) so there is one normalisation pass:

```python
    # P13: the check's CWE is known bookkeeping — never trust the LLM echo.
    # Same for file paths: resolve them against the files we actually inlined.
    stamped_cwe = f"CWE-{check.cwe_id}"
    review_result = review_result.model_copy(update={
        "findings": [
            f.model_copy(update={
                "cwe_id": stamped_cwe,
                "file_path": _resolve_finding_path(f.file_path, included),
            })
            for f in review_result.findings
        ],
    })
```

Log at WARNING when resolution changed or failed a path (`logger.warning("holistic.finding_path_unresolved", cwe_id=..., raw=...)` for `"unknown"` outcomes; debug for successful non-exact resolutions).

**B.3** `models/degradation.py` — add to `DegradationKind` (keep the comment style):

```python
    "location_unresolved",  # LLM finding had no resolvable file path — SARIF result has no location
```

**B.4** `passes/holistic.py`, in `run_holistic` immediately before the `if all_files_reviewed:` block (~line 287): record one aggregate degradation:

```python
    unresolved = sum(1 for f in all_findings if f.file_path == "unknown")
    if unresolved:
        state.degrade(Degradation(
            pass_name="holistic", kind="location_unresolved", subject="holistic",
            detail=f"{unresolved} finding(s) had no resolvable file path — "
                   f"emitted without a SARIF location; the verify pass treats them as NEEDS_CONTEXT",
            count=unresolved,
        ))
```

(Single aggregation point — do **not** degrade inside `run_single_check`; retried checks would double-count.)

**B.5** `passes/merge.py` `_finding_to_sarif_result` (~339-374): emit no location for unresolved paths. SARIF 2.1.0 `result.locations` is optional.

```python
    result = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": f"{finding.title}: {finding.description}"},
    }
    if finding.file_path and finding.file_path != "unknown":
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path},
                "region": {"startLine": finding.line_number or 1},
            }
        }]
    else:
        result.setdefault("properties", {})["location_unresolved"] = True
```

Two knock-ons in the same function — fix both:
- The CWE-tag block currently does `result["properties"] = {...}` (line ~359) — change to `result.setdefault("properties", {})["tags"] = [...]` so it cannot clobber `location_unresolved`.
- The `end_line` block (~371-372) must be guarded with `if "locations" in result and ...`.

**B.6** Verify (and fix if needed) that every downstream consumer tolerates a location-less result: `sarif/loader.py` `get_result_location` / `get_finding_key`, `merge._score_all_findings`, `reporting/common.extract_report_data`, and dedup in `sarif/merger.py`. `fingerprint_and_track_findings` already skips locationless results (`merge.py:54-56`). Where a consumer indexes `locations[0]` unconditionally, guard it and default to `("", 0)`-style values (loader already has conventions — follow them).

### Tests

Extend `tests/unit/test_output_parser.py` and add `tests/unit/test_finding_location.py`:

1. `_resolve_finding_path` truth table: exact; `"./"`-prefixed; unique suffix (`"auth/login.py"` vs included `"src/auth/login.py"`); unique basename; ambiguous basename → `"unknown"`; absolute-ish echo (`"/repo/src/auth/login.py"` suffix-matches); empty/`"unknown"` passthrough.
2. Merge: a `HolisticFinding` with `file_path="unknown"` → SARIF result has **no** `locations` key, has `properties.location_unresolved == True`, and still carries its CWE tag.
3. Merge: a resolvable finding is byte-identical to today's output (regression guard).
4. Pipeline-level: run_holistic with a `FunctionModel` returning one finding whose `**File:**` line names a file not in the prompt → final state has the `location_unresolved` degradation with `count=1`.

### Acceptance

```bash
pytest tests/unit/ -q && python scripts/check_rules.py --all   # green
```

Commit: `P021-B: validate holistic file paths against prompt contents; no fabricated SARIF locations`

---

## 4. WP-C — Silent failure paths become operator-visible

### Problem

Three failures are log-only (invisible in normal CLI output, no degradation), violating the degradation model's own contract:

1. **Call-graph build failure** — `passes/pipeline.py:84-86` catches *all* exceptions, logs WARNING, returns `(None, None)`; Pass 4 file selection silently downgrades to keyword-only. This fires in practice: pyan3 raises an internal `KeyError` on real codebases (reproduced against SCAR's own source; known limitation from plan 010).
2. **Quality-summary failure** — `cli/review.py:358-360` swallows to a log; the operator just doesn't see the quality panel and doesn't know why.
3. (`fingerprint_and_track_findings` — reviewed; stays log-only per §0.4 item 7. Add the decision comment.)

### Changes

**C.1** `models/degradation.py` — add to `DegradationKind`:

```python
    "call_graph_failed",   # call graph build failed — holistic file selection fell back to keyword-only
```

**C.2** `passes/pipeline.py` `_build_call_graph_if_available` — replace the `except` (currently :84-86). Keep the broad catch (this is an *optional* capability; a graph bug must not kill the review — fail-*visible*, not fail-fatal), but record it:

```python
    except Exception as e:
        logger.warning(
            "pipeline.call_graph_failed",
            error=str(e),
            error_type=type(e).__name__,
        )
        state.degrade(Degradation(
            pass_name="pipeline", kind="call_graph_failed", subject="call_graph",
            detail=f"call graph unavailable ({type(e).__name__}: {str(e)[:120]}) — "
                   f"holistic file selection degraded to keyword-only",
            count=0,
        ))
        return None, None
```

Note: `_build_call_graph_if_available` is only invoked in full mode (`run_pipeline`, ~line 282, inside the `mode == "full"` branch) — verify that remains true so sast-mode runs can't emit this degradation.

**C.3** `cli/review.py` quality-summary `except` (~358-360) — add an operator-visible one-liner (keep the log):

```python
            except Exception as quality_err:
                logger.warning("quality.scoring_failed", error=str(quality_err),
                               error_type=type(quality_err).__name__)
                click.echo(click.style(
                    "  (code quality summary unavailable — see log for details)",
                    fg="yellow"), err=True)
```

**C.4** `passes/merge.py` `fingerprint_and_track_findings` — extend the existing docstring/except with the decision (comment only, no behaviour change): *"Reviewed 2026-07-25 (plan 021): deliberately NOT a Degradation — cross-run telemetry only, no impact on this run's coverage or report."*

**C.5** `src/security_review/model_capabilities.py` — above the three `*_FORMAT_*` constants, add the P5-exemption comment (§0.4 item 5): *"These format blocks are output contracts coupled to output_parser.py's regexes — deliberately code, not config/prompts/ (P5 exemption, plan 021): editing them without updating the parser silently breaks finding extraction."*

### Tests

1. `tests/unit/test_degradations.py` (existing file — extend): construct `Degradation(pass_name="pipeline", kind="call_graph_failed", ...)` validates; renders through `render_degradations_md` (reporting/common) without error.
2. New test in `tests/unit/test_checkpoint.py`-style pipeline harness or a focused unit: monkeypatch `code_analysis.store.GraphStore` (or the analyze step) to raise `KeyError("pyan3 internal")`, call `_build_call_graph_if_available(state)` → returns `(None, None)` AND `state.degradations` contains `kind="call_graph_failed"`.

### Acceptance

```bash
pytest tests/unit/ -q && python scripts/check_rules.py --all
```

Commit: `P021-C: call-graph and quality-summary failures are operator-visible; document retained exemptions`

---

## 5. WP-D — SCAR never writes into the target repo

### Problem

SCAR mutates the repository it scans, undocumented, in three places:

1. `passes/pipeline.py:68-69` — `init_target_gitignore(state.target_path)` + `GraphStore(state.target_path / ".scar" / "graph.db")`
2. `passes/merge.py:48-49` — same pair, during fingerprint tracking (runs in **all** modes)
3. `src/code_analysis/call_graph_csharp.py:55` — writes `<target>/.scar/roslyn-callgraph.json`

`init_target_gitignore` (`code_analysis/store.py:103-109`) creates `.scar/` and a `.gitignore` inside the target. A scanner writing into its subject breaks read-only expectations (CI checkouts, customer repos). Since `.scar/` is gitignored in the target, it never travels with the repo anyway — it is purely a local cache and belongs in SCAR's own `var/`.

### Changes

**D.1** `src/code_analysis/store.py` — **delete** `init_target_gitignore` and add (module needs `import hashlib`; `MODULE_ROOT` imported from `code_analysis` — no cycle: `code_analysis/__init__.py` does not import `store`):

```python
def target_cache_dir(target_root: Path) -> Path:
    """Per-target cache directory under SCAR's own var/cache/graphs/.

    SCAR never writes into the repository it scans (plan 021). The key is
    derived from the resolved target path, so repeat runs against the same
    target reuse the same incremental graph DB.
    """
    key = hashlib.sha256(str(Path(target_root).resolve()).encode("utf-8")).hexdigest()[:16]
    cache_dir = MODULE_ROOT / "var" / "cache" / "graphs" / key
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir
```

**D.2** `passes/pipeline.py` (~:55, :68-69): drop `init_target_gitignore` from the import and call; use
`with GraphStore(target_cache_dir(state.target_path) / "graph.db") as store:`

**D.3** `passes/merge.py` (~:46-49): same substitution.

**D.4** `src/code_analysis/call_graph_csharp.py` (~:55): `output_path = target_cache_dir(root) / "roslyn-callgraph.json"` (import `target_cache_dir` from `code_analysis.store`; keep the existing lazy-import style of that module if applicable).

**D.5** Tests: update every `.scar` reference under `tests/` —
- `tests/unit/test_finding_tracking.py`: line ~54 monkeypatches `code_analysis.store.init_target_gitignore` (which no longer exists) — replace with monkeypatching `code_analysis.store.target_cache_dir` to return `tmp_path`; path assertions move from `tmp_path/.scar/graph.db` to the monkeypatched dir.
- `tests/unit/test_code_analysis/test_store.py` and `test_call_graph_csharp.py`: adjust any `.scar` path construction/assertions; where they exercised `init_target_gitignore`, replace with `target_cache_dir` behaviour tests (key stability: same resolved path → same dir; different paths → different dirs; dir is under `var/cache/graphs/`).
- Grep-gate: `grep -rn '\.scar' src/ tests/` must return **zero** hits after this WP.

**D.6** Do **not** auto-delete pre-existing `.scar/` dirs in previously scanned targets (never delete inside user repos). Note this in the CHANGELOG entry (WP-J).

`var/.gitignore` already ignores everything under subdirectories except `.gitkeep` — `var/cache/graphs/**` needs no gitignore change (verify with `git status` after a test run).

### Tests

As per D.5, plus: `target_cache_dir` unit tests (key determinism, mkdir idempotence).

### Acceptance

```bash
grep -rn '\.scar' src/ tests/ | wc -l    # 0
pytest tests/unit/ -q && python scripts/check_rules.py --all
```

Commit: `P021-D: graph/fingerprint cache lives in var/cache/graphs — never in the scanned repo`

---

## 6. WP-E — Quality scorer: one file-set resolution for AST + tools

### Problem

`score_project` (`src/code_quality/score.py:48-70`) passes the raw `scope`/`exclude` to both `analyze()` and `run_tools()`, but the two resolve `None` differently:

- `analyze` → `collect_files` applies `EXCLUDE_DEFAULTS` when `exclude is None` (`code_analysis/collect.py:50`, defaults at :13-26 — `.venv/`, `__pycache__/`, `obj/`, `bin/`, …).
- `BanditRunner.run` (`code_quality/tools.py:48-64`) receives `exclude=None` → **forwards no excludes at all** and, with `scope=None`, scans the whole root (`:54-55`).

Consequence: bandit scores files the AST dimensions never measured. Against a target with a `.venv/` (or SCAR itself: `setup.py`, `scripts/`, the deliberately-vulnerable `eval/` corpus), the security dimension is polluted by out-of-scope findings — the composite CQI is not measuring one codebase. (Empirically: quality.json reported 2 HIGH bandit findings; `bandit -r src` reports 0.)

### Changes

**E.1** `src/code_quality/score.py` — resolve once, use everywhere:

```python
from code_analysis.collect import EXCLUDE_DEFAULTS
...
    effective_exclude = list(exclude) if exclude is not None else list(EXCLUDE_DEFAULTS)

    metrics = analyze(
        target, scope=scope, exclude=effective_exclude,
        languages=languages, include_graph=include_graph,
    )
    ...
    tool_results = run_tools(tools, target, scope, effective_exclude) if tools else {}
```

**E.2** `src/code_quality/tools.py` `BanditRunner.run` — add a comment where non-directory patterns are dropped (`:57-64`): bandit only accepts directory excludes; glob patterns like `*.g.cs` are irrelevant to a Python-only scanner. No behaviour change beyond receiving real excludes now. Apply the same reading to `RadonRunner` (`:124+`) — it receives the same resolved list; verify it doesn't silently diverge for `scope=None` (it builds targets from root the same way — acceptable once excludes align; fix only if it ignores `exclude` entirely).

**E.3** Known/intended asymmetry to document in `score_security`'s docstring: test files are excluded from the AST *source* counts (`code_analysis` classification) but bandit still scans them (minus the `B101` assert-noise filter, `tools.py:40`) — bandit findings in tests are real signal.

### Tests

New `tests/unit/test_code_quality/test_scope_alignment.py`:

1. Monkeypatch-capture the args `BanditRunner.run` builds (patch `code_quality.tools._run_command` to record `args` and return `('{"results":[],"metrics":{}}', "", 0)`): `score_project(target, tools=["bandit"], exclude=None)` → the bandit invocation includes `--exclude` entries derived from `EXCLUDE_DEFAULTS` **iff** those dirs exist under the tmp target (create `tmp/.venv/x.py` to force it).
2. End-to-end guard (integration, `tests/integration/test_quality_scope.py`, `@pytest.mark.skipif(not shutil.which("bandit"), ...)`): tmp tree with `src/clean.py` (benign) and `.venv/evil.py` containing `import subprocess; subprocess.run("ls", shell=True)` → `score_project(tmp, tools=["bandit"])` security dimension shows **zero** HIGH findings.

### Acceptance

```bash
pytest tests/unit/ -q && pytest tests/integration/ -q && python scripts/check_rules.py --all
python scar.py quality --target . --scope src --json | python -c "import json,sys; d=json.load(sys.stdin); print(d['dimensions']['security'])"
# ^ must show no HIGH-severity bandit sub-score penalty sourced from setup.py/eval (src-only now)
```

Commit: `P021-E: bandit/radon score exactly the file set the AST dimensions measure`

---

## 7. WP-F — Single PQI implementation

### Problem

Two live PQI scorers exist and have already diverged: `scripts/code_quality.py` (1,067 lines, standalone — run by `.githooks/pre-commit` with `--no-bandit --no-radon`) and the `src/code_quality/` package (run by `scar.py quality`). Both define `score_maintainability` / `score_security` / `score_modularity` / … Two scorers guarantee the hook's `quality.json` and the CLI's output disagree.

### Changes

**F.1** Delete `scripts/code_quality.py`.

**F.2** `.githooks/pre-commit` — replace the quality line:

```bash
python scar.py quality --target . --scope src --no-tools --output .codemap/quality.json
```

(`--no-tools` preserves the old hook's fast AST-only behaviour — the old flags were `--no-bandit --no-radon`. `quality_cmd` already supports `--scope`, `--no-tools`, `--output` — see `src/security_review/cli/quality_cmd.py`.)

**F.3** Grep and rewire every reference: `grep -rn "scripts/code_quality" README.md docs/ AGENTS.md setup.py .githooks/` — update README's "Code Quality Scoring" section and any doc that names the script; historical mentions inside `docs/09-plans/` stay as-is (history).

**F.4** Verify the JSON written by `scar.py quality --output` carries the same top-level shape consumers expect (`composite`, `quality_band`, `dimensions`, `floor_penalty`, `file_count`, `line_count`) — it is an internal artifact; a changed sub-score set is acceptable, a missing top-level key is not.

### Tests

None new — the deletion is the fix. Acceptance exercises the hook path.

### Acceptance

```bash
test ! -f scripts/code_quality.py
python scar.py quality --target . --scope src --no-tools --output /tmp/q.json && python -c "import json; d=json.load(open('/tmp/q.json')); assert 'composite' in d and 'dimensions' in d"
python scripts/check_rules.py --all && pytest tests/unit/ -q
# Fire the hook for real: make a scratch whitespace commit on the branch and confirm the pre-commit hook succeeds end-to-end, then amend/undo it.
```

Commit: `P021-F: single PQI implementation — hook uses scar.py quality; delete scripts/code_quality.py`

---

## 8. WP-G — setup.py: remove shell=True

### Problem

`setup.py:807` runs fix commands with `subprocess.run(cmd, shell=True, …)` — bandit B602 HIGH, and the repo's own cardinal rule ("Never use shell=True", AGENTS.md rule 1 / rule 001.5) violated in its onboarding entry point. Current `fix_cmd` values (grep `fix_cmd=` in setup.py) are mostly plain commands (`brew install …`, `git config …`, `gh auth login`, `pip install …`), but a few are *instructions*, not commands (`export OPENAI_API_KEY='sk-...'` — which does nothing useful in a child process anyway — and `"See https://cli.github.com/"`).

### Changes

**G.1** In the fix-runner (setup.py ~:800-812), replace the `shell=True` branch:

```python
import shlex  # top of file with the other imports

_SHELL_META = ("&&", "||", "|", ";", ">", "<", "$", "`")

...
                if is_pip_cmd:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                else:
                    if cmd.startswith(("export ", "See ")) or any(m in cmd for m in _SHELL_META):
                        # An instruction for the operator, not an executable command.
                        print(f"  {_C.YELLOW}Manual step — run yourself: {cmd}{_C.RESET}")
                        continue
                    result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=300)
```

(Adapt the skip-accounting to the surrounding loop's counters — inspect the actual loop before editing; `continue` must not corrupt the fixed/failed tally. Match the file's existing `_C` colour constants.)

**G.2** Manually verify each current `fix_cmd` still behaves: every `brew/go/git/gh/pip install` string round-trips through `shlex.split` identically; the `export`/`See` entries become manual-step prints (an improvement — under `shell=True` they were no-ops that reported success).

### Tests

setup.py has no unit-test harness (operator tool) — acceptance is static + bandit:

```bash
bandit setup.py -q -f json | python -c "import json,sys; d=json.load(sys.stdin); assert not [r for r in d['results'] if r['issue_severity']=='HIGH'], d['results']"
grep -n "shell=True" setup.py | wc -l    # 0
python setup.py --check                  # still runs and reports (exit code may be 0 or 1 depending on machine state — it must not crash)
```

Commit: `P021-G: setup.py fix commands run without shell=True; instruction-style fixes become manual steps`

---

## 9. WP-H — Rule-checker scopes: subprocess chokepoint, init-minimal, documented exemptions

### Problem

After WP-0, file discovery covers all of `src/`, but seven rules still filter on `src/security_review/` internally. Two of those scopes now hide real drift:

- **001.4 subprocess isolation** (`check_subprocess_isolation`, `scripts/check_rules.py:90-119`): `src/code_quality/tools.py:24` calls `subprocess.run` directly, while `src/code_analysis/call_graph_csharp.py:45` voluntarily routes through `security_review.tools.runner.run_tool_sync` (with a docstring explaining why). One question, two answers.
- **001.3 init minimal** (`check_init_minimal`, :74-88): `src/code_analysis/__init__.py` is ~182 lines and contains the public `analyze()` implementation — logic in `__init__` (violates the repo standard; passes only because the rule is scoped).

The remaining five scoped rules are legitimately package-specific but say so nowhere.

### Changes

**H.1** `src/code_quality/tools.py` — route `_run_command` through the chokepoint, mirroring `call_graph_csharp.py`'s documented pattern (lazy import to avoid any import-order surprises):

```python
def _run_command(args: list[str], cwd: Path, timeout: int = 120) -> tuple[str, str, int]:
    """Run a tool. Routes through security_review.tools.runner.run_tool_sync —
    the repo's single subprocess chokepoint (AGENTS.md rule 1) — rather than
    calling subprocess directly.
    """
    from security_review.tools.runner import run_tool_sync

    proc = run_tool_sync(args, timeout_seconds=timeout, cwd=str(cwd))
    return proc.stdout, proc.stderr, proc.returncode
```

(Verify `run_tool_sync`'s exact signature/return in `src/security_review/tools/runner.py:~721` region first and adapt; preserve `_run_command`'s current return contract so `BanditRunner`/`RadonRunner` need no changes.)

**H.2** `scripts/check_rules.py` `check_subprocess_isolation` — widen scope to `src/` (change the `startswith("src/security_review/")` guard to `startswith("src/")`), keeping the existing exemptions (`tools/runner.py` suffix, `"/cli/"`). Confirm `src/code_analysis/parsers/python.py` does not false-positive (it compares AST attribute names to the *string* `"subprocess"` — the rule's regexes require `subprocess.` followed by `run|call|Popen|check_output`, which that file does not contain — verify by running the checker).

**H.3** Slim `src/code_analysis/__init__.py`: move `analyze()` and `_is_test_file()` verbatim into a new `src/code_analysis/analysis.py` (module docstring: "Project-level analysis orchestration — main `analyze()` entry point."), keep `MODULE_ROOT`/`_find_project_root`/parser-registration/imports in `__init__.py`, and re-export `analyze` from `__init__` so `from code_analysis import analyze` keeps working everywhere (`code_quality/score.py:6` etc. — zero caller changes). Then widen `check_init_minimal`'s scope guard to `src/`.

**H.4** Document the deliberately scoped rules — in `scripts/check_rules.py` docstrings AND the matching entries in `docs/04-rules/001_module_boundaries.jsonl` / `002_code_patterns.jsonl` / `003_configuration.jsonl` / `004_findings_and_sarif.jsonl` (`scope` field), state scope + reason:

- 001.2 `check_direct_logging` — security_review only: `get_logger()` is a security_review facility; code_analysis/code_quality are standalone packages using `structlog.get_logger()` directly (process-global structlog config still applies).
- 002.6 `check_sync_blocking` — security_review only: async-context rule for the pipeline.
- 003.6 / 003.7 pricing & model strings — security_review only: the LLM layer lives there.
- 004.4 forward-slash URIs — `sarif/` + `passes/sast.py` by design.
- 002.1 file size — `src/` only **for now**; `scripts/` exemption is explicit and expires with the scripts-consolidation plan (§0.4 item 1). State that in the jsonl entry.

**H.5** Fix the `get_all_source_files` docstring (`check_rules.py:~686`) — it still says "under src/security_review/" while the code globs `src/`.

### Tests

The checker is its own test:

```bash
python scripts/check_rules.py --all      # green — including the newly widened 001.3/001.4 over code_analysis/code_quality
pytest tests/unit/ -q                    # green — analyze() re-export intact (test_code_analysis + test_code_quality suites prove it)
grep -rn "subprocess.run" src/ --include="*.py" | grep -v "tools/runner.py" | grep -v "/cli/"   # zero hits
```

Commit: `P021-H: subprocess chokepoint and init-minimal enforced across src/; scoped rules documented`

---

## 10. WP-I — pydantic-ai exact pin + deprecated-API migration + limiter reset hook

### Problem

Installed pydantic-ai is **1.63.0** while `requirements.txt`/`pyproject.toml` float `pydantic-ai[openai,anthropic]>=0.2.14` — in a repo whose ADR-001 exists precisely because a floating SDK broke detection. The code also uses APIs deprecated in the installed version (31 warnings in the unit run): `usage.request_tokens`/`usage.response_tokens` and `OpenAIModel`. A future silent upgrade removes them.

### Changes

**I.1** Pin exactly, with the house rationale comment, in `requirements.txt` and every `pyproject.toml` extra that names it (`openai`, `anthropic`, `all`, `dev`):

```
# Pin to the tested version (ADR-001 discipline: floating LLM-stack deps have
# bitten us before — A/B test before ANY upgrade).
pydantic-ai[openai,anthropic]==1.63.0
```

**I.2** Migrate `usage.request_tokens or 0` → `usage.input_tokens or 0` and `usage.response_tokens or 0` → `usage.output_tokens or 0` at all six sites:
`passes/triage.py:294-295`, `passes/holistic.py:405-406`, `passes/verify.py:316-317`, `passes/config_review.py:151-152`, `preflight.py:59`, `tracing.py:53-54`. In `tracing.py`, also rename the emitted dict keys to `input_tokens`/`output_tokens` (trace files are debug artifacts; clean break per P9 — no dual keys).

**I.3** `providers.py:127-130` — `from pydantic_ai.models.openai import OpenAIChatModel` and construct `OpenAIChatModel(...)` (same args). Grep `OpenAIModel` across `src/ tests/ scripts/` and migrate any other site.

**I.4** `providers.py` — add the test-reset hook next to `_provider_limiters` (:79-98), mirroring the `lru_cache.cache_clear()` convention used in `model_providers.py`:

```python
def reset_provider_limiters() -> None:
    """Test hook: clear the shared per-provider limiters (mirrors the
    .cache_clear() convention in model_providers.py)."""
    _provider_limiters.clear()
```

### Tests

```bash
pip install -e '.[dev]' 2>&1 | tail -2          # resolves cleanly against the exact pin
pytest tests/unit/ -q 2>&1 | grep -cE "request_tokens is deprecated|response_tokens is deprecated|OpenAIModel.*was renamed"   # 0
pytest tests/unit/ -q                           # green
```

Also add one unit test asserting `reset_provider_limiters()` empties the dict after a `_get_limiter` call (in `tests/unit/test_providers.py`).

Commit: `P021-I: pin pydantic-ai==1.63.0; migrate deprecated usage/OpenAIModel APIs; limiter reset hook`

---

## 11. WP-J — Documentation drift

### Changes (all factual corrections — verify each against code while editing)

**J.1** Plan status headers: `docs/09-plans/010-…md` and `014-…md` still read `**Status:** Draft` — set to `**Status:** Implemented (merged to main 2026-07-17)`. Sweep the other plan headers (`grep -n "^\*\*Status" docs/09-plans/*.md`) and correct any other shipped-but-Draft headers factually (001/005/007/008 are implemented per the backlog audit; 019/020 should say Implemented; leave genuinely open plans — 004/011/012/013/015/016/017 — untouched).

**J.2** `docs/09-plans/010-…md` — at the "Location of the database" paragraph (~line 1308): append one line: *"**Superseded by plan 021 WP-D:** the cache now lives in SCAR's own `var/cache/graphs/<target-key>/`; SCAR no longer writes into the scanned repository."*

**J.3** `README.md`:
- **Setup table** (~lines 40-52): remove the "Editable install" row (setup.py's `check_editable_install` explicitly states no install is needed) and correct the external-tools row to the actual `EXTERNAL_TOOLS` list in `setup.py:65-162` (enumerate from the source at edit time — do not copy this plan).
- **Quickstart**: add a numbered first-value path near the top of Setup: 1) `git clone` + `cd`, 2) `python setup.py --fix`, 3) provider auth (`gh auth login` for the default copilot provider — call it out explicitly), 4) `python scar.py health-check`, 5) `python scar.py review --target <repo> --mode full`.
- **Viewing Reports**: document `reports --prune-incomplete` and `--yes` (recovery for crashed/incomplete runs) alongside `--show`/`--compare`.
- **Code Intelligence** section: document the graph cache location (`var/cache/graphs/…`, from WP-D) and the guarantee that SCAR never writes into the target repo; document that a call-graph failure now surfaces as a `call_graph_failed` degradation.
- Fix any references to the deleted `scripts/code_quality.py` (WP-F did the greps — this is the doc side).

**J.4** `CHANGELOG.md` — add under `## Unreleased` a "Review integrity & self-compliance (plan 021)" block: one bullet per WP A-I in the existing house style, explicitly noting (a) empty holistic responses now degrade instead of counting as clean, (b) SARIF results may omit `locations` when the path is unresolved (`properties.location_unresolved: true`), (c) the graph cache moved out of target repos (old `.scar/` dirs in previously scanned targets are left in place — delete manually if unwanted), (d) hook now calls `scar.py quality`, (e) pydantic-ai pinned.

### Acceptance

```bash
python scripts/check_rules.py --all && pytest tests/unit/ -q   # docs-only, but run anyway (003.3 YAML-header rule etc.)
```

Commit: `P021-J: fix plan-status/README/CHANGELOG drift; document quickstart, prune-incomplete, graph cache`

---

## 12. Final acceptance (run after WP-J, before handing back for QA)

```bash
python scripts/check_rules.py --all          # all rules green across all of src/
pytest tests/unit/ -q                        # green; count strictly greater than 471 (new tests added)
pytest tests/integration/ -q                 # green (20 at baseline; +1 quality-scope test if bandit present)
python scar.py health-check                  # Environment healthy.
bandit setup.py -q -f json | python -c "import json,sys; assert not [r for r in json.load(sys.stdin)['results'] if r['issue_severity']=='HIGH']"
grep -rn '\.scar' src/ tests/ | wc -l        # 0
grep -rn "shell=True" setup.py src/ | grep -v "check_rules\|# " | wc -l   # 0

# Live smoke (deterministic, no LLM cost): sast mode end-to-end
cp -r eval /tmp/scar-smoke-target
python scar.py review --target /tmp/scar-smoke-target --mode sast --format summary
test ! -d /tmp/scar-smoke-target/.scar       # scanner did not write into the target
ls var/cache/graphs/*/graph.db               # fingerprint tracking used SCAR's own cache
```

Every WP is one commit on `review-integrity-021`, in order `P021-0` … `P021-J`. Do **not** merge to main and do **not** push — stop after final acceptance and report results per WP (pass/fail + any deviations), for human QA.

## 13. Notes for the QA pass (human + reviewing agent)

- The two behaviour claims worth re-verifying by hand: (1) `FunctionModel`-returning-`""` produces `check_failed` degradations, never a clean check (WP-A test 2); (2) a SARIF result for an unresolved-path finding has no `locations` and carries `properties.location_unresolved` (WP-B test 2).
- Diff hygiene: each commit must map 1:1 to its WP — anything else is scope creep, reject it.
- Behavioural deltas that are *intended* (do not flag as regressions): holistic "Triage"/coverage counts may drop on flaky providers (previously inflated by false-clean checks); `.codemap/quality.json` sub-score keys may change shape (WP-F single scorer); trace JSON keys renamed to `input_tokens`/`output_tokens` (WP-I).
