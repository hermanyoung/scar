# Plan 019 — Invariant Debt Remediation

**Status:** Ready for implementation — **blocked on Plan 018 being merged first**
**Date:** 2026-07-06
**Source:** Verified plan-backlog audit of 2026-07-05/06 (plans 001–017 checked deliverable-by-deliverable against the code) + PRR follow-ups
**Depends on:** `docs/09-plans/018-operational-readiness-remediation.md` — **hard dependency**, see §0.3
**Closes residuals from:** plans 002 (§1.6, §1.7, §1.8, §2.1, §2.2, §3.4), 005 (test gaps), 006 (hadolint CWE map, IDOR rubric), 009 (P3 overflow)

---

## 0. Purpose and context

The backlog audit found shipped code that violates the repo's own rulebook, hidden under green tests:

- **AGENTS.md critical rule #5** ("Every finding must have a CWE ID") is unenforced: `cwe_id` is optional on all LLM finding models, the holistic pass never stamps the CWE it *already knows* (P13 violation — the check IS the CWE), and **hadolint findings enter SARIF with no CWE at all** (its SARIF carries no CWE tags and the `cwe_source: rule_id_map` spec field is consumed by nothing).
- **AGENTS.md critical rule #3** ("No hardcoded model strings"): `CopilotModel.__init__` defaults `model_id="claude-sonnet-4.6"`.
- `CWE-829` is missing from `config/taxonomy/cwe.yaml` while `eval/docker/best-practices/ground_truth.yaml` expects it.
- Cross-tool SAST dedup runs on **un-normalized URIs** (dedup happens before URI normalization), so the same finding reported by two tools with different URI formats is double-counted.
- `TriageResult.findings` requires `min_length=1` — a schema that cannot represent a legitimate empty result.
- `config/taxonomy/bandit-cwe-map.yaml` is dead config: zero consumers anywhere in `src/`.
- Context-overflow errors from providers are treated as generic transient failures — the retry re-sends the identical oversized prompt and fails identically.
- Plans 001–009 carry stale `Status:` headers that no longer reflect reality, and five unit-test files promised by plan 002 were never written.

This plan fixes exactly those. It is written for a fresh agent with no prior context. **Do not improvise.** Where a cited line number has drifted, the cited code snippet/symbol is authoritative — re-locate it.

### 0.1 Mandatory reading before writing any code

1. `AGENTS.md` + `CLAUDE.md` (repo root) — especially critical rules #3, #5, #9 (never trust LLM-echoed identifiers), #11 (no fallbacks).
2. `docs/03-principles/01-project-principles.md` — P9 (breaking changes free), P10, P12, P13.
3. `docs/05-standards/01-python-coding-standards.md`, `02-testing-standards.md`.
4. `docs/09-plans/018-operational-readiness-remediation.md` §2 (Degradation model + `state.degrade()` API) — this plan **uses** that API.
5. Every file you edit, in full, before editing.

### 0.2 Binding constraints

Identical to plan 018 §0.2 (absolute imports, subprocess only in `tools/runner.py`, models are leaf, every except logs or re-raises, no new TODO markers, YAML options headers per rule 003.3, tests never call real LLMs, `python scripts/check_rules.py --all` + `pytest tests/unit/ -v` green after every work package). Additional for this plan:

- **New CWEs: update `config/taxonomy/cwe.yaml` FIRST**, then rules/maps/tests (AGENTS.md convention).
- Auto-repair over reject (ADR philosophy, architecture invariant P-05): validators normalise, they do not raise `ModelRetry`. The rule-#5 enforcement below is therefore done by **deterministic stamping + a visible merge-boundary drop**, NOT by making Pydantic fields required (a required field would reject entire responses that auto-repair could save).

### 0.3 Prerequisites (verbatim, in order)

```bash
cd /path/to/scar
git log --oneline -5        # CONFIRM a commit implementing plan 018 exists (degradation ledger etc.).
rg -l "class Degradation" src/security_review/models/   # MUST hit models/degradation.py.
rg -n "def degrade" src/security_review/passes/state.py # MUST hit.
# If either check fails: STOP. Implement docs/09-plans/018-operational-readiness-remediation.md first.
pip install -e '.[all]'
python -c "import security_review; print(security_review.__file__)"   # must be THIS checkout
pytest tests/unit/ -v && python scripts/check_rules.py --all           # green baseline
git checkout -b invariant-debt-019
```

One commit per work package, message `WP<letter>: <title>`.

### 0.4 Out of scope — do NOT do these

- Anything already in plan 018 (do not re-touch its deliverables beyond the integration points named below).
- New detection content beyond the CWE-829 taxonomy entry and the CWE-863 rubric edit (JWT = plan 014, API specs = plan 015 — untouched).
- Call-graph/file-selection work (plan 010), noise-reduction pre-filter (plan 004), harness extraction (plan 017).
- Copilot retry/backoff redesign — WP-F below only *classifies* overflow and halves the file list; it does not touch `copilot_model.py` session logic (ADR-001 canary protection).
- Typed `PipelineState` transitions (TODO.md item — explicitly deferred).

---

## 1. Work packages

| WP | Title | Primary files |
|----|-------|---------------|
| A | Model-layer schema fixes | `models/findings.py`, `passes/triage.py` (verify only) |
| B | CWE integrity: deterministic stamp + merge boundary guard | `passes/holistic.py`, `passes/merge.py`, `sarif/taxonomy.py`, `sarif/converter.py` |
| C | Hadolint rule→CWE mapping + CWE-829 + dead-map deletion | `config/taxonomy/cwe.yaml`, `config/taxonomy/hadolint-cwe-map.yaml` (new), `passes/sast.py`, `tools/registry.py`, delete `config/taxonomy/bandit-cwe-map.yaml` |
| D | Config hygiene: CopilotModel required params + IDOR rubric | `copilot_model.py`, `providers.py` (verify), `config/taxonomy/cwe.yaml` |
| E | Dedup correctness: normalize URIs before merge | `passes/sast.py` |
| F | Context-overflow classification + halve-and-retry | `errors.py`, `passes/holistic.py`, `passes/config_review.py` |
| G | Missing unit tests (plan 002 §2.1 remainder + plan 005 C# gaps) | `tests/unit/` |
| H | Plan-status housekeeping + doc touch-ups | `docs/09-plans/001..017` headers, `AGENTS.md` |

---

## 2. WP-A — Model-layer schema fixes

### A.1 `TriageResult.findings` must allow empty (plan 002 §2.2)

`src/security_review/models/findings.py:83`:

```python
findings: list[TriagedFinding] = Field(min_length=1)
```

→

```python
findings: list[TriagedFinding] = Field(default_factory=list)
```

Rationale: an empty result is legitimate (all calls failed, or zero findings passed the score filter after dispatch). The current constraint forces callers into the `None`-means-many-things pattern. Verify the only constructor site guards on non-empty (`passes/triage.py:188` `if all_triaged:`) — **do not change that guard** (plan 018 WP1 already handles the messaging for the None case); this WP only removes the schema landmine. Search for other constructors: `rg "TriageResult(" src/ tests/` and fix any test that relied on `min_length=1` rejection.

### A.2 Do NOT touch `files_reviewed: Field(min_length=1)`

`HolisticReviewResult.files_reviewed` (findings.py:209) and `ConfigReviewResult.files_reviewed` (models/config_review.py:36) keep `min_length=1`. Plan 018 WP2 sets `files_reviewed` to the actually-included list, which is non-empty in every reachable path (a check with zero relevant files is skipped before any call). Documented here so you don't "fix" it speculatively.

### Tests

- Extend/create `tests/unit/test_findings_model.py`: `TriageResult(findings=[], total_confirmed=0, total_false_positive=0, total_needs_context=0)` constructs successfully.

### Acceptance

`pytest tests/unit/ -v` green; `rg "min_length=1" src/security_review/models/findings.py` matches only `files_reviewed` and the `str` fields, not `findings`.

---

## 3. WP-B — CWE integrity: deterministic stamp + merge boundary guard

### Problem

- `BaseFinding.cwe_id: str | None = Field(default=None)` (`models/findings.py:103`) with a warn-only validator (`normalise_cwe_id`, lines 124-138). AGENTS.md rule #5 is enforced nowhere.
- The holistic pass runs **one call per CWE** (`run_single_check` receives `check`), yet the finding's `cwe_id` is whatever the LLM echoed — `run_single_check` overrides only `files_reviewed` (`passes/holistic.py:375`). This violates P13: the CWE is known bookkeeping, not something to trust from the model.
- `sarif/converter.py:54` and `:134` hardcode the tag `external/cwe/cwe-1395` with no check that `1395` exists in the taxonomy (plan 002 §1.7).

### Changes

**B.1 `sarif/taxonomy.py` — add a public existence helper** (below `load_cwe_registry`):

```python
def cwe_exists(cwe_id: str) -> bool:
    """True if the given ID ('CWE-89', '89', or 89) is in config/taxonomy/cwe.yaml."""
    key = str(cwe_id).upper().removeprefix("CWE-").lstrip("0") or "0"
    registry = load_cwe_registry()
    return key in registry or str(cwe_id).removeprefix("CWE-") in registry
```

(Note: registry keys are unpadded strings like `"89"`, `"863"` — verify with `load_cwe_registry().keys()` in a REPL-style test before finalising the key normalisation; keys in the YAML are exactly as written in the file, e.g. `"78"`, `"250"`, `"1395"`.)

**B.2 Deterministic CWE stamp in the holistic pass** (`passes/holistic.py`, in `run_single_check`, immediately after the `files_reviewed` override block at ~lines 372-379):

```python
# P13: the check's CWE is known bookkeeping — never trust the LLM echo.
stamped_cwe = f"CWE-{check.cwe_id}"
review_result = review_result.model_copy(update={
    "findings": [f.model_copy(update={"cwe_id": stamped_cwe}) for f in review_result.findings],
})
```

Fold this into the existing normalisation block cleanly (one `model_copy` chain is fine as long as both `files_reviewed` (018 WP2's `included`) and the stamped findings are applied). Note `check.cwe_id` is the bare number string (e.g. `"863"`) — confirm by reading `src/security_review/checks.py` (`CWECheck` fields) before writing the f-string; if `check.cwe_id` already includes the `CWE-` prefix, do not double-prefix.

**B.3 Merge-boundary guard** (`passes/merge.py`): in the two loops that append LLM findings (holistic loop at ~lines 82-91, config-review loop at ~lines 94-103), before converting each finding:

```python
if not finding.cwe_id:
    logger.warning("merge.finding_dropped_no_cwe",
                   rule_id=finding.rule_id, file_path=finding.file_path)
    dropped_no_cwe += 1
    continue
```

Initialise `dropped_no_cwe = 0` before the loops; after both loops, if non-zero:

```python
if dropped_no_cwe:
    state.degrade(Degradation(
        pass_name="merge", kind="parse_failed", subject="cwe_id",
        detail=f"{dropped_no_cwe} LLM finding(s) had no parseable CWE ID and were "
               f"dropped from the report (AGENTS.md rule 5)",
        count=dropped_no_cwe,
    ))
```

(import `Degradation` from `security_review.models.degradation`; this is a plan-018 API.) After B.2, holistic findings can never hit this guard — it protects config-review findings and any future pass.

**B.4 Converter taxonomy guard** (`sarif/converter.py`): at module level add:

```python
_DEPENDENCY_CWE = "1395"


def _dependency_cwe_tag() -> str:
    """The CWE tag for third-party-dependency findings, validated against the taxonomy."""
    from security_review.sarif.taxonomy import cwe_exists
    if not cwe_exists(_DEPENDENCY_CWE):
        raise ConfigurationError(
            f"CWE-{_DEPENDENCY_CWE} is not in config/taxonomy/cwe.yaml — "
            f"add it before converting dependency-scanner output.",
            code="SYS_CWE_NOT_FOUND",
        )
    return f"external/cwe/cwe-{_DEPENDENCY_CWE}"
```

Replace both hardcoded `"external/cwe/cwe-1395"` literals (lines 54, 134) with `_dependency_cwe_tag()`. Check the file's existing imports for `ConfigurationError` (`from security_review.errors import ConfigurationError`) and add if absent. The lazy inner import avoids a module-level cycle (taxonomy imports nothing from converter — verify).

### Tests

- `tests/unit/test_cwe_integrity.py`:
  - `cwe_exists("CWE-89")`, `cwe_exists("89")` True; `cwe_exists("CWE-99999")` False.
  - Holistic stamp: run `run_single_check` with a `FunctionModel` returning a markdown finding that **claims the wrong CWE** (e.g. `CWE-79` inside a CWE-863 check) → resulting findings all have `cwe_id == "CWE-863"`.
  - Merge guard: state with a `config_review_result` containing one finding with `cwe_id=None` → SARIF omits it, one `parse_failed` degradation with `count=1` recorded.
  - Converter: monkeypatch `cwe_exists` to return False → `convert_pip_audit_to_sarif` on a minimal fixture raises `ConfigurationError` with code `SYS_CWE_NOT_FOUND`.

### Acceptance

1. `rg '"external/cwe/cwe-1395"' src/` → zero hits (only the validated helper remains).
2. Unit tests above green; full suite + rules checker green.

---

## 4. WP-C — Hadolint CWE mapping + CWE-829 + dead-map deletion

### Problem

Hadolint is wired (spec `tools/specs/hadolint.yaml`, `cwe_source: rule_id_map`) but its SARIF rules (DLnnnn) carry no CWE tags, and **nothing consumes `cwe_source`** (`rg -n "cwe_source" src/security_review/ --type py` → only the field definition `tools/registry.py:46` and a display line `cli/tools.py:76`). Result: every hadolint finding enters the report CWE-less, violating rule #5, and `reports`' CWE columns/taxonomy blocks undercount Docker findings. `eval/docker/best-practices/ground_truth.yaml` expects `CWE-829` and `CWE-250`; `config/taxonomy/cwe.yaml` has `"250"` but **no `"829"`**. Separately, `config/taxonomy/bandit-cwe-map.yaml` has zero consumers (bandit's own SARIF already carries CWE tags) — dead config.

### Changes (in this order — taxonomy first, per AGENTS.md)

**C.1 `config/taxonomy/cwe.yaml`:** add (alongside the other `detection: sast` entries, numerically ordered near `"798"`/`"862"`):

```yaml
"829":
  name: "Inclusion of Functionality from Untrusted Control Sphere"
  detection: sast  # hadolint (unpinned base images) + opengrep docker rules
```

**C.2 New file `config/taxonomy/hadolint-cwe-map.yaml`:**

```yaml
# =============================================================================
# Hadolint rule -> CWE mapping
# =============================================================================
# Loaded by: src/security_review/passes/sast.py (_apply_rule_cwe_map) for tool
# specs with cwe_source: rule_id_map.
# Schema: <tool rule ID>: "CWE-NNN"   — every CWE must exist in cwe.yaml
# (validated at load; unmapped rules keep no CWE tag and are logged at debug).
# =============================================================================
DL3002: "CWE-250"   # last USER is root — execution with unnecessary privileges
DL3006: "CWE-829"   # image tag not pinned — untrusted functionality inclusion
DL3007: "CWE-829"   # :latest tag — mutable, unpredictable base image
```

Do not invent further entries; extend only when a rule fires in eval and its CWE exists in the taxonomy.

**C.3 Consume `cwe_source: rule_id_map`** (`passes/sast.py`): add a module-level function and call it per-document in `run_sast`'s results loop, right where valid docs are collected (the `elif doc is not None:` branch, currently ~lines 78-81), before `valid_docs.append(doc)`:

```python
if spec.cwe_source == "rule_id_map":
    _apply_rule_cwe_map(doc, spec.name)
```

```python
def _apply_rule_cwe_map(sarif: dict, tool_name: str) -> None:
    """Inject external/cwe/cwe-NNN tags onto rules using config/taxonomy/{tool}-cwe-map.yaml."""
    map_path = MODULE_ROOT / "config" / "taxonomy" / f"{tool_name}-cwe-map.yaml"
    if not map_path.exists():
        raise ConfigurationError(
            f"Tool '{tool_name}' declares cwe_source: rule_id_map but "
            f"{map_path} does not exist.",
            code="SYS_CONFIG_INVALID",
        )
    with open(map_path, encoding="utf-8") as f:
        rule_map = yaml.safe_load(f) or {}
    from security_review.sarif.taxonomy import cwe_exists
    for rule_id, cwe in rule_map.items():
        if not cwe_exists(cwe):
            raise ConfigurationError(
                f"{map_path}: {rule_id} maps to {cwe}, which is not in "
                f"config/taxonomy/cwe.yaml. Add the CWE to the taxonomy first.",
                code="SYS_CWE_NOT_FOUND",
            )
    for run in sarif.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            cwe = rule_map.get(rule.get("id", ""))
            if cwe is None:
                logger.debug("sast.rule_unmapped", tool_name=tool_name, rule_id=rule.get("id"))
                continue
            num = int(cwe.removeprefix("CWE-"))
            tags = rule.setdefault("properties", {}).setdefault("tags", [])
            tag = f"external/cwe/cwe-{num:03d}"
            if tag not in tags:
                tags.append(tag)
```

Imports needed in sast.py: `yaml`, `from security_review import MODULE_ROOT`, `from security_review.errors import ConfigurationError` (check which are already imported — `ScannerError`/`SARIFError` are; add the rest). NOTE: hadolint results may reference rules only via `result.ruleId` without a `rules` array in the driver — **verify against a real hadolint SARIF** (`var/tmp/` from a previous run, or run `python scar.py review --target eval/docker --mode sast` once and inspect). If the driver has no `rules` array, extend `_apply_rule_cwe_map` to also tag results directly: for each result whose `ruleId` is in the map, append the tag to `result.properties.tags`. Implement whichever the real output requires — and cover both shapes in the unit test.

**C.4 Make `cwe_source` honest** (`tools/registry.py:46`): constrain the decorative free string:

```python
cwe_source: Literal["metadata", "rule_id_map"] = "metadata"
```

(`from typing import Literal`.) All existing specs use exactly these two values (`rg "cwe_source" src/security_review/tools/specs/`) — verify before committing.

**C.5 Delete `config/taxonomy/bandit-cwe-map.yaml`** (P9 — dead config; zero consumers, bandit SARIF is self-tagging). Update the one doc reference: `AGENTS.md` Key Directories line `config/taxonomy/ — CWE registry, Bandit CWE mappings` → `config/taxonomy/ — CWE registry, tool rule→CWE maps`. Search for other mentions: `rg "bandit-cwe-map" . --hidden -g '!.git'` and fix every hit (docs/01-architecture list included).

### Tests

- `tests/unit/test_rule_cwe_map.py`: fabricate a minimal hadolint-shaped SARIF dict (rule DL3007 + one result) → `_apply_rule_cwe_map` injects `external/cwe/cwe-829`; unmapped rule untouched; a map entry with an unknown CWE raises `ConfigurationError`; a `rule_id_map` spec with no map file raises. Cover the driver-rules and results-only shapes per C.3.

### Acceptance

1. `python scar.py review --target eval/docker --mode sast` (local, free): the summary's Top CWEs section includes `CWE-829` and `CWE-250`, and the SARIF taxonomy block lists them.
2. `rg -l "bandit-cwe-map" .` → zero hits.
3. Suite + rules checker green (rule 004.7 cross-checks rules↔taxonomy — the new 829 entry satisfies it).

---

## 5. WP-D — Config hygiene: CopilotModel required params + IDOR severity rubric

### D.1 `CopilotModel.__init__` hardcoded defaults (plan 002 §3.4; AGENTS.md rule #3)

`src/security_review/copilot_model.py` (~lines 174-179): remove all three defaults:

```python
def __init__(
    self,
    model_id: str,
    session_timeout: float,
    backoff_seconds: float,
) -> None:
```

Update every constructor call site (`rg -n "CopilotModel(" src/ tests/ scripts/`): `providers.py:139-143` already passes all three (no change); fix any test/script that relied on defaults by passing explicit values from a loaded config (never re-hardcode strings — in tests, literal test values like `model_id="test-model"` are fine per rule scoping). Apply the same treatment to `ClaudeModel`/`CodexModel` **only if** their `__init__` signatures carry model-string defaults (`rg -n "def __init__" src/security_review/claude_model.py src/security_review/codex_model.py` — fix if found, leave otherwise).

### D.2 IDOR severity rubric (plan 006 residual)

`config/taxonomy/cwe.yaml`, the `"863"` entry (verified at line ~354): replace its `check:` block with:

```yaml
"863":
  name: "Incorrect Authorization"
  detection: llm
  file_types: [controller, repository, service]
  check: |
    Check for authorization checks that are present but incorrect (IDOR).
    Look for database queries that fetch records by user-supplied ID without
    an ownership filter:
    - dbContext.Entity.Find(id) without .Where(e => e.UserId == currentUser)
    - Model.objects.get(pk=id) without filtering by request.user
    - SELECT ... WHERE id = ? without AND user_id = ?
    The key question: can User A access User B's data by changing an ID
    in the URL or request body?
    Check the service/repository layer too — an ownership check in the
    controller does not cover a service method callable from elsewhere.
    Severity rubric (apply consistently):
    - CRITICAL: write operations (UPDATE/DELETE/state change) reachable
      without an ownership check.
    - HIGH: bulk read of another user's records.
    - MEDIUM: single-record read without an ownership check.
    Evidence: name the missing ownership field/filter for every finding.
    Create a separate finding for each vulnerable call site — do not consolidate.
```

(Keeps the original text; appends the plan-006 rubric, the service-layer instruction, and the ADR-006 granularity sentence. This matches `eval/csharp/cwe-863-idor/ground_truth.yaml`, which encodes medium GETs and critical PUT/DELETE.)

### Tests / verification

- No real-LLM test. Verify prompt loads: extend `tests/unit/test_checks.py` (WP-G) to assert the 863 check text contains `Severity rubric`.
- **Note for the human reviewer** (put this in your final report, do not run it): the 863 prompt change should be validated against the benchmark protocol (`python scar.py test-cwe --cwe 863 --target ../example-target` / `scripts/benchmark_cwes.py --cwes 863`) before the next baseline update — real LLM calls, human-triggered only.

### Acceptance

`rg 'claude-sonnet-4.6' src/security_review/copilot_model.py` → zero hits; suite + rules green (rule 003.7 excludes `copilot_model.py` today — after this change the exclusion is vacuous for the default; leave the rule file untouched).

---

## 6. WP-E — Dedup correctness: normalize URIs before merge (plan 002 §1.6)

### Problem

`run_sast` merges per-tool SARIF **before** normalizing URIs: `merge_sarif(valid_docs)` at `passes/sast.py:86` runs on raw tool output, then `_normalize_sarif_uris(merged, target)` at `:92`. `merge_sarif` dedups by `get_finding_key` (`sarif/loader.py:90-104`), which uses the **raw** `artifactLocation.uri`. Tools emit different formats (`file:///abs/path`, `/abs/path`, `relative/path`), so identical findings from two tools carry different keys and are double-counted instead of deduped (highest-severity-wins never triggers).

### Change

In `run_sast` (`passes/sast.py`), normalize each document **before** the merge and delete the post-merge call:

```python
# Normalize all URIs to relative paths BEFORE merging, so merge_sarif's
# (cwe, file, line) dedup key compares like with like across tools.
for doc in valid_docs:
    _normalize_sarif_uris(doc, target)

merged = merge_sarif(valid_docs)
```

and remove the now-redundant `_normalize_sarif_uris(merged, target)` line (currently after `normalise_sarif_levels(merged)`). Keep `normalise_sarif_levels` and `redact_sarif` where they are. Also apply the same pre-merge normalization inside `_run_file_targeted_tool` **only if** its per-file docs are merged there (they are: `merge_sarif(sarif_docs)` at ~line 148) — hadolint per-file URIs are absolute paths to individual Dockerfiles; normalize each doc with `target_path` resolved from the *repo target*, which is not in scope inside that helper today. Thread it: add parameter `target_root: str` to `_run_file_targeted_tool`, pass `target` from `run_sast`, and normalize each doc before that inner merge.

### Tests

- `tests/unit/test_merge_dedup.py`: two single-run SARIF docs containing the *same* finding (same CWE tag, same line) with URIs `file:///repo/src/a.py` and `/repo/src/a.py`; after normalizing both with `target_root="/repo"` and merging → exactly one result, and the higher severity of the two wins. Also assert the old behavior is gone: merging *without* normalization is no longer reachable from `run_sast` (test via `run_sast` with two monkeypatched tool outputs, not by re-testing `merge_sarif` internals).

### Acceptance

Suite + rules green; `python scar.py review --target eval/python --mode sast` finding count is ≤ the pre-change count on the same corpus (record both numbers in your report — a drop is the dedup working; an increase is a bug).

---

## 7. WP-F — Context-overflow classification + halve-and-retry (plan 009 P3, minimal form)

### Problem

A provider context-overflow error ("prompt too long") is classified as a generic transient failure; the holistic retry pass re-sends the **identical oversized prompt** and fails identically, burning ~2× the wall-clock for zero output. With plan 018 WP2, files that get dropped are at least *recorded* — but an overflowing check produces no output at all.

### Changes

**F.1 `errors.py`** — add:

```python
_OVERFLOW_PATTERNS = (
    "context length", "context_length_exceeded", "maximum context",
    "prompt is too long", "request too large", "token limit",
    "input is too long", "exceeds the maximum",
)


def is_context_overflow_error(exc: Exception) -> bool:
    """True if the exception message indicates the prompt exceeded the model's context window."""
    msg = str(exc).lower()
    return any(p in msg for p in _OVERFLOW_PATTERNS)
```

**F.2 `passes/holistic.py`** — classify and halve. In `_classify_result` (lines 51-89), before the generic-transient branch inside `isinstance(result, Exception)`:

```python
if is_context_overflow_error(result):
    logger.warning("holistic.check_overflow", cwe_id=check.cwe_id, error=str(result))
    return _Outcome.OVERFLOW, [], []
```

Add `OVERFLOW = auto()` to `_Outcome`. In the first-pass result loop (~lines 184-194) handle it by re-queueing with half the files (they are already ordered by security weight — manifest order):

```python
elif outcome == _Outcome.OVERFLOW:
    half = file_paths[: max(1, len(file_paths) // 2)]
    dropped = file_paths[len(half):]
    state.degrade(Degradation(
        pass_name="holistic", kind="files_omitted", subject=f"CWE-{check.cwe_id}",
        detail=f"prompt exceeded the model context window — retrying CWE-{check.cwe_id} "
               f"with the top {len(half)} of {len(file_paths)} files; "
               f"{len(dropped)} files NOT reviewed for this CWE",
        count=len(dropped),
    ))
    failed_checks.append((check, half))
```

In the retry loop (~lines 225-252), an OVERFLOW outcome on the retry is terminal: treat it like the second-RETRY give-up branch (`checks_failed += 1`, `logger.error("holistic.check_failed_after_retry", ...)` — plus the plan-018 `check_failed` degradation that branch already records). Do **not** recurse further halvings.

**F.3 `passes/config_review.py`** — in the `except` handler (~lines 151-159), before the fatal check: if `is_context_overflow_error(e)` and this is the first attempt, halve `file_paths` (same top-half rule), record the same `files_omitted` degradation (subject `"config_review"`), rebuild the prompt via the WP2-updated `_build_config_review_prompt`, and retry the agent call once. Structure this as a small loop (`for attempt in range(2):`) rather than duplicated call code; on second overflow fall through to the existing non-fatal failure path (which records `check_failed` per plan 018).

### Tests

- `tests/unit/test_overflow.py`: `is_context_overflow_error` truth table (each pattern + a non-matching "rate limited" message → False). `_classify_result` with an exception whose message is "prompt is too long: 210000 tokens" returns `_Outcome.OVERFLOW`. Holistic first-pass handling: `FunctionModel` that raises an overflow-message error on the first call and succeeds on the retry → check completes, one `files_omitted` degradation recorded, retried call received fewer files (assert via the FunctionModel capturing prompt sizes or via the degradation count).

### Acceptance

Suite + rules green. No behavior change on non-overflow errors (existing retry tests unaffected).

---

## 8. WP-G — Missing unit tests (plan 002 §2.1 remainder + plan 005 gaps)

Plan 002 promised six unit-test files; only `test_priority.py` exists. Plan 018 adds budget/preflight/exit-code tests — do not duplicate those. Create exactly:

1. **`tests/unit/test_checks.py`** — `load_cwe_checks()` returns >0 checks; every returned check has non-empty `check_prompt` and `file_types`; the `"863"` check text contains `"Severity rubric"` (WP-D.2); `select_files_for_check` matches a fabricated manifest entry named `UserController.cs` for a `[controller]` check and excludes a `README.md`.
2. **`tests/unit/test_config.py`** — `load_config(Path("nonexistent.yaml"))` raises `ConfigurationError`; a YAML missing a required key (e.g. `llm.provider_model`) raises with a message naming the field; an unknown key (`llm.tempratura`) is rejected (`extra="forbid"`).
3. **`tests/unit/test_providers.py`** — `resolve_model_name("copilot", "claude-opus") == "claude-opus-4.6"`; `resolve_model_name("anthropic", "claude-opus") == "claude-opus-4-6"`; canonical input passes through unchanged; `build_model("nonsense:x", llm_config=...)` raises `ConfigurationError` (`Unsupported provider`); `build_model("copilot", ...)` (no colon/model) raises. Build `llm_config` from the shipped YAML via `load_config()`.
4. **`tests/unit/test_merge_dedup.py`** — per WP-E.
5. **C# parser coverage (plan 005 gap)** — `tests/unit/test_code_analysis/fixtures/csharp/{Clean.cs,Complex.cs,Unsafe.cs}` (mirror the intent of the existing `fixtures/python/{clean,complex,unsafe}.py` — read them first; Unsafe.cs should include `Process.Start` + `BinaryFormatter` usages so unsafe-pattern counters trigger) and `tests/unit/test_code_analysis/test_csharp_parser.py` mirroring `test_python_parser.py`'s structure (read it first; same assertions adapted: symbols extracted, complexity computed, unsafe patterns counted, clean file yields zero unsafe hits).

All tests: no network, no subprocess to real tools (monkeypatch where a runner would be invoked), no LLM (`ALLOW_MODEL_REQUESTS=False` already global).

### Acceptance

`pytest tests/unit/ -v` green; the five new files exist; `pytest tests/unit/test_code_analysis/ -v` exercises the C# parser (non-zero assertions, not import-only).

---

## 9. WP-H — Plan-status housekeeping + doc touch-ups

The backlog's `Status:` headers no longer reflect verified reality. Set each header line exactly as below and append one `**Disposition (2026-07-06):**` line immediately under the header block (do not otherwise rewrite the historical plans):

| File (docs/09-plans/) | Set `**Status:**` to | Disposition line |
|---|---|---|
| 001-implementation-plan.md | `Implemented` | `Delivered (architecture evolved: batching dropped for per-CWE selection; prompts absorbed into config/taxonomy/cwe.yaml).` |
| 002-codebase-remediation-plan.md | `Partially implemented — residuals closed by plans 018/019` | `Items 1.1/1.5/3.3/3.5/3.6 done; 1.3→018 WP1, 1.4→018 WP4; 1.6/1.7/1.8/2.1/2.2/3.4→019; 3.1/3.2 obsolete.` |
| 003-code-intel-integration-plan.md | `Superseded` | `Engine extraction delivered via plan 005 (src/code_analysis); Pass-1/selection integration redesigned by plan 010.` |
| 004-noise-reduction-and-ci-integration-plan.md | `Planned — re-scoped` | `CI layer delivered by plan 018 (WP5 --fail-on, WP11 ci.yml). Remaining scope: pre-filter, precedents, confidence gate, --diff.` |
| 005-code-quality-module-plan.md | `Implemented` | `Test gaps (C# parser fixtures/tests) closed by plan 019 WP-G.` |
| 006-coverage-and-detection-improvements.md | `Implemented — gaps closed by 018/019` | `Coverage-in-reports→018 WP1/WP2; hadolint CWE map + CWE-829 + IDOR rubric→019 WP-C/WP-D.` |
| 007-pre-materialized-context.md | `Implemented` | `Extended to all LLM passes; dual-mode fallback deliberately dropped (ADR-003, AGENTS.md rule 10).` |
| 008-copilot-concurrency-architecture.md | `Implemented` | `Config surface evolved to per-provider blocks; hardcoded __init__ defaults removed by plan 019 WP-D.` |
| 009-provider-model-improvements.md | `Partially implemented` | `P1 done; P2 rejected (conflicts with pricing.yaml rule + 018 WP4); P3→019 WP-F; P4/P6 not planned.` |

Leave 010–017 headers as they are (Draft/Planned — accurate). Also:

- `AGENTS.md`: taxonomy directory description update (WP-C.5) — done there; verify no other stale mention of bandit map remains.
- `CHANGELOG.md` (created by plan 018): add under `## Unreleased`: `- Invariant debt remediation (plan 019): CWE integrity (deterministic stamp, hadolint mapping, CWE-829), pre-merge URI dedup fix, overflow halve-and-retry, CopilotModel required params, backlog status reconciliation.`

### Acceptance

`rg -n "^\*\*Status:\*\*" docs/09-plans/00*.md` shows the table above; `rg "bandit-cwe-map" . -g '!.git'` → zero hits.

---

## 10. Global verification protocol (run at the end, in order)

```bash
pip install -e '.[all]'
python scripts/check_rules.py --all              # zero violations
pytest tests/unit/ -v                             # all green
python scar.py review --target eval/docker --mode sast     # Top CWEs includes CWE-829, CWE-250
python scar.py review --target eval/python --mode sast     # finding count vs pre-019 baseline: report both numbers
python scar.py health-check                       # still green (taxonomy/pricing checks from 018 pass with new 829 entry)
rg '"external/cwe/cwe-1395"' src/                 # zero hits
rg "claude-sonnet-4.6" src/security_review/copilot_model.py   # zero hits
rg -l "bandit-cwe-map" . -g '!.git'               # zero hits
```

Do NOT run `--mode full`, `test-cwe`, `eval`, `test-providers`, or `scripts/benchmark_*` — real LLM calls are human-triggered only. Flag in your final report that the CWE-863 prompt change (WP-D.2) awaits a human-run benchmark (`--cwes 863`) before the next golden-baseline update.

**Definition of done:** every WP's acceptance criteria met; both checkers green; one commit per WP on `invariant-debt-019`; do not push or open a PR — stop after the final commit and report per-WP results, including the two finding-count baselines from WP-E.
