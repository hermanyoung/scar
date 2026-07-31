# Plan 003: Integrate code_intel into the Pipeline

**Date:** 2 May 2026
**Status:** [~] Superseded — implemented as src/code_analysis; scripts/code_intel.py prototype removed 2026-07-31
**Scope:** Replace keyword-based security-weight scoring in Pass 1 with code_intel's PageRank + unsafe patterns + quality metrics. Feed structural data to downstream passes.
**Disposition (2026-07-06):** Engine extraction delivered via plan 005 (src/code_analysis); Pass-1/selection integration redesigned by plan 010.

---

## 1. Current State (Before)

### Pass 1 — `passes/inventory.py`

Security-weight scoring uses two heuristics:

1. **Filename matching** (lines 184-205): `"controller" in name_lower` → +3, `"auth" in name_lower` → +2, etc.
2. **Content regex** (lines 49-79, 207-214): reads first 4KB, runs 25 regex patterns like `re.compile(r"BinaryFormatter")` → +4.

Result: integer 0-10 stored as `FileEntry.security_weight`.

**Problems:**
- A utility module imported by 30 files scores 1 (no keywords), but a vulnerability there has wide blast radius.
- No cross-file reasoning — each file scored in isolation.
- No quality signal — a poorly typed file with bare excepts gets the same weight as a well-typed one.
- Regex on 4KB truncation misses patterns deeper in the file.
- No structural data passed to downstream passes.

### PipelineState

Has `manifest` and `batch_plan` — no `code_map` or `quality_baseline` fields.

### SecurityReviewDeps

Has `manifest` and `sast_sarif` — no `code_map` or `quality_baseline`.

### Downstream Passes

- **Triage (Pass 3):** uses `manifest.files` to group findings by file. No quality signal.
- **Holistic (Pass 4):** uses `manifest.files` filtered by language. No structural overview in LLM context.
- **Batching:** sorts by `security_weight` descending — high-weight files get reviewed first.

---

## 2. Target State (After)

### Pass 1 — `passes/inventory.py`

Security-weight scoring uses code_intel's composite scorer:

1. **PageRank** (0-3): graph-based importance from cross-reference analysis.
2. **Unsafe patterns** (0-3): AST-detected patterns with CWE IDs (eval, pickle, BinaryFormatter, etc.).
3. **Surface indicators** (0-2): endpoint decorators/attributes detected via AST.
4. **Quality penalty** (0-2): low type coverage, deep nesting, bare excepts.

Result: float 0.0-10.0 stored as `FileEntry.security_weight` (type changes from `int` to `float`).

### PipelineState

Gains two new fields:
- `code_map: dict | None` — structural map for Pass 4 LLM context.
- `quality_baseline: dict | None` — aggregate quality metrics for Pass 3 confidence calibration.

### SecurityReviewDeps

Gains two new fields:
- `code_map: dict | None` — passed to holistic agent for structural context.
- `quality_baseline: dict | None` — passed to triage agent for confidence calibration.

### Downstream Passes

- **Triage (Pass 3):** receives `quality_baseline`. Can adjust FP confidence threshold based on codebase quality (low quality → less aggressive FP filtering). *Implementation deferred — just wire the data through for now.*
- **Holistic (Pass 4):** receives `code_map`. Renders token-budgeted structural overview and prepends it to the LLM prompt so the agent can reason about cross-file flows. *This is the highest-value change.*
- **Batching:** unchanged — still sorts by `security_weight`, but the weights are now better.

---

## 3. Files to Change

| File | Change | Risk |
|---|---|---|
| `models/inventory.py` | `security_weight: int` → `float`, add `unsafe_pattern_count: int` | Low — field type change, batching comparisons still work |
| `passes/inventory.py` | Replace `_compute_security_weight()` and `_SECURITY_WEIGHT_PATTERNS` with code_intel calls | Medium — core logic replacement |
| `passes/pipeline.py` | Add `code_map` and `quality_baseline` to `PipelineState` | Low — additive |
| `agents/deps.py` | Add `code_map` and `quality_baseline` to `SecurityReviewDeps` | Low — additive |
| `passes/holistic.py` | Prepend structural overview from `code_map` to LLM prompt | Medium — prompt change |
| `passes/triage.py` | Wire `quality_baseline` into deps (no behaviour change yet) | Low — additive |
| `passes/config_review.py` | Wire `quality_baseline` into deps (no behaviour change yet) | Low — additive |

**Files NOT changed:**
- `passes/batching.py` — still sorts by `security_weight`, float comparison works identically
- `passes/sast.py` — doesn't use security weights
- `passes/merge.py` — uses `build_exposure_index()` which does `security_weight / 10.0` — works with floats unchanged
- `priority.py` — `build_exposure_index()` normalises `security_weight / 10.0` → this already handles floats correctly, no change needed
- `sarif/`, `tools/`, `agents/*/agent.py`

---

## 4. Implementation Steps

### Step 1: Update `models/inventory.py`

```python
class FileEntry(BaseModel):
    path: str = Field(min_length=1)
    language: str
    size_bytes: int = Field(ge=0)
    security_weight: float = Field(ge=0.0, le=10.0)  # was int
    estimated_tokens: int = Field(ge=0)
    unsafe_pattern_count: int = Field(ge=0, default=0)  # NEW
```

### Step 2: Update `passes/pipeline.py`

Add to `PipelineState`:
```python
    # Pass 1 outputs
    manifest: FileManifest | None = None
    batch_plan: BatchPlan | None = None
    code_map: dict | None = None
    quality_baseline: dict | None = None
```

### Step 3: Update `agents/deps.py`

Add to `SecurityReviewDeps`:
```python
    code_map: dict | None = None
    quality_baseline: dict | None = None
```

### Step 4: Rewrite `passes/inventory.py`

Remove:
- `_SECURITY_WEIGHT_PATTERNS` (25 regex patterns)
- `_compute_security_weight()` function
- The `content = file_path.read_text(...)[:4096]` block

Add:
- Import `code_intel` analysis functions
- After file discovery, pass the discovered file list TO code_intel (single source of truth for file scope)
- Call `analyze()` once — it does parsing, PageRank, unsafe detection, and quality metrics in one pass
- Map code_intel results back to `FileEntry` objects
- Store `code_map` and `quality_baseline` on state
- Wrap code_intel in try/except — on failure, fall back to keyword-based `_fallback_weight()`

```python
async def run_inventory(state: PipelineState) -> None:
    # 1. File discovery (keep existing _walk_files — single source of truth)
    target = state.target_path.resolve()
    max_size = state.config.sast.scanner_max_file_size_bytes
    all_files = _walk_files(target, max_size)

    # 2. Run code_intel on the SAME file list (no separate discovery)
    intel = None
    try:
        from security_review.code_intel import analyze_files
        # Only pass Python/C# files to code_intel — it can't analyse config/yaml
        code_files = [f for f in all_files if f.suffix in (".py", ".cs")]
        if code_files:
            intel = analyze_files(code_files, target)
    except Exception as e:
        logger.warning("inventory.code_intel_failed", error=str(e))
        # Pipeline continues with fallback weights — code_intel is not critical

    # 3. Build file entries using code_intel weights where available
    entries = []
    for file_path in all_files:
        rel_path = str(file_path.relative_to(target)).replace("\\", "/")
        ext = file_path.suffix.lower()
        language = _EXTENSION_LANGUAGE.get(ext, "other")
        size_bytes = file_path.stat().st_size
        estimated_tokens = max(1, size_bytes // _CHARS_PER_TOKEN)

        # code_intel weight for Python/C#, fallback for config/other
        weight_info = intel.weights.get(rel_path) if intel else None
        if weight_info:
            security_weight = weight_info.total
            unsafe_count = len(weight_info.unsafe_patterns)
        else:
            security_weight = _fallback_weight(file_path, language)
            unsafe_count = 0

        entries.append(FileEntry(
            path=rel_path, language=language,
            size_bytes=size_bytes, security_weight=security_weight,
            estimated_tokens=estimated_tokens,
            unsafe_pattern_count=unsafe_count,
        ))

    entries.sort(key=lambda e: e.security_weight, reverse=True)

    state.manifest = FileManifest(...)

    # 4. Store code_intel outputs for downstream passes
    if intel:
        state.code_map = intel.export_map()      # renamed from render_json
        state.quality_baseline = intel.quality_summary
```

**Key design decisions:**
- **Single file discovery:** `_walk_files()` remains the only file discovery function. code_intel receives a pre-filtered file list via `analyze_files()`, never runs its own `collect_files()`. This prevents mismatched file sets.
- **Graceful degradation:** If code_intel fails (tree-sitter crash, timeout, import error), the pipeline logs a warning and continues with `_fallback_weight()`. code_intel is an enhancement, not a gate.
- **One `analyze()` call:** code_intel parses each file once and returns `CodeIntelResult` with all data (modules, graph, ranks, unsafe patterns, metrics, weights). No triple-parsing.
- **Fallback for non-code files:** Config files, Dockerfiles, YAML — these don't go through code_intel. `_fallback_weight()` is extracted from the existing `_compute_security_weight()` lines 184-205 (the filename-based heuristics like `"controller" in name_lower` → +3). The content regex scanning (lines 207-214) is dropped — code_intel's AST analysis replaces it.

**Performance note:** `analyze_files()` runs `ast.parse()` on every Python file and `tree_sitter.parse()` on every C# file, then computes PageRank. On a 10,000-file codebase expect ~5-15 seconds added to Pass 1. This is a one-time cost that replaces the per-file 4KB regex scanning, and the improved weight quality justifies it.

### Step 5: Update `passes/holistic.py`

Prepend structural overview to the holistic review prompt. Token budget comes from config (not hardcoded).

```python
async def run_holistic(state: PipelineState) -> None:
    ...
    # Build structural context for the LLM
    structural_context = ""
    if state.code_map:
        from security_review.code_intel import render_structural_overview
        # Token budget: 1/4 of max_tokens_per_batch, leaves 3/4 for source code
        overview_budget = state.config.llm.max_tokens_per_batch // 4
        structural_context = render_structural_overview(
            state.code_map, max_tokens=overview_budget,
        )
    ...
```

The `render_structural_overview()` returns a Markdown string with:
- File ranking by PageRank (top N files)
- Class hierarchies with base types
- Import dependency arrows
- Circular dependency warnings

Trimmed progressively if it exceeds the token budget (low-rank files removed first).

### Step 6: Wire deps in `passes/triage.py`, `passes/holistic.py`, `passes/config_review.py`

All three passes construct `SecurityReviewDeps`. Add the new fields:

```python
deps = SecurityReviewDeps(
    config=state.config,
    manifest=state.manifest,
    sast_sarif=state.sast_sarif or {},
    cost_tracker=state.cost_tracker,
    target_path=state.target_path,
    run_id=state.run_id,
    code_map=state.code_map,              # NEW
    quality_baseline=state.quality_baseline,  # NEW
    batch_id=batch.batch_id,
)
```

---

## 5. Import Strategy

`scripts/code_intel.py` is a standalone 1100-line script. Move the engine into the package, keep the script as a thin CLI wrapper.

```
src/security_review/code_intel/
├── __init__.py      # re-exports analyze(), analyze_files(), CodeIntelResult
└── engine.py        # everything: types, parsers, graph, quality, weights, renderer
                     # (moved from scripts/code_intel.py, minus CLI)

scripts/code_intel.py → thin CLI wrapper (~30 lines):
    from security_review.code_intel import analyze
    # argparse CLI only
```

Start with 2 files. Split `engine.py` further only if it exceeds 500 lines of any single concern.

**New entry point for pipeline integration:**

```python
# src/security_review/code_intel/__init__.py

from security_review.code_intel.engine import (
    analyze,                    # standalone analysis (discovers own files)
    analyze_files,              # NEW: accepts pre-discovered file list
    CodeIntelResult,
    render_markdown,            # existing — full report
    render_structural_overview, # NEW — holistic-pass subset of render_markdown
)

# Renamed from render_json to avoid collision with reporting/json_export.render_json
from security_review.code_intel.engine import render_json as export_map
```

**Functions to CREATE during the move (do not exist yet):**

- `analyze_files(files, target_root)` — like `analyze()` but skips `collect_files()`, uses caller's file list
- `render_structural_overview(code_map, max_tokens)` — extracts the Structure section from `render_markdown()` output (file rankings, class hierarchies, import graph). Does NOT include unsafe patterns or quality baseline (those are already on deps separately). Uses existing `_trim_to_budget()` for token limiting.
- `CodeIntelResult.export_map()` — method wrapper around existing `render_json()`, renamed to avoid collision

**`analyze_files()` — the pipeline entry point:**

```python
def analyze_files(files: list[Path], target_root: Path) -> CodeIntelResult:
    """Run code_intel on a pre-discovered file list.

    Unlike analyze(), this does NOT call collect_files(). The caller
    (passes/inventory.py) provides the authoritative file list.
    This prevents mismatched file sets between inventory and code_intel.
    """
```

---

## 6. What NOT to Change

- **Batching logic** — `passes/batching.py` sorts by `security_weight` and partitions by tokens. Works identically with float weights.
- **Priority scoring** — `priority.py`'s `build_exposure_index()` does `security_weight / 10.0`. Works with floats unchanged. No change needed.
- **SAST pass** — doesn't use security weights at all. Runs tools based on file extension.
- **Agent prompts** — the triage/holistic/config prompts in `config/prompts/` stay the same. The structural overview is prepended in code, not baked into the prompt template.
- **SARIF output** — security weight is not in SARIF. No SARIF changes.
- **`_walk_files()` and `_EXCLUDE_DIRS`** — file discovery stays the same. code_intel receives the inventory's file list via `analyze_files()` — it does NOT run its own `collect_files()`. Single source of truth for file scope.
- **code_intel's `collect_files()`** — still exists for standalone CLI usage (`python scripts/code_intel.py --target .`), but is NOT called by the pipeline.

---

## 7. Testing

### Before/After Comparison

Run on the same target codebase and compare:

```bash
# Before: current keyword-based weights
python security-review.py review --target /path/to/target --mode sast -v 2>&1 | tee before.log

# After: code_intel weights
python security-review.py review --target /path/to/target --mode sast -v 2>&1 | tee after.log

# Compare file ordering
diff <(grep "security_weight" before.log) <(grep "security_weight" after.log)
```

### Specific Assertions

| Test | Expected |
|---|---|
| `test_inventory_weight_uses_pagerank` | A utility imported by 20+ files scores higher than an isolated file with `eval` |
| `test_inventory_weight_unsafe_patterns` | Files with BinaryFormatter/pickle/eval get `unsafe_score > 0` |
| `test_inventory_weight_surface` | Controllers/endpoints get `surface_score > 0` |
| `test_inventory_weight_quality_penalty` | Files with <30% type coverage get `quality_penalty > 0` |
| `test_inventory_code_map_stored` | `state.code_map` is populated after Pass 1 |
| `test_inventory_quality_baseline_stored` | `state.quality_baseline` is populated after Pass 1 |
| `test_holistic_receives_structural_context` | Holistic LLM prompt contains "Codebase Structure" section |
| `test_config_files_still_weighted` | Config files (no code_intel) still get reasonable weights via fallback |
| `test_batching_works_with_float_weights` | Batching sorts correctly with float security_weight |

### Regression

The existing `test_inventory_excludes_generated` test must still pass — file exclusion logic is unchanged.

---

## 8. Rollback

If code_intel integration causes issues:
- Revert `passes/inventory.py` to the keyword-based `_compute_security_weight()`
- Remove `code_map` and `quality_baseline` from `PipelineState` and `SecurityReviewDeps`
- The structural overview in holistic.py is additive — removing it degrades quality but doesn't break the pipeline

No data migration needed. No schema changes in SARIF output.

---

## 9. Implementation Order

1. **Move engine:** Move code_intel engine to `src/security_review/code_intel/` (`__init__.py` + `engine.py`)
2. **Add `analyze_files()`:** New entry point that accepts a pre-discovered file list (no `collect_files()`)
3. **Rename `render_json` → `export_map`:** Avoid collision with `reporting/json_export.render_json`
4. **Update `models/inventory.py`:** `security_weight: int` → `float`, add `unsafe_pattern_count`
5. **Update `passes/pipeline.py`:** Add `code_map`, `quality_baseline` to `PipelineState`
6. **Update `agents/deps.py`:** Add `code_map`, `quality_baseline` to `SecurityReviewDeps`
7. **Rewrite `passes/inventory.py`:** Replace `_compute_security_weight` with code_intel, add try/except fallback
8. **Update `passes/holistic.py`:** Prepend structural overview with configurable token budget
9. **Wire deps:** Add `code_map` and `quality_baseline` in `passes/triage.py`, `passes/holistic.py`, `passes/config_review.py`
10. **Update `scripts/code_intel.py`:** Thin CLI wrapper importing from the package
11. **Run before/after comparison** on a real codebase
12. **Write tests**
