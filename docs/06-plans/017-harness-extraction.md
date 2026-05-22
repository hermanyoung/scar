# Plan 017 — Harness Extraction

**Date:** 2026-05-17
**Status:** Draft
**Depends on:** None (prerequisite for Plan 016)
**Blocks:** Plan 016 (DART)

---

## Problem

`src/security_review/` contains two kinds of code in one package:

1. **Infrastructure** (~4,561 lines) — LLM providers, SARIF processing, reporting, cost tracking, output parsing, tool execution. This code is provider-specific, hard-won (Copilot SDK pinning, JSON repair, temperature workarounds), and actively maintained. It has zero knowledge of security code review.

2. **SAST pipeline** (~4,248 lines) — passes, agents, CWE checks, source file inlining, config review. This code is specific to static analysis of source code.

Both live in `security_review.*`. When Plan 016 (DART) adds a DAST pipeline, it needs the infrastructure but not the SAST pipeline. Today, DART would have to either fork (maintaining two copies of every provider fix) or import from `security_review.*` (coupling a DAST tool to a SAST package name).

The fix is to extract the infrastructure into `src/harness/` so both `src/scar/` and `src/dart/` import from a shared, product-agnostic package.

---

## Solution

Mechanical refactoring in three steps:
1. Move infrastructure modules from `src/security_review/` to `src/harness/`
2. Rename remaining SAST modules from `src/security_review/` to `src/scar/`
3. Update all imports (find-and-replace, no logic changes)

No behavior changes. Every function, every class, every test must produce identical results before and after.

---

## What moves where

### `src/harness/` (extracted from `src/security_review/`)

| Module | Lines | Notes |
|---|---|---|
| `providers.py` | 167 | `build_model()` dispatch. Import of `LLMConfig` changes to `harness.config_schema` |
| `model_providers.py` | 146 | SDK factories. Import of `get_settings` changes |
| `claude_model.py` | 212 | Unchanged |
| `copilot_model.py` | 425 | Unchanged |
| `codex_model.py` | 216 | Unchanged |
| `model_settings.py` | 79 | Import of `LLMConfig` changes |
| `model_capabilities.py` | 109 | Unchanged |
| `output_parser.py` | ~270 | **Split required** — triage + holistic parsers move to harness; config review parser stays in scar (imports `ConfigReviewResult`) |
| `budget.py` | 128 | Import of `errors` changes |
| `priority.py` | ~100 | **Split required** — `PriorityScore`, `score_finding()`, `_lookup_exposure()` move to harness; `build_exposure_index(manifest: FileManifest)` stays in scar (imports `FileManifest`) |
| `config.py` | 70 | **Split required** — see below |
| `errors.py` | 61 | Unchanged (no internal imports) |
| `evidence.py` | 71 | Unchanged |
| `logging.py` | 190 | Unchanged |
| `tracing.py` | 64 | Unchanged |
| `sarif/` (7 files) | 936 | **converter.py split required** — `_wrap_sarif()` + `convert_sarif_v1_to_v2()` stay in harness; `convert_pip_audit_to_sarif()` + `convert_dotnet_vuln_to_sarif()` move to `scar/sarif_adapters.py` |
| `reporting/` (7 files) | 711 | All imports change |
| `models/findings.py` | 210 | Import of `sarif.taxonomy` changes |
| `models/report.py` | 31 | Unchanged (no internal imports) |
| `models/coverage.py` | 54 | Moves to harness (generic concept, zero internal imports — used by `reporting/common.py`) |
| `prompts.py` | ~20 | **New** — `load_prompt()` extracted from `agents/deps.py` (shared utility, reads `config/prompts/`) |
| `tools/runner.py` | 108 | Import of `models.report`, `tools.registry` changes |
| `tools/registry.py` | 109 | Import of `errors` changes. **`_SPECS_DIR` default removed** — `specs_dir` becomes required parameter (no silent default) |
| `tools/redactor.py` | 54 | Import of `sarif.types` changes |
| **Total** | **~4,600** | |

### `src/scar/` (renamed from `src/security_review/`, minus harness modules)

| Module | Lines | Notes |
|---|---|---|
| `passes/` (9 files) | 2,101 | All `from security_review.X` → `from harness.X` or `from scar.X` |
| `agents/` (7 files) | 110 | All imports change |
| `checks.py` | 152 | Imports from `harness.errors`, `scar.models.inventory` |
| `context_builder.py` | 116 | Imports from `harness.logging` |
| `output_parser.py` | ~60 | `parse_config_review_response()` only (imports `scar.models.config_review`) |
| `priority.py` | ~34 | `build_exposure_index(manifest: FileManifest)` only (imports `scar.models.inventory`) |
| `sarif_adapters.py` | ~160 | `convert_pip_audit_to_sarif()`, `convert_dotnet_vuln_to_sarif()` (imports `harness.sarif.converter._wrap_sarif`) |
| `agents/deps.py` | ~30 | `SecurityReviewDeps` only (`load_prompt()` moved to harness) |
| `config_schema.py` | 108 | **Split required** — see below |
| `evaluation.py` | 534 | Imports from both `harness.*` and `scar.*` |
| `models/inventory.py` | 32 | Unchanged (no internal imports beyond pydantic) |
| `models/config_review.py` | 36 | Imports from `harness.models.findings` |
| `models/coverage.py` | 54 | Unchanged |
| `cli/` (9 files) | 960 | All imports change |
| `__init__.py` | 25 | Module root — path resolution |
| `__main__.py` | 11 | Entry point delegation |
| **Total** | **4,248** | |

---

## Modules that require splitting (5 modules)

### `config_schema.py` — split into shared + SAST-specific

**Current:** One file with `LLMConfig`, `ProviderConfig` (shared) and `SASTConfig`, `TriageConfig`, `ReviewConfig`, `SecurityReviewConfig` (SAST-specific).

**After:**

`src/harness/config_schema.py` (~72 lines):
```python
class ProviderConfig(BaseModel, extra="forbid"):
    max_concurrent: int
    session_timeout: float
    backoff_seconds: float

class LLMConfig(BaseModel, extra="forbid"):
    provider_model: str
    triage_model: str | None
    output_retries: int
    max_budget_usd: float
    max_tokens_per_batch: int
    concurrency: int
    cache_ttl: str | None
    thinking_budget: int | None
    temperature: float | None
    providers: dict[str, ProviderConfig]

    def provider_config(self, provider: str) -> ProviderConfig: ...
```

`src/scar/config_schema.py` (~50 lines):
```python
from harness.config_schema import LLMConfig  # shared

class SASTConfig(BaseModel, extra="forbid"): ...
class TriageConfig(BaseModel, extra="forbid"): ...
class ReviewConfig(BaseModel, extra="forbid"): ...

class SecurityReviewConfig(BaseModel, extra="forbid"):
    llm: LLMConfig  # from harness
    sast: SASTConfig
    triage: TriageConfig
    review: ReviewConfig
```

### `config.py` — split into shared + SAST-specific

**Current:** `Settings` (API keys from .env — shared) and `load_config()` (loads `security_review.yaml` — SAST-specific).

**After:**

`src/harness/config.py` (~40 lines):
```python
class Settings(BaseSettings):
    openai_api_key: str
    anthropic_api_key: str

@lru_cache
def get_settings() -> Settings: ...
```

`src/scar/config.py` (~35 lines):
```python
from harness.config import get_settings  # re-export for backward compat
from scar.config_schema import SecurityReviewConfig

def load_config(config_path: Path | None) -> SecurityReviewConfig: ...
```

### `priority.py` — split scoring engine from exposure builder

**Current:** `PriorityScore`, `score_finding()`, `_lookup_exposure()`, and `build_exposure_index(manifest: FileManifest)` in one file. `score_finding()` and `_lookup_exposure()` are generic (operate on `dict[str, float]`). Only `build_exposure_index()` imports `FileManifest`.

**After:**

`src/harness/priority.py` (~100 lines):
```python
# PriorityScore dataclass
# score_finding(level, file_path, exposure_index, triage_verdict, detection_method) -> PriorityScore
# _lookup_exposure(file_path, exposure_index) -> float
# _SEVERITY_SCORES, _CONFIDENCE_SCORES, _BANDS dicts
```

`src/scar/priority.py` (~34 lines):
```python
from harness.priority import score_finding, PriorityScore  # re-export
from scar.models.inventory import FileManifest

def build_exposure_index(manifest: FileManifest | None) -> dict[str, float]:
    """Build file_path -> exposure score from SAST file manifest."""
    if manifest is None:
        return {}
    return {entry.path: max(0.1, entry.security_weight / 10.0) for entry in manifest.files}
```

No signature changes to `score_finding()`. DART writes its own `build_url_exposure_index()` in `src/dart/priority.py`.

### `output_parser.py` — split triage/holistic from config review

**Current:** Contains `parse_triage_response()`, `parse_holistic_response()`, and `parse_config_review_response()`. The config review parser imports `ConfigReviewResult` from `models.config_review` (SCAR-specific).

**After:**

`src/harness/output_parser.py` (~270 lines):
```python
# parse_triage_response() — uses harness.models.findings.TriagedFinding
# parse_holistic_response() — uses harness.models.findings.HolisticReviewResult
# _try_json_triage(), _try_json_holistic()
# _parse_markdown_triage(), _parse_markdown_holistic()
# _parse_single_finding_section()
# _extract_json()
```

`src/scar/output_parser.py` (~60 lines):
```python
from harness.output_parser import _extract_json  # reuse JSON extraction
from scar.models.config_review import ConfigReviewResult

# parse_config_review_response() — uses scar.models.config_review.ConfigReviewResult
```

### `sarif/converter.py` — split generic wrapper from SAST-specific converters

**Current:** Contains `_wrap_sarif()` (generic SARIF document builder), `convert_sarif_v1_to_v2()` (generic), `convert_pip_audit_to_sarif()` (SAST-specific), `convert_dotnet_vuln_to_sarif()` (SAST-specific).

**After:**

`src/harness/sarif/converter.py` (~100 lines):
```python
# _wrap_sarif(tool_name, rules, results) -> SarifDocument  — generic builder
# convert_sarif_v1_to_v2(path) -> SarifDocument — generic
# _dotnet_severity_to_sarif(severity) -> str — helper
```

`src/scar/sarif_adapters.py` (~160 lines):
```python
from harness.sarif.converter import _wrap_sarif

# convert_pip_audit_to_sarif(json_path) -> SarifDocument
# convert_dotnet_vuln_to_sarif(json_path) -> SarifDocument
```

### `agents/deps.py` — extract `load_prompt()` to harness

**Current:** Contains `SecurityReviewDeps` (SCAR-specific dataclass) and `load_prompt()` (generic — reads markdown from `config/prompts/`). DART needs `load_prompt()` for its own prompts.

**After:**

`src/harness/prompts.py` (~20 lines, new):
```python
from harness import MODULE_ROOT
from harness.errors import ConfigurationError

def load_prompt(name: str, variant: str | None = None) -> str:
    """Load a prompt from config/prompts/{name}.md or config/prompts/{name}/{variant}.md."""
    base = MODULE_ROOT / "config" / "prompts"
    path = base / name / f"{variant}.md" if variant else base / f"{name}.md"
    if not path.exists():
        raise ConfigurationError(f"Prompt file not found: {path}", code="SYS_CONFIGURATION_ERROR")
    return path.read_text(encoding="utf-8")
```

`src/scar/agents/deps.py` (~30 lines):
```python
from harness.prompts import load_prompt  # re-export for existing callers
from scar.config_schema import SecurityReviewConfig
...
class SecurityReviewDeps: ...
```

### `models/findings.py` — import path change only (no split)

**Current:** `_valid_cwe_ids()` imports from `security_review.sarif.taxonomy`.

**After:** Import becomes `harness.sarif.taxonomy` — no split needed.

### `models/coverage.py` — moves to harness (reclassified)

**Current:** In `src/security_review/models/coverage.py`. The plan originally classified it as SCAR-specific.

**After:** Moves to `src/harness/models/coverage.py`. `CoverageReport` and `FileCoverage` are generic concepts (file type + detection layers) with zero internal imports. `reporting/common.py` imports it — since reporting is in harness, coverage must be too.

### `tools/registry.py` — remove default `_SPECS_DIR`

**Current:** `_SPECS_DIR = Path(__file__).resolve().parent / "specs"` — defaults to the directory next to registry.py.

**After:** Remove `_SPECS_DIR`. Make `specs_dir` parameter required in `load_tool_specs()` (no default). SCAR's `run_sast()` passes `scar_specs_dir`, DART's `run_scan()` passes `dart_specs_dir`. The harness never guesses where specs live. Follows "fail fast, no silent defaults" (P6).

### `__init__.py` — project root resolution

**Current:** `_find_project_root()` returns `MODULE_ROOT`.

**After:** Both `src/harness/__init__.py` and `src/scar/__init__.py` need root resolution. Extract the `.project_root` finder into `harness.__init__` and have `scar.__init__` import it.

---

## What does NOT move

These stay in `src/scar/` because they are SAST-specific:

| Module | Reason |
|---|---|
| `passes/*` | SAST pipeline orchestration |
| `agents/*` | SAST-specific LLM agents (triage, holistic, config_review). `load_prompt()` extracted to harness. |
| `checks.py` | CWE check registry with file-type matchers |
| `context_builder.py` | Source file reading and prompt inlining |
| `evaluation.py` | SAST eval/benchmark harness |
| `models/inventory.py` | `FileEntry`, `FileManifest` (source file metadata) |
| `models/config_review.py` | `ConfigFinding`, `ConfigReviewResult` |
| `cli/*` | SCAR CLI commands |
| `config_schema.py` (partial) | `SASTConfig`, `TriageConfig`, `ReviewConfig`, `SecurityReviewConfig` |
| `config.py` (partial) | `load_config()` for SAST YAML |
| `output_parser.py` (partial) | `parse_config_review_response()` |
| `priority.py` (partial) | `build_exposure_index(manifest: FileManifest)` |
| `sarif_adapters.py` (new) | `convert_pip_audit_to_sarif()`, `convert_dotnet_vuln_to_sarif()` |

---

## Phase 1 — Create `src/harness/` Package

### Task 1.1 — Create directory structure

```bash
mkdir -p src/harness/{sarif,reporting,models,tools}
```

### Task 1.2 — Move infrastructure modules

```bash
# Top-level modules
for f in providers.py model_providers.py claude_model.py copilot_model.py \
         codex_model.py model_settings.py model_capabilities.py \
         output_parser.py budget.py priority.py errors.py evidence.py \
         logging.py tracing.py; do
    cp src/security_review/$f src/harness/$f
done

# Subpackages
cp -r src/security_review/sarif/* src/harness/sarif/
cp -r src/security_review/reporting/* src/harness/reporting/
cp src/security_review/models/findings.py src/harness/models/findings.py
cp src/security_review/models/report.py src/harness/models/report.py
cp src/security_review/models/__init__.py src/harness/models/__init__.py
cp -r src/security_review/tools/* src/harness/tools/
```

### Task 1.3 — Split config_schema.py

Create `src/harness/config_schema.py` with `LLMConfig` and `ProviderConfig` only.

Update `src/security_review/config_schema.py` to import `LLMConfig` from `harness.config_schema`.

### Task 1.4 — Split config.py

Create `src/harness/config.py` with `Settings` and `get_settings()` only.

Update `src/security_review/config.py` to import from `harness.config`.

### Task 1.5 — Create `src/harness/__init__.py`

```python
"""Harness — shared LLM, SARIF, and reporting infrastructure."""
from pathlib import Path

def _find_project_root() -> Path:
    """Walk up from this file to find .project_root marker."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / ".project_root").exists():
            return current
        current = current.parent
    raise RuntimeError("Cannot find .project_root marker")

MODULE_ROOT = _find_project_root()
```

### Task 1.6 — Update all imports in `src/harness/`

Find-and-replace in all files under `src/harness/`:
```
from security_review.  →  from harness.
```

Verify no `from security_review.` imports remain in `src/harness/`.

---

## Phase 2 — Rename `src/security_review/` to `src/scar/`

### Task 2.1 — Rename the directory

```bash
mv src/security_review src/scar
```

### Task 2.2 — Delete modules that moved to harness

```bash
# These now live in src/harness/ — delete the copies in src/scar/
rm src/scar/providers.py src/scar/model_providers.py
rm src/scar/claude_model.py src/scar/copilot_model.py src/scar/codex_model.py
rm src/scar/model_settings.py src/scar/model_capabilities.py
rm src/scar/output_parser.py src/scar/budget.py src/scar/priority.py
rm src/scar/errors.py src/scar/evidence.py src/scar/logging.py src/scar/tracing.py
rm -rf src/scar/sarif/ src/scar/reporting/ src/scar/tools/
rm src/scar/models/findings.py src/scar/models/report.py
```

### Task 2.3 — Update all imports in `src/scar/`

Two replacements needed:

1. Modules that moved to harness:
```
from security_review.providers       →  from harness.providers
from security_review.budget          →  from harness.budget
from security_review.errors          →  from harness.errors
from security_review.sarif.loader    →  from harness.sarif.loader
from security_review.reporting.      →  from harness.reporting.
from security_review.models.findings →  from harness.models.findings
from security_review.tools.          →  from harness.tools.
...  (all harness modules)
```

2. Modules that stayed in scar:
```
from security_review.passes.    →  from scar.passes.
from security_review.agents.    →  from scar.agents.
from security_review.checks     →  from scar.checks
from security_review.cli.       →  from scar.cli.
from security_review.context_builder  →  from scar.context_builder
...  (all scar modules)
```

### Task 2.4 — Update `scar.py` entry point

```python
sys.path.insert(0, str(_root / "src"))
from scar.cli import cli  # was: from security_review.cli import cli
```

### Task 2.5 — Update `pyproject.toml`

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/harness", "src/scar"]

[project]
name = "security-code-review"
```

---

## Phase 3 — Update Config Files and References

### Task 3.1 — Update config paths in code

The harness `__init__.py` provides `MODULE_ROOT`. Config file references that use `MODULE_ROOT / "config"` remain correct since the project root doesn't change.

### Task 3.2 — Update AGENTS.md and CLAUDE.md

Replace references to `src/security_review/` with:
- `src/harness/` for infrastructure modules
- `src/scar/` for SAST pipeline modules

### Task 3.3 — Update docs

- `docs/01-architecture/001-system-architecture.md` — update directory layout and module map
- `docs/05-standards/01-python-coding-standards.md` — update layer boundary table
- `docs/04-rules/*.jsonl` — update file paths in check commands

### Task 3.4 — Update `.codemap/`

Regenerate codemap after the rename:
```bash
python scripts/code_map.py --scope src/harness,src/scar
```

---

## Phase 4 — Update Tests

### Task 4.1 — Restructure test directories

```
tests/
├── harness/          # Tests for shared infrastructure
│   ├── test_sarif_loader.py
│   ├── test_sarif_merger.py
│   ├── test_cwe_taxonomy.py
│   ├── test_output_parser.py
│   ├── test_priority.py
│   ├── test_findings_model.py
│   ├── test_tool_registry.py
│   └── test_coverage_model.py    # CoverageReport stays in scar, but findings model tests go here
├── scar/             # Tests for SAST pipeline
│   ├── test_inventory.py
│   ├── test_context_builder.py
│   ├── test_evaluation.py
│   ├── test_checks.py            # NEW — from Plan 014/015 additions
│   └── test_code_analysis/
├── conftest.py       # Shared fixtures, ALLOW_MODEL_REQUESTS=False
```

### Task 4.2 — Update all test imports

Same find-and-replace as production code:
```
from security_review.  →  from harness. or from scar.
```

### Task 4.3 — Verify all tests pass

```bash
pytest tests/ -v
```

Every test must produce the same result as before the refactoring.

---

## Phase 5 — Update Scripts

### Task 5.1 — Update scripts/ imports

```bash
grep -rl "from security_review" scripts/ | head -20
```

Update each script's imports. Scripts may import from both `harness.*` and `scar.*`.

### Task 5.2 — Update check_rules.py paths

`scripts/check_rules.py` hardcodes paths like `src/security_review/`. Update to check both `src/harness/` and `src/scar/`.

---

## Verification Checklist

After all phases:

1. `python scar.py --help` — identical output
2. `python scar.py review --target ../example-target --mode sast` — produces same SARIF
3. `python scar.py health-check` — all tools detected
4. `pytest tests/ -v` — all tests pass, zero failures
5. `grep -r "from security_review\." src/` — zero results (no old imports remain)
6. `grep -r "from harness\." src/scar/` — only imports shared infrastructure
7. `grep -r "from scar\." src/harness/` — zero results (harness never imports from scar)
8. `python scripts/check_rules.py --all` — all rules pass with updated paths

---

## Risk Mitigation

1. **Do this on a branch.** The rename touches every file. If something breaks, `git checkout main` restores everything.
2. **Run the full benchmark after.** `python scripts/benchmark_cwes.py --providers claude:claude-opus` — all 11 CWEs must still pass. Any regression means the refactoring broke something.
3. **No logic changes.** This is purely structural. If you find yourself changing function signatures, adding parameters, or modifying behavior — stop. That's a separate PR.
4. **Commit in phases.** Phase 1 (create harness), Phase 2 (rename scar), Phase 3 (config/docs), Phase 4 (tests), Phase 5 (scripts). Each phase should be a separate commit so you can bisect if something breaks.

---

## Goal

```
/goal Execute Plan 017 (harness extraction). Goal is reached when:
1. src/harness/ exists with providers.py, copilot_model.py, claude_model.py, codex_model.py, model_providers.py, model_settings.py, model_capabilities.py, budget.py, errors.py, evidence.py, logging.py, tracing.py, config.py, prompts.py, config_schema.py (LLMConfig + ProviderConfig only)
2. src/harness/output_parser.py has parse_triage_response() and parse_holistic_response() but NOT parse_config_review_response()
3. src/harness/priority.py has score_finding() and PriorityScore but NOT build_exposure_index()
4. src/harness/sarif/converter.py has _wrap_sarif() and convert_sarif_v1_to_v2() but NOT convert_pip_audit_to_sarif()
5. src/harness/sarif/ has loader.py, merger.py, converter.py, tags.py, taxonomy.py, types.py, normalise.py
6. src/harness/reporting/ has all renderer modules
7. src/harness/models/ has findings.py, report.py, coverage.py
8. src/harness/tools/ has runner.py, registry.py (specs_dir is required param, no default), redactor.py
9. src/scar/ exists with passes/, agents/, checks.py, context_builder.py, config_schema.py (SASTConfig etc.), evaluation.py, cli/, models/, output_parser.py (config review only), priority.py (build_exposure_index only), sarif_adapters.py (pip-audit + dotnet-vuln converters)
10. No module in src/harness/ imports from src/scar/ — grep returns zero results
11. No module in src/ uses "from security_review." — all old imports are gone
12. python scar.py --help output is identical to before
13. pytest tests/ -v passes with zero failures — same count, same results
Stop after 35 turns or if test count drops (indicates missing test migration).
```

---

## Acceptance Criteria

1. `src/harness/` contains all shared infrastructure (~4,561 lines)
2. `src/scar/` contains all SAST-specific code (~4,248 lines)
3. Zero imports from `security_review.*` remain anywhere in `src/`
4. Zero imports from `scar.*` in `src/harness/` (harness is product-agnostic)
5. `python scar.py review --target ... --mode sast` produces identical SARIF output
6. All tests pass with identical results
7. All 11 baseline CWEs still pass on benchmark
8. `pyproject.toml` builds both packages
