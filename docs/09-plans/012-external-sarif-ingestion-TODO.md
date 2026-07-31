# Plan 012 — External SARIF Ingestion Mode

**Date:** 2026-05-17
**Status:** [ ] Draft — not implemented
**Depends on:** None (uses existing triage infrastructure)
**Research:** [008-Pentest Toolchain Research](../98-research/008-The%202025–2026%20Command-Line%20Web%20Application%20Penetration%20Testing%20Toolchain%2C%20with%20LLM-Assisted%20Verification.md)

---

## Problem

SCAR's triage pass (Pass 3) is a sophisticated LLM-powered finding triager: it reads source code, traces data flow, and assigns CONFIRMED/FALSE_POSITIVE/NEEDS_CONTEXT verdicts with confidence scores and rationale. But it only processes findings from SCAR's own SAST pass (Pass 2).

Teams running external scanners — Nuclei, Dalfox, ZAP, Snyk, Checkmarx, or any SARIF-producing tool — have no way to feed those findings through SCAR's triage pipeline. They must triage manually or build a separate pipeline.

The pentest toolchain research describes the practical recipe as: "JSONL output → Python orchestrator → Anthropic/OpenAI API with PydanticAI for triage." SCAR already does this internally — it just needs an external entry point.

### What makes SCAR's triage better than a generic LLM pipeline

1. **Source code context** — SCAR reads the actual source file at the finding's location and inlines it in the triage prompt. A generic DAST triager only sees the HTTP request/response.
2. **Priority scoring** — SCAR computes priority = severity x confidence x exposure, where exposure comes from file security weight.
3. **CWE taxonomy** — findings are tagged with normalised CWE IDs and the output includes the CWE taxonomy block.
4. **Structured audit trail** — every LLM decision is recorded in triage.json.

---

## Solution

Add a `--ingest` CLI command that accepts one or more external SARIF or JSONL files, merges them into SCAR's pipeline, and runs them through the existing triage and priority-scoring passes. The target codebase must be provided so SCAR can read source files for context.

```bash
# Triage external Nuclei findings with source code context
python scar.py ingest --target ../my-app --input nuclei.sarif --provider claude:claude-opus

# Triage multiple scanner outputs
python scar.py ingest --target ../my-app --input nuclei.sarif --input zap.sarif --provider claude:claude-opus

# Ingest JSONL (Nuclei, Dalfox format)
python scar.py ingest --target ../my-app --input dalfox.jsonl --provider claude:claude-opus

# Ingest and also run SCAR's own SAST (merge everything)
python scar.py ingest --target ../my-app --input nuclei.sarif --mode full --provider claude:claude-opus
```

---

## Architecture

```
BEFORE (current):
  review --target → Pass 1 (inventory) → Pass 2 (SAST) → Pass 3 (triage) → ... → merge

AFTER (ingest mode):
  ingest --target --input → load external SARIF → Pass 1 (inventory) → [optional Pass 2] → Pass 3 (triage) → merge
                                                                         ↑
                                                                 external findings injected
                                                                 into state.sast_sarif
```

### Key design decisions

1. **No new triage logic** — external findings flow through the same `run_triage()`. The only new code is the SARIF/JSONL loader and the CLI command.
2. **Inventory still runs** — SCAR needs the file manifest to compute exposure scores and to read source files for triage context.
3. **SAST is optional** — `--mode sast` runs SCAR's own SAST before ingesting (useful for combining internal + external findings). Default: skip SAST, triage only external findings.
4. **JSONL adapter** — Nuclei and Dalfox output JSONL with different schemas. A thin adapter converts them to SARIF before merging.
5. **External findings are tagged** — each ingested finding gets `properties.tool_name` set to the source scanner name, so the triage prompt tells the LLM which scanner produced it.

---

## Codemap Reference

Read `.codemap/map.md` for the full type/method inventory. Key modules:

| Module | Role in this plan |
|---|---|
| `src/security_review/cli/review.py` (213 lines) | Reference for CLI command pattern |
| `src/security_review/sarif/loader.py` (189 lines) | `load_sarif()`, `load_sarif_from_string()` — already loads external SARIF |
| `src/security_review/sarif/merger.py` (103 lines) | `merge_sarif()` — deduplicates by (CWE, file, line) |
| `src/security_review/passes/triage.py` (351 lines) | `run_triage()` — unchanged, processes whatever is in `state.sast_sarif` |
| `src/security_review/passes/pipeline.py` (141 lines) | `run_pipeline()` — pipeline orchestrator, may need a new mode |
| `src/security_review/passes/state.py` (79 lines) | `PipelineState` — carries `sast_sarif` between passes |
| `src/security_review/passes/inventory.py` (284 lines) | `run_inventory()` — unchanged, provides file manifest |
| `src/security_review/context_builder.py` (116 lines) | `read_file_content()`, `format_context_window()` — used by triage |
| `src/security_review/sarif/converter.py` (256 lines) | Reference for SARIF conversion pattern |

---

## Phase 1 — JSONL-to-SARIF Adapter

### Task 1.1 — Add JSONL loader for Nuclei format

**File:** `src/security_review/sarif/converter.py` (extend existing)

Nuclei JSONL has one JSON object per line:
```json
{"template-id":"cve-2024-1234","info":{"name":"...","severity":"high","tags":["cve"],"classification":{"cwe-id":["CWE-89"]}},"matched-at":"https://target/path","host":"target","curl-command":"curl ...","matcher-name":"...","timestamp":"..."}
```

Add:
```python
def convert_nuclei_jsonl_to_sarif(jsonl_path: Path) -> SarifDocument:
    """Convert Nuclei JSONL output to SARIF 2.1.0.

    Reuses _wrap_sarif() helper (converter.py:229) which all existing
    converters (pip-audit, dotnet-vuln, sarif-v1) already use.
    """
```

Map fields:
- `template-id` → `ruleId`
- `info.severity` → `level` (critical/high→error, medium→warning, low/info→note)
- `info.classification.cwe-id[0]` → CWE tag
- `matched-at` → `artifactLocation.uri`
- `info.name` → `message.text`

### Task 1.2 — Add JSONL loader for Dalfox format

**File:** `src/security_review/sarif/converter.py` (extend existing)

Dalfox JSONL:
```json
{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","method":"GET","data":"https://target/search?q=%3Cscript%3E","param":"q","payload":"<script>","evidence":"...","cwe":"CWE-79","severity":"High"}
```

Add:
```python
def convert_dalfox_jsonl_to_sarif(jsonl_path: Path) -> SarifDocument:
    """Convert Dalfox JSONL output to SARIF 2.1.0.

    Reuses _wrap_sarif() helper from this module.
    """
```

Note: Dalfox also natively supports `--format sarif` — document this as the preferred approach.

### Task 1.3 — Auto-detect input format

**File:** `src/security_review/sarif/converter.py`

```python
def load_external_findings(path: Path) -> SarifDocument:
    """Load external scanner output, auto-detecting format.

    Supported formats:
    - SARIF 2.1.0 (.sarif, .json with $schema or version=2.1.0)
    - Nuclei JSONL (.jsonl with template-id field)
    - Dalfox JSONL (.jsonl with inject_type field)

    Raises SARIFError if format cannot be detected.
    """
```

---

## Phase 2 — CLI Command

### Task 2.1 — Add `ingest` CLI command

**File:** `src/security_review/cli/ingest.py` (new, ~120 lines)

```python
@cli.command()
@click.option("--target", required=True, type=click.Path(exists=True),
              help="Path to codebase root (for source code context during triage).")
@click.option("--input", "input_files", required=True, multiple=True,
              type=click.Path(exists=True),
              help="External SARIF or JSONL file(s) to triage.")
@click.option("--provider", default=None,
              help="LLM provider:model (e.g. claude:claude-opus).")
@click.option("--include-sast", is_flag=True,
              help="Also run SCAR's own SAST tools before triage.")
@click.option("--format", "report_format", default="summary",
              help="Report format: summary, full, json, csv, all.")
@click.option("--output", default=None, help="Output directory.")
@click.option("--verbose", "-v", is_flag=True)
@click.option("--debug", is_flag=True)
@click.option("--quiet", is_flag=True)
@click.option("--json-logs", is_flag=True)
@click.option("--no-file-log", is_flag=True)
@click.option("--trace", is_flag=True)
def ingest(target, input_files, provider, include_sast, report_format, output,
           verbose, debug, quiet, json_logs, no_file_log, trace):
    """Triage external scanner findings with LLM + source code context."""
```

### Task 2.2 — Pipeline integration

The `ingest` command:
1. Loads and converts all `--input` files via `load_external_findings()`
2. Merges them into a single SARIF document via `merge_sarif()`
3. Tags each finding with `properties.external_source = True` and `properties.tool_name`
4. Creates a `PipelineState` with mode `"ingest"` or `"ingest-sast"`
5. Runs `run_inventory()` (for file manifest and exposure scores)
6. Optionally runs `run_sast()` if `--include-sast`
7. Merges external SARIF into `state.sast_sarif`
8. Runs `run_triage()` — unchanged
9. Runs `run_merge()` — unchanged

### Task 2.3 — Register command in CLI

**File:** `src/security_review/cli/__init__.py`

Add at the bottom:
```python
import security_review.cli.ingest  # noqa: F401, E402
```

---

## Phase 3 — Pipeline Mode

### Task 3.1 — Add `ingest` mode to pipeline

**File:** `src/security_review/passes/pipeline.py`

Add to `run_pipeline()`:
```python
elif mode == "ingest":
    # Pass 3: Triage (external findings already in state.sast_sarif)
    progress(3, "triage", "running", "LLM triaging external findings...")
    await run_triage(state)
    ...
elif mode == "ingest-sast":
    # Pass 2: SAST + external merge
    progress(2, "sast", "running", "Running SAST tools...")
    await run_sast(state)
    # External findings already merged into state.sast_sarif by CLI
    # Pass 3: Triage
    ...
```

### Task 3.2 — Add mode to ReviewConfig

**File:** `src/security_review/config_schema.py`

Update mode validation:
```python
class ReviewConfig(BaseModel, extra="forbid"):
    mode: str = Field(default="full", pattern=r"^(full|sast|sast-triage|ingest|ingest-sast)$")
```

---

## Phase 4 — Testing

### Task 4.1 — Unit tests for JSONL converters

**File:** `tests/unit/test_sarif_converter.py` (extend existing)

- Test `convert_nuclei_jsonl_to_sarif()` with sample Nuclei JSONL
- Test `convert_dalfox_jsonl_to_sarif()` with sample Dalfox JSONL
- Test `load_external_findings()` auto-detection for SARIF, Nuclei JSONL, Dalfox JSONL
- Test that unknown format raises `SARIFError`

### Task 4.2 — Integration test for ingest command

**File:** `tests/integration/test_ingest.py` (new)

- Run `scar.py ingest --target eval/python/cwe-089-sql-injection --input test_nuclei.jsonl --provider ...`
- Verify triage output contains verdicts for ingested findings
- Verify findings have `properties.external_source = True`

### Task 4.3 — Test fixtures

Create sample JSONL files in `tests/fixtures/`:
- `nuclei_sample.jsonl` — 3 Nuclei findings (1 true positive, 1 false positive, 1 info)
- `dalfox_sample.jsonl` — 2 Dalfox XSS findings
- `external_sample.sarif` — valid SARIF 2.1.0 from a hypothetical scanner

---

## Goal

```
/goal Implement Plan 012 (external SARIF ingestion). Goal is reached when:
1. src/security_review/sarif/converter.py has convert_nuclei_jsonl_to_sarif() and convert_dalfox_jsonl_to_sarif() functions
2. src/security_review/sarif/converter.py has load_external_findings() with auto-detection for SARIF, Nuclei JSONL, and Dalfox JSONL
3. src/security_review/cli/ingest.py exists with a Click command registered in cli/__init__.py
4. python scar.py ingest --help shows all options (--target, --input, --provider, --include-sast, --format, --verbose, --debug)
5. src/security_review/config_schema.py ReviewConfig.mode accepts "ingest" and "ingest-sast"
6. src/security_review/passes/pipeline.py handles mode="ingest" (skip SAST, run triage on external findings)
7. tests/unit/ has tests for the JSONL converters and format auto-detection
8. pytest tests/unit/ -v passes with zero failures
9. Existing review command is completely unchanged — python scar.py review --help output is identical
Stop after 25 turns.
```

---

## Acceptance Criteria

1. `scar.py ingest --target ... --input nuclei.sarif` produces a triaged SARIF report
2. `scar.py ingest --target ... --input nuclei.jsonl` auto-detects Nuclei JSONL and converts
3. External findings are tagged with `properties.external_source` and `properties.tool_name`
4. Triage uses source code context from `--target` (not just the scanner output)
5. Priority scoring includes exposure from the file manifest
6. Multiple `--input` files are merged and deduplicated
7. `--include-sast` runs SCAR's own SAST and merges with external findings
8. `pytest tests/unit/ -v` passes
9. Existing `review` command is unchanged
