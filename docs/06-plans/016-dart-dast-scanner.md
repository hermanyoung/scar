# Plan 016 — DART: Dynamic Application Security Testing Scanner

**Date:** 2026-05-17
**Status:** Draft
**Depends on:** Plan 012 (external SARIF ingestion — for SCAR correlation), Plan 017 (harness extraction)
**Research:** [008-Pentest Toolchain Research](../98-research/008-The%202025–2026%20Command-Line%20Web%20Application%20Penetration%20Testing%20Toolchain%2C%20with%20LLM-Assisted%20Verification.md)

---

## Problem

SCAR is a SAST tool — it reviews source code. It cannot detect vulnerabilities that only manifest at runtime: missing HTTP security headers, CORS misconfigurations, exposed endpoints that aren't referenced in code, default credentials on deployed services, or CVEs in running server software.

The pentest toolchain research describes a production DAST pipeline: authenticated crawling (Katana) → parameter discovery (Arjun) → vulnerability scanning (Nuclei + Dalfox + sqlmap) → LLM-assisted triage. Every component exists as a mature CLI tool. What's missing is an orchestrator that ties them together with structured output and LLM triage — the same gap SCAR fills for SAST.

### Why a separate product, same repo

SCAR's primitive is the **source file**. DART's primitive is the **HTTP request/response pair**. These are different systems with different safety profiles, auth models, and operational contexts (see session discussion). They need separate entry points, separate pipelines, and separate CLI commands.

But they share a **substantial, hard-won LLM harness** (~3,750 lines):

- **Provider layer** (1,812 lines) — 5 providers (claude, copilot, anthropic, openai, codex), each with SDK-specific workarounds (Copilot 0.2.2 pinning, temperature not supported, JSON repair, session timeouts). Months of debugging.
- **Output parser** (330 lines) — JSON-first + markdown-fallback strategy that works across all providers. The triage response format (verdict/confidence/rationale) is identical for SAST and DAST.
- **SARIF processing** (669 lines) — loader, merger, converter, tags, taxonomy, types.
- **Reporting** (492 lines) — terminal, markdown, JSON, CSV renderers.
- **Infrastructure** (447 lines) — budget/pricing, errors, evidence, logging, tracing.

This shared code is not commodity — it's the most complex and actively maintained part of the system. Forking it means maintaining two copies of every provider fix, every SDK upgrade, every model alias update. A monorepo with a shared harness package keeps it in one place.

### Monorepo structure (after Plan 017 extraction)

```
security-code-review/
├── src/harness/                  # Shared LLM + SARIF harness (~3,750 lines)
│   ├── providers.py              # build_model() dispatch
│   ├── model_providers.py        # SDK factories (Anthropic, OpenAI, Codex)
│   ├── claude_model.py           # Claude Agent SDK wrapper
│   ├── copilot_model.py          # Copilot SDK wrapper (0.2.2 pinned)
│   ├── codex_model.py            # Codex wrapper
│   ├── model_settings.py         # Provider-specific ModelSettings
│   ├── model_capabilities.py     # Native JSON detection per model
│   ├── output_parser.py          # JSON-first, markdown-fallback
│   ├── budget.py                 # Cost tracking from pricing.yaml
│   ├── priority.py               # Base priority scoring (severity x confidence x exposure)
│   ├── config.py                 # .env + YAML loading
│   ├── errors.py                 # Error taxonomy
│   ├── evidence.py               # SHA-256 evidence manifest
│   ├── logging.py                # structlog config
│   ├── tracing.py                # Per-agent traces
│   ├── sarif/                    # Full SARIF package (loader, merger, converter, tags, taxonomy, types)
│   ├── reporting/                # All renderers (terminal, markdown, JSON, CSV, common, dispatcher)
│   ├── models/                   # findings.py (TriagedFinding, verdicts), report.py (ToolResult)
│   └── tools/                    # runner.py, registry.py, redactor.py (subprocess execution)
│
├── src/scar/                     # SAST pipeline (~3,900 lines, imports from harness)
│   ├── passes/                   # inventory, sast, triage, holistic, config_review, merge, pipeline
│   ├── agents/                   # triage, holistic, config_review agents
│   ├── checks.py                 # CWE check registry, file type matchers
│   ├── context_builder.py        # Source file inlining for LLM prompts
│   ├── config_schema.py          # SAST-specific config (LLMConfig, SASTConfig, etc.)
│   ├── evaluation.py             # Eval/benchmark harness
│   ├── models/                   # inventory.py, config_review.py, coverage.py
│   └── cli/                      # review, test-cwe, test-providers, eval, reports, tools, quality
│
├── src/dart/                     # DAST pipeline (NEW, imports from harness)
│   ├── passes/                   # target, crawl, scan, triage, merge, pipeline
│   ├── agents/                   # dast_triage agent
│   ├── context_builder.py        # HTTP request/response formatting for LLM prompts
│   ├── config_schema.py          # DAST-specific config (DASTConfig, ScanConfig, etc.)
│   ├── priority.py               # URL-based exposure scoring (extends harness.priority)
│   ├── models/                   # target.py (TargetInfo), crawl.py (CrawlResult)
│   ├── tools/specs/              # nuclei.yaml, httpx.yaml, katana.yaml, dalfox.yaml
│   └── cli/                      # scan, health-check
│
├── config/
│   ├── .env                      # API keys (shared)
│   ├── models.yaml               # Model aliases (shared)
│   ├── pricing.yaml              # Token pricing (shared)
│   ├── settings/
│   │   ├── scar.yaml             # SAST pipeline config (renamed from security_review.yaml)
│   │   ├── dart.yaml             # DAST pipeline config (NEW)
│   │   └── logging.yaml          # Shared logging config
│   ├── prompts/
│   │   ├── scar/                 # SAST prompts (moved from prompts/)
│   │   └── dart/                 # DAST prompts (NEW)
│   └── taxonomy/                 # CWE registry (shared)
│
├── scar.py                       # SAST entry point (existing, updated imports)
├── dart.py                       # DAST entry point (NEW)
└── pyproject.toml                # Three packages: harness, scar, dart
```

---

## Architecture

### DART pipeline: target → crawl → scan → triage → merge

```
dart.py (CLI entry point)
  │
  └── dart.passes.pipeline          run_pipeline()
        dart.passes.state            DASTPipelineState
        │
        ├── dart.passes.target       Pass 1: target validation + httpx probe
        │     └── dart/tools/specs/httpx.yaml
        │
        ├── dart.passes.crawl        Pass 2: authenticated crawling (optional)
        │     └── dart/tools/specs/katana.yaml
        │
        ├── dart.passes.scan         Pass 3: vulnerability scanning
        │     ├── dart/tools/specs/nuclei.yaml
        │     ├── dart/tools/specs/dalfox.yaml   (optional)
        │     └── harness.sarif.converter        JSONL → SARIF (reused)
        │
        ├── dart.passes.triage       Pass 4: LLM triage of scanner findings
        │     ├── dart.agents.dast_triage        (no tools — HTTP context inlined)
        │     ├── harness.output_parser          parse_triage_response() (reused)
        │     └── harness.providers              build_model() (reused)
        │
        └── dart.passes.merge        Final: SARIF merge + report
              ├── harness.sarif.taxonomy         (reused)
              ├── harness.sarif.merger           (reused)
              └── harness.reporting.dispatcher   (reused)
```

| Pass | Name | What it does | Tools | Output |
|---|---|---|---|---|
| 1 | **Target** | Validate URL, detect tech stack, check auth | httpx | `TargetInfo` (status, headers, tech) |
| 2 | **Crawl** | Authenticated crawling for URL/endpoint discovery | Katana | `CrawlResult` (URLs, forms, JS endpoints) |
| 3 | **Scan** | Run vulnerability scanners against discovered URLs | Nuclei, Dalfox | Merged SARIF |
| 4 | **Triage** | LLM reviews each finding with HTTP request/response context | LLM agent | Triaged SARIF |
| 5 | **Merge** | Final SARIF with CWE taxonomy + reports | — | SARIF + markdown + triage.json |

### Key design decisions

1. **Imports from harness, never from scar.** DART imports `from harness.providers import build_model`, `from harness.sarif.merger import merge_sarif`, etc. It never imports from `src/scar/`. The two products are siblings, not parent-child.
2. **Same tool runner** — `harness.tools.runner.run_tool()` is unchanged. DAST tools are YAML specs with `target_type: url`. `build_command()` substitutes `{target_url}` instead of `{target_path}`.
3. **Same SARIF interchange** — all scanner output is converted to SARIF 2.1.0 with CWE tags via `harness.sarif`. The merge pass, taxonomy injection, and reporting are identical.
4. **Same LLM triage pattern** — one finding per agent call, structured verdict (CONFIRMED/FALSE_POSITIVE/NEEDS_CONTEXT), parsed by `harness.output_parser.parse_triage_response()`. The difference is context: SCAR inlines source code, DART inlines HTTP request/response.
5. **Same budget tracking** — `harness.budget.CostTracker` records LLM spend. Same pricing.yaml. Same triage.json audit trail.
6. **Crawl is optional** — if the user provides a URL list, crawling is skipped. Nuclei accepts `-list urls.txt` directly.
7. **Auth is pass-through** — DART doesn't manage sessions, refresh tokens, or handle MFA. The user provides an `auth.txt` file (cookies/headers), DART passes it to tools via `-H @auth.txt`. This is the research's "browser-state-first strategy."
8. **No destructive operations by default** — Nuclei runs with `-severity medium,high,critical`. sqlmap is NOT included (too destructive). Dalfox is optional. The default scan is non-invasive.

---

## Prerequisite: Plan 017 (Harness Extraction)

This plan assumes `src/harness/` has been extracted from `src/security_review/` per Plan 017. If Plan 017 is not yet done, DART can temporarily import from `security_review.*` directly — but the extraction should happen before DART ships to avoid coupling the two products through SCAR's namespace.

---

## Phase 0 — Scaffold (Day 1)

### Task 0.1 — Create DART package

```bash
mkdir -p src/dart/{passes,agents/dast_triage,models,tools/specs,cli}
touch src/dart/__init__.py src/dart/passes/__init__.py src/dart/agents/__init__.py
touch src/dart/agents/dast_triage/__init__.py src/dart/models/__init__.py
touch src/dart/tools/__init__.py src/dart/cli/__init__.py
```

### Task 0.2 — Create entry point

**File:** `dart.py` (root, ~30 lines)

```python
#!/usr/bin/env python3
"""DART -- Dynamic Application Security Testing Scanner."""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent
_marker = _root / ".project_root"
if not _marker.exists():
    raise RuntimeError(f"Cannot find .project_root at {_root}")
sys.path.insert(0, str(_root / "src"))

from dart.cli import cli
cli()
```

### Task 0.3 — Create CLI skeleton

**File:** `src/dart/cli/app.py` (~30 lines)

```python
import click

@click.group()
@click.pass_context
def cli(ctx):
    """DART -- Dynamic Application Security Testing Scanner."""
    ctx.ensure_object(dict)
```

**File:** `src/dart/cli/__init__.py`

```python
"""DART CLI -- Click command group."""
from dart.cli.app import cli  # noqa: F401

def _setup_logging(verbose, debug, quiet, json_logs, no_file_log):
    # Same pattern as SCAR -- delegates to harness.logging
    from harness.logging import setup_logging
    level = "DEBUG" if debug else ("WARNING" if quiet else "INFO")
    setup_logging(level=level, format_type="json" if json_logs else "console",
                  enable_console=verbose or debug or json_logs,
                  enable_file_logging=not no_file_log)
    return {"verbose": verbose, "debug": debug, "quiet": quiet}

import dart.cli.scan  # noqa: F401, E402
```

### Task 0.4 — Add to pyproject.toml

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/harness", "src/scar", "src/dart"]
```

### Task 0.5 — Verify

```bash
python dart.py --help
```

---

## Phase 1 — Target Validation Pass

### Task 1.1 — Add httpx tool spec

**File:** `src/dart/tools/specs/httpx.yaml`

```yaml
# httpx -- HTTP probing and technology detection
# Options: -sc (status code), -tech-detect, -title, -ip, -server,
#          -H (headers), -mc (match codes), -fc (filter codes),
#          -jsonl (JSON lines output), -silent, -timeout
name: httpx
binary: httpx
version_cmd: ["httpx", "-version"]
output_format: jsonl
sarif_native: false
success_exit_codes: [0]
arg_template:
  - "{binary}"
  - -u
  - "{target_url}"
  - -sc
  - -tech-detect
  - -title
  - -ip
  - -server
  - -jsonl
  - -silent
  - -o
  - "{output_path}"
default_args: {}
output_capture: file
timeout_seconds: 30
target_type: url
applies_to: ["*"]
cwe_source: none
optional: false
```

### Task 1.2 — Create target models

**File:** `src/dart/models/target.py` (~40 lines)

```python
from dataclasses import dataclass

@dataclass
class TargetInfo:
    url: str
    status_code: int
    title: str
    tech_stack: list[str]
    server: str
    ip: str
    security_headers: dict[str, str]
    is_authenticated: bool
```

### Task 1.3 — Create target pass

**File:** `src/dart/passes/target.py` (~80 lines)

```python
"""Pass 1: Target validation and probing.

Verifies the target URL is reachable, detects technology stack,
and extracts HTTP security headers for baseline analysis.
"""
from harness.tools.runner import run_tool
from harness.tools.registry import load_tool_specs

async def run_target(state: DASTPipelineState) -> None:
    """Execute Pass 1: validate target and extract metadata."""
    # Load httpx spec from dart/tools/specs/
    # Run httpx probe
    # Parse JSONL output
    # Extract security headers (HSTS, CSP, X-Frame-Options, etc.)
    # Store in state.target_info
```

### Task 1.4 — Create pipeline state

**File:** `src/dart/passes/state.py` (~60 lines)

```python
from dataclasses import dataclass, field
from pathlib import Path
from harness.budget import CostTracker
from harness.evidence import EvidenceManifest
from harness.reporting.common import ReportData
from harness.sarif.types import SarifDocument
from harness.models.findings import TriageResult

@dataclass
class DASTPipelineState:
    config: DASTConfig
    target_url: str
    auth_file: Path | None
    work_dir: Path
    target_info: TargetInfo | None = None
    crawl_urls: list[str] | None = None
    crawl_enabled: bool = False
    scan_sarif: SarifDocument | None = None
    triage_result: TriageResult | None = None
    run_id: str = ""
    cost_tracker: CostTracker = field(default_factory=lambda: CostTracker(None))
    evidence: EvidenceManifest = field(default_factory=EvidenceManifest)
    on_progress: ProgressCallback = _noop_progress
    report_formats: list[str] = field(default_factory=lambda: ["summary"])
    report_data: ReportData | None = None
    trace_enabled: bool = False
```

---

## Phase 2 — Scan Pass (Nuclei Integration)

### Task 2.1 — Add Nuclei tool spec

**File:** `src/dart/tools/specs/nuclei.yaml`

```yaml
# Nuclei -- template-based vulnerability scanner
# Options: -u (URL), -list (URL list), -H (headers), -severity,
#          -tags, -jle (JSONL export), -nh (no httpx), -silent,
#          -rate-limit, -bulk-size, -concurrency, -timeout
name: nuclei
binary: nuclei
version_cmd: ["nuclei", "-version"]
output_format: jsonl
sarif_native: false
success_exit_codes: [0, 1]
arg_template:
  - "{binary}"
  - -u
  - "{target_url}"
  - -severity
  - "{severity_filter}"
  - -tags
  - "{tag_filter}"
  - -jle
  - "{output_path}"
  - -nh
  - -silent
  - -rate-limit
  - "{rate_limit}"
default_args:
  severity_filter: "medium,high,critical"
  tag_filter: "cve,kev,oast,exposure,misconfiguration,default-login"
  rate_limit: "100"
output_capture: file
timeout_seconds: 600
target_type: url
applies_to: ["*"]
cwe_source: template_metadata
optional: false
```

### Task 2.2 — Add Dalfox tool spec (optional)

**File:** `src/dart/tools/specs/dalfox.yaml`

```yaml
# Dalfox -- XSS vulnerability scanner
# Options: url, -C (cookie), --format (output format),
#          -o (output file), --silence, --delay
name: dalfox
binary: dalfox
version_cmd: ["dalfox", "version"]
output_format: jsonl
sarif_native: true
success_exit_codes: [0, 1]
arg_template:
  - "{binary}"
  - url
  - "{target_url}"
  - --format
  - jsonl
  - -o
  - "{output_path}"
  - --silence
default_args: {}
output_capture: file
timeout_seconds: 300
target_type: url
applies_to: ["*"]
cwe_source: metadata
optional: true
```

### Task 2.3 — Create scan pass

**File:** `src/dart/passes/scan.py` (~200 lines)

```python
"""Pass 3: Run DAST scanners against the target.

Loads DAST tool specs (target_type=url), runs them concurrently,
converts JSONL output to SARIF via harness.sarif.converter,
merges and deduplicates via harness.sarif.merger.
"""
from harness.tools.runner import run_tool
from harness.tools.registry import load_tool_specs
from harness.sarif.merger import merge_sarif
from harness.sarif.converter import _wrap_sarif  # reuse existing helper
from harness.errors import ScannerError

async def run_scan(state: DASTPipelineState) -> None:
    """Execute Pass 3: vulnerability scanning."""
    specs_dir = Path(__file__).resolve().parent.parent / "tools" / "specs"
    specs = load_tool_specs(specs_dir)
    dast_specs = [s for s in specs if s.target_type == "url"]
    ...
```

### Task 2.4 — Nuclei JSONL -> SARIF converter

**File:** `src/dart/sarif_adapters.py` (~100 lines)

```python
"""DAST scanner output adapters -- Nuclei JSONL, Dalfox JSONL to SARIF.

Reuses harness.sarif.converter._wrap_sarif() for SARIF document construction.
"""
from harness.sarif.converter import _wrap_sarif

def convert_nuclei_jsonl_to_sarif(jsonl_path: Path) -> SarifDocument:
    """Convert Nuclei JSONL output to SARIF 2.1.0."""
    # Read JSONL line by line
    # Map: template-id -> ruleId, info.severity -> level, info.classification.cwe-id -> CWE tag
    # Build rules dict and results list
    # Return _wrap_sarif("nuclei", rules, results)

def convert_dalfox_jsonl_to_sarif(jsonl_path: Path) -> SarifDocument:
    """Convert Dalfox JSONL output to SARIF 2.1.0."""
    # Map: inject_type -> ruleId, severity -> level, cwe -> CWE tag
    # Return _wrap_sarif("dalfox", rules, results)
```

---

## Phase 3 — DAST Triage Pass

### Task 3.1 — Create DAST triage agent

**File:** `src/dart/agents/dast_triage/agent.py` (~30 lines)

```python
from pydantic_ai import Agent

dast_triage_agent = Agent(
    output_type=str,
    system_prompt=(
        "You are a security engineer triaging a DAST scanner finding. "
        "You receive the scanner's detection details, the HTTP request "
        "that triggered the finding, and the server's response.\n\n"
        "Rules:\n"
        "1. Determine if this is a true positive, false positive, or needs "
        "   manual verification.\n"
        "2. Consider the scanner's template/detection logic -- is it reliable?\n"
        "3. Look at the response for actual evidence of the vulnerability.\n"
        "4. Consider whether the finding could be a WAF/CDN artifact.\n"
        "5. Provide a confidence score (0.0-1.0) and one-paragraph rationale.\n\n"
        "Respond with:\n"
        "**Verdict:** CONFIRMED | FALSE_POSITIVE | NEEDS_CONTEXT\n"
        "**Confidence:** 0.X\n"
        "**Rationale:** ..."
    ),
)
```

### Task 3.2 — Create DAST context builder

**File:** `src/dart/context_builder.py` (~80 lines)

DART's equivalent of SCAR's context_builder. Formats HTTP request/response pairs for LLM prompts:

```python
def format_dast_finding_context(finding: dict) -> str:
    """Format a DAST finding with HTTP context for LLM triage.

    Includes: scanner name, template ID, matched URL, severity,
    curl command (if available), response snippet, and scanner reasoning.
    """
```

### Task 3.3 — Create triage pass

**File:** `src/dart/passes/triage.py` (~250 lines)

Same architecture as SCAR's triage: one finding per agent call, concurrent batches, verdicts written back to SARIF by index. Reuses `harness.output_parser.parse_triage_response()` — the triage response format (verdict/confidence/rationale) is identical.

```python
from harness.output_parser import parse_triage_response
from harness.providers import build_model
from harness.model_settings import build_model_settings
from harness.budget import CostTracker
```

---

## Phase 4 — Crawl Pass (Optional)

### Task 4.1 — Add Katana tool spec

**File:** `src/dart/tools/specs/katana.yaml`

```yaml
# Katana -- authenticated web crawler
# Options: -u (URL), -headless, -system-chrome, -jc (JS crawl),
#          -jsl (JSLuice), -aff (auto form fill), -xhr (XHR extraction),
#          -d (depth), -H (headers), -j (JSONL output), -o (output file),
#          -cdp (Chrome DevTools Protocol), -silent
name: katana
binary: katana
version_cmd: ["katana", "-version"]
output_format: jsonl
sarif_native: false
success_exit_codes: [0]
arg_template:
  - "{binary}"
  - -u
  - "{target_url}"
  - -jc
  - -jsl
  - -xhr
  - -d
  - "{crawl_depth}"
  - -j
  - -o
  - "{output_path}"
  - -silent
default_args:
  crawl_depth: "3"
output_capture: file
timeout_seconds: 300
target_type: url
applies_to: ["*"]
cwe_source: none
optional: true
```

### Task 4.2 — Create crawl pass

**File:** `src/dart/passes/crawl.py` (~100 lines)

```python
"""Pass 2: Authenticated web crawling (optional).

Discovers URLs, forms, and JS endpoints via Katana.
Output feeds into the scan pass as a URL list for Nuclei.
"""
from harness.tools.runner import run_tool

async def run_crawl(state: DASTPipelineState) -> None:
    """Execute Pass 2: crawl target for URL discovery."""
    # Load katana spec from dart/tools/specs/
    # If katana not installed and optional, skip with warning
    # Run katana, parse JSONL output for discovered URLs
    # Store in state.crawl_urls
```

---

## Phase 5 — CLI, Pipeline, Config

### Task 5.1 — Create DAST config schema

**File:** `src/dart/config_schema.py` (~60 lines)

```python
from pydantic import BaseModel, Field

class ScanConfig(BaseModel, extra="forbid"):
    severity_filter: str = Field(default="medium,high,critical")
    tag_filter: str = Field(default="cve,kev,oast,exposure,misconfiguration,default-login")
    rate_limit: int = Field(default=100)
    scanner_timeout_seconds: int = Field(default=600)

class CrawlConfig(BaseModel, extra="forbid"):
    depth: int = Field(default=3)
    timeout_seconds: int = Field(default=300)

class DASTConfig(BaseModel, extra="forbid"):
    llm: LLMConfig  # imported from harness.config_schema -- SHARED
    scan: ScanConfig
    crawl: CrawlConfig
    output_dir: str = Field(default="var/output")
```

### Task 5.2 — Create DAST config file

**File:** `config/settings/dart.yaml`

```yaml
# ============================================================
# DART Configuration
# ============================================================
# llm:
#   provider_model: str     -- LLM provider:model for triage
#   output_retries: int     -- retries on parse failure (default: 3)
#   max_budget_usd: float   -- informational budget cap
#   concurrency: int        -- concurrent triage calls
# scan:
#   severity_filter: str    -- Nuclei severity filter
#   tag_filter: str         -- Nuclei template tag filter
#   rate_limit: int         -- requests per second
#   scanner_timeout_seconds: int
# crawl:
#   depth: int              -- Katana crawl depth
#   timeout_seconds: int
# ============================================================

llm:
  provider_model: "claude:claude-opus"
  output_retries: 3
  max_budget_usd: 10.0
  concurrency: 5

scan:
  severity_filter: "medium,high,critical"
  tag_filter: "cve,kev,oast,exposure,misconfiguration,default-login"
  rate_limit: 100
  scanner_timeout_seconds: 600

crawl:
  depth: 3
  timeout_seconds: 300
```

### Task 5.3 — Create scan CLI command

**File:** `src/dart/cli/scan.py` (~150 lines)

```python
@cli.command()
@click.option("--url", required=True, help="Target URL to scan.")
@click.option("--auth", "auth_file", default=None,
              type=click.Path(exists=True),
              help="Auth file with Cookie/Authorization headers.")
@click.option("--provider", default=None,
              help="LLM provider:model for triage (e.g. claude:claude-opus).")
@click.option("--crawl/--no-crawl", default=False,
              help="Crawl target for URL discovery before scanning.")
@click.option("--crawl-depth", type=int, default=3,
              help="Crawler depth (default: 3).")
@click.option("--severity", default="medium,high,critical",
              help="Nuclei severity filter.")
@click.option("--tags", default="cve,kev,oast,exposure,misconfiguration,default-login",
              help="Nuclei template tags.")
@click.option("--rate-limit", type=int, default=100,
              help="Requests per second limit.")
@click.option("--format", "report_format", default="summary",
              help="Report format: summary, full, json, csv, all.")
@click.option("--output", default=None, help="Output directory.")
@click.option("--verbose", "-v", is_flag=True)
@click.option("--debug", is_flag=True)
@click.option("--quiet", is_flag=True)
@click.option("--json-logs", is_flag=True)
@click.option("--no-file-log", is_flag=True)
@click.option("--trace", is_flag=True)
def scan(url, auth_file, provider, crawl, crawl_depth, severity, tags,
         rate_limit, report_format, output, verbose, debug, quiet,
         json_logs, no_file_log, trace):
    """Scan a target URL for vulnerabilities."""
```

### Task 5.4 — Create pipeline

**File:** `src/dart/passes/pipeline.py` (~80 lines)

```python
async def run_pipeline(state: DASTPipelineState) -> Path:
    """Execute the DAST pipeline: target -> crawl -> scan -> triage -> merge."""
    from dart.passes.target import run_target
    from dart.passes.crawl import run_crawl
    from dart.passes.scan import run_scan
    from dart.passes.triage import run_triage
    from dart.passes.merge import run_merge

    # Pass 1: Target validation
    await run_target(state)

    # Pass 2: Crawl (optional)
    if state.crawl_enabled:
        await run_crawl(state)

    # Pass 3: Scan
    await run_scan(state)

    # Pass 4: Triage (optional, requires provider)
    if state.config.llm.provider_model and _count_findings(state.scan_sarif) > 0:
        await run_triage(state)

    # Merge
    return await run_merge(state)
```

---

## Phase 6 — Priority Scoring and SCAR Correlation

### Task 6.1 — URL-based exposure scoring

**File:** `src/dart/priority.py` (~60 lines)

Extends `harness.priority.score_finding()` with URL-based exposure instead of file-based:

| URL Pattern | Exposure | Rationale |
|---|---|---|
| `/api/*`, `/graphql` | 1.0 | API endpoints — direct attack surface |
| `/admin/*`, `/manage/*` | 0.9 | Admin panels — high value |
| `/auth/*`, `/login`, `/oauth` | 0.9 | Auth endpoints — credential exposure |
| `/upload/*`, `/import/*` | 0.8 | File handling — injection vectors |
| `/health`, `/status`, `/metrics` | 0.5 | Info disclosure, not directly exploitable |
| `/static/*`, `/assets/*` | 0.2 | Static content — low risk |
| Everything else | 0.6 | Default |

### Task 6.2 — SCAR correlation via Plan 012

DART outputs standard SARIF. SCAR's Plan 012 ingestion works out of the box:

```bash
# Run DART
python dart.py scan --url https://staging.app --auth auth.txt --output dart-results/

# Correlate with source code via SCAR
python scar.py ingest --target ../app-source \
  --input dart-results/security-report.sarif \
  --provider claude:claude-opus
```

When SCAR ingests DART's SARIF, findings with the same CWE that map to the same source file are corroborated — DAST confirms SAST, or vice versa.

---

## Phase 7 — Testing

### Task 7.1 — Unit tests

**Directory:** `tests/dart/`

- Test Nuclei JSONL → SARIF conversion (sample fixtures)
- Test Dalfox JSONL → SARIF conversion
- Test `TargetInfo` extraction from httpx JSONL output
- Test URL-based exposure scoring
- Test DAST triage response parsing (reuses `harness.output_parser`)
- Test `DASTConfig` schema validation with `extra="forbid"`

### Task 7.2 — Integration tests

- Run `dart.py scan --url https://httpbin.org` (safe, public target)
- Verify Nuclei output converts to valid SARIF with CWE taxonomy
- Verify `dart.py health-check` reports tool availability

### Task 7.3 — Health check command

**File:** `src/dart/cli/health_check.py` (~40 lines)

```bash
python dart.py health-check
# nuclei    v3.3.x  ✓
# httpx     v1.6.x  ✓
# katana    v1.1.x  ✓ (optional)
# dalfox    v2.9.x  ✗ (optional, not installed)
```

---

## Usage Examples

```bash
# Basic scan (Nuclei only, no crawl, no triage)
python dart.py scan --url https://staging.myapp.com

# Authenticated scan
python dart.py scan --url https://staging.myapp.com --auth auth.txt

# Full scan with crawl + LLM triage
python dart.py scan --url https://staging.myapp.com --auth auth.txt \
  --crawl --provider claude:claude-opus

# Scan with custom Nuclei tags
python dart.py scan --url https://staging.myapp.com \
  --tags "cve,kev,default-login,exposed-panels"

# Rate-limited scan (for production-adjacent targets)
python dart.py scan --url https://staging.myapp.com --rate-limit 10

# Correlate DART findings with SCAR source analysis
python scar.py ingest --target ../myapp-source \
  --input dart-output/security-report.sarif \
  --provider claude:claude-opus
```

---

## Goal

```
/goal Implement DART Phase 0-3 (scaffold, target, scan, triage). Goal is reached when:
1. src/dart/ package exists with passes/, agents/, models/, tools/specs/, cli/ subdirectories
2. dart.py entry point works -- python dart.py --help shows the scan command
3. src/dart/tools/specs/ has httpx.yaml, nuclei.yaml, dalfox.yaml, katana.yaml
4. src/dart/passes/ has target.py, scan.py, triage.py, crawl.py, merge.py, pipeline.py, state.py
5. All imports use harness.* for shared infrastructure -- zero imports from scar.*
6. config/settings/dart.yaml exists with commented options header
7. python dart.py scan --url https://httpbin.org produces a SARIF report in var/output/
8. python dart.py health-check reports tool availability
9. pytest tests/dart/ -v passes with zero failures
10. SCAR is completely unchanged -- python scar.py review --help output is identical, pytest tests/scar/ -v still passes
Stop after 40 turns.
```

---

## Acceptance Criteria

1. `dart.py scan --url <target>` runs httpx probe + Nuclei scan and produces SARIF output
2. `dart.py scan --url <target> --auth auth.txt` passes auth headers to all tools
3. `dart.py scan --url <target> --crawl` runs Katana before Nuclei
4. `dart.py scan --url <target> --provider claude:claude-opus` adds LLM triage
5. DART's SARIF output is compatible with SCAR's `ingest` command (Plan 012)
6. All shared imports are from `harness.*` — no imports from `scar.*`
7. `dart.py health-check` reports nuclei, httpx, katana, dalfox availability
8. SCAR is unchanged — all existing tests pass, CLI identical
9. `pytest tests/dart/ -v` passes
