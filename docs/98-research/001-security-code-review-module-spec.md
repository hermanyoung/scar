# Security Code Review Module — Production Specification

**Repository:** `security-review`
**Version:** 1.0.0
**Date:** 1 May 2026
**Author:** Herman Young
**Status:** Draft for review

---

## 0.0 Summary

Build a standalone, git-submodule-distributable security code review module for C# (.NET) and Python codebases. The module runs deterministic SAST tools (OpenGrep, Bandit, Roslyn/SecurityCodeScan, gitleaks, pip-audit, `dotnet list package --vulnerable`) then orchestrates a five-pass LLM review pipeline via PydanticAI with configurable providers (OpenAI GPT-5.5, Anthropic Claude Opus 4.7, optional GitHub Copilot SDK adapter). All findings are normalised into SARIF 2.1.0 with CWE taxonomy tagging. The module must run on macOS (Apple Silicon + Intel) and Windows (10/11), be invocable from a single CLI entry point (`python -m security_review`), and produce machine-readable output suitable for GitHub Code Scanning upload.

The architecture is: detect → scan → triage → review → report. Deterministic tools handle pattern-level detection. The LLM handles cross-file reasoning, false-positive filtering, authorisation-model analysis, configuration review, and remediation guidance. SARIF is the interchange format between every layer.

---

## 1.0 Boundaries

### 1.1 Technology Decision Matrix

| Component | Technology | Version (pinned) | Role | Rationale |
|---|---|---|---|---|
| LLM orchestration | PydanticAI | >= 0.2.14 | Agent framework with typed outputs | Structured output via Pydantic models; provider-agnostic; tool definitions; output validators; retry with ModelRetry |
| Default LLM | OpenAI GPT-5.5 | gpt-5.5 | Primary reviewer (5-pass pipeline) | Best-available coding model with `--output-schema` support via Responses API; TAC pathway to GPT-5.5-Cyber |
| Target LLM | Anthropic Claude Opus 4.7 | claude-opus-4-7 | Primary reviewer when Anthropic Enterprise lands | 1M context, $5/$25 per MTok, SOTA SWE-bench Pro (64.3%); NativeOutput strict mode for schema compliance |
| Optional LLM adapter | CopilotModel | n/a (internal) | Route through Copilot subscription billing | For orgs preferring single billing surface; prompted-mode structured output with JSON repair |
| Pattern SAST (multi-lang) | OpenGrep | >= 1.19.0 | AST-based pattern matching for C# and Python | LGPL fork of Semgrep; same YAML rule format; SARIF native; no login/cloud requirement |
| Python SAST | Bandit | >= 1.9.4 | Python-specific AST security linter | 68+ security checks; CWE-mapped; SARIF via `bandit[sarif]` extra |
| C# SAST | Microsoft.CodeAnalysis.NetAnalyzers | >= 10.0.203 | Roslyn-hosted security analysers (CA21xx, CA30xx, CA53xx) | Bundled with .NET SDK; SARIF via ErrorLog MSBuild property |
| C# SAST | SecurityCodeScan / security-scan | >= 5.6.7 | Taint-driven SQLi/XSS/CSRF/XXE detection | SCS0001-SCS0035 rules; standalone dotnet tool with --export SARIF |
| Secret scanning | gitleaks | >= 8.30.1 | Hardcoded credentials, API keys, tokens | SARIF native; composite rules; TOML config with org extensions |
| Python SCA | pip-audit | >= 2.10.0 | Vulnerable Python dependencies | PyPA Advisory DB + OSV; JSON output (no native SARIF — convert in pipeline) |
| C# SCA | dotnet list package | .NET SDK >= 8.0 | Vulnerable NuGet packages | `--vulnerable --include-transitive --format json`; GitHub Advisory DB |
| SARIF processing | sarif.py (internal) | n/a | Load, merge, convert, deduplicate, tag | Ported from mission-control; extends with CWE taxonomy block |
| Subprocess execution | tool_runner.py (internal) | n/a | Only module calling external processes | `asyncio.create_subprocess_exec` (never shell=True); timeout; exit-code handling |
| Configuration | pydantic-settings | >= 2.7 | Typed config with env/YAML loading | Two-tier: secrets via .env, settings via YAML with `extra="forbid"` validation |
| C# AST parsing | tree-sitter + tree-sitter-c-sharp | >= 0.23 | Structural analysis of C# files for code_intel | Pure-Python bindings with pre-built wheels; no .NET SDK needed for structural parsing; consistent cross-platform AST extraction |
| CLI | click or typer | >= 0.12 | Entry point and mode selection | `python -m security_review --mode full --target . --output report.sarif` |

### 1.2 Language and Framework Scope

**Python:** Django, Flask, FastAPI, general stdlib. Bandit + OpenGrep rules cover injection, deserialisation, crypto, secrets, subprocess, XML, YAML, pickle, eval, template injection.

**C# (.NET):** ASP.NET Core (MVC, Razor, Blazor, minimal APIs), Entity Framework Core, Newtonsoft.Json, System.Text.Json, System.Security.Cryptography. Roslyn analysers + SecurityCodeScan + OpenGrep rules cover injection, deserialisation (BinaryFormatter family), crypto, CORS, cookies, CSRF, authorisation, XXE, LDAP, XPath.

### 1.3 Platform Support

| Platform | Shell | Subprocess | Notes |
|---|---|---|---|
| macOS (Apple Silicon + Intel) | zsh/bash | `asyncio.create_subprocess_exec` with list args | Primary dev platform; all tools available via brew/pip |
| Windows 10/11 | PowerShell/cmd | `asyncio.create_subprocess_exec` with list args | `shutil.which()` for binary resolution; no shell=True; WSL not required |

**Cross-platform rule:** `asyncio.create_subprocess_exec(*cmd)` with list args works identically on both platforms. Binary resolution via `shutil.which()` in the tool registry. `Path.resolve()` for path canonicalisation. No `os.sep` assumptions in SARIF URIs (always forward slash per SARIF spec).

### 1.4 Out of Scope

1. **Real-time IDE integration.** This module produces SARIF files. IDE consumption (VS Code SARIF Viewer, GitHub Code Scanning) is downstream.
2. **PR-level diff-only mode.** v1 reviews whole files/projects. Diff-scoped review is v2.
3. **Auto-fix / patch generation.** The module reports findings with remediation guidance. It does not modify source code.
4. **Roslyn analyzer development.** The module consumes existing CA/SCS rules; it does not author new Roslyn analyzers.
5. **OpenGrep rule authoring UI.** Rules are YAML files edited in an IDE. No web UI.
6. **Continuous monitoring / commit-by-commit scanning.** This is a point-in-time review tool, not a daemon. OpenAI's Codex Security product covers continuous scanning.
7. **Container image scanning.** Dockerfile review is in scope (Pass 5); base-image CVE scanning (Trivy, Grype) is out of scope.
8. **DAST / runtime testing.** Static analysis only.
9. **VB.NET, F#, JavaScript/TypeScript.** Future language packs; the architecture supports them but v1 ships C# and Python only.
10. **Graph persistence.** No Apache AGE, no knowledge graph. Findings are ephemeral per run.

---

## 2.0 Architecture

### 2.1 Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         security-review                             │
│                                                                     │
│  Pass 1: INVENTORY ──→ file manifest, language detection,           │
│                        security-weight scoring, batch planning      │
│                                                                     │
│  Pass 2: DETERMINISTIC SAST ──→ OpenGrep + Bandit + Roslyn +       │
│                                  gitleaks + pip-audit +             │
│                                  dotnet list --vulnerable           │
│                                  → merged SARIF (sast.sarif)        │
│                                                                     │
│  Pass 3: TRIAGE (LLM) ──→ confirm / refute each SAST finding       │
│                            with full-file context                   │
│                            → annotated SARIF (triaged.sarif)        │
│                                                                     │
│  Pass 4: HOLISTIC REVIEW (LLM) ──→ cross-file analysis:            │
│                                     authZ closure, crypto audit,    │
│                                     deserialisation, IDOR,          │
│                                     business logic                  │
│                                     → new findings JSON             │
│                                                                     │
│  Pass 5: CONFIG REVIEW (LLM) ──→ appsettings, launchSettings,      │
│                                   Dockerfile, CI YAML,              │
│                                   pyproject.toml, .env patterns     │
│                                   → new findings JSON               │
│                                                                     │
│  MERGE ──→ merge all SARIF + LLM findings → security-report.sarif  │
│            + security-report.md (summary)                           │
│            + triage.json (audit log)                                │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Directory Layout

```
security-review/
├── pyproject.toml
├── README.md
├── AGENTS.md                           # Codex/Copilot/Claude instruction router
├── CLAUDE.md                           # @./AGENTS.md (symlink or import)
├── .github/
│   ├── copilot-instructions.md         # Repo-wide Copilot PR review guidance
│   └── instructions/
│       ├── csharp-security.instructions.md   # applyTo: "**/*.cs"
│       └── python-security.instructions.md   # applyTo: "**/*.py"
│
├── src/
│   └── security_review/
│       ├── __init__.py
│       ├── __main__.py                 # CLI entry point
│       ├── cli.py                      # click/typer CLI definition
│       │
│       ├── config.py                   # Settings (secrets) + AppConfig (YAML)
│       ├── config_schema.py            # All typed config schemas
│       ├── errors.py                   # Error taxonomy
│       ├── logging.py                  # structlog setup
│       │
│       ├── providers.py                # _build_model() provider routing
│       ├── copilot_model.py            # CopilotModel adapter (optional)
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── findings.py             # Finding, TriageVerdict, HolisticFinding
│       │   ├── inventory.py            # FileManifest, BatchPlan, SecurityWeight
│       │   ├── config_review.py        # ConfigFinding
│       │   └── report.py               # SecurityReport (top-level output)
│       │
│       ├── sarif/
│       │   ├── __init__.py
│       │   ├── loader.py               # load_sarif() → normalised dicts
│       │   ├── merger.py               # merge_sarif() with dedup
│       │   ├── converter.py            # convert JSON/JSONL → SARIF
│       │   ├── taxonomy.py             # CWE taxonomy injection
│       │   └── tags.py                 # external/cwe/cwe-NNN tag normalisation
│       │
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── runner.py               # _run_tool_subprocess() — ONLY subprocess caller
│       │   ├── registry.py             # SecurityToolSpec + capability resolution
│       │   ├── redactor.py             # Secret pattern redaction
│       │   └── specs/                  # Per-tool spec YAML (loaded by registry)
│       │       ├── opengrep.yaml
│       │       ├── bandit.yaml
│       │       ├── gitleaks.yaml
│       │       ├── roslyn.yaml
│       │       ├── security_scan.yaml
│       │       ├── pip_audit.yaml
│       │       └── dotnet_vuln.yaml
│       │
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── deps.py                 # SecurityReviewDeps dataclass
│       │   ├── triage/
│       │   │   ├── __init__.py
│       │   │   └── agent.py            # Pass 3: confirm/refute SAST findings
│       │   ├── holistic/
│       │   │   ├── __init__.py
│       │   │   └── agent.py            # Pass 4: cross-file security review
│       │   └── config_review/
│       │       ├── __init__.py
│       │       └── agent.py            # Pass 5: configuration file review
│       │
│       ├── passes/
│       │   ├── __init__.py
│       │   ├── inventory.py            # Pass 1: file discovery + batching
│       │   ├── sast.py                 # Pass 2: deterministic tool orchestration
│       │   ├── triage.py               # Pass 3: LLM triage orchestration
│       │   ├── holistic.py             # Pass 4: LLM holistic orchestration
│       │   ├── config_review.py        # Pass 5: LLM config review orchestration
│       │   ├── merge.py                # Final SARIF merge + report generation
│       │   ├── pipeline.py            # PipelineState + run_pipeline() orchestrator
│       │   └── batching.py            # plan_batches() — token-aware file partitioning
│       │
│       ├── code_intel/
│       │   ├── __init__.py
│       │   ├── types.py               # ModuleInfo, SymbolInfo, UnsafePattern, FileMetrics
│       │   ├── parsers/
│       │   │   ├── __init__.py
│       │   │   ├── base.py            # LanguageParser ABC
│       │   │   ├── python_parser.py   # Python AST parser (stdlib ast)
│       │   │   └── csharp_parser.py   # C# parser (tree-sitter-c-sharp)
│       │   ├── graph.py               # Cross-reference graph + PageRank
│       │   ├── quality.py             # Quality metrics (complexity, type cov, error handling)
│       │   ├── unsafe_patterns.py     # Language-specific unsafe pattern detection
│       │   ├── security_weight.py     # Composite security-weight scorer
│       │   └── renderer.py            # Markdown/JSON output with token budget
│       │
│       ├── evidence.py                 # SHA-256 manifest (append-only)
│       └── budget.py                   # CostTracker (cumulative LLM cost audit)
│
├── config/
│   ├── settings/
│   │   └── security_review.yaml        # AppConfig defaults
│   ├── providers.yaml                  # auth_mode + env_var per provider
│   └── prompts/
│       ├── system.md                   # Reviewer persona / output contract
│       ├── triage.md                   # Pass 3 prompt
│       ├── holistic/
│       │   ├── csharp.md               # Pass 4 C#-specific
│       │   └── python.md               # Pass 4 Python-specific
│       └── config_review.md            # Pass 5 prompt
│
├── rules/
│   ├── opengrep/
│   │   ├── csharp/
│   │   │   ├── lang/
│   │   │   │   ├── cwe-089-sql-injection/
│   │   │   │   │   ├── ado-net-string-concat.yaml
│   │   │   │   │   ├── ado-net-string-concat.cs
│   │   │   │   │   ├── dapper-raw-sql.yaml
│   │   │   │   │   └── dapper-raw-sql.cs
│   │   │   │   ├── cwe-079-xss/
│   │   │   │   ├── cwe-502-deserialization/
│   │   │   │   ├── cwe-327-weak-crypto/
│   │   │   │   ├── cwe-078-os-command-injection/
│   │   │   │   └── cwe-798-hardcoded-credentials/
│   │   │   ├── aspnet-core/
│   │   │   │   ├── cwe-352-csrf/
│   │   │   │   ├── cwe-601-open-redirect/
│   │   │   │   ├── cwe-611-xxe/
│   │   │   │   └── cwe-918-ssrf/
│   │   │   └── ef-core/
│   │   │       └── cwe-089-sql-injection/
│   │   └── python/
│   │       ├── lang/
│   │       │   ├── cwe-094-code-injection/
│   │       │   ├── cwe-502-deserialization/
│   │       │   ├── cwe-078-os-command-injection/
│   │       │   ├── cwe-327-weak-crypto/
│   │       │   └── cwe-798-hardcoded-credentials/
│   │       ├── django/
│   │       │   ├── cwe-089-sql-injection/
│   │       │   ├── cwe-079-xss/
│   │       │   └── cwe-352-csrf/
│   │       ├── flask/
│   │       └── fastapi/
│   ├── gitleaks/
│   │   └── .gitleaks.toml
│   └── roslyn/
│       ├── Directory.Build.security.props
│       └── security.editorconfig
│
├── taxonomy/
│   ├── cwe.yaml                        # Canonical CWE registry (~45 entries)
│   ├── cwe-top25-2024.yaml
│   ├── owasp-top10-2021.yaml
│   └── hadolint-cwe-map.yaml           # DLnnnn → CWE mapping
│
├── corpus/
│   ├── csharp/
│   │   ├── cwe-089-sql-injection/
│   │   │   ├── source/
│   │   │   │   ├── SqliDemo.csproj
│   │   │   │   └── VulnerableController.cs
│   │   │   ├── expected.sarif
│   │   │   └── description.md
│   │   ├── cwe-502-deserialization/
│   │   ├── cwe-327-weak-crypto/
│   │   ├── cwe-079-xss/
│   │   └── false-positives/
│   └── python/
│       ├── cwe-089-sql-injection/
│       ├── cwe-078-os-command-injection/
│       ├── cwe-094-code-injection/
│       ├── cwe-502-deserialization/
│       └── false-positives/
│
└── tests/
    ├── conftest.py                     # vulnerable_app, sample_sarif, sample_roe
    ├── unit/
    │   ├── test_sarif_loader.py
    │   ├── test_sarif_merger.py
    │   ├── test_tool_registry.py
    │   ├── test_inventory.py
    │   ├── test_findings_model.py
    │   └── test_cwe_taxonomy.py
    ├── integration/
    │   ├── test_opengrep_scan.py
    │   ├── test_bandit_scan.py
    │   ├── test_gitleaks_scan.py
    │   ├── test_triage_agent.py
    │   └── test_full_pipeline.py
    └── corpus/
        └── runner.py                   # Snapshot regression harness
```

### 2.3 Module Dependency Map

```
cli.py
  └── passes/
        ├── inventory.py ──→ models/inventory.py
        ├── sast.py ──→ tools/runner.py ──→ tools/registry.py ──→ tools/specs/*.yaml
        │                └── sarif/loader.py, sarif/merger.py, sarif/converter.py
        ├── triage.py ──→ agents/triage/agent.py ──→ models/findings.py
        │                                          └── providers.py ──→ PydanticAI
        ├── holistic.py ──→ agents/holistic/agent.py ──→ models/findings.py
        ├── config_review.py ──→ agents/config_review/agent.py ──→ models/config_review.py
        └── merge.py ──→ sarif/merger.py, sarif/taxonomy.py, sarif/tags.py
                       └── models/report.py
                       └── evidence.py

config.py ──→ config_schema.py (YAML schemas)
           └── providers.yaml (auth config)

tools/runner.py ──→ tools/redactor.py (secret pattern masking)
                 └── evidence.py (hash manifest for raw output)
```

Data flows downward. No circular imports. `tools/runner.py` is the only module that calls `asyncio.create_subprocess_exec`. Agents never call subprocess directly.

### 2.4 Pipeline Orchestrator

```python
# src/security_review/passes/pipeline.py

@dataclass
class PipelineState:
    """Carries inter-pass state through the 5-pass pipeline.

    Created by cli.py, passed to each pass function, mutated in place.
    This is the single source of truth for what each pass produced.
    """
    config: SecurityReviewConfig
    target_path: Path
    work_dir: Path                          # temp dir for intermediate files

    # Pass 1 outputs
    manifest: FileManifest | None = None
    batch_plan: BatchPlan | None = None
    code_map: dict | None = None               # Structural map from code_intel (§7.0)
    quality_baseline: dict | None = None        # Aggregate quality metrics from code_intel

    # Pass 2 outputs
    sast_sarif: dict | None = None          # merged SARIF from all tools
    tool_results: list[ToolResult] = field(default_factory=list)

    # Pass 3 outputs
    triage_result: TriageResult | None = None

    # Pass 4 outputs
    holistic_result: HolisticReviewResult | None = None

    # Pass 5 outputs
    config_review_result: ConfigReviewResult | None = None

    # Cross-cutting
    run_id: str = field(default_factory=lambda: uuid4().hex[:12])
    cost_tracker: CostTracker | None = None  # initialised from config/pricing.yaml
    evidence: EvidenceManifest = field(default_factory=EvidenceManifest)


async def run_pipeline(state: PipelineState) -> Path:
    """Execute the 5-pass pipeline. Returns path to final SARIF.

    Each pass reads from state and writes its output back to state.
    The pipeline is linear — no pass runs concurrently with another.
    Within a pass, tools/batches may run concurrently.
    """
    await run_inventory(state)       # Pass 1
    await run_sast(state)            # Pass 2

    if state.config.review.mode == "full":
        await run_triage(state)      # Pass 3
        await run_holistic(state)    # Pass 4
        await run_config_review(state)  # Pass 5

    return await run_merge(state)    # Always
```

### 2.5 SecurityReviewDeps

```python
# src/security_review/agents/deps.py

@dataclass
class SecurityReviewDeps:
    """Dependency injection container for PydanticAI agents.

    Passed as RunContext[SecurityReviewDeps]. Agents use this to access
    file contents, SAST findings, inventory, and config without importing
    modules directly or calling subprocess.
    """
    config: SecurityReviewConfig
    manifest: FileManifest
    # Read-only view of files in scope. Agents call read_file() tool,
    # which reads from disk but validates the path against the manifest.

    sast_sarif: dict
    # Merged SARIF from Pass 2. Agents can query findings by file/CWE.
    # Used by Pass 3 (triage input) and Pass 4 (dedup check).

    cost_tracker: CostTracker
    # Shared cost tracker for audit logging. Budget enforcement is handled
    # by PydanticAI's UsageLimits passed to each agent.run() call.

    code_map: dict | None
    # Structural map from code_intel (§7.0). Used by Pass 4 holistic agent
    # as a token-budgeted "codebase overview" in the LLM context.

    quality_baseline: dict | None
    # Aggregate quality metrics from code_intel. Used by Pass 3 triage to
    # calibrate false-positive confidence thresholds.

    target_path: Path
    # Root of the codebase under review. All file_path values are relative
    # to this root.

    run_id: str
    # Unique identifier for this pipeline run. Bound to structlog context
    # at pipeline start. Propagated to all log entries and triage.json.

    batch_id: str = ""
    # Identifies which batch this agent invocation is processing.
    # Used for logging and triage audit trail.
```

### 2.6 Budget and Cost Tracking

**Enforcement** uses PydanticAI's built-in `UsageLimits` — no custom pre-flight checks needed:

```python
from pydantic_ai import UsageLimits

# Each agent.run() call receives usage_limits for per-call enforcement
result = await triage_agent.run(
    prompt,
    deps=deps,
    usage_limits=UsageLimits(
        request_limit=10,              # max LLM round-trips per call
        total_tokens_limit=200_000,    # max tokens per call
    ),
    usage=pipeline_usage,              # shared Usage object for cost propagation
)
# PydanticAI raises UsageLimitExceeded automatically — no custom check needed
```

**Cost tracking** uses a thin wrapper that reads pricing from YAML config (not hardcoded):

```python
# src/security_review/budget.py

class CostTracker:
    """Tracks cumulative LLM cost across all agent calls in a pipeline run.

    Uses PydanticAI's Usage object for token counting. Computes cost from
    config/pricing.yaml. Does NOT enforce limits — UsageLimits handles that.
    This class is for audit logging and the triage.json evidence pack.
    """

    def __init__(self, pricing: dict[str, ModelPricing]):
        self._pricing = pricing  # loaded from config/pricing.yaml
        self._calls: list[CostEntry] = []

    def record(self, result: RunResult, agent_name: str, batch_id: str) -> None:
        usage = result.usage()
        model_id = result.model_name()  # exact model from API response, not alias
        pricing = self._pricing.get(model_id, self._pricing["default"])
        cost = (
            usage.request_tokens * pricing.input_per_token
            + usage.response_tokens * pricing.output_per_token
        )
        self._calls.append(CostEntry(
            agent=agent_name,
            batch_id=batch_id,
            model_requested=result.model_name(),
            model_responded=model_id,  # track exact version for reproducibility
            tokens_in=usage.request_tokens,
            tokens_out=usage.response_tokens,
            cost_usd=cost,
            cumulative_usd=self.total_spent,
        ))

    @property
    def total_spent(self) -> float:
        return sum(c.cost_usd for c in self._calls)

    def to_audit_log(self) -> list[dict]:
        return [c.model_dump() for c in self._calls]
```

```yaml
# config/pricing.yaml
# LLM pricing per token — update when provider pricing changes.
# Never hardcode pricing in Python code.
openai:gpt-5.5:
  input_per_token: 0.000002
  output_per_token: 0.000010
openai:gpt-5.4-mini:
  input_per_token: 0.0000004
  output_per_token: 0.0000016
anthropic:claude-opus-4-7:
  input_per_token: 0.000005
  output_per_token: 0.000025
default:
  input_per_token: 0.000003
  output_per_token: 0.000015
```

**Anti-patterns:**
- **Do not build custom budget enforcement.** PydanticAI's `UsageLimits` + `UsageLimitExceeded` handles this. Our code only needs to track cost for audit.
- **Do not track budget per-agent.** Cost tracking is a pipeline-level concern. All agents share one `CostTracker` via `PipelineState`.
- **Do not silently skip LLM calls when budget is low.** Let `UsageLimitExceeded` propagate and the CLI reports partial results.
- **Do not hardcode pricing.** All pricing comes from `config/pricing.yaml`; update when providers change rates.
- **Always record the exact model version** from the API response (`result.model_name()`), not the requested alias. Critical for reproducibility and detecting model drift.

### 2.7 Batching Strategy

**Pass 3 (Triage):** Group SAST findings by file. Each batch contains all findings for a set of files, plus the full source of those files. Batch size is governed by `max_tokens_per_batch` (default 150K tokens). The triage agent processes one batch per LLM call, returning a `TriageResult` per batch. Results are merged by concatenating `findings` lists.

**Pass 4 (Holistic):** Group files by security weight (from Pass 1). High-weight files (controllers, auth middleware, crypto) are batched first. Each batch includes the SAST findings for those files (for dedup checking). Batch size is governed by `max_tokens_per_batch`. Each batch produces a `HolisticReviewResult`; findings are merged and deduplicated against SAST results by `(file_path, line_number, cwe_id)`.

**Pass 5 (Config):** All config files are typically small enough for a single batch. If total tokens exceed `max_tokens_per_batch`, split by file type (JSON configs, Dockerfiles, CI YAML).

```python
# src/security_review/passes/batching.py

def plan_batches(
    files: list[FileEntry],
    sast_findings: dict,
    max_tokens: int,
) -> list[Batch]:
    """Partition files into batches that fit within max_tokens.

    Each Batch contains:
      - file_paths: list of files to include
      - finding_count: number of SAST findings for these files
      - estimated_tokens: token estimate (source + findings + prompt overhead)

    Files are sorted by security_weight descending so high-priority
    files are reviewed first (if budget runs out, low-weight files
    are the ones skipped).
    """
```

### 2.8 Provider Routing

```python
# src/security_review/providers.py

from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.models.anthropic import AnthropicModel

def build_model(model_string: str) -> Model:
    """Build a PydanticAI Model from a prefixed string.

    Supported prefixes:
        openai:gpt-5.5
        anthropic:claude-opus-4-7
        copilot:claude-sonnet-4.6
    """
    provider, _, model_name = model_string.partition(":")
    if not model_name:
        raise ConfigurationError(f"Model string must be 'provider:model', got '{model_string}'",
                                  code="SYS_CONFIGURATION_ERROR")

    if provider == "openai":
        from security_review.config import get_settings
        return OpenAIModel(model_name, api_key=get_settings().openai_api_key)

    if provider == "anthropic":
        from security_review.config import get_settings
        return AnthropicModel(model_name, api_key=get_settings().anthropic_api_key)

    if provider == "copilot":
        from security_review.copilot_model import CopilotModel
        return CopilotModel(model_id=model_name)

    raise ConfigurationError(f"Unsupported provider '{provider}'",
                              code="SYS_CONFIGURATION_ERROR")
```

**Anti-patterns:**
- **Do not use FallbackModel.** Cost-runaway risk if a fallback silently switches to a more expensive provider. Provider selection is explicit at config time.
- **Do not hardwire model strings in agent definitions.** All model strings come from `config/settings/security_review.yaml`.
- **Do not import provider SDK clients at module level.** Import inside the branch to avoid requiring both `openai` and `anthropic` packages on every install.

### 2.5 Configuration

```python
# src/security_review/config_schema.py

class LLMConfig(BaseModel, extra="forbid"):
    provider_model: str = Field(
        default="openai:gpt-5.5",
        pattern=r"^(openai|anthropic|copilot):.+$",
        description="Provider-prefixed model string"
    )
    # Rationale: GPT-5.5 is the default because it has native output-schema
    # support via Responses API and is available to all ChatGPT Enterprise orgs.

    triage_model: str | None = Field(
        default=None,
        description="Override model for Pass 3 triage. Falls back to provider_model."
    )
    # Rationale: triage is high-volume, low-complexity. A cheaper model
    # (e.g. openai:gpt-5.4-mini) can handle confirm/refute with lower cost.

    output_retries: int = Field(default=3, ge=1, le=5)
    # Rationale: 3 retries is sufficient for JSON repair + ModelRetry cycles.
    # More than 5 indicates a prompt or schema problem, not a retry problem.

    max_budget_usd: float = Field(default=5.0, ge=0.50, le=100.0)
    # Rationale: hard ceiling for a single review run. Prevents unbounded
    # spend on large repos or pathological LLM loops.

    max_tokens_per_batch: int = Field(default=150_000, ge=10_000, le=500_000)
    # Rationale: 150K tokens per batch keeps well within the reliable
    # retrieval range for both GPT-5.5 (1M context) and Opus 4.7 (1M context).
    # Retrieval degrades measurably above ~400K.

class SASTConfig(BaseModel, extra="forbid"):
    opengrep_rules_path: str = Field(default="rules/opengrep")
    gitleaks_config_path: str = Field(default="rules/gitleaks/.gitleaks.toml")
    roslyn_props_path: str = Field(default="rules/roslyn/Directory.Build.security.props")
    scanner_timeout_seconds: int = Field(default=300, ge=30, le=1800)
    scanner_max_file_size_bytes: int = Field(default=1_048_576, ge=1024)
    # Rationale: 1MB. Files larger than this are typically generated,
    # minified, or vendored — skip them.

class TriageConfig(BaseModel, extra="forbid"):
    fp_confidence_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    # Rationale: findings with LLM confidence >= 0.75 that the finding is
    # a false positive are suppressed in the report (but retained in triage.json).

class ReviewConfig(BaseModel, extra="forbid"):
    mode: str = Field(default="full", pattern=r"^(full|sast|diff)$")
    # full: all 5 passes. sast: passes 1-2 only. diff: future (v2).
    target_path: str = Field(default=".")
    output_sarif: str = Field(default="security-report.sarif")
    output_summary: str = Field(default="security-report.md")
    output_triage: str = Field(default="triage.json")

class SecurityReviewConfig(BaseModel, extra="forbid"):
    llm: LLMConfig = LLMConfig()
    sast: SASTConfig = SASTConfig()
    triage: TriageConfig = TriageConfig()
    review: ReviewConfig = ReviewConfig()
```

```yaml
# config/settings/security_review.yaml
llm:
  provider_model: "openai:gpt-5.5"
  triage_model: "openai:gpt-5.4-mini"
  output_retries: 3
  max_budget_usd: 5.0
  max_tokens_per_batch: 150000

sast:
  opengrep_rules_path: "rules/opengrep"
  gitleaks_config_path: "rules/gitleaks/.gitleaks.toml"
  scanner_timeout_seconds: 300

triage:
  fp_confidence_threshold: 0.75

review:
  mode: "full"
  target_path: "."
  output_sarif: "security-report.sarif"
```

```yaml
# config/providers.yaml
openai:
  auth_mode: api_key
  env_var: OPENAI_API_KEY

anthropic:
  auth_mode: api_key
  env_var: ANTHROPIC_API_KEY

copilot:
  auth_mode: copilot_oauth
  # No env_var — CopilotModel handles auth via copilot CLI login
```

---

## 3.0 Tool Registry and Subprocess Execution

### 3.1 SecurityToolSpec

```python
# src/security_review/tools/registry.py

class OutputFormat(str, Enum):
    SARIF = "sarif"
    JSON = "json"
    JSONL = "jsonl"

class OutputCapture(str, Enum):
    FILE = "file"        # tool writes to output_path directly
    STDOUT = "stdout"    # tool writes to stdout; runner captures and writes to output_path

class SecurityToolSpec(BaseModel, extra="forbid"):
    name: str
    binary: str
    version_cmd: list[str]                 # e.g. ["opengrep", "--version"]
    output_format: OutputFormat
    sarif_native: bool                     # if False, converter.py is called
    success_exit_codes: list[int] = [0]    # [0, 1] for bandit/opengrep
    arg_template: list[str]                # list-based command template with {placeholders}
    # Rationale: list-based template avoids the string→shlex.split() roundtrip
    # that breaks on Windows (POSIX quoting rules) and on paths with spaces.
    # Each element is substituted independently; no shell parsing involved.
    default_args: dict[str, str] = {}
    output_capture: OutputCapture = OutputCapture.FILE
    # Rationale: most tools write to a file (--output, --report-path).
    # Some (dotnet list package) write to stdout. The runner handles both.
    redact_output: bool = False            # True for gitleaks
    timeout_seconds: int = 300
    applies_to: list[str] = []             # glob patterns: ["*.py", "requirements*.txt"]
    target_type: str = "directory"         # "directory" | "file"
    # Rationale: most tools accept a directory. pip-audit accepts a file
    # (requirements.txt). The inventory pass resolves the correct target
    # based on this field.
    cwe_source: str = "metadata"           # "metadata" | "mapping_file" | "none"

    def build_command(self, target_path: str, output_path: str) -> list[str]:
        """Build the command list by substituting placeholders in arg_template.

        Each list element is substituted independently — no shell parsing,
        no shlex.split(), works identically on macOS and Windows.
        """
        subs = {
            "binary": self.binary,
            "target_path": target_path,
            "output_path": output_path,
            **self.default_args,
        }
        return [arg.format(**subs) for arg in self.arg_template]
```

### 3.2 Tool Specs

```yaml
# src/security_review/tools/specs/opengrep.yaml
name: opengrep
binary: opengrep
version_cmd: ["opengrep", "--version"]
output_format: sarif
sarif_native: true
success_exit_codes: [0, 1]
arg_template: ["{binary}", "scan", "--config", "{rules_path}", "--sarif-output={output_path}", "--error", "{target_path}"]
default_args:
  rules_path: "rules/opengrep"
output_capture: file
timeout_seconds: 300
target_type: directory
applies_to: ["*.py", "*.cs", "*.razor", "*.csproj"]
cwe_source: metadata
```

```yaml
# src/security_review/tools/specs/bandit.yaml
name: bandit
binary: bandit
version_cmd: ["bandit", "--version"]
output_format: sarif
sarif_native: true
success_exit_codes: [0, 1]
arg_template: ["{binary}", "-r", "{target_path}", "-f", "sarif", "-o", "{output_path}", "--severity-level", "medium"]
output_capture: file
timeout_seconds: 120
target_type: directory
applies_to: ["*.py"]
cwe_source: metadata
```

```yaml
# src/security_review/tools/specs/gitleaks.yaml
name: gitleaks
binary: gitleaks
version_cmd: ["gitleaks", "version"]
output_format: sarif
sarif_native: true
success_exit_codes: [0, 1]
arg_template: ["{binary}", "dir", "--source", "{target_path}", "--report-format", "sarif", "--report-path", "{output_path}", "--config", "{config_path}", "--redact", "--exit-code", "1", "--no-banner"]
default_args:
  config_path: "rules/gitleaks/.gitleaks.toml"
output_capture: file
redact_output: true
timeout_seconds: 120
target_type: directory
applies_to: []  # runs on everything
cwe_source: none  # all findings map to CWE-798
```

```yaml
# src/security_review/tools/specs/security_scan.yaml
name: security-scan
binary: security-scan
version_cmd: ["security-scan", "--version"]
output_format: sarif
sarif_native: true
success_exit_codes: [0, 1]
arg_template: ["{binary}", "{target_path}", "--excl-proj=**/*Test*/**", "--cwe", "--export={output_path}"]
output_capture: file
timeout_seconds: 600
target_type: directory
applies_to: ["*.sln", "*.csproj"]
cwe_source: metadata
# Authority: taint-driven analysis (SQLi, XSS, CSRF, XXE — SCS0001-SCS0035).
# OpenGrep covers the same CWEs via pattern matching. SecurityCodeScan adds
# inter-procedural taint tracking that OpenGrep cannot do. Both run; SARIF
# merge deduplicates by (cwe_id, file_path, line_number), highest severity wins.
```

```yaml
# src/security_review/tools/specs/pip_audit.yaml
name: pip-audit
binary: pip-audit
version_cmd: ["pip-audit", "--version"]
output_format: json
sarif_native: false   # requires conversion
success_exit_codes: [0, 1]
arg_template: ["{binary}", "-r", "{target_path}", "-f", "json", "-o", "{output_path}", "--desc"]
# Note: -r expects a requirements FILE, not a directory.
# The inventory pass resolves the actual file (requirements.txt, requirements-dev.txt)
# and invokes pip-audit once per file. target_type: file enforces this.
output_capture: file
timeout_seconds: 120
target_type: file     # expects requirements.txt, not a directory
applies_to: ["requirements*.txt"]
# pyproject.toml and Pipfile.lock use different pip-audit flags:
#   pyproject.toml → pip-audit (no -r, reads from pyproject.toml in cwd)
#   Pipfile.lock   → not supported by pip-audit; skip
# These variants are handled by the inventory pass, not by this spec.
cwe_source: mapping_file
```

```yaml
# src/security_review/tools/specs/dotnet_vuln.yaml
name: dotnet-vuln
binary: dotnet
version_cmd: ["dotnet", "--version"]
output_format: json
sarif_native: false   # requires conversion
success_exit_codes: [0, 1]
arg_template: ["{binary}", "list", "{target_path}", "package", "--vulnerable", "--include-transitive", "--format", "json"]
# Note: dotnet list package writes JSON to stdout, not to a file.
# output_capture: stdout tells the runner to capture stdout and write it
# to output_path. The converter then reads output_path as JSON.
output_capture: stdout
timeout_seconds: 180
target_type: directory
applies_to: ["*.sln", "*.csproj"]
cwe_source: mapping_file
```

### 3.3 Tool Runner

```python
# src/security_review/tools/runner.py

async def run_tool(
    spec: SecurityToolSpec,
    target_path: str,
    output_path: str,
    cwd: str | None = None,
) -> ToolResult:
    """Execute a security tool as a subprocess. Never uses shell=True.

    Returns ToolResult with exit_code, stdout, stderr, duration_ms.
    Timeout → ToolResult(exit_code=-1, stderr="timed out after {N}s").
    Binary not found → ToolResult(exit_code=-1, stderr=str(OSError)).

    If spec.output_capture == STDOUT, captures stdout and writes it to
    output_path after successful execution. This handles tools like
    `dotnet list package` that write JSON to stdout instead of a file.
    """
    cmd = spec.build_command(target_path, output_path)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=spec.timeout_seconds,
        )
        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        success = proc.returncode in spec.success_exit_codes

        # For tools that write to stdout, capture and write to output_path
        if success and spec.output_capture == OutputCapture.STDOUT:
            Path(output_path).write_text(stdout_str, encoding="utf-8")

        return ToolResult(
            tool_name=spec.name,
            exit_code=proc.returncode,
            stdout=stdout_str,
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            success=success,
        )
    except asyncio.TimeoutError:
        proc.kill()
        return ToolResult(
            tool_name=spec.name,
            exit_code=-1,
            stderr=f"timed out after {spec.timeout_seconds}s",
            success=False,
        )
    except OSError as e:
        return ToolResult(
            tool_name=spec.name,
            exit_code=-1,
            stderr=str(e),
            success=False,
        )
```

**Anti-patterns:**
- **Do not use `shell=True` or `create_subprocess_shell`.** Tool output containing backticks, semicolons, or pipe characters will execute as shell commands. This is an injection surface.
- **Do not assume exit code 1 is failure.** Bandit, OpenGrep, and gitleaks return 1 when findings are present. Use `success_exit_codes`.
- **Do not call subprocess from agents.** Only `tools/runner.py` calls `create_subprocess_exec`. Agents receive SARIF results via deps.

---

## 4.0 Pydantic Output Models

### 4.1 Finding Models

```python
# src/security_review/models/findings.py

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class TriageVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_CONTEXT = "NEEDS_CONTEXT"

class TriagedFinding(BaseModel):
    """Output of Pass 3: LLM verdict on a single SAST finding."""
    original_rule_id: str = Field(min_length=1)
    original_tool: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    verdict: TriageVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=10)
    # Invariant T-02: FALSE_POSITIVE verdict requires confidence >= fp_confidence_threshold

    @field_validator("rationale", mode="before")
    @classmethod
    def strip_rationale(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v

class TriageResult(BaseModel):
    """Batch output of Pass 3."""
    findings: list[TriagedFinding] = Field(min_length=1)
    total_confirmed: int = Field(ge=0)
    total_false_positive: int = Field(ge=0)
    total_needs_context: int = Field(ge=0)

class BaseFinding(BaseModel):
    """Common fields shared by all LLM-generated findings (Pass 4 and Pass 5).

    Extracted to avoid field drift between HolisticFinding and ConfigFinding.
    Both subclasses inherit these fields and add their own constraints.
    """
    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10)
    severity: Severity
    file_path: str = Field(min_length=1)
    line_number: int | None = Field(default=None, ge=1)
    cwe_id: str | None = Field(default=None, pattern=r"^CWE-\d{1,4}$")
    remediation: str = Field(min_length=10)

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: str) -> str:
        return v.upper().strip() if isinstance(v, str) else v

class HolisticFinding(BaseFinding):
    """Output of Pass 4: a new finding discovered by cross-file LLM analysis."""
    rule_id: str = Field(min_length=1, pattern=r"^SR-[A-Z]+-\d{3}$")
    # Rationale: SR = security-review prefix; category code; 3-digit sequence.
    # Examples: SR-AUTHZ-001, SR-CRYPTO-002, SR-DESER-001

    description: str = Field(min_length=20)  # stricter than base
    confidence: Literal["high", "medium", "low"]
    owasp_category: str | None = Field(default=None, pattern=r"^A\d{2}:\d{4}")
    end_line: int | None = Field(default=None, ge=1)
    evidence: str = Field(min_length=5)
    # Invariant H-03: evidence must quote actual code from the reviewed file

class HolisticReviewResult(BaseModel):
    """Batch output of Pass 4."""
    findings: list[HolisticFinding] = []
    files_reviewed: list[str] = Field(min_length=1)
    review_notes: str = ""

class ConfigFinding(BaseFinding):
    """Output of Pass 5: configuration-level security finding."""
    rule_id: str = Field(pattern=r"^SR-CFG-\d{3}$")

class ConfigReviewResult(BaseModel):
    """Output of Pass 5."""
    findings: list[ConfigFinding] = []
    files_reviewed: list[str] = Field(min_length=1)
```

### 4.2 Output Validators

```python
# In each agent definition

@triage_agent.output_validator
async def validate_triage(ctx, output: TriageResult) -> TriageResult:
    problems = []
    expected_total = len(output.findings)
    actual_total = output.total_confirmed + output.total_false_positive + output.total_needs_context
    if actual_total != expected_total:
        problems.append(
            f"Totals ({actual_total}) must equal len(findings) ({expected_total})"
        )
    for f in output.findings:
        if f.verdict == TriageVerdict.FALSE_POSITIVE and not f.rationale.strip():
            problems.append(
                f"FALSE_POSITIVE for {f.original_rule_id} at {f.file_path}:{f.line_number} "
                f"requires non-empty rationale"
            )
    if problems:
        raise ModelRetry("Triage output validation:\n- " + "\n- ".join(problems))
    return output

@holistic_agent.output_validator
async def validate_holistic(ctx, output: HolisticReviewResult) -> HolisticReviewResult:
    problems = []
    for f in output.findings:
        if f.confidence == "high" and f.cwe_id is None:
            problems.append(
                f"{f.rule_id}: high-confidence finding must include cwe_id"
            )
        if f.end_line is not None and f.line_number is not None:
            if f.end_line < f.line_number:
                problems.append(
                    f"{f.rule_id}: end_line ({f.end_line}) < line_number ({f.line_number})"
                )
    if problems:
        raise ModelRetry("Holistic review validation:\n- " + "\n- ".join(problems))
    return output
```

**Anti-patterns:**
- **Do not dump full ValidationError.errors() into ModelRetry.** The LLM needs a compact list of specific corrections, not a Pydantic error trace.
- **Do not use `output_type=str`.** Every agent must return a typed Pydantic model. Raw strings are not spec-compliant output.
- **Do not use bare `str` for fields with constrained values.** Severity uses Enum. Verdict uses Enum. CWE uses a regex pattern. Confidence uses Literal.

---

## 5.0 Agent Prompts

### 5.1 Prompt Loading

```python
# src/security_review/agents/deps.py

_MODULE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
# Resolves to the security-review/ repo root regardless of whether the
# module is invoked directly or via a git submodule from a consumer repo.
# __file__ = src/security_review/agents/deps.py
# .parent x4 = security-review/

def load_prompt(name: str, variant: str | None = None) -> str:
    """Load a prompt from config/prompts/{name}.md or config/prompts/{name}/{variant}.md.

    Resolves relative to the module's repo root (_MODULE_ROOT), not the
    current working directory. This ensures prompts are found when the
    module is installed as a git submodule (e.g. .security/src/security_review).

    Missing files raise ConfigurationError — never return empty string.
    No template substitution. Prompts are static markdown.
    """
    base = _MODULE_ROOT / "config" / "prompts"
    if variant:
        path = base / name / f"{variant}.md"
    else:
        path = base / f"{name}.md"

    if not path.exists():
        raise ConfigurationError(
            f"Prompt file not found: {path}",
            code="SYS_CONFIGURATION_ERROR",
        )
    return path.read_text(encoding="utf-8")
```

### 5.2 Pass 3 — Triage Agent Prompt

```markdown
<!-- config/prompts/triage.md -->

You are a security code reviewer performing triage on static analysis findings.

**Input:** You receive a list of SAST findings (tool name, rule ID, file path, line number, message) and the full source code of each affected file.

**Task:** For each finding, determine whether it is a true positive, a false positive, or requires additional context.

**Protocol:**
1. Read the finding's rule description and the code at the reported location.
2. Read the surrounding context (at minimum 20 lines above and below).
3. Trace the data flow from source to sink where applicable.
4. Determine if the flagged pattern is actually exploitable in context.
5. Assign a verdict: CONFIRMED, FALSE_POSITIVE, or NEEDS_CONTEXT.
6. Assign a confidence score (0.0 to 1.0).
7. Write a rationale (minimum 10 words) explaining your reasoning.

**What NOT to do:**
- Do not mark a finding as FALSE_POSITIVE because "it might be mitigated elsewhere." If you cannot see the mitigation in the provided code, mark NEEDS_CONTEXT.
- Do not invent context not present in the provided files. If you need a file that was not provided, mark NEEDS_CONTEXT.
- Do not repeat the tool's message as your rationale. Your rationale must add reasoning the tool cannot provide.
- Do not assume parameterised queries are safe if you can see string concatenation in the same method.
- Do not assume [Authorize] is present on a controller if you cannot see the attribute in the provided code.

**Output:** Return a TriageResult with one TriagedFinding per input finding. The totals must match the length of the findings list.
```

### 5.3 Pass 4 — Holistic Agent Prompt (C#)

```markdown
<!-- config/prompts/holistic/csharp.md -->

You are a senior application security engineer reviewing a C# / ASP.NET Core codebase for vulnerabilities that pattern-based static analysis cannot detect.

**Input:** You receive full source files for controllers, services, middleware, configuration, and entity models. You also receive the merged SAST findings from earlier analysis passes.

**Focus areas (in priority order):**

1. **Authorisation closure.** Trace every public endpoint back through MapGroup, RequireAuthorization, [Authorize] attributes, and base controller inheritance. Flag endpoints that are publicly reachable without explicit authorisation. Flag [AllowAnonymous] overriding [Authorize] on state-changing endpoints.

2. **Insecure deserialisation.** Flag ALL uses of BinaryFormatter, NetDataContractSerializer, LosFormatter, SoapFormatter, ObjectStateFormatter. Flag Newtonsoft.Json with TypeNameHandling != None without a SerializationBinder whitelist. These are Critical severity regardless of context.

3. **Cryptographic failures.** Flag MD5, SHA1, HMACSHA1, DES, TripleDES, RC2, RIPEMD160, ECB mode. Flag symmetric keys shorter than 256 bits. Flag keys sourced from appsettings.json rather than KeyVault/IConfiguration.

4. **Direct object reference.** Flag controller actions that call dbContext.X.Find(id) or .Where(x => x.Id == id) using a user-supplied ID without an ownership check.

5. **Cookie and session.** Flag CookieOptions without Secure=true, HttpOnly=true, SameSite=Strict|Lax for auth-related cookies.

6. **CORS.** Flag AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader(). Flag AllowAnyOrigin().AllowCredentials() (invalid per spec).

7. **Error handling.** Flag UseDeveloperExceptionPage() outside env.IsDevelopment(). Flag exception handlers that return ex.ToString() or ex.StackTrace to the client.

**What NOT to do:**
- Do not repeat findings already present in the SAST results. Check the provided SAST findings list before reporting.
- Do not flag [AllowAnonymous] on genuinely public endpoints (health checks, login, public APIs) without explaining why the exemption is inappropriate.
- Do not flag MD5 used in non-security contexts (e.g. cache key generation) as Critical. Use MEDIUM for non-security hash uses.

**Output:** Return a HolisticReviewResult. Each finding must include evidence quoting actual code from the reviewed files. Use rule IDs in the format SR-AUTHZ-001, SR-CRYPTO-001, SR-DESER-001, SR-IDOR-001, SR-COOKIE-001, SR-CORS-001, SR-ERROR-001.
```

### 5.4 Pass 4 — Holistic Agent Prompt (Python)

```markdown
<!-- config/prompts/holistic/python.md -->

You are a senior application security engineer reviewing a Python codebase for vulnerabilities that pattern-based static analysis cannot detect.

**Input:** You receive full source files for views, routes, models, middleware, serializers, and configuration. You also receive the merged SAST findings from earlier analysis passes.

**Focus areas (in priority order):**

1. **Injection via ORM bypass.** Flag Django `raw()`, `extra()`, `RawSQL()`, `cursor.execute()` with string formatting. Flag SQLAlchemy `text()` with f-strings or `.format()`. Flag FastAPI/Flask routes that pass user input directly to database queries without parameterisation.

2. **Insecure deserialisation.** Flag ALL uses of `pickle.loads()`, `pickle.load()`, `shelve.open()`, `marshal.loads()`, `yaml.load()` without `Loader=SafeLoader`, `jsonpickle.decode()`. These are Critical severity regardless of context.

3. **Command injection.** Flag `subprocess.call/run/Popen` with `shell=True` and user-controlled arguments. Flag `os.system()`, `os.popen()`. Flag `eval()`, `exec()`, `compile()` with any external input.

4. **Authentication and authorisation.** Trace Django views for `@login_required` / `LoginRequiredMixin`. Trace Flask routes for `@login_required` or custom auth decorators. Trace FastAPI for `Depends()` with auth dependency. Flag endpoints that mutate state without auth enforcement.

5. **Template injection.** Flag Jinja2 `Environment(autoescape=False)`. Flag Django `mark_safe()` on user-controlled input. Flag `|safe` filter on user input in templates. Flag `render_template_string()` with user input.

6. **Cryptographic failures.** Flag `hashlib.md5()`, `hashlib.sha1()` for security purposes (password hashing, HMAC). Flag `DES`, `Blowfish`, `ARC4` from `cryptography` or `pycryptodome`. Flag hardcoded keys/IVs in source.

7. **SSRF and path traversal.** Flag `requests.get/post()` with user-controlled URLs without allowlist validation. Flag `open()` with user-controlled paths without path sanitisation (`os.path.join` + `os.path.commonpath` check).

**What NOT to do:**
- Do not repeat findings already present in the SAST results. Check the provided SAST findings list before reporting.
- Do not flag `pickle` used in internal caching (Redis, Celery task serialisation) as Critical if the pickle source is trusted internal infrastructure. Use MEDIUM and note the trust assumption.
- Do not flag `hashlib.md5()` / `hashlib.sha1()` used for checksums, cache keys, or ETags as Critical. Use MEDIUM for non-security hash uses.
- Do not flag `subprocess.run([...], shell=False)` with hardcoded arguments as command injection.

**Output:** Return a HolisticReviewResult. Each finding must include evidence quoting actual code from the reviewed files. Use rule IDs in the format SR-AUTHZ-001, SR-CRYPTO-001, SR-DESER-001, SR-INJECT-001, SR-SSRF-001, SR-TMPL-001, SR-PATH-001.
```

### 5.5 Tool Docstring Conventions

Short (1 sentence) when the name is self-explanatory:
```python
async def read_file(ctx: RunContext[SecurityReviewDeps], file_path: str) -> str:
    """Read the full contents of a source file within the review scope."""
```

Longer (2-4 sentences) when return shape matters:
```python
async def get_sast_findings_for_file(ctx: RunContext[SecurityReviewDeps], file_path: str) -> str:
    """Get all SAST findings for a specific file from the deterministic scan pass.

    Returns JSON array of findings. Each entry has: rule_id, tool_name,
    line_number, severity, message, cwe_id.
    Empty array if no findings exist for this file.
    """
```

Args/Returns sections only when the semantics need explanation:
```python
async def check_authorization_chain(
    ctx: RunContext[SecurityReviewDeps],
    controller_path: str,
    endpoint_method: str,
) -> str:
    """Check whether an endpoint has authorisation coverage.

    Walks the class hierarchy from the endpoint method up through base
    controllers and middleware to determine if [Authorize] or
    RequireAuthorization() is applied.

    Args:
        controller_path: Relative path to the controller .cs file.
        endpoint_method: Method name (e.g. "GetUser", "PostOrder").

    Returns:
        JSON object with: has_auth (bool), auth_source (str|null),
        allows_anonymous (bool), chain (list of checked locations).
    """
```

---

## 6.0 SARIF Output

### 6.1 CWE Taxonomy in SARIF

Every output SARIF file includes a `taxonomies` entry for CWE plus `external/cwe/cwe-NNN` tags on each rule, per the conventions established in the CWE structuring research.

```python
# src/security_review/sarif/taxonomy.py

def build_cwe_taxonomy(used_cwes: set[str]) -> dict:
    """Build a SARIF taxonomies entry for the CWEs referenced in results.

    Args:
        used_cwes: Set of CWE IDs (e.g. {"89", "79", "502"})

    Returns:
        SARIF toolComponent dict for the CWE taxonomy.
    """
    registry = load_cwe_registry()  # from taxonomy/cwe.yaml
    return {
        "name": "CWE",
        "version": "4.16",
        "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.16.pdf",
        "organization": "MITRE",
        "isComprehensive": False,
        "taxa": [
            {
                "id": str(cwe_id),
                "name": registry[cwe_id]["name"],
                "shortDescription": {"text": registry[cwe_id]["name"]},
            }
            for cwe_id in sorted(used_cwes)
            if cwe_id in registry
        ],
    }
```

### 6.2 Tag Normalisation

```python
# src/security_review/sarif/tags.py

def normalise_cwe_tags(rule: dict) -> list[str]:
    """Ensure rule.properties.tags contains external/cwe/cwe-NNN entries.

    GitHub Code Scanning reads CWE from these tags.
    Normalises from various formats:
      "CWE-89: SQL Injection" → "external/cwe/cwe-089"
      "CWE-79" → "external/cwe/cwe-079"
      89 (int) → "external/cwe/cwe-089"
    """
```

---

## 7.0 Code Intelligence

### 7.1 Overview

Two standalone analysis scripts (`code_map.py`, `code_quality.py`) are refactored into a `code_intel` package inside the module. This package provides **language-agnostic structural analysis** with pluggable parsers for Python and C#. It feeds three pipeline stages:

| Consumer | What it gets | Why |
|---|---|---|
| **Pass 1 (Inventory)** | PageRank importance scores, unsafe pattern counts, complexity metrics | Replaces keyword-based security-weight with graph-based importance. Files that are highly connected AND contain unsafe patterns get reviewed first. |
| **Pass 3 (Triage)** | Codebase quality baseline (type coverage, exception handling quality) | Low-quality codebases get less aggressive false-positive filtering. If the code is poorly typed and full of bare excepts, err on the side of CONFIRMED. |
| **Pass 4 (Holistic)** | Structural map with import graph, class hierarchies, endpoint-to-service traces | Stuffed into LLM context as a "codebase overview" so the agent can reason about cross-file flows without reading every file. Token-budgeted rendering. |

### 7.2 Architecture

```
src/security_review/
    code_intel/
    ├── __init__.py
    ├── types.py                  # Language-agnostic data types
    ├── parsers/
    │   ├── __init__.py
    │   ├── base.py               # LanguageParser ABC
    │   ├── python_parser.py      # Python AST parser (stdlib ast)
    │   └── csharp_parser.py      # C# parser (tree-sitter-c-sharp)
    ├── graph.py                  # Cross-reference graph + PageRank
    ├── quality.py                # Quality metrics (complexity, type coverage, error handling)
    ├── unsafe_patterns.py        # Language-specific unsafe pattern detection
    ├── security_weight.py        # Composite security-weight scorer
    └── renderer.py               # Markdown/JSON output with token budget
```

### 7.3 Language Parser Interface

```python
# src/security_review/code_intel/parsers/base.py

class LanguageParser(ABC):
    """Abstract parser that extracts structural information from source files.

    Each language implements this interface. The code_intel orchestrator
    selects the parser based on file extension.
    """

    @abstractmethod
    def parse_file(self, file_path: Path, rel_path: str) -> ModuleInfo | None:
        """Extract module structure: classes, functions, imports, constants.
        Returns None if the file cannot be parsed (syntax error, binary, etc.)."""

    @abstractmethod
    def detect_unsafe_patterns(self, file_path: Path) -> list[UnsafePattern]:
        """Detect security-relevant patterns via AST inspection.
        Lighter than SAST — runs instantly, no external tool required."""

    @abstractmethod
    def compute_file_metrics(self, file_path: Path) -> FileMetrics:
        """Compute quality metrics: nesting depth, function length,
        type annotation coverage, exception handling quality."""

    @property
    @abstractmethod
    def language(self) -> str:
        """Return language identifier: 'python' or 'csharp'."""

    @property
    @abstractmethod
    def extensions(self) -> list[str]:
        """File extensions this parser handles: ['.py'] or ['.cs', '.razor']."""
```

### 7.4 Python Parser

Uses stdlib `ast` module (zero external dependencies). Extracted from the existing `code_map.py` and `code_quality.py` scripts.

```python
# src/security_review/code_intel/parsers/python_parser.py

class PythonParser(LanguageParser):
    language = "python"
    extensions = [".py"]

    # Unsafe patterns detected via AST (no Bandit needed)
    UNSAFE_CALLS = {
        "eval": CWE("CWE-94", "Code injection via eval()"),
        "exec": CWE("CWE-94", "Code injection via exec()"),
        "__import__": CWE("CWE-94", "Dynamic import can load arbitrary modules"),
    }
    UNSAFE_ATTRS = {
        ("os", "system"): CWE("CWE-78", "OS command injection via os.system()"),
        ("os", "popen"): CWE("CWE-78", "OS command injection via os.popen()"),
        ("pickle", "loads"): CWE("CWE-502", "Deserialization of untrusted data"),
        ("pickle", "load"): CWE("CWE-502", "Deserialization of untrusted data"),
        ("yaml", "load"): CWE("CWE-502", "yaml.load() without SafeLoader"),
        ("marshal", "loads"): CWE("CWE-502", "Deserialization via marshal"),
    }
    UNSAFE_KWARGS = {
        # subprocess.*(shell=True)
        ("subprocess",): ("shell", True, CWE("CWE-78", "subprocess with shell=True")),
    }
```

### 7.5 C# Parser

Uses `tree-sitter-c-sharp` for AST parsing. No .NET SDK required for structural analysis (the SDK is only needed by Roslyn/SecurityCodeScan in Pass 2).

```python
# src/security_review/code_intel/parsers/csharp_parser.py

class CSharpParser(LanguageParser):
    language = "csharp"
    extensions = [".cs", ".razor"]

    # Unsafe patterns detected via tree-sitter AST
    UNSAFE_TYPES = {
        "BinaryFormatter": CWE("CWE-502", "BinaryFormatter deserialization"),
        "NetDataContractSerializer": CWE("CWE-502", "NetDataContractSerializer deserialization"),
        "LosFormatter": CWE("CWE-502", "LosFormatter deserialization"),
        "SoapFormatter": CWE("CWE-502", "SoapFormatter deserialization"),
        "ObjectStateFormatter": CWE("CWE-502", "ObjectStateFormatter deserialization"),
    }
    UNSAFE_CALLS = {
        "Process.Start": CWE("CWE-78", "OS command injection via Process.Start"),
        "Assembly.Load": CWE("CWE-94", "Dynamic assembly loading"),
        "Assembly.LoadFrom": CWE("CWE-94", "Dynamic assembly loading from path"),
        "Type.InvokeMember": CWE("CWE-94", "Reflection-based invocation"),
    }
    UNSAFE_PATTERNS = {
        # SqlCommand with string concat (tree-sitter can detect binary_expression
        # inside object_creation_expression where type is SqlCommand)
        "sql_string_concat": CWE("CWE-89", "SQL command with string concatenation"),
        # TypeNameHandling set to anything other than None
        "type_name_handling": CWE("CWE-502", "Newtonsoft TypeNameHandling != None"),
    }
    SECURITY_ATTRIBUTES = {
        # Attributes that indicate security-relevant endpoints
        "Authorize", "AllowAnonymous", "HttpGet", "HttpPost", "HttpPut",
        "HttpDelete", "HttpPatch", "Route", "ApiController",
        "ValidateAntiForgeryToken",
    }

    def __init__(self):
        import tree_sitter_c_sharp as ts_csharp
        from tree_sitter import Language, Parser
        self._language = Language(ts_csharp.language())
        self._parser = Parser(self._language)

    def parse_file(self, file_path: Path, rel_path: str) -> ModuleInfo | None:
        source = file_path.read_bytes()
        tree = self._parser.parse(source)
        # Extract: using directives (imports), namespace, classes,
        # methods, properties, attributes, base types
        ...

    def detect_unsafe_patterns(self, file_path: Path) -> list[UnsafePattern]:
        # Walk tree-sitter AST looking for:
        # - object_creation_expression where type matches UNSAFE_TYPES
        # - invocation_expression where method matches UNSAFE_CALLS
        # - binary_expression inside SqlCommand constructor args
        # - assignment where left is TypeNameHandling and right != None
        ...

    def compute_file_metrics(self, file_path: Path) -> FileMetrics:
        # From tree-sitter AST:
        # - nesting depth (if/for/while/try/using nesting)
        # - method length (end_line - start_line per method_declaration)
        # - parameter count per method
        # - public vs private member ratio
        # - exception handling: catch blocks, catch(Exception), empty catch
        ...
```

### 7.6 Security-Weight Scoring

Replaces the keyword-based `I-02` invariant with a composite score:

```python
# src/security_review/code_intel/security_weight.py

def compute_security_weight(
    module: ModuleInfo,
    pagerank: float,
    unsafe_patterns: list[UnsafePattern],
    metrics: FileMetrics,
) -> float:
    """Compute a composite security-weight for a file.

    Returns a float 0.0-10.0 where higher = review first.

    Components:
      - pagerank_score (0-3): How connected is this file? High PageRank
        means a vulnerability here has wide blast radius.
      - unsafe_score (0-3): How many unsafe patterns were detected?
        Direct indicator of likely true positives.
      - surface_score (0-2): Is this an endpoint/controller/route handler?
        External attack surface gets priority.
      - quality_penalty (0-2): Low type coverage + high complexity + bare
        excepts = higher risk of latent bugs.
    """
    pagerank_score = min(3.0, pagerank * 3.0)

    unsafe_score = min(3.0, len(unsafe_patterns) * 1.0)

    surface_score = 0.0
    surface_indicators = {
        "python": {"@app.route", "@router.", "def get(", "def post(", "def put(", "def delete("},
        "csharp": {"[HttpGet]", "[HttpPost]", "[ApiController]", "[Route(", "MapGet(", "MapPost("},
    }
    # Check decorators and class attributes against surface_indicators
    if _has_surface_indicators(module, surface_indicators):
        surface_score = 2.0

    quality_penalty = 0.0
    if metrics.type_coverage < 0.3:
        quality_penalty += 0.5
    if metrics.max_nesting > 5:
        quality_penalty += 0.5
    if metrics.bare_except_count > 0:
        quality_penalty += 0.5
    if metrics.avg_function_length > 60:
        quality_penalty += 0.5

    return min(10.0, pagerank_score + unsafe_score + surface_score + quality_penalty)
```

### 7.7 Token-Budgeted Rendering for LLM Context

```python
# src/security_review/code_intel/renderer.py

def render_for_holistic_review(
    code_map: dict,
    max_tokens: int = 8192,
) -> str:
    """Render the code map as a Markdown structural overview for Pass 4.

    The LLM receives this alongside source files so it can reason about
    cross-file flows (controller → service → repository → database).

    Includes:
      - Import graph with dependency arrows
      - Class hierarchies with base types
      - Endpoint → handler → service traces
      - Circular dependency warnings

    Token-budgeted: if the full map exceeds max_tokens, low-PageRank
    symbols are progressively trimmed (methods first, then functions,
    then entire modules).
    """
```

### 7.8 Integration with Pipeline

```python
# In passes/inventory.py (Pass 1)

async def run_inventory(state: PipelineState) -> None:
    # 1. File discovery (existing)
    files = discover_files(state.target_path, state.config)

    # 2. Language detection (existing)
    language = detect_language(files)

    # 3. Structural analysis (NEW — from code_intel)
    parser = get_parser(language)  # PythonParser or CSharpParser
    modules = [parser.parse_file(f, rel) for f, rel in files]
    graph = build_reference_graph(modules)
    ranks = compute_pagerank(graph)
    unsafe = {m.path: parser.detect_unsafe_patterns(f) for m, f in zip(modules, files)}
    metrics = {m.path: parser.compute_file_metrics(f) for m, f in zip(modules, files)}

    # 4. Security-weight scoring (UPGRADED — PageRank + unsafe + quality)
    weights = {
        m.path: compute_security_weight(m, ranks.get(m.path, 0), unsafe[m.path], metrics[m.path])
        for m in modules
    }

    # 5. Batch planning (existing, but now uses upgraded weights)
    state.manifest = FileManifest(files=files, weights=weights)
    state.batch_plan = plan_batches(files, weights, state.config.llm.max_tokens_per_batch)

    # 6. Store code_intel outputs for downstream passes
    state.code_map = assemble_code_map(modules, ranks)
    state.quality_baseline = aggregate_quality_metrics(metrics)
```

### 7.9 Dependencies

| Package | Version | Purpose | Required |
|---|---|---|---|
| `tree-sitter` | >= 0.23 | Tree-sitter Python bindings | Yes (for C# parsing) |
| `tree-sitter-c-sharp` | >= 0.23 | C# grammar for tree-sitter | Yes (for C# parsing) |

Both are pip-installable, pure Python wheels with pre-built native extensions. No build tools required.

Python parsing uses stdlib `ast` only — no additional dependencies.

### 7.10 Anti-Patterns

- **Do not call tree-sitter from agents.** Parsing happens in Pass 1 only. Agents receive pre-computed structural data via `SecurityReviewDeps`.
- **Do not use code_intel to replace SAST tools.** Unsafe pattern detection is a lightweight pre-scan for prioritisation. It is NOT a substitute for OpenGrep, Bandit, or SecurityCodeScan — those tools do inter-procedural analysis, taint tracking, and rule-based detection that AST walking cannot.
- **Do not run code_quality's Bandit/Radon wrappers.** The pipeline already runs Bandit via `tools/runner.py` with SARIF output. Running it twice through different parsers is waste.
- **Do not hardcode language-specific patterns in the scorer.** All unsafe patterns and surface indicators live in the parser classes. `security_weight.py` is language-agnostic.

---

## 8.0 Behavioural Invariants

| ID | Invariant | Test method |
|---|---|---|
| **I-01** | Pass 1 excludes files matching `obj/`, `bin/`, `Migrations/`, `*.designer.cs`, `*.g.cs`, `__pycache__/`, `.venv/`, `node_modules/` | `test_inventory_excludes_generated` |
| **I-02** | Pass 1 assigns security weight >= 4.0 to files with unsafe patterns (eval, pickle, BinaryFormatter, etc.) OR high PageRank (top 10%) OR endpoint surface indicators ([HttpPost], @app.route, MapGet) | `test_inventory_security_weight` |
| **I-02a** | PageRank-based weight ranks files by connectivity — a utility module imported by 20 files scores higher than an isolated script with `eval` | `test_inventory_pagerank_ranking` |
| **I-02b** | C# parser detects BinaryFormatter, Process.Start, SqlCommand string concat, TypeNameHandling via tree-sitter AST | `test_csharp_parser_unsafe_patterns` |
| **I-02c** | Python parser detects eval, exec, pickle.loads, os.system, subprocess(shell=True), yaml.load via stdlib AST | `test_python_parser_unsafe_patterns` |
| **I-03** | Pass 2 runs only tools whose `applies_to` patterns match files in the manifest | `test_sast_skips_irrelevant_tools` |
| **I-04** | Pass 2 treats exit code in `success_exit_codes` as success, not error | `test_sast_bandit_exit_code_1_is_success` |
| **I-05** | Merged SAST SARIF deduplicates by `(cwe_id, file_path, line_number)`, highest severity wins | `test_sarif_merge_dedup_highest_severity` |
| **T-01** | Pass 3 produces exactly one TriagedFinding per input SAST finding | `test_triage_one_verdict_per_finding` |
| **T-02** | FALSE_POSITIVE verdict requires confidence >= `fp_confidence_threshold` (default 0.75) | `test_triage_fp_confidence_threshold` |
| **T-03** | FALSE_POSITIVE verdict requires rationale with min_length=10 | `test_triage_fp_requires_rationale` |
| **T-04** | Triage totals (confirmed + fp + needs_context) equal len(findings) | `test_triage_totals_match` |
| **H-01** | Pass 4 does not duplicate findings already in the SAST results (dedup by file_path + line_number + CWE) | `test_holistic_no_sast_duplicates` |
| **H-02** | High-confidence holistic findings must include a cwe_id | `test_holistic_high_confidence_has_cwe` |
| **H-03** | Evidence field must quote actual code from reviewed files (verified by substring match against source) | `test_holistic_evidence_matches_source` |
| **H-04** | BinaryFormatter/NetDataContractSerializer findings are always CRITICAL regardless of context | `test_holistic_binaryformatter_critical` |
| **C-01** | Pass 5 reviews appsettings*.json, launchSettings.json, Dockerfile*, *.yml (CI), pyproject.toml when present | `test_config_review_coverage` |
| **C-02** | Secrets in appsettings (matching password/secret/key/token patterns) are flagged HIGH or CRITICAL | `test_config_review_secrets_severity` |
| **S-01** | Final SARIF includes `taxonomies[].name == "CWE"` with taxa for all referenced CWEs | `test_sarif_has_cwe_taxonomy` |
| **S-02** | Every rule in final SARIF has `properties.tags` containing `external/cwe/cwe-NNN` | `test_sarif_rules_have_cwe_tags` |
| **S-03** | SARIF validates against SARIF 2.1.0 schema | `test_sarif_schema_validation` |
| **S-04** | SARIF merge deduplicates cross-tool: same (file, line, CWE) from OpenGrep and Roslyn keeps highest severity | `test_sarif_cross_tool_dedup` |
| **E-01** | Evidence manifest SHA-256 hashes are computed on redacted output, not raw | `test_evidence_hashes_redacted` |
| **E-02** | Evidence manifest is append-only; duplicate paths raise ValueError | `test_evidence_append_only` |
| **P-01** | Provider routing rejects unknown prefixes with ConfigurationError | `test_provider_unknown_prefix_raises` |
| **P-02** | No subprocess calls exist outside tools/runner.py (enforced by grep in CI) | `test_no_subprocess_outside_runner` |
| **P-03** | Total LLM spend does not exceed max_budget_usd (structural via PydanticAI usage tracking) | `test_budget_enforcement` |

---

## 9.0 Error Taxonomy

Error codes follow the `{CATEGORY}_{NOUN}_{STATE}` convention (UPPER_SNAKE_CASE). Categories:
- `SCAN_*` — Scanner/tool execution errors
- `SARIF_*` — SARIF parsing and conversion errors
- `LLM_*` — LLM provider and output errors
- `SYS_*` — System configuration and environment errors

```python
# src/security_review/errors.py

class SecurityReviewError(Exception):
    """Base exception for all security review errors."""
    def __init__(self, message: str, code: str):
        self.code = code
        super().__init__(message)

class ScannerError(SecurityReviewError): ...
class SARIFError(SecurityReviewError): ...
class LLMError(SecurityReviewError): ...
class ConfigurationError(SecurityReviewError): ...
```

| Code | Category | Message template | Retryable | Recovery |
|---|---|---|---|---|
| `SCAN_BINARY_NOT_FOUND` | SCAN | `{tool_name} binary not found at {binary_path}` | No | Install the tool; run `doctor` |
| `SCAN_TOOL_TIMEOUT` | SCAN | `{tool_name} timed out after {timeout}s on {target_path}` | Yes (30s) | Increase timeout or reduce target scope |
| `SCAN_TOOL_FAILED` | SCAN | `{tool_name} exited with code {exit_code}: {stderr}` | No | Check tool config; see stderr |
| `SARIF_PARSE_FAILED` | SARIF | `Failed to parse SARIF from {tool_name}: {detail}` | No | Check tool version; output may not be SARIF 2.1.0 |
| `SARIF_CONVERT_FAILED` | SARIF | `Failed to convert {source_format} to SARIF: {detail}` | No | Check converter for {tool_name} |
| `LLM_PROVIDER_FAILED` | LLM | `{provider} API error: {detail}` | Yes (5s) | Retry; check API key and quota |
| `LLM_RATE_LIMITED` | LLM | `{provider} rate limited; retry after {retry_after}s` | Yes | Reduce concurrency or wait |
| `LLM_BUDGET_EXCEEDED` | LLM | `LLM spend ${current} exceeds budget ${budget}` | No | Increase max_budget_usd or reduce scope |
| `LLM_SCHEMA_VIOLATED` | LLM | `LLM output failed schema validation after {retries} retries` | No | Review prompt; check output model constraints |
| `SYS_CONFIG_INVALID` | SYS | `Configuration error: {detail}` | No | Fix config/settings/security_review.yaml |
| `SYS_SECRET_MISSING` | SYS | `Required env var {env_var} not set` | No | Set the env var or add to .env |
| `SYS_TARGET_NOT_FOUND` | SYS | `Target path {target_path} does not exist` | No | Check --target argument |
| `SYS_CWE_NOT_FOUND` | SYS | `CWE {cwe_id} not found in taxonomy/cwe.yaml` | No | Add entry to taxonomy or fix rule metadata |

---

## 10.0 Security

### 10.1 Trust Boundaries

This module has two active trust boundaries:

1. **External content → LLM context.** Source code under review is untrusted input to the LLM. A malicious file in the reviewed project can contain prompt-injection instructions targeting the reviewer agent. Controls: output schema enforcement (Pydantic models prevent freeform output), cross-agent isolation (each pass gets only its specific input), no code execution by the LLM (read-only tools only).

2. **LLM output → SARIF report.** LLM-generated findings are consumed by downstream systems (GitHub Code Scanning, developer dashboards). Controls: every finding passes Pydantic validation; CWE IDs are validated against the taxonomy registry; file paths are validated against the inventory manifest; line numbers are validated as positive integers; no raw LLM text appears in SARIF without schema enforcement.

### 10.2 Agent-Specific Threats

| Threat | Likelihood | Impact | Control |
|---|---|---|---|
| Indirect prompt injection via reviewed code | HIGH | MEDIUM | Output schema enforcement; no free-text fields in critical positions; triage rationale length-bounded |
| LLM hallucinates file paths or CWE IDs | MEDIUM | LOW | File paths validated against inventory manifest; CWE IDs validated against taxonomy/cwe.yaml |
| Cost exhaustion via pathological input | LOW | MEDIUM | `max_budget_usd` hard limit; `max_tokens_per_batch` caps context size; `output_retries` capped at 5 |
| Secret leakage in SARIF output | MEDIUM | HIGH | `tools/redactor.py` masks secrets in SARIF message/snippet before output; raw preserved as .raw sidecar |
| Tool command injection | LOW | CRITICAL | `create_subprocess_exec` with list args only; no shell=True anywhere; binary paths resolved via shutil.which() |

### 10.3 Secret Management

| Secret | Storage | Access | Rotation |
|---|---|---|---|
| `OPENAI_API_KEY` | .env file (gitignored) | `get_settings().openai_api_key` | Per org policy; no default |
| `ANTHROPIC_API_KEY` | .env file (gitignored) | `get_settings().anthropic_api_key` | Per org policy; no default |
| Copilot OAuth token | Managed by copilot CLI (`~/.config/github-copilot/`) | CopilotModel handles auth | Automatic refresh |

### 10.4 Audit Trail

Every run produces `triage.json` containing the full LLM triage audit log: every finding, every verdict, every rationale, the exact model version returned by the API (not the requested alias), the prompt hash, the cost entry, and the timestamp. This file is the evidence pack for compliance reviews of the AI tool itself.

---

## 11.0 Observability

### 11.1 structlog Configuration

```python
# src/security_review/logging.py

import structlog

def configure_logging(verbose: bool = False, json_output: bool = False) -> None:
    """Configure structlog for the pipeline.

    Args:
        verbose: Enable DEBUG level. Default is INFO.
        json_output: Emit JSON lines to stderr (for CI). Default is human-readable.
    """
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.DEBUG if verbose else logging.INFO
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )
```

### 11.2 Correlation via run_id

Every pipeline run generates a `run_id` (12-char hex from uuid4). This ID is bound to the structlog context at pipeline start and propagated to every log entry, every triage.json record, and every cost entry.

```python
# In cli.py / run_pipeline()
import structlog

structlog.contextvars.bind_contextvars(
    run_id=state.run_id,
    target=str(state.target_path),
    mode=state.config.review.mode,
)
logger = structlog.get_logger()
logger.info("pipeline.started")
```

### 11.3 What to Log

| Event | Level | Fields |
|---|---|---|
| `pipeline.started` | INFO | run_id, target, mode |
| `pipeline.pass_started` | INFO | run_id, pass_number, pass_name |
| `pipeline.pass_completed` | INFO | run_id, pass_number, duration_ms, finding_count |
| `tool.started` | INFO | run_id, tool_name, target_path |
| `tool.completed` | INFO | run_id, tool_name, exit_code, duration_ms, finding_count |
| `tool.failed` | ERROR | run_id, tool_name, exit_code, stderr (truncated) |
| `tool.timeout` | WARNING | run_id, tool_name, timeout_seconds |
| `agent.started` | INFO | run_id, agent_name, batch_id, model_requested |
| `agent.completed` | INFO | run_id, agent_name, batch_id, model_responded, tokens_in, tokens_out, cost_usd, duration_ms |
| `agent.retry` | WARNING | run_id, agent_name, retry_count, reason |
| `agent.failed` | ERROR | run_id, agent_name, error_code, detail |
| `budget.warning` | WARNING | run_id, spent_usd, budget_usd, remaining_pct |
| `pipeline.completed` | INFO | run_id, total_findings, total_cost_usd, duration_ms |

### 11.4 What NOT to Log

- **Never log**: API keys, file contents, LLM prompt/response bodies, SARIF finding details (these go to output files, not logs)
- **Never log at DEBUG in production**: raw tool stdout/stderr (can contain secrets from reviewed code)
- **Do not guess the log source from logger name** — always set explicitly via structlog contextvars

---

## 12.0 CLI Interface

### 12.1 Entry Point

```python
# src/security_review/__main__.py
"""Allow `python -m security_review` invocation."""
from security_review.cli import app
app()
```

### 12.2 Commands and Flags

```python
# src/security_review/cli.py
import typer

app = typer.Typer(name="security-review", help="Security code review pipeline.")

@app.command()
def review(
    target: Path = typer.Option(".", "--target", "-t", help="Path to codebase root"),
    mode: str = typer.Option("full", "--mode", "-m", help="full | sast | triage-only"),
    # full: all 5 passes. sast: passes 1-2 only. triage-only: passes 1-3.
    output: Path = typer.Option("security-report.sarif", "--output", "-o", help="Output SARIF path"),
    summary: Path = typer.Option("security-report.md", "--summary", help="Output markdown summary path"),
    config: Path = typer.Option(None, "--config", "-c", help="Override config YAML path"),
    provider: str = typer.Option(None, "--provider", "-p", help="Override provider:model string"),
    budget: float = typer.Option(None, "--budget", help="Override max_budget_usd"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON progress to stderr"),
):
    """Run the security review pipeline."""

@app.command()
def doctor():
    """Check that all required external tools are installed and accessible.

    For each tool in the registry:
      - Resolves binary via shutil.which()
      - Runs version_cmd and checks output
      - Reports: tool name, expected version, installed version, status (ok/missing/outdated)

    Exit code 0 if all required tools are found, 1 otherwise.
    Optional tools (security-scan, dotnet) report warnings, not errors.
    """

@app.command()
def list_rules(
    language: str = typer.Option(None, "--language", "-l", help="Filter by language: python | csharp"),
):
    """List all configured OpenGrep, Bandit, and Roslyn rules with CWE mappings."""
```

**Design notes:**
- `--mode triage-only` runs passes 1-3 (SAST + triage). Useful for quick CI checks where holistic review is too expensive.
- `--provider` overrides `llm.provider_model` from config. Useful for A/B testing models: `--provider anthropic:claude-opus-4-7`.
- `--budget` overrides `llm.max_budget_usd`. Useful for CI (low budget) vs. deep review (higher budget).
- `--json` emits structured progress events to stderr (pass started, pass completed, finding count, budget spent). Useful for CI integration.
- `doctor` is the bootstrap verification command referenced in §11.2.

---

## 13.0 Testing

### 13.1 Test Matrix

| Layer | Type | Tool | Assertions | File |
|---|---|---|---|---|
| SARIF loader | Unit | pytest | Parses valid SARIF; extracts CWE from tags and relationships | `tests/unit/test_sarif_loader.py` |
| SARIF merger | Unit | pytest | Dedup by (cwe, file, line); highest severity wins (S-04, S-05) | `tests/unit/test_sarif_merger.py` |
| Tool registry | Unit | pytest | Resolves binaries; builds commands; respects applies_to | `tests/unit/test_tool_registry.py` |
| Inventory | Unit | pytest | Excludes generated files (I-01); weights security files (I-02) | `tests/unit/test_inventory.py` |
| Finding models | Unit | pytest | Validators fire on empty rationale (T-03); severity normalises | `tests/unit/test_findings_model.py` |
| CWE taxonomy | Unit | pytest | Registry loads; rejects PROHIBITED CWEs as primary | `tests/unit/test_cwe_taxonomy.py` |
| OpenGrep scan | Integration | pytest + opengrep | Runs against corpus/python/cwe-094; produces expected SARIF | `tests/integration/test_opengrep_scan.py` |
| Bandit scan | Integration | pytest + bandit | Runs against corpus/python/cwe-078; exit code 1 = success | `tests/integration/test_bandit_scan.py` |
| gitleaks scan | Integration | pytest + gitleaks | Runs against corpus with hardcoded secret; redacts in output | `tests/integration/test_gitleaks_scan.py` |
| Triage agent | Integration | pytest + PydanticAI | Produces valid TriageResult; totals match (T-04) | `tests/integration/test_triage_agent.py` |
| Full pipeline | Integration | pytest | All 5 passes; final SARIF validates (S-03) | `tests/integration/test_full_pipeline.py` |
| Corpus regression | Snapshot | runner.py | Each corpus entry produces expected (ruleId, file, line) tuples | `tests/corpus/runner.py` |

### 13.2 Shared Fixtures

```python
# tests/conftest.py

@pytest.fixture
def vulnerable_python_app(tmp_path) -> Path:
    """Write a deliberately vulnerable Python file for scanner testing.
    Contains: eval(), subprocess.call(shell=True), hardcoded password.
    Confirmed true positives for CWE-094, CWE-078, CWE-798."""

@pytest.fixture
def vulnerable_csharp_app(tmp_path) -> Path:
    """Write a deliberately vulnerable C# controller.
    Contains: SqlCommand string concat, BinaryFormatter, missing [Authorize].
    Confirmed true positives for CWE-089, CWE-502, CWE-862."""

@pytest.fixture
def sample_sarif() -> dict:
    """Minimal valid SARIF 2.1.0 document with 3 findings across 2 tools."""

@pytest.fixture
def clean_python_app(tmp_path) -> Path:
    """Write a secure Python file that should produce zero findings.
    Uses parameterised queries, subprocess with list args, no hardcoded secrets."""

@pytest.fixture
def clean_csharp_app(tmp_path) -> Path:
    """Write a secure C# controller with [Authorize], parameterised EF queries,
    Secure/HttpOnly cookies. Should produce zero findings."""
```

### 13.3 PydanticAI Testing Patterns

**CI guardrail — prevent accidental LLM calls in tests:**

```python
# tests/conftest.py
from pydantic_ai import models as pydantic_ai_models

# Fail loudly if any test accidentally makes a real LLM call
pydantic_ai_models.ALLOW_MODEL_REQUESTS = False
```

**Deterministic testing with TestModel (no LLM, validates schema only):**

```python
from pydantic_ai.models.test import TestModel

async def test_triage_agent_output_validates(sample_sarif, vulnerable_python_app):
    """Verify triage agent produces valid TriageResult without calling LLM."""
    with triage_agent.override(model=TestModel()):
        result = await triage_agent.run(
            "Triage these findings",
            deps=mock_deps,
        )
        assert isinstance(result.output, TriageResult)
        assert result.output.total_confirmed + result.output.total_false_positive + \
               result.output.total_needs_context == len(result.output.findings)
```

**Scripted testing with FunctionModel (full control over LLM response):**

```python
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse, TextPart

def mock_triage_response(messages, info):
    """Return a canned triage result for deterministic testing."""
    return ModelResponse(parts=[TextPart(json.dumps({
        "findings": [{
            "original_rule_id": "B602",
            "original_tool": "bandit",
            "file_path": "app.py",
            "line_number": 42,
            "verdict": "CONFIRMED",
            "confidence": 0.95,
            "rationale": "subprocess.call with shell=True and user input is exploitable"
        }],
        "total_confirmed": 1,
        "total_false_positive": 0,
        "total_needs_context": 0,
    }))])

async def test_triage_agent_confirms_shell_true():
    """Verify triage correctly confirms shell=True finding."""
    with triage_agent.override(model=FunctionModel(mock_triage_response)):
        result = await triage_agent.run("Triage these findings", deps=mock_deps)
        assert result.output.findings[0].verdict == TriageVerdict.CONFIRMED
```

**Test naming convention:** `test_{action}_{expected_result}_{condition}`

```python
test_triage_confirms_finding_when_shell_true
test_triage_rejects_fp_when_confidence_below_threshold
test_holistic_flags_binaryformatter_as_critical
test_sarif_merge_deduplicates_across_tools
```

### 13.4 CI Structural Checks

```yaml
# In CI workflow
- name: No subprocess outside runner
  run: |
    VIOLATIONS=$(grep -rn "create_subprocess\|subprocess\." src/security_review/ \
      --include="*.py" \
      | grep -v "tools/runner.py" \
      | grep -v "# subprocess-ok:" || true)
    if [ -n "$VIOLATIONS" ]; then
      echo "P-02 VIOLATION: subprocess calls outside tools/runner.py"
      echo "$VIOLATIONS"
      exit 1
    fi
```

---

## 14.0 Distribution

### 14.1 Git Submodule

Consumer repos add the module:
```bash
git submodule add https://github.acme.corp/sec/security-review .security
```

Run a review:
```bash
cd /path/to/target-repo
python -m security_review --target . --mode full --output security-report.sarif
```

Or with the `.security` submodule:
```bash
python .security/src/security_review --target . --mode full
```

### 14.2 Bootstrap

```bash
# Install Python dependencies
pip install -e .security[all]

# Verify external tools are installed
python -m security_review doctor
# Checks: opengrep, bandit, gitleaks, dotnet (optional), security-scan (optional)
# Reports: installed version, expected version, status
```

### 14.3 Versioning

SemVer tags on the security-review repo. MAJOR for output schema changes (SARIF structure, finding model), MINOR for new rules or CWE entries, PATCH for rule tuning and bug fixes. Consumer repos pin via submodule SHA.

---

## 15.0 Files Involved (Complete)

```
src/security_review/__init__.py
src/security_review/__main__.py
src/security_review/cli.py
src/security_review/config.py
src/security_review/config_schema.py
src/security_review/errors.py
src/security_review/logging.py
src/security_review/providers.py
src/security_review/copilot_model.py
src/security_review/code_intel/__init__.py
src/security_review/code_intel/types.py
src/security_review/code_intel/parsers/__init__.py
src/security_review/code_intel/parsers/base.py
src/security_review/code_intel/parsers/python_parser.py
src/security_review/code_intel/parsers/csharp_parser.py
src/security_review/code_intel/graph.py
src/security_review/code_intel/quality.py
src/security_review/code_intel/unsafe_patterns.py
src/security_review/code_intel/security_weight.py
src/security_review/code_intel/renderer.py
src/security_review/evidence.py
src/security_review/budget.py
src/security_review/models/__init__.py
src/security_review/models/findings.py
src/security_review/models/inventory.py
src/security_review/models/config_review.py
src/security_review/models/report.py
src/security_review/sarif/__init__.py
src/security_review/sarif/loader.py
src/security_review/sarif/merger.py
src/security_review/sarif/converter.py
src/security_review/sarif/taxonomy.py
src/security_review/sarif/tags.py
src/security_review/tools/__init__.py
src/security_review/tools/runner.py
src/security_review/tools/registry.py
src/security_review/tools/redactor.py
src/security_review/tools/specs/opengrep.yaml
src/security_review/tools/specs/bandit.yaml
src/security_review/tools/specs/gitleaks.yaml
src/security_review/tools/specs/roslyn.yaml
src/security_review/tools/specs/security_scan.yaml
src/security_review/tools/specs/pip_audit.yaml
src/security_review/tools/specs/dotnet_vuln.yaml
src/security_review/agents/__init__.py
src/security_review/agents/deps.py
src/security_review/agents/triage/__init__.py
src/security_review/agents/triage/agent.py
src/security_review/agents/holistic/__init__.py
src/security_review/agents/holistic/agent.py
src/security_review/agents/config_review/__init__.py
src/security_review/agents/config_review/agent.py
src/security_review/passes/__init__.py
src/security_review/passes/inventory.py
src/security_review/passes/sast.py
src/security_review/passes/triage.py
src/security_review/passes/holistic.py
src/security_review/passes/config_review.py
src/security_review/passes/merge.py
src/security_review/passes/pipeline.py
src/security_review/passes/batching.py
config/settings/security_review.yaml
config/providers.yaml
config/pricing.yaml
config/prompts/system.md
config/prompts/triage.md
config/prompts/holistic/csharp.md
config/prompts/holistic/python.md
config/prompts/config_review.md
rules/opengrep/csharp/lang/cwe-089-sql-injection/*.yaml
rules/opengrep/csharp/lang/cwe-079-xss/*.yaml
rules/opengrep/csharp/lang/cwe-502-deserialization/*.yaml
rules/opengrep/csharp/lang/cwe-327-weak-crypto/*.yaml
rules/opengrep/csharp/lang/cwe-078-os-command-injection/*.yaml
rules/opengrep/csharp/lang/cwe-798-hardcoded-credentials/*.yaml
rules/opengrep/csharp/aspnet-core/cwe-352-csrf/*.yaml
rules/opengrep/csharp/aspnet-core/cwe-601-open-redirect/*.yaml
rules/opengrep/csharp/aspnet-core/cwe-611-xxe/*.yaml
rules/opengrep/csharp/aspnet-core/cwe-918-ssrf/*.yaml
rules/opengrep/csharp/ef-core/cwe-089-sql-injection/*.yaml
rules/opengrep/python/lang/cwe-094-code-injection/*.yaml
rules/opengrep/python/lang/cwe-502-deserialization/*.yaml
rules/opengrep/python/lang/cwe-078-os-command-injection/*.yaml
rules/opengrep/python/lang/cwe-327-weak-crypto/*.yaml
rules/opengrep/python/lang/cwe-798-hardcoded-credentials/*.yaml
rules/opengrep/python/django/cwe-089-sql-injection/*.yaml
rules/opengrep/python/django/cwe-079-xss/*.yaml
rules/opengrep/python/django/cwe-352-csrf/*.yaml
rules/opengrep/python/flask/*.yaml
rules/opengrep/python/fastapi/*.yaml
rules/gitleaks/.gitleaks.toml
rules/roslyn/Directory.Build.security.props
rules/roslyn/security.editorconfig
taxonomy/cwe.yaml
taxonomy/cwe-top25-2024.yaml
taxonomy/owasp-top10-2021.yaml
taxonomy/hadolint-cwe-map.yaml
corpus/csharp/cwe-089-sql-injection/source/*.cs
corpus/csharp/cwe-089-sql-injection/expected.sarif
corpus/csharp/cwe-502-deserialization/source/*.cs
corpus/csharp/cwe-502-deserialization/expected.sarif
corpus/csharp/false-positives/*.cs
corpus/python/cwe-089-sql-injection/source/*.py
corpus/python/cwe-078-os-command-injection/source/*.py
corpus/python/cwe-094-code-injection/source/*.py
corpus/python/false-positives/*.py
tests/conftest.py
tests/unit/test_sarif_loader.py
tests/unit/test_sarif_merger.py
tests/unit/test_tool_registry.py
tests/unit/test_inventory.py
tests/unit/test_findings_model.py
tests/unit/test_cwe_taxonomy.py
tests/integration/test_opengrep_scan.py
tests/integration/test_bandit_scan.py
tests/integration/test_gitleaks_scan.py
tests/integration/test_triage_agent.py
tests/integration/test_full_pipeline.py
tests/corpus/runner.py
AGENTS.md
CLAUDE.md
.github/copilot-instructions.md
.github/instructions/csharp-security.instructions.md
.github/instructions/python-security.instructions.md
pyproject.toml
README.md
```

---

*End of specification.*
