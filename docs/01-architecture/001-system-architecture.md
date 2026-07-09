# SCAR — System Architecture

## Directory Layout

```
scar/
├── scar.py                         # CLI entry point
├── pyproject.toml                   # Package config + dependencies
├── config/
│   ├── .env                         # API keys (gitignored)
│   ├── .env.example                 # Template for config/.env
│   ├── models.yaml                  # Model alias + provider-override registry
│   ├── settings/
│   │   ├── security_review.yaml     # Pipeline configuration
│   │   └── logging.yaml             # Logging configuration
│   ├── providers.yaml               # Provider auth config
│   ├── pricing.yaml                 # LLM token pricing (resolved/wire-form keys)
│   ├── golden/                      # Golden fixture baselines for regression tests
│   ├── prompts/                     # Agent system prompts (holistic uses inline
│   │   │                            # prompts built in code, not files here)
│   │   ├── triage.md
│   │   └── config_review.md
│   ├── taxonomy/
│   │   ├── cwe.yaml                 # CWE registry (single source of truth)
│   │   └── bandit-cwe-map.yaml
│   └── rules/
│       ├── opengrep/                # OpenGrep YAML rules + test files
│       ├── gitleaks/.gitleaks.toml
│       └── roslyn/                  # C# Roslyn analyzer config
├── src/security_review/             # Python source
├── tests/                           # pytest suite (unit/, integration/, regression/, eval/)
├── eval/                            # Vulnerable code samples for evaluation/regression testing
├── scripts/                         # Utility scripts
├── var/                             # Runtime output (gitignored)
│   ├── output/                      # SARIF, summary, triage.json, run.json, events.jsonl
│   ├── logs/                        # JSONL structured logs
│   └── tmp/                         # Intermediate tool output (run-scoped: tmp/<run_id>/)
└── docs/
```

## Module Dependency Map

Data flows downward. No circular imports.

```
scar.py (CLI entry point)
  │
  └── passes/pipeline.py             run_pipeline()
        passes/state.py              PipelineState
        │
        ├── passes/inventory.py      Pass 1: file discovery + security weighting
        │     └── models/inventory.py
        │
        ├── passes/sast.py           Pass 2: deterministic SAST orchestration
        │     ├── tools/runner.py    ONLY module that calls subprocess
        │     ├── tools/registry.py  Tool specs loaded from YAML
        │     ├── sarif/loader.py    Load + normalise SARIF
        │     ├── sarif/merger.py    Merge + dedup SARIF
        │     └── sarif/converter.py JSON → SARIF conversion
        │
        ├── passes/triage.py         Pass 3: LLM triage orchestration
        │     └── agents/triage/agent.py
        │           (no tools — file content inlined in prompt)
        │
        ├── passes/holistic.py       Pass 4: CWE-driven LLM review
        │     ├── checks.py          CWE check registry (from taxonomy/cwe.yaml)
        │     ├── context_builder.py inline_files() — token-budgeted file inlining
        │     ├── output_parser.py   parse_holistic_response() — JSON + markdown fallback
        │     └── agents/holistic/agent.py
        │           (no tools — file content inlined in prompt)
        │
        ├── passes/config_review.py  Pass 5: config file review
        │     └── agents/config_review/agent.py
        │           (no tools — config file content inlined in prompt)
        │
        └── passes/merge.py          Final SARIF merge + report generation
              ├── sarif/taxonomy.py  CWE taxonomy injection
              └── sarif/tags.py      CWE tag normalisation

providers.py                         Provider routing (single dispatch)
  ├── OpenAIModel                    openai:* → standard API key
  ├── AnthropicModel                 anthropic:* → standard API key
  ├── CopilotModel                   copilot:* → GitHub Copilot SDK OAuth
  ├── ClaudeModel                    claude:* → Claude Max/Pro OAuth (Agent SDK)
  └── codex:*                        BLOCKED — codex-auth v0.1.1 returns empty responses

config.py → config_schema.py         Configuration (secrets via .env, settings via YAML)
budget.py                            Cost tracking (audit, not enforcement)
evidence.py                          SHA-256 evidence manifest
logging.py                           structlog configuration
errors.py                            Error taxonomy (SCAN_, SARIF_, LLM_, SYS_)
```

## Layers

### Layer 1: Configuration

```
config.py              Settings (secrets from .env) + load_config (YAML)
config_schema.py        LLMConfig (+ ProviderConfig), SASTConfig, TriageConfig, ReviewConfig
providers.py            build_model() — single provider dispatch point
model_providers.py      get_openai_provider(), get_anthropic_provider() — SDK provider factories
model_settings.py       build_model_settings() — provider-specific ModelSettings (caching, thinking)
claude_model.py         ClaudeModel — Claude Agent SDK wrapper (Max/Pro OAuth)
copilot_model.py        CopilotModel — GitHub Copilot SDK wrapper (OAuth)
```

`Settings` loads API keys from `config/.env`. `SecurityReviewConfig` loads pipeline settings from `config/settings/security_review.yaml`. `build_model()` constructs a PydanticAI Model from a `provider:model` string. Per-provider concurrency limits (`ConcurrencyLimitedModel`) are applied here — shared across all passes so triage + holistic + config_review respect a single rate-limit gate. Agents never import provider-specific code.

### Layer 2: SARIF Processing

```
sarif/loader.py         load_sarif(), normalize_uri(), get_result_location()
sarif/merger.py         merge_sarif() — dedup by (CWE, file, line), highest severity wins
sarif/converter.py      pip-audit JSON → SARIF, dotnet JSON → SARIF
sarif/taxonomy.py       CWE taxonomy block injection
sarif/tags.py           external/cwe/cwe-NNN tag normalisation
sarif/types.py          Type aliases for SARIF dicts
```

`normalize_uri(uri, target_root)` is the single function that handles all URI format variations (file://, absolute, relative). Every caller passes `target_root` so URIs become relative paths consistently.

### Layer 3: Tool Infrastructure

```
tools/registry.py       SecurityToolSpec + load_tool_specs() from YAML
tools/runner.py         run_tool() — ONLY subprocess caller in the codebase
tools/redactor.py       Secret pattern masking in SARIF output
tools/specs/*.yaml      Per-tool configuration (7 tools)
```

`tools/runner.py` is the only module that calls `asyncio.create_subprocess_exec`. No other module touches subprocess. Tool specs are YAML files declaring binary path, arg template, exit codes, output format, and file type filters.

### Layer 4: CWE Check Registry

```
checks.py               load_cwe_checks() from taxonomy/cwe.yaml
taxonomy/cwe.yaml        Single source of truth for all CWE checks
```

Each CWE in the taxonomy declares its detection method (`sast`, `llm`, `sast+llm`, `tool`), target file types, and a focused check prompt. `load_cwe_checks()` returns the subset that requires LLM reasoning. Adding a new security check is a YAML entry — no code changes.

### Layer 5: Agents

```
agents/deps.py           SecurityReviewDeps + load_prompt()
agents/triage/agent.py   Pass 3 agent — confirm/refute SAST findings
agents/holistic/agent.py Pass 4 agent — CWE-driven cross-file analysis
agents/config_review/agent.py  Pass 5 agent — config file review
context_builder.py       inline_files() — token-budgeted file content inlining
output_parser.py         parse_holistic_response(), parse_triage_response()
```

All agents use `output_type=str` — no tool calls. File content is inlined into the prompt by the pass orchestrator before the agent is called (P14 — pre-materialized context). Agents are provider-agnostic — no default model set on any agent. The model is passed at `.run()` time.

`output_parser.py` extracts structured findings from the agent's plain text response:
- Tries JSON parsing first (works for native JSON providers like Anthropic, OpenAI)
- Falls back to markdown pattern matching (handles prompted providers like Copilot, Claude)
- Triage: extracts `**Verdict:**`, `**Confidence:**`, `**Rationale:**` per finding
- Holistic: extracts `### SR-XXX-NNN` sections with severity, file path, evidence

### Layer 6: Pipeline Orchestration

```
passes/state.py          PipelineState — mutable dataclass carrying inter-pass data
passes/pipeline.py       run_pipeline() + progress callback orchestration
passes/inventory.py      Pass 1
passes/sast.py           Pass 2
passes/triage.py         Pass 3
passes/holistic.py       Pass 4
passes/config_review.py  Pass 5
passes/merge.py          Final merge
passes/batching.py       Token-aware file partitioning
```

`PipelineState` (in `state.py`) is a mutable dataclass that carries inter-pass state. Each pass reads from state and writes its output back. The pipeline is linear — no pass runs concurrently with another. Within a pass, tools/batches may run concurrently.

`on_progress` callback decouples progress reporting from the pipeline. The CLI sets it to display human-readable progress. Tests leave it as no-op.

## Data Flow

```
Target codebase
  │
  ▼
Pass 1: Inventory
  │  FileManifest (file paths, languages, security weights)
  ▼
Pass 2: SAST
  │  Merged SARIF (deterministic findings from bandit, opengrep, betterleaks)
  ▼
Pass 3: Triage
  │  TriageResult (each SAST finding confirmed/refuted with rationale)
  ▼
Pass 4: Holistic
  │  HolisticReviewResult (new findings from 26 focused CWE checks)
  ▼
Pass 5: Config Review
  │  ConfigReviewResult (configuration security findings)
  ▼
Merge
  │
  ├── var/output/security-report.sarif    SARIF 2.1.0 + CWE taxonomy
  ├── var/output/security-report.md       Human-readable summary
  └── var/output/triage.json              Full LLM audit trail
```

## Trust Boundaries

1. **Reviewed code → LLM context.** Source code under review is untrusted input. A malicious file can contain prompt injection. Controls: output schema enforcement (Pydantic models prevent freeform output), path traversal guard (`.resolve()` + `is_relative_to()`), no code execution by agents (read-only tools only).

2. **LLM output → SARIF report.** LLM-generated findings flow into downstream systems (GitHub Code Scanning, dashboards). Controls: every finding passes Pydantic validation with auto-repair validators, CWE IDs validated against taxonomy, file paths validated against manifest.

## Security Invariants

| ID | Invariant |
|----|-----------|
| P-01 | No subprocess calls outside `tools/runner.py` |
| P-02 | No `shell=True` anywhere in the codebase |
| P-03 | All agent tools validate file paths against manifest + target root |
| P-04 | All SARIF URIs normalised through `normalize_uri()` with `target_root` |
| P-05 | All output validators auto-repair instead of raising `ModelRetry` |
| P-06 | Provider selection is explicit at config time — no fallback models |
| P-07 | API keys loaded from `config/.env`, never hardcoded |
