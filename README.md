# SCAR — Security Code AI Review

Security code review for C# (.NET) and Python codebases. Combines deterministic SAST tools with LLM-powered multi-pass review. Outputs SARIF 2.1.0 with CWE taxonomy tagging.

## Table of Contents

- [Setup](#setup)
- [Running a Security Review](#running-a-security-review)
- [Pipeline Modes](#pipeline-modes)
- [Pipeline Architecture](#pipeline-architecture)
- [Output](#output)
- [Code Quality Scoring](#code-quality-scoring)
- [Code Intelligence](#code-intelligence)
- [Testing Rules](#testing-rules)
- [Testing CWE Checks (LLM)](#testing-cwe-checks-llm)
- [Provider Testing & Benchmarks](#provider-testing--benchmarks)
- [Viewing Reports](#viewing-reports)
- [Configuration](#configuration)
- [Testing & Development](#testing--development)
- [Git Submodule Usage](#git-submodule-usage)
- [Project Structure](#project-structure)

---

## Setup

The `setup.py` script checks your OS, Python version, all Python packages, external SAST tools, project structure, GitHub Copilot authentication, and LLM provider availability. It is idempotent — run it as often as you like.

```bash
# Interactive — checks everything, prompts to install what's missing
python setup.py

# Auto-install — no prompts, installs everything it can
python setup.py --fix

# CI mode — exit 0 if ready, exit 1 if not (no prompts)
python setup.py --check
```

### What it checks

| Category | Details |
|----------|---------|
| OS | macOS / Linux / Windows detection, platform-specific install commands |
| Python | Requires >= 3.11 |
| Editable install | `pip install -e '.[all]'` |
| 12 Python packages | pydantic, pydantic-ai, structlog, rich, tree-sitter, bandit, pytest, etc. |
| 8 external tools | opengrep, betterleaks, hadolint, trivy, pip-audit, dotnet, security-scan, copilot SDK |
| Project structure | Config files, prompts, taxonomy, rules directories |
| GitHub Copilot auth | `gh auth status` + copilot extension |
| LLM provider config | Model alias resolution, API keys or Copilot SDK |

### Manual install (if you prefer)

```bash
# 1. Python packages
pip install -e '.[all]'

# 2. External tools (macOS)
brew install opengrep betterleaks hadolint trivy

# 3. Verify
python setup.py --check
```

---

## Running a Security Review

```bash
# Full review (SAST + LLM triage + holistic + config review)
python scar.py review --target /path/to/codebase

# SAST only — no LLM, fast
python scar.py review --target . --mode sast

# SAST + LLM triage (no holistic/config passes)
python scar.py review --target . --mode sast-triage

# Specify provider and model
python scar.py review --target . --provider copilot:claude-opus-4.6

# Set a budget cap (USD)
python scar.py review --target . --budget 2.0

# Verbose output (shows batch/tool detail)
python scar.py review --target . -v

# Debug mode (full tracebacks + DEBUG-level logs)
python scar.py review --target . --debug

# Write per-agent trace files for inspection
python scar.py review --target . --trace

# Triage LOW-priority findings too (default: MODERATE+ only)
python scar.py review --target . --triage-all

# Choose report format(s): summary, full, json, csv, all
python scar.py review --target . --format all

# Quiet mode (errors only — for scripting)
python scar.py review --target . --quiet

# JSON log lines to stderr (for CI pipelines)
python scar.py review --target . --json-logs

# Custom config file
python scar.py review --target . --config my-config.yaml
```

### All review options

| Option | Description |
|--------|-------------|
| `--target PATH` | Path to codebase root (required) |
| `--mode MODE` | `full` / `sast` / `sast-triage` (default: `full`) |
| `--provider STR` | LLM provider:model (e.g. `copilot:claude-opus-4.6`) |
| `--budget FLOAT` | Max LLM spend in USD |
| `--output PATH` | Output SARIF path (default: auto-generated under `var/output/`) |
| `--summary PATH` | Output markdown summary path |
| `--format FMT` | Report format: `summary`, `full`, `json`, `csv`, `all` (comma-separated) |
| `--config PATH` | Override config YAML path |
| `--triage-all` | Triage LOW findings too (default: MODERATE+ only, score ≥ 0.20) |
| `--trace` | Write per-agent trace files to `var/output/{run}/traces/` |
| `-v` / `--verbose` | Show batch/tool detail and structlog output |
| `--debug` | DEBUG-level logging + full tracebacks |
| `--quiet` | Errors only — suppress all progress output |
| `--json-logs` | JSON log lines to stderr (for CI) |
| `--no-file-log` | Disable file logging to `var/logs/` |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed cleanly — all requested passes ran |
| `1` | Failed before producing a report (config error, crash before merge) |
| `2` | **Partial** — a report was written, but one or more passes failed and were skipped. Findings only reflect the passes that completed; see `triage.json`'s `pass_failures` and the report's "Pass Failures" section. |
| `130` | Interrupted (Ctrl-C) |

A pass failure does not discard prior passes' results — inventory and SAST findings (and any completed LLM passes) are always merged into the report, even if a later pass fails.

---

## Pipeline Modes

| Mode | Passes Run | LLM Required | Use Case |
|------|-----------|-------------|----------|
| `sast` | 1 (Inventory) + 2 (SAST) + Merge | No | Fast deterministic scan, CI gating |
| `sast-triage` | 1 + 2 + 3 (Triage) + Merge | Yes | SAST with false-positive filtering |
| `full` | 1 + 2 + 3 + 4 (Holistic) + 5 (Config) + Merge | Yes | Complete security review |

---

## Pipeline Architecture

```
Pass 1: INVENTORY        File discovery, language detection, security-weight scoring
Pass 2: SAST             OpenGrep, Bandit, Betterleaks, Hadolint, Trivy, Roslyn
Pass 3: TRIAGE (LLM)     Confirm/refute each SAST finding with full-file context
Pass 4: HOLISTIC (LLM)   Cross-file analysis — authZ, crypto, deserialization, IDOR
Pass 5: CONFIG (LLM)     Review appsettings, Dockerfile, CI YAML, pyproject.toml
MERGE                     Combine all findings -> SARIF + reports + triage.json
```

**Priority scoring:** Every finding is scored as `priority = severity x confidence x exposure` (0.0-1.0), then classified into bands:

| Band | Score | Meaning |
|------|-------|---------|
| URGENT | >= 0.70 | Exploitable, high-severity, confirmed |
| ELEVATED | >= 0.40 | Likely real, needs attention |
| MODERATE | >= 0.20 | Possible issue, worth reviewing |
| LOW | < 0.20 | Informational or low-confidence |

---

## Output

Output is written to `var/output/{date}-{target}-{run-id}/`:

| File | Format | Description |
|------|--------|-------------|
| `security-report.sarif` | SARIF 2.1.0 | Full findings with CWE taxonomy (GitHub Code Scanning compatible) |
| `security-report.md` | Markdown | Human-readable summary report |
| `security-report-full.md` | Markdown | Detailed report with all findings grouped by priority band |
| `security-report.json` | JSON | Machine-readable findings export |
| `security-report.csv` | CSV | Spreadsheet-friendly export |
| `triage.json` | JSON | Full audit trail — LLM decisions, cost log, evidence manifest |

Use `--format all` to generate every format, or `--format summary,json` for specific ones.

---

## Code Quality Scoring

The `quality` command scores a codebase across 7 dimensions using the PyQuality Index (PQI), producing a composite 0-100 score.

```bash
# Score a codebase
python scar.py quality --target /path/to/codebase

# Show improvement recommendations
python scar.py quality --target . --recommendations

# JSON output
python scar.py quality --target . --json

# Write JSON to file
python scar.py quality --target . -o quality-report.json

# Specific scope / exclusions
python scar.py quality --target . --scope src/ --exclude tests/

# AST-only (no external tools like bandit/radon)
python scar.py quality --target . --no-tools

# Weight profile: production (default), library, safety_critical
python scar.py quality --target . --profile safety_critical
```

**Dimensions:** Maintainability, Security, Modularity, Testability, Robustness, Elegance, Reusability.

When a full security review is run, the quality Security dimension is automatically upgraded with real findings data instead of AST-only heuristics.

---

## Code Intelligence

Structural analysis scripts for codebase understanding and security prioritisation.

```bash
# Generate a structural code map (Markdown)
python scripts/code_map.py

# Code map to stdout
python scripts/code_map.py --stdout

# JSON format, pretty-printed
python scripts/code_map.py --format json --pretty

# Token-budgeted for LLM context
python scripts/code_map.py --max-tokens 2048

# Summary statistics only
python scripts/code_map.py --stats

# Full code intelligence analysis
python scripts/code_intel.py --target .

# Security-weight ranking
python scripts/code_intel.py --target . --weights

# Unsafe pattern report
python scripts/code_intel.py --target . --unsafe

# Quality metrics
python scripts/code_intel.py --target . --quality
```

---

## Testing Rules

### Test a specific CWE's rules against a target

```bash
# Run all OpenGrep rules for CWE-89 (SQL injection) against a codebase
python scar.py test-rule --cwe 89 --target /path/to/codebase

# Filter to Python rules only
python scar.py test-rule --cwe 89 --target src/ --language python

# Test sensitive logging rules
python scar.py test-rule --cwe 532 --target ../my-app/
```

### List configured rules

```bash
# All rules
python scar.py list-rules

# Python rules only
python scar.py list-rules --language python

# C# rules only
python scar.py list-rules --language csharp
```

### Check tool availability

```bash
python scar.py health-check
```

### Validate internal code rules

```bash
# Check staged files (pre-commit)
python scripts/check_rules.py

# Check all source files
python scripts/check_rules.py --all

# Run a specific rule
python scripts/check_rules.py --rule 002.7
```

---

## Testing CWE Checks (LLM)

Run a single LLM holistic CWE check against a target without running the full pipeline. Useful for testing prompt quality and verifying detection logic.

```bash
# Run CWE-863 (Incorrect Authorization) check
python scar.py test-cwe --cwe 863 --target ../my-app/

# With trace output written to var/output/
python scar.py test-cwe --cwe 863 --target ../my-app/ --trace

# Specify a model
python scar.py test-cwe --cwe 502 --target src/ --provider copilot:claude-opus
```

---

## Provider Testing & Benchmarks

### Test LLM providers

Verify that provider + model combinations work with structured output and tool calling.

```bash
# Test all Copilot models (default)
python scar.py test-providers --copilot

# Test a specific model
python scar.py test-providers --models copilot:claude-opus-4.6

# Test OpenAI + Anthropic (needs API keys)
python scar.py test-providers --api

# Test everything
python scar.py test-providers --all
```

### Benchmark models

Compare LLM models against the ground-truth corpus. Reports F2 score, MCC, precision, recall, and per-CWE breakdown.

```bash
# Compare two models
python scripts/benchmark_models.py copilot:claude-sonnet-4.6 copilot:claude-opus-4.6

# Multiple runs for stability measurement
python scripts/benchmark_models.py --runs 3 copilot:claude-sonnet-4.6

# SAST-only baseline (no LLM, measures tool coverage)
python scripts/benchmark_models.py --sast-only

# Use a private held-out corpus
python scripts/benchmark_models.py --corpus ~/.security-review/eval-corpus/ copilot:claude-opus-4.6
```

---

## Viewing Reports

Browse and diff previous review runs.

```bash
# List all previous runs
python scar.py reports

# Filter by target name
python scar.py reports --target my-app

# Show the full report for a specific run
python scar.py reports --show d8e9f8db

# Compare findings between two runs
python scar.py reports --compare d2120108 d8e9f8db
```

---

## Configuration

### Default config

Configuration lives in `config/settings/security_review.yaml`:

```yaml
llm:
  provider_model: "copilot:claude-opus"     # Default LLM provider + model
  triage_model: "copilot:claude-sonnet"     # Override for Pass 3 (null = use provider_model)
  output_retries: 3                          # Max PydanticAI output validation retries
  max_budget_usd: 100                        # Max total LLM spend per run (0 = unlimited)
  max_tokens_per_batch: 150000               # Per-batch token limit
  concurrency: 1                             # Pass-level: concurrent CWE check dispatches
  cache_ttl: "ephemeral"                     # Anthropic prompt caching (ephemeral | 5m | 1h | null)
  # thinking_budget: 10000                   # Anthropic extended thinking (null = disabled)

  providers:
    copilot:
      max_concurrent: 2      # Copilot rate-limits aggressively
      session_timeout: 90.0
      backoff_seconds: 10.0
    anthropic:
      max_concurrent: 10
      session_timeout: 120.0
    openai:
      max_concurrent: 10
      session_timeout: 120.0

sast:
  opengrep_rules_path: "config/rules/opengrep"
  gitleaks_config_path: "config/rules/gitleaks/.gitleaks.toml"
  scanner_timeout_seconds: 300

triage:
  fp_confidence_threshold: 0.75              # FP verdict threshold
  min_score: 0.20                            # Triage MODERATE+ by default (0.0 = triage all)

review:
  mode: "full"                               # full | sast | sast-triage
  target_path: "."
  output_sarif: "security-report.sarif"
```

### Providers

Configured in `config/providers.yaml`:

| Provider | Auth Method | Cost | Setup |
|----------|------------|------|-------|
| `claude` | Claude Max/Pro OAuth | $0 | CLAUDE_CODE_OAUTH_TOKEN (auto via Claude Code) |
| `copilot` | GitHub Copilot OAuth | $0 | `gh auth login` + `pip install github-copilot-sdk` |
| `anthropic` | API key | Per-token | Set `ANTHROPIC_API_KEY` |
| `openai` | API key | Per-token | Set `OPENAI_API_KEY` |

### Model aliases

Short names are resolved through `config/models.yaml`:

```
copilot:claude-sonnet    ->  copilot:claude-sonnet-4.6
copilot:claude-opus      ->  copilot:claude-opus-4.6
claude:claude-sonnet     ->  claude:claude-sonnet-4-6   (dashes for Claude Agent SDK)
anthropic:claude-sonnet  ->  anthropic:claude-sonnet-4-6  (dashes for Anthropic SDK)
openai:gpt               ->  openai:gpt-5.5
```

### Pricing

LLM pricing is externalised to `config/pricing.yaml` — never hardcoded. Cost tracking uses this file for per-token cost computation and cumulative budget enforcement.

---

## Testing & Development

```bash
# Install dev dependencies
pip install -e '.[dev]'

# Unit tests (no external tools needed)
pytest tests/unit/ -v

# Integration tests (requires bandit, opengrep, betterleaks, etc.)
pytest tests/integration/ -v

# All tests
pytest -v

# Eval regression tests (snapshot comparison against ground truth)
pytest tests/eval/ -v
```

### OpenGrep rule tests

Every OpenGrep rule under `config/rules/opengrep/` has a companion test file with `ruleid:` and `ok:` annotations. To validate rules:

```bash
# Run OpenGrep's built-in test mode against all rules
opengrep scan --test config/rules/opengrep/
```

---

## Git Submodule Usage

```bash
git submodule add https://github.acme.corp/sec/security-review .security
pip install -e .security[all]
python .security/scar.py review --target . --mode full
```

---

## Project Structure

```
scar/
  scar.py                     # Main CLI entry point (click)
  setup.py                    # Environment setup & health check
  src/
    security_review/          # Core pipeline module
      cli/                    #   Click CLI: app.py (group) + one module per command
      passes/                 #   5-pass pipeline stages + orchestrator
      agents/                 #   PydanticAI agent definitions (triage, holistic, config_review)
      models/                 #   Pydantic output models (findings, inventory, config_review, report)
      sarif/                  #   SARIF 2.1.0 loading, merging, taxonomy, tag normalisation
      tools/                  #   Subprocess runner (sole subprocess caller) + tool registry
      reporting/              #   Report renderers (summary, full, json, csv, terminal)
    code_analysis/            # Code intelligence (AST parsing, PageRank, security weighting)
    code_quality/             # PyQuality Index scoring
  config/
    settings/                 # App configuration YAML (security_review.yaml, logging.yaml)
    models.yaml               # Model aliases & provider overrides
    pricing.yaml              # LLM token pricing
    providers.yaml            # Auth config per provider
    prompts/                  # LLM agent system prompts (triage.md, config_review.md)
    taxonomy/                 # CWE registry (cwe.yaml) — single source of truth for all checks
    rules/                    # SAST tool rules
      opengrep/                #   40+ OpenGrep YAML rules with test files
      gitleaks/                #   Secret scanning config
      roslyn/                  #   Roslyn analyzer settings
    golden/                    # Golden fixture baselines for regression testing
  eval/                       # Vulnerable code samples with ground truth (python/, csharp/, docker/)
  tests/
    unit/                     # Unit tests (no external deps, no LLM calls)
    integration/              # Integration tests (needs tools installed)
    regression/                # Golden fixture tests (real LLM calls)
    eval/                       # Snapshot regression harness
  scripts/
    benchmark_cwes.py         # Per-CWE provider benchmarking against a reference target
    benchmark_models.py        # Model accuracy benchmarking against the eval corpus
    test_providers.py          # Provider compatibility tests
    check_rules.py             # Internal code rule checker
    code_intel.py               # Structural analysis
    code_map.py                 # Code map generation
    code_quality.py             # Standalone quality scoring
  var/
    output/                   # Review output: {date}-{target}-{run-id}/
    logs/                     # JSONL system logs (daily rotation)
  docs/                       # Architecture, plans, standards, research
  .githooks/                  # pre-commit / commit-msg hooks (activate with: git config core.hooksPath .githooks)
```

---

## License

MIT — Herman Young
