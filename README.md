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

### Quickstart

1. `git clone` the repo, then `cd` into it.
2. `python setup.py --fix` — installs everything it can, no prompts.
3. Authenticate the default `copilot` provider: `gh auth login` (GitHub Copilot OAuth, $0 via subscription).
4. `python scar.py health-check` — confirms tools + auth are ready.
5. `python scar.py review --target <repo> --mode full` — run a complete review.

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
| 13 Python packages | pydantic, pydantic-settings, pyyaml, click, structlog, rich, tree-sitter, tree-sitter-c-sharp, pydantic-ai, json-repair, bandit, pytest, pytest-asyncio |
| 8 external tools | OpenGrep, Betterleaks, Hadolint, Trivy, .NET SDK, GitHub Copilot SDK, Claude Agent SDK, Codex CLI |
| Project structure | Config files, prompts, taxonomy, rules directories |
| GitHub Copilot auth | `gh auth status` + copilot extension |
| LLM provider config | Model alias resolution, API keys or Copilot SDK |

No editable install is needed — run directly with `python scar.py` (see `setup.py`'s `check_editable_install`).

### Manual install (if you prefer)

```bash
# 1. Python packages
pip install -e '.[all]'

# 2. External tools (macOS)
brew install opengrep betterleaks hadolint trivy

# 3. Verify
python setup.py --check
```

### Provider credentials

API-key providers (`anthropic:`, `openai:`) read their keys from `config/.env` (gitignored, never committed). OAuth providers (`copilot:`, `claude:`) authenticate via `gh auth login` / `claude setup-token` instead — no keys needed in `.env`.

```bash
cp config/.env.example config/.env
# then edit config/.env and fill in only the providers you actually use
```

`python scar.py health-check` reports whether the configured provider's auth is ready (see the "auth: `<provider>`" row) without making any network calls.

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

# Resume a killed/aborted run from its output directory (keeps completed
# passes and spend; reuses the original run's configuration verbatim)
python scar.py review --resume var/output/2026-07-14-my-app-1a2b3c4d/

# Stream a partial SARIF after each LLM pass (security-report.partial.sarif)
python scar.py review --target . --stream
```

### All review options

| Option | Description |
|--------|-------------|
| `--target PATH` | Path to codebase root (required unless `--resume` is given) |
| `--mode MODE` | `full` / `sast` / `sast-triage` (default: `full`) |
| `--resume PATH` | Resume a previous run from its `var/output/{date}-{target}-{id}/` directory — completed passes are restored from checkpoints, spend is preserved. Conflicts with `--target`/`--mode`/`--provider`/other config flags |
| `--stream` | Write `security-report.partial.sarif` after each LLM pass (readable partial report if the run dies) |
| `--provider STR` | LLM provider:model (e.g. `copilot:claude-opus-4.6`) |
| `--budget FLOAT` | Max LLM spend in USD (0 = unlimited) |
| `--output PATH` | Output SARIF path (default: auto-generated under `var/output/`) |
| `--summary PATH` | Output markdown summary path |
| `--format FMT` | Report format: `summary`, `full`, `json`, `csv`, `all` (comma-separated) |
| `--config PATH` | Override config YAML path |
| `--triage-all` | Triage LOW findings too (default: MODERATE+ only, score ≥ 0.20) |
| `--trace` | Write per-agent trace files to `var/output/{run}/traces/` |
| `--exclude GLOB` | fnmatch glob (relative path) to exclude from the review, repeatable (e.g. `--exclude 'vendor/*'`) |
| `--include GLOB` | Restrict the review to matching globs, repeatable |
| `--no-preflight` | Skip the pre-run provider auth probe and pricing validation (`full`/`sast-triage` modes only) |
| `--fail-on BAND` | Exit 3 if any finding is at or above this priority band: `urgent`/`elevated`/`moderate`/`low` (for CI gating) |
| `--fail-on-degraded` | Exit 4 if the review completed with coverage gaps (degradations) |
| `-v` / `--verbose` | Show batch/tool detail and structlog output |
| `--debug` | DEBUG-level logging + full tracebacks |
| `--quiet` | Errors only — suppress all progress output |
| `--json-logs` | JSON log lines to stderr (for CI) |
| `--no-file-log` | Disable file logging to `var/logs/` |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass — completed cleanly, no `--fail-on`/`--fail-on-degraded` threshold triggered |
| `1` | Crash — failed before producing a report, or aborted mid-run (partial artifacts salvaged when possible; see "Partial results salvaged" on stderr) |
| `2` | CLI usage error (click) — e.g. an invalid option value |
| `3` | Findings at or above the `--fail-on` threshold |
| `4` | Completed, but with coverage gaps (degradations) and `--fail-on-degraded` was set |
| `130` | Interrupted (Ctrl-C) |

A pass failure or crash does not discard prior passes' results — inventory and SAST findings (and any completed LLM passes) are salvaged and merged into the report even if a later pass fails or the run is interrupted. Coverage gaps (missing tools, failed checks, budget cutoffs, etc.) are always recorded as degradations and rendered in every report format, regardless of whether `--fail-on-degraded` is set — the flag only controls whether they affect the exit code.

---

## Pipeline Modes

| Mode | Passes Run | LLM Required | Use Case |
|------|-----------|-------------|----------|
| `sast` | 1 (Inventory) + 2 (SAST) + Merge | No | Fast deterministic scan; combine with `--fail-on` for CI gating |
| `sast-triage` | 1 + 2 + 3 (Triage) + Merge | Yes | SAST with false-positive filtering |
| `full` | 1 + 2 + 3 + 4 (Holistic) + 5 (Config) + 6 (Verify) + Merge (7) | Yes | Complete security review |

---

## Pipeline Architecture

```
Pass 1: INVENTORY        File discovery, language detection, security-weight scoring
Pass 2: SAST             OpenGrep, Bandit, Betterleaks, Hadolint, Trivy, Roslyn
Pass 3: TRIAGE (LLM)     Confirm/refute each SAST finding with full-file context
Pass 4: HOLISTIC (LLM)   Cross-file analysis — authZ, crypto, deserialization, IDOR
Pass 5: CONFIG (LLM)     Review appsettings, Dockerfile, CI YAML, pyproject.toml
Pass 6: VERIFY (LLM)     Independent adversarial verdict on every LLM-discovered
                         finding — a separate skeptic agent re-reads the source
                         (never the finder's reasoning) and defaults to disbelief
Pass 7: MERGE            Combine all findings -> SARIF + reports + triage.json
```

Pass 6 writes its verdict into the same `properties.triage_verdict` field Pass 3
uses, so the "Triage" counts in the summary and terminal output include Pass-6
verdicts. Refuted findings are kept in the SARIF (scored low), never dropped.
Each completed pass is checkpointed to `var/output/{run}/state/`, so a killed
run can be continued with `--resume` without losing work or spend.

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
| `security-report.partial.sarif` | SARIF 2.1.0 | Partial merged report written after each LLM pass (`--stream` only) |
| `state/` | JSON | Per-pass checkpoints + config/cost snapshots — what `--resume` restores |

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

**Graph cache:** Call graphs and file-cache fingerprints are persisted per-target under SCAR's own `var/cache/graphs/<target-key>/graph.db` (`<target-key>` is a hash of the resolved target path). SCAR never writes into the repository it scans — no `.scar/` directory is created in the target. If a previously scanned repo has an old `.scar/` directory from before this change, it is orphaned and safe to delete manually.

If the call graph fails to build (e.g. a `pyan3` internal error), the pipeline does not fail — it records a `call_graph_failed` degradation and falls back to keyword-only file selection for the holistic pass. Degradations are always visible in every report format.

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
```

Structural analysis (parsing, call graph, PageRank, security-weight) lives in
the `src/code_analysis/` package, consumed directly by the pipeline. Quality
metrics are available via `python scar.py quality --target .`.

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

# Delete run directories that never produced a security-report.md
# (crashed/interrupted before Pass 7 — Merge). Prompts for confirmation.
python scar.py reports --prune-incomplete

# Same, but skip the confirmation prompt (for scripting)
python scar.py reports --prune-incomplete --yes
```

`--prune-incomplete` is recovery for runs that crashed or were interrupted before a report was ever written — it never touches a run directory that has a `security-report.md`, so runs salvaged mid-pipeline (see "Exit codes" above) are always kept.

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
| `codex` | ChatGPT Plus/Pro OAuth | $0 | `codex` CLI auth (`pip install codex-auth`) |

### Model aliases

Short names are resolved through `config/models.yaml`:

```
copilot:claude-sonnet    ->  copilot:claude-sonnet-4.6
copilot:claude-opus      ->  copilot:claude-opus-4.6
claude:claude-sonnet     ->  claude:claude-sonnet-4-6   (dashes for Claude Agent SDK)
anthropic:claude-sonnet  ->  anthropic:claude-sonnet-4-6  (dashes for Anthropic SDK)
openai:gpt               ->  openai:gpt-5.5
```

`python scar.py list-models` prints the live version of this table — every provider, its alias resolutions, and the per-1M-token rates — read straight from `config/models.yaml` and `config/pricing.yaml`, with the models named in `config/settings/security_review.yaml` marked. It makes no network or LLM calls.

```bash
python scar.py list-models                       # everything SCAR can bill and run
python scar.py list-models --provider anthropic  # one provider
python scar.py list-models --all                 # include models with no pricing entry
python scar.py list-models --json                # machine-readable
```

Models are only listed by default if `config/pricing.yaml` has an entry for them, because cost tracking rejects a model it cannot price. `--all` reveals the rest.

### Azure AI Foundry models

`--foundry` switches the same command from the local registry to a live query against the Azure AI Foundry resource named in the `foundry:` block of `config/settings/security_review.yaml`. It reports what is **published** on that resource — the models callable right now — and marks which of them SCAR can actually route to, meaning those with a `foundry:<model>` entry in `config/pricing.yaml`.

```bash
python scar.py list-models --foundry                                  # published on the resource
python scar.py list-models --foundry --catalog                        # + everything the region offers
python scar.py list-models --foundry --catalog --publisher Anthropic   # narrow the catalog
python scar.py list-models --foundry --json                            # machine-readable
```

The catalog view distinguishes the two hosting variants Anthropic models ship in on Foundry — `hosted-on=anthropic` (billed through Anthropic, needs commercial declarations at deployment) versus `hosted-on=azure` (first-party, usually the default version) — and shows each model's inference retirement date.

Catalog presence is not permission: an approved-publisher Azure Policy can still refuse a deployment. Authentication comes from your `az login` session, so the `foundry:` block holds resource coordinates only and never credentials. `az` is invoked through `tools/runner.run_tool_sync`, the repository's single subprocess chokepoint.

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
      passes/                 #   Pipeline pass stages + orchestrator + checkpoint/resume
      agents/                 #   PydanticAI agent definitions (triage, holistic, config_review, verify)
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
    prompts/                  # LLM agent system prompts (triage.md, config_review.md, verify.md)
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
    code_map.py                 # Code map generation (thin CLI over src/code_analysis)
  var/
    output/                   # Review output: {date}-{target}-{run-id}/
    logs/                     # JSONL system logs (daily rotation)
  docs/                       # Architecture, plans, standards, research
  .githooks/                  # pre-commit / commit-msg hooks (activate with: git config core.hooksPath .githooks)
```

---

## License

MIT — Herman Young
