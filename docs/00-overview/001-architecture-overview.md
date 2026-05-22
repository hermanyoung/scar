# SCAR — Architecture Overview

## The Problem

A single LLM prompt cannot perform a comprehensive security review.

Even the best model, given the instruction "review this codebase for security vulnerabilities", will produce shallow, inconsistent results. It will focus on whatever catches its attention first, miss entire vulnerability classes, hallucinate findings it cannot evidence, and produce different results on every run. Scaling to thousands of files makes it worse — the model loses focus, exceeds context limits, and burns through retries on malformed output.

This is not a model quality issue. It is a prompting architecture issue. One broad question produces broad, unreliable answers.

## The Solution

Decompose the review into many small, focused, deterministic steps.

A single prompt forces the model to simultaneously decide what to look for, which files matter, and whether each issue is real. That is three cognitive tasks competing for the same context window. Performance degrades predictably. The model anchors on whatever it spots first, coverage becomes random, and results vary between runs.

The fix is to separate those decisions. We decide what to look for (the CWE taxonomy). We decide which files matter (file type selection per vulnerability class). The model only answers one question: does this specific file have this specific problem? That is a classification task, not an open-ended exploration. LLMs are dramatically better at classification than generation under ambiguity.

Instead of "review this codebase for vulnerabilities", we ask:

> "Read these 12 controller files. Check whether each POST/PUT/DELETE endpoint has an explicit authorization decorator (@login_required, [Authorize], Depends(auth)). Flag endpoints that modify data without one."

That is CWE-862 (Missing Authorization). One check, one question, relevant files only.

We do this 26 times — once per CWE that requires LLM reasoning. Each check has its own prompt, its own file selection, and produces structured findings. The LLM never has to hold the entire codebase in context or decide what to look for. We decide what to look for. The LLM decides whether each specific file has the specific problem.

## Architecture

The pipeline has 5 passes. Passes 1-2 are deterministic (no LLM). Passes 3-5 use LLM agents with focused prompts.

```
Pass 1: INVENTORY
  Discover files, detect languages, score security relevance.
  Output: FileManifest with security weights per file.

Pass 2: DETERMINISTIC SAST
  Run pattern-based tools concurrently:
    - Bandit (Python AST security linter)
    - OpenGrep (AST pattern matching, custom YAML rules)
    - betterleaks (hardcoded secrets, API keys, tokens)
    - Hadolint (Dockerfile linter)
    - Trivy (dependency vulnerabilities — Python, .NET, npm/pnpm)
    - Roslyn / SecurityCodeScan (C# analyzers)
  Each tool produces SARIF. Results are merged and deduplicated.
  Output: Merged SARIF with all deterministic findings.

Pass 3: TRIAGE (LLM)
  For each SAST finding, ask the LLM:
    "Is this a true positive, false positive, or does it need more context?"
  The LLM reads the source file, traces data flow, and assigns a verdict
  with confidence score and rationale.
  Output: TriageResult — each finding confirmed or filtered.

Pass 4: CWE-DRIVEN REVIEW (LLM)
  For each CWE that requires human-like reasoning (26 checks):
    1. Select files relevant to this CWE (controllers for auth checks,
       crypto modules for weak algorithms, config files for secrets, etc.)
    2. Read file contents locally and inline them directly into the prompt
    3. One agent call per CWE — no tool calls, no multi-turn, no timeouts
    4. The agent checks for the specific issue and returns structured findings
  One agent call per CWE. Not one prompt for everything.
  Output: HolisticReviewResult — new findings the SAST tools cannot detect.

Pass 5: CONFIG REVIEW (LLM)
  Review configuration files (appsettings.json, Dockerfile, CI YAML,
  pyproject.toml, .env patterns) for security misconfigurations.
  Output: ConfigReviewResult.

MERGE
  Combine all SARIF + LLM findings into final output:
    - security-report.sarif (SARIF 2.1.0 with CWE taxonomy)
    - security-report.md (human-readable summary)
    - triage.json (full audit trail of LLM decisions)
```

## Why One CWE at a Time

The taxonomy file (`taxonomy/cwe.yaml`) is the single source of truth. Each CWE declares:

- **detection method**: `sast` (pattern rules only), `llm` (LLM check only), `sast+llm` (both), or `tool` (external scanner)
- **file_types**: which files the LLM should read (controller, auth, crypto, config, etc.)
- **check**: the focused prompt — one question about one vulnerability class

Example — CWE-862 Missing Authorization:

```yaml
"862":
  name: "Missing Authorization"
  detection: llm
  file_types: [controller, route, middleware]
  check: |
    Check whether state-changing endpoints (POST, PUT, DELETE) have explicit
    authorization enforcement. Read each controller and route file. Verify
    presence of auth decorators/attributes:
    - Python Django: @login_required, @permission_required, LoginRequiredMixin
    - Python Flask: @login_required or custom auth decorator
    - Python FastAPI: Depends() with auth dependency
    - C# ASP.NET: [Authorize], [Authorize(Roles=...)], RequireAuthorization()
    Flag endpoints that modify data without any of these.
```

This approach means:

1. **The LLM never decides what to look for** — we enumerate every CWE to check
2. **Each call is focused** — small context, one question, clear success criteria
3. **File selection is targeted** — auth checks only read controllers, crypto checks only read crypto modules
4. **Adding a new check is one YAML entry** — no code changes needed
5. **Progress is granular** — you see each CWE check as it runs
6. **Failures are isolated** — if CWE-862 fails, CWE-502 still runs

## Provider Architecture

The pipeline is provider-agnostic. The same agents run against any LLM:

| Provider | Auth | Cost |
|----------|------|------|
| `claude:claude-sonnet-4-6` | Claude Max/Pro OAuth | $0 (subscription) |
| `claude:claude-opus-4-6` | Claude Max/Pro OAuth | $0 (subscription) |
| `copilot:claude-opus-4.6` | GitHub Copilot OAuth | $0 (subscription) |
| `copilot:claude-sonnet-4.6` | GitHub Copilot OAuth | $0 (subscription) |
| `copilot:gpt-5.5` | GitHub Copilot OAuth | $0 (subscription) |
| `anthropic:claude-sonnet-4-6` | API key | Per-token |
| `openai:gpt-5.5` | API key | Per-token |

The `build_model()` function in `providers.py` is the single dispatch point. Agents never know which provider they are using — the model is passed at `.run()` time.

Output models use auto-repair field validators so the same Pydantic schemas work across all providers regardless of whether the LLM uses native JSON schema enforcement or prompted mode.

## Priority Scoring

Every finding receives a composite priority score: **Severity x Confidence x Exposure**.

This tells you what to fix first. Severity alone is not enough — a HIGH severity finding in dead code matters less than a MEDIUM severity finding in a public-facing controller.

| Component | What it measures | Range | Source |
|-----------|-----------------|-------|--------|
| **Severity** | How bad if exploited | 0.1 - 1.0 | SARIF level (error=1.0, warning=0.6, note=0.3) |
| **Confidence** | How sure we are it's real | 0.5 - 1.0 | Triage verdict or detection method |
| **Exposure** | Is the code reachable from external input | 0.1 - 1.0 | File security weight from inventory |

**Confidence values:**

| Source | Score | Meaning |
|--------|-------|---------|
| LLM triage confirmed | 1.0 | The LLM read the code and confirmed it's exploitable |
| SAST + LLM confirmed | 0.9 | Pattern match validated by LLM reasoning |
| LLM-only finding | 0.8 | LLM holistic/config review finding (no SAST validation) |
| SAST pattern match only | 0.7 | Pattern matched, no LLM triage performed |
| Unvalidated | 0.6 | No triage performed (sast-only mode) |
| Needs context | 0.5 | LLM couldn't determine without more information |

**Exposure** comes from the inventory pass. Files are scored 0-10 based on indicators like "controller" in the filename, presence of route decorators, auth-related imports, subprocess calls, etc. This maps to 0.1-1.0 for the priority calculation.

**Example:**

```
Finding: SQL injection in UserController.cs:45
  Severity:   1.0  (error — HIGH/CRITICAL)
  Confidence: 1.0  (LLM triage confirmed)
  Exposure:   0.8  (controller file, security weight 8/10)
  Priority:   0.80 (URGENT band)

Finding: Weak hash in cache_utils.py:12
  Severity:   0.6  (warning — MEDIUM)
  Confidence: 0.7  (SAST pattern match only)
  Exposure:   0.2  (internal utility, security weight 2/10)
  Priority:   0.08 (LOW band)
```

The first finding is a confirmed SQL injection in a public controller. The second is a weak hash in an internal cache utility. Priority scoring puts the controller fix first, even though both are "security findings."

Priority bands: **URGENT** (>= 0.70), **ELEVATED** (>= 0.40), **MODERATE** (>= 0.20), **LOW** (< 0.20).

All components are stored in the SARIF `properties` for each finding, so the scoring is fully transparent and auditable.

## Output

All findings are normalised into SARIF 2.1.0 with CWE taxonomy tagging. Output goes to `var/output/{date}-{target}-{run-id}/`:

- **security-report.sarif** — machine-readable, compatible with GitHub Code Scanning and VS Code SARIF Viewer. Each finding includes priority score and components in `properties`.
- **security-report.md** — human-readable summary with priority-sorted findings table, severity counts, top CWEs, triage stats
- **triage.json** — full audit trail of every LLM decision (verdict, rationale, confidence, model version, cost)

## Key Design Decisions

1. **Deterministic first, LLM second.** Pattern-based tools catch the obvious issues. The LLM handles what patterns cannot: authorization closure, data flow across files, business logic, configuration intent.

2. **One CWE per agent call.** Not one prompt for everything. Not one agent per file. One focused question per vulnerability class, targeting only the files that could have that vulnerability.

3. **Auto-repair, not reject.** LLMs produce imperfect structured output. Field validators normalise formatting mistakes (wrong CWE format, percentage instead of decimal, missing zero-padding) instead of burning retries. The finding content matters more than the formatting.

4. **Taxonomy as config.** Adding a new security check is a YAML entry, not a code change. The taxonomy declares what to check, how to check it, and which files to read. The pipeline reads it and executes.

5. **Provider-agnostic.** The same pipeline runs on Copilot (free), Anthropic (API key), or OpenAI (API key). No provider-specific code in any agent or pass.