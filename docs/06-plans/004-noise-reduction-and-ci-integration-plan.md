# Noise Reduction and CI Integration Plan

**Source:** Analysis of [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) (Anthropic's official Claude Code security review action)
**Created:** 2 May 2026
**Status:** Planned
**Principles:** P1 (Deterministic Before Non-Deterministic), P5 (Config Not Code), P10 (Modular Reusable), P12 (Accuracy Over Volume)

---

## 0. Motivation

Anthropic ships a security review tool that is architecturally simpler than ours (pure LLM, no SAST, no SARIF, no typed outputs) but has invested heavily in **false positive engineering** — hard exclusion rules, codified precedents, confidence gating, and diff-aware scoping. Our pipeline is structurally superior but underinvests in noise reduction. This plan adopts their best ideas while preserving our architecture.

Key metrics to improve:
- **LLM cost per run** — reduce by 30-50% via pre-filtering
- **False positive rate** — reduce via precedents and confidence gating
- **Time to first result** — reduce via diff-aware scoping
- **Developer friction** — reduce via slash command entry point

---

## 1. Hard Exclusion Pre-Filter (Pass 2.5)

### Problem

Every SAST finding goes directly to Pass 3 (LLM triage). On a large codebase with 200+ SAST findings, many are obvious noise: DoS warnings, resource leaks, memory safety in managed languages, findings in test files. Each burns an LLM call (~$0.01-0.05).

### Design

Insert a deterministic pre-filter between Pass 2 (SAST) and Pass 3 (Triage). This honours P1: use deterministic rules before spending LLM tokens.

```
Pass 2 (SAST) -> Pass 2.5 (Pre-Filter) -> Pass 3 (Triage)
```

### Implementation

**New file:** `src/security_review/passes/pre_filter.py`

```python
@dataclass(frozen=True)
class ExclusionRule:
    """A single hard exclusion rule with compiled regex patterns."""
    name: str
    reason: str
    patterns: list[re.Pattern]
    file_filter: Callable[[str], bool] | None = None  # Optional file-type gate
```

**Exclusion categories** (derived from Anthropic's `HardExclusionRules` + our domain):

| Category | Patterns | Rationale |
|----------|----------|-----------|
| DoS / resource exhaustion | `denial of service`, `resource exhaustion`, `infinite loop`, `unbounded recursion` | Not exploitable vulns |
| Rate limiting | `missing rate limit`, `unlimited requests` | Hardening, not vuln |
| Resource leaks | `memory leak`, `unclosed resource`, `file descriptor leak`, `connection leak` | Not security vulns |
| Open redirects | `open redirect`, `unvalidated redirect` | Low impact |
| Memory safety in managed langs | `buffer overflow`, `use after free`, `null pointer dereference` in `.py`/`.cs` files | Impossible in Python/C# |
| Regex injection | `regex injection`, `regular expression dos` | Not exploitable |
| Test files | Any finding in `test_*`, `*_test.*`, `*Tests.cs`, `tests/`, `__tests__/` | Not production code |
| Documentation | Any finding in `*.md`, `*.rst`, `*.txt` | Not executable |
| Generated code | Findings in `*.designer.cs`, `*.g.cs`, `Migrations/` | Auto-generated |

**Interface:**

```python
def run_pre_filter(state: PipelineState) -> None:
    """Tag SAST findings that match hard exclusion rules.

    Mutates state.sast_sarif in place:
    - Sets properties.pre_filter_excluded = true
    - Sets properties.pre_filter_reason = "..."
    - Does NOT remove findings (audit trail preserved)
    """
```

**Triage integration:** Pass 3 skips findings where `properties.pre_filter_excluded == true`.

**Config:** `config/exclusions.yaml` — all patterns externalised per P5. Schema:

```yaml
exclusions:
  - name: dos_resource_exhaustion
    reason: "DoS/resource exhaustion finding (not an exploitable vulnerability)"
    patterns:
      - "denial of service"
      - "resource exhaustion"
      - "infinite.*loop"
      - "unbounded.*recursion"
  - name: test_files
    reason: "Finding in test file (not production code)"
    file_patterns:
      - "test_*"
      - "*_test.*"
      - "*Tests.cs"
      - "tests/**"
```

### Acceptance Criteria

- [ ] `pre_filter.py` loads rules from `config/exclusions.yaml`
- [ ] Unit tests cover each exclusion category with positive and negative cases
- [ ] Test files, empty findings, special chars, and long text are handled
- [ ] Excluded findings remain in SARIF with `pre_filter_excluded` property
- [ ] Pass 3 skips excluded findings
- [ ] Progress reports: "Pre-filter: 47 excluded, 153 sent to triage"

### Estimated Effort: 1 day

---

## 2. Exclusion Precedents for Triage and Holistic Prompts

### Problem

Our triage and holistic prompts give generic instructions. LLMs repeatedly flag the same false positive patterns: `json.loads()` as deserialization, Entity Framework queries as SQL injection, `Depends()` as missing auth. Anthropic maintains 17 codified "precedent" rules that encode domain expertise.

### Design

Create a `config/prompts/precedents.md` file injected into triage and holistic system prompts. Precedents are language-specific policy decisions, not patterns.

### Content (Initial Set)

```markdown
## Precedents — Do Not Report

These are standing decisions. Apply them before reporting any finding.

### Python
1. `json.loads()` and `json.load()` are safe deserialization. Not CWE-502.
2. `yaml.safe_load()` is safe. Only `yaml.load()` without SafeLoader is CWE-502.
3. `subprocess.run(args, shell=False)` with a list is safe. Only `shell=True` with string input is CWE-078.
4. FastAPI `Depends()` is trusted framework dependency injection.
5. Pydantic model validation is trusted input sanitisation at the boundary.
6. `os.environ.get()` reads trusted values. Environment variables are not attacker-controlled.
7. `hashlib` for checksums (file integrity, cache keys) is not weak crypto. Only flag `hashlib.md5` / `hashlib.sha1` for password hashing or digital signatures.
8. Logging URLs, request paths, and non-PII metadata is safe. Only flag logging of secrets, passwords, tokens, or PII.

### C# (.NET)
9. Entity Framework Core parameterises queries by default. LINQ-to-SQL is safe. Only flag raw SQL via `FromSqlRaw()` with string concatenation.
10. `System.Text.Json.JsonSerializer` is safe deserialization. Not CWE-502.
11. ASP.NET Core model binding with `[FromBody]` validates via data annotations. Not missing validation.
12. `IConfiguration["key"]` reads trusted config. Not attacker-controlled input.
13. `[Authorize]` on a controller class applies to all actions. Do not flag individual actions as missing auth if the class has it.

### General
14. Test files (`test_*`, `*_test.*`, `*Tests.cs`, `*Spec.cs`) should not generate findings.
15. UUIDs (v4) are cryptographically random and unguessable. Do not flag UUID-based access as IDOR.
16. CLI arguments and environment variables are trusted input in server-side code.
17. A lack of rate limiting, audit logging, or CSRF on non-browser APIs is hardening, not a vulnerability.
```

### Integration

- `load_prompt("triage")` returns the triage prompt + precedents appended
- `_build_check_prompt()` in holistic.py appends precedents to each CWE check
- Precedents file path is configurable via `config/settings/security_review.yaml`

### Acceptance Criteria

- [ ] `config/prompts/precedents.md` created with initial set
- [ ] Triage agent system prompt includes precedents
- [ ] Holistic agent system prompt includes precedents
- [ ] Precedents are loaded from file (not hardcoded in Python)
- [ ] Benchmark: re-run triage on corpus — FP rate should decrease

### Estimated Effort: 0.5 day

---

## 3. Post-Triage Confidence Gate

### Problem

A finding triaged as `CONFIRMED` with confidence 0.51 still appears in the report at the same priority as one with confidence 0.95. Anthropic gates on confidence >= 0.8 for HIGH and >= 0.7 for MEDIUM.

### Design

Add a configurable `min_confidence` threshold to `TriageConfig`. Findings below threshold are downgraded:

- `CONFIRMED` with `confidence < threshold` becomes `NEEDS_CONTEXT`
- Priority score recalculated with `needs_context` confidence weight (0.5 instead of 1.0)

### Implementation

**Config change** in `config_schema.py`:

```python
class TriageConfig(BaseModel, extra="forbid"):
    fp_confidence_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    min_confidence: float = Field(
        default=0.70, ge=0.0, le=1.0,
        description="Minimum confidence to keep CONFIRMED verdict. Below this, downgrade to NEEDS_CONTEXT.",
    )
    min_level: str = Field(default="warning", ...)
```

**Merge pass change** in `merge.py` `_score_all_findings()`:

```python
# After reading triage_verdict from properties:
if verdict == "CONFIRMED":
    confidence_val = result.get("properties", {}).get("triage_confidence", 1.0)
    if confidence_val < state.config.triage.min_confidence:
        verdict = "NEEDS_CONTEXT"  # Downgrade
        props["triage_verdict_original"] = "CONFIRMED"
        props["triage_verdict"] = "NEEDS_CONTEXT"
        props["triage_downgrade_reason"] = f"confidence {confidence_val} < threshold {state.config.triage.min_confidence}"
```

### Acceptance Criteria

- [ ] `min_confidence` added to `TriageConfig` with default 0.70
- [ ] Triage pass writes `triage_confidence` to SARIF properties
- [ ] Merge pass downgrades low-confidence CONFIRMED to NEEDS_CONTEXT
- [ ] Original verdict preserved in `triage_verdict_original`
- [ ] Unit test: finding with confidence 0.5 is downgraded; 0.9 is not

### Estimated Effort: 0.5 day

---

## 4. Claude Code `/security-review` Slash Command

### Problem

Developers must install our CLI and learn the command syntax. Anthropic ships a zero-install slash command that works inside Claude Code.

### Design

Create `.claude/commands/security-review.md` — a single file that becomes a `/security-review` command in any project that includes our module.

### Implementation

**New file:** `.claude/commands/security-review.md`

The command will:
1. Inject live `git status`, `git diff --name-only`, and `git diff` output
2. Run our pipeline via `python -m security_review --mode sast --target .`
3. If full mode is available (API keys configured), run `--mode full`
4. Format output as the markdown summary report

Key design decisions:
- Restrict tools to `Bash(git:*)`, `Bash(python -m security_review:*)`, `Read`, `Glob`, `Grep`
- Use sub-tasks: one for scanning, parallel sub-tasks for false positive assessment
- Confidence cutoff at 8/10 (matching Anthropic's approach)
- Output format: markdown report matching our `security-report.md` format

### Acceptance Criteria

- [ ] `.claude/commands/security-review.md` created
- [ ] `/security-review` runs successfully in Claude Code
- [ ] Output matches our standard markdown report format
- [ ] Works in sast-only mode without API keys
- [ ] Works in full mode when API keys are configured
- [ ] Tool restrictions prevent unintended file modifications

### Estimated Effort: 0.5 day

---

## 5. Diff-Aware Review Mode (`--diff`)

### Problem

Our pipeline reviews the entire codebase. For CI/CD integration on pull requests, this is wasteful — only changed files need review. Anthropic's tool is exclusively diff-aware, which makes it fast and cheap for PR workflows.

### Design

Add `--diff` flag to the CLI that scopes the pipeline to changed files while preserving full-repo context for SAST tools that need it.

### Behaviour

```
security-review --mode full --diff --target .
```

| Pass | Diff Mode Behaviour |
|------|---------------------|
| Pass 1 (Inventory) | Discover all files (SAST needs full context), but tag changed files via `git diff --name-only` |
| Pass 2 (SAST) | Run on full repo (tools need complete context for cross-file resolution) |
| Pass 2.5 (Pre-Filter) | No change |
| Pass 3 (Triage) | Only triage findings in changed files. Skip findings in unchanged files. |
| Pass 4 (Holistic) | Only check CWEs against changed files. Include diff context in prompt. |
| Pass 5 (Config) | Only review changed config files |
| Merge | Include all findings but tag unchanged-file findings as `diff_excluded` |

### Implementation

**Config change:**

```python
class ReviewConfig(BaseModel, extra="forbid"):
    mode: str = Field(default="full", pattern=r"^(full|sast|sast-triage)$")
    diff_base: str | None = Field(
        default=None,
        description="Git ref for diff base (e.g. 'origin/main'). If set, scopes LLM passes to changed files.",
    )
```

**CLI change:**

```python
@app.command()
def review(
    ...
    diff: bool = typer.Option(False, "--diff", help="Scope LLM passes to files changed since origin/main"),
    diff_base: str = typer.Option("origin/main", "--diff-base", help="Git ref for diff comparison"),
):
```

**New utility:** `src/security_review/diff.py`

```python
def get_changed_files(target_path: Path, diff_base: str = "origin/main") -> set[str]:
    """Get files changed between diff_base and HEAD.

    Returns set of relative file paths (forward slashes).
    Falls back to empty set if not a git repo or diff_base doesn't exist.
    """
```

**Inventory change:** `FileEntry` gets `changed: bool = False` field. Set by comparing against `get_changed_files()`.

**Triage change:** Filter `sast_findings` to only include findings where file is in the changed set.

**Holistic change:** `select_files_for_check()` intersects with changed files when in diff mode.

**Merge change:** Findings in unchanged files get `properties.diff_excluded = true` and deprioritised band.

### Acceptance Criteria

- [ ] `--diff` flag scopes LLM passes to changed files only
- [ ] `--diff-base` allows custom base ref (default: `origin/main`)
- [ ] SAST still runs on full repo (tools need complete context)
- [ ] Findings in unchanged files appear in SARIF but tagged as `diff_excluded`
- [ ] Summary report distinguishes "in-scope" vs "out-of-scope" findings
- [ ] Graceful fallback when not in a git repo or base ref doesn't exist
- [ ] Cost reduction measurable: same repo, full vs diff mode

### Estimated Effort: 2-3 days

---

## 6. Custom Instruction Files

### Problem

Different organisations have different security policies. Currently, changing what the LLM checks for requires modifying Python code or prompt files in the module itself. Anthropic supports `custom-security-scan-instructions` and `false-positive-filtering-instructions` as external files.

### Design

Add two configurable paths in `ReviewConfig` that load external instruction files and append them to agent prompts.

### Implementation

**Config change:**

```python
class ReviewConfig(BaseModel, extra="forbid"):
    ...
    custom_scan_instructions: str | None = Field(
        default=None,
        description="Path to custom security scan instructions (appended to holistic prompts)",
    )
    custom_filter_instructions: str | None = Field(
        default=None,
        description="Path to custom false positive filtering instructions (appended to triage prompt)",
    )
```

**CLI change:**

```python
custom_instructions: Path = typer.Option(
    None, "--custom-instructions",
    help="Path to custom security scan instructions file",
)
```

**Prompt integration:**
- Triage: `load_prompt("triage")` + custom_filter_instructions content
- Holistic: `_build_check_prompt()` + custom_scan_instructions content
- Config review: `_build_config_review_prompt()` + custom_scan_instructions content

**Documentation:** Create `docs/guides/custom-instructions.md` explaining:
- File format (plain text, appended to prompts)
- Example: organisation-specific security categories
- Example: compliance requirements (GDPR, PCI DSS, HIPAA)
- Example: technology-specific exclusions

### Acceptance Criteria

- [ ] `custom_scan_instructions` path loads and appends to holistic/config prompts
- [ ] `custom_filter_instructions` path loads and appends to triage prompt
- [ ] Missing file raises `ConfigurationError` (fail fast per P6)
- [ ] CLI `--custom-instructions` flag works
- [ ] Example custom instruction files in `docs/guides/`
- [ ] No impact when fields are not set (default None)

### Estimated Effort: 1 day

---

## 7. Eval Framework for Accuracy Measurement

### Problem

We have corpus files for unit testing but no framework for measuring precision and recall against real-world codebases. Anthropic's eval engine runs against real GitHub PRs and reports findings. Our P12 principle says "recall per CWE can be tested against corpus samples" but this isn't built.

### Design

Create `scripts/eval_pr.py` — a CLI tool that runs our pipeline against a GitHub PR and reports accuracy metrics.

### Implementation

**New file:** `scripts/eval_pr.py`

```
python scripts/eval_pr.py owner/repo#123 --verbose --output-dir eval_results/
```

**Workflow:**

1. Parse `owner/repo#pr_number` argument
2. Clone repo into temporary worktree (git worktree for efficiency)
3. Fetch PR head: `git fetch origin pull/{N}/head && git checkout FETCH_HEAD`
4. Run pipeline: `python -m security_review --mode full --target {worktree} --output {output_dir}`
5. Parse SARIF output
6. If annotations file exists (`eval_annotations/{owner}_{repo}_{pr}.yaml`), compare findings against expected
7. Report: total findings, by severity, by CWE, precision/recall if annotated
8. Clean up worktree

**Annotations format** (`eval_annotations/`):

```yaml
repo: owner/repo
pr: 123
description: "SQL injection in user search endpoint"
expected_findings:
  - file: "app/controllers/users.py"
    line_range: [42, 45]
    cwe: "CWE-89"
    severity: HIGH
  - file: "app/controllers/admin.py"
    line_range: [18, 22]
    cwe: "CWE-862"
    severity: MEDIUM
expected_false_positives:
  - file: "app/utils/hash.py"
    cwe: "CWE-328"
    reason: "hashlib.sha256 used for file checksums, not passwords"
```

**Metrics:**

```python
@dataclass
class EvalMetrics:
    total_findings: int
    true_positives: int       # Found and expected
    false_positives: int      # Found but not expected
    false_negatives: int      # Expected but not found
    precision: float          # TP / (TP + FP)
    recall: float             # TP / (TP + FN)
    runtime_seconds: float
    cost_usd: float
```

### Acceptance Criteria

- [ ] `scripts/eval_pr.py` runs pipeline against a GitHub PR
- [ ] Git worktree used for efficient repo management
- [ ] SARIF output parsed and findings extracted
- [ ] Annotations YAML format defined and validated
- [ ] Precision/recall computed when annotations exist
- [ ] Results saved to JSON in output directory
- [ ] Cleanup of worktrees on success and failure

### Estimated Effort: 2 days

---

## Implementation Order and Dependencies

```
Phase A (parallel, no dependencies):
  [1] Hard Exclusion Pre-Filter
  [2] Exclusion Precedents
  [3] Confidence Gate
  [4] Slash Command

Phase B (depends on Phase A):
  [5] Diff-Aware Mode (depends on inventory changes from [1])
  [6] Custom Instructions (depends on config patterns from [2])

Phase C (independent):
  [7] Eval Framework
```

### Total Estimated Effort: 7-8 days

### Success Metrics

| Metric | Current | Target | How to Measure |
|--------|---------|--------|----------------|
| LLM cost per run (100-file Python repo) | ~$2.50 | < $1.50 | Compare triage.json cost before/after pre-filter |
| False positive rate | ~30% (estimated) | < 15% | Eval framework against annotated PRs |
| Triage findings skipped by pre-filter | 0% | 30-50% | Pre-filter progress log |
| Time for PR-scoped review | N/A (not supported) | < 60s for 10-file diff | `--diff` mode timing |
| Developer adoption friction | CLI install required | Zero (slash command) | `/security-review` works without install |

---

## References

- **Source repo:** [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) (cloned to `/tmp/claude-code-security-review`)
- **Key files studied:**
  - `claudecode/findings_filter.py` — Hard exclusion rules + LLM filtering
  - `claudecode/claude_api_client.py` — Precedents and FP filtering prompts
  - `claudecode/prompts.py` — Security audit prompt template
  - `.claude/commands/security-review.md` — Slash command implementation
  - `claudecode/evals/eval_engine.py` — PR evaluation framework
  - `docs/custom-filtering-instructions.md` — Custom instruction documentation
- **Our principles:** P1, P5, P6, P10, P12 (see `docs/03-principles/01-project-principles.md`)
