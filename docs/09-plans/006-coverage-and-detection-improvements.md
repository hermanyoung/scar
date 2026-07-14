# Plan 006: Coverage Model and Detection Improvements

**Date:** 3 May 2026
**Status:** Implemented — gaps closed by 018/019
**Branch:** feat/coverage-and-detection-improvements
**Scope:** Build a coverage awareness layer, add deterministic Dockerfile scanning, strengthen LLM prompts for config/IaC, add corpus tests for new detections, and improve IDOR detection reliability.
**Disposition (2026-07-06):** Coverage-in-reports→018 WP1/WP2; hadolint CWE map + CWE-829 + IDOR rubric→019 WP-C/WP-D.

---

## 1. Problem Statement

A security review of `example-target` using an external prompt found two real issues:

1. **IDOR (CWE-863)** — Our tool found this (holistic pass), but with inconsistent severity across runs (Critical vs Medium for read-only operations).
2. **Docker ARG→ENV secret leakage** — Our tool missed this entirely. The Dockerfile is picked up by the config review pass, but the prompt doesn't mention ARG→ENV patterns.

Root cause analysis reveals a systemic gap, not two individual bugs:

### Current coverage by file type

| File Type | Extensions | Deterministic (SAST) | Semantic (LLM) | Layers |
|---|---|---|---|---|
| Python | .py | OpenGrep, Bandit, pip-audit | Holistic pass | 2 |
| C# | .cs, .csproj | OpenGrep, Roslyn, SecurityCodeScan | Holistic pass | 2 |
| Config | .json, .yaml, .toml, .xml | gitleaks | Config review | 2 |
| **Dockerfile** | Dockerfile, .dockerfile | **None** | Config review (weak) | **1 (weak)** |
| **CI/CD** | .yml in .github/, azure-pipelines | gitleaks (secrets only) | Config review (generic) | **1.5** |
| **IaC** | .bicep, .tf, .bicepparam | **None** | Config review (generic) | **1 (weak)** |
| Package manifests | .csproj, requirements.txt | dotnet list, pip-audit | Config review | 2 |

**Principle:** Every file type should have at least one deterministic check AND one semantic check (defense in depth). Dockerfile, CI/CD, and IaC currently have at most one weak layer.

**Principle:** The tool should report what it CAN'T detect, not just what it finds. Users currently assume full coverage.

---

## 2. Target State

### A. Coverage reporting in review output

After the findings summary, show what was covered:

```
  Coverage
  ──────────────────────────────────────────────────
  C# (12 files)        OpenGrep + Roslyn + LLM Holistic
  Config (5 files)     gitleaks + LLM Config Review
  Dockerfile (1 file)  hadolint + LLM Config Review
  Bicep (3 files)      LLM Config Review only
  ──────────────────────────────────────────────────
```

When a file type has only LLM coverage, mark it so the user knows the limitation.

### B. Dockerfile deterministic scanning (hadolint)

Integrate hadolint as an optional SAST tool, same pattern as bandit/opengrep:
- Tool spec in `config/tools/`
- SARIF output parsing (hadolint supports `--format sarif`)
- Catches: running as root, :latest tags, curl piped to shell, missing pipefail, unquoted variables

### C. Strengthened LLM config review prompt

Expand the config review prompt from 7 generic focus areas to specific per-file-type checklists:

**Dockerfile additions:**
- ARG with secret-like names (TOKEN, PASSWORD, SECRET, KEY, CREDENTIAL) persisted via ENV
- Multi-stage secret bleed (secrets in build stage accessible via `docker history`)
- curl piped to shell without hash verification
- COPY of .env, .pfx, .key, .pem files into image
- Missing health check instruction

**CI/CD additions:**
- Workflow secrets referenced in echo/print/log statements
- pull_request_target with checkout of PR HEAD (code injection vector)
- Actions pinned to mutable tags (v1, master) instead of SHA
- Excessive permissions (write-all, contents: write without justification)

**IaC additions (Bicep/Terraform):**
- Storage accounts without HTTPS-only
- Key vaults without purge protection
- Network security groups allowing 0.0.0.0/0 inbound
- Managed identity vs credential-based auth

### D. Improved IDOR detection reliability

The holistic pass catches IDOR but classifies severity inconsistently. Two improvements:

1. **Prompt refinement** — The csharp.md holistic prompt already mentions IDOR at item 4, but it's too brief. Expand with specific severity guidance:
   - Read-only IDOR (listing/fetching other users' data) = Medium
   - Write IDOR (modifying/deleting other users' data) = Critical
   - This removes the LLM's judgment variance on severity classification

2. **code_analysis IDOR heuristic** — Add a detection signal to the code_analysis module: detect controllers with auth attributes where data access methods return unfiltered collections. This gives the holistic pass a hint rather than relying on it to spot the pattern cold. (Deferred to a future plan — this is a code_analysis enhancement, not a prompt fix.)

---

## 3. Files to Change

### New files

| File | Purpose |
|---|---|
| `config/tools/hadolint.yaml` | Tool spec for hadolint (sarif_native — no custom parser needed if SARIF is clean) |
| `corpus/docker/cwe-200-secret-exposure/source/Dockerfile` | Vulnerable Dockerfile (ARG→ENV) |
| `corpus/docker/cwe-200-secret-exposure/ground_truth.yaml` | Expected findings |
| `corpus/docker/cwe-200-secret-exposure/patched/Dockerfile` | Fixed version (BuildKit secrets) |
| `corpus/docker/best-practices/source/Dockerfile` | Root user, :latest, curl pipe |
| `corpus/docker/best-practices/ground_truth.yaml` | Expected findings |
| `corpus/docker/false-positives/source/Dockerfile` | Non-secret ARG→ENV (build metadata only) |
| `corpus/docker/false-positives/ground_truth.yaml` | Expected: no findings |
| `corpus/csharp/cwe-863-idor/source/VulnerableController.cs` | Controller with auth but no ownership check |
| `corpus/csharp/cwe-863-idor/source/ContactsService.cs` | Service layer returning unfiltered data |
| `corpus/csharp/cwe-863-idor/ground_truth.yaml` | Expected IDOR findings with severity |
| `corpus/csharp/cwe-863-idor/patched/SecureController.cs` | Fixed version with ownership checks |
| `tests/unit/test_coverage_model.py` | Unit tests for coverage reporting |

### Modified files

| File | Change |
|---|---|
| `config/prompts/config_review.md` | Expand Docker, CI/CD, IaC sections |
| `config/prompts/holistic/csharp.md` | Expand IDOR section with severity guidance |
| `config/prompts/holistic/python.md` | Add IDOR severity guidance (Django/Flask equivalent) |
| `src/security_review/tools/specs/hadolint.yaml` | New: hadolint tool spec |
| `src/security_review/passes/config_review.py` | Add Bicep/Terraform extensions to config file detection |
| `src/security_review/passes/inventory.py` | Add .bicep, .tf, .bicepparam to extension map; build coverage model |
| `src/security_review/reporting/terminal.py` | Render coverage section |
| `src/security_review/models/coverage.py` | New file: FileCoverage, CoverageReport dataclasses |
| `src/security_review/reporting/common.py` | Add coverage field to ReportData (reads from PipelineState) |

### Files NOT changed

- `src/code_analysis/` — no changes (future IDOR heuristic is a separate plan)
- `src/code_quality/` — no changes
- `security-review.py` — no changes (coverage renders via terminal.py)
- Holistic pass mechanics — only the prompt changes, not the pass logic
- Config review pass mechanics — only the prompt and extension list change

---

## 4. Coverage Model

### Design

During inventory (Pass 1), build a coverage map alongside the manifest:

```python
@dataclass
class FileCoverage:
    file_type: str               # "csharp", "python", "dockerfile", "bicep", "config", etc.
    deterministic_tools: list[str]   # ["opengrep", "roslyn", "security-scan"]
    semantic_passes: list[str]       # ["holistic", "config_review"]
    coverage_level: str              # "strong" (2+ layers), "moderate" (1 det + 1 sem), "weak" (sem only), "none"

@dataclass
class CoverageReport:
    by_type: dict[str, FileCoverage]
    file_counts: dict[str, int]      # {"csharp": 12, "dockerfile": 1, ...}
    weak_types: list[str]            # file types with < 2 layers
```

Built from the tool registry (which tools apply to which extensions). The semantic pass→file type mapping is hardcoded — there are only 2 semantic passes (holistic for code, config_review for config/docker/IaC), not worth a registry until we add more.

### Coverage classification

| Layers | Level | Meaning |
|---|---|---|
| Deterministic + Semantic | **Strong** | Both SAST rules and LLM review |
| Deterministic only | **Moderate** | SAST rules but no LLM review (unlikely) |
| Semantic only | **Weak** | LLM review only, no deterministic checks |
| None | **None** | File discovered but no analysis applied |

### Where it's computed

In `passes/inventory.py` after file discovery, before batching. Uses the tool registry (`config/tools/tools.yaml`) to determine which tools apply to which file extensions.

### Where it's rendered

1. Terminal output (after findings table, before quality breakdown)
2. Markdown summary report (new section)
3. JSON report (new `coverage` field)

---

## 5. Hadolint Integration

### Tool spec (`config/tools/hadolint.yaml`)

```yaml
name: hadolint
binary: hadolint
version_cmd: ["hadolint", "--version"]
output_format: sarif
sarif_native: true
success_exit_codes: [0, 1]
arg_template: ["{binary}", "--format", "sarif", "{target_path}"]
output_capture: stdout
timeout_seconds: 60
target_type: file
applies_to: ["Dockerfile", "Dockerfile.*", "*.dockerfile"]
cwe_source: rule_id_map
```

**Note:** `target_type: file` — hadolint operates on individual Dockerfiles, not directories.
The SAST pass must invoke it once per matching file. Verify the SAST runner supports
`target_type: file` or add support if missing.

### CWE mapping

| Hadolint Rule | CWE | Description |
|---|---|---|
| DL3007 | CWE-829 | Using :latest tag |
| DL3002 | CWE-250 | Running as root (no USER) |
| DL3001 | CWE-78 | curl piped to shell |
| DL4006 | CWE-78 | SHELL not set to pipefail |
| SC2086 | CWE-78 | Unquoted variable in RUN |

**Note:** Hadolint does NOT detect ARG→ENV secret leakage. That check (`SecretsUsedInArgOrEnv`) is a Docker BuildKit lint rule, not part of hadolint. ARG→ENV secret detection relies on the LLM config review prompt. If we need deterministic detection, we'd write a custom regex-based check (future work, not in this plan).

### Graceful degradation

Hadolint is marked `optional: true`. If not installed:
- `health-check` shows it as optional
- Pipeline continues without it
- Coverage report shows "Dockerfile: LLM Config Review only"

---

## 6. Config Review Prompt Expansion

### Current (22 lines, 7 generic areas)

The prompt lists 7 focus areas with 1-2 sentence descriptions each. Docker gets one line: "Flag running as root, using :latest tags, exposing unnecessary ports, COPY of sensitive files."

### Proposed (structured per file type)

```markdown
You are a security engineer reviewing configuration files for security misconfigurations.

**Input:** You receive configuration files. Each file's type is identified in the listing.

## Universal checks (all file types)

1. **Secrets in configuration.** Flag any password, API key, token, secret, or connection
   string hardcoded in config files. CRITICAL or HIGH severity.
2. **Debug and development modes.** Flag debug=True, Development environment settings
   in production-facing configs.
3. **Insecure defaults.** Flag HTTPS disabled, TLS < 1.2, certificate validation disabled.

## Dockerfile

4. **ARG→ENV secret leakage.** Flag any ARG with a secret-like name (TOKEN, PASSWORD,
   SECRET, KEY, CREDENTIAL, FEED_ACCESS) that is persisted via ENV in any stage.
   The secret becomes visible in `docker history` even if the final image is a
   different stage. MEDIUM severity.
5. **Running as root.** Flag missing USER directive in the final stage. LOW severity.
6. **Mutable base images.** Flag :latest or unpinned tags. Use digest pinning. LOW severity.
7. **Secrets copied into image.** Flag COPY of .env, .pfx, .key, .pem, credentials.json,
   or files matching secret patterns. HIGH severity.
8. **Unsafe downloads.** Flag curl/wget piped to sh/bash without hash verification. MEDIUM.
9. **Missing HEALTHCHECK.** Flag final stage without HEALTHCHECK instruction. LOW severity.

## CI/CD (GitHub Actions, Azure Pipelines, GitLab CI)

10. **Secret exposure in logs.** Flag secrets.X or $(SECRET) used in echo, print, or
    log statements. HIGH severity.
11. **Dangerous triggers.** Flag pull_request_target with checkout of PR head — code
    injection vector. CRITICAL severity.
12. **Mutable action references.** Flag actions pinned to branch tags (v1, main, master)
    instead of commit SHA. MEDIUM severity.
13. **Excessive permissions.** Flag write-all, contents: write, or packages: write
    without clear justification. MEDIUM severity.

## IaC (Bicep, Terraform, ARM templates)

14. **Public network exposure.** Flag network security groups, firewalls, or load
    balancers allowing 0.0.0.0/0 inbound. HIGH severity.
15. **Storage without HTTPS.** Flag storage accounts with supportsHttpsTrafficOnly=false
    or enableHttpsTrafficOnly=false. MEDIUM severity.
16. **Key vault without protection.** Flag key vaults without purge protection or
    soft delete. MEDIUM severity.
17. **Credential-based auth.** Flag connection strings with embedded credentials where
    managed identity or DefaultAzureCredential is available. MEDIUM severity.

## Application config (appsettings.json, web.config, .env)

18. **CORS.** Flag AllowAnyOrigin in production configs. Flag AllowAnyOrigin combined
    with AllowCredentials (invalid per spec). MEDIUM severity.
19. **Security headers.** Flag missing HSTS, X-Content-Type-Options, X-Frame-Options
    configuration. LOW severity.
20. **Dependency config.** Flag allow-prereleases, disabled vulnerability scanning,
    or pinned-to-vulnerable versions. LOW severity.

**Output:** Return a ConfigReviewResult. Use rule IDs SR-CFG-001 through SR-CFG-999.
```

---

## 7. Holistic Prompt IDOR Refinement

### Current (csharp.md, item 4)

```
4. **Direct object reference.** Flag controller actions that call dbContext.X.Find(id)
   or .Where(x => x.Id == id) using a user-supplied ID without an ownership check.
```

### Proposed

```
4. **Direct object reference (IDOR).**
   a. Flag controller actions that retrieve, modify, or delete resources by user-supplied
      ID without verifying the authenticated user owns the resource.
   b. Check BOTH the controller AND the service layer — if the service returns unfiltered
      data (e.g. `.ToListAsync()` with no user predicate), that is an IDOR even if the
      controller has [Authorize].
   c. Look for ownership fields (CreatedBy, UserId, OwnerId, TenantId) in the entity
      model that are never checked in queries.
   d. **Severity classification:**
      - **Critical:** Write operations (PUT, POST, DELETE) on another user's resource
      - **Medium:** Read operations (GET by ID, GET list) exposing another user's data
   e. Evidence must quote the specific query or service call that lacks the ownership
      predicate, AND the entity model field that should be used for filtering.
```

---

## 8. Corpus Tests

### Why corpus tests are needed

Corpus tests are regression tests for detection quality. Without them:
- We can't verify that prompt changes actually improve detection
- We can't prevent regressions when we modify prompts or add tools
- We have no baseline for false positive rates

### Corpus structure (follows existing convention)

```
corpus/
├── docker/
│   ├── cwe-200-secret-exposure/
│   │   ├── source/Dockerfile           # Vulnerable: ARG→ENV secret
│   │   ├── patched/Dockerfile          # Fixed: BuildKit secrets
│   │   └── ground_truth.yaml           # Expected findings
│   ├── best-practices/
│   │   ├── source/Dockerfile           # Root user, :latest, curl pipe
│   │   ├── patched/Dockerfile          # Fixed versions
│   │   └── ground_truth.yaml
│   └── false-positives/
│       ├── source/Dockerfile           # ARG→ENV for non-secret build metadata only
│       └── ground_truth.yaml           # Expected: no findings
├── csharp/
│   ├── cwe-863-idor/
│   │   ├── source/
│   │   │   ├── VulnerableController.cs # [Authorize] but no ownership check
│   │   │   └── ContactsService.cs      # Unfiltered .ToListAsync()
│   │   ├── patched/
│   │   │   ├── SecureController.cs     # With ownership verification
│   │   │   └── ContactsService.cs      # User-scoped queries
│   │   └── ground_truth.yaml           # Expected: 4 IDOR findings with severity
│   └── cwe-863-idor-false-positive/
│       ├── source/
│       │   └── AdminController.cs      # [Authorize(Roles="Admin")] — intentionally unscoped
│       └── ground_truth.yaml           # Expected: no findings (admin endpoints are legitimately unscoped)
├── cicd/                               # Future: add when CI/CD detection is validated
└── iac/                                # Future: add when IaC detection is validated
```

### Ground truth format (same as existing)

```yaml
# corpus/docker/cwe-200-secret-exposure/ground_truth.yaml
cwe: "200"
language: docker
description: "Build secret persisted in Docker image layer via ARG→ENV"

findings:
  - file: "Dockerfile"
    line: 44
    cwe_id: "CWE-200"
    label: true_positive
    description: "FEED_ACCESSTOKEN build argument persisted as ENV in image layer"
    sink: "ENV VSS_NUGET_EXTERNAL_FEED_ENDPOINTS"
    source: "ARG FEED_ACCESSTOKEN"

  - file: "Dockerfile"
    line: 42
    cwe_id: "CWE-78"
    label: true_positive
    description: "curl piped to sh without hash verification"
    sink: "sh"
    source: "curl -L https://..."
```

### IDOR ground truth with severity

```yaml
# corpus/csharp/cwe-863-idor/ground_truth.yaml
cwe: "863"
language: csharp
description: "IDOR via [Authorize] without ownership verification"

findings:
  - file: "VulnerableController.cs"
    line: 34
    cwe_id: "CWE-863"
    label: true_positive
    severity: medium
    description: "GET list returns all records without user-scoped filter"

  - file: "VulnerableController.cs"
    line: 43
    cwe_id: "CWE-863"
    label: true_positive
    severity: medium
    description: "GET by ID fetches any record without ownership check"

  - file: "VulnerableController.cs"
    line: 72
    cwe_id: "CWE-863"
    label: true_positive
    severity: critical
    description: "PUT updates any record without ownership verification"

  - file: "VulnerableController.cs"
    line: 95
    cwe_id: "CWE-863"
    label: true_positive
    severity: critical
    description: "DELETE removes any record without ownership verification"
```

### Docker false positive corpus

```yaml
# corpus/docker/false-positives/ground_truth.yaml
cwe: "200"
language: docker
description: "Dockerfile using ARG→ENV for non-secret build metadata"

findings:
  - file: "Dockerfile"
    line: 16
    cwe_id: "CWE-200"
    label: false_positive
    description: "ENV APPMETADATABUILDNUMBER=$APPMETADATABUILDNUMBER — build number is not a secret"

  - file: "Dockerfile"
    line: 17
    cwe_id: "CWE-200"
    label: false_positive
    description: "ENV APPMETADATABRANCHNAME=$APPMETADATABRANCHNAME — branch name is not a secret"
```

The source Dockerfile for this entry uses ARG→ENV exclusively for non-secret build metadata (build numbers, branch names, commit hashes). The scanner must NOT flag these as secret exposure. The distinction is the ARG name — `BUILDNUMBER`, `BRANCHNAME`, `COMMITHASH` are not secret-like, while `TOKEN`, `PASSWORD`, `SECRET`, `KEY`, `CREDENTIAL` are.

### IDOR false positive corpus

```yaml
# corpus/csharp/cwe-863-idor-false-positive/ground_truth.yaml
cwe: "863"
language: csharp
description: "Admin controller with intentionally unscoped access"

findings:
  - file: "AdminController.cs"
    line: 15
    cwe_id: "CWE-863"
    label: false_positive
    description: "Admin endpoint with [Authorize(Roles='Admin')] — unscoped access is intentional for admin users"
```

---

## 9. Implementation Steps

### Phase 1: Corpus tests (regression baseline)

1. Create `corpus/docker/cwe-200-secret-exposure/` — source Dockerfile, patched, ground truth
2. Create `corpus/docker/best-practices/` — root user, :latest, curl pipe
3. Create `corpus/docker/false-positives/` — non-secret ARG→ENV build metadata (must NOT flag)
4. Create `corpus/csharp/cwe-863-idor/` — vulnerable controller + service, ground truth with severity
5. Create `corpus/csharp/cwe-863-idor-false-positive/` — admin controller (intentional unscoped)
6. Run current pipeline against corpus entries, record baseline detection rates

### Phase 2: Prompt improvements (no code changes)

7. Expand `config/prompts/config_review.md` with per-file-type checklists
8. Expand `config/prompts/holistic/csharp.md` IDOR section with severity guidance
9. Expand `config/prompts/holistic/python.md` with equivalent IDOR severity guidance (Django/Flask `Model.objects.get(pk=id)` without ownership)
10. Re-run pipeline against corpus entries, verify improvement
11. Verify no regression on existing corpus entries (python/cwe-078, csharp/cwe-089, etc.)

### Phase 3: Hadolint integration

12. Install hadolint: `brew install hadolint`
13. Create `config/tools/hadolint.yaml` tool spec (sarif_native — no custom parser)
14. Add hadolint to tool registry
15. Add Dockerfile to SAST pass file type routing
16. Map hadolint rules to CWEs
17. Test against corpus Dockerfiles
18. Mark as optional in health-check

### Phase 4: Coverage model

19. Create `src/security_review/models/coverage.py` — FileCoverage, CoverageReport
20. Build coverage map in `passes/inventory.py` from tool registry + hardcoded semantic pass mapping
21. Store coverage on PipelineState, flow to ReportData
22. Add coverage section to terminal output
23. Add coverage section to markdown summary
24. Add `.bicep`, `.tf`, `.bicepparam` to config file detection in `passes/config_review.py`
25. Write unit tests for coverage model

### Phase 5: Validation

26. Full review on `example-target` — verify Docker secret is now caught
27. Full review on `example-target` — verify IDOR severity is consistent (Critical for write, Medium for read)
28. Full review on this repo — verify no regressions, coverage report shows strong coverage
29. Run all corpus entries — compare against ground truths (manual comparison for now)
30. Run `pytest tests/unit/ -v` — all unit tests pass

---

## 10. What NOT to Build

- No code_analysis IDOR heuristic — deferred to a future plan (requires cross-file semantic analysis)
- No Terraform/Bicep deterministic scanner — rely on LLM config review for now (coverage report makes this visible)
- No automated corpus benchmark scorer — corpus validation is manual for now (run pipeline, compare output to ground_truth.yaml). Automate when we have 20+ corpus entries
- No changes to scoring/priority formula — coverage is informational, not a score modifier

---

## 11. Success Criteria

1. `python security-review.py review --target ../example-target/` catches the Docker ARG→ENV secret
2. IDOR findings have consistent severity: Critical for write ops, Medium for read ops
3. Review output includes coverage section showing per-file-type coverage
4. Coverage section flags Bicep as "LLM Config Review only" (weak coverage)
5. All existing corpus ground truths still pass (no regressions)
6. New corpus entries (Docker, IDOR, IDOR false positive) have ground truths
7. `pytest tests/unit/ -v` — all tests pass
8. hadolint shown as optional in `python security-review.py health-check`

---

## 12. Rollback

- Prompt changes are the highest-risk item (could introduce false positives). Revert config_review.md and csharp.md to previous versions.
- Hadolint integration is additive and optional — remove tool spec, no impact.
- Coverage model is display-only — removing it doesn't affect findings.
- Corpus tests are read-only fixtures — no impact on pipeline behaviour.
