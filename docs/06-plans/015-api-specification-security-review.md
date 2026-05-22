# Plan 015 — API Specification Security Review

**Date:** 2026-05-17
**Status:** Draft
**Depends on:** None (taxonomy + inventory + config review enhancement)
**Research:** [008-Pentest Toolchain Research](../98-research/008-The%202025–2026%20Command-Line%20Web%20Application%20Penetration%20Testing%20Toolchain%2C%20with%20LLM-Assisted%20Verification.md)

---

## Problem

The pentest toolchain research shows that API specifications (OpenAPI/Swagger, GraphQL schemas) are a primary attack surface for DAST scanners. RESTler statefully fuzzes OpenAPI-defined endpoints and finds resource leaks and hierarchy violations. Nuclei has templates for exposed Swagger endpoints. Arjun mines parameters from specs.

SCAR's Pass 5 (config review) reads `appsettings.json`, `Dockerfile`, CI YAML, and general config files. But it does **not** read or analyze API specification files. These specs are a direct declaration of the application's attack surface — they often reveal:

1. **State-changing operations without security declarations** — POST/PUT/DELETE endpoints missing `security:` in OpenAPI, or mutations without `@auth` directives in GraphQL
2. **Internal endpoints in public specs** — admin, debug, health-check, or internal-only endpoints included in client-facing specs
3. **Sensitive data in examples** — API keys, tokens, PII, or real data in `example:` values
4. **IDOR-prone parameters** — sequential integer IDs as path parameters (e.g. `/users/{id}`) without documented authorization
5. **Overly permissive scopes** — OAuth2 scopes that grant more access than endpoints need
6. **Missing rate limiting** — no `x-rate-limit` or throttling metadata on high-risk endpoints

### Why spec-level review matters

The specification is the **contract**. If the spec declares an endpoint without auth, either the endpoint genuinely has no auth (vulnerability) or the spec is incomplete (documentation gap that leads to insecure client implementations). Either way, it's a finding worth flagging.

---

## Solution

Three additions:
1. **Detect API spec files** in the inventory pass — OpenAPI (`.json`/`.yaml` with `openapi:` key), Swagger (`.json`/`.yaml` with `swagger:` key), GraphQL schemas (`.graphql`, `.gql`)
2. **Add API spec CWE checks** to the taxonomy — focused LLM prompts for spec-level security analysis
3. **Enhance config review** to include API specs, or run spec checks as additional holistic checks

---

## Architecture

```
BEFORE:
  Pass 5 (config_review.py):
    _CONFIG_PATTERNS: appsettings, dockerfile, pyproject, .env, settings, config
    _CONFIG_EXTENSIONS: .json, .yaml, .yml, .toml, .xml, .props, ...

AFTER:
  Pass 1 (inventory.py):
    Detect openapi/swagger/graphql files → tag language="openapi" or "graphql"

  Pass 4 (holistic.py) — NEW CWE checks pick up spec files automatically:
    CWE-862: select_files_for_check(file_types=[controller, route, openapi])
    CWE-285: new check — "Improper Authorization" in API specs

  Pass 5 (config_review.py):
    _CONFIG_PATTERNS: add "openapi", "swagger", "graphql"
    Config review prompt enhanced for API specs
```

### Key design decisions

1. **Spec review runs in Pass 4 and Pass 5** — not a new pass. API specs are treated as config files (Pass 5) for general misconfiguration, and as file types for CWE-specific checks (Pass 4).
2. **Detection is content-based** — a `.json` file with `"openapi": "3.0"` at the top level is an OpenAPI spec. A `.yaml` file with `swagger: "2.0"` is a Swagger spec. A `.graphql` file is a GraphQL schema. Path-based detection (e.g. "swagger.json") is a fallback.
3. **No spec parsing library** — the LLM reads the spec as text. OpenAPI specs are YAML/JSON, which the LLM handles natively. This avoids adding a new dependency.
4. **Spec findings get their own rule IDs** — `SR-SPEC-NNN` to distinguish from code-level findings.

---

## Codemap Reference

Read `.codemap/map.md` for the full type/method inventory. Key modules:

| Module | Role in this plan |
|---|---|
| `config/taxonomy/cwe.yaml` (44 CWEs) | Add API-spec-specific CWE checks |
| `src/security_review/checks.py` (153 lines) | Add `openapi`, `graphql` to `_FILE_TYPE_MATCHERS` |
| `src/security_review/passes/inventory.py` (284 lines) | Detect API spec files by content |
| `src/security_review/passes/config_review.py` (207 lines) | Add spec patterns to `_CONFIG_PATTERNS` |
| `src/security_review/passes/holistic.py` (471 lines) | Unchanged — picks up new CWE checks automatically |
| `src/security_review/context_builder.py` (116 lines) | Unchanged — inlines spec files like any other |

---

## Phase 1 — API Spec Detection

### Task 1.1 — Detect OpenAPI/Swagger/GraphQL in inventory

**File:** `src/security_review/passes/inventory.py`

In the file discovery logic, add content-based detection for API specs. Currently, language detection is extension-based. Add a post-pass that reads the first few bytes of config-classified files to detect API specs.

**Performance guard:** Only apply content sniffing to files already classified as `language="config"` by extension AND with `.json`/`.yaml`/`.yml` extension. Do not sniff every file. For large repos with thousands of config files, add a filename pre-filter (must contain "openapi", "swagger", "api", "spec" in the name — or be under 1MB):

```python
_API_SPEC_INDICATORS = {
    "openapi": "openapi",      # OpenAPI 3.x
    "swagger": "swagger",      # Swagger 2.0
}

def _detect_api_spec(file_path: Path) -> str | None:
    """Check if a JSON/YAML file is an API specification.

    Returns 'openapi', 'swagger', or None.
    Reads only the first 500 bytes to avoid loading large files.
    """
    try:
        head = file_path.read_text(encoding="utf-8", errors="replace")[:500].lower()
        if '"openapi"' in head or 'openapi:' in head:
            return "openapi"
        if '"swagger"' in head or 'swagger:' in head:
            return "swagger"
    except OSError:
        pass
    return None
```

For `.graphql` and `.gql` files, detect by extension:
```python
_EXTENSION_LANGUAGE["graphql"] = "graphql"
_EXTENSION_LANGUAGE["gql"] = "graphql"
```

Set `security_weight` to at least 5 for API spec files — they define the public attack surface.

### Task 1.2 — Add file type matchers

**File:** `src/security_review/checks.py`

```python
_FILE_TYPE_MATCHERS: dict[str, list[str]] = {
    ...
    "openapi": ["openapi", "swagger", "api-spec", "api-definition"],
    "graphql": ["graphql", "schema", "typedefs"],
    ...
}
```

### Task 1.3 — Fix language filter in `select_files_for_check()`

**File:** `src/security_review/checks.py`

**CRITICAL:** The function `select_files_for_check()` hardcodes `f.language in ("python", "csharp")` at lines 121 and 129. This silently filters out files with `language="openapi"`, `language="graphql"`, or `language="config"`. Without this fix, API spec files will never be selected for any CWE check.

Fix: Make the language filter CWE-aware. If a check's `file_types` includes `openapi` or `graphql`, expand the allowed languages to include those types. The simplest approach:

```python
def select_files_for_check(check: CWECheck, files: list[FileEntry]) -> list[FileEntry]:
    # Determine which languages to include based on file_types
    allowed_languages = {"python", "csharp"}
    spec_types = {"openapi", "graphql", "swagger", "config", "dockerfile"}
    if any(ft in spec_types for ft in check.file_types):
        allowed_languages.update(spec_types)
    ...
    # Use allowed_languages instead of hardcoded ("python", "csharp")
```

This also benefits Plan 014 (JWT checks with `file_types: [config, startup]`) and any future checks targeting non-source-code files.

---

## Phase 2 — Taxonomy Updates

### Task 2.1 — Add API spec CWE checks

**File:** `config/taxonomy/cwe.yaml`

```yaml
"285":
  name: "Improper Authorization"
  detection: llm
  file_types: [openapi, graphql, swagger]
  check: |
    Review this API specification for authorization gaps.
    Check for:
    1. OpenAPI/Swagger:
       - Operations (POST, PUT, DELETE, PATCH) without a `security:` declaration
       - Operations with `security: []` (explicitly no auth)
       - Missing global `security:` default with no per-operation override
       - OAuth2 scopes that are overly broad (e.g. "admin" scope on read endpoints)
    2. GraphQL:
       - Mutations without @auth or @requireAuth directives
       - Queries that return sensitive types without auth constraints
       - Introspection enabled in the schema (security exposure)
    3. Both:
       - Endpoints that accept user IDs as path/query parameters without
         documented authorization (IDOR risk indicators)
       - Admin or internal endpoints exposed in client-facing specs

    For each issue found, include:
    - The specific operation/path/mutation
    - What security declaration is missing
    - Why it matters (what an unauthenticated/unauthorized user could do)

"1059":
  name: "Insufficient Technical Documentation"
  detection: llm
  file_types: [openapi, graphql, swagger]
  check: |
    Review this API specification for security-relevant documentation gaps.
    Check for:
    1. Endpoints with response schemas that expose internal fields
       (database IDs, internal status codes, stack traces in error examples)
    2. Example values containing sensitive data (API keys, tokens, PII,
       real email addresses, real phone numbers)
    3. Missing error response documentation (no 401/403 response defined
       suggests auth was not considered)
    4. Missing rate-limit headers in responses (x-rate-limit-*, Retry-After)
    5. Endpoints accepting file uploads without documented size limits
       or type restrictions

    Only flag issues with concrete security impact — not general documentation quality.
```

### Task 2.2 — Enhance existing CWE-862 to include spec files

**File:** `config/taxonomy/cwe.yaml`

Update CWE-862 file_types to include API specs:

```yaml
"862":
  name: "Missing Authorization"
  detection: llm
  file_types: [controller, route, middleware, openapi, graphql]
  check: |
    ... existing check prompt ...

    If reviewing an API specification (OpenAPI/Swagger/GraphQL):
    - Check that state-changing operations have security declarations
    - Check that sensitive data endpoints have auth requirements
    - Cross-reference with any security scheme definitions in the spec
```

---

## Phase 3 — Config Review Enhancement

### Task 3.1 — Add API spec patterns to config review

**File:** `src/security_review/passes/config_review.py`

```python
_CONFIG_PATTERNS = {
    "appsettings", "launchsettings", "dockerfile", "docker-compose",
    "pyproject", ".env", "settings", "config",
    "openapi", "swagger",  # NEW
}

_CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".xml", ".props",
    ".editorconfig", ".env", ".cfg", ".ini",
    ".bicep", ".bicepparam", ".tf", ".tfvars",
    ".graphql", ".gql",  # NEW
}
```

### Task 3.2 — Enhance config review prompt for API specs

**File:** `config/prompts/config_review.md`

Add a section to the config review system prompt:

```markdown
## API Specifications (OpenAPI, Swagger, GraphQL)

When reviewing API specification files, check for:
- Security scheme definitions present and applied globally
- State-changing operations (POST/PUT/DELETE/PATCH) with security declarations
- Sensitive data in example values
- Internal/admin endpoints exposed in public specs
- Missing error response definitions (401, 403, 429)
- CORS configuration in the spec (overly permissive origins)
```

---

## Phase 4 — Eval Corpus

### Task 4.1 — Add API spec eval entries

**Directory:** `eval/openapi/cwe-285-missing-auth/`

Create `source/openapi.yaml`:
```yaml
openapi: "3.0.3"
info:
  title: "Test API"
  version: "1.0.0"
paths:
  /users:
    get:
      summary: "List users"
      # No security declaration — should be flagged
      responses:
        "200":
          description: "OK"
  /users/{id}:
    delete:
      summary: "Delete user"
      # No security declaration on state-changing operation — should be flagged
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        "204":
          description: "Deleted"
  /health:
    get:
      summary: "Health check"
      # No security is fine here
      responses:
        "200":
          description: "OK"
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
# Note: no global security: declaration
```

Create `ground_truth.yaml`:
```yaml
cwe: "285"
findings:
  - path: "DELETE /users/{id}"
    description: "State-changing operation without security declaration"
  - path: "GET /users"
    description: "Data endpoint without security declaration"
```

**Directory:** `eval/openapi/cwe-285-correct/` (false positive test)

Create `source/openapi.yaml` with proper `security:` declarations on all sensitive endpoints.

**Directory:** `eval/graphql/cwe-285-missing-auth/`

Create `source/schema.graphql`:
```graphql
type Query {
  users: [User!]!
  user(id: ID!): User
}

type Mutation {
  deleteUser(id: ID!): Boolean!
  updateUser(id: ID!, input: UserInput!): User!
}

type User {
  id: ID!
  email: String!
  passwordHash: String!  # Should not be in schema
}
```

---

## Phase 5 — Testing

### Task 5.1 — Unit tests

**File:** `tests/unit/test_inventory.py` (extend)

- Test `_detect_api_spec()` returns `"openapi"` for OpenAPI 3.x JSON
- Test `_detect_api_spec()` returns `"swagger"` for Swagger 2.0 YAML
- Test `_detect_api_spec()` returns `None` for regular JSON/YAML
- Test `.graphql` files are detected as language `"graphql"`

**File:** `tests/unit/test_checks.py` (extend)

- Test `select_files_for_check()` with `file_types: [openapi]` matches OpenAPI files
- Test `load_cwe_checks()` returns CWE-285 and CWE-1059

### Task 5.2 — OpenGrep rule tests (if rules added)

No OpenGrep rules in this plan — API spec review is LLM-only because the patterns are structural (missing declarations) not textual.

### Task 5.3 — Benchmark

```bash
python scar.py test-cwe --cwe 285 --target eval/openapi/cwe-285-missing-auth --provider claude:claude-opus
```

---

## Goal

```
/goal Implement Plan 015 (API specification security review). Goal is reached when:
1. src/security_review/passes/inventory.py detects OpenAPI/Swagger files by content sniffing (reads first 500 bytes for "openapi" or "swagger" keys) and .graphql/.gql by extension
2. API spec files get security_weight >= 5 in the manifest
3. config/taxonomy/cwe.yaml contains CWE-285 and CWE-1059 with detection: llm and file_types including openapi/graphql
4. CWE-862 file_types updated to include openapi and graphql
5. src/security_review/checks.py _FILE_TYPE_MATCHERS has "openapi" and "graphql" entries AND select_files_for_check() language filter expanded to include non-source languages when file_types reference them
6. src/security_review/passes/config_review.py _CONFIG_PATTERNS includes "openapi" and "swagger", _CONFIG_EXTENSIONS includes ".graphql" and ".gql"
7. eval/ contains at least 2 API spec eval entries (eval/openapi/cwe-285-missing-auth/ and a false-positive entry)
8. load_cwe_checks() returns CWE-285 and CWE-1059 checks
9. pytest tests/unit/ -v passes with zero failures
10. All 11 existing baseline CWEs still detected (no regressions)
Stop after 20 turns.
```

---

## Acceptance Criteria

1. OpenAPI/Swagger files detected in inventory by content sniffing (not just extension)
2. GraphQL files detected by `.graphql`/`.gql` extension
3. API spec files get `security_weight >= 5`
4. CWE-285 and CWE-1059 added to taxonomy with focused spec-review prompts
5. CWE-862 file_types updated to include `openapi`, `graphql`
6. Config review picks up API spec files
7. Eval corpus entries for API spec flaws (positive + false positive)
8. Existing detection unchanged — all 11 baseline CWEs still pass
9. `pytest tests/unit/ -v` passes
