# Plan 014 — JWT/Auth Token Implementation Review

**Date:** 2026-05-17
**Status:** [x] Implemented (merged to main 2026-07-17)
**Depends on:** None (taxonomy + rule additions)
**Research:** [008-Pentest Toolchain Research](../98-research/008-The%202025–2026%20Command-Line%20Web%20Application%20Penetration%20Testing%20Toolchain%2C%20with%20LLM-Assisted%20Verification.md)

---

## Problem

The pentest toolchain research highlights jwt_tool as a key testing tool: alg=none bypass, key confusion (HS256/RS256), claim tampering, embedded-jwk, and kid injection. These are runtime tests against JWT endpoints. But the **root causes** are all in source code — and SCAR doesn't check for them.

SCAR's current taxonomy has:
- CWE-522 (Insufficiently Protected Credentials) — checks for plaintext credential storage
- CWE-346 (Origin Validation Error) — checks for CORS/origin issues
- CWE-798 (Use of Hard-coded Credentials) — SAST rule for hardcoded secrets

None of these target JWT implementation flaws specifically. JWT validation code is typically in auth middleware — SCAR reads middleware for CWE-862/693 but asks authorization-focused questions, not JWT-specific ones.

### Common JWT implementation flaws (code-level)

| Flaw | CWE | Severity | Detection |
|---|---|---|---|
| Hardcoded signing key | CWE-321 | CRITICAL | SAST (regex/AST) |
| Accepting `alg: none` | CWE-327 | CRITICAL | LLM (config review) |
| Missing algorithm restriction | CWE-757 | HIGH | LLM (config review) |
| Missing `aud`/`iss`/`exp` validation | CWE-345 | HIGH | LLM + SAST |
| Symmetric key for asymmetric algorithm | CWE-327 | HIGH | LLM |
| `kid` in SQL/file path without sanitization | CWE-89/22 | HIGH | LLM (data flow) |
| Token stored in localStorage | CWE-922 | MEDIUM | SAST (JS pattern) |
| Refresh token not rotated | CWE-384 | MEDIUM | LLM |

---

## Solution

Three additions:
1. **New CWE entries** in taxonomy for JWT-specific flaws with focused LLM check prompts
2. **New OpenGrep rules** for deterministic JWT patterns (hardcoded keys, missing validation parameters)
3. **Enhanced file type matching** so JWT-related files are selected for these checks

---

## Codemap Reference

Read `.codemap/map.md` for the full type/method inventory. Key modules:

| Module | Role in this plan |
|---|---|
| `config/taxonomy/cwe.yaml` (44 CWEs) | Add JWT-specific CWE entries |
| `src/security_review/checks.py` (153 lines) | Add `jwt` to `_FILE_TYPE_MATCHERS` |
| `config/rules/opengrep/` | Add JWT-specific OpenGrep rules + test files |
| `src/security_review/passes/holistic.py` (471 lines) | Unchanged — picks up new CWE checks automatically |
| `src/security_review/agents/holistic/agent.py` (36 lines) | Unchanged |

---

## Phase 1 — Taxonomy Updates

### Task 1.1 — Add JWT CWE entries

**File:** `config/taxonomy/cwe.yaml`

Add the following entries (or enhance existing entries):

```yaml
"321":
  name: "Use of Hard-coded Cryptographic Key"
  detection: sast+llm
  file_types: [auth, config, startup]
  check: |
    Check for hardcoded JWT signing keys in authentication code.
    Look for:
    1. String literals used as symmetric signing keys (HS256/HS384/HS512)
       - new SymmetricSecurityKey(Encoding.UTF8.GetBytes("hardcoded-string"))
       - jwt.encode(payload, "hardcoded-secret", algorithm="HS256")
       - SigningCredentials with inline byte arrays or string constants
    2. Private keys embedded in source code (PEM format, base64-encoded)
    3. Signing keys loaded from appsettings.json without environment variable override
    Flag any signing key that is not loaded from environment variables,
    key vault, or a certificate store at runtime.

"345":
  name: "Insufficient Verification of Data Authenticity"
  detection: llm
  file_types: [auth, middleware, startup]
  check: |
    Check JWT token validation configuration for missing claim validation.
    Look for:
    1. C# (.NET):
       - TokenValidationParameters with ValidateIssuer=false
       - TokenValidationParameters with ValidateAudience=false
       - TokenValidationParameters with ValidateLifetime=false
       - TokenValidationParameters with RequireExpirationTime=false
       - Missing ValidIssuer/ValidIssuers or ValidAudience/ValidAudiences
    2. Python:
       - jwt.decode() with options={"verify_exp": False}
       - jwt.decode() with options={"verify_aud": False}
       - jwt.decode() without audience= parameter
       - jwt.decode() without issuer= parameter
       - jwt.decode() with verify=False or algorithms not specified
    3. Both languages:
       - Token validation that only checks signature but not claims
       - Expiration check disabled or set to unreasonably long duration
    Flag any JWT validation that disables issuer, audience, or expiry checks.

"757":
  name: "Selection of Less-Secure Algorithm During Negotiation"
  detection: llm
  file_types: [auth, middleware, startup]
  check: |
    Check JWT validation code for missing algorithm restriction.
    Look for:
    1. C# (.NET):
       - TokenValidationParameters without ValidAlgorithms set
       - JwtSecurityTokenHandler without explicit algorithm validation
       - Accepting both HS256 and RS256 when only one is intended
    2. Python:
       - jwt.decode() without algorithms= parameter (allows alg:none)
       - jwt.decode(algorithms=["HS256","RS256"]) mixing symmetric/asymmetric
       - PyJWT < 2.0 which accepted alg:none by default
    3. Both languages:
       - No whitelist of accepted algorithms
       - Using symmetric key (HS256) when asymmetric (RS256/ES256) is intended
       - Accepting the algorithm from the token header without validation
    Flag any JWT validation that does not explicitly restrict the accepted
    signing algorithm to a single, intended algorithm.
```

### Task 1.2 — Update file type matchers

**File:** `src/security_review/checks.py`

**Do NOT create a new `jwt` file type.** The existing `"auth"` entry at line 99 already includes `["auth", "identity", "login", "oauth", "jwt", "token"]`, which covers JWT files. Creating a separate `jwt` entry would duplicate keyword coverage.

Instead, add the missing keywords `"bearer"` and `"claims"` to the existing `"auth"` entry:

```python
"auth": ["auth", "identity", "login", "oauth", "jwt", "token", "bearer", "claims"],
```

The new CWE entries (321, 345, 757) should use `file_types: [auth, config, startup]` — not a new `jwt` type.

---

## Phase 2 — OpenGrep Rules

### Task 2.1 — Hardcoded JWT signing key (C#)

**File:** `config/rules/opengrep/cwe-321-hardcoded-jwt-key.yaml`

```yaml
rules:
  - id: cwe-321-hardcoded-jwt-key-csharp
    patterns:
      - pattern: |
          new SymmetricSecurityKey(Encoding.$METHOD.GetBytes($KEY))
      - metavariable-regex:
          metavariable: $KEY
          regex: '"[^"]{8,}"'
    message: "Hardcoded JWT signing key. Store signing keys in environment variables or key vault."
    severity: ERROR
    languages: [csharp]
    metadata:
      cwe: CWE-321
      owasp: A02:2021
```

**Test file:** `config/rules/opengrep/cwe-321-hardcoded-jwt-key.cs`

```csharp
// ruleid: cwe-321-hardcoded-jwt-key-csharp
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my-super-secret-key-12345"));

// ok: cwe-321-hardcoded-jwt-key-csharp
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]));
```

### Task 2.2 — Hardcoded JWT signing key (Python)

**File:** `config/rules/opengrep/cwe-321-hardcoded-jwt-key-python.yaml`

```yaml
rules:
  - id: cwe-321-hardcoded-jwt-key-python
    patterns:
      - pattern: jwt.encode($PAYLOAD, $KEY, ...)
      - metavariable-regex:
          metavariable: $KEY
          regex: '"[^"]{8,}"'
    message: "Hardcoded JWT signing key. Load from environment variables."
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-321
      owasp: A02:2021
```

**Test file:** `config/rules/opengrep/cwe-321-hardcoded-jwt-key-python.py`

```python
import jwt

# ruleid: cwe-321-hardcoded-jwt-key-python
token = jwt.encode(payload, "my-hardcoded-secret-key", algorithm="HS256")

# ok: cwe-321-hardcoded-jwt-key-python
token = jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")
```

### Task 2.3 — Missing algorithm restriction (Python)

**File:** `config/rules/opengrep/cwe-757-jwt-no-algorithm.yaml`

```yaml
rules:
  - id: cwe-757-jwt-no-algorithm-python
    pattern: jwt.decode($TOKEN, $KEY)
    message: "jwt.decode() without algorithms= parameter accepts alg:none. Specify algorithms=['HS256'] explicitly."
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-757
      owasp: A02:2021
```

**Test file:** `config/rules/opengrep/cwe-757-jwt-no-algorithm.py`

```python
import jwt

# ruleid: cwe-757-jwt-no-algorithm-python
data = jwt.decode(token, secret)

# ok: cwe-757-jwt-no-algorithm-python
data = jwt.decode(token, secret, algorithms=["HS256"])
```

### Task 2.4 — Disabled validation (C#)

**File:** `config/rules/opengrep/cwe-345-jwt-disabled-validation.yaml`

```yaml
rules:
  - id: cwe-345-jwt-validate-issuer-false
    pattern: ValidateIssuer = false
    message: "JWT issuer validation disabled. Set ValidateIssuer=true and provide ValidIssuer."
    severity: WARNING
    languages: [csharp]
    metadata:
      cwe: CWE-345
      owasp: A07:2021

  - id: cwe-345-jwt-validate-audience-false
    pattern: ValidateAudience = false
    message: "JWT audience validation disabled. Set ValidateAudience=true and provide ValidAudience."
    severity: WARNING
    languages: [csharp]
    metadata:
      cwe: CWE-345
      owasp: A07:2021

  - id: cwe-345-jwt-validate-lifetime-false
    pattern: ValidateLifetime = false
    message: "JWT lifetime validation disabled. Tokens will not expire."
    severity: ERROR
    languages: [csharp]
    metadata:
      cwe: CWE-345
      owasp: A07:2021
```

**Test file:** `config/rules/opengrep/cwe-345-jwt-disabled-validation.cs`

```csharp
var parameters = new TokenValidationParameters
{
    // ruleid: cwe-345-jwt-validate-issuer-false
    ValidateIssuer = false,
    // ruleid: cwe-345-jwt-validate-audience-false
    ValidateAudience = false,
    // ruleid: cwe-345-jwt-validate-lifetime-false
    ValidateLifetime = false,
};

var goodParameters = new TokenValidationParameters
{
    // ok: cwe-345-jwt-validate-issuer-false
    ValidateIssuer = true,
    ValidIssuer = "https://issuer.example.com",
    // ok: cwe-345-jwt-validate-audience-false
    ValidateAudience = true,
    ValidAudience = "my-api",
    // ok: cwe-345-jwt-validate-lifetime-false
    ValidateLifetime = true,
};
```

---

## Phase 3 — Eval Corpus

### Task 3.1 — Add JWT eval entries

**Directory:** `eval/csharp/cwe-321-hardcoded-jwt-key/`

Create:
- `source/JwtService.cs` — hardcoded HS256 key in `SymmetricSecurityKey`
- `source/Startup.cs` — JWT middleware with `TokenValidationParameters`
- `expected.sarif` — expected SAST finding for hardcoded key
- `ground_truth.yaml` — CWE-321, line number, description

**Directory:** `eval/csharp/cwe-345-jwt-missing-validation/`

Create:
- `source/Startup.cs` — `TokenValidationParameters` with `ValidateIssuer=false`, `ValidateAudience=false`
- `expected.sarif` — expected SAST findings

**Directory:** `eval/python/cwe-757-jwt-no-algorithm/`

Create:
- `source/auth.py` — `jwt.decode(token, secret)` without `algorithms=`
- `expected.sarif` — expected SAST finding

**Directory:** `eval/csharp/cwe-345-jwt-correct/` (false positive test)

Create:
- `source/Startup.cs` — properly configured `TokenValidationParameters`
- `expected.sarif` — empty (no findings expected)

---

## Phase 4 — Testing

### Task 4.1 — OpenGrep rule tests

Run OpenGrep against each rule's test file:
```bash
python scar.py test-rule --cwe 321 --language csharp
python scar.py test-rule --cwe 321 --language python
python scar.py test-rule --cwe 757 --language python
python scar.py test-rule --cwe 345 --language csharp
```

### Task 4.2 — Benchmark new CWEs

If a reference target with JWT code is available:
```bash
python scar.py test-cwe --cwe 321 --target ../target --provider claude:claude-opus
python scar.py test-cwe --cwe 345 --target ../target --provider claude:claude-opus
python scar.py test-cwe --cwe 757 --target ../target --provider claude:claude-opus
```

### Task 4.3 — Unit tests

**File:** `tests/unit/test_checks.py` (extend)

- Test that `load_cwe_checks()` returns the new JWT CWE entries
- Test that `select_files_for_check()` with `file_types: [jwt]` matches files with "jwt", "token", "auth" in path

---

## Goal

```
/goal Implement Plan 014 (JWT/auth token review). Goal is reached when:
1. config/taxonomy/cwe.yaml contains CWE-321, CWE-345, and CWE-757 with detection llm or sast+llm and check prompts
2. src/security_review/checks.py _FILE_TYPE_MATCHERS "auth" entry includes "bearer" and "claims" keywords (extended, NOT a new "jwt" entry)
3. config/rules/opengrep/ has at least 4 new YAML rules for JWT flaws (cwe-321 csharp, cwe-321 python, cwe-757 python, cwe-345 csharp)
4. Each OpenGrep rule has a matching test file (.cs or .py) with ruleid: and ok: annotations
5. eval/ contains at least 3 JWT eval corpus entries (cwe-321, cwe-345, cwe-757) with source/ and ground_truth.yaml
6. load_cwe_checks() returns the 3 new JWT CWE checks
7. select_files_for_check() with file_types=[auth] matches files with "jwt", "token", "bearer", or "claims" in the path
8. python scar.py test-rule --cwe 321 --language csharp exits 0 (OpenGrep rule test passes)
9. pytest tests/unit/ -v passes with zero failures
10. All 11 existing baseline CWEs still detected (no regressions)
Stop after 20 turns.
```

---

## Acceptance Criteria

1. Three new CWE entries in taxonomy (321, 345, 757) with focused check prompts
2. Four new OpenGrep rules with matching test files
3. `"bearer"` and `"claims"` added to the existing `"auth"` entry in `_FILE_TYPE_MATCHERS` (no new `jwt` entry)
4. Eval corpus entries for JWT flaws (positive + false positive)
5. OpenGrep rule tests pass (`test-rule` command)
6. Existing CWE checks unchanged
7. `pytest tests/unit/ -v` passes
