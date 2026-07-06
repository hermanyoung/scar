# Plan 011 — Entry-Point-to-Sink Data Flow Tracing

**Date:** 2026-05-17
**Status:** Draft
**Depends on:** Plan 010 (call graph infrastructure)
**Research:** [008-Pentest Toolchain Research](../98-research/008-The%202025–2026%20Command-Line%20Web%20Application%20Penetration%20Testing%20Toolchain%2C%20with%20LLM-Assisted%20Verification.md)

---

## Problem

SCAR's holistic pass (Pass 4) runs one CWE check per file batch. File selection is keyword-based (`_FILE_TYPE_MATCHERS` in `checks.py`): CWE-89 SQL Injection reads files with "repository" or "dal" in the path, CWE-862 Missing Authorization reads files with "controller" in the path. Each CWE check sees files independently.

This misses **multi-step injection chains**. If `UserController.CreateUser(name)` calls `UserService.Save(name)` which calls `UserStore.Insert(name)` which builds raw SQL, the holistic pass may see the controller and the store separately but never traces the data flow between them. The LLM cannot reason about a chain it cannot see.

The pentest toolchain research identifies Vulnhuntr's approach as the state-of-the-art for SAST: "automatically creates and analyzes entire code call chains starting from remote user input and ending at server output." This is the single highest-value detection gap in SCAR.

### What this plan does NOT do

- Does not build the call graph itself — that is Plan 010's scope
- Does not replace the existing CWE-per-check architecture — it adds a new check type alongside it
- Does not require a running application — this is static analysis of source code

---

## Solution

Add a new check type `detection: flow` to the CWE taxonomy. Flow checks define `source_patterns` (entry points — controller actions, route handlers, API endpoints) and `sink_patterns` (dangerous calls — SQL execution, subprocess, deserialization, file I/O). The pass uses Plan 010's call graph to find paths from sources to sinks, then inlines the entire chain into a single LLM prompt asking: "Does untrusted input from this entry point reach this sink without sanitization?"

---

## Architecture

```
BEFORE (current Pass 4):
  checks.py:select_files_for_check(keywords) → context_builder.inline_files() → LLM

AFTER (new flow checks in Pass 4):
  call_graph → walk.py:find_source_to_sink_paths() → returns [chain of (file, method, line)]
  → context_builder.inline_chain() → formats chain as ordered code blocks → LLM
```

### Key design decisions

1. **Flow checks run inside Pass 4** — they are holistic checks, just with a different file-selection strategy. No new pass needed.
2. **One LLM call per chain** — not per source, not per sink. Each source→sink path is one prompt.
3. **Chain context is ordered** — the prompt presents files in call-chain order (controller → service → repository), not alphabetical. This gives the LLM the data flow direction.
4. **Existing CWE checks remain** — flow checks are additive. CWE-89 still has its existing keyword-based check for finding SQL injection in isolated files. The flow check finds injection chains that cross file boundaries.
5. **Requires Plan 010 call graph** — if the call graph is unavailable (plan not implemented), flow checks are skipped with a warning.

---

## Codemap Reference

Read `.codemap/map.md` for the full type/method inventory. Key modules:

| Module | Role in this plan |
|---|---|
| `src/security_review/checks.py` (153 lines) | Add `detection: flow` support, new `FlowCheck` dataclass, `select_chain_for_check()` |
| `src/security_review/passes/holistic.py` (471 lines) | Dispatch flow checks alongside existing CWE checks |
| `src/security_review/context_builder.py` (116 lines) | Add `inline_chain()` for ordered chain formatting |
| `src/security_review/output_parser.py` (330 lines) | Unchanged — flow check output uses the same SR-XXX-NNN format |
| `src/security_review/agents/holistic/agent.py` (36 lines) | System prompt already handles cross-file findings (rule 8) |
| `config/taxonomy/cwe.yaml` (44 CWEs) | Add `source_patterns`, `sink_patterns`, `max_hops` to flow CWEs |
| `src/code_analysis/walk.py` (Plan 010) | Graph walk: BFS from sources to sinks with hop limit |

---

## Phase 1 — Taxonomy and Data Model

### Task 1.1 — Add flow check fields to taxonomy

**File:** `config/taxonomy/cwe.yaml`

Add `source_patterns`, `sink_patterns`, and `max_hops` as optional fields to CWEs that benefit from data flow tracing. **Do NOT change the existing `detection:` field** — the existing `sast+llm` check must remain. `load_flow_checks()` selects entries that have `source_patterns` + `sink_patterns` fields, regardless of the `detection` value. This makes flow checks additive, not replacements.

```yaml
"89":
  name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
  detection: sast+llm  # UNCHANGED — existing check stays
  source_patterns:  # NEW — enables flow check alongside existing check
    - "controller.*action"
    - "route.*handler"
    - "@app.route"
    - "[HttpPost]"
    - "[HttpPut]"
  sink_patterns:
    - "ExecuteSql"
    - "FromSqlRaw"
    - "cursor.execute"
    - "db.execute"
    - "RawSqlString"
  max_hops: 5
  file_types: [controller, service, repository]
  check: |
    Trace the data flow from the entry point to the SQL execution sink.
    Check whether user-supplied parameters are passed through any
    sanitization, parameterization, or ORM method before reaching the
    SQL execution call. Flag chains where raw string concatenation or
    interpolation carries user input into SQL.
```

Initial flow CWEs (highest value):
- CWE-89 (SQL Injection) — controller → service → raw SQL
- CWE-78 (OS Command Injection) — controller → service → subprocess
- CWE-22 (Path Traversal) — controller → file handler → file I/O
- CWE-502 (Deserialization) — controller → deserializer with untrusted input
- CWE-918 (SSRF) — controller → HTTP client with user-controlled URL

### Task 1.2 — Add FlowCheck dataclass

**File:** `src/security_review/checks.py`

Add alongside existing `CWECheck`:

```python
@dataclass(frozen=True)
class FlowCheck:
    """A data-flow-tracing CWE check."""
    cwe_id: str
    name: str
    source_patterns: list[str]
    sink_patterns: list[str]
    max_hops: int
    check_prompt: str

def load_flow_checks() -> list[FlowCheck]:
    """Load CWE checks that have source_patterns + sink_patterns defined.

    Reuses _load_taxonomy() (shared with load_cwe_checks()) to avoid
    re-reading cwe.yaml. Selects entries by presence of flow fields,
    NOT by detection value — flow checks are additive alongside
    existing llm/sast+llm checks.
    """
```

### Task 1.3 — Add `inline_chain()` to context_builder

**File:** `src/security_review/context_builder.py`

```python
def inline_chain(
    target_path: Path,
    chain: list[tuple[str, str, int]],  # [(file_path, method_name, line)]
    *,
    max_tokens: int = 100_000,
    reserve_tokens: int = 30_000,
) -> tuple[str, list[str]]:
    """Inline files in call-chain order with chain annotation.

    Reuses read_file_content() and format_full_file() from this module.
    Does NOT duplicate the token-budget loop from inline_files() — shares
    the same budget logic, just adds step-number annotations and
    call-chain ordering.

    Each file is preceded by its position in the chain:
    '## Step 1: UserController.CreateUser (Controllers/UserController.cs:45)'
    """
```

**Important:** Extract the token-budget loop from `inline_files()` into a shared helper (e.g. `_budget_loop()`) and reuse it in both `inline_files()` and `inline_chain()`. Do not duplicate the budget logic.

The chain is presented in order so the LLM sees the data flow direction:
```
## Step 1: UserController.CreateUser (Controllers/UserController.cs:45)
```csharp
[HttpPost]
public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
{
    await _userService.Save(request.Name);
    ...
}
```

## Step 2: UserService.Save (Services/UserService.cs:23)
```csharp
public async Task Save(string name)
{
    await _userStore.Insert(name);
}
```

## Step 3: UserStore.Insert (Data/UserStore.cs:67)
```csharp
public async Task Insert(string name)
{
    await _db.ExecuteSqlRaw($"INSERT INTO Users (Name) VALUES ('{name}')");
}
```
```

---

## Phase 2 — Graph Walk Integration

### Task 2.1 — Wire flow checks into holistic pass

**File:** `src/security_review/passes/holistic.py`

In `run_holistic()`, after loading CWE checks, also load flow checks:

```python
flow_checks = load_flow_checks()
if not flow_checks:
    logger.info("holistic.no_flow_checks")
elif not _has_call_graph():
    logger.warning("holistic.flow_checks_skipped", reason="No call graph available (Plan 010 not implemented)")
else:
    # Run flow checks
    for check in flow_checks:
        chains = find_source_to_sink_paths(
            graph=call_graph,
            source_patterns=check.source_patterns,
            sink_patterns=check.sink_patterns,
            max_hops=check.max_hops,
        )
        for chain in chains:
            # One LLM call per chain
            prompt = _build_flow_prompt(check, chain, state.target_path, sast_context)
            # ... dispatch like existing CWE checks
```

### Task 2.2 — Build flow-specific prompt

**File:** `src/security_review/passes/holistic.py`

```python
def _build_flow_prompt(
    check: FlowCheck,
    chain: list[tuple[str, str, int]],
    target_path: Path,
    sast_context: str,
) -> str:
    """Build a prompt for a data flow chain."""
    chain_context, files_included = inline_chain(target_path, chain)
    return (
        f"# CWE-{check.cwe_id}: {check.name}\n\n"
        f"## Detection Task\n{check.check_prompt}\n\n"
        f"## Data Flow Chain ({len(chain)} steps)\n\n"
        f"The following code shows a call chain from an entry point to a potentially "
        f"dangerous sink. Review whether untrusted input flows through this chain "
        f"without proper sanitization.\n\n"
        f"{chain_context}\n\n"
        f"## Existing SAST Findings (do not duplicate)\n{sast_context}\n\n"
        f"## Response Format\n"
        f"If the chain is vulnerable, report a finding with:\n"
        f"- Rule ID: SR-FLOW-NNN\n"
        f"- File path: the sink file (last step)\n"
        f"- Evidence: quote code from BOTH the source and sink\n"
        f"If the chain has proper sanitization, say 'No findings'."
    )
```

---

## Phase 3 — Testing

### Task 3.1 — Unit tests

**File:** `tests/unit/test_checks.py` (new or extend existing)

- Test `load_flow_checks()` returns flow checks from taxonomy
- Test `inline_chain()` formats chain in order with step numbers
- Test that flow checks are skipped when no call graph is available

### Task 3.2 — Eval corpus entries

**Directory:** `eval/`

Add flow-specific test cases:
- `eval/csharp/cwe-089-sql-injection-chain/` — controller → service → raw SQL (should find)
- `eval/python/cwe-078-command-injection-chain/` — route handler → helper → subprocess (should find)
- `eval/csharp/cwe-089-sql-parameterized-chain/` — controller → service → parameterized SQL (should NOT find)

### Task 3.3 — Benchmark

Run `python scripts/benchmark_cwes.py` with flow checks enabled against the reference target. Flow checks should find chains that the existing per-file CWE-89 check misses.

---

## Goal

```
/goal Implement Plan 011 (entry-point-to-sink data flow tracing). Goal is reached when:
1. config/taxonomy/cwe.yaml contains at least 5 CWEs with detection: flow, each with source_patterns, sink_patterns, and max_hops
2. src/security_review/checks.py has a FlowCheck dataclass and load_flow_checks() that loads them
3. src/security_review/context_builder.py has inline_chain() that formats files in call-chain order with step annotations
4. src/security_review/passes/holistic.py dispatches flow checks when a call graph is available and skips with a warning when it is not
5. Flow findings use rule IDs SR-FLOW-NNN
6. eval/ contains at least one flow-specific corpus entry (e.g. eval/csharp/cwe-089-sql-injection-chain/)
7. pytest tests/unit/ -v passes with zero failures
8. All existing CWE checks still work — load_cwe_checks() returns the same checks as before
Stop after 30 turns or if blocked on Plan 010 call graph infrastructure.
```

---

## Acceptance Criteria

1. `load_flow_checks()` returns at least 5 flow checks from taxonomy
2. Flow checks are skipped with a warning when Plan 010 call graph is not available
3. `inline_chain()` formats files in call-chain order with step annotations
4. Each chain produces a single LLM call, not one per file
5. Flow findings use rule IDs `SR-FLOW-NNN` and include evidence from both source and sink
6. All existing CWE checks continue to work unchanged
7. `pytest tests/unit/ -v` passes
