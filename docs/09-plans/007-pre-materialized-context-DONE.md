# Plan 007: Pre-materialized Context for Holistic Pass

**Date:** 4 May 2026
**Status:** [x] Implemented
**Branch:** feat/pre-materialized-context (create from feat/coverage-and-detection-improvements)
**Scope:** Replace tool-call-based file reading in the holistic pass (Pass 4) with pre-materialized context. Read all files locally and inline them in the prompt. Eliminates tool timeouts, the root cause of unreliable IDOR detection.
**Disposition (2026-07-06):** Extended to all LLM passes; dual-mode fallback deliberately dropped (ADR-003, AGENTS.md rule 10).

---

## 1. Problem Statement

The holistic pass dispatches CWE checks to an LLM agent that reads files via tool calls (`read_file`, `get_sast_findings`). Under concurrent load, the Copilot SDK's tool bridge times out — silently returning "Tool execution timed out" instead of file content. The LLM then has no code to analyze and returns empty findings.

**Evidence across 18 runs on example-target:**
- IDOR detected: 3/18 runs (17% reliability)
- Docker secret detected: 6/6 runs after OpenGrep rule added (100% — deterministic)
- Tool timeout warnings: present in every holistic pass under concurrent load

**Root cause:** The Copilot SDK's rate limits surface as silent `asyncio.TimeoutError` (not as rate-limit errors). Each CWE check requires 17+ tool calls (read_file × N files + get_sast_findings × N). With concurrent checks, this produces 50-100+ concurrent tool calls through a bridge that can't handle the throughput.

**Industry consensus (validated by research):** No production security tool (Semgrep, Snyk, GitHub Copilot Autofix) uses LLM tool calls for file reading during security analysis. They all run deterministic analysis first, then inline narrowed context into a single LLM call.

---

## 2. Target Architecture

### Before (tool-call based)

```
Prompt ("check CWE-863 in these 17 files")
  → LLM decides to call read_file("ContactsController.cs")
    → Copilot SDK tool bridge → async future → 120s timeout risk
  → LLM decides to call read_file("ContactsService.cs")
    → Copilot SDK tool bridge → async future → 120s timeout risk
  → ... (17 more tool calls)
  → LLM decides to call get_sast_findings("ContactsController.cs")
    → ... (17 more tool calls)
  → LLM finally produces findings
```

**34+ round trips, each subject to timeout. ~50% failure rate under load.**

### After (pre-materialized context)

```
Read all 17 files locally (microseconds)
  → Look up SAST findings from in-memory SARIF (microseconds)
  → Build single prompt with all content inlined
  → ONE LLM call → structured response
```

**1 round trip. 0% timeout risk on file reads. Deterministic input.**

---

## 3. Design

### 3.1 New agent: `holistic_inline_agent`

Create a new PydanticAI agent with **no tools**. The agent receives all context in the prompt — no need to call `read_file` or `get_sast_findings`.

```python
# src/security_review/agents/holistic/inline_agent.py

holistic_inline_agent = Agent(
    output_type=HolisticReviewResult,
    system_prompt=SYSTEM_PROMPT,  # same security reviewer role
    retries=3,
    deps_type=SecurityReviewDeps,
    # NO tools registered — all context is in the prompt
)
```

The existing `holistic_agent` (with tools) is kept but not used by default. It becomes a fallback for future use cases where tool calls are needed (e.g., very large repos where inlining exceeds context).

### 3.2 Prompt structure

The `_build_check_prompt` function in `holistic.py` changes from:

```
## Security Check: CWE-863 Incorrect Authorization
{check_prompt}

**Files to review:**
- src/Controllers/ContactsController.cs
- src/Services/AzureSqlContactsService.cs
- ...

**Instructions:**
1. Use read_file to examine each file listed above.
2. Use get_sast_findings_for_file to check what SAST already found.
3. Only report findings you have evidence for.
4. If no issues are found, return an empty findings list.
5. All findings must reference CWE-863.
```

To:

```
## Security Check: CWE-863 Incorrect Authorization
{check_prompt}

**Existing SAST findings (do not duplicate):**
- ContactsController.cs:47 — 'if' statement can be simplified (roslyn)
- ContactsController.cs:64 — 'if' statement can be simplified (roslyn)

**Source files:**

### src/Controllers/ContactsController.cs
```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
...
```

### src/Services/AzureSqlContactsService.cs
```csharp
using Microsoft.EntityFrameworkCore;
...
```

### src/Models/Database/Contact.cs
```csharp
public record Contact
{
    public string Id { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    ...
}
```

**Instructions:**
1. Review ALL source files above for CWE-863.
2. Do not duplicate the SAST findings listed above.
3. Only report findings with evidence — quote actual code from the files.
4. If no issues are found, return an empty findings list.
5. All findings must reference CWE-863.
```

### 3.3 Token budgeting

Before building the prompt, compute the token budget:

```python
def _build_inline_prompt(
    check: CWECheck,
    file_paths: list[str],
    target_path: Path,
    sast_sarif: dict,
    max_input_tokens: int = 100_000,  # from config: llm.max_tokens_per_batch
) -> str:
```

**Algorithm:**

1. **Reserve** — system prompt (~500 tokens) + response (~30k tokens) = ~30.5k reserved
2. **Available** — `max_input_tokens - 30_500`
3. **Read all files** — local I/O, compute token estimate per file (len / 4)
4. **Sort by priority** — files with higher security_weight first
5. **Inline until budget exhausted:**
   - Full content for files that fit
   - For the file that would exceed budget: truncate to first N lines + "... truncated (M lines omitted)"
   - Remaining files: skip with a note "File omitted (token budget exceeded)"
6. **Always include SAST findings section** — pre-computed from in-memory SARIF, negligible tokens

### 3.4 Modified `_run_single_check`

```python
async def _run_single_check(
    *, check, file_paths, state, model, model_string,
) -> tuple[list[HolisticFinding], list[str]] | None:
    # 1. Build prompt with inlined file contents + SAST findings
    prompt = _build_inline_prompt(
        check=check,
        file_paths=file_paths,
        target_path=state.target_path,
        sast_sarif=state.sast_sarif,
        max_input_tokens=state.config.llm.max_tokens_per_batch,
    )

    # 2. Run the inline agent (no tools, single call)
    result = await holistic_inline_agent.run(
        prompt,
        deps=deps,
        model=model,
        usage_limits=UsageLimits(
            request_limit=5,  # prompt + response + retries (no tool calls)
            total_tokens_limit=500_000,
        ),
    )
    ...
```

**Key change:** `request_limit` drops from `len(files) * 2 + 5` (~39) to **5** (prompt + response + up to 3 validation retries). No tool calls means no multi-turn conversation.

---

## 4. Files to Change

### New files

| File | Purpose |
|---|---|
| `src/security_review/agents/holistic/inline_agent.py` | New PydanticAI agent with no tools |

### Modified files

| File | Change |
|---|---|
| `src/security_review/passes/holistic.py` | Replace `_build_check_prompt` with `_build_inline_prompt`. Use `holistic_inline_agent` instead of `holistic_agent`. Remove tool-call request limit calculation. |
| `src/security_review/agents/holistic/__init__.py` | Export both agents (inline as default, tool-based as fallback) |
| `security-review.py` | Update `test-cwe` command to use inline agent |
| `config/settings/security_review.yaml` | Add `holistic_mode: inline` setting (values: `inline`, `tools`) |
| `src/security_review/config_schema.py` | Add `holistic_mode` field to LLMConfig |

### Files NOT changed

| File | Reason |
|---|---|
| `src/security_review/agents/holistic/agent.py` | Kept as-is for fallback/future use |
| `src/security_review/agents/tools.py` | Kept — still used by triage and config_review agents |
| `src/security_review/copilot_model.py` | Retry/semaphore stays as safety net for triage pass tool calls |
| `src/security_review/agents/deps.py` | No changes needed — deps still provides manifest + SARIF |
| `src/security_review/models/findings.py` | Output model unchanged — same `HolisticReviewResult` |

---

## 5. Prompt Construction Details

### `_build_inline_prompt(check, file_paths, target_path, sast_sarif, max_input_tokens)`

```python
def _build_inline_prompt(
    check: CWECheck,
    file_paths: list[str],
    target_path: Path,
    sast_sarif: dict,
    max_input_tokens: int = 100_000,
) -> str:
    """Build a self-contained prompt with all file contents and SAST findings inlined.

    Token budgeting: files are included in security_weight order (highest first).
    Files exceeding the budget are truncated or omitted with a note.
    """
    target_root = str(target_path.resolve())

    # 1. Read all files (local I/O)
    file_contents: dict[str, str] = {}
    for fp in file_paths:
        full_path = target_path / fp
        try:
            file_contents[fp] = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            file_contents[fp] = f"# Error: could not read {fp}"

    # 2. Get SAST findings for all files
    sast_section_lines = []
    for fp in file_paths:
        findings = get_findings_for_file(sast_sarif, fp, target_root=target_root)
        for f in findings:
            sast_section_lines.append(
                f"- {fp}:{f['line_number']} — {f['message'][:100]} ({f['tool_name']})"
            )

    # 3. Build prompt sections
    header = f"## Security Check: {check.display_name}\n\n{check.check_prompt}\n"

    if sast_section_lines:
        sast_section = (
            "\n**Existing SAST findings (do not duplicate):**\n"
            + "\n".join(sast_section_lines) + "\n"
        )
    else:
        sast_section = "\n**No existing SAST findings for these files.**\n"

    instructions = (
        "\n**Instructions:**\n"
        "1. Review ALL source files above for " + check.display_name + ".\n"
        "2. Do not duplicate the SAST findings listed above.\n"
        "3. Only report findings with evidence — quote actual code from the files.\n"
        "4. If no issues are found for this CWE, return an empty findings list.\n"
        f"5. All findings must reference CWE-{check.cwe_id}.\n"
    )

    # 4. Token budget for file contents
    overhead_estimate = len(header + sast_section + instructions) // 4 + 500  # system prompt
    available_tokens = max_input_tokens - overhead_estimate - 30_000  # reserve for response

    # 5. Inline files in priority order (caller sorts by security_weight)
    files_section_lines = ["\n**Source files:**\n"]
    tokens_used = 0
    files_included = []
    files_omitted = []

    for fp in file_paths:
        content = file_contents[fp]
        file_tokens = len(content) // 4  # rough estimate

        if tokens_used + file_tokens <= available_tokens:
            # Full content
            ext = fp.rsplit(".", 1)[-1] if "." in fp else ""
            files_section_lines.append(f"### {fp}")
            files_section_lines.append(f"```{ext}")
            files_section_lines.append(content)
            files_section_lines.append("```\n")
            tokens_used += file_tokens
            files_included.append(fp)
        elif tokens_used < available_tokens:
            # Partial content — truncate to fit remaining budget
            remaining_chars = (available_tokens - tokens_used) * 4
            truncated = content[:remaining_chars]
            total_lines = content.count("\n")
            included_lines = truncated.count("\n")
            ext = fp.rsplit(".", 1)[-1] if "." in fp else ""
            files_section_lines.append(f"### {fp}")
            files_section_lines.append(f"```{ext}")
            files_section_lines.append(truncated)
            files_section_lines.append(f"\n... TRUNCATED ({total_lines - included_lines} lines omitted)")
            files_section_lines.append("```\n")
            tokens_used = available_tokens
            files_included.append(fp)
        else:
            files_omitted.append(fp)

    if files_omitted:
        files_section_lines.append(
            f"\n**Note:** {len(files_omitted)} file(s) omitted due to token budget: "
            + ", ".join(files_omitted)
        )

    return header + sast_section + "\n".join(files_section_lines) + instructions
```

---

## 6. Config Changes

### `config/settings/security_review.yaml`

```yaml
llm:
  holistic_mode: inline    # "inline" (pre-materialized) or "tools" (tool-call based)
```

### `src/security_review/config_schema.py`

```python
class LLMConfig(BaseModel, extra="forbid"):
    ...
    holistic_mode: str = Field(
        default="inline",
        description="Holistic pass mode: 'inline' (pre-materialized context) or 'tools' (tool-call based)"
    )
```

### Holistic pass dispatch

```python
# In passes/holistic.py
if state.config.llm.holistic_mode == "tools":
    from security_review.agents.holistic.agent import holistic_agent as agent
else:
    from security_review.agents.holistic.inline_agent import holistic_inline_agent as agent
```

---

## 7. System Prompt for Inline Agent

```python
SYSTEM_PROMPT = (
    "You are a security code reviewer performing a focused check for a specific "
    "vulnerability class (CWE). You receive:\n"
    "1. A specific CWE to check for with detection guidance.\n"
    "2. Existing SAST findings to avoid duplicating.\n"
    "3. Full source file contents to review.\n\n"
    "Rules:\n"
    "1. Review ALL provided source files — the code is already in the prompt.\n"
    "2. Do not duplicate findings already listed in the SAST section.\n"
    "3. Only report findings with evidence — quote the actual vulnerable code.\n"
    "4. If no issues are found for this CWE, return an empty findings list.\n"
    "5. Severity must reflect actual exploitability in context, not theoretical risk.\n"
    "6. Use rule IDs in the format SR-{CATEGORY}-NNN (e.g. SR-AUTHZ-001, SR-IDOR-001).\n"
    "7. For cross-file vulnerabilities, cite code from BOTH the caller and the callee."
)
```

Key difference from current system prompt: rule 1 says "the code is already in the prompt" instead of "Use read_file to examine each file." Rule 7 is new — explicitly asks for cross-file evidence (important for IDOR).

---

## 8. `test-cwe` Command Update

Update the `test-cwe` command in `security-review.py` to use the inline agent by default:

```python
# Instead of calling _run_single_check (which uses the tool-based agent),
# build the inline prompt and call the inline agent directly.
prompt = _build_inline_prompt(check, file_paths, target_path, state.sast_sarif, cfg.llm.max_tokens_per_batch)
result = await holistic_inline_agent.run(prompt, deps=deps, model=model, ...)
```

---

## 9. What Stays Unchanged

- **Retry/semaphore in copilot_model.py** — stays as safety net for triage pass (which still uses tool calls for individual finding validation)
- **Config review pass (Pass 5)** — still uses tool calls (small file set, low concurrency)
- **Triage pass (Pass 3)** — still uses tool calls (one finding at a time, lower throughput)
- **`_run_batch` + dead letter retry** — stays for the tool-based fallback mode
- **`select_files_for_check`** — still selects which files are relevant per CWE
- **All output models** — `HolisticReviewResult`, `HolisticFinding` unchanged
- **All prompt files** — `config/prompts/holistic/csharp.md`, `python.md` unchanged (they're still used as the holistic system prompt loaded by the agent)

---

## 10. Implementation Steps

1. Create `src/security_review/agents/holistic/inline_agent.py` — new agent, no tools
2. Create `src/security_review/agents/holistic/__init__.py` — export both agents
3. Write `_build_inline_prompt()` in `passes/holistic.py` — file reading, SAST lookup, token budgeting
4. Modify `_run_single_check()` to use inline agent when `holistic_mode == "inline"`
5. Add `holistic_mode` to `config_schema.py` and `security_review.yaml`
6. Update `test-cwe` in `security-review.py` to use inline prompt
7. Run `test-cwe 863 ../example-target/` — verify 4/4 IDOR findings
8. Run full review on `example-target/` — verify IDOR + Docker + CVEs
9. Run `pytest tests/unit/ -v` — no regressions
10. Compare report against d2120108 (best previous run: 28 findings, 4 IDOR, 1 Docker, 11 CVEs)

---

## 11. Success Criteria

1. `test-cwe 863 ../example-target/` finds 4 IDOR findings — **every time** (not 50%)
2. Full review finds IDOR + Docker secret + CVEs — **consistently**
3. Zero `copilot.tool_timeout` warnings during the holistic pass
4. Total holistic pass time reduced (one call per CWE vs 30+ tool calls per CWE)
5. `holistic_mode: tools` still works as fallback
6. All existing unit tests pass (128)

---

## 12. Rollback

- Set `holistic_mode: tools` in YAML to revert to tool-call architecture
- Delete `inline_agent.py` and revert `holistic.py` changes
- No impact on other passes, output models, or SARIF format
