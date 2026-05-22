# GitHub Copilot Python SDK Rate Limiting, Tool-Call Throughput, and Multi-File LLM Code Analysis Architecture

## TL;DR

- **The Python `github-copilot-sdk` is a JSON-RPC façade over the bundled Copilot CLI; it does not directly expose HTTP 429 headers.** Rate-limit responses from the upstream `/responses` endpoint surface as `session.error` events or, in pathological cases, as `asyncio.TimeoutError` from a default 30-second JSON-RPC timeout — meaning 429s can be silently consumed as timeouts unless you watch for `session.error` and lengthen `request` / `send_and_wait` timeouts. Throughput is bounded by per-user Copilot quotas (premium-request budget), not by an SDK-level concurrency knob; the SDK does support multiple concurrent sessions per CLI server and a documented "CLI pool / load-balancer / sticky session" pattern for higher concurrency.
- **For high-throughput, cross-file CWE checks the recommended architecture is map-reduce / hierarchical with an AST-driven repo map, not a single mega-prompt full of inlined files.** Aider, Cursor, Cline, Continue and Snyk DeepCode all converge on the same pattern: build a tree-sitter symbol graph, rank files by structural relevance (PageRank, embeddings + reranker, or call-graph reachability), inline only the top-N at full fidelity, and represent the rest as elided "repo map" skeletons within a fixed token budget. Commercial SAST + LLM products (Semgrep AI Workflows, Snyk DeepCode AI / CodeReduce, GitHub Copilot Autofix) all use deterministic program analysis to scope the LLM context rather than letting the LLM read files autonomously.
- **For 10–20 source files (100–3 000 lines each) practical token budgeting means: count with `tiktoken` (cl100k/o200k), reserve 25–35 % of the window for output, rank files by relevance to the specific CWE, inline top-priority files in full, demote others to AST skeletons or summaries, and keep a hard cap at ~70–80 % of the model's context window** (the same threshold Cline uses for its auto-compaction trigger). Tool-call-based file reading is preferable when relevance ranking is uncertain or when files are mutable mid-session; pre-inlining wins when the analysis target is well-bounded, latency-sensitive, or rate-limit constrained.

---

## Key Findings

### 1. GitHub Copilot Python SDK — rate limiting, error handling, async bridge

- The package on PyPI is `github-copilot-sdk` (importable as `from copilot import CopilotClient`). It is a Python wrapper around the bundled Copilot CLI binary, communicating via **JSON-RPC over a local subprocess** (`SubprocessConfig`) or an external server (`ExternalServerConfig`).
- The SDK is **async-first**: `CopilotClient`, `Session`, `session.send`, `session.send_and_wait`, and tool handlers are all coroutines. The async bridge uses an event-emitter pattern (`session.on(handler)` returning an unsubscribe closure), an internal **future + queue** in `copilot/jsonrpc.py` (`asyncio.wait_for(future, timeout=timeout)`), and idiomatic `asyncio.Event` / `asyncio.Queue` patterns for waiting on `session.idle`, `assistant.message`, and `assistant.message_delta` events.
- **HTTP 429 / rate-limit handling.** The SDK does not surface raw HTTP headers (Retry-After, X-RateLimit-Remaining) — those live inside the CLI's internal OpenAI-compatible client. From the user's perspective, rate limits appear as:
  - A `session.error` event whose payload contains `code: 'rate_limited'` and a message such as "Sorry, you have exceeded your Copilot token usage."
  - The CLI's own response text "Sorry, you've hit a rate limit … Please try again in N minutes." surfaced through `assistant.message`.
  - In the worst case, no event at all — issue **openclaw/openclaw#71120** documents that a Copilot `/responses` 429 with a `text/plain` body and no `Retry-After` header was *silently consumed* by the SDK retry layer, only producing a `surface_error` after the run timeout (default 600 s) elapsed. The SDK's `shouldBypassLongSdkRetry` path only marks 429s non-retryable when `Retry-After > 60 s` is present, which Copilot's weekly-quota 429 omits.
- **Default timeouts are aggressive.** Issue **github/copilot-sdk#389** ("Python: send_and_wait() always runs into timeout") and **#558** (`TimeoutError: Timeout after XXXs waiting for session.idle`) show the default `send_and_wait` timeout is **60 s**. Issue **#539** documents that `JsonRpcClient.request()` defaults to a **30-second** timeout and that long-running RPCs (`fleet.start`) will inherit it — meaning a slow tool call or a queued rate-limited request can raise `asyncio.TimeoutError` rather than a meaningful rate-limit error. Issue **#17** asks for the timeout to be configurable when MCP tools (Playwright) take longer than 30 s. **Net effect:** in the Python SDK, "timeout" and "rate-limited" can be indistinguishable to a naïve caller; you have to attach a handler for `SessionEventType.SESSION_ERROR` and filter by `code == 'rate_limited'` to disambiguate.
- **`create_session` options for pre-loading context** include:
  - `model`, `streaming`, `tools`, `system_message` (with `mode=replace|customize` and per-section overrides on ten sections including `identity`, `tone`, `tool_efficiency`, `environment_context`, `code_change_rules`, `guidelines`, `safety`, `tool_instructions`, `custom_instructions`, `last_instructions`).
  - `skill_directories` — paths to `SKILL.md` directories that pre-load specialized prompts and domain knowledge for the agent at session-create time.
  - `mcp_servers` — MCP server configs that expose pre-built tool surfaces (e.g., the GitHub MCP server at `https://api.githubcopilot.com/mcp/`).
  - `custom_agents` — named agent personas with their own prompts.
  - `available_tools` / `excluded_tools` — explicit tool allow / deny lists.
  - `provider` — BYOK (Bring Your Own Key) configuration for OpenAI / Azure / Anthropic / Ollama, allowing you to bypass Copilot's per-user quota entirely and use your own provider's rate limits.
  - `infinite_sessions={"enabled": True, "background_compaction_threshold": 0.80, "buffer_exhaustion_threshold": 0.95}` — automatic context-window compaction at 80 % utilization, blocking writes at 95 %; thresholds are **utilization ratios, not token counts**.
  - `session_id` — required for resumability (`resume_session`); without it, the SDK auto-generates a random ID and the session is non-resumable.
  - Lifecycle hooks: `on_session_start`, `on_session_end`, `on_pre_tool_use`, `on_post_tool_use`, `on_user_prompt_submitted`, `on_error_occurred` — each can return `additional_context` strings that are injected into the agent before it sees the next prompt (a clean way to pre-stuff context).
- **Session concurrency limits.** The SDK explicitly supports "multiple concurrent sessions, each maintaining independent state" within one `CopilotClient`, verified in `python/e2e/test_multi_client.py`. There is **no documented hard cap** in the SDK itself; the practical ceiling is the user's premium-request quota and the single CLI process's throughput. The CLI itself has a built-in **30-minute idle timeout** that auto-cleans up inactive sessions. Protocol v3 added experimental support for *multiple clients sharing one session* via a broadcast event model. The SDK explicitly **does not provide built-in session locking** — concurrent writes to a shared `session_id` are undefined behavior and you must serialize access yourself (the docs recommend Redis `SETNX` with TTL).

### 2. Recommended patterns for high-throughput Copilot SDK use

GitHub publishes a `cookbook/python/multiple-sessions.md` recipe and a "Scaling Copilot SDK deployments" doc that prescribe three patterns:

| Pattern | When to use | Mechanism |
|---|---|---|
| **One CLI per user / strong isolation** | Multi-tenant SaaS, SOC 2 / HIPAA, mixed auth tokens | `CLIPool` keyed by `userId`; each user's `CopilotClient` spawns its own CLI server on a unique port |
| **Single CLI, many sessions** | Internal tools, trusted tenants, parallel tasks | One `CopilotClient`, many `client.create_session(...)` calls; each session has independent context, history, and (optionally) model. Verified to be the natural API. |
| **CLI fleet with a load balancer** | Hundreds of concurrent users, horizontal scale | `CLILoadBalancer` choosing servers via round-robin or sticky-session hash on `userId`; each CLI runs `--headless --host 0.0.0.0` |

Additional throughput levers documented in the SDK and surrounding tooling:

- **BYOK** to use your own OpenAI / Azure / Anthropic quota, sidestepping Copilot's premium-request budget.
- **Steering vs. enqueue** message modes — `mode="immediate"` interrupts the in-flight turn, `mode="enqueue"` (the default) buffers messages to start a new turn after the current one finishes (FIFO), reducing wasted reasoning when input arrives mid-turn.
- **Plan mode** + reduced "parallelized tools" — GitHub's own usage docs explicitly recommend enabling plan mode and reducing parallel tool calls when nearing usage limits because parallelized tool execution is what burns weekly quota fastest.
- **Distributed tracing** — `telemetry={"otlp_endpoint": "..."}` in client options gives you OpenTelemetry spans for every session, message, and tool call, which is critical to debugging where rate-limit hangs originate.
- **Community wrappers** add resilience the SDK lacks: `copex` (PyPI) wraps the SDK with adaptive concurrency, exponential backoff with jitter, a sliding-window circuit breaker, model fallback chains, and rate-limit-aware backoff. This pattern (retry/backoff/fallback) is what most production Copilot-SDK callers end up implementing themselves.

**Important caveat on rate limits.** Even with the "right" architecture, GitHub Copilot rate limits are *per-user* and (since the March 2026 fix described in community discussion **#190176**) sensitive to which model you use — "newer models like Opus 4.6 and GPT-5.4" consume the weekly budget much faster, and the limit applies *across all models* once tripped. Pro+ users have reported being locked out for 5–18+ hours, sometimes "463 hours" in extreme cases (community discussion **#192485**). For genuinely high-throughput batch CWE analysis you almost certainly want BYOK rather than Copilot subscription quota.

### 3. How AI coding assistants actually handle multi-file context

The prevailing pattern across **Aider, Cursor, Cline, Continue, and Hermes Agent** is *not* to inline ten or twenty files verbatim. It is:

- **Aider** — AST + PageRank + token-budgeted "repo map".
  - Tree-sitter parses every file in 40+ languages and extracts `name.definition.*` and `name.reference.*` tags from `tags.scm` queries.
  - A NetworkX graph is built where nodes are files and edges are import / call / inheritance dependencies.
  - **Personalized PageRank** ranks files by relevance to the chat-window state.
  - A **binary search** over the ranked list selects the top-K definitions that fit in `--map-tokens` (default 1 024 tokens, roughly 2 048 with the `map-multiplier-no-files` of 2 when no files are explicitly added).
  - The chosen tags are rendered with `grep_ast.TreeContext` as scope-aware *elided* code views (definitions kept, bodies elided), producing a compact structural overview rather than full file contents.
  - Files explicitly added via `/add` are sent verbatim; everything else is the repo map.
  - A `diskcache.Cache` keyed by mtime avoids re-parsing.
  - Aider's blog post claims it processes **~15 B tokens / week** at scale with this design.
- **Continue (formerly Cline of Continue, now distinct from `cline.bot`)** — embeddings + keyword + reranker.
  - Tree-sitter chunks code along function / class boundaries; chunks larger than the embedder's max (e.g., 16 000 tokens for `voyage-code-3`) are split.
  - Chunks are stored in **LanceDB** (default) with metadata; SQLite holds the relational map.
  - At query time `@codebase` runs a hybrid retrieval: `nRetrieve=25` initial results from embedding similarity, optionally re-ranked with `voyage rerank-lite-1`, `cohere`, or an LLM reranker, down to `nFinal=5`. Newer agent mode (Claude 3 / Llama 3.1+ / Gemini 1.5 / GPT-4o families) automatically attaches a *repository map* of file paths.
  - Continue's blog post on "accuracy limits of codebase retrieval" notes the **HyDE** trick (have the LLM generate a hypothetical code snippet and embed *that* against the corpus) measurably improves recall over embedding the raw question.
- **Cursor** — workspace index + `@`-mentions + on-the-fly chunking.
  - On first open Cursor builds a semantic index of the workspace.
  - `@file`, `@folder`, `@code`, `@codebase`, `@docs`, `@web` are explicit context-injection mechanisms.
  - For long files Cursor "chunks the file into smaller chunks and re-ranks them based on relevance to the query."
  - Cursor's pipeline is documented as **Collect → Reorder → Reason** (scan codebase, reorder by relevance, plan how to use context).
  - The Cursor docs and community guidance explicitly warn against over-specifying — "If you include 20 files via `@file` when only 3 are relevant, you dilute the AI's attention" — and recommend `@codebase` instead, which lets Cursor's retriever pick.
- **Cline** — turn-by-turn context curation rather than upfront stuffing.
  - Cline is a "context engineering harness": every turn it assembles the system prompt, environment details (open tabs, working dir), tool definitions, conversation history, and file previews.
  - **FileContextTracker** records every file read/edit with a `record_source` (`read_tool | user_edited | cline_edited | file_mentioned`) and timestamps (`cline_read_date`, `cline_edit_date`, `user_edit_date`) so that *stale* duplicate file reads can be evicted automatically — Cline's blog explicitly identifies "multiple old versions of the same file in context" as a leading cause of `replace_in_file` errors.
  - **ContextManager** does dynamic truncation; **Auto Compact** triggers at ~75–80 % of the model's window (Cline's docs say "effective limit is ~75-80% of maximum for optimal performance"); `/smol` and `/newtask` are user-driven compaction shortcuts; `Focus Chain` keeps a re-injected todo list to maintain narrative integrity.
  - Cline historically had a **300 KB hard file-size cap** that triggered "prompt too long" errors with no recovery (issue **#4389**); chunked / streaming file reads are an active feature request.
- **Hermes Agent / similar** — currently rely on agent-driven `read_file` and `search_files`; issue **#535** explicitly proposes adopting Aider's PageRank repo-map verbatim.

**Common token-budget tactics observed across all five tools:**

1. **Filter then rank** — graph (PageRank) or vector (embeddings + reranker) ranking before any inlining decision.
2. **Elide rather than truncate** — keep function signatures and class skeletons, drop bodies.
3. **Dedupe stale reads** — Cline's removal of older file versions is the canonical example.
4. **Hybrid retrieval** — embeddings + keyword (BM25 / SQLite FTS) + structural (call graph) almost always beats any single signal.
5. **Cache aggressively** — mtime-keyed parse cache (Aider's `.aider.tags.cache.v3/`), indexing on first-open (Cursor), local LanceDB / SQLite (Continue).

**Trade-offs (tool-call file reads vs. pre-inlining):**

| Aspect | Tool-call reads | Pre-inline at prompt time |
|---|---|---|
| Token cost upfront | Low | High (unavoidable for unused files) |
| Latency | Adds ~1 round trip per file (subject to SDK timeout, see §1) | Single big prompt, single inference |
| Adapts to agent's actual need | Yes — only fetches what it asks for | No — over-includes the speculative top-K |
| Risk of rate-limit / timeout | High under bursty workloads | Low (one call) |
| Risk of stale content (long sessions) | Low (fresh reads) | High (snapshot at prompt time) |
| Best for | Exploratory analysis, large repos, mutable state | Bounded analyses, single CWE checks, batch SAST passes |

**Files that exceed the context window.** Universal pattern: chunk (tree-sitter aware), rank chunks, include only the highest-ranked. Continue's docs note that for `voyage-code-3` (16 000-token max chunk size) this is enough to fit "most files," with truncation as a fallback. Cline streams file reads; Aider only ever sends elided definitions for non-edit files; Cursor reranks chunks per query.

### 4. Cross-file CWE / security analysis without tool-call bottlenecks

Four patterns dominate the literature and shipping products:

**(a) Map-reduce / dual-LLM (Simon Willison, DeepMind CaMeL, agentic-patterns).**
- *Map* phase: a quarantined LLM is dispatched per file, returning a strictly-typed structured finding (`{cwe: ..., severity: ..., line_range: ...}`).
- *Reduce* phase: a privileged orchestrator (often deterministic code) aggregates findings without ever seeing raw file bytes.
- Benefits: parallelizable, prompt-injection resistant, bounded per-file token cost, easy to retry individual maps under rate-limit pressure.
- Costs: cross-file flows (taint that crosses files) are invisible to a single map call — the reduce step or a second pass must reconstruct them.
- Corelight's blog on "Leveraging Map-Reduce & LLMs for Network Detection" and Threat Model Co's "LLM Map-Reduce Pattern" both document concrete production uses.

**(b) Hierarchical / cascaded analysis.**
- File-level pass → module-level pass (synthesize file findings + dependency facts) → cross-module pass (only on hot paths).
- Snyk DeepCode AI's **CodeReduce** is the productized form: program analysis trims the code window to "only the portions of code needed to perform the fix," shrinking the LLM's attention to the source/sink/sanitizer slice. Snyk reports CodeReduce makes other LLMs (including non-DeepCode ones) more accurate than vanilla GPT-4 on autofix.

**(c) Pre-computed dependency / call graphs steering selection.**
- Aider's PageRank over a tree-sitter call/import graph is the canonical example.
- The arXiv paper *Codebase-Memory* (2603.27277) shows a Tree-Sitter MCP-served knowledge graph delivers **83 % answer quality vs. 92 % for a file-exploration agent at 10× fewer tokens and 2.1× fewer tool calls**, with type-resolution passes for Go / C / C++.
- *LLM-Assisted Static Analysis for Detecting Security Vulnerabilities* (arXiv 2405.17238) describes a `FilterPath(Path, G, LLM, C)` pattern where a CodeQL-style path graph is computed deterministically and the LLM only sees ±5 lines around the source/sink plus enclosing function/class — explicitly a context-narrowing strategy for CWE checks.

**(d) AST-based context extraction.**
- Same tree-sitter substrate as Aider, but used to extract only the symbols (functions, classes, variable scopes) the LLM needs, with bodies elided.
- The "Tree-sitter MCP" ecosystem on PulseMCP advertises **70–95 % token reduction** versus naive file inlining.
- Polyglot-LS demonstrates a code-action-driven version where the prompt is parameterized by the AST node currently in focus.

**Commercial tools — a comparison.**

| Product | Cross-file primitive | LLM role | Avoids tool-call bottleneck via |
|---|---|---|---|
| **Semgrep AI / Workflows** | Pro Engine inter-file taint (interfile: true; 25 % fewer FPs, 250 % more TPs) | LLM step *after* deterministic taint analysis classifies/synthesizes/triages | Static analysis enumerates routes & taint paths; LLM only reasons over pre-extracted code slices |
| **Snyk DeepCode AI** | Symbolic/AST event graph + ML-trained rules in 19+ languages | LLM (in-house, plus optional GPT) for autofix; symbolic engine validates fixes | CodeReduce focuses LLM on source/sink slice, not whole files |
| **GitHub Copilot Autofix (CodeQL)** | CodeQL data-flow analysis identifies the alert path | LLM generates a fix from alert context | Documentation explicitly notes that "if affected code is within a very large file or repository, context provided to the LLM may be truncated"—they don't even attempt fixes when context is insufficient |
| **Semgrep Multimodal Detection** | Pro Engine taint trace → LLM verifies missing authorization | LLM reasons only about pre-traced flows | Deterministic step gates the LLM call entirely |

**Key takeaway:** none of these commercial products give the LLM unconstrained tool-call access to a multi-file repository for security analysis. Every one of them runs a deterministic program analysis first (CodeQL, Semgrep Pro Engine, Snyk's symbolic engine, or a tree-sitter graph), then surgically presents the LLM with a narrow context window. This is the same conclusion a Copilot-SDK-based pipeline should reach: relying on tool-call file reads for CWE analysis is the *worst* of both worlds — it incurs the latency of N round trips, the rate-limit risk of N requests, and the LLM-attention dilution of N files.

### 5. Token-budgeting best practices for 10–20 files of 100–3 000 lines

**Estimating tokens.**
- Use `tiktoken` with the encoding matching your target model: `o200k_base` for GPT-4o / GPT-5 family, `cl100k_base` for GPT-4 / GPT-4-turbo / `text-embedding-3-*`, `p50k_base` for Codex/older. For Claude, Anthropic's `client.messages.countTokens()` is authoritative; `tiktoken p50k_base` is a *rough* approximation but errors of 5–15 % are common because Claude uses a distinct BPE.
- Quick rules of thumb (used by `count_tokens` PyPI package and most AI tooling): **~4 characters per token** for source code, or **~1.33 tokens per word**. For 100–3 000-line files (assume 60 chars/line average), that gives roughly **1 500 tokens per 100 lines / 45 000 tokens per 3 000-line file** — so a single large file can already eat 10–25 % of a 200 K context.
- Always count the *final wire payload*, not just file contents. Tool/function schemas, system prompt, prior assistant messages, and (for Copilot SDK) the SDK-injected `environment_context`, `tool_instructions`, `safety`, and `last_instructions` sections all consume tokens before your file content even arrives.

**Reserving output budget.**
- For analyzing CWEs across 10–20 files, reserve **25–35 %** of the model's window for the response. Models with structured-output / reasoning traces (GPT-5, Claude 3.7+ with reasoning enabled) can produce *much* longer outputs — Cline and Continue both expose `reasoning_budget_tokens` configuration knobs explicitly because reasoning tokens count against output.
- Cline's empirically derived "effective limit ≈ 75–80 % of maximum" is a good ceiling for *combined* input + output before performance degrades and auto-compaction kicks in.

**Truncating / summarizing large files.**
- Prefer **AST elision** (drop function bodies, keep signatures + docstrings + decorators) over naive head/tail truncation; this is what Aider's `to_tree()` does via `grep_ast.TreeContext`.
- For files over a "fits-in-budget" threshold:
  1. Extract only functions/classes touched by the CWE-relevant taint sources/sinks.
  2. Replace untouched bodies with `# … N lines elided …`.
  3. Add a one-line natural-language summary at the top.
- For extremely large files, pre-summarize with a **cheaper / smaller model** in a one-time map step and cache the summary keyed by file mtime / git SHA.

**Priority ordering of files for a specific CWE.**
- Two complementary signals work best in practice:
  1. **Structural relevance** — files containing known sources/sinks/sanitizers for the CWE (e.g., for CWE-89 SQL injection: anything calling `sqlite3.execute`, `psycopg2.cursor`, `cursor.execute`, ORM raw SQL APIs; anything containing user-input handlers like Flask/Django/FastAPI routes).
  2. **Graph proximity** — PageRank over the call graph, personalized toward the source-side and sink-side files (Aider-style).
- Use Semgrep / CodeQL / a custom tree-sitter pass to *emit the candidate flows first*, then prioritize files in flow-coverage order.
- For CWEs with no clean source/sink model (e.g., CWE-285 Improper Authorization, CWE-639 IDOR) lean on the Semgrep AI Workflows pattern: enumerate routes deterministically, then ask the LLM about handlers in route-coverage order.

**Context-window management across model backends.**

| Model | Context window | Pragmatic input cap (75 %) | Per-call latency-friendly target |
|---|---|---|---|
| GPT-4o / GPT-4.1 | 128 K | ~96 K | ≤ 30 K input + ≤ 8 K output |
| GPT-5 / GPT-5-codex (per Copilot SDK examples) | 200–400 K (varies) | depends on tier | ≤ 60 K input + ≤ 16 K output |
| Claude 3.7 Sonnet / 4 Sonnet (Cline default) | 200 K | ~150 K | ≤ 40 K input + ≤ 16 K output |
| Claude Opus 4.6 | 200 K | ~150 K | smaller (premium quota burns fast) |
| Gemini 1.5/2 Pro | 1–2 M | ~750 K | possible to inline more, but recall declines past ~256 K in published needle-in-haystack evals |
| Voyage code embedders (for retrieval, not generation) | 16 K per chunk | n/a | chunk + rerank |

For **Copilot-SDK** specifically, the model is not chosen by you on a per-token basis — it's the Copilot-CLI model selection — and you cannot directly query the remaining context. The `infinite_sessions` config (`background_compaction_threshold=0.80`, `buffer_exhaustion_threshold=0.95`) is your only knob, and thresholds are *utilization ratios*, not absolute counts. If you need byte-accurate token accounting, do it client-side with `tiktoken` *before* `session.send()`, or bypass the SDK and call your provider directly via BYOK.

**Putting it together — a recommended recipe for cross-file CWE analysis:**

1. **Plan deterministically.** Run Semgrep (`--pro` for inter-file) or a tree-sitter pass to emit candidate flows / route handlers / source-sink pairs.
2. **Rank files** by flow coverage + PageRank over the import graph; produce an ordered list per CWE.
3. **Budget.** Compute a token budget per call: `model_window × 0.75 − system_prompt − tool_schemas − response_reserve`. With `tiktoken`, walk down the ranked list inlining files until budget is exhausted; fall back to AST-elided skeletons for the rest.
4. **Map step.** Issue one Copilot-SDK session per file (or per flow) with `enqueue` mode if serializing on one CLI; or fan out across a CLI pool for true parallelism. Use BYOK if you'll exceed weekly Copilot quota.
5. **Defensive timeouts.** Override the 30 s JSON-RPC default by passing `timeout=120` (or more) to `send_and_wait`, and *always* register a `SessionEventType.SESSION_ERROR` handler that branches on `code == 'rate_limited'` versus other errors — otherwise rate limits will manifest as `asyncio.TimeoutError` and you'll mistake quota exhaustion for hangs.
6. **Reduce step.** Aggregate per-file findings deterministically; only invoke a final LLM if you need narrative cross-flow synthesis, and keep that reduce prompt under 30 K tokens by passing structured findings, not raw code.

---

## Details

### Copilot SDK API surface (Python) confirmed from PyPI + repo

```python
from copilot import CopilotClient, define_tool, SubprocessConfig, ExternalServerConfig
from copilot.session import PermissionHandler, PermissionRequestResult
from copilot.generated.session_events import (
    AssistantMessageData, AssistantMessageDeltaData, SessionIdleData,
    SessionEventType, PermissionRequest,
)

async with CopilotClient() as client:
    async with await client.create_session(
        on_permission_request=PermissionHandler.approve_all,
        model="gpt-5",
        streaming=True,
        tools=[my_tool],
        system_message={"mode": "customize", "sections": {...}},
        skill_directories=["./skills/cwe-reviewer"],
        mcp_servers={...},
        infinite_sessions={"enabled": True,
                            "background_compaction_threshold": 0.80,
                            "buffer_exhaustion_threshold": 0.95},
        provider={"type": "openai", "api_key": ...},   # BYOK
    ) as session:
        session.on(handler)                 # all events
        session.on("session.error", on_err) # specific
        await session.send({"prompt": "..."}, timeout=120.0)
        # or:
        resp = await session.send_and_wait({"prompt": "..."}, timeout=120.0)
```

Notable confirmed behaviors:
- `client.create_session` is async and returns a session that itself supports `async with`.
- `session.on(handler)` returns an unsubscribe closure.
- `send_and_wait` raises `asyncio.TimeoutError` on `effective_timeout` expiry; default is **60 s**.
- The internal `JsonRpcClient.request(method, params, timeout=30.0)` controls per-RPC timeouts; long-running tools or slow networks therefore need explicit per-call overrides.
- `client.get_session_metadata(session_id)` is O(1).
- `client.list_sessions()` and `client.delete_session(id)` exist for fleet management.
- Async context managers were added in PR #475 (release notes).
- A bug where structured `ToolResultObject` values were being stringified before RPC (#970) was fixed in v0.3.0; before the fix, `toolTelemetry` and `resultType` were silently lost.

### Why 429s look like timeouts (mechanism)

The vendored OpenAI client inside the CLI (`node_modules/openai/client.js:354`) raises `RateLimitError` on 429, but only after exhausting its retry budget. Internal logic at `transport-stream-shared-B2Os3U8j.js:29–36` (`shouldBypassLongSdkRetry`) only marks 429 non-retryable when status ∈ {408, 409, 429, ≥500} **and** a `Retry-After` header is present **and** retry-after exceeds 60 s. Copilot's weekly-quota 429 returns `text/plain` with no `Retry-After`, so retries continue, and by the time the SDK gives up, the user-facing JSON-RPC layer can already have hit its own timeout (defaults 30 s for RPC, 60 s for `send_and_wait`, 600 s for the agent-level run timeout). The reproducible symptom (per openclaw/openclaw#71120) is **10 minutes of silence** followed by `surface_error`. Mitigations in user code:

- Set explicit `timeout=...` on every `send_and_wait`.
- Subscribe to `session.error` events with a typed match on `code == 'rate_limited'`.
- Wrap calls in your own retry/circuit-breaker (or use the `copex` wrapper).
- Switch model fallbacks (Auto model selection, weaker model) when rate-limited; GitHub's docs explicitly advise this.

### Snyk DeepCode AI / CodeReduce in detail

DeepCode AI combines a symbolic, rule-based AST/event-graph engine (the inheritance from the original DeepCode acquisition) with multiple in-house ML models. Its multi-file capability comes from the symbolic engine's interfile dataflow analysis (Java, JavaScript/TypeScript, Python, C#, Go, PHP, Kotlin, Swift, C/C++). The LLM is gated by **CodeReduce**, which "leverages program analysis to limit the LLM's attention mechanism to only the portions of code needed." Snyk's blog claims CodeReduce raised LLM autofix accuracy enough that other LLMs (Claude, GPT-4) outperform vanilla GPT-4 on Snyk's autofix benchmark *when fed the CodeReduce slice*. The lesson is portable: **a deterministic context-narrowing pass is worth more than a bigger model.**

### Semgrep AI Workflows in detail

Semgrep's "Multimodal Detection" workflow is the clearest published example of LLM + SAST hybrid for CWE checks:

1. Pro Engine taint analysis traces user-input → sensitive-sink across files (`interfile: true`).
2. The taint trace (source location + sink location + path nodes) is passed to an LLM step.
3. The LLM reasons about whether authorization checks are missing along the path.
4. Outputs are constrained (yes/no/uncertain + rationale).

This pipeline reportedly delivers **90 % better recall than Claude Code alone** on IDOR detection. The workflow is built on Semgrep's Custom Workflows SDK (Python), making it a useful template if you're building cross-file CWE analysis on top of Copilot SDK rather than Semgrep.

### GitHub Copilot Autofix limitations

GitHub's own Copilot Autofix (powered by Copilot APIs + CodeQL) explicitly documents the multi-file limitation: *"Some security alerts, such as those that require tracing data flow across a complex, multi-file codebase or those that represent subtle logic flaws, could be difficult for the model to resolve. … If the affected code is within a very large file or repository, the context provided to the LLM may be truncated. The model needs sufficient context to understand the surrounding code logic and safely apply a fix; when this context is limited, the feature will not attempt a fix."* This is a candid acknowledgement that even GitHub's flagship product punts on cross-file context when it doesn't have a deterministic anchor — reinforcing that the pattern **deterministic-analysis-first → LLM-narrow-window** is the state of the art.

---

## Caveats

- **The Copilot SDK is in public preview.** As of v0.3.0 (release notes April 2026), naming, types, and behaviors have changed across releases (the v0.3.0 release alone documented 39 `Params → Request` renames and dozens of cross-language naming alignments). Some of the API surface cited above (e.g., `infinite_sessions` thresholds, `system_message.mode="customize"` section overrides) is recent and may evolve.
- **Rate-limit details on the Copilot side are not officially published as concrete numbers.** GitHub's usage-limits page is intentionally vague about per-minute / per-hour / per-week quotas, citing "fairness," "abuse mitigation," and operational opacity; the community discussions cited (#180092, #189890, #190176, #192485, #150373) provide the only public datapoints, and several of them are speculative or reflect transient bugs that have since been patched. Numbers like "5–18 hours waiting" or "463 hours" are user-reported anecdotes, not GitHub policy.
- **The `openclaw/openclaw#71120` analysis is from a third-party tool dissecting the bundled OpenAI SDK behavior** — its conclusions about retry logic, `Retry-After` handling, and `shouldBypassLongSdkRetry` reflect the state of the bundled CLI at the time of that issue (April 2026) and may have been patched since. Treat the mechanism description as plausible and reproducible at that snapshot, not as eternal truth.
- **Cline is not Continue.** The user's question conflates them ("Cline (formerly Continue)"). They are *separate* projects: Cline (`cline.bot`, `github.com/cline/cline`) is a VS Code agentic extension with FileContextTracker / Auto Compact; Continue (`continue.dev`, `github.com/continuedev/continue`) is a different VS Code/JetBrains assistant with `@codebase` LanceDB-backed retrieval. The findings above attribute mechanisms to the correct project.
- **"~75–80 % of context window" as a soft cap is Cline's specific recommendation**, not a universal truth; other tools tolerate higher fill (Aider regularly inlines whole files when explicitly added to chat). Treat it as a starting point, not a law.
- **Token-count estimates per file are rough.** Source code tokenizes denser than prose for cl100k_base (whitespace clusters help) but sparser for languages with long identifiers. For production budgeting, count concrete files with `tiktoken` rather than using char-based heuristics.
- **BYOK changes the rate-limit profile entirely.** If you BYOK against your own OpenAI/Anthropic/Azure account, you inherit *that* provider's rate-limit semantics (which *do* expose proper `x-ratelimit-*` headers and `Retry-After`). The 429-as-timeout problem described above is specific to using Copilot's own gateway through the SDK.
- **Some commercial product claims are vendor marketing.** The "250 % more true positives," "90 % better recall," "80 % accurate autofixes," and "70–95 % token reduction" figures are vendor-reported on vendor benchmarks; they directionally support the architectural claims but should not be cited as independently verified.
- **Future-tense / aspirational statements were filtered out** of the report where possible. Statements about features in private beta (Semgrep Custom Workflows, parts of Snyk DeepCode AI, "experimental support for multiple concurrent sessions" in the Copilot CLI changelog) are flagged as such in the source material; treat them as in-flight rather than GA.