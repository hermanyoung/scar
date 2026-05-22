# How the GitHub Copilot SDK Handles Structured JSON Responses (as of May 2026)

## TL;DR

- **The GitHub Copilot SDK does *not* expose a first-class `response_format` / `json_schema` parameter analogous to OpenAI's Structured Outputs.** It is a wrapper around the GitHub Copilot CLI agent runtime communicating over JSON-RPC, not a thin chat-completions client, so JSON Schema enforcement of the *final assistant message* is not part of its public API surface in the Public Preview (April 2026 release).
- **Schema-driven structured output is achieved indirectly through three patterns the SDK does support natively:** (1) **typed custom tools** defined with Zod (TypeScript) or Pydantic (Python) via `defineTool`/`@define_tool`, whose JSON Schemas are enforced by the underlying model's tool-calling; (2) the **`session.ui.elicitation()` API** with a `requestedSchema` (JSON Schema) for collecting structured *user* input; and (3) **prompt-engineered JSON output** that the developer parses with `JSON.parse(response.data.content)` after the model returns.
- **For "real" OpenAI-style Structured Outputs you currently must use BYOK** (Bring Your Own Key) and point the SDK's `provider` config at an OpenAI-compatible endpoint using `wireApi: "responses"`. GitHub's January 15, 2026 changelog explicitly noted that the BYOK Responses API path "enables structured outputs and richer multimodal interactions" — but that capability lives in the upstream provider, not in a Copilot SDK schema-binding helper.

## Key Findings

1. **The SDK is an agent runtime, not a chat-completions SDK.** All four official SDKs (Node.js/TypeScript `@github/copilot-sdk`, Python `github-copilot-sdk`, Go `github.com/github/copilot-sdk-go`, .NET `GitHub.Copilot.SDK`) plus the community Java port talk to a local Copilot CLI server over JSON-RPC. The CLI manages models, planning, tool-loops, MCP, and authentication; the SDK exposes `CopilotClient`, `createSession()`, `send()`/`sendAndWait()`, and event subscriptions.

2. **No `responseFormat`/`response_format` field exists on `SessionConfig` or `MessageOptions`** in any documented SDK README, changelog entry, or public-preview docs as of May 2026. A search of the github/copilot-sdk repository, GitHub Docs, and the npm/PyPI READMEs returns only:
   - Tool parameter schemas (input schemas the model must call your code with).
   - Elicitation `requestedSchema` (JSON Schema for user form input).
   - System-prompt section overrides (`replace`, `append`, `customize`).
   None of these binds the *final assistant text* to a schema with grammar-constrained decoding the way OpenAI's `response_format: { type: "json_schema", strict: true }` does.

3. **Structured output is currently a "tool-calling or prompt-engineering" exercise.** The GitHub Blog's own "Building AI-powered GitHub issue triage with the Copilot SDK" example, and the third-party Medium tutorial "Adding agentic AI with Copilot SDK" (form-filling agent), both show the canonical pattern: put JSON formatting rules in a `systemMessage`, call `session.sendAndWait({ prompt })`, then `JSON.parse(response.data.content)` (or accumulate `assistant.message_delta` chunks and parse the result). The third-party `mvkaran/gh-copilot` GitHub Action exposes an `output-schema` input that is passed to the prompt and validated post-hoc — its troubleshooting docs explicitly say: "JSON parsing errors → Use output-schema to guide structure."

4. **Custom tools are where rigorous schema enforcement actually lives.** Tool-call argument schemas are passed end-to-end to the underlying model and the model's tool-call arguments are validated/coerced through Zod or Pydantic before your handler runs. This is the SDK's only "guaranteed-shape" data path:
   - **Node.js:** `defineTool("name", { parameters: z.object({ ... }), handler })` — Zod schemas are auto-converted to JSON Schema; raw JSON Schemas are also accepted.
   - **Python:** `@define_tool(description=...)` plus a Pydantic `BaseModel` parameter class; the SDK auto-generates the JSON Schema from the model.
   - **.NET:** Built on `Microsoft.Extensions.AI` `AIFunction`/`AIFunctionFactory`, which derives the JSON Schema from method attributes.
   - **Go:** Manual `map[string]interface{}` parameter schemas with handler typing into Go structs (`json:"..."` tags).

5. **Elicitation provides schema-driven *user-side* structured I/O.** Every SDK exposes `session.ui.elicitation()` (and convenience wrappers `confirm`, `select`, `input`) that accept a `requestedSchema` (JSON Schema, supporting `type`, `properties`, `enum`, `minLength`, `maxLength`, `minimum`, `maximum`, `default`, `required`). The result returns `{ action: "accept" | "decline" | "cancel", content: { ... } }` where `content` is validated against the schema. **This is the closest the SDK ships to "structured outputs", but it captures *human* input via a UI dialog, not LLM output.** It also requires the host to advertise `capabilities.ui.elicitation = true`.

6. **Recent changes during the 2025–2026 timeframe relevant to structured output:**
   - **January 14, 2026** — GitHub Changelog: "Copilot SDK in technical preview." Initial release of the four-language SDKs.
   - **January 15, 2026** — GitHub Changelog: "Copilot bring your own key (BYOK) enhancements." Notes that BYOK now supports models using the **Responses API**, which "unlocks structured outputs and richer multimodal interactions." This is the only changelog item that explicitly mentions structured outputs; the capability is provided by the upstream OpenAI/Foundry endpoint, not by a new SDK abstraction.
   - **March 30, 2026** — `onElicitationRequest` callback added to Node SDK (PR #908) for elicitation-provider support, generalizing schema-driven user-form prompts.
   - **April 2, 2026** — GitHub Changelog: "Copilot SDK in public preview." Adds Java SDK, blob attachments, fine-grained system-prompt customization sections (`identity`, `tone`, `tool_efficiency`, `code_change_rules`, `safety`, `tool_instructions`, `custom_instructions`, `last_instructions`), OpenTelemetry support, BYOK against OpenAI / Microsoft Foundry / Anthropic. **No native `response_format` was added.**
   - **April 7, 2026** — Copilot CLI itself supports BYOK and local models (Ollama, vLLM, Foundry Local), via `COPILOT_PROVIDER_BASE_URL` etc.
   - May 2026 (CLI v1.0.41) — MCP servers with non-conforming `outputSchema` are now accessible (a robustness fix, not a new SDK feature). Some MCP tools may now return `structuredContent` per the MCP 2025-06-18 spec, which is a parallel, MCP-side mechanism for structured outputs that flows through the agent.

7. **Relationship to OpenAI's Structured Outputs.** Because the Copilot SDK runs through the Copilot CLI's agentic loop — which itself wraps multiple model providers (GPT-5/5.1/5.2/5.3-Codex, Claude Sonnet 4.5, Gemini, etc.) — it has not exposed the OpenAI-specific `response_format: { type: "json_schema", json_schema: {...}, strict: true }` knob. Two reasons emerge from the docs and changelog:
   - The CLI normalizes across providers (GitHub-hosted, Anthropic, OpenAI, Foundry, OpenRouter, Ollama, vLLM); a uniform schema-binding API would have to fall back gracefully on providers that lack grammar-constrained decoding.
   - The agentic loop is multi-step (plan → tool call → tool call → final message); binding the *final* message to a strict schema while the model is still tool-calling is not well-defined. GitHub's recommended pattern is therefore to use a custom tool whose parameters are the structured object you want — the model "calls" your tool with the structured payload, your handler returns success, and the model is gently steered toward emitting that schema.
   - When you do need OpenAI-style strict JSON, the supported path is BYOK with `provider: { type: "openai", baseUrl: "...", wireApi: "responses", apiKey: ... }`, and you supply the `response_format` to the upstream provider via your own request augmentation — the SDK does not surface a typed parameter for it.

## Details

### Programmatic API surface relevant to JSON output

**Node.js / TypeScript (`@github/copilot-sdk`):**

```ts
import { CopilotClient, defineTool } from "@github/copilot-sdk";
import { z } from "zod";

const client = new CopilotClient();

// Pattern A — Tool-calling with Zod-derived JSON Schema (strongest schema enforcement)
const recordIssue = defineTool("record_issue", {
  description: "Record a triaged issue.",
  parameters: z.object({
    title: z.string(),
    severity: z.enum(["low", "medium", "high"]),
    labels: z.array(z.string()),
  }),
  handler: async (issue) => {
    // `issue` is already validated and typed
    await db.insert(issue);
    return { ok: true };
  },
});

const session = await client.createSession({
  model: "gpt-5",
  tools: [recordIssue],
  systemMessage: {
    mode: "customize",
    sections: {
      tone: { action: "replace", content: "When you finish triage, call record_issue." },
    },
  },
});
await session.sendAndWait({ prompt: "Triage issue #123 and record it." });

// Pattern B — Prompt-engineered JSON, then parse manually (most common in the wild)
const session2 = await client.createSession({
  model: "gpt-4.1",
  systemMessage: {
    mode: "customize",
    sections: {
      tone: {
        action: "replace",
        content:
          'Respond ONLY with JSON matching: {"summary": string, "labels": string[]}. No markdown.',
      },
    },
  },
});
const r = await session2.sendAndWait({ prompt: "Summarize PR #42" });
const parsed = JSON.parse(r!.data.content);  // developer is responsible for validation
```

**Python (`github-copilot-sdk`):**

```python
from copilot import CopilotClient, define_tool
from copilot.session import PermissionHandler
from pydantic import BaseModel, Field

class TriageResult(BaseModel):
    title: str
    severity: str = Field(pattern="^(low|medium|high)$")
    labels: list[str]

@define_tool(description="Record a triaged issue.")
async def record_issue(params: TriageResult) -> str:
    await db.insert(params.model_dump())
    return "ok"

async with CopilotClient() as client:
    async with await client.create_session(
        on_permission_request=PermissionHandler.approve_all,
        model="gpt-5",
        tools=[record_issue],
    ) as session:
        await session.send("Triage issue #123 and record it.")
```

The Python SDK also offers a low-level tool definition (`Tool(name=..., parameters={...}, handler=...)`) where you write JSON Schema by hand if you do not want Pydantic.

**.NET (`GitHub.Copilot.SDK`):** Tool definitions use `Microsoft.Extensions.AI`'s `AIFunctionFactory.Create(MyMethod)`, which extracts the JSON Schema directly from method signatures and `[Description]` attributes. The SDK is NativeAOT-compatible and explicitly disables reflection-based JSON serialization, so any structured-output binding is generator-driven.

**Go:** No high-level Pydantic/Zod equivalent; you write `Parameters: map[string]interface{}{...}` and unmarshal the model-supplied arguments into a Go struct in your `Handler`.

### Elicitation (schema-driven user input, not model output)

```ts
const result = await session.ui.elicitation({
  message: "Configure deployment",
  requestedSchema: {
    type: "object",
    properties: {
      region:   { type: "string", enum: ["us-east-1", "eu-west-1"] },
      replicas: { type: "number", minimum: 1, maximum: 10 },
    },
    required: ["region"],
  },
});
// result.action === "accept" => result.content is shape-validated.
```

This is the clearest "JSON-Schema-enforced" surface in the SDK, but it routes a request from the agent/MCP server *to* a UI handler, not from the LLM back to your code.

### Validation behavior

- **Tool argument schemas:** validated by Zod/Pydantic in your SDK process before your handler runs; if validation fails the SDK responds to the CLI with an error and the model typically retries. This is grammar-constrained on providers that support strict tool-calling (GPT-5.x family, Claude Sonnet 4.5).
- **Final assistant message:** **no schema validation by the SDK.** `response.data.content` is a free-form string. Any JSON parsing or schema validation is the developer's responsibility (e.g., `JSON.parse`, then `zod.safeParse`, or `BaseModel.model_validate_json`).
- **MCP tool results:** if an MCP tool advertises `outputSchema`, the May 2026 CLI 1.0.41 release improved compatibility ("MCP servers with non-conforming outputSchema are now accessible"); the agent receives `structuredContent` per the MCP 2025-06-18 spec, but per-MCP-spec validation enforcement is up to the host.
- **Elicitation results:** validated against `requestedSchema` before being returned to the caller.

### Comparison to OpenAI Structured Outputs

| Capability | OpenAI SDK | GitHub Copilot SDK (May 2026) |
|---|---|---|
| `response_format = { type: "json_schema", strict: true }` on the final assistant message | Yes, with grammar-constrained decoding on supported `gpt-4o-2024-08-06+` and `gpt-5` models | **Not exposed.** Achieved indirectly via prompt + post-parse, or via a tool whose parameters are the target schema |
| Pydantic / Zod auto-conversion to JSON Schema | `client.beta.chat.completions.parse(..., response_format=MyModel)`; `zodResponseFormat(MySchema)` | Available **only for tool parameters** via `defineTool`/`@define_tool`, not for response binding |
| Refusal handling | Dedicated `refusal` field | None — treat as plain text |
| Strict tool calling | `tools=[{ "type": "function", "function": {..., "strict": true}}]` | Tool calling supported; "strict" is provider-dependent and not surfaced as an SDK flag |
| Streaming structured outputs | `client.responses.stream()` parses incrementally | Stream `assistant.message_delta` chunks, accumulate, parse at end |
| Path to OpenAI-native structured outputs | Native | Via BYOK provider config: `provider: { type: "openai", wireApi: "responses", baseUrl, apiKey }` — but you must add `response_format` yourself in the upstream call; the SDK gives no helper |

### Why the SDK chose this design (inferred from docs)

The repo README, the GitHub Blog "Build an agent into any app with the GitHub Copilot SDK" announcement, and the DEV.to walkthrough all emphasize that the SDK is a **programmable agent runtime**, deliberately reusing the same loop that powers Copilot CLI: planning, tool invocation, file edits, MCP, multi-turn execution, infinite sessions/compaction. In that paradigm, the "final answer" is one event at the end of an arbitrarily long chain, and binding it to a strict schema interferes with intermediate tool calls. GitHub's recommended idiom is therefore: *if you need structured data out, define a tool whose `parameters` schema is the data structure you want, and let the agent call it*. That tool-call argument is your structured output.

### What developers are doing in practice (May 2026)

- **GitHub's own tutorials and the blog issue-triage demo:** prompt-engineered JSON in the system message, then `JSON.parse(response.data.content)`. No schema enforcement.
- **The community `mvkaran/gh-copilot` GitHub Action:** offers an `output-schema` input plus automatic syntax validation for JSON/YAML/Markdown — implemented above the SDK by post-validating the text response.
- **DevOps community patterns (RepoCheckAI, github-sre-agent, copilot-sdk-samples):** structured "report" outputs are built by giving the agent custom tools (`record_finding`, `create_issue`) whose argument schemas capture the desired structure. The "issue" *is* the structured output.
- **Form-filling agent (Medium, "Adding agentic AI with Copilot SDK"):** tells the model in `systemMessage` to emit `{ fields, message }`, accumulates SSE deltas server-side, then `JSON.parse(fullResponse)` before returning to the React frontend. Highlights the brittleness ("the AI models in VS Code Copilot didn't understand how to use the SDK correctly") and lack of schema guardrails.

## Caveats

- **Public preview status.** Both the changelog and every SDK README state: "This SDK is in public preview and may change in breaking ways." A `responseFormat` parameter could be added at any time; one community issue (#61) and the broader feature-request channel point at gaps in the JSON-RPC protocol that the SDK can only cover once the CLI exposes them. The SDK supports protocol versions 2 and 3 today.
- **CLI-version coupling.** The SDK is bound to a specific Copilot CLI version (downloaded at build time for .NET, bundled in wheels for Python). Structured-output capabilities will follow the CLI's protocol additions, not SDK-only releases.
- **Provider variance.** Even if you use BYOK, strict JSON-Schema decoding only works on providers that implement it (OpenAI Responses API, Azure Foundry on `wireApi: "responses"`, recent Anthropic models with `output_config.format`). Local models via Ollama/vLLM may not honor strict schemas; the Copilot CLI BYOK docs warn that models must support tool calling and streaming and recommend ≥128k context.
- **Model-routing uncertainty.** Issue #142 in github/copilot-sdk (January 23, 2026) reported that the `model` parameter on `createSession` was sometimes silently downgraded (e.g., requesting `gpt-5.1-codex`, getting `gpt-4.1` or `gpt-4o`). If you are relying on a particular model's structured-output guarantees, verify the actual model used per session.
- **No validation of the final message.** Even when prompts work well, the SDK provides no built-in retry/repair loop on malformed JSON in `response.data.content`. You must implement your own (e.g., parse → on-error re-prompt).
- **Microsoft Copilot Studio is a different product.** Several search results referred to "JSON output" in Microsoft Copilot Studio (auto-detect/custom JSON modes), the Microsoft 365 Agents Toolkit, and the AI Toolkit's `json_schema` Structured Output feature. These are unrelated to GitHub's `github/copilot-sdk` and were excluded from the analysis above.
- **Distinguish SDK from CLI.** GitHub Copilot CLI issue #52 ("JSON-formatted output") is a *separate* feature request to make the CLI emit a JSONL transcript of its agentic events for shell scripting; it is not about LLM-side structured outputs and would not change the SDK's response-binding behavior.
- **Source dating note.** Some referenced articles (Anthropic's `claude-opus-4-7` example, "May 15, 2026" trip-planning sample) appear to be forward-dated examples in vendor docs rather than statements about Copilot SDK capabilities; they were used only to characterize the comparison landscape, not to imply features in the Copilot SDK.