# Plan 022 — Azure AI Foundry Provider for Anthropic Claude Models

**Status:** [x] Implemented (merged to main 2026-07-31)
**Date:** 2026-07-30
**Source:** Provider-architecture review requested to evaluate Azure AI Foundry (Claude-on-Foundry) as a new `foundry:` provider, following the same pattern as the existing `openai:`/`anthropic:`/`copilot:`/`claude:`/`codex:` providers in `src/security_review/providers.py`.
**Depends on:** none. Independent of Plan 021 (in progress on `main` at time of writing — do not touch the files that plan is mid-editing: `context_builder.py`, `models/degradation.py`, `passes/config_review.py`, `passes/inventory.py`, `passes/sast.py`, `tools/specs/*.yaml`).
**Baseline environment:** `python` resolves to Anaconda Python 3.14.4 (works fine here — the pin that matters is the library pin below, not the interpreter). `pydantic-ai==1.63.0` (exact match between `pyproject.toml` and the installed package — no drift). `anthropic==0.84.0` installed (transitively pulled in by `pydantic-ai[anthropic]==1.63.0`). HEAD at time of writing: `4296` (short) / `42966c64ffc1ae948e3c421262907b4c51042624`.

**Target Azure resource (verified live, 2026-07-30, `az` 2.84.0):**

| | |
|---|---|
| Subscription | `ice-security-research` (`e9ae84d8-7fa3-49c1-838e-81ce8a57a576`) |
| Tenant | `6d6a11bc-469a-48df-a548-d3f353ac1be8` |
| Resource group | `rg-secrch-mission-control-dev-001` |
| Account | `gis-mission-control-resource` — kind `AIServices`, SKU `S0`, region **swedencentral** |
| Foundry endpoint | `https://gis-mission-control-resource.services.ai.azure.com/` (the account's "AI Foundry API" endpoint — **this is the `llm.foundry_base_url` value**, and it is *not* the account's default `properties.endpoint`, which is the `.cognitiveservices.azure.com` form) |
| Claude deployments | **none.** The 11 existing deployments are OpenAI (`gpt-4.1`, `gpt-5.4`, `gpt-5-mini`, `gpt-5-nano`, `gpt-5.3-codex`, `model-router`, `text-embedding-3-large`), DeepSeek (`DeepSeek-V4-Pro`, `V4-Flash`, `V3.2`) and MoonshotAI (`Kimi-K2.6`). A Claude deployment must be created first — see WP-0. |

This is the same resource `mission-control` already points at, so SCAR will share its quota. Note the two facts that shape the whole plan: nothing Anthropic is deployed yet, and the hosting option that governs structured outputs is selected by **model version** at deployment time (§1).

---

## 0. Purpose and context

### 0.0 Correction of scope

An earlier pass at this task drafted a plan against `/Users/herman.young/development/mission-control` by mistake, using that repo's provider architecture as the template. **This plan supersedes that one and targets this repo (SCAR) instead.** Mission-control's `model_providers.py`/`model_builder.py` split, `output_mode: native` structured-output story, and `foundry_anthropic:` naming were all specific to that codebase and do not transfer 1:1 — see §0.2 for the concrete architectural deltas.

### 0.1 What Foundry actually buys SCAR (read before assuming the pitch from the original ask)

The original ask cited "structured outputs and caching" as the Foundry benefits. For SCAR specifically, only one of those is real:

- **Caching: real and already half-built.** `model_settings.py::build_model_settings()` already wires Anthropic prompt caching (`anthropic_cache_instructions`, `anthropic_cache_tool_definitions`) whenever the resolved provider is `anthropic:`. It is gated by a single `if provider == "anthropic":` string check (`src/security_review/model_settings.py:34`). Claude-on-Foundry speaks the same Anthropic Messages wire protocol, so this gate just needs to also match `foundry:` — no new caching logic required (see WP-C).
- **Structured outputs: already implemented, and `foundry:` inherits them for free.** AGENTS.md Critical Rule 7 ("Agents return `output_type=str`") describes the *agent-definition default* only. At runtime every LLM pass overrides it per call: `native_json = supports_native_json(model)` and then `output_type=TriagedFinding if native_json else str`. See `model_capabilities.py:99-113` plus the four call sites — `passes/triage.py:83,268-281`, `passes/holistic.py:165,412-424`, `passes/config_review.py:80,110-140`, `passes/verify.py:75,290-303`. Native JSON is used for `anthropic:` and `openai:`; the markdown/JSON prompt blocks + `output_parser.py` are the *fallback* for `copilot:`/`claude:`/`codex:`, which cannot enforce a schema. So this is not a new capability to design — it is an existing, capability-gated path that the Foundry provider joins automatically. Verified empirically at the pinned versions (`pydantic-ai==1.63.0`, `anthropic==0.84.0`): an `AnthropicModel` backed by an `AsyncAnthropicFoundry` client reports `profile.supports_json_schema_output = True`, and that flag survives SCAR's full wrapper chain (`RetryingModel(ConcurrencyLimitedModel(AnthropicModel))` — both are `WrapperModel` subclasses that proxy `.profile`), so `supports_native_json()` returns `True` for `foundry:` with **no code change beyond the provider branch in WP-B**.

  Two consequences that do need deliberate handling, and they are the reason WP-C2 exists:

  1. **The mechanism is output-tool calling, not the structured-outputs beta.** This was verified rather than assumed, because it determines how much the Foundry hosting option matters. Running an agent with `output_type=TriagedFinding` through a `FunctionModel` spy yields `output_tools=[('final_result', strict=None)]` and `allow_text_output=False` — a tool call. The Anthropic profile's `default_structured_output_mode` is `'tool'`, and `_build_output_config()` (`pydantic_ai/models/anthropic.py:1152-1171`) only emits the beta `output_config={'format': ...}` when `output_mode == 'native'`, which SCAR never requests (it passes a bare `output_type=<Model>`, not `NativeOutput(...)`). The codebase already knew this — `retry_model.py:129-131` says *"native-JSON providers return tool-call parts for structured output"*. **Consequence: tool calling works on Foundry regardless of hosting option**, so the Hosted-on-Anthropic/Hosted-on-Azure choice is a future-proofing preference here (it gates the beta, `strict: true` on tool definitions, and thinking-plus-output-tools), not a blocker. An earlier draft of this plan overstated it as a hard requirement.

  2. **The real blocker is SCAR's own capability gate against a stale profile map.** `supports_native_json()` reads `model.profile.supports_json_schema_output`, which PydanticAI derives from the *model-name string*. At the pinned `pydantic-ai==1.63.0` that map does not know the newest Claude names — verified: `claude-opus-4-6` and `claude-haiku-4-5` report `True`, while **`claude-opus-5`, `claude-sonnet-5`, and `claude-opus-4-8` report `False`, identical to a model name that does not exist**. So deploying Opus 5 on Foundry would leave SCAR silently taking the regex path against a model perfectly capable of structured output — it simply never asks. Nothing errors; you just quietly lose the feature you provisioned for. This is why the model choice in WP-0 is coupled to the SDK pin, and why WP-C2's `native` mode must be able to *assert* capability rather than merely check it.

  3. **Capability detection is still endpoint-blind.** A profile describes a model name, never the deployment behind it. Combined with (2), the honest summary is that this flag is unreliable in both directions for Foundry, which is the whole justification for WP-C2 making the decision explicit config.
- **The real, unstated benefit: a second stable, per-token-billed Anthropic path.** This session's own recent scan of `mission-control` hit two failure modes back to back: GitHub Copilot quota exhaustion (`copilot:`, subscription rate limits) and repeated `empty_response` degradations on the Claude Agent SDK (`claude:`, subscription/session-bound transport — see `test_holistic_empty_response.py`). SCAR already has a subscription-independent, per-token path (`anthropic:`, direct API key), and Foundry does not add a *new capability* over it — it adds Azure-billed redundancy and, if your org already consolidates cloud spend through Azure, one invoice instead of two. Frame it to the team as "a second production-grade Anthropic transport, billed through Azure" rather than "a categorically new feature."

### 0.2 Architectural deltas vs. mission-control (do not port these assumptions)

| mission-control had... | SCAR actually has... |
|---|---|
| `model_providers.py` (factories) + `model_builder.py` (dispatch) as two files | Same split exists, but named `model_providers.py` (factories, `@lru_cache` per-secret) + `providers.py` (dispatch `build_model()` + alias resolution) |
| `providers.yaml` with `auth_mode`/`base_url`/`scope` per provider | No such file. Non-secret provider knobs (`max_concurrent`, `session_timeout`, `backoff_seconds`) live in `llm.providers.<name>` in `config/settings/security_review.yaml`; provider-specific *feature* knobs (`cache_ttl`, `thinking_budget`) live directly on `LLMConfig`, not nested under `providers.<name>` |
| `models.yaml` role aliases (`quick`/`moderate`/`comprehensive`) fanned out across ~30 agent configs | A single `llm.provider_model` (+ optional `llm.triage_model` override) in `security_review.yaml`. "Making Foundry the default" is a two-line YAML edit, not a fan-out (see WP-H) |
| `output_mode: native` per-agent schema field | No per-agent field, but the same capability exists globally and is already live: `supports_native_json(model)` (`model_capabilities.py:99`) selects `output_type=<PydanticModel>` vs. `output_type=str` per call in all four passes. WP-C2 makes the selection explicitly configurable instead of inferred |
| `AgentModelSchema.known_providers` list | `LLMConfig.provider_model` / `triage_model` / `VerificationConfig.model` each carry their own regex `pattern=r"^(openai|anthropic|copilot|codex|claude):.+$"` — three separate literals to extend, not one registry |
| `azure-identity` / Entra ID already a dependency (used elsewhere in mission-control) | No Azure dependency anywhere in SCAR today. **This plan uses API-key auth only** — adding `DefaultAzureCredential`/Entra would be a new pattern with a new dependency for a single provider, which P10 ("modular, reusable, elegant, robust") and the user's "exhaust existing options before introducing a new pattern" rule both argue against. Every existing SCAR provider (`openai`, `anthropic`, `openai`-backed `codex`) authenticates with a bearer secret resolved through `resolve_api_key()`; Foundry does the same. |
| `foundry:` prefix already claimed by Azure OpenAI (GPT), forcing `foundry_anthropic:` | `foundry:` is unclaimed in SCAR — grep confirms no existing provider branch, config key, or test references it. Use the short prefix. |

### 0.3 Mandatory reading before writing any code

1. `AGENTS.md` — Critical Rules, especially #2 (no hardcoded pricing), #3 (no hardcoded model strings), #7 (plain-text output), #11 (fail fast, no fallbacks).
2. `docs/03-principles/01-project-principles.md` — P5 (scope is configuration, not code), P6 (fail fast/loud), P7 (separate implementation from registration), P10 (modular/reusable/elegant/robust).
3. `src/security_review/providers.py` — the file this plan extends. Read `build_model()` end to end before editing it.
4. `src/security_review/model_providers.py` — the factory-per-provider pattern (`@lru_cache(maxsize=1)` keyed on secret, `resolve_api_key()` as the single secret-resolution chokepoint).
5. `src/security_review/model_settings.py` — the caching/thinking wiring this plan extends by one condition.
6. `src/security_review/model_capabilities.py` — read the whole file, docstring included. It is the existing structured-output strategy and the thing WP-C2 modifies; its docstring is the contract.
7. `src/security_review/output_parser.py` and one pass end to end (`passes/triage.py` is the shortest) — you need to see both halves of the native/prompted branch before changing which half runs.
8. `config/pricing.yaml` and `config/models.yaml` header comments — both files document their own schema inline; read them before editing.

### 0.4 Binding constraints (recap — violations will fail review)

- Fail fast, fail loud. A missing `AZURE_FOUNDRY_API_KEY` or missing `llm.foundry_base_url` must raise `ConfigurationError` immediately at model-build time — never a silent `None`/empty-string default that surfaces as an opaque SDK error three batches later.
- No hardcoded model strings or pricing in Python. Every new model/alias goes in `config/models.yaml`; every new price goes in `config/pricing.yaml`.
- Config schemas use `extra="forbid"` — new Pydantic fields must be added explicitly, not smuggled in via `**kwargs`.
- Absolute imports only; local (function-scope) SDK imports for provider branches, matching the existing lazy-import pattern in `build_model()`.
- Do not touch: `eval/` corpus, `config/prompts/*.md` content, `config/taxonomy/`, or the provider adapter internals of `copilot_model.py` / `claude_model.py` / `codex_model.py` — none of them are in scope for this plan.
- One work package = one commit. Suggested message format: `P022-<letter>: <imperative summary>`.
- **Never commit broken code.** Before every commit: `pytest tests/unit/ -v` must pass. Do not run `pytest tests/regression/` (real LLM calls, real cost) until WP-G's manual smoke test.
- No time estimates anywhere in follow-up notes or commit messages.
- Line numbers below are anchors from HEAD `42966c6`. Re-locate by content before editing — several other files are mid-edit on this branch for the unrelated Plan 021 (see "Depends on" above); line numbers in *this file* only refer to files not touched by that plan.

### 0.5 Prerequisites (verbatim, in order)

```bash
cd /Users/herman.young/development/scar
git status --short                 # confirm no unrelated uncommitted changes you'd lose
python -c "import anthropic; print(anthropic.__version__)"   # expect >= 0.83.0 (Foundry client landed in 0.83.0)
pytest tests/unit/ -q               # baseline green before starting
```

If `anthropic.__version__` is below `0.83.0`, stop and bump it first (`pip install -U anthropic` — it is a transitive dependency of the `pydantic-ai[anthropic]` extra, not exactly pinned itself, so this is normally safe without touching the `pydantic-ai==1.63.0` pin). At `0.84.0` (the baseline above) `AsyncAnthropicFoundry` is importable, but it is only one patch release past the version where Foundry support first shipped — treat WP-G's smoke test as load-bearing, not a formality.

---

## 1. Provider naming and auth design

- **Prefix:** `foundry:` (e.g. `foundry:claude-opus`, `foundry:claude-sonnet`). Unclaimed in SCAR today.
- **Auth mode:** API key only. Resolved through the existing `resolve_api_key()` chokepoint in `model_providers.py`, mirroring `anthropic`/`openai` exactly. No Entra ID / `DefaultAzureCredential` — see §0.2 rationale.
- **Env var:** `AZURE_FOUNDRY_API_KEY` (secret — lives in `config/.env`, resolved via `Settings`, never read directly outside `resolve_api_key()`).
- **Non-secret resource endpoint:** `llm.foundry_base_url` — a new field directly on `LLMConfig` (matching where `cache_ttl`/`thinking_budget` already live — provider-specific knobs are flat fields on `LLMConfig`, not nested under `llm.providers.<name>`, which is reserved for capacity/timeout settings shared by every provider). Format: the Foundry resource root **without** the `/anthropic` suffix, e.g. `https://<your-resource>.services.ai.azure.com` — the factory function appends `/anthropic` itself (Anthropic's SDK expects the full path including that segment).
- **Wire protocol:** Identical Anthropic Messages API. `AnthropicModel` + `AnthropicModelSettings` from PydanticAI are reused unchanged — only the client construction differs (`AsyncAnthropicFoundry` instead of `AsyncAnthropic`).
- **Deployment/hosting option: the model *version* is the hosting option.** This is the single most important operational fact in this plan and it is not obvious from the portal. Querying the catalogue directly (`az cognitiveservices model list -l swedencentral`) exposes a `hostedOn` capability per model-version, and for every dual-hosted Claude model **version 1 is `hostedOn=anthropic` and version 2 is `hostedOn=azure`**. Since PydanticAI drives native structured output through Anthropic's beta `output_config.format` on `client.beta.messages` (§0.1), the version you deploy decides whether structured outputs are available at all.

  Verified matrix for `swedencentral` (2026-07-30):

  | Model | `hostedOn=anthropic` | `hostedOn=azure` |
  |---|---|---|
  | `claude-opus-5` | **version 1** | version 2 |
  | `claude-sonnet-5` | **version 1** | version 2 |
  | `claude-opus-4-8` | **version 1** | version 2 |
  | `claude-haiku-4-5` | **version 20251001** | version 2 |
  | `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-opus-4-7`, `claude-opus-4-5`, `claude-opus-4-1`, `claude-sonnet-4-5`, `claude-fable-5` | — (no `hostedOn` advertised) | — |

  Two consequences worth internalising before WP-0:

  1. **SCAR's current models are not the right choice here.** `config/models.yaml` aliases point at `claude-opus-4.6` / `claude-sonnet-4.6`, and neither advertises a Hosted-on-Anthropic variant. If you want structured outputs — you do (§3) — the Foundry models are **`claude-opus-5` v1** and **`claude-sonnet-5` v1**, with `claude-haiku-4-5` v20251001 available as a cheap option. WP-D handles the registry consequences.
  2. **Auto-upgrade would silently break it.** The existing deployments on this resource carry `versionUpgradeOption: OnceNewDefaultVersionAvailable`. On a Claude deployment that setting is actively dangerous: an automatic v1 → v2 move is an Anthropic-hosted → Azure-hosted move, which can remove structured-output support *mid-life*, with no deploy event on your side to correlate against. Deploy with **no auto-upgrade** (WP-0) and record the version in the resource tags.

---

## 2. Work packages

### 2.0 Design rationale: why a sixth provider and not a parameterised `anthropic:`

The obvious "more elegant" alternative is to skip the new prefix entirely and give the existing `anthropic:` branch an optional `base_url` / client override, which would cover Foundry, a corporate LLM gateway, LiteLLM, or any Anthropic-compatible proxy with one code path instead of two. That is worth rejecting explicitly so nobody "simplifies" it back later.

Four things in SCAR are keyed on the provider prefix, and all four genuinely differ between direct Anthropic and Foundry:

1. **Pricing.** `config/pricing.yaml` keys are `provider:model` and `budget.py:133-140` resolves them from the prefix. Azure Foundry billing (marketplace/committed-throughput, possibly negotiated) is not Anthropic list price. Collapsing both onto `anthropic:*` keys makes per-platform cost attribution impossible and silently misprices whichever one you didn't configure.
2. **Rate limits.** `llm.providers.<name>` drives `max_concurrent` and the shared `ConcurrencyLimiter` (`providers.py:85-98`). A Foundry resource's quota is independent of your Anthropic Console quota; sharing one limiter would either under-use one or trip the other.
3. **Auth.** Different secret (`AZURE_FOUNDRY_API_KEY` vs `ANTHROPIC_API_KEY`), reported separately by `health-check`.
4. **Capability soundness.** Foundry is the one Anthropic-family path where the model profile can overstate the endpoint (§0.1), which is why `structured_output` exists as config. Fusing the paths would hide that distinction behind an optional argument.

The duplication this costs is small and shallow: two ~10-line factories in `model_providers.py` differing only in client class, mirroring the existing `get_anthropic_provider` / `get_openai_provider` pair. Sharing wire-protocol code is already handled by both branches constructing the same `AnthropicModel` — the reuse is at the layer that matters, and no abstraction is needed to get it.

One implementation note that follows from this: keep `@lru_cache(maxsize=1)` on `get_foundry_provider` despite it taking two arguments. `provider_model`, `triage_model`, and `verification.model` may name three different *models*, but they share one `(api_key, base_url)` pair within a run, so a single cache slot is correct and never thrashes. Do not "fix" it to a larger maxsize without a reason.

### WP-0: Provision the Claude deployment — **BLOCKED by Azure Policy**

There is no Claude deployment on the target resource, and a deployment attempt on 2026-07-30 established that this cannot currently be self-served. Two sequential blockers, in the order you hit them:

#### Blocker 1 (external, hard): Azure Policy forbids Anthropic model deployments

```
az cognitiveservices account deployment create -n gis-mission-control-resource \
  -g rg-secrch-mission-control-dev-001 --deployment-name claude-opus-5 \
  --model-name claude-opus-5 --model-version 1 --model-format Anthropic \
  --sku-name GlobalStandard --sku-capacity 1000
```

fails (via the equivalent ARM `PUT`, api-version `2026-05-01`) with:

```
InvalidResourceProperties: Policy evaluation returned compliance: NonCompliant for model claude-opus-5/1
with error: This action is noncompliant with policy
  /providers/Microsoft.Management/managementGroups/af8e2487-08f8-4d30-a770-a89a46b7dff7
  /providers/Microsoft.Authorization/policyAssignments/init-cogs-appr-models
Operator NotIn returned True for Field Microsoft.CognitiveServices.Data/accounts/deployments/model.publisher
Operator Equals returned True for Count of [parameters('allowedAssetIds')]
```

What this means, precisely: a management-group policy assignment named **`init-cogs-appr-models`** maintains an approved-model allow-list, and the Anthropic **publisher** is not on it (`model.publisher` NotIn), nor is the specific model in `allowedAssetIds`. The assignment sits at management group `af8e2487-08f8-4d30-a770-a89a46b7dff7`, above this subscription, so it cannot be changed from here.

It also cannot be *inspected* from here — both `az policy assignment show` at the management-group scope and `az policy assignment list` at subscription scope return `AuthorizationFailed` for `Microsoft.Authorization/policyAssignments/read`. So the allow-list's current contents are unknown to us; only the failing conditions are.

**What to ask for, and who from.** This needs the platform / cloud-governance owner of that management group, requesting either Anthropic added to the approved publishers (and/or the specific asset IDs for `claude-opus-5` and `claude-sonnet-5` added to `allowedAssetIds`), or a scoped policy exemption for `rg-secrch-mission-control-dev-001`. Useful precedent to cite: **third-party publishers are already approved on this very resource** — `DeepSeek-V4-Pro`, `DeepSeek-V4-Flash`, `DeepSeek-V3.2` (publisher DeepSeek) and `Kimi-K2.6` (publisher MoonshotAI) are deployed and running. So the ask is "add another already-GA Foundry publisher to an existing allow-list", not "make an exception to a principle". Note those deployments were created 2026-05-25, so confirm whether the policy post-dates them.

**Quota is not a constraint** — verified available and entirely unused in `swedencentral`:

| Quota pool | Limit | Used |
|---|---|---|
| `AIServices.GlobalStandard.claude-opus-5` (Anthropic-hosted) | 2000 | 0 |
| `AIServices.GlobalStandard.claude-opus-5.Azure` (Azure-hosted) | 2000 | 0 |
| `AIServices.GlobalStandard.claude-sonnet-5` / `.Azure` | 2000 each | 0 |
| `AIServices.GlobalStandard.claude-haiku-4-5` / `.Azure` | 4000 each | 0 |

The `.Azure` suffix on the quota pools independently confirms the §1 finding that hosting variant is a distinct SKU dimension, not just a label.

#### Blocker 2 (needs your input, and the CLI cannot express it)

Once policy is cleared, Anthropic deployments additionally require commercial-declaration metadata:

```
InvalidModelProviderData: ModelProviderData is required for Anthropic model deployments but was not
provided. Please provide all required fields: industry, organizationName, and countryCode.
```

`az cognitiveservices account deployment create` has **no parameter for this** (confirmed against `--help` on az 2.84.0), so the deployment must go through the portal (which prompts for the fields) or a direct ARM call. These are declarations about your organisation transmitted to Anthropic — they are yours to state, not mine to infer, so they are left blank here deliberately. The ARM form:

```bash
SUB=e9ae84d8-7fa3-49c1-838e-81ce8a57a576; RG=rg-secrch-mission-control-dev-001
ACC=gis-mission-control-resource
az rest --method put \
  --uri "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.CognitiveServices/accounts/$ACC/deployments/claude-opus-5?api-version=2026-05-01" \
  --body '{
    "sku": {"name": "GlobalStandard", "capacity": 1000},
    "properties": {
      "model": {"format": "Anthropic", "name": "claude-opus-5", "version": "1"},
      "versionUpgradeOption": "NoAutoUpgrade",
      "modelProviderData": {"industry": "<TBC>", "organizationName": "<TBC>", "countryCode": "<TBC>"}
    }
  }'
```

#### The deployment settings, once unblocked

1. **Models:** `claude-opus-5` for `provider_model`, `claude-sonnet-5` for `triage_model` — mirroring SCAR's existing opus-for-depth / sonnet-for-volume split (`security_review.yaml:53-54`).
2. **Version: `1`.** This is the hosting option (§1). Version 1 is `hostedOn=anthropic`; version 2 is `hostedOn=azure`. Structured output works either way (it is tool calling — §0.1 consequence 1), but v1 keeps the `output_config` beta, `strict` tool schemas, and thinking-with-output-tools available later.
3. **Deployment name = model name** (`claude-opus-5`, `claude-sonnet-5`). This is what keeps `providers.foundry: {}` empty in WP-D and the pricing keys self-describing. Avoid environment suffixes; the resource group is already dev-scoped.
4. **Capacity `1000`** (of 2000 available). The SKU default of `10` is far too low — holistic batches run to `max_tokens_per_batch: 150000` and dispatch concurrently, and rate-limit stalls surface as `RetryingModel` backoff (slow progress), not as an error. Reconcile with `llm.providers.foundry.max_concurrent` in WP-H, remembering `mission-control` shares this resource.
5. **`versionUpgradeOption: NoAutoUpgrade`** — the existing deployments here carry `OnceNewDefaultVersionAvailable`, which on a Claude deployment would be an unannounced v1 → v2 (Anthropic-hosted → Azure-hosted) move.

**Acceptance:**

```bash
az cognitiveservices account deployment list -n gis-mission-control-resource \
  -g rg-secrch-mission-control-dev-001 \
  --query "[?properties.model.format=='Anthropic'].{deployment:name, model:properties.model.name, version:properties.model.version, capacity:sku.capacity, upgrade:properties.versionUpgradeOption}" -o table
```

Both deployments listed, `version: 1`, capacity as chosen, upgrade option not `OnceNewDefaultVersionAvailable`. Tag the resource with model + version so the hosting variant is discoverable without re-deriving it from the catalogue.

---

### WP-A: Secrets and config schema plumbing

**Files:**

| File | Change |
|---|---|
| `src/security_review/config.py` | Add `azure_foundry_api_key: str = Field(default="", description="Azure AI Foundry API key (Anthropic Claude deployment)")` to `Settings` (after `anthropic_api_key`, `config.py:28`) |
| `src/security_review/config_schema.py` | Add `foundry_base_url: str \| None` field to `LLMConfig` (after `temperature`, `config_schema.py:51-56`); extend the three provider-prefix regexes to include `foundry` |
| `src/security_review/model_providers.py` | New `get_foundry_provider(api_key: str, base_url: str)` factory; extend `resolve_api_key()` with a `foundry` branch |

**Implementation steps:**

1. In `config.py`, add the new `Settings` field right after `anthropic_api_key` (`config.py:28`):

   ```python
   azure_foundry_api_key: str = Field(default="", description="Azure AI Foundry API key (Anthropic Claude deployment)")
   ```

2. In `config_schema.py`, add to `LLMConfig` right after `temperature` (`config_schema.py:51-56`) and before the `providers:` dict field (`:58`):

   ```python
   foundry_base_url: str | None = Field(
       default=None,
       description=(
           "Azure AI Foundry resource endpoint for the 'foundry:' provider, "
           "e.g. 'https://<resource>.services.ai.azure.com' (no trailing "
           "'/anthropic' — the provider factory appends it). Required when "
           "provider_model or triage_model uses 'foundry:'."
       ),
   )
   ```

3. In `config_schema.py`, extend all three occurrences of the provider regex from
   `r"^(openai|anthropic|copilot|codex|claude):.+$"` to
   `r"^(openai|anthropic|copilot|codex|claude|foundry):.+$"` — this is `LLMConfig.provider_model` (`:25`), `LLMConfig.triage_model` (`:30`), and `VerificationConfig.model` (`:102`). Change all three in the same commit; a mismatch between them is the kind of drift `extra="forbid"` schemas are supposed to prevent, so don't leave one behind.

4. In `model_providers.py`, add the new factory after `get_openai_provider` (`model_providers.py:49`), grouped with the other API-key-authenticated providers (ahead of the OAuth-based `get_codex_oauth_provider`):

   ```python
   @lru_cache(maxsize=1)
   def get_foundry_provider(api_key: str, base_url: str):
       """Create a PydanticAI AnthropicProvider for Claude on Azure AI Foundry.

       Wire protocol is identical to the direct Anthropic API (AnthropicModel
       and AnthropicModelSettings work unchanged) — only the client differs:
       AsyncAnthropicFoundry instead of AsyncAnthropic. base_url is the
       Foundry resource root; the SDK requires the '/anthropic' path segment
       appended, which callers should NOT include themselves.

       Cached by (api_key, base_url) — changing either creates a fresh client.
       """
       from anthropic import AsyncAnthropicFoundry
       from pydantic_ai.providers.anthropic import AnthropicProvider

       client = AsyncAnthropicFoundry(api_key=api_key, base_url=f"{base_url.rstrip('/')}/anthropic")
       logger.info("provider.foundry_ready", auth_mode="api_key")
       return AnthropicProvider(anthropic_client=client)
   ```

5. In `resolve_api_key()` (`model_providers.py:111-146`), add a `foundry` branch after the `openai` branch and before `codex` (`:137-139`):

   ```python
   if provider == "foundry":
       key = os.environ.get("AZURE_FOUNDRY_API_KEY") or get_settings().azure_foundry_api_key
       if not key:
           raise ConfigurationError(
               "AZURE_FOUNDRY_API_KEY not set. Set it in environment or config/.env.",
               code="SYS_SECRET_MISSING",
           )
       return key
   ```

6. **Fail at config load, not at first model build.** Add a `@model_validator(mode="after")` to `SecurityReviewConfig` (`config_schema.py:125`) asserting that if any of `llm.provider_model`, `llm.triage_model`, or `verification.model` uses the `foundry:` prefix, then `llm.foundry_base_url` is set. The root class is the only place with visibility of all three, since `verification.model` lives on `VerificationConfig`. This is the primary P6 gate: without it, a missing endpoint is discovered at the first LLM call — which in `full` mode is *after* inventory and the entire SAST pass have run, wasting minutes of work to report a config typo. Note this would be the first validator in `config_schema.py`; `model_validator` is stock Pydantic, not a new pattern, and cross-field requirements have no other correct home.

   The branch guard in WP-B step 1 stays as well, and that is deliberate rather than duplication: `build_model()` is a public entry point that tests and future callers reach with a hand-built `LLMConfig` that never passed through the root validator (this plan's own `test_build_model_foundry_missing_base_url_raises` does exactly that). The validator catches operator error at startup; the guard keeps the function honest in isolation.

**Acceptance:** `resolve_api_key("foundry")` raises `ConfigurationError` with a clear message when unset, and returns the key when `AZURE_FOUNDRY_API_KEY` is set. `LLMConfig(provider_model="foundry:claude-opus-5", foundry_base_url="https://x.services.ai.azure.com", ...)` validates without a Pydantic error, and `load_config()` on a YAML with `provider_model: "foundry:..."` but no `foundry_base_url` fails immediately with a message naming the missing key.

---

### WP-B: `build_model()` dispatch

**File:** `src/security_review/providers.py`

**Implementation steps:**

1. Add a new branch immediately after the `anthropic` branch (`providers.py:138-141`) and before `copilot` (`:143`) — grouping it next to the other Anthropic-wire-protocol branch:

   ```python
   elif provider == "foundry":
       from pydantic_ai.models.anthropic import AnthropicModel
       from security_review.model_providers import get_foundry_provider, resolve_api_key
       if not cfg.foundry_base_url:
           raise ConfigurationError(
               "llm.foundry_base_url must be set in config/settings/security_review.yaml "
               "when provider_model or triage_model uses 'foundry:'.",
               code="SYS_CONFIGURATION_ERROR",
           )
       inner = AnthropicModel(
           model_name,
           provider=get_foundry_provider(resolve_api_key("foundry"), cfg.foundry_base_url),
       )
   ```

2. No other change to `build_model()` is needed — the `ConcurrencyLimitedModel` + `RetryingModel` wrapping at the bottom of the function (`providers.py:165-171`) is already provider-agnostic and applies to `foundry:` automatically once `inner` is set.

3. Update the module docstring (`providers.py:1-17`) to list the new provider alongside the other five, e.g.:

   ```
   foundry:claude-opus-5         — Azure AI Foundry (API key, per-token, Azure-billed)
   ```

**Acceptance:** `build_model("foundry:claude-opus-5", llm_config=cfg)` with a valid `foundry_base_url` and `AZURE_FOUNDRY_API_KEY` set returns a wrapped `AnthropicModel`; with `foundry_base_url` unset it raises `ConfigurationError` mentioning `foundry_base_url` specifically (not a generic KeyError/AttributeError three layers down).

---

### WP-C: Extend caching to the Foundry path

**File:** `src/security_review/model_settings.py`

**Implementation steps:**

1. Change the single gate at `model_settings.py:34` from:

   ```python
   if provider == "anthropic":
   ```

   to:

   ```python
   if provider in ("anthropic", "foundry"):
   ```

2. No other line in `build_model_settings()` changes — `anthropic_cache_instructions`, `anthropic_cache_tool_definitions`, `anthropic_thinking`, and the adaptive-thinking model-name check are all wire-protocol-level Anthropic settings that apply identically to Foundry.

3. Update the module docstring (`model_settings.py:1-12`) — "Returns AnthropicModelSettings for anthropic: provider" becomes "...for anthropic:/foundry: providers".

**Acceptance:** `build_model_settings("foundry:claude-sonnet-5", cfg)` with `cache_ttl="ephemeral"` returns an `AnthropicModelSettings` with `anthropic_cache=True`, identical in shape to the `anthropic:` case.

---

### WP-C2: Make the structured-output decision explicit and configurable

**Why:** structured outputs are the more reliable path (they delete an entire regex-scraping layer that can silently drop a finding — see §3.1 below), and `foundry:` gets them automatically. But the *decision* is currently inferred from a model-name profile that knows nothing about the endpoint (§0.1, consequence 2). One YAML key removes the guesswork, gives an escape hatch if a Foundry deployment turns out not to support the beta, and makes native-vs-prompted an A/B you can measure with the existing regression harness instead of an argument.

**Files:**

| File | Change |
|---|---|
| `src/security_review/config_schema.py` | Add `structured_output: str` field to `LLMConfig` (`auto` \| `native` \| `prompted`) |
| `src/security_review/model_capabilities.py` | Change `supports_native_json()` **in place** to take the config; extract the raw profile probe into a module-private helper |
| `src/security_review/passes/{triage,holistic,config_review,verify}.py` | Pass `state.config.llm` to the four existing `supports_native_json(model)` calls |
| `config/settings/security_review.yaml` | Add the `structured_output:` key with the header-comment documentation the file's schema block already conventions |

**Design note — one function, not two.** An earlier draft added a *new* `resolve_native_json(model, llm_config)` next to the existing `supports_native_json(model)`. That was wrong on two counts, and the correction is the point of this note. First, near-duplicate names doing almost the same thing is exactly the duplication this codebase avoids. Second and worse, it leaves `supports_native_json()` importable as a **silent bypass**: any future pass that calls the old name gets profile inference with the operator's `structured_output` setting ignored, and nothing fails — it just quietly uses the wrong output path. Changing the existing function in place is safe and cheap: it has exactly four call sites (all in passes, all of which already hold `state.config.llm` for `build_model_settings`), and — verified — **zero test coverage today**, so no test depends on the old signature. Keep the raw probe as a module-private `_profile_supports_json_schema(model)` so the capability/policy split still exists as structure, without exposing a second public name that can be called by mistake.

**Implementation steps:**

1. Add to `LLMConfig` (next to `foundry_base_url` from WP-A):

   ```python
   structured_output: str = Field(
       pattern=r"^(auto|native|prompted)$",
       description=(
           "How agent output is obtained. 'auto' = use native JSON schema "
           "enforcement when the model's profile supports it (anthropic, "
           "openai, foundry) and prompted markdown/JSON parsing otherwise "
           "(copilot, claude, codex). 'native' = force schema enforcement and "
           "fail loudly if the provider cannot honour it. 'prompted' = force "
           "the text + output_parser.py path for every provider."
       ),
   )
   ```

   No `default=` — per AGENTS.md rule 11 this is a required config value, so a missing key fails at load time rather than silently picking a mode.

   **Interaction with WP-C4.** As written below, `native` *asserts* capability and raises if the profile disagrees. That is the correct semantics once WP-C4 lands, because the profile will then report `True` for Opus 5. If WP-C4's fallback path is taken instead (no clean SDK version exists), `native` changes meaning from "assert" to "force" — it attaches an overridden profile at model construction. Implement the assert form here; only revisit if WP-C4 actually falls back, and if it does, update this function's docstring rather than leaving two conflicting descriptions in the tree.

2. In `model_capabilities.py`, rename the existing body to a private probe and make the public function the policy (P7: the capability check and the policy decision stay separate concerns, but only one of them is public API):

   ```python
   def _profile_supports_json_schema(model) -> bool:
       """Raw capability probe: does this model's profile enforce JSON schema?"""
       try:
           return bool(model.profile.supports_json_schema_output)
       except AttributeError as e:
           logger.debug("model_capabilities.no_profile", model=type(model).__name__, error=str(e))
           return False


   def supports_native_json(model, llm_config: LLMConfig) -> bool:
       """Decide whether to request native schema-enforced output.

       'auto' trusts the model profile; 'native'/'prompted' override it. The
       override exists because a profile describes a *model*, not an
       *endpoint*: a Foundry deployment can advertise a Claude model whose
       profile claims JSON-schema support while the deployment itself does
       not expose Anthropic's structured-outputs beta.
       """
       mode = llm_config.structured_output
       if mode == "prompted":
           return False
       if mode == "native":
           if not _profile_supports_json_schema(model):
               raise ConfigurationError(
                   f"llm.structured_output='native' but model "
                   f"{type(model).__name__} does not support JSON-schema output. "
                   f"Use 'auto' or 'prompted'.",
                   code="SYS_CONFIG_INVALID",
               )
           return True
       return _profile_supports_json_schema(model)
   ```

   Update the module docstring too (`model_capabilities.py:1-29`) — its usage example currently shows the old single-argument call and is the first thing the next reader will copy.

3. Update the four call sites (`triage.py:83`, `holistic.py:165`, `config_review.py:80`, `verify.py:75`) to `supports_native_json(model, state.config.llm)`. Nothing downstream of those lines changes — each pass already branches on the resulting boolean. Confirm with a grep that four is still the true count before and after (`rg 'supports_native_json' src/ tests/`); if a fifth appears later, this is the function that must not be called without config.

4. Add to `config/settings/security_review.yaml` under `llm:`, and document it in that file's header schema comment block (`security_review.yaml:7-22`) alongside `cache_ttl`/`thinking_budget`:

   ```yaml
   structured_output: "auto"
   ```

**Acceptance:** `supports_native_json()` returns `True` for a `foundry:`/`anthropic:` model under `auto`, `False` for a `copilot:` model under `auto`, `False` for every provider under `prompted`, and raises `ConfigurationError` for a `copilot:` model under `native`. Setting `structured_output: "prompted"` makes a `foundry:` run take the `output_parser.py` path with no code edit — that is the escape hatch WP-G leans on. `rg 'supports_native_json' src/` shows no remaining single-argument call.

---

### WP-C4: Bump `pydantic-ai` so the Opus 5 / Sonnet 5 profiles are recognised

**Why this is required and not optional.** At the pinned `pydantic-ai==1.63.0`, `anthropic_model_profile()` reports `supports_json_schema_output = False` for `claude-opus-5`, `claude-sonnet-5`, and `claude-opus-4-8` — the same answer it gives for a model name that does not exist. Only older names (`claude-opus-4-6`, `claude-haiku-4-5`) report `True`. Since `supports_native_json()` reads exactly that flag, deploying Opus 5 without this bump means SCAR takes the regex path against a model that is fully capable of structured output: it simply never asks. Nothing errors, and the feature you provisioned for is silently absent. Verified by direct inspection of the profile function at the installed version.

The two profiles are otherwise **identical field for field** — `default_structured_output_mode`, `json_schema_transformer`, `prompted_output_template`, `thinking_tags`, `supports_tools`, and the builtin-tool set all match; `supports_json_schema_output` is the single divergence. That is what makes a version bump a clean fix rather than a gamble: nothing else about how SCAR talks to the model changes.

**Files:** `pyproject.toml` (lines 22, 26-27, 32, 45 — the pin is repeated in the base dependency list and in the `openai`/`anthropic` extras, and all occurrences must move together), `requirements.txt`.

**Implementation steps:**

1. Find the earliest `pydantic-ai` release whose Anthropic profile recognises `claude-opus-5` and `claude-sonnet-5`. Do not just take latest — the smallest move that fixes the problem is the one with the least regression surface. Check candidates without committing to them:

   ```bash
   pip download pydantic-ai==<candidate> -d /tmp/pai --no-deps -q && \
     python -c "import zipfile,glob,re; ..."   # or install into a throwaway venv and call
   # anthropic_model_profile('claude-opus-5').supports_json_schema_output
   ```

   The check that matters is one line: `anthropic_model_profile('claude-opus-5').supports_json_schema_output is True`.

2. **A/B the candidate against the current pin before adopting it.** This is mandatory per AGENTS.md — the repo carries a documented SDK regression precedent (Copilot SDK `0.3.0` broke CWE-312/522 detection 100% of the time via suspected prompt truncation, which is why versions are pinned exactly rather than floored). The harness already exists:

   ```bash
   python scripts/benchmark_cwes.py --ab-sdk 1.63.0,<candidate> --runs 3 --providers copilot:claude-opus
   ```

   Use a provider that works *today* (`copilot:` or `claude:`) for the A/B, so you are measuring the SDK change in isolation rather than confounding it with the new Foundry path.

3. Update the pin in both files, keeping the exact-pin convention (`==`, not `>=`) and keeping every occurrence in `pyproject.toml` consistent.

4. Re-run the unit suite and the golden regression baseline on a provider that currently works:

   ```bash
   pytest tests/unit/ -v
   pytest tests/regression/ -v --provider copilot:claude-opus
   ```

   A `PASS → FAIL` on any CWE is a regression that blocks the bump; `FAIL → FAIL` is a known gap; `FAIL → PASS` is an improvement worth capturing with `--save-golden`.

5. Re-verify the wrapper-chain assumption at the new version, since it is load-bearing for the whole plan and is not covered by any existing test until WP-C2 adds one:

   ```bash
   python -c "
   from anthropic import AsyncAnthropicFoundry
   from pydantic_ai.providers.anthropic import AnthropicProvider
   from pydantic_ai.models.anthropic import AnthropicModel
   c = AsyncAnthropicFoundry(api_key='dummy', base_url='https://x.services.ai.azure.com/anthropic')
   m = AnthropicModel('claude-opus-5', provider=AnthropicProvider(anthropic_client=c))
   print(m.profile.supports_json_schema_output)   # must print True
   "
   ```

**Fallback if no acceptable version exists.** If every candidate that recognises Opus 5 also regresses the golden baseline, do not force the bump. The alternative is to construct the Foundry model with an explicit profile — `AnthropicModel(name, provider=..., profile=replace(anthropic_model_profile(name), supports_json_schema_output=True))`, which is verified to produce a profile identical to a recognised model's — driven by `structured_output: "native"` so it is an operator declaration rather than a hidden patch. Treat this as the documented fallback, not the default: it asserts a capability the SDK does not vouch for, and it needs revisiting at every future upgrade.

**Acceptance:** `anthropic_model_profile('claude-opus-5').supports_json_schema_output is True` at the new pin; `pytest tests/unit/ -v` green; the regression baseline shows no `PASS → FAIL` on any CWE; both `pyproject.toml` and `requirements.txt` carry the same exact pin.

---

### WP-C3: Fix the holistic `parse_failed` misclassification in native mode

**This is a pre-existing bug that this plan would activate.** It is dormant today only because the default provider is `claude:` (prompted). Do not ship WP-H without it.

**The defect.** `holistic.py:489-491` computes:

```python
parse_failed = empty_response or (
    not review_result.findings and review_result.review_notes is not None
)
```

`review_notes` is an **in-band sentinel from the parser**: `output_parser.py:204` sets `review_notes=text[:1000]` in exactly one case — a non-empty response it could not parse. On the prompted path that inference is sound.

On the **native** path it is not. `review_notes` is a normal optional field on `HolisticReviewResult` (`models/findings.py:214`), it appears in the JSON schema handed to the model, and so the *model itself* fills it in. A perfectly correct clean result — `findings=[]` plus `review_notes="No IDOR patterns found in these handlers"` — therefore computes `parse_failed=True`. Consequences, in order of severity: the check is routed to RETRY (`_classify_result`), the retry costs a full second batch, and if the model answers the same correct way again the run records a `check_failed` degradation asserting the CWE was **NOT assessed**. A clean check is reported as an unassessed one — a false negative in the coverage report, which is precisely the integrity class Plan 021 exists to eliminate.

**The fix.** The sentinel only means anything on the parsed path, so gate it. `native_json` is already a parameter of the enclosing function (`holistic.py:371`), so it is in scope:

```python
# review_notes is an in-band sentinel set by output_parser.py:204 for a
# non-empty-but-unparseable response. In native mode the field is
# LLM-populated and carries no such meaning — a clean check may legitimately
# set it, so consulting it there would report an assessed check as failed.
parse_failed = empty_response or (
    not native_json
    and not review_result.findings
    and review_result.review_notes is not None
)
```

Also confirm the sibling passes are genuinely unaffected rather than assuming it: `triage.py:300-315`, `verify.py:323-`, and `config_review.py:150-160` all branch on `isinstance(output, <Model>)` and use no in-band sentinel, so they need no change. Holistic is the only pass that infers parse state from a field's presence.

**Test:** construct a `HolisticReviewResult(findings=[], files_reviewed=["a.py"], review_notes="No findings.")`, run the classification with `native_json=True`, and assert `parse_failed is False`; with `native_json=False` assert `True` (the prompted contract is preserved). This test fails against current `main`, which is how you know it is a real fix and not a no-op.

---

### WP-D: Model registry entries

**File:** `config/models.yaml`

**Depends on WP-0** — the deployment names it creates are the literal strings this file must resolve to.

The registry currently assumes one Claude generation across all providers: `aliases` map short names to dotted canonical IDs (`claude-opus: "claude-opus-4.6"`) and `providers.anthropic`/`providers.claude` convert those to dashed wire IDs. Foundry breaks that assumption, because the models available with `hostedOn=anthropic` are a *different generation* (opus-5 / sonnet-5) from what the aliases point at (opus-4.6 / sonnet-4.6) — see §1. Do **not** paper over this by mapping `"claude-opus-4.6" → "claude-opus-5"` in the `providers.foundry` block: that would make `resolve_model_name()` silently return a different model than the operator named, and pricing/audit records would then attribute Opus-5 spend to an Opus-4.6 request. That is precisely the class of bookkeeping lie P13 forbids.

**Implementation steps:**

1. Add the Foundry-generation models as first-class canonical IDs in `aliases:` (`config/models.yaml:23-29`), so an operator can name them explicitly:

   ```yaml
   claude-opus-5: "claude-opus-5"
   claude-sonnet-5: "claude-sonnet-5"
   ```

   These are identity mappings, which looks redundant but is deliberate: it registers the names as known canonical IDs in the one file that is meant to list them, rather than leaving them as unregistered strings that only work by falling through `resolve_model_name()`'s pass-through branch. Add a comment noting they are the Foundry Hosted-on-Anthropic generation.

2. Add an **empty** `foundry` entry to the `providers:` map (`config/models.yaml:34-45`):

   ```yaml
   foundry: {}   # Deployment names match canonical IDs exactly (WP-0 step 3) — no override needed
   ```

   Empty is correct here and mirrors `copilot: {}` / `openai: {}`. Foundry's model IDs are already dash-form with no version dot to translate (`claude-opus-5`, not `claude-opus-5.0`), so there is nothing for an override table to do — provided WP-0 step 3's naming discipline was followed. If someone deployed under a different name anyway, *this* is where the mapping goes, and it is the only place.

3. Leave the existing `claude-opus` / `claude-sonnet` / `claude-haiku` aliases untouched. They continue to mean the 4.6/4.5 generation for `copilot:`, `claude:`, and `anthropic:`. `foundry:` users name `claude-opus-5` / `claude-sonnet-5` explicitly. Resisting the temptation to overload the short aliases per-provider is what keeps one alias from meaning two different models depending on prefix.

**Acceptance:** `resolve_model_name("foundry", "claude-opus-5") == "claude-opus-5"`, and `resolve_model_name("anthropic", "claude-opus") == "claude-opus-4-6"` still holds (no regression to the existing providers). Confirmed against the live deployment list in WP-G, not just by reading YAML.

---

### WP-E: Pricing entries + cache-aware cost accounting

This work package splits in two. **WP-E1** is required before `foundry:` can be used at all (SCAR fails fast on missing pricing — see `budget.py:61-66`). **WP-E2** fixes a pre-existing gap that this plan's own caching claim (§0.1) would otherwise make misleading in the cost report; it is a deliberate decision point, not an oversight.

#### WP-E1 (required): pricing entries

**File:** `config/pricing.yaml`

1. Add one entry per model deployed in WP-0, keyed on the resolved `foundry:<deployment-name>` from WP-D, in USD per token:

   ```yaml
   # Anthropic Claude via Microsoft Foundry (GlobalStandard, swedencentral).
   # Rates are per-token; confirm against Azure Cost Management for this
   # resource — Foundry Claude is billed through Azure Marketplace and the
   # effective rate can differ from Anthropic's list price.
   foundry:claude-opus-5:
     input_per_token: 0.0000XX
     output_per_token: 0.000XXX
   foundry:claude-sonnet-5:
     input_per_token: 0.00000XX
     output_per_token: 0.0000XXX
   ```

   **Do not copy the `anthropic:` values at `config/pricing.yaml:61-69` as a stand-in.** Those are Opus/Sonnet **4.6** rates, and WP-D established that the Foundry models are the **5** generation — a different price point. Placeholder digits are deliberate above: fill them from the Azure pricing page or a first-invoice reading for this subscription. A wrong-but-plausible number here is worse than a missing one, because `max_budget_usd` (currently 100) silently enforces against it and `pricing_entry_exists()` cannot tell a stale rate from a correct one.

**Acceptance:** `pricing_entry_exists("foundry:claude-opus-5")` returns `True` after WP-D + this step. `scar.py health-check` (`cli/tools.py:70-80`) shows a green `pricing: foundry:...` line for whichever model `provider_model`/`triage_model` is set to.

#### WP-E2 (decision point): cache tokens are billed at the full input rate — a pre-existing gap

`CostTracker.record()` (`budget.py:44-93`) takes only `tokens_in`/`tokens_out` and every call site (`passes/holistic.py:432-438`, `passes/triage.py:289`, `passes/config_review.py:166`, `passes/verify.py:311`, `preflight.py:55`) passes `usage.input_tokens`/`usage.output_tokens` straight through. PydanticAI's `usage()` result also exposes cache-specific token counts (Anthropic's Messages API returns `cache_read_input_tokens` and `cache_creation_input_tokens` separately from `input_tokens`), but nothing in SCAR reads them. This means every cost report today — for the *existing* `anthropic:` provider, not just the new `foundry:` one — bills cache reads at the same rate as a cold input token, when Anthropic actually charges roughly 10% of the input rate for a cache read and a premium for a cache write. Net effect: **SCAR's cost tracker over-reports true spend whenever caching is active**, which can trip `max_budget_usd` prematurely.

This is a real bug, but it predates this plan and touches five call sites plus the pricing schema — it is not a one-line fix. Two options, pick one explicitly rather than defaulting silently:

- **Option 1 (recommended, scoped as WP-E2):** Extend `ModelPricing` with optional `cache_read_per_token: float | None` and `cache_write_per_token: float | None` (both `None` = "not tracked, bill at `input_per_token`" — an explicit, documented approximation, not a silent fallback), extend `CostEntry`/`CostTracker.record()` to accept optional `cache_read_tokens: int = 0` / `cache_write_tokens: int = 0`, and update the five call sites to pass `usage.cache_read_tokens` / `usage.cache_write_tokens` (confirm PydanticAI's exact `Usage`/`RunUsage` attribute names for your installed `pydantic-ai==1.63.0` before wiring — attribute names have moved between PydanticAI minor versions). Add the real per-token cache rates to the `anthropic:` and `foundry:` pricing entries once wired. While in there, add the same two counts to the trace payload in `tracing.py:52-56`, which today records only `input_tokens`/`output_tokens`/`total_tokens` — without it there is no per-call evidence of whether the cache was hit, which is the observability WP-G step 3 has to fall back on inferring from cost.
- **Option 2 (defer):** Ship WP-A through WP-D/WP-E-Part-1 now, file this as a follow-up plan. Caching still reduces *actual* Anthropic/Azure invoice cost immediately; only SCAR's own internal cost *report* stays imprecise (over-counts) until fixed.

**Do not silently do neither and claim caching "reduces cost" in the final report without caveat** — that would overstate what was actually delivered. If you pick Option 2, say so explicitly in the WP-E commit message.

---

### WP-F: `health-check` wiring

**File:** `src/security_review/cli/tools.py`

**Implementation steps:**

1. Extend the auth-presence tuple at `cli/tools.py:84` from `if provider in ("anthropic", "openai"):` to `if provider in ("anthropic", "openai", "foundry"):`. `resolve_api_key("foundry")` (WP-A) already raises a descriptive `ConfigurationError` on missing key, which this branch already catches and reports — no new branch needed, just widen the existing one.
2. Optionally (not required for correctness, but consistent with the `pricing:` check already present at `:70-80`), the `foundry_base_url` presence could also be surfaced here. If added, keep it a simple boolean presence check — do not attempt a live network call to the Foundry resource from `health-check` (that would violate the "no subprocess, presence checks only" comment already on this function at `:82`).

**Acceptance:** `scar.py health-check` with `provider_model: "foundry:claude-opus-5"` and no `AZURE_FOUNDRY_API_KEY` set shows a red `auth: foundry` line with the exact `ConfigurationError` message, not a crash.

---

### WP-G: Dependency verification and live smoke test

This is not optional and not skippable by reading the code — `anthropic==0.84.0` is one patch release past where `AsyncAnthropicFoundry` first shipped, and no unit test can substitute for one real call against your actual Foundry resource.

**Steps:**

1. Confirm the import surface exists at the currently pinned version:

   ```bash
   python -c "from anthropic import AsyncAnthropicFoundry; print('ok')"
   ```

2. Fetch the API key for the resource and wire the two settings. The resource and endpoint are already known (baseline table); only the key needs retrieving:

   ```bash
   az cognitiveservices account keys list -n gis-mission-control-resource \
     -g rg-secrch-mission-control-dev-001 --query key1 -o tsv
   ```

   Put it in `config/.env` as `AZURE_FOUNDRY_API_KEY=...` (never committed — confirm `config/.env` is gitignored before pasting a live key), and set `llm.foundry_base_url: "https://gis-mission-control-resource.services.ai.azure.com"` in `config/settings/security_review.yaml`. The base URL is non-secret and belongs in YAML; the factory appends `/anthropic` (WP-A step 4).
3. Run a single triage-only pass against a small target (`review.mode: "sast-triage"`) with `provider_model: "foundry:claude-<model>"`, `structured_output: "native"`, and `verification.enabled: false`, and confirm:
   - The run completes without a `ConfigurationError` or raw SDK exception.
   - `triage.json`'s audit log shows non-zero `tokens_in`/`tokens_out` and a `cost_usd` computed from the WP-E pricing entry (not zero, not a `ConfigurationError` about missing pricing).
   - With `cache_ttl: "ephemeral"` set, re-running the same target a second time in the same process shows a lower effective cost per call after the first (evidence the cache is actually being hit — Anthropic's API-level cache hit/miss isn't otherwise surfaced without WP-E2).
4. **Prove structured output specifically** — this is the step that resolves the §0.1 uncertainty about whether your deployment honours `output_config`. Run with `--debug` and confirm from the logs/audit trail that verdicts came back as validated `TriagedFinding` instances rather than through `output_parser.py`. Two failure signatures to watch for, and what each means:
   - A `400`/`invalid_request` mentioning `output_config`, `format`, or an unrecognised beta parameter → the deployment does not support structured outputs. Set `llm.structured_output: "prompted"` (WP-C2) to unblock, and note it against the resource; consider redeploying as "Hosted on Anthropic".
   - Repeated Pydantic validation retries followed by an empty/failed pass → `output_config` was accepted-but-ignored and the model replied in prose. Same remedy; this is the silent variant and the reason WP-C2's escape hatch is config rather than code.
5. Re-run step 3 with `structured_output: "prompted"` and confirm the run also succeeds. Both paths must work before WP-H, so that flipping the default never leaves you with a single untested route.
6. If step 1, 3, or 4 fails in a way that implicates the SDK version rather than this plan's code, bump `anthropic` (`pip install -U anthropic`) and retry before concluding the plan itself is broken.

**Acceptance:** One successful end-to-end triage run against a real Foundry resource under `structured_output: "native"` *and* one under `"prompted"`, both with a cost entry in `triage.json` attributable to `foundry:<model>`, and a recorded note of which hosting option the resource uses.

---

### WP-H: Flip the default (optional, do only after WP-G passes)

**File:** `config/settings/security_review.yaml`

Unlike mission-control's alias fan-out across dozens of agent configs, SCAR has exactly two settings to change:

```yaml
llm:
  provider_model: "foundry:claude-opus-5"
  triage_model: "foundry:claude-sonnet-5"
  foundry_base_url: "https://gis-mission-control-resource.services.ai.azure.com"
  structured_output: "auto"        # resolves to native for foundry: — see WP-C2
```

Also add a `providers.foundry:` capacity block (mirroring `providers.anthropic:` at `security_review.yaml:101-104`, since Foundry has its own independent rate limits from the direct Anthropic API):

```yaml
    foundry:
      max_concurrent: 10
      session_timeout: 120.0
      backoff_seconds: 5.0
```

`max_concurrent: 10` is the `anthropic:` value and is only a starting point — it must be reconciled with the deployment capacity chosen in WP-0 step 4, and this resource is **shared with `mission-control`**, which draws on the same quota. If the first scan spends its time in `model.retry` warnings, that is the deployment's tokens-per-minute ceiling, not a SCAR bug: lower this number or raise the deployment capacity.

**Do this only after WP-G's smoke test has passed against a real resource** — flipping the pipeline's default provider without a verified live call is exactly the kind of "opaque SDK error three batches into a real scan" that P6 (fail fast, fail loud) exists to prevent catching in production instead of in a smoke test.

**Acceptance:** A full-mode run (`review.mode: "full"`) completes end to end against a real target using `foundry:` as both `provider_model` and `triage_model`, with `pytest tests/unit/ -v` still green (no regression to the other four providers' code paths, which this plan does not modify).

---

## 3. Is native structured output actually more reliable?

Short answer: yes for output *integrity*, and SCAR already has the harness to prove it rather than assume it. But it is not free of risk, and the risks are concentrated in exactly the pass where SCAR's value lives (holistic). Both sides, honestly:

### 3.1 Why native is the better default

- **It deletes a layer whose failure mode is partial, and therefore invisible.** Be precise here, because the codebase is more mature than a naive version of this argument assumes: *total* parse failure is already handled well. `output_parser.py:204` returns a result carrying `review_notes` when a response is non-empty but unparseable, `holistic.py:489-491` turns that into `parse_failed=True` → retry → and ultimately a `check_failed` degradation ("NOT assessed"), and `degradation.py:22` has a first-class `parse_failed` kind. That path is not silent. The residual risk is the *partial* one: if the model emits five findings and only three match the expected `### SR-…` / `**CWE:**` shape, the parser returns three, `review_notes` stays `None`, `parse_failed` is `False`, and the run reports a successful check that quietly lost two findings with no degradation recorded. Native schema enforcement removes that window entirely — there is no partially-matched regex, only a validated object or a validation error. For a security scanner, that window is the whole argument.
- **Validation moves to the boundary.** With `output_type=TriagedFinding`, malformed output is a Pydantic validation error that PydanticAI retries (`llm.output_retries`, currently 3) and that ultimately surfaces as a failure. On the prompted path the same malformed output yields a *successful* run that parsed zero findings.
- **It reclaims prompt tokens and removes prompt/parser coupling.** The `TRIAGE_FORMAT_MARKDOWN` / `HOLISTIC_FORMAT_MARKDOWN` / `CONFIG_FORMAT_JSON` blocks stop being appended at all.
- **It is already the path for `anthropic:`/`openai:`**, so this is not new surface area — it is wider use of an existing one.

### 3.2 Why it still needs measuring, not assuming

- **PydanticAI forces `strict=True` in native mode** (`pydantic_ai/models/anthropic.py:376-384` — `strict=False` raises `UserError`). Strict schema-constrained decoding narrows what the schema may express, and unsupported JSON Schema keywords get transformed or dropped. SCAR's models carry constraints that matter (`TriagedFinding.confidence` bounded `0.0-1.0`, `files_reviewed` with `min_length=1`, enum-typed `verdict`/`severity`) — confirm they survive the transform on a real call, not just in `model_json_schema()`.
- **Extended thinking interacts with output mode.** `pydantic_ai/models/anthropic.py:358-374` raises `UserError` for thinking + output tools with `tool_choice=required`, and auto-promotes `output_mode` to `native` when thinking is enabled. SCAR exposes `llm.thinking_budget`, so if you ever enable it together with structured output, that interaction is live. Test the combination you intend to run.
- **Rigid output shapes can cost analytic depth on open-ended tasks.** The holistic pass asks a deliberately open question ("find authZ/IDOR/deserialization flaws across these files"); a schema that demands a fixed per-finding structure can push a model toward filling the shape rather than reasoning. This is the one claim in this section nobody should take on faith in either direction.
- **The measurement already exists.** `tests/regression/` compares live CWE detection against `config/golden/example-target.yaml` (11 CWEs × provider, PASS→FAIL = regression, FAIL→PASS = improvement). WP-C2's `llm.structured_output` key turns native-vs-prompted into a one-key A/B on that harness, per AGENTS.md's documented workflow:

  ```bash
  pytest tests/regression/ -v --provider foundry:claude-opus      # with structured_output: "native"
  pytest tests/regression/ -v --provider foundry:claude-opus      # re-run with structured_output: "prompted"
  ```

  Compare detection counts before making `native` the standing default for the holistic pass. Note these are real LLM calls with real cost.

**Recommendation:** keep `structured_output: "auto"` (which gives Foundry native output automatically), and treat §3.2's holistic-depth question as a measured follow-up rather than a blocker — the integrity argument in §3.1 is strong enough to justify native as the default for triage/verify/config-review regardless.

---

## 4. Tests to add

**File:** `tests/unit/test_providers.py` (extend the existing file — do not create a new one)

Following the existing style in this file exactly:

```python
def test_resolve_foundry_canonical_id_passes_through():
    # Foundry deployment names are canonical IDs already — providers.foundry is {} (WP-D).
    assert resolve_model_name("foundry", "claude-opus-5") == "claude-opus-5"


def test_existing_provider_aliases_unchanged_by_foundry_entry():
    # Guard against WP-D regressing the 4.6 generation for the other providers.
    assert resolve_model_name("anthropic", "claude-opus") == "claude-opus-4-6"
    assert resolve_model_name("copilot", "claude-opus") == "claude-opus-4.6"


def test_build_model_foundry_missing_base_url_raises():
    cfg = load_config(None)
    cfg.llm.provider_model = "foundry:claude-opus-5"
    cfg.llm.foundry_base_url = None
    with pytest.raises(ConfigurationError) as exc_info:
        build_model("foundry:claude-opus-5", llm_config=cfg.llm)
    assert "foundry_base_url" in str(exc_info.value)
```

**File:** a `model_settings`-focused test (no existing file for this module today — add `tests/unit/test_model_settings.py`, matching the convention that one source module gets one test module):

```python
def test_build_model_settings_applies_caching_to_foundry():
    cfg = LLMConfig(provider_model="foundry:claude-opus-5", cache_ttl="ephemeral", ...)
    settings = build_model_settings("foundry:claude-sonnet-5", cfg)
    assert settings.get("anthropic_cache") is True
```

**File:** `tests/unit/test_model_capabilities.py` (check whether one exists before creating it) — covering WP-C2's policy function. These need no network: construct the model with a dummy key, exactly as this plan's own verification did.

```python
def _foundry_model():
    from anthropic import AsyncAnthropicFoundry
    from pydantic_ai.models.anthropic import AnthropicModel
    from pydantic_ai.providers.anthropic import AnthropicProvider
    client = AsyncAnthropicFoundry(api_key="dummy", base_url="https://x.services.ai.azure.com/anthropic")
    return AnthropicModel("claude-opus-4-6", provider=AnthropicProvider(anthropic_client=client))


def test_foundry_model_supports_native_json_under_auto():
    cfg = load_config(None).llm          # structured_output: "auto"
    assert supports_native_json(_foundry_model(), cfg) is True


def test_prompted_mode_overrides_capable_model():
    cfg = load_config(None).llm
    cfg.structured_output = "prompted"
    assert supports_native_json(_foundry_model(), cfg) is False


def test_native_mode_on_incapable_provider_raises():
    from security_review.copilot_model import CopilotModel
    cfg = load_config(None).llm
    cfg.structured_output = "native"
    with pytest.raises(ConfigurationError):
        supports_native_json(CopilotModel(model_id="claude-opus-4.6", session_timeout=300.0, backoff_seconds=10.0), cfg)
```

These are the first tests this function has ever had — it currently has none, despite gating output handling for every pass. WP-C2 is therefore closing a pre-existing coverage gap as well as adding the config switch.

Also assert the capability flag survives the wrapper chain, since that is the single assumption the whole "foundry gets structured output for free" claim rests on and it is invisible in any individual file:

```python
def test_native_json_capability_survives_wrapper_chain():
    """RetryingModel/ConcurrencyLimitedModel must proxy .profile — if a future
    wrapper stops doing so, foundry/anthropic silently fall back to prompted."""
    model = build_model("foundry:claude-opus-5", llm_config=cfg)   # needs AZURE_FOUNDRY_API_KEY-shaped env, no network
    assert supports_native_json(model) is True
```

**File:** `tests/unit/test_health_check.py` if one exists (check before assuming — grep for `cli/tools.py` test coverage; if none exists, this plan does not introduce one, since `health-check` currently has no dedicated test file and adding one is out of scope creep beyond a single new provider).

Run `pytest tests/unit/ -v` after each WP, not just at the end — per the user's standing instruction, do not move to the next work package before the current one's tests pass.

---

## 5. Dependency graph and execution order

```
WP-0  (Azure deployment)  ─── Azure-side, blocks D/E1/G. Start it first because it may
                              need someone else's permissions and marketplace terms
WP-A  (secrets/schema)    ─── code work can proceed in parallel with WP-0
WP-B  (build_model)       ─── depends on WP-A
WP-C  (caching)           ─── independent of WP-B, can run in parallel with it
WP-C2 (output mode config)─── depends on WP-A (adds an LLMConfig field); independent of B/C
WP-C4 (pydantic-ai bump)  ─── independent of all other WPs and of WP-0's policy blocker;
                              gates whether structured output actually engages for Opus 5,
                              so do it early — its A/B runs on copilot:/claude: today
WP-C3 (holistic parse fix)─── independent of everything else; fixes a bug WP-H would
                              otherwise activate. Its test fails on current main, so it
                              can be written and merged ahead of the rest if convenient
WP-D  (models.yaml)       ─── independent, but WP-B's smoke test needs it
WP-E1 (pricing)           ─── depends on WP-D (needs resolved wire IDs)
WP-E2 (cache cost)        ─── independent decision point; can be deferred (see WP-E)
WP-F  (health-check)      ─── depends on WP-A
WP-G  (smoke test)        ─── depends on WP-A through WP-F (E1); WP-C2 is what makes
                              its native/prompted comparison a config flip, not a patch
WP-H  (flip default)      ─── depends on WP-G passing; do not skip ahead to this
```

Recommended order: **raise the WP-0 policy request today** (it is an external dependency on another team, and WP-D/E1/G/H are all blocked behind it), then proceed with everything that does not need Azure: C3 → C4 → A → B → C → C2 → F. When the policy clears: WP-0 → D → E1 → G → decide on E2 → H.

The plan is deliberately partitioned this way because the Azure blocker is not on the critical path for any of the code. C3 (a correctness fix) and C4 (the SDK bump, whose A/B runs against `copilot:`/`claude:`) both stand alone and both need to land before the native path is exercised for real.

---

## 6. Risk assessment

| WP | Risk | Mitigation |
|---|---|---|
| A | Low — additive config fields, `extra="forbid"` catches typos | Unit test per new field |
| B | Low — mirrors the existing `anthropic:` branch almost exactly | Smoke test in WP-G before relying on it |
| C | Very low — one-line condition widen | Existing anthropic caching tests (if any) plus new foundry-specific one |
| C2 | Medium — touches all four passes and changes a public signature, and a wrong decision here silently changes how every finding is extracted for every provider | `auto` reproduces today's behaviour exactly, so the default path is a no-op by construction; the signature change makes every call site a compile-time-obvious edit rather than an optional one; unit tests cover all three modes × capable/incapable providers, where there were previously none |
| C3 | Low to implement, high value — a three-line condition change with a test that fails on current `main` | Verified against `output_parser.py:204` and `models/findings.py:214` that `review_notes` is a parser-only sentinel; verified the other three passes use `isinstance` and are unaffected |
| — | **Profile says native, endpoint does not support it.** `supports_native_json()` reads a model-name profile, never the Foundry endpoint, so an Azure-hosted deployment can be mis-detected. Ignored-`output_config` is the nasty variant: prose reply → validation retries → a pass that reports nothing rather than failing. *Downgraded from "highest-consequence" now that `hostedOn` is readable from the catalogue up front (§1) — it is a choice at deploy time rather than a discovery at run time* | Deploy version 1 (§1, WP-0 step 2); WP-G step 4 forces any residual mismatch to surface before WP-H; WP-C2 gives a config-only escape hatch so the remedy needs no code change mid-incident |
| 0 | **Highest risk in the plan, and it is not technical: the deployment is blocked by a management-group Azure Policy we cannot read or change.** If governance declines to approve the Anthropic publisher, the entire plan is unshippable regardless of code quality | Raise it first, before any code work; cite the DeepSeek/MoonshotAI precedent on the same resource; the code WPs are partitioned to be useful independently, and `anthropic:` remains the working per-token fallback if the answer is no |
| C4 | Medium — an SDK bump is the one change in this plan that can regress detection quality across *all* providers, and this repo has a documented precedent for exactly that | Mandatory A/B via `scripts/benchmark_cwes.py` plus the golden regression baseline before adopting; pick the earliest version that fixes the profile, not latest; documented profile-override fallback if no version is clean |
| D | Low, now that the catalogue has been read — deployment names are known-good if WP-0 step 3 is followed, and the generation mismatch (4.6 aliases vs. 5 deployments) is handled explicitly rather than by a rename map | Empty `providers.foundry: {}` plus explicit canonical IDs; the plan forbids the tempting `4.6 → 5` override that would misattribute cost |
| — | **Auto-upgrade silently removes structured outputs.** A Claude deployment left on `OnceNewDefaultVersionAvailable` can move v1 (`hostedOn=anthropic`) → v2 (`hostedOn=azure`) with no action on your side, disabling the `output_config` beta mid-life. The symptom would appear as validation retries or a mysterious 400 weeks after a working deployment | WP-0 step 5 disables auto-upgrade; record model+version in resource tags; WP-C2's `structured_output: "prompted"` is the immediate mitigation if it ever does happen |
| E1 | Low — same shape as five existing pricing entries | `pricing_entry_exists()` check already fails fast on a missing key |
| E2 | Medium — touches five call sites and a schema shared by all providers, not just Foundry | Scope explicitly as its own commit; do not fold into the same commit as A-D; can be deferred outright per the plan text |
| F | Low | One-line tuple extension |
| G | High if skipped — this is the only step that proves any of the above actually works against a real Azure resource | Do not proceed to H without it |
| H | Medium — changes the pipeline's default for every future run | Gate strictly behind WP-G; keep `anthropic:`/`claude:` as documented fallback provider strings in case Foundry has an outage |
