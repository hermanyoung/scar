"""Typed configuration schemas for the security review module.

All config is validated with extra="forbid" to catch typos in YAML.

The YAML file (config/settings/security_review.yaml) is the single source of
truth. These schemas validate it — they do NOT provide silent defaults.
Fields without defaults MUST be present in the YAML or Pydantic will reject
the config at startup (fail fast).
"""
from pydantic import BaseModel, Field, model_validator

from security_review.errors import ConfigurationError


class ProviderConfig(BaseModel, extra="forbid"):
    """Per-provider capacity and timeout settings."""

    max_concurrent: int = Field(ge=1, le=100, description="Max concurrent requests to this provider")
    session_timeout: float = Field(ge=10.0, le=600.0, description="Seconds to wait for a single response")
    backoff_seconds: float = Field(ge=1.0, le=60.0, description="Wait time before retry on timeout")


class LLMConfig(BaseModel, extra="forbid"):
    provider_model: str = Field(
        pattern=r"^(openai|anthropic|copilot|codex|claude|foundry):.+$",
        description="Provider-prefixed model string",
    )
    triage_model: str | None = Field(
        default=None,
        pattern=r"^(openai|anthropic|copilot|codex|claude|foundry):.+$",
        description="Override model for Pass 3 triage. Falls back to provider_model.",
    )
    output_retries: int = Field(default=3, ge=1, le=5)
    max_budget_usd: float = Field(ge=0.0, le=1000.0, description="0 = unlimited")
    max_tokens_per_batch: int = Field(default=150_000, ge=10_000, le=500_000)
    concurrency: int = Field(ge=1, le=50, description="Pass-level: how many agent calls dispatched concurrently")

    cache_ttl: str | None = Field(
        default=None,
        pattern=r"^(ephemeral|5m|1h)$",
        description="Anthropic prompt cache TTL. 'ephemeral' = request-scoped, '5m'/'1h' = time-based. null = disabled.",
    )

    thinking_budget: int | None = Field(
        default=None,
        ge=1000,
        le=100_000,
        description="Max thinking tokens for Anthropic extended reasoning. None = disabled.",
    )

    temperature: float | None = Field(
        default=None,
        ge=0.0,
        le=2.0,
        description="LLM sampling temperature. None = provider default. Set 0 for reproducible benchmark runs.",
    )

    foundry_base_url: str | None = Field(
        default=None,
        description="Azure OpenAI data-plane endpoint for the foundry: provider, "
                    "e.g. https://<account>.openai.azure.com/. Required by foundry: models.",
    )
    foundry_api_version: str | None = Field(
        default=None,
        description="Azure OpenAI API version, e.g. 2024-12-01-preview. Required by foundry: models.",
    )
    foundry_token_scope: str | None = Field(
        default=None,
        description="Entra ID token scope. Differs in sovereign clouds (US Gov, China), "
                    "so it is configured rather than assumed. Required by foundry: models.",
    )

    providers: dict[str, ProviderConfig] = Field(
        description="Provider-specific capacity and timeout settings",
    )

    def provider_config(self, provider: str) -> ProviderConfig:
        """Get config for a specific provider."""
        prov = self.providers.get(provider)
        if prov is None:
            raise ConfigurationError(
                f"No provider config for '{provider}'. "
                f"Add it to llm.providers in config/settings/security_review.yaml.",
                code="SYS_CONFIG_INVALID",
            )
        return prov


class SASTConfig(BaseModel, extra="forbid"):
    opengrep_rules_path: str
    gitleaks_config_path: str
    roslyn_props_path: str
    scanner_timeout_seconds: int = Field(ge=30, le=1800)
    scanner_max_file_size_bytes: int = Field(ge=1024)


class TriageConfig(BaseModel, extra="forbid"):
    fp_confidence_threshold: float = Field(ge=0.0, le=1.0)
    min_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Minimum priority score to triage. 0.20 = MODERATE+, 0.40 = ELEVATED+, 0.0 = triage everything.",
    )
    default_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence assigned when LLM response omits a confidence value.",
    )


class VerificationConfig(BaseModel, extra="forbid"):
    """Pass 6: independent adversarial verification of LLM-discovered findings."""

    enabled: bool
    model: str | None = Field(
        default=None,
        pattern=r"^(openai|anthropic|copilot|codex|claude|foundry):.+$",
        description="Override model for verification. null = use llm.provider_model.",
    )
    samples: int = Field(
        ge=1, le=5,
        description="Skeptic votes per finding. 1 = single; 3 = majority-refute.",
    )
    verify_holistic: bool
    verify_config_review: bool


class ReviewConfig(BaseModel, extra="forbid"):
    mode: str = Field(default="full", pattern=r"^(full|sast|sast-triage)$")
    target_path: str = Field(default=".")
    output_sarif: str
    output_summary: str = Field(default="security-report.md")
    output_triage: str = Field(default="triage.json")
    exclude: list[str] = Field(default_factory=list,
                               description="fnmatch globs (relative paths) to exclude from inventory")
    include: list[str] = Field(default_factory=list,
                               description="when non-empty, only matching relative paths are reviewed")


class FoundryConfig(BaseModel, extra="forbid"):
    """Azure AI Foundry resource coordinates for model enumeration.

    Holds no credentials — the az CLI session supplies auth. Every field is
    required so that `list-models --foundry` always names the exact resource it
    queries rather than inheriting whichever subscription happens to be active.
    """

    subscription_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        description="Azure subscription GUID owning the Foundry account.",
    )
    resource_group: str = Field(min_length=1)
    account_name: str = Field(min_length=1, description="Cognitive Services / AIServices account name.")
    location: str = Field(min_length=1, description="Azure region, e.g. swedencentral.")
    az_timeout_seconds: int = Field(
        ge=10, le=600,
        description="Per-call timeout for az CLI invocations.",
    )


class SecurityReviewConfig(BaseModel, extra="forbid"):
    llm: LLMConfig
    sast: SASTConfig
    triage: TriageConfig
    review: ReviewConfig
    verification: VerificationConfig
    foundry: FoundryConfig | None = Field(
        default=None,
        description="Optional. Required only by `list-models --foundry`.",
    )

    @model_validator(mode="after")
    def _foundry_models_need_endpoint(self) -> "SecurityReviewConfig":
        """Fail at load time, not mid-run, when a foundry: model has no endpoint.

        build_model() would otherwise raise on the first agent call — after
        inventory and SAST have already run and spent wall-clock time.
        """
        users = [
            name for name, value in (
                ("llm.provider_model", self.llm.provider_model),
                ("llm.triage_model", self.llm.triage_model),
                ("verification.model", self.verification.model),
            )
            if value and value.startswith("foundry:")
        ]
        if not users:
            return self

        missing = [
            key for key, value in (
                ("llm.foundry_base_url", self.llm.foundry_base_url),
                ("llm.foundry_api_version", self.llm.foundry_api_version),
                ("llm.foundry_token_scope", self.llm.foundry_token_scope),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"{', '.join(users)} use the foundry: provider but "
                f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set."
            )
        return self
