"""Typed configuration schemas for the security review module.

All config is validated with extra="forbid" to catch typos in YAML.

The YAML file (config/settings/security_review.yaml) is the single source of
truth. These schemas validate it — they do NOT provide silent defaults.
Fields without defaults MUST be present in the YAML or Pydantic will reject
the config at startup (fail fast).
"""
from pydantic import BaseModel, Field

from security_review.errors import ConfigurationError


class ProviderConfig(BaseModel, extra="forbid"):
    """Per-provider capacity and timeout settings."""

    max_concurrent: int = Field(ge=1, le=100, description="Max concurrent requests to this provider")
    session_timeout: float = Field(ge=10.0, le=600.0, description="Seconds to wait for a single response")
    backoff_seconds: float = Field(ge=1.0, le=60.0, description="Wait time before retry on timeout")


class LLMConfig(BaseModel, extra="forbid"):
    provider_model: str = Field(
        pattern=r"^(openai|anthropic|copilot|codex|claude):.+$",
        description="Provider-prefixed model string",
    )
    triage_model: str | None = Field(
        default=None,
        pattern=r"^(openai|anthropic|copilot|codex|claude):.+$",
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


class ReviewConfig(BaseModel, extra="forbid"):
    mode: str = Field(default="full", pattern=r"^(full|sast|sast-triage)$")
    target_path: str = Field(default=".")
    output_sarif: str
    output_summary: str = Field(default="security-report.md")
    output_triage: str = Field(default="triage.json")


class SecurityReviewConfig(BaseModel, extra="forbid"):
    llm: LLMConfig
    sast: SASTConfig
    triage: TriageConfig
    review: ReviewConfig
