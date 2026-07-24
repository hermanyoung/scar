"""Pre-flight validation for LLM modes: pricing keys + provider auth probe.

Called by the CLI (NOT by passes/pipeline.py — P6 keeps the pipeline free
of pydantic_ai imports) before Pass 1, so an expired token or missing
pricing entry fails in seconds, not after the SAST wall-clock.
"""
from __future__ import annotations

import structlog
from pydantic_ai import Agent, UsageLimits

from security_review.budget import CostTracker, pricing_entry_exists
from security_review.config_schema import SecurityReviewConfig
from security_review.errors import ConfigurationError, LLMError
from security_review.providers import build_model

logger = structlog.get_logger(__name__)


def validate_pricing(config: SecurityReviewConfig) -> None:
    """Fail fast if any configured model lacks a pricing entry."""
    models = {config.llm.provider_model}
    if config.llm.triage_model:
        models.add(config.llm.triage_model)
    if config.verification.model:
        models.add(config.verification.model)
    missing = sorted(m for m in models if not pricing_entry_exists(m))
    if missing:
        raise ConfigurationError(
            f"No pricing entry for {', '.join(missing)} in config/pricing.yaml. "
            f"Add entries for the resolved model ID(s) before running LLM passes.",
            code="SYS_CONFIG_INVALID",
        )


async def probe_provider(config: SecurityReviewConfig, cost_tracker: CostTracker) -> None:
    """One minimal LLM request to prove auth + reachability. Raises LLMError on failure."""
    model_string = config.llm.provider_model
    model = build_model(model_string, llm_config=config.llm)
    agent = Agent(system_prompt="Reply with the single word OK.", output_type=str)
    try:
        result = await agent.run(
            "ping", model=model,
            usage_limits=UsageLimits(request_limit=1, total_tokens_limit=2_000),
        )
    except Exception as e:
        logger.error("preflight.failed", model=model_string,
                     error=str(e), error_type=type(e).__name__)
        raise LLMError(
            f"Provider preflight failed for '{model_string}': {e}. "
            f"Check auth before re-running (copilot: 'gh auth status'; "
            f"anthropic/openai: API key in config/.env; claude: 'claude setup-token').",
            code="LLM_AUTH_FAILED",
        ) from e
    usage = result.usage()
    cost_tracker.record(
        agent_name="preflight", batch_id="preflight-000",
        model_requested=model_string,
        tokens_in=usage.input_tokens or 0, tokens_out=usage.output_tokens or 0,
    )
    logger.info("preflight.ok", model=model_string)
