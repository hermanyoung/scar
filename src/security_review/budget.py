"""Cost tracking and budget guard for LLM calls across the pipeline.

PydanticAI's UsageLimits handles per-call token limits.
CostTracker handles cumulative USD budget across all batches.
"""
from __future__ import annotations

import structlog
import yaml
from pydantic import BaseModel, Field

from security_review import MODULE_ROOT
from security_review.errors import ConfigurationError
from security_review.providers import resolve_model_name

logger = structlog.get_logger(__name__)


class ModelPricing(BaseModel):
    input_per_token: float
    output_per_token: float


class CostEntry(BaseModel):
    agent: str
    batch_id: str
    model_requested: str
    model_responded: str
    tokens_in: int = Field(ge=0)
    tokens_out: int = Field(ge=0)
    cost_usd: float = Field(ge=0.0)
    cumulative_usd: float = Field(ge=0.0)


class CostTracker:
    """Tracks cumulative LLM cost across all agent calls in a pipeline run."""

    def __init__(self, pricing: dict[str, ModelPricing] | None = None):
        if pricing is None:
            pricing = _load_pricing()
        self._pricing = pricing
        self._calls: list[CostEntry] = []

    def record(
        self,
        agent_name: str,
        batch_id: str,
        model_requested: str,
        tokens_in: int,
        tokens_out: int,
    ) -> CostEntry:
        """Record a single LLM call and compute its cost.

        Pricing is looked up by the *resolved* model string (alias expansion +
        provider-specific override, e.g. 'copilot:claude-opus' -> 'copilot:claude-opus-4.6'
        or 'anthropic:claude-opus' -> 'anthropic:claude-opus-4-6') so config/pricing.yaml
        keys match what providers.py actually dispatches to, not the raw --provider string.
        """
        resolved = _resolve_pricing_key(model_requested)
        pricing = self._pricing.get(resolved)
        if pricing is None:
            raise ConfigurationError(
                f"No pricing entry for model '{resolved}' (requested '{model_requested}') "
                f"in config/pricing.yaml. Add an explicit '{resolved}' entry.",
                code="SYS_CONFIG_INVALID",
            )

        cost = (
            tokens_in * pricing.input_per_token
            + tokens_out * pricing.output_per_token
        )

        entry = CostEntry(
            agent=agent_name,
            batch_id=batch_id,
            model_requested=model_requested,
            model_responded=resolved,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost,
            cumulative_usd=self.total_spent + cost,
        )
        self._calls.append(entry)
        logger.info(
            "budget.recorded",
            agent=agent_name,
            batch_id=batch_id,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=round(cost, 6),
            cumulative_usd=round(entry.cumulative_usd, 4),
        )
        return entry

    @property
    def total_spent(self) -> float:
        return sum(c.cost_usd for c in self._calls)

    def would_exceed_budget(self, max_budget_usd: float) -> bool:
        """Check if cumulative spend has reached the configured budget ceiling.

        Call this before each batch. If True, the pass should stop
        dispatching new batches and log a warning. 0 = unlimited.
        """
        if max_budget_usd <= 0:
            return False
        return self.total_spent >= max_budget_usd

    def to_audit_log(self) -> list[dict]:
        return [c.model_dump() for c in self._calls]

    def restore(self, entries: list[dict]) -> None:
        """Repopulate from a prior run's audit log (--resume).

        Replaces any recorded calls so total_spent — and therefore
        would_exceed_budget() — reflects the original run's spend.
        """
        self._calls = [CostEntry.model_validate(e) for e in entries]
        logger.info(
            "budget.restored",
            entries=len(self._calls),
            cumulative_usd=round(self.total_spent, 4),
        )


def pricing_entry_exists(model_string: str) -> bool:
    """True if the resolved form of provider:model has a pricing entry."""
    if not model_string.partition(":")[2]:
        return False
    return _resolve_pricing_key(model_string) in _load_pricing()


def _resolve_pricing_key(model_string: str) -> str:
    """Resolve a 'provider:model' string to its canonical pricing.yaml key.

    Shared by CostTracker.record() and pricing_entry_exists() so both look
    up pricing the same way build_model() actually dispatches models.
    """
    provider, _, name = model_string.partition(":")
    return f"{provider}:{resolve_model_name(provider, name)}"


def _load_pricing() -> dict[str, ModelPricing]:
    """Load pricing from config/pricing.yaml."""
    pricing_path = MODULE_ROOT / "config" / "pricing.yaml"
    if not pricing_path.exists():
        raise ConfigurationError(
            f"Pricing config not found: {pricing_path}",
            code="SYS_CONFIG_INVALID",
        )

    with open(pricing_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Pricing config is not a YAML mapping: {pricing_path}",
            code="SYS_CONFIG_INVALID",
        )

    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = ModelPricing(**value)
    return result
