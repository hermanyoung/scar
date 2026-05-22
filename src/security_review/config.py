"""Configuration loading: secrets via .env, settings via YAML."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings

from pydantic import ValidationError

from security_review import MODULE_ROOT
from security_review.config_schema import SecurityReviewConfig
from security_review.errors import ConfigurationError


class Settings(BaseSettings):
    """Secrets loaded from environment variables / .env file."""

    model_config = {
        "env_file": "config/.env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    openai_api_key: str = Field(default="", description="OpenAI API key")
    anthropic_api_key: str = Field(default="", description="Anthropic API key")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


_DEFAULT_CONFIG = MODULE_ROOT / "config" / "settings" / "security_review.yaml"


def load_config(config_path: Path | None = None) -> SecurityReviewConfig:
    """Load SecurityReviewConfig from YAML file.

    Auto-discovers config/settings/security_review.yaml when no path specified.
    Fails fast if the config file is missing or empty.
    """
    if config_path is None:
        config_path = _DEFAULT_CONFIG

    resolved = Path(config_path).resolve()
    if not resolved.exists():
        raise ConfigurationError(
            f"Configuration file not found: {resolved}",
            code="SYS_CONFIG_INVALID",
        )

    with open(resolved, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raise ConfigurationError(
            f"Configuration file is empty: {resolved}",
            code="SYS_CONFIG_INVALID",
        )

    try:
        return SecurityReviewConfig.model_validate(raw)
    except ValidationError as e:
        raise ConfigurationError(
            f"Invalid configuration in {resolved}: {e}",
            code="SYS_CONFIG_INVALID",
        ) from e
