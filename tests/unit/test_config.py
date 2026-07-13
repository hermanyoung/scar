"""Tests for config loading and schema validation (Plan 019 WP-G / plan 002 §2.1 remainder)."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from security_review import MODULE_ROOT
from security_review.config import load_config
from security_review.errors import ConfigurationError


def _shipped_config_dict() -> dict:
    path = MODULE_ROOT / "config" / "settings" / "security_review.yaml"
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_load_config_missing_file_raises():
    with pytest.raises(ConfigurationError):
        load_config(Path("nonexistent.yaml"))


def test_load_config_missing_required_key_names_the_field(tmp_path: Path):
    raw = _shipped_config_dict()
    del raw["llm"]["provider_model"]
    cfg_path = tmp_path / "broken.yaml"
    cfg_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(cfg_path)
    assert "provider_model" in str(exc_info.value)


def test_load_config_unknown_key_rejected(tmp_path: Path):
    raw = _shipped_config_dict()
    raw["llm"]["tempratura"] = 0.7  # typo'd key must be caught by extra="forbid"
    cfg_path = tmp_path / "typo.yaml"
    cfg_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(cfg_path)
    assert "tempratura" in str(exc_info.value)
