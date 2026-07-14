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


# -- verification section (Plan 020 Phase 1) ------------------------------------


def _load_from_dict(raw: dict, tmp_path: Path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return load_config(cfg_path)


def test_config_without_verification_section_raises(tmp_path: Path):
    raw = _shipped_config_dict()
    del raw["verification"]

    with pytest.raises(ConfigurationError) as exc_info:
        _load_from_dict(raw, tmp_path)
    assert "verification" in str(exc_info.value)


def test_config_with_verification_section_parses(tmp_path: Path):
    cfg = _load_from_dict(_shipped_config_dict(), tmp_path)
    assert cfg.verification.enabled is True
    assert cfg.verification.model is None
    assert cfg.verification.samples == 1
    assert cfg.verification.verify_holistic is True
    assert cfg.verification.verify_config_review is False


@pytest.mark.parametrize("samples", [0, 6])
def test_config_verification_samples_out_of_range_raises(tmp_path: Path, samples: int):
    raw = _shipped_config_dict()
    raw["verification"]["samples"] = samples

    with pytest.raises(ConfigurationError) as exc_info:
        _load_from_dict(raw, tmp_path)
    assert "samples" in str(exc_info.value)


def test_config_verification_model_bad_prefix_raises(tmp_path: Path):
    raw = _shipped_config_dict()
    raw["verification"]["model"] = "not-a-provider-model"

    with pytest.raises(ConfigurationError):
        _load_from_dict(raw, tmp_path)
