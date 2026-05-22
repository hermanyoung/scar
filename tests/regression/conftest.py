"""Regression tests make real LLM calls — override the global ALLOW_MODEL_REQUESTS block."""
from __future__ import annotations

from pathlib import Path

import pytest

try:
    from pydantic_ai import models as pydantic_ai_models
    pydantic_ai_models.ALLOW_MODEL_REQUESTS = True
except ImportError:
    pass

DEFAULT_GOLDEN = Path(__file__).parent.parent.parent / "config" / "golden" / "example-target.yaml"
DEFAULT_TARGET = Path(__file__).parent.parent.parent.parent / "example-target"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--provider", default="", help="Provider to test (default: all in golden file)"
    )
    parser.addoption(
        "--target", default=str(DEFAULT_TARGET), help="Target repository path"
    )
    parser.addoption(
        "--golden-file", default=str(DEFAULT_GOLDEN), help="Path to golden YAML"
    )
    parser.addoption(
        "--save-golden", action="store_true", default=False,
        help="Update golden file with current results (after verified improvement)",
    )
