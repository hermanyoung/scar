"""Tests for per-handler console log level (Plan 018 WP6)."""
from __future__ import annotations

import logging

from security_review.logging import setup_logging


def test_console_handler_level_independent_of_root_level():
    setup_logging(
        level="INFO", enable_console=True, console_level="WARNING",
        enable_file_logging=False,
    )
    root_logger = logging.getLogger()
    stream_handlers = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)]

    assert len(stream_handlers) == 1
    assert stream_handlers[0].level == logging.WARNING
    assert root_logger.level == logging.INFO


def test_console_handler_level_defaults_to_root_when_unset():
    setup_logging(
        level="DEBUG", enable_console=True, console_level=None,
        enable_file_logging=False,
    )
    root_logger = logging.getLogger()
    stream_handlers = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)]

    assert len(stream_handlers) == 1
    assert stream_handlers[0].level == logging.NOTSET  # inherits root's effective level
    assert root_logger.level == logging.DEBUG
