"""Structured logging configuration for the security review pipeline.

All modules use structlog. Configuration is loaded from config/settings/logging.yaml.

Structured fields in every JSON log record:
    timestamp   - ISO 8601 UTC timestamp
    level       - Log level (debug, info, warning, error, critical)
    logger      - Module path (e.g. security_review.passes.sast)
    event       - Log message
    func_name   - Function that emitted the log
    lineno      - Line number in source file
    run_id      - Pipeline run correlation ID (when bound via contextvars)

Console output uses human-readable format by default. File output is always JSONL.
File handler rotates daily at local midnight with 14-day retention.

Usage:
    from security_review.logging import setup_logging, get_logger

    setup_logging()                          # Load from logging.yaml
    setup_logging(level="DEBUG")             # Override level
    setup_logging(enable_file_logging=False)  # Disable file output

    logger = get_logger(__name__)
    logger.info("tool.started", tool_name="bandit", target="src/")
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any

import structlog
import yaml
from structlog.typing import Processor

from security_review import MODULE_ROOT

_logging_config: dict[str, Any] | None = None


def _load_logging_config() -> dict[str, Any]:
    """Load logging configuration from config/settings/logging.yaml."""
    global _logging_config
    if _logging_config is not None:
        return _logging_config

    config_path = MODULE_ROOT / "config" / "settings" / "logging.yaml"
    if not config_path.exists():
        raise FileNotFoundError(
            f"Logging configuration not found: {config_path}. "
            f"Ensure config/settings/logging.yaml exists."
        )

    with open(config_path, encoding="utf-8") as f:
        _logging_config = yaml.safe_load(f) or {}

    return _logging_config


def _resolve_log_path(configured_path: str) -> Path:
    """Resolve log file path relative to project root."""
    return MODULE_ROOT / configured_path


def setup_logging(
    level: str | None = None,
    format_type: str | None = None,
    enable_console: bool | None = None,
    enable_file_logging: bool | None = None,
) -> None:
    """Configure structured logging for the pipeline.

    Configuration is loaded from config/settings/logging.yaml.
    Parameters override the YAML configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Overrides config.
        format_type: Output format ('json' or 'console'). Overrides config.
        enable_console: Whether to enable console output. Overrides config.
        enable_file_logging: Whether to write to JSONL file. Overrides config.
    """
    config = _load_logging_config()

    effective_level = level if level is not None else config.get("level", "INFO")
    effective_format = format_type if format_type is not None else config.get("format", "json")

    handlers_config = config.get("handlers", {})
    console_config = handlers_config.get("console", {})
    file_config = handlers_config.get("file", {})

    effective_console_enabled = (
        enable_console if enable_console is not None
        else console_config.get("enabled", True)
    )
    effective_file_enabled = (
        enable_file_logging if enable_file_logging is not None
        else file_config.get("enabled", True)
    )

    log_level = getattr(logging, effective_level.upper())

    # Shared processors — used by both structlog and stdlib formatter
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.CallsiteParameterAdder(
            parameters=[
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            ],
        ),
    ]

    json_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )

    # Configure structlog to wrap stdlib logging
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Build console formatter based on format preference
    if effective_format == "console":
        console_formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(),
            foreign_pre_chain=shared_processors,
        )
    else:
        console_formatter = json_formatter

    # Configure root stdlib logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any existing handlers (safe to call multiple times)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler — stderr so it doesn't interfere with SARIF stdout
    if effective_console_enabled:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handler — JSONL with daily rotation
    if effective_file_enabled:
        log_path = _resolve_log_path(file_config.get("path", "var/logs/system.jsonl"))
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = TimedRotatingFileHandler(
            filename=str(log_path),
            when=file_config.get("rotation_when", "midnight"),
            interval=file_config.get("rotation_interval", 1),
            backupCount=file_config.get("backup_count", 14),
            encoding="utf-8",
        )
        file_handler.setFormatter(json_formatter)
        root_logger.addHandler(file_handler)

    # Quieten noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)


def get_logger(name: str) -> Any:
    """Get a structlog logger instance.

    Args:
        name: Logger name, typically __name__
    """
    return structlog.get_logger(name)
