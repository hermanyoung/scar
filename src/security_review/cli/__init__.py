"""SCAR CLI — Click command group and shared utilities.

Commands register themselves by importing `cli` and decorating with @cli.command().
All command modules are imported at the bottom of this file to trigger registration.
"""
from __future__ import annotations

from security_review import MODULE_ROOT
from security_review.cli.app import cli  # noqa: F401 — re-exported for command modules

# Re-export for command modules that need it (test-rule subprocess, reports dir, etc.)
PROJECT_ROOT = MODULE_ROOT


def _setup_logging(verbose: bool, debug: bool, quiet: bool,
                   json_logs: bool, no_file_log: bool) -> dict:
    """Configure logging and return context dict for progress callbacks."""
    if debug:
        level = "DEBUG"
    elif quiet:
        level = "WARNING"
    else:
        level = "INFO"

    show_console_logs = verbose or debug or json_logs

    from security_review.logging import setup_logging
    setup_logging(
        level=level,
        format_type="json" if json_logs else "console",
        enable_console=show_console_logs,
        enable_file_logging=not no_file_log,
    )

    return {"verbose": verbose, "debug": debug, "quiet": quiet}


# Import command modules to trigger @cli.command() registration.
# Order does not matter — Click collects commands by name.
import security_review.cli.review  # noqa: F401, E402
import security_review.cli.tools  # noqa: F401, E402
import security_review.cli.reports  # noqa: F401, E402
import security_review.cli.test_cwe  # noqa: F401, E402
import security_review.cli.test_providers  # noqa: F401, E402
import security_review.cli.eval_cmd  # noqa: F401, E402
import security_review.cli.quality_cmd  # noqa: F401, E402
