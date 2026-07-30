"""SCAR CLI — Click command group aggregator.

Commands register themselves by importing `cli` from `security_review.cli.app`
and decorating with @cli.command(). All command modules are imported below
to trigger registration.

This file only imports downward (app.py, then each command module) — it is
never imported back by app.py or any command module, so there is no
circular import. Command modules that need `cli`, `PROJECT_ROOT`, or
`_setup_logging` import them from `security_review.cli.app` directly, not
from this package `__init__.py`.
"""
from __future__ import annotations

from security_review.cli.app import cli  # noqa: F401 — re-exported for `from security_review.cli import cli`

# Import command modules to trigger @cli.command() registration.
# Order does not matter — Click collects commands by name.
import security_review.cli.review  # noqa: F401, E402
import security_review.cli.tools  # noqa: F401, E402
import security_review.cli.reports  # noqa: F401, E402
import security_review.cli.test_cwe  # noqa: F401, E402
import security_review.cli.test_providers  # noqa: F401, E402
import security_review.cli.eval_cmd  # noqa: F401, E402
import security_review.cli.quality_cmd  # noqa: F401, E402
import security_review.cli.models_cmd  # noqa: F401, E402
