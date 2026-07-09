"""Click CLI group and shared infrastructure for SCAR command modules.

The `cli` group, `PROJECT_ROOT`, and `_setup_logging` are defined here (not
in __init__.py) to satisfy rule 001.3 (no logic in __init__.py) AND to avoid
a circular import: command modules (review.py, tools.py, etc.) import from
this module directly. None of them — and this module itself — ever import
from `security_review.cli` (the package `__init__.py`), which is the
aggregator that imports the command modules for registration. If a command
module imported back from `security_review.cli`, that would be a real
circular import relying on Python's partially-initialized-module import
order rather than a genuine one-directional dependency.
"""
from __future__ import annotations

import click

from security_review import MODULE_ROOT, __version__

# Re-exported for command modules that need the repo root (test-rule
# subprocess, reports dir, eval corpus path, etc.)
PROJECT_ROOT = MODULE_ROOT


def _setup_logging(verbose: bool, debug: bool, quiet: bool,
                   json_logs: bool, no_file_log: bool) -> dict:
    """Configure logging and return context dict for progress callbacks.

    The console handler is always enabled — only its *level* changes with
    verbosity — so logger.warning/error (budget exhaustion, missing tools,
    failed checks) reach stderr by default instead of being file-only.
    --quiet delivers on its "Errors only" promise instead of showing nothing;
    the file audit trail stays at INFO regardless of console verbosity.

    | flags               | root & file level | console level |
    |---------------------|--------------------|---------------|
    | (default)           | INFO               | WARNING       |
    | -v / --json-logs    | INFO               | INFO          |
    | --debug             | DEBUG              | DEBUG         |
    | --quiet             | INFO               | ERROR         |
    """
    if debug:
        level, console_level = "DEBUG", "DEBUG"
    elif quiet:
        level, console_level = "INFO", "ERROR"
    elif verbose or json_logs:
        level, console_level = "INFO", "INFO"
    else:
        level, console_level = "INFO", "WARNING"

    from security_review.logging import setup_logging
    setup_logging(
        level=level,
        format_type="json" if json_logs else "console",
        enable_console=True,
        enable_file_logging=not no_file_log,
        console_level=console_level,
    )

    return {"verbose": verbose, "debug": debug, "quiet": quiet}


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="scar")
@click.pass_context
def cli(ctx):
    """SCAR — Security Code AI Review."""
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        _show_tree()


def _show_tree():
    """Show all commands, options, and quick-start examples as a Rich tree."""
    from rich.console import Console
    from rich.tree import Tree

    console = Console()

    root = Tree("[bold cyan]scar[/bold cyan]  [dim]Security Code AI Review[/dim]")

    def _build(group: click.Group, node: Tree) -> None:
        for name in sorted(group.commands):
            cmd = group.commands[name]
            short_help = cmd.help.split("\n")[0] if cmd.help else ""
            label = f"[cyan]{name}[/cyan]  [dim]{short_help}[/dim]"
            child = node.add(label)

            if hasattr(cmd, "params"):
                for param in cmd.params:
                    if isinstance(param, click.Option):
                        opts = "/".join(param.opts)
                        type_str = ""
                        if param.type and param.type.name not in ("BOOL", "BOOL_FLAG", ""):
                            type_str = f" [dim]{param.type.name}[/dim]"
                        default = ""
                        if param.default is not None and param.default != () and not param.is_flag:
                            default = f" [dim](default: {param.default})[/dim]"
                        help_str = f"  [dim]{param.help}[/dim]" if param.help else ""
                        child.add(f"[yellow]{opts}[/yellow]{type_str}{default}{help_str}")

    _build(cli, root)

    console.print()
    console.print(root)

    examples = Tree("[bold]Quick Start[/bold]")
    examples.add("[dim]python scar.py[/dim] [cyan]health-check[/cyan]                                  [dim]Check tool availability[/dim]")
    examples.add("[dim]python scar.py[/dim] [cyan]review[/cyan] --target /path/to/code                 [dim]Full review (default provider)[/dim]")
    examples.add("[dim]python scar.py[/dim] [cyan]review[/cyan] --target . --mode sast                 [dim]SAST only, no LLM[/dim]")
    examples.add("[dim]python scar.py[/dim] [cyan]review[/cyan] --target . --provider copilot:claude-opus   [dim]Full review with Opus[/dim]")
    examples.add("[dim]python scar.py[/dim] [cyan]review[/cyan] --target . --mode sast-triage -v        [dim]SAST + triage, verbose[/dim]")
    examples.add("[dim]python scar.py[/dim] [cyan]test-rule[/cyan] --cwe 89 --target ../my-app/              [dim]Test CWE-89 rules against a target[/dim]")
    examples.add("[dim]python scar.py[/dim] [cyan]test-providers[/cyan] --copilot                       [dim]Test all Copilot models[/dim]")

    console.print()
    console.print(examples)
    console.print()


@cli.command()
def tree():
    """Show all commands and options in a tree structure."""
    _show_tree()
