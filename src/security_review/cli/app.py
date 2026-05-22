"""Click CLI group and shared tree display for SCAR.

The `cli` group is defined here (not in __init__.py) to satisfy rule 001.3
(no logic in __init__.py). Command modules import `cli` from here.
"""
from __future__ import annotations

import click


@click.group(invoke_without_command=True)
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
