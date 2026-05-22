"""CLI commands: health-check, list-rules, test-rule — SAST tool management."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import click

from security_review.cli import PROJECT_ROOT, _setup_logging, cli


@cli.command("health-check")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def health_check(verbose, debug):
    """Check that all required external tools are installed."""
    _setup_logging(verbose, debug, quiet=not verbose and not debug,
                   json_logs=False, no_file_log=True)

    from security_review.tools.registry import load_tool_specs

    specs = load_tool_specs()
    all_ok = True

    click.echo("\nSCAR — Tool Check\n")

    for spec in specs:
        binary_path = shutil.which(spec.binary)
        if binary_path:
            click.echo(click.style(f"  [+] {spec.name:<20}", fg="green") +
                       f"binary={spec.binary:<20} ok")
        elif spec.optional:
            click.echo(click.style(f"  [?] {spec.name:<20}", fg="yellow") +
                       f"binary={spec.binary:<20} optional (not found)")
        else:
            click.echo(click.style(f"  [!] {spec.name:<20}", fg="red") +
                       f"binary={spec.binary:<20} MISSING")
            all_ok = False

    click.echo()
    if all_ok:
        click.echo(click.style("All required tools found.", fg="green"))
    else:
        click.echo(click.style("Some required tools are missing.", fg="red"))
        raise SystemExit(1)


@cli.command("list-rules")
@click.option("--language", default=None,
              type=click.Choice(["python", "csharp"]),
              help="Filter by language.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def list_rules(language, verbose, debug):
    """List configured SAST rules and CWE mappings."""
    _setup_logging(verbose, debug, quiet=not verbose and not debug,
                   json_logs=False, no_file_log=True)

    from security_review.tools.registry import load_tool_specs

    specs = load_tool_specs()
    for spec in specs:
        if language:
            if language == "python" and "*.py" not in spec.applies_to:
                continue
            if language == "csharp" and not any(
                p in spec.applies_to for p in ["*.cs", "*.csproj", "*.sln"]
            ):
                continue

        click.echo(f"\n{spec.name}:")
        click.echo(f"  Binary:      {spec.binary}")
        click.echo(f"  Applies to:  {', '.join(spec.applies_to) or 'all files'}")
        click.echo(f"  SARIF native: {spec.sarif_native}")
        click.echo(f"  CWE source:  {spec.cwe_source}")


@cli.command("test-rule")
@click.option("--cwe", required=True, help="CWE number (e.g. 532 or CWE-532).")
@click.option("--target", required=True, type=click.Path(exists=True),
              help="Path to codebase root.")
@click.option("--language", default=None,
              type=click.Choice(["python", "csharp"]),
              help="Limit to one language's rules.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def test_rule(cwe, target, language, verbose, debug):
    """Run OpenGrep rules for a single CWE against a target."""
    _setup_logging(verbose, debug, quiet=False, json_logs=False, no_file_log=True)

    cwe_num = cwe.replace("CWE-", "").replace("cwe-", "").lstrip("0")
    rules_root = PROJECT_ROOT / "config" / "rules" / "opengrep"
    target_path = Path(target).resolve()

    if not target_path.exists():
        click.echo(f"Target not found: {target_path}", err=True)
        raise SystemExit(1)

    padded = cwe_num.zfill(3)
    matches = sorted(set(rules_root.rglob(f"cwe-{cwe_num}*")) | set(rules_root.rglob(f"cwe-{padded}*")))
    rule_dirs = [m for m in matches if m.is_dir()]

    if language:
        rule_dirs = [d for d in rule_dirs if f"/{language}/" in str(d) or f"\\{language}\\" in str(d)]

    if not rule_dirs:
        click.echo(f"No rules found for CWE-{cwe_num}" + (f" ({language})" if language else ""), err=True)
        raise SystemExit(1)

    click.echo(f"Running {len(rule_dirs)} rule set(s) for CWE-{cwe_num} against {target_path.name}/\n")
    for d in rule_dirs:
        rel = d.relative_to(rules_root)
        click.echo(f"  {rel}/")

    cmd = ["opengrep", "scan"]
    for d in rule_dirs:
        cmd.extend(["--config", str(d)])
    cmd.append(str(target_path))

    click.echo()
    result = subprocess.run(cmd)
    raise SystemExit(result.returncode)
