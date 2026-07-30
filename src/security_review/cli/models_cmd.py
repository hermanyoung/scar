"""CLI command: list-models — show the model registry, name resolution, and pricing.

Answers "what can I pass to --provider?" from config alone: config/models.yaml
(short aliases plus per-provider wire-ID overrides) joined with config/pricing.yaml.
Pure config inspection — no network calls, no LLM calls, no subprocesses.

A model is only usable if it has a pricing entry, because CostTracker.record()
raises on a missing one (budget.py). That is why rows without pricing are hidden
unless --all is passed: the default view is "what will actually run".
"""
from __future__ import annotations

import click

from security_review.cli.app import _setup_logging, cli


def _per_million(rate: float) -> str:
    """Render a per-token rate as USD per 1M tokens."""
    return f"${rate * 1_000_000:,.2f}"


def _collect_rows(provider_filter: str | None, show_all: bool) -> list[dict]:
    """Join aliases, provider overrides, and pricing into one row per model.

    Uses the same loaders and resolver as providers.py/budget.py rather than
    re-reading the YAML, so this command can never disagree with what
    build_model() and CostTracker actually resolve.
    """
    from security_review.budget import _load_pricing
    from security_review.errors import ConfigurationError
    from security_review.providers import _load_model_registry, resolve_model_name

    registry = _load_model_registry()
    aliases: dict = registry.get("aliases") or {}
    providers: dict = registry.get("providers") or {}
    pricing = _load_pricing()

    if provider_filter and provider_filter not in providers:
        raise ConfigurationError(
            f"Unknown provider '{provider_filter}'. "
            f"Known providers (config/models.yaml): {', '.join(sorted(providers))}.",
            code="SYS_CONFIG_INVALID",
        )

    rows: list[dict] = []
    for provider in sorted(providers):
        if provider_filter and provider != provider_filter:
            continue

        routed_keys: set[str] = set()
        for alias in sorted(aliases):
            wire = resolve_model_name(provider, alias)
            key = f"{provider}:{wire}"
            routed_keys.add(key)
            price = pricing.get(key)
            if price is None and not show_all:
                continue
            rows.append({
                "provider": provider,
                "alias": alias,
                "wire_id": wire,
                "key": key,
                "input_per_token": price.input_per_token if price else None,
                "output_per_token": price.output_per_token if price else None,
            })

        # Priced models no alias routes to — reachable only by naming the wire
        # ID in full (e.g. --provider openai:gpt-5.4-mini). Worth showing, or
        # the list would imply they are unavailable.
        for key, price in sorted(pricing.items()):
            if not key.startswith(f"{provider}:") or key in routed_keys:
                continue
            rows.append({
                "provider": provider,
                "alias": None,
                "wire_id": key.partition(":")[2],
                "key": key,
                "input_per_token": price.input_per_token,
                "output_per_token": price.output_per_token,
            })

    return rows


def _configured_models() -> tuple[dict[str, str], str | None]:
    """Map 'provider:model' -> the config field using it, for in-use markers.

    Returns ({}, reason) when the config cannot be loaded — listing the registry
    is still useful without it, so this reports the problem rather than aborting.
    """
    from security_review.budget import _resolve_pricing_key
    from security_review.config import load_config

    try:
        cfg = load_config(None)
    except Exception as e:
        return {}, str(e)

    in_use: dict[str, str] = {}
    for field, value in (
        ("llm.provider_model", cfg.llm.provider_model),
        ("llm.triage_model", cfg.llm.triage_model),
        ("verification.model", cfg.verification.model),
    ):
        if not value:
            continue
        key = _resolve_pricing_key(value)
        in_use[key] = field if key not in in_use else f"{in_use[key]}, {field}"
    return in_use, None


def _foundry_config():
    """Load the foundry: block, or explain precisely what is missing."""
    from security_review.config import load_config
    from security_review.errors import ConfigurationError

    cfg = load_config(None)
    if cfg.foundry is None:
        raise ConfigurationError(
            "No `foundry:` block in config/settings/security_review.yaml — required "
            "for --foundry. Set subscription_id, resource_group, account_name, "
            "location, and az_timeout_seconds.",
            code="SYS_CONFIG_INVALID",
        )
    return cfg.foundry


def _render_foundry(show_catalog: bool, publisher: str | None, as_json: bool) -> None:
    """Show what is published on the Foundry resource, and optionally what is deployable."""
    from security_review.budget import pricing_entry_exists
    from security_review.foundry_catalog import list_catalog, list_deployments

    cfg = _foundry_config()
    deployments = list_deployments(cfg)
    catalog = list_catalog(cfg, publisher) if show_catalog else []

    # A deployed model is only reachable from a review run once pricing exists
    # for it, since CostTracker.record() rejects an unpriced model.
    usable = {d.model_name: pricing_entry_exists(f"foundry:{d.model_name}") for d in deployments}

    if as_json:
        import json
        click.echo(json.dumps({
            "resource": {
                "account_name": cfg.account_name,
                "resource_group": cfg.resource_group,
                "location": cfg.location,
                "subscription_id": cfg.subscription_id,
            },
            "published": [dict(d.model_dump(), scar_priced=usable[d.model_name])
                          for d in deployments],
            "catalog": [e.model_dump() for e in catalog],
        }, indent=2))
        return

    click.echo(f"\nSCAR — Azure AI Foundry   ({cfg.account_name} / {cfg.location})")

    click.echo(f"\n{click.style('Published — callable now', fg='cyan', bold=True)}")
    if not deployments:
        click.echo(click.style("  none deployed on this resource", fg="yellow"))
    for d in deployments:
        mark = click.style("  [+]", fg="green") if usable[d.model_name] else click.style("  [!]", fg="red")
        capacity = f"cap={d.capacity}" if d.capacity is not None else ""
        click.echo(f"{mark} {d.model_name:<24} {d.version:<12} {d.publisher:<12} "
                   f"{d.sku:<18} {capacity:<10} {d.state}")
    if deployments:
        priced = sum(1 for v in usable.values() if v)
        click.echo(f"\n  {len(deployments)} published, {priced} priced in config/pricing.yaml.")
        if priced < len(deployments):
            click.echo("  [!] = SCAR cannot route to it yet: add a "
                       "'foundry:<model>' entry to config/pricing.yaml.")

    if show_catalog:
        label = f"Available to deploy in {cfg.location}"
        if publisher:
            label += f" — publisher {publisher}"
        click.echo(f"\n{click.style(label, fg='cyan', bold=True)}")
        if not catalog:
            click.echo(click.style("  no catalog entries matched", fg="yellow"))
        for e in catalog:
            flags = " ".join(filter(None, [
                "default" if e.is_default_version else "",
                f"hosted-on={e.hosted_on}" if e.hosted_on else "",
            ]))
            retires = f"retires {e.inference_retires[:10]}" if e.inference_retires else ""
            click.echo(f"      {e.model_name:<24} v{e.version:<10} {e.publisher:<12} "
                       f"{e.lifecycle_status:<20} {flags:<28} {retires}")
        click.echo(f"\n  {len(catalog)} model/version pair(s) offered. Catalog presence is not "
                   "permission — Azure Policy can still refuse the deployment.")
    else:
        click.echo("\n  Pass --catalog to also list what the region offers for deployment.")
    click.echo()


@cli.command("list-models")
@click.option("--foundry", "use_foundry", is_flag=True,
              help="List Azure AI Foundry models published on the configured resource.")
@click.option("--catalog", "show_catalog", is_flag=True,
              help="With --foundry: also list models the region offers for deployment.")
@click.option("--publisher", default=None,
              help="With --foundry --catalog: filter the catalog by publisher (e.g. Anthropic).")
@click.option("--provider", "provider_filter", default=None,
              help="Show only one provider (e.g. anthropic, copilot, claude).")
@click.option("--all", "show_all", is_flag=True,
              help="Include models with no config/pricing.yaml entry (not usable as-is).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def list_models(use_foundry, show_catalog, publisher, provider_filter,
                show_all, as_json, verbose, debug):
    """List models SCAR can use, with resolved wire IDs and pricing."""
    _setup_logging(verbose, debug, quiet=not verbose and not debug,
                   json_logs=False, no_file_log=True)

    from security_review.errors import ConfigurationError

    if use_foundry and provider_filter:
        click.echo("--provider filters the local registry and cannot be combined with "
                   "--foundry. Use --publisher to filter Foundry models.", err=True)
        raise SystemExit(1)
    if not use_foundry and (show_catalog or publisher):
        click.echo("--catalog and --publisher only apply with --foundry.", err=True)
        raise SystemExit(1)

    try:
        if use_foundry:
            _render_foundry(show_catalog, publisher, as_json)
            return
        rows = _collect_rows(provider_filter, show_all)
    except ConfigurationError as e:
        click.echo(str(e), err=True)
        raise SystemExit(1)

    in_use, config_error = _configured_models()

    if as_json:
        import json
        payload = [dict(r, in_use=in_use.get(r["key"])) for r in rows]
        click.echo(json.dumps(payload, indent=2))
        return

    click.echo("\nSCAR — Model Registry   (config/models.yaml + config/pricing.yaml)")
    if config_error:
        click.echo(click.style(
            f"  [!] config not loaded — in-use markers unavailable: {config_error}",
            fg="yellow",
        ))

    current_provider = None
    for row in rows:
        if row["provider"] != current_provider:
            current_provider = row["provider"]
            click.echo(f"\n{click.style(current_provider, fg='cyan', bold=True)}")

        priced = row["input_per_token"] is not None
        mark = click.style("  [+]", fg="green") if priced else click.style("  [!]", fg="red")
        alias = row["alias"] or "-"
        rate = (
            f"{_per_million(row['input_per_token'])} in / "
            f"{_per_million(row['output_per_token'])} out per 1M"
            if priced else "no pricing entry — unusable until added"
        )
        note = ""
        if row["key"] in in_use:
            note = click.style(f"   <- {in_use[row['key']]}", fg="yellow")
        click.echo(f"{mark} {alias:<16} -> {row['wire_id']:<22} {rate}{note}")

    if not rows:
        click.echo(click.style("\n  No models matched.", fg="yellow"))
        return

    usable = sum(1 for r in rows if r["input_per_token"] is not None)
    click.echo(f"\n{usable} usable model(s)"
               + ("" if show_all else "   (pass --all to include unpriced entries)"))
    click.echo("Use with: python scar.py review --target . --provider <provider>:<alias|wire-id>\n")
