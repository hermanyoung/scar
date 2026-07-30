"""Azure AI Foundry model enumeration — deployed models and deployable catalog.

Two distinct questions this module answers, which Foundry keeps separate:

  * **Deployments** — models published on the account, callable right now.
  * **Catalog** — models the region will *let* you deploy, subject to quota and
    Azure Policy. Presence here is not permission; deployment can still be
    refused by an approved-publisher policy.

Auth comes from the operator's `az login` session, so no credentials pass
through this module. Every `az` invocation goes through tools/runner.run_tool_sync
— the repository's single subprocess chokepoint (rule 001.4) — which is also why
the calls are synchronous: enumeration happens outside the async pipeline.
"""
from __future__ import annotations

import json

import structlog
from pydantic import BaseModel

from security_review.config_schema import FoundryConfig
from security_review.errors import ConfigurationError

logger = structlog.get_logger(__name__)


class FoundryDeployment(BaseModel):
    """A model published on the Foundry account — callable now."""

    deployment_name: str
    model_name: str
    version: str
    publisher: str
    sku: str
    capacity: int | None
    state: str


class FoundryCatalogEntry(BaseModel):
    """A model/version the region offers for deployment."""

    model_name: str
    version: str
    publisher: str
    skus: list[str]
    lifecycle_status: str
    is_default_version: bool
    hosted_on: str | None
    inference_retires: str | None


def _az_json(cfg: FoundryConfig, args: list[str]) -> list[dict]:
    """Run an `az` query and parse its JSON array output.

    run_tool_sync never raises — a missing binary and a timeout both arrive as
    returncode=-1 — so every failure mode is converted here into a
    ConfigurationError carrying az's own stderr, rather than an empty list that
    would read as "no models found".
    """
    from security_review.tools.runner import run_tool_sync

    cmd = ["az", *args, "--subscription", cfg.subscription_id, "-o", "json"]
    result = run_tool_sync(cmd, timeout_seconds=cfg.az_timeout_seconds)

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ConfigurationError(
            f"az query failed ({' '.join(args[:3])}): {detail or 'no output'}\n"
            f"Check that the Azure CLI is installed and `az login` is current.",
            code="SYS_CONFIG_INVALID",
        )

    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as e:
        raise ConfigurationError(
            f"az returned unparseable JSON for {' '.join(args[:3])}: {e}",
            code="SYS_CONFIG_INVALID",
        ) from e

    if not isinstance(payload, list):
        raise ConfigurationError(
            f"az returned {type(payload).__name__}, expected a JSON array, "
            f"for {' '.join(args[:3])}.",
            code="SYS_CONFIG_INVALID",
        )
    return payload


def list_deployments(cfg: FoundryConfig) -> list[FoundryDeployment]:
    """List models published on the configured Foundry account."""
    raw = _az_json(cfg, [
        "cognitiveservices", "account", "deployment", "list",
        "-g", cfg.resource_group, "-n", cfg.account_name,
    ])

    deployments = [
        FoundryDeployment(
            deployment_name=item.get("name") or "",
            model_name=(item.get("properties", {}).get("model") or {}).get("name") or "",
            version=str((item.get("properties", {}).get("model") or {}).get("version") or ""),
            publisher=(item.get("properties", {}).get("model") or {}).get("format") or "",
            sku=(item.get("sku") or {}).get("name") or "",
            capacity=(item.get("sku") or {}).get("capacity"),
            state=item.get("properties", {}).get("provisioningState") or "",
        )
        for item in raw
    ]
    logger.info("foundry.deployments_listed",
                account=cfg.account_name, count=len(deployments))
    return sorted(deployments, key=lambda d: (d.publisher, d.model_name))


def list_catalog(cfg: FoundryConfig, publisher: str | None = None) -> list[FoundryCatalogEntry]:
    """List model/version pairs the region offers for deployment.

    Azure returns one record per account kind (AIServices, MaaS), so identical
    model/version pairs repeat; they are deduplicated here because the kind does
    not change what you can deploy on an AIServices account.
    """
    raw = _az_json(cfg, ["cognitiveservices", "model", "list", "--location", cfg.location])

    entries: dict[tuple[str, str], FoundryCatalogEntry] = {}
    for item in raw:
        model = item.get("model") or {}
        fmt = model.get("format") or ""
        if publisher and fmt.lower() != publisher.lower():
            continue
        key = (model.get("name") or "", str(model.get("version") or ""))
        if key in entries:
            continue
        capabilities = model.get("capabilities") or {}
        deprecation = model.get("deprecation") or {}
        entries[key] = FoundryCatalogEntry(
            model_name=key[0],
            version=key[1],
            publisher=fmt,
            skus=[s.get("name") or "" for s in (model.get("skus") or [])],
            lifecycle_status=model.get("lifecycleStatus") or "",
            is_default_version=bool(model.get("isDefaultVersion")),
            hosted_on=capabilities.get("hostedOn"),
            inference_retires=(deprecation.get("inference") or None),
        )

    logger.info("foundry.catalog_listed", location=cfg.location,
                publisher=publisher or "all", count=len(entries))
    return sorted(entries.values(), key=lambda e: (e.publisher, e.model_name, e.version))


def list_publishers(cfg: FoundryConfig) -> dict[str, int]:
    """Count catalog entries per publisher — the menu for --publisher."""
    counts: dict[str, int] = {}
    for entry in list_catalog(cfg):
        counts[entry.publisher] = counts.get(entry.publisher, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
