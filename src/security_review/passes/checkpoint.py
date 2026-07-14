"""Checkpoint/resume: persist per-pass pipeline state under {run_dir}/state/.

pipeline.py calls init_run() before Pass 1 and save_pass() after each
completed pass. A killed run keeps every completed pass's work and its
spend; ``--resume <run-dir>`` rehydrates the slices via load_into() and the
pipeline skips restored passes. Composes with the 018 salvage path: the
checkpoints written during the run make a salvaged run directory resumable.

Per plan 020 addendum A.8, run.json (written at run start by the CLI, 018
WP3) is the single run manifest — init_run() extends it with the output
paths instead of duplicating its facts into a separate meta file; the full
config snapshot lives in state/config.json.

Fail-fast (rule 11): a present-but-unreadable or schema-invalid checkpoint
raises ConfigurationError — never silently recompute. A *missing* file just
means that pass has not run yet.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import structlog

from security_review.config_schema import SecurityReviewConfig
from security_review.errors import ConfigurationError
from security_review.fsio import atomic_write_json
from security_review.models.config_review import ConfigReviewResult
from security_review.models.coverage import CoverageReport, FileCoverage
from security_review.models.degradation import Degradation
from security_review.models.findings import HolisticReviewResult, TriageResult
from security_review.models.inventory import FileManifest
from security_review.passes.state import PipelineState

logger = structlog.get_logger()

# Pass names that produce a checkpoint, in pipeline order. Merge is not
# checkpointed — it is cheap, side-effect-only, and always re-runs.
CHECKPOINTED_PASSES = ("inventory", "sast", "triage", "holistic", "config_review", "verify")


def state_dir(run_dir: Path) -> Path:
    """The checkpoint directory for a run."""
    return run_dir / "state"


def init_run(state: PipelineState) -> None:
    """Snapshot the config and extend run.json with output paths (before Pass 1).

    run.json itself is written by the CLI before the pipeline starts (018
    WP3); when the pipeline is embedded without the CLI (tests), a minimal
    manifest is created so the run directory is still resumable.
    """
    sdir = state_dir(state.output_dir)
    atomic_write_json(sdir / "config.json", state.config.model_dump())

    run_path = state.output_dir / "run.json"
    if run_path.exists():
        manifest = _read_json(run_path)
    else:
        manifest = {
            "run_id": state.run_id,
            "target": str(state.target_path),
            "mode": state.config.review.mode,
        }
    manifest["outputs"] = {
        "output_sarif": state.config.review.output_sarif,
        "output_summary": state.config.review.output_summary,
        "output_triage": state.config.review.output_triage,
    }
    atomic_write_json(run_path, manifest)


def save_pass(state: PipelineState, pass_name: str) -> None:
    """Atomically persist one pass's output slice; refresh cost + degradations."""
    sdir = state_dir(state.output_dir)
    atomic_write_json(sdir / f"{pass_name}.json", _slice_for(state, pass_name))
    atomic_write_json(sdir / "cost.json", state.cost_tracker.to_audit_log())
    atomic_write_json(sdir / "degradations.json", [d.model_dump() for d in state.degradations])
    logger.debug("checkpoint.saved", pass_name=pass_name, dir=str(sdir))


def completed_passes(run_dir: Path) -> set[str]:
    """Pass names with a checkpoint file present (validity is checked by load_into)."""
    sdir = state_dir(run_dir)
    return {name for name in CHECKPOINTED_PASSES if (sdir / f"{name}.json").exists()}


def load_into(state: PipelineState, run_dir: Path) -> set[str]:
    """Rehydrate every present checkpoint slice into ``state``.

    Returns the restored pass names. Raises ConfigurationError on any
    present-but-invalid file — never silently recomputes (rule 11).
    """
    sdir = state_dir(run_dir)
    restored: set[str] = set()

    for name in CHECKPOINTED_PASSES:
        path = sdir / f"{name}.json"
        if not path.exists():
            continue
        _restore_slice(state, name, _read_json(path), path)
        restored.add(name)
        logger.info("checkpoint.restored", pass_name=name, path=str(path))

    cost_path = sdir / "cost.json"
    if cost_path.exists():
        entries = _read_json(cost_path)
        try:
            state.cost_tracker.restore(entries)
        except Exception as e:
            raise ConfigurationError(
                f"Invalid cost checkpoint {cost_path}: {e}",
                code="SYS_CONFIG_INVALID",
            ) from e
        logger.info("checkpoint.restored", pass_name="cost",
                    entries=len(entries), spent_usd=round(state.cost_tracker.total_spent, 4))

    degradations_path = sdir / "degradations.json"
    if degradations_path.exists():
        raw = _read_json(degradations_path)
        try:
            # Direct assignment (not state.degrade) — these events were
            # already mirrored to the run ledger by the original run.
            state.degradations = [Degradation.model_validate(d) for d in raw]
        except Exception as e:
            raise ConfigurationError(
                f"Invalid degradations checkpoint {degradations_path}: {e}",
                code="SYS_CONFIG_INVALID",
            ) from e

    return restored


def load_resume_context(run_dir: Path) -> tuple[dict, SecurityReviewConfig]:
    """Read run.json + state/config.json for ``--resume``. Fail-fast on anything invalid."""
    run_path = run_dir / "run.json"
    config_path = state_dir(run_dir) / "config.json"
    for required in (run_path, config_path):
        if not required.exists():
            raise ConfigurationError(
                f"Not a resumable run directory — missing {required}. "
                f"Point --resume at a var/output/<date>-<target>-<id>/ directory.",
                code="SYS_CONFIG_INVALID",
            )
    manifest = _read_json(run_path)
    for key in ("run_id", "target"):
        if key not in manifest:
            raise ConfigurationError(
                f"Run manifest {run_path} is missing '{key}' — cannot resume.",
                code="SYS_CONFIG_INVALID",
            )
    try:
        config = SecurityReviewConfig.model_validate(_read_json(config_path))
    except ConfigurationError:
        raise
    except Exception as e:
        raise ConfigurationError(
            f"Invalid config snapshot {config_path}: {e}",
            code="SYS_CONFIG_INVALID",
        ) from e
    return manifest, config


# -- Internals -----------------------------------------------------------------


def _slice_for(state: PipelineState, pass_name: str) -> dict:
    """The JSON-serialisable state slice a pass checkpoint captures."""
    if pass_name == "inventory":
        return {
            "manifest": state.manifest.model_dump() if state.manifest else None,
            "coverage": asdict(state.coverage) if state.coverage else None,
        }
    if pass_name == "sast":
        return {"sast_sarif": state.sast_sarif}
    if pass_name == "triage":
        # sast_sarif is re-persisted here because triage writes verdicts in
        # place into its result properties — this captures them.
        return {
            "triage_result": state.triage_result.model_dump() if state.triage_result else None,
            "sast_sarif": state.sast_sarif,
        }
    if pass_name == "holistic":
        return {"holistic_result": state.holistic_result.model_dump() if state.holistic_result else None}
    if pass_name == "config_review":
        return {"config_review_result": state.config_review_result.model_dump() if state.config_review_result else None}
    if pass_name == "verify":
        # verify mutates triage_verdict in place on Pass 4/5 findings —
        # re-persist both results so the verdicts survive.
        return {
            "holistic_result": state.holistic_result.model_dump() if state.holistic_result else None,
            "config_review_result": state.config_review_result.model_dump() if state.config_review_result else None,
        }
    raise ValueError(f"Unknown checkpoint pass: {pass_name}")


def _restore_slice(state: PipelineState, pass_name: str, data: dict, path: Path) -> None:
    """Rehydrate one pass slice, validating shapes. Raises ConfigurationError."""
    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Invalid checkpoint {path}: expected a JSON object, got {type(data).__name__}",
            code="SYS_CONFIG_INVALID",
        )
    try:
        if pass_name == "inventory":
            if data.get("manifest") is not None:
                state.manifest = FileManifest.model_validate(data["manifest"])
            if data.get("coverage") is not None:
                state.coverage = CoverageReport(by_type={
                    file_type: FileCoverage(**cov)
                    for file_type, cov in data["coverage"]["by_type"].items()
                })
        elif pass_name == "sast":
            if data.get("sast_sarif") is not None:
                state.sast_sarif = data["sast_sarif"]
        elif pass_name == "triage":
            if data.get("triage_result") is not None:
                state.triage_result = TriageResult.model_validate(data["triage_result"])
            if data.get("sast_sarif") is not None:
                state.sast_sarif = data["sast_sarif"]
        elif pass_name == "holistic":
            if data.get("holistic_result") is not None:
                state.holistic_result = HolisticReviewResult.model_validate(data["holistic_result"])
        elif pass_name == "config_review":
            if data.get("config_review_result") is not None:
                state.config_review_result = ConfigReviewResult.model_validate(data["config_review_result"])
        elif pass_name == "verify":
            if data.get("holistic_result") is not None:
                state.holistic_result = HolisticReviewResult.model_validate(data["holistic_result"])
            if data.get("config_review_result") is not None:
                state.config_review_result = ConfigReviewResult.model_validate(data["config_review_result"])
    except Exception as e:  # pydantic ValidationError, TypeError, KeyError, ...
        raise ConfigurationError(
            f"Invalid checkpoint {path}: {e} — delete the file to recompute "
            f"that pass, or start a fresh run.",
            code="SYS_CONFIG_INVALID",
        ) from e


def _read_json(path: Path):
    """Read a checkpoint JSON file, fail-fast on corruption."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ConfigurationError(
            f"Corrupt checkpoint {path}: {e} — delete the file to recompute "
            f"that pass, or start a fresh run.",
            code="SYS_CONFIG_INVALID",
        ) from e
