"""Pass 5: LLM configuration review orchestration.

Reviews configuration files for security misconfigurations.
"""
from __future__ import annotations

import structlog
from pydantic_ai import UsageLimits

from security_review.agents.config_review.agent import config_review_agent
from security_review.agents.deps import SecurityReviewDeps
from security_review.context_builder import inline_files
from security_review.errors import is_fatal_error
from security_review.model_capabilities import supports_native_json, CONFIG_FORMAT_JSON
from security_review.models.config_review import ConfigReviewResult
from security_review.models.degradation import Degradation
from security_review.model_settings import build_model_settings
from security_review.output_parser import parse_config_review_response
from security_review.passes.state import PipelineState
from security_review.providers import build_model
from security_review.tracing import write_trace

logger = structlog.get_logger()

# Config file patterns to review
_CONFIG_PATTERNS = {
    "appsettings", "launchsettings", "dockerfile", "docker-compose",
    "pyproject", ".env", "settings", "config",
}

_CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".xml", ".props",
    ".editorconfig", ".env", ".cfg", ".ini",
    ".bicep", ".bicepparam", ".tf", ".tfvars",
}


async def run_config_review(state: PipelineState) -> None:
    """Execute Pass 5: LLM configuration file security review."""

    logger.info("pipeline.pass_started", pass_number=5, pass_name="config_review")

    if state.manifest is None:
        logger.warning("config_review.skipped", reason="No manifest")
        return

    # Find config files
    config_files = [
        f for f in state.manifest.files
        if f.language == "config" or _is_config_file(f.path)
    ]

    if not config_files:
        logger.info("config_review.skipped", reason="No config files in manifest")
        return

    model_string = state.config.llm.provider_model
    model = build_model(model_string, llm_config=state.config.llm)
    model_settings = build_model_settings(model_string, state.config.llm)
    native_json = supports_native_json(model)

    file_paths = [f.path for f in config_files]

    deps = SecurityReviewDeps(
        config=state.config,
        manifest=state.manifest,
        sast_sarif=state.sast_sarif or {"runs": []},
        cost_tracker=state.cost_tracker,
        target_path=state.target_path,
        run_id=state.run_id,
        batch_id="config-batch-000",
    )

    if state.cost_tracker.would_exceed_budget(state.config.llm.max_budget_usd):
        logger.warning(
            "config_review.budget_exhausted",
            spent_usd=state.cost_tracker.total_spent,
            max_budget_usd=state.config.llm.max_budget_usd,
        )
        state.degrade(Degradation(
            pass_name="config_review", kind="budget_exhausted", subject="config_review",
            detail=f"budget reached — {len(file_paths)} config files were NOT reviewed",
            count=len(file_paths),
        ))
        logger.info("pipeline.pass_completed", pass_number=5, finding_count=0)
        return

    # Native JSON: PydanticAI enforces ConfigReviewResult schema directly.
    # Prompted: append JSON format instruction, parse the text response.
    if native_json:
        user_prompt = _build_config_review_prompt(file_paths, state.target_path)
        output_type = ConfigReviewResult
    else:
        user_prompt = _build_config_review_prompt(file_paths, state.target_path) + "\n\n" + CONFIG_FORMAT_JSON
        output_type = str

    logger.info(
        "agent.started",
        agent_name="config_review",
        model_requested=model_string,
        file_count=len(file_paths),
        native_json=native_json,
    )

    try:
        result = await config_review_agent.run(
            user_prompt,
            deps=deps,
            model=model,
            model_settings=model_settings,
            output_type=output_type,
            retries=state.config.llm.output_retries,
            usage_limits=UsageLimits(
                request_limit=2,
                total_tokens_limit=500_000,
            ),
        )

        # Normalize output to ConfigReviewResult, overriding files_reviewed (P13).
        output = result.output
        if isinstance(output, ConfigReviewResult):
            config_result = output.model_copy(update={"files_reviewed": file_paths})
        else:
            config_result = parse_config_review_response(output, files_reviewed=file_paths)
            if config_result is None:
                logger.warning("config_review.parse_failed", file_count=len(file_paths))
                state.degrade(Degradation(
                    pass_name="config_review", kind="parse_failed", subject="config_review",
                    detail="LLM response was unparseable — config files were NOT reviewed",
                    count=len(file_paths),
                ))

        if config_result is not None:
            state.config_review_result = config_result

        # Record cost
        usage = result.usage()
        state.cost_tracker.record(
            agent_name="config_review",
            batch_id="config-batch-000",
            model_requested=model_string,
            model_responded=model_string,
            tokens_in=usage.request_tokens or 0,
            tokens_out=usage.response_tokens or 0,
        )

        finding_count = len(config_result.findings) if config_result else 0
        logger.info(
            "agent.completed",
            agent_name="config_review",
            finding_count=finding_count,
        )

        if state.trace_enabled and config_result:
            write_trace(
                output_dir=state.output_dir,
                agent_name="config_review",
                trace_id="config-review",
                prompt=user_prompt,
                result=result,
                output=config_result.model_dump(),
            )

    except Exception as e:
        logger.error(
            "agent.failed",
            agent_name="config_review",
            error=str(e),
            error_type=type(e).__name__,
        )
        if is_fatal_error(e):
            raise
        state.degrade(Degradation(
            pass_name="config_review", kind="check_failed", subject="config_review",
            detail=f"agent call failed ({type(e).__name__}) — {len(file_paths)} config files were NOT reviewed",
            count=len(file_paths),
        ))

    logger.info(
        "pipeline.pass_completed",
        pass_number=5,
        finding_count=len(state.config_review_result.findings) if state.config_review_result else 0,
    )


def _is_config_file(path: str) -> bool:
    """Check if a file path looks like a configuration file."""
    name_lower = path.lower().rsplit("/", 1)[-1]

    # Check name patterns
    for pattern in _CONFIG_PATTERNS:
        if pattern in name_lower:
            return True

    # Check extension
    if "." in name_lower:
        ext = "." + name_lower.rsplit(".", 1)[-1]
        if ext in _CONFIG_EXTENSIONS:
            return True

    # Dockerfile (no extension)
    if name_lower.startswith("dockerfile"):
        return True

    # CI files
    if ".github/" in path.lower() or ".gitlab-ci" in name_lower:
        return True

    return False


def _build_config_review_prompt(file_paths: list[str], target_path) -> str:
    """Build prompt with config file contents inlined (P14: no tool calls)."""
    from pathlib import Path

    file_content, _, _ = inline_files(Path(target_path), file_paths, reserve_tokens=0)

    return (
        "Review the following configuration files for security issues.\n\n"
        "Look for: secrets/credentials, debug modes, permissive CORS, "
        "missing security headers, insecure Docker configurations, "
        "and any security-relevant misconfigurations.\n\n"
        "**Configuration files:**\n\n"
        + file_content
    )
