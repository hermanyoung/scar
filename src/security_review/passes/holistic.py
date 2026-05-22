"""Pass 4: CWE-driven LLM security analysis with concurrent batches.

Runs one focused agent call per CWE that requires LLM reasoning.
Each check reads only relevant files and asks one specific question.
CWE checks are dispatched in concurrent batches (configurable via llm.concurrency).

Architecture: taxonomy/cwe.yaml is the single source of truth.
Each CWE with detection=llm or detection=sast+llm has a check prompt.
This pass loads those checks and executes them concurrently.
"""
from __future__ import annotations

import asyncio
import time
from enum import Enum, auto

from pathlib import Path

import structlog
from pydantic_ai import UsageLimits
from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings

from security_review.agents.deps import SecurityReviewDeps
from security_review.agents.holistic.agent import holistic_agent
from security_review.checks import CWECheck, load_cwe_checks, select_files_for_check
from security_review.context_builder import inline_files
from security_review.errors import is_fatal_error
from security_review.model_capabilities import supports_native_json, HOLISTIC_FORMAT_MARKDOWN
from security_review.models.findings import HolisticFinding, HolisticReviewResult
from security_review.model_settings import build_model_settings
from security_review.output_parser import parse_holistic_response
from security_review.passes.state import PipelineState
from security_review.providers import build_model
from security_review.sarif.loader import get_findings_for_file
from security_review.tracing import write_trace

logger = structlog.get_logger()


# -- Result classification (single source of truth for both passes) ----------


class _Outcome(Enum):
    """Classification of a single CWE check result."""
    COMPLETED = auto()       # findings extracted (possibly empty — LLM said "no findings")
    RETRY = auto()           # transient failure or parse failure — worth retrying
    FATAL = auto()           # auth/config error — abort the entire pass


def _classify_result(
    result: tuple[list[HolisticFinding], list[str], bool] | Exception | None,
    check: CWECheck,
) -> tuple[_Outcome, list[HolisticFinding], list[str]]:
    """Classify a single check result. Returns (outcome, findings, files_reviewed).

    This is the single place that decides what to do with a check result.
    Both the first pass and retry pass call this — no duplicated logic.
    """
    if isinstance(result, Exception):
        if is_fatal_error(result):
            return _Outcome.FATAL, [], []
        logger.warning(
            "holistic.check_failed",
            cwe_id=check.cwe_id,
            error=str(result),
            error_type=type(result).__name__,
        )
        return _Outcome.RETRY, [], []

    if result is None:
        return _Outcome.RETRY, [], []

    findings, files_reviewed, parse_failed = result

    if findings:
        return _Outcome.COMPLETED, findings, files_reviewed

    if parse_failed:
        logger.warning(
            "holistic.check_parse_failed",
            cwe_id=check.cwe_id,
            files_reviewed=len(files_reviewed),
        )
        return _Outcome.RETRY, [], files_reviewed

    # LLM explicitly found no issues — accept.
    logger.debug("holistic.check_no_findings", cwe_id=check.cwe_id)
    return _Outcome.COMPLETED, [], files_reviewed


# -- Main pass ---------------------------------------------------------------


async def run_holistic(state: PipelineState) -> None:
    """Execute Pass 4: CWE checks dispatched in concurrent batches."""

    logger.info("pipeline.pass_started", pass_number=4, pass_name="holistic")

    if state.manifest is None or state.sast_sarif is None:
        logger.warning("holistic.skipped", reason="No manifest or SAST results")
        return

    source_files = [
        f for f in state.manifest.files
        if f.language in ("python", "csharp")
    ]
    if not source_files:
        logger.info("holistic.skipped", reason="No source files in manifest")
        return

    checks = load_cwe_checks()
    if not checks:
        logger.warning("holistic.skipped", reason="No CWE checks defined in taxonomy")
        return

    # Filter checks to those with relevant files
    runnable: list[tuple[CWECheck, list[str]]] = []
    for check in checks:
        relevant_files = select_files_for_check(check, source_files)
        file_paths = [f.path for f in relevant_files]
        if file_paths:
            runnable.append((check, file_paths))
        else:
            logger.debug("holistic.check_skipped", cwe_id=check.cwe_id, reason="No relevant files")

    if not runnable:
        logger.info("holistic.skipped", reason="No CWE checks matched any files")
        return

    model_string = state.config.llm.provider_model
    model = build_model(model_string, llm_config=state.config.llm)
    model_settings = build_model_settings(model_string, state.config.llm)
    native_json = supports_native_json(model)
    concurrency = state.config.llm.concurrency

    all_findings: list[HolisticFinding] = []
    all_files_reviewed: set[str] = set()
    checks_completed = 0
    checks_failed = 0
    total_checks = len(runnable)

    # -- First pass: run checks in concurrent batches --------------------------

    failed_checks: list[tuple[CWECheck, list[str]]] = []
    t_start = time.monotonic()

    state.on_progress(
        4, "holistic", "tool",
        f"running {total_checks} CWE checks across {len(set(fp for _, fps in runnable for fp in fps))} files",
    )

    for batch_start in range(0, total_checks, concurrency):
        if state.cost_tracker.would_exceed_budget(state.config.llm.max_budget_usd):
            remaining = total_checks - batch_start
            logger.warning(
                "holistic.budget_exhausted",
                spent_usd=state.cost_tracker.total_spent,
                max_budget_usd=state.config.llm.max_budget_usd,
                checks_completed=checks_completed,
                checks_skipped=remaining,
            )
            break

        batch_end = min(batch_start + concurrency, total_checks)
        batch = runnable[batch_start:batch_end]

        elapsed = time.monotonic() - t_start
        done_count = checks_completed + checks_failed + len(failed_checks)
        if done_count > 0:
            avg = elapsed / done_count
            remaining_time = (total_checks - done_count) * avg
            eta = f"~{int(remaining_time)}s left"
        else:
            eta = "estimating..."
        cwe_ids = ", ".join(c.cwe_id for c, _ in batch)
        state.on_progress(
            4, "holistic", "counter",
            f"[{done_count}/{total_checks}] CWE-{cwe_ids} ({int(elapsed)}s elapsed, {eta})",
        )

        batch_results = await _run_batch(batch, state, model, model_string, model_settings, native_json)

        for (check, file_paths), result in zip(batch, batch_results):
            outcome, findings, files_reviewed = _classify_result(result, check)

            if outcome == _Outcome.FATAL:
                raise result  # type: ignore[misc]
            elif outcome == _Outcome.RETRY:
                failed_checks.append((check, file_paths))
            else:
                all_findings.extend(findings)
                all_files_reviewed.update(files_reviewed)
                checks_completed += 1

        elapsed = time.monotonic() - t_start
        done_count = checks_completed + checks_failed + len(failed_checks)
        if done_count > 0 and done_count < total_checks:
            avg = elapsed / done_count
            remaining_time = (total_checks - done_count) * avg
            eta = f" ~{int(remaining_time)}s left"
        else:
            eta = ""
        state.on_progress(
            4, "holistic", "counter",
            f"[{done_count}/{total_checks}] "
            f"{len(all_findings)} findings"
            f"{f', {len(failed_checks)} pending retry' if failed_checks else ''}"
            f" ({int(elapsed)}s{eta})",
        )

    # -- Retry pass: re-run failed checks one at a time ------------------------

    if failed_checks:
        logger.info(
            "holistic.retry_pass",
            failed_count=len(failed_checks),
            cwe_ids=[c.cwe_id for c, _ in failed_checks],
        )
        state.on_progress(
            4, "holistic", "detail",
            f"retrying {len(failed_checks)} failed check(s) sequentially",
        )

        for check, file_paths in failed_checks:
            if state.cost_tracker.would_exceed_budget(state.config.llm.max_budget_usd):
                logger.warning("holistic.retry_budget_exhausted", cwe_id=check.cwe_id)
                checks_failed += 1
                continue

            retry_results = await _run_batch(
                [(check, file_paths)], state, model, model_string, model_settings, native_json,
            )

            retry_result_raw = retry_results[0]
            outcome, findings, files_reviewed = _classify_result(retry_result_raw, check)

            if outcome == _Outcome.FATAL:
                raise retry_result_raw  # type: ignore[misc]
            elif outcome == _Outcome.COMPLETED:
                all_findings.extend(findings)
                all_files_reviewed.update(files_reviewed)
                checks_completed += 1
                if findings:
                    logger.info("holistic.retry_succeeded", cwe_id=check.cwe_id,
                                finding_count=len(findings))
                else:
                    logger.info("holistic.retry_no_findings", cwe_id=check.cwe_id)
            else:
                # Second RETRY — give up on this check.
                checks_failed += 1
                logger.error("holistic.check_failed_after_retry", cwe_id=check.cwe_id)

    if all_files_reviewed:
        state.holistic_result = HolisticReviewResult(
            findings=all_findings,
            files_reviewed=sorted(all_files_reviewed),
        )

    logger.info(
        "pipeline.pass_completed",
        pass_number=4,
        finding_count=len(all_findings),
        checks_completed=checks_completed,
        checks_failed=checks_failed,
    )


async def _run_batch(
    batch: list[tuple[CWECheck, list[str]]],
    state: PipelineState,
    model: Model,
    model_string: str,
    model_settings: ModelSettings | None = None,
    native_json: bool = False,
) -> list[tuple[list[HolisticFinding], list[str], bool] | Exception | None]:
    """Run a batch of CWE checks concurrently. Returns results in order.

    Each result is (findings, files_reviewed, parse_failed):
      parse_failed=True  — LLM responded but parser extracted nothing (retry).
      parse_failed=False — LLM explicitly found no issues (accept).
    """
    tasks = [
        run_single_check(
            check=check,
            file_paths=file_paths,
            state=state,
            model=model,
            model_string=model_string,
            model_settings=model_settings,
            native_json=native_json,
        )
        for check, file_paths in batch
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def run_single_check(
    *,
    check: CWECheck,
    file_paths: list[str],
    state: PipelineState,
    model: Model,
    model_string: str,
    model_settings: ModelSettings | None = None,
    native_json: bool = False,
) -> tuple[list[HolisticFinding], list[str], bool] | None:
    """Run a single CWE check. Returns (findings, files_reviewed, parse_failed) or None on failure.

    parse_failed=True when the LLM responded but parsing produced nothing (worth retrying).
    parse_failed=False with empty findings means the LLM explicitly found no issues.
    """
    deps = SecurityReviewDeps(
        config=state.config,
        manifest=state.manifest,
        sast_sarif=state.sast_sarif,
        cost_tracker=state.cost_tracker,
        target_path=state.target_path,
        run_id=state.run_id,
        batch_id=f"cwe-{check.cwe_id}",
    )

    logger.info(
        "agent.started",
        agent_name="holistic",
        cwe_id=check.cwe_id,
        cwe_name=check.short_name,
        model_requested=model_string,
        file_count=len(file_paths),
    )

    prompt = _build_inline_prompt(
        check=check,
        file_paths=file_paths,
        target_path=state.target_path,
        sast_sarif=state.sast_sarif or {},
        max_input_tokens=state.config.llm.max_tokens_per_batch,
    )

    # Native JSON providers: PydanticAI enforces the HolisticReviewResult schema.
    # Prompted providers: append format instruction, output_parser extracts findings.
    if native_json:
        output_type = HolisticReviewResult
    else:
        output_type = str
        prompt = prompt + "\n\n" + HOLISTIC_FORMAT_MARKDOWN

    result = await holistic_agent.run(
        prompt,
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

    # Record cost
    usage = result.usage()
    state.cost_tracker.record(
        agent_name="holistic",
        batch_id=f"cwe-{check.cwe_id}",
        model_requested=model_string,
        model_responded=model_string,
        tokens_in=usage.request_tokens or 0,
        tokens_out=usage.response_tokens or 0,
    )

    # Normalize output — always override files_reviewed with our known list (P13).
    output = result.output
    if isinstance(output, HolisticReviewResult):
        review_result = output.model_copy(update={"files_reviewed": file_paths})
    else:
        review_result = parse_holistic_response(output, files_reviewed=file_paths)
        if review_result is None:
            review_result = HolisticReviewResult(findings=[], files_reviewed=file_paths)

    # parse_failed=True when the LLM gave a non-empty response but we extracted nothing.
    # review_notes is set by the parser exactly when that happens.
    parse_failed = not review_result.findings and review_result.review_notes is not None

    logger.info(
        "agent.completed",
        agent_name="holistic",
        cwe_id=check.cwe_id,
        finding_count=len(review_result.findings),
        parse_failed=parse_failed,
    )

    if state.trace_enabled:
        write_trace(
            output_dir=state.output_dir,
            agent_name="holistic",
            trace_id=f"holistic-{check.cwe_id.lower()}",
            prompt=prompt,
            result=result,
            output=review_result.model_dump(),
        )

    return review_result.findings, review_result.files_reviewed, parse_failed


# -- Prompt builders ---------------------------------------------------------


def _build_inline_prompt(
    check: CWECheck,
    file_paths: list[str],
    target_path: Path,
    sast_sarif: dict,
    max_input_tokens: int = 100_000,
) -> str:
    """Build a self-contained prompt with file contents and SAST findings inlined.

    Uses context_builder.inline_files for token-budget-aware file inclusion.
    """
    target_root = str(target_path.resolve())

    # Collect SAST findings for context
    sast_lines: list[str] = []
    for fp in file_paths:
        findings = get_findings_for_file(sast_sarif, fp, target_root=target_root)
        for f in findings:
            sast_lines.append(
                f"- {fp}:{f['line_number']} — {f['message'][:100]} ({f['tool_name']})"
            )

    # Build prompt sections
    header = f"## Security Check: {check.display_name}\n\n{check.check_prompt}\n"

    if sast_lines:
        sast_section = (
            "\n**Existing SAST findings (do not duplicate):**\n"
            + "\n".join(sast_lines) + "\n"
        )
    else:
        sast_section = "\n**No existing SAST findings for these files.**\n"

    instructions = (
        "\n**Instructions:**\n"
        f"1. Review ALL source files above for {check.display_name}.\n"
        "2. Do not duplicate the SAST findings listed above.\n"
        "3. Only report findings with evidence — quote actual code from the files.\n"
        "4. If no issues are found for this CWE, say 'No findings' clearly.\n"
        f"5. All findings must reference CWE-{check.cwe_id}.\n"
    )

    # Inline files with token budget (P14: all context pre-materialized).
    # Subtract prompt overhead here and pass reserve_tokens=0 so inline_files
    # does not apply an additional internal reduction on top of our budget.
    overhead = len(header + sast_section + instructions) // 4 + 500
    file_content, included, omitted = inline_files(
        target_path,
        file_paths,
        max_tokens=max_input_tokens - overhead,
        reserve_tokens=0,
    )

    logger.debug(
        "holistic.prompt_built",
        cwe_id=check.cwe_id,
        files_included=len(included),
        files_omitted=len(omitted),
    )

    return header + sast_section + "\n**Source files:**\n" + file_content + instructions


