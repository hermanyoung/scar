"""Pass 3: LLM triage — one finding per agent call, concurrent batches.

Each SAST finding is triaged individually for accuracy. Findings are
dispatched in concurrent batches (configurable via llm.concurrency).
Progress updates after each concurrent batch with running totals.

Verdicts are written back to state.sast_sarif by index — no reliance
on shallow-copy mutation or LLM-echoed identifiers (P13).
"""
from __future__ import annotations

import asyncio
import time

import structlog
from pydantic_ai import UsageLimits
from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings

from security_review.agents.deps import SecurityReviewDeps
from security_review.agents.triage.agent import build_triage_agent
from security_review.context_builder import format_context_window, read_file_content
from security_review.errors import is_fatal_error
from security_review.model_capabilities import supports_native_json, TRIAGE_FORMAT_MARKDOWN
from security_review.models.degradation import Degradation
from security_review.models.findings import TriagedFinding, TriageResult
from security_review.model_settings import build_model_settings
from security_review.output_parser import parse_triage_response
from security_review.providers import build_model
from security_review.passes.state import PipelineState
from security_review.sarif.loader import extract_findings, get_result_location
from security_review.tracing import write_trace

logger = structlog.get_logger()


async def run_triage(state: PipelineState) -> None:
    """Execute Pass 3: one LLM call per SAST finding, N at a time."""

    logger.info("pipeline.pass_started", pass_number=3, pass_name="triage")

    if state.sast_sarif is None or state.manifest is None:
        logger.warning("triage.skipped", reason="No SAST results or manifest")
        return

    all_sast_findings = extract_findings(state.sast_sarif)
    if not all_sast_findings:
        logger.info("triage.skipped", reason="No SAST findings to triage")
        return

    # The canonical SARIF results list — verdicts are written here by index.
    sarif_results = state.sast_sarif["runs"][0]["results"]

    # Filter by priority score — findings are already scored in Pass 2.
    min_score = state.config.triage.min_score

    # Build (filtered_index, sarif_index) pairs so we can write back by index.
    indexed_findings: list[tuple[int, dict]] = [
        (i, f) for i, f in enumerate(all_sast_findings)
        if f.get("properties", {}).get("priority", 0) >= min_score
    ]

    skipped = len(all_sast_findings) - len(indexed_findings)
    if skipped:
        logger.info("triage.filtered",
                     total=len(all_sast_findings),
                     triaging=len(indexed_findings),
                     skipped_low_priority=skipped,
                     min_score=min_score)

    if not indexed_findings:
        logger.info("triage.skipped", reason=f"No findings at priority score >= {min_score}")
        state.on_progress(3, "triage", "tool", f"0 of {len(all_sast_findings)} findings above threshold ({min_score})")
        return

    state.on_progress(
        3, "triage", "tool",
        f"triaging {len(indexed_findings)} of {len(all_sast_findings)} findings "
        f"(score >= {min_score}, {skipped} skipped)",
    )

    model_string = state.config.llm.triage_model or state.config.llm.provider_model
    model = build_model(model_string, llm_config=state.config.llm)
    model_settings = build_model_settings(model_string, state.config.llm)
    native_json = supports_native_json(model)
    target_root = str(state.target_path.resolve())
    concurrency = state.config.llm.concurrency

    all_triaged: list[TriagedFinding] = []
    completed = 0
    failed = 0
    total_findings = len(indexed_findings)
    t_start = time.monotonic()

    # Process in concurrent batches
    for batch_start in range(0, total_findings, concurrency):
        if state.cost_tracker.would_exceed_budget(state.config.llm.max_budget_usd):
            logger.warning(
                "triage.budget_exhausted",
                spent_usd=state.cost_tracker.total_spent,
                triaged=batch_start,
                remaining=total_findings - batch_start,
            )
            remaining = total_findings - batch_start
            state.degrade(Degradation(
                pass_name="triage", kind="budget_exhausted", subject="triage",
                detail=f"budget ${state.config.llm.max_budget_usd:.2f} reached after {batch_start} of "
                       f"{total_findings} findings — {remaining} findings remain Untriaged",
                count=remaining,
            ))
            state.on_progress(3, "triage", "tool",
                              f"budget exhausted — {remaining} of {total_findings} findings not triaged")
            break

        batch_end = min(batch_start + concurrency, total_findings)
        batch = indexed_findings[batch_start:batch_end]

        # Report progress with timing
        elapsed = time.monotonic() - t_start
        done_count = completed + failed
        if done_count > 0:
            avg = elapsed / done_count
            remaining = (total_findings - done_count) * avg
            eta = f"~{int(remaining)}s left"
        else:
            eta = "estimating..."
        state.on_progress(
            3, "triage", "counter",
            f"[{done_count}/{total_findings}] triaging finding {batch_start + 1}... "
            f"({int(elapsed)}s elapsed, {eta}, ${state.cost_tracker.total_spent:.2f})",
        )

        # Launch all findings in this batch concurrently
        tasks = [
            _triage_single_finding(
                finding=finding,
                index=batch_start + j,
                total=total_findings,
                state=state,
                model=model,
                model_string=model_string,
                model_settings=model_settings,
                target_root=target_root,
                native_json=native_json,
            )
            for j, (sarif_idx, finding) in enumerate(batch)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results: write verdicts to canonical SARIF by index
        for j, result in enumerate(results):
            sarif_idx, finding = batch[j]
            if isinstance(result, Exception):
                rule_id = finding.get("ruleId", "unknown")
                failed += 1
                logger.error(
                    "agent.failed",
                    agent_name="triage",
                    finding_index=batch_start + j,
                    rule_id=rule_id,
                    error=str(result),
                    error_type=type(result).__name__,
                )
                if is_fatal_error(result):
                    raise result
            elif result is not None:
                completed += 1
                all_triaged.append(result)
                # Write verdict to the canonical SARIF results by index.
                # No shallow-copy dependency — direct write to state.sast_sarif.
                sarif_results[sarif_idx].setdefault("properties", {})["triage_verdict"] = result.verdict.value
            else:
                failed += 1

        # Report batch completion with running totals and timing
        confirmed = sum(1 for t in all_triaged if t.verdict.value == "CONFIRMED")
        fp = sum(1 for t in all_triaged if t.verdict.value == "FALSE_POSITIVE")
        needs_ctx = sum(1 for t in all_triaged if t.verdict.value == "NEEDS_CONTEXT")
        elapsed = time.monotonic() - t_start
        done_count = completed + failed
        if done_count > 0 and done_count < total_findings:
            avg = elapsed / done_count
            remaining = (total_findings - done_count) * avg
            eta = f" ~{int(remaining)}s left"
        else:
            eta = ""
        state.on_progress(
            3, "triage", "counter",
            f"[{done_count}/{total_findings}] "
            f"{confirmed} confirmed, {fp} FP, "
            f"{needs_ctx} needs context"
            f"{f', {failed} failed' if failed else ''}"
            f" ({int(elapsed)}s{eta}, ${state.cost_tracker.total_spent:.2f})",
        )

    if failed:
        state.degrade(Degradation(
            pass_name="triage", kind="triage_call_failed", subject="triage",
            detail=f"{failed} of {total_findings} triage calls failed — those findings remain Untriaged",
            count=failed,
        ))

    if all_triaged:
        state.triage_result = TriageResult(
            findings=all_triaged,
            total_confirmed=sum(1 for t in all_triaged if t.verdict.value == "CONFIRMED"),
            total_false_positive=sum(1 for t in all_triaged if t.verdict.value == "FALSE_POSITIVE"),
            total_needs_context=sum(1 for t in all_triaged if t.verdict.value == "NEEDS_CONTEXT"),
        )

    logger.info(
        "pipeline.pass_completed",
        pass_number=3,
        triaged=completed,
        failed=failed,
    )


async def _triage_single_finding(
    *,
    finding: dict,
    index: int,
    total: int,
    state: PipelineState,
    model: Model,
    model_string: str,
    model_settings: ModelSettings | None = None,
    target_root: str,
    native_json: bool = False,
) -> TriagedFinding | None:
    """Triage a single SAST finding. Returns TriagedFinding or None on failure.

    File content is read locally and inlined in the prompt — no tool calls.
    The caller writes the verdict back to state.sast_sarif by index.
    """
    rule_id = finding.get("ruleId", "unknown")
    file_path, line = get_result_location(finding, target_root=target_root)
    message = finding.get("message", {}).get("text", "")
    tool_name = finding.get("properties", {}).get("tool_name", "unknown")
    band = finding.get("properties", {}).get("priority_band", "LOW")

    # Read file locally and build context window (P14: no tool calls)
    file_content = read_file_content(state.target_path, file_path)
    if file_content is None:
        return None
    context = format_context_window(file_content, line)

    ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    prompt = (
        f"## Triage: {rule_id}\n\n"
        f"**Tool:** {tool_name}\n"
        f"**File:** {file_path}\n"
        f"**Line:** {line}\n"
        f"**Finding:** {message}\n\n"
        f"**Source code** (line {line} marked with >>>):\n"
        f"```{ext}\n{context}\n```\n\n"
        f"**Instructions:**\n"
        f"1. Examine the code at line {line} and surrounding context above\n"
        f"2. Determine if this specific finding is exploitable in context\n"
        f"3. Return a single TriagedFinding with verdict: CONFIRMED, FALSE_POSITIVE, or NEEDS_CONTEXT\n"
        f"4. Your rationale must explain WHY — not just repeat the tool message\n"
    )

    deps = SecurityReviewDeps(
        config=state.config,
        manifest=state.manifest,
        sast_sarif=state.sast_sarif,
        cost_tracker=state.cost_tracker,
        target_path=state.target_path,
        run_id=state.run_id,
        batch_id=f"triage-{index:03d}",
    )

    logger.debug(
        "triage.prompt_built",
        finding_index=index,
        file_path=file_path,
        line=line,
        prompt_chars=len(prompt),
        context_lines=context.count("\n") + 1,
    )

    logger.info(
        "agent.started",
        agent_name="triage",
        finding_index=index,
        priority_band=band,
        rule_id=rule_id,
        file_path=file_path,
        line=line,
    )

    # Native JSON providers: PydanticAI enforces the schema directly.
    # Prompted providers: append format instruction, parse the text response.
    if native_json:
        user_prompt = prompt
        output_type = TriagedFinding
    else:
        user_prompt = prompt + "\n\n" + TRIAGE_FORMAT_MARKDOWN
        output_type = str

    agent = build_triage_agent(state.config.llm.output_retries)
    result = await agent.run(
        user_prompt,
        deps=deps,
        model=model,
        model_settings=model_settings,
        output_type=output_type,
        usage_limits=UsageLimits(
            request_limit=2,
            total_tokens_limit=200_000,
        ),
    )

    # Record cost
    usage = result.usage()
    state.cost_tracker.record(
        agent_name="triage",
        batch_id=f"triage-{index:03d}",
        model_requested=model_string,
        tokens_in=usage.request_tokens or 0,
        tokens_out=usage.response_tokens or 0,
    )

    # Normalize output to TriagedFinding, always overriding identifiers (P13).
    output = result.output
    if isinstance(output, TriagedFinding):
        verdict = output.model_copy(update={
            "file_path": file_path,
            "line_number": line,
            "original_rule_id": rule_id,
            "original_tool": tool_name,
        })
    else:
        verdict = parse_triage_response(
            output,
            file_path=file_path,
            line_number=line,
            rule_id=rule_id,
            tool_name=tool_name,
            default_confidence=state.config.triage.default_confidence,
        )

    if verdict:
        logger.info(
            "agent.completed",
            agent_name="triage",
            finding_index=index,
            rule_id=rule_id,
            verdict=verdict.verdict.value,
        )

        if state.trace_enabled:
            write_trace(
                output_dir=state.output_dir,
                agent_name="triage",
                trace_id=f"triage-{index:03d}",
                prompt=prompt,
                result=result,
                output=verdict.model_dump(),
            )

        if state.ledger is not None:
            state.ledger.append("triage_verdict", index=index, rule_id=rule_id,
                                file=file_path, line=line, verdict=verdict.verdict.value,
                                cumulative_usd=round(state.cost_tracker.total_spent, 4))

        return verdict

    return None
