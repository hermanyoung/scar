"""Pass 6: independent adversarial verification of LLM-discovered findings.

Pass 4 (holistic) and Pass 5 (config review) findings are net-new
discoveries by a single LLM call. Until this pass existed they went
straight to output auto-stamped CONFIRMED. This pass assigns each one an
independent TriageVerdict from a separate skeptic agent (plan 020):

  - The finder never grades its own work: a separate agent, fresh deps.
  - Only the artifact crosses the boundary: the verifier receives the
    claim (rule id, CWE, file, line, title) and freshly re-read source —
    never the finder's description/evidence/confidence/remediation
    (persuasion, not evidence — including them re-introduces anchoring).
  - Default to disbelief: the prompt instructs FALSE_POSITIVE unless the
    vulnerability is demonstrable in the provided code.
  - Reuses Pass 3's verdict semantics verbatim (TriagedFinding,
    parse_triage_response, TRIAGE_FORMAT_MARKDOWN) — no parallel model.

A finding this pass attempted but could not adjudicate is stamped
NEEDS_CONTEXT, never left None — an unverified finding must never fall
through merge's CONFIRMED default (§1.5.2). Refuted findings are kept and
scored low, never dropped (audit trail preserved).
"""
from __future__ import annotations

import asyncio

import structlog
from pydantic_ai import UsageLimits
from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings

from security_review.agents.deps import SecurityReviewDeps
from security_review.agents.verify.agent import build_verify_agent
from security_review.context_builder import format_context_window, read_file_content
from security_review.errors import is_fatal_error
from security_review.model_capabilities import supports_native_json, TRIAGE_FORMAT_MARKDOWN
from security_review.models.degradation import Degradation
from security_review.models.findings import BaseFinding, HolisticFinding, TriagedFinding
from security_review.model_settings import build_model_settings
from security_review.output_parser import parse_triage_response
from security_review.passes._batch import run_in_batches
from security_review.passes.state import PipelineState
from security_review.providers import build_model
from security_review.tracing import write_trace

logger = structlog.get_logger()


async def run_verification(state: PipelineState) -> None:
    """Execute Pass 6: assign an independent verdict to each LLM-discovered finding."""

    logger.info("pipeline.pass_started", pass_number=6, pass_name="verify")

    cfg = state.config.verification
    if not cfg.enabled:
        logger.info("verify.skipped", reason="verification.enabled is false")
        return
    if state.config.review.mode != "full":
        logger.info("verify.skipped", reason=f"mode is '{state.config.review.mode}', not 'full'")
        return

    # Collect findings to verify (holistic always if enabled; config opt-in).
    targets: list[BaseFinding] = []
    if cfg.verify_holistic and state.holistic_result:
        targets += state.holistic_result.findings
    if cfg.verify_config_review and state.config_review_result:
        targets += state.config_review_result.findings
    if not targets:
        logger.info("verify.skipped", reason="No LLM-discovered findings to verify")
        return

    model_string = cfg.model or state.config.llm.provider_model
    model = build_model(model_string, llm_config=state.config.llm)
    model_settings = build_model_settings(model_string, state.config.llm)
    native_json = supports_native_json(model)
    total = len(targets)

    state.on_progress(
        6, "verify", "tool",
        f"verifying {total} LLM finding(s), {cfg.samples} skeptic vote(s) each",
    )

    verified = 0
    unresolved = 0

    def _describe(batch, batch_start: int) -> str:
        return f"verifying finding {batch_start + 1}..."

    def _summarize() -> str:
        verdicts = [f.triage_verdict for f in targets if f.triage_verdict]
        return (
            f"{verdicts.count('CONFIRMED')} confirmed, "
            f"{verdicts.count('FALSE_POSITIVE')} FP, "
            f"{verdicts.count('NEEDS_CONTEXT')} needs context"
        )

    def _on_budget_exhausted(batch_start: int, remaining: int) -> None:
        nonlocal unresolved
        logger.warning(
            "verify.budget_exhausted",
            spent_usd=state.cost_tracker.total_spent,
            verified=batch_start,
            remaining=remaining,
        )
        # An unverified finding must never auto-confirm (§1.5.2): the
        # findings the budget cut off are explicitly stamped NEEDS_CONTEXT.
        for finding in targets[batch_start:]:
            finding.triage_verdict = "NEEDS_CONTEXT"
            unresolved += 1
        state.degrade(Degradation(
            pass_name="verify", kind="budget_exhausted", subject="verify",
            detail=f"budget reached after {batch_start} of {total} findings — "
                   f"{remaining} findings NOT verified (stamped NEEDS_CONTEXT)",
            count=remaining,
        ))
        state.on_progress(6, "verify", "tool",
                          f"budget exhausted — {remaining} of {total} findings not verified")

    def _make_coro(finding: BaseFinding, index: int):
        return _verify_single_finding(
            finding=finding,
            index=index,
            state=state,
            model=model,
            model_string=model_string,
            model_settings=model_settings,
            native_json=native_json,
            samples=cfg.samples,
        )

    def _on_result(finding: BaseFinding, index: int, result) -> None:
        nonlocal verified, unresolved
        if isinstance(result, Exception):
            # Fatal errors are re-raised by run_in_batches after this returns;
            # non-fatal exceptions are handled per-sample inside the coroutine
            # and only reach here if the coroutine itself broke.
            verdict, reason = None, f"{type(result).__name__}: {result}"
            logger.error(
                "agent.failed",
                agent_name="verify",
                finding_index=index,
                rule_id=finding.rule_id,
                error=str(result),
                error_type=type(result).__name__,
            )
        else:
            verdict, reason = result

        if verdict is None:
            # Attempted but not adjudicated -> NEEDS_CONTEXT, never None (§1.5.2).
            finding.triage_verdict = "NEEDS_CONTEXT"
            unresolved += 1
            logger.warning(
                "verify.unresolved",
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                reason=reason,
            )
            state.degrade(Degradation(
                pass_name="verify", kind="check_failed", subject=finding.rule_id,
                detail=f"verification could not adjudicate {finding.rule_id} "
                       f"({reason}) — verdict set to NEEDS_CONTEXT",
                count=1,
            ))
        else:
            finding.triage_verdict = verdict
            verified += 1
            logger.info(
                "agent.completed",
                agent_name="verify",
                finding_index=index,
                rule_id=finding.rule_id,
                verdict=verdict,
            )

        if state.ledger is not None:
            state.ledger.append("verify_verdict", rule_id=finding.rule_id,
                                verdict=finding.triage_verdict,
                                cumulative_usd=round(state.cost_tracker.total_spent, 4))

    await run_in_batches(
        targets,
        state=state,
        pass_number=6,
        pass_name="verify",
        make_coro=_make_coro,
        on_result=_on_result,
        describe=_describe,
        summarize=_summarize,
        on_budget_exhausted=_on_budget_exhausted,
    )

    logger.info(
        "pipeline.pass_completed",
        pass_number=6,
        verified=verified,
        unresolved=unresolved,
    )


async def _verify_single_finding(
    *,
    finding: BaseFinding,
    index: int,
    state: PipelineState,
    model: Model,
    model_string: str,
    model_settings: ModelSettings | None,
    native_json: bool,
    samples: int,
) -> tuple[str | None, str | None]:
    """Verify one finding with `samples` concurrent skeptic votes.

    Returns (verdict_value, None) on success, or (None, reason) when the
    finding could not be adjudicated (file_unreadable / all_samples_failed).
    Fatal sample errors are re-raised. The caller writes the verdict back —
    this function never mutates the finding (P13-style bookkeeping in code).
    """
    prompt = _build_verify_prompt(finding, state)
    if prompt is None:
        return None, "file_unreadable"

    tool_name = "holistic" if isinstance(finding, HolisticFinding) else "config-review"

    calls = [
        _run_verify_sample(
            finding=finding,
            index=index,
            sample=k,
            prompt=prompt,
            state=state,
            model=model,
            model_string=model_string,
            model_settings=model_settings,
            native_json=native_json,
            tool_name=tool_name,
        )
        for k in range(samples)
    ]
    results = await asyncio.gather(*calls, return_exceptions=True)

    votes: list[str] = []
    for k, res in enumerate(results):
        if isinstance(res, Exception):
            if is_fatal_error(res):
                raise res
            # A failed sample counts as a non-vote (§1.6).
            logger.warning(
                "verify.sample_failed",
                rule_id=finding.rule_id,
                finding_index=index,
                sample=k,
                error=str(res),
                error_type=type(res).__name__,
            )
        elif res is not None:
            votes.append(res)

    if not votes:
        return None, "all_samples_failed"
    return _aggregate_votes(votes, samples), None


async def _run_verify_sample(
    *,
    finding: BaseFinding,
    index: int,
    sample: int,
    prompt: str,
    state: PipelineState,
    model: Model,
    model_string: str,
    model_settings: ModelSettings | None,
    native_json: bool,
    tool_name: str,
) -> str | None:
    """Run one skeptic call. Returns the verdict value, or None on parse failure."""
    deps = SecurityReviewDeps(
        config=state.config,
        manifest=state.manifest,
        sast_sarif=state.sast_sarif or {"runs": []},
        cost_tracker=state.cost_tracker,
        target_path=state.target_path,
        run_id=state.run_id,
        batch_id=f"verify-{index:03d}",
    )

    # Native JSON providers: PydanticAI enforces the schema directly.
    # Prompted providers: append Pass 3's format instruction, parse the text.
    if native_json:
        user_prompt = prompt
        output_type = TriagedFinding
    else:
        user_prompt = prompt + "\n\n" + TRIAGE_FORMAT_MARKDOWN
        output_type = str

    agent = build_verify_agent(state.config.llm.output_retries)
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

    # Record cost for every call, including extra samples.
    usage = result.usage()
    state.cost_tracker.record(
        agent_name="verify",
        batch_id=f"verify-{index:03d}",
        model_requested=model_string,
        tokens_in=usage.input_tokens or 0,
        tokens_out=usage.output_tokens or 0,
    )

    # Normalize output, always overriding identifiers with known-correct
    # values from the finding (P13) — the verifier only reads the location.
    output = result.output
    if isinstance(output, TriagedFinding):
        verdict = output.model_copy(update={
            "file_path": finding.file_path,
            "line_number": finding.line_number or 1,
            "original_rule_id": finding.rule_id,
            "original_tool": tool_name,
        })
    else:
        verdict = parse_triage_response(
            output,
            file_path=finding.file_path,
            line_number=finding.line_number or 1,  # file-level findings use 1
            rule_id=finding.rule_id,
            tool_name=tool_name,
            default_confidence=state.config.triage.default_confidence,
        )

    if verdict is None:
        logger.warning(
            "verify.parse_failed",
            rule_id=finding.rule_id,
            finding_index=index,
            sample=sample,
        )
        return None

    if state.trace_enabled:
        write_trace(
            output_dir=state.output_dir,
            agent_name="verify",
            trace_id=f"verify-{index:03d}-s{sample}",
            prompt=prompt,
            result=result,
            output=verdict.model_dump(),
        )

    return verdict.verdict.value


def _aggregate_votes(votes: list[str], samples: int) -> str:
    """Aggregate skeptic votes conservatively (§1.6).

    CONFIRMED only on a strict majority of the *requested* samples — a
    failed sample is a non-vote and makes confirmation harder, never easier.
    """
    if samples == 1:
        return votes[0]
    if votes.count("CONFIRMED") * 2 > samples:
        return "CONFIRMED"
    if "FALSE_POSITIVE" in votes:
        return "FALSE_POSITIVE"
    return "NEEDS_CONTEXT"


def _build_verify_prompt(finding: BaseFinding, state: PipelineState) -> str | None:
    """Build the anti-anchoring prompt: ONLY the claim + freshly re-read code.

    finding.description / evidence / confidence / remediation are DELIBERATELY
    excluded — they are the finder's persuasion, and including them
    re-introduces anchoring (design principle 2). Returns None when the
    finding's file cannot be resolved or read (-> NEEDS_CONTEXT, no LLM call).
    """
    if not finding.file_path or finding.file_path == "unknown":
        return None
    file_content = read_file_content(state.target_path, finding.file_path)
    if file_content is None:
        return None

    context = format_context_window(file_content, finding.line_number or 1)
    ext = finding.file_path.rsplit(".", 1)[-1] if "." in finding.file_path else ""
    return (
        f"## Verify claimed vulnerability\n\n"
        f"**Claimed class:** {finding.cwe_id or 'unspecified'} — {finding.title}\n"
        f"**File:** {finding.file_path}\n"
        f"**Line:** {finding.line_number or '(file-level)'}\n\n"
        f"**Source code** (line marked with >>>):\n```{ext}\n{context}\n```\n\n"
        f"**Instructions:**\n"
        f"1. Determine independently whether {finding.cwe_id or 'this vulnerability'} "
        f"is demonstrable in the code above.\n"
        f"2. Default to FALSE_POSITIVE. Cite specific lines in your rationale.\n"
        f"3. Return verdict, confidence, and rationale.\n"
    )
