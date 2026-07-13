"""Tests for context-overflow classification + halve-and-retry (Plan 019 WP-F)."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.profiles import ModelProfile

from security_review.checks import CWECheck
from security_review.config import load_config
from security_review.errors import is_context_overflow_error
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.holistic import _classify_result, _Outcome, run_holistic
from security_review.passes.state import PipelineState


# -- is_context_overflow_error truth table --------------------------------------


@pytest.mark.parametrize("message", [
    "context length exceeded for this model",
    "error: context_length_exceeded",
    "maximum context window is 200000 tokens",
    "prompt is too long: 210000 tokens",
    "Request too large for gpt-5.5",
    "you have hit the token limit",
    "input is too long for requested model",
    "the request exceeds the maximum allowed size",
])
def test_overflow_patterns_match(message: str):
    assert is_context_overflow_error(RuntimeError(message)) is True


def test_non_overflow_message_does_not_match():
    assert is_context_overflow_error(RuntimeError("rate limited")) is False


# -- _classify_result ------------------------------------------------------------


def _make_check(cwe_id: str = "999") -> CWECheck:
    return CWECheck(
        cwe_id=cwe_id, name="Test Check", detection="llm",
        file_types=[], check_prompt="Check for the test vulnerability.",
    )


def test_classify_result_overflow():
    outcome, findings, files = _classify_result(
        RuntimeError("prompt is too long: 210000 tokens"), _make_check(),
    )
    assert outcome == _Outcome.OVERFLOW
    assert findings == []
    assert files == []


def test_classify_result_non_overflow_exception_still_retry():
    outcome, _, _ = _classify_result(RuntimeError("rate limited"), _make_check())
    assert outcome == _Outcome.RETRY


# -- Holistic first-pass overflow handling ----------------------------------------


async def test_holistic_overflow_halves_files_and_retries(tmp_path: Path, monkeypatch):
    file_names = ["f1.py", "f2.py", "f3.py", "f4.py"]
    for name in file_names:
        (tmp_path / name).write_text(f"# {name}\nx = 1\n", encoding="utf-8")

    prompts_seen: list[str] = []

    def _respond(messages, info):
        prompt_text = " ".join(
            str(getattr(part, "content", ""))
            for message in messages for part in message.parts
        )
        prompts_seen.append(prompt_text)
        if len(prompts_seen) == 1:
            raise RuntimeError("prompt is too long: 210000 tokens")
        return ModelResponse(parts=[TextPart(content="No findings.")])

    monkeypatch.setattr(
        "security_review.passes.holistic.load_cwe_checks", lambda: [_make_check()],
    )
    # Prompted-mode profile: run_holistic must take the output_type=str +
    # markdown-parse path (FunctionModel's default profile claims native JSON).
    prompted_model = FunctionModel(_respond, profile=ModelProfile(
        supports_json_schema_output=False,
        default_structured_output_mode="prompted",
    ))
    monkeypatch.setattr(
        "security_review.passes.holistic.build_model",
        lambda model_string, llm_config: prompted_model,
    )
    monkeypatch.setattr(
        "security_review.passes.holistic.build_model_settings",
        lambda model_string, llm_config: None,
    )

    state = PipelineState(config=load_config(None), target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(
        files=[FileEntry(path=name, language="python", size_bytes=12,
                         security_weight=1, estimated_tokens=5) for name in file_names],
        total_files=4, total_tokens=20, languages={"python": 4},
    )
    state.sast_sarif = {"runs": []}

    await run_holistic(state)

    # The check completed on the halved retry.
    assert state.holistic_result is not None
    assert state.holistic_result.files_reviewed == ["f1.py", "f2.py"]

    # Exactly one files_omitted degradation from the overflow halving.
    omitted = [d for d in state.degradations if d.kind == "files_omitted"]
    assert len(omitted) == 1
    assert omitted[0].subject == "CWE-999"
    assert omitted[0].count == 2
    assert "context window" in omitted[0].detail

    # The retried call received fewer files (top half only).
    assert len(prompts_seen) == 2
    assert "f1.py" in prompts_seen[1] and "f2.py" in prompts_seen[1]
    assert "f3.py" not in prompts_seen[1] and "f4.py" not in prompts_seen[1]
