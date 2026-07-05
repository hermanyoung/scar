"""Integration tests for the triage agent using PydanticAI FunctionModel.

Per ADR-004, agents use output_type=str — the agent never returns a
validated TriagedFinding/TriageResult directly. Parsing into TriagedFinding
happens downstream via output_parser.parse_triage_response(), which is what
passes/triage.py actually calls after triage_agent.run(). These tests
exercise that same two-step contract, not the raw agent output.
"""
from __future__ import annotations

import json

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel

from security_review.agents.deps import SecurityReviewDeps
from security_review.agents.triage.agent import triage_agent
from security_review.budget import CostTracker
from security_review.config import load_config
from security_review.models.findings import TriageVerdict
from security_review.models.inventory import FileEntry, FileManifest
from security_review.output_parser import parse_triage_response


@pytest.fixture
def mock_deps(tmp_path, sample_sarif):
    return SecurityReviewDeps(
        config=load_config(),
        manifest=FileManifest(
            files=[
                FileEntry(
                    path="app.py",
                    language="python",
                    size_bytes=500,
                    security_weight=5,
                    estimated_tokens=125,
                )
            ],
            total_files=1,
            total_tokens=125,
            languages={"python": 1},
        ),
        sast_sarif=sample_sarif,
        cost_tracker=CostTracker(),
        target_path=tmp_path,
        run_id="test-run-001",
        batch_id="batch-000",
    )


def _mock_triage_response(messages, info):
    """Simulate a prompted-provider response: JSON wrapped in a "findings" list,
    with echoed identifiers that deliberately differ from the caller's
    ground truth — this proves parse_triage_response overrides them (P13)
    rather than trusting whatever the LLM echoes back.
    """
    return ModelResponse(parts=[TextPart(json.dumps({
        "findings": [{
            "original_rule_id": "WRONG-RULE-ID",
            "original_tool": "wrong-tool",
            "file_path": "wrong_file.py",
            "line_number": 999,
            "verdict": "CONFIRMED",
            "confidence": 0.95,
            "rationale": "subprocess.call with shell=True and user input is exploitable via command injection",
        }],
        "total_confirmed": 1,
        "total_false_positive": 0,
        "total_needs_context": 0,
    }))])


@pytest.mark.asyncio
async def test_triage_agent_output_validates(mock_deps):
    """Verify the agent -> output_parser pipeline used by passes/triage.py.

    The agent itself returns output_type=str (ADR-004) — this test asserts
    that raw text contract, then verifies parse_triage_response() extracts a
    valid TriagedFinding from it with the caller's ground-truth identifiers
    (file_path, line_number, rule_id, tool_name) overriding the LLM-echoed
    ones, per Principle P13.
    """
    model = FunctionModel(_mock_triage_response)
    with triage_agent.override(model=model):
        result = await triage_agent.run(
            "Triage these findings",
            deps=mock_deps,
            model=model,
        )
        assert isinstance(result.output, str)

        finding = parse_triage_response(
            result.output,
            file_path="app.py",
            line_number=13,
            rule_id="B602",
            tool_name="bandit",
            default_confidence=0.5,
        )

        assert finding is not None
        assert finding.verdict == TriageVerdict.CONFIRMED
        assert finding.confidence == 0.95
        # Ground-truth identifiers override the LLM-echoed values (P13).
        assert finding.file_path == "app.py"
        assert finding.line_number == 13
        assert finding.original_rule_id == "B602"
        assert finding.original_tool == "bandit"
