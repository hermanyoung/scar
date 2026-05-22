"""Integration tests for the triage agent using PydanticAI FunctionModel."""
from __future__ import annotations

import json

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel

from security_review.agents.deps import SecurityReviewDeps
from security_review.agents.triage.agent import triage_agent
from security_review.budget import CostTracker
from security_review.config_schema import SecurityReviewConfig
from security_review.models.findings import TriageResult, TriageVerdict
from security_review.models.inventory import FileEntry, FileManifest


@pytest.fixture
def mock_deps(tmp_path, sample_sarif):
    return SecurityReviewDeps(
        config=SecurityReviewConfig(),
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
    """Return a valid triage result that passes output validation."""
    return ModelResponse(parts=[TextPart(json.dumps({
        "findings": [{
            "original_rule_id": "B602",
            "original_tool": "bandit",
            "file_path": "app.py",
            "line_number": 13,
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
    """Verify triage agent produces valid TriageResult with FunctionModel."""
    model = FunctionModel(_mock_triage_response)
    with triage_agent.override(model=model):
        result = await triage_agent.run(
            "Triage these findings",
            deps=mock_deps,
            model=model,
        )
        assert isinstance(result.output, TriageResult)
        assert result.output.total_confirmed == 1
        assert result.output.findings[0].verdict == TriageVerdict.CONFIRMED
        assert (
            result.output.total_confirmed
            + result.output.total_false_positive
            + result.output.total_needs_context
            == len(result.output.findings)
        )
