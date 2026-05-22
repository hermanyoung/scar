#!/usr/bin/env python3
"""Provider compatibility test suite.

Tests each provider + model combination against three checks:
  1. Simple structured output (no tools)
  2. Agent with tools + structured output
  3. Complex multi-finding response matching real pipeline schemas

Usage:
    python scripts/test_providers.py                          # all available providers
    python scripts/test_providers.py copilot:claude-opus-4.6  # specific model
    python scripts/test_providers.py --copilot                # all copilot models
    python scripts/test_providers.py --api                    # openai + anthropic (needs keys)
    python scripts/test_providers.py --all                    # everything
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_ai import Agent, RunContext

# ---------------------------------------------------------------------------
# Ensure config/.env is loaded for API key providers
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# Test 1: Simple schema
# ---------------------------------------------------------------------------

class SimpleResult(BaseModel):
    answer: str
    confidence: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Test 2: Tool agent with single finding
# ---------------------------------------------------------------------------

class SingleFinding(BaseModel):
    rule_id: str
    file_path: str
    line_number: int = Field(ge=1)
    verdict: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class SingleTriageOutput(BaseModel):
    findings: list[SingleFinding] = Field(min_length=1)
    total_confirmed: int = Field(ge=0)


@dataclass
class ToolTestDeps:
    file_content: str = "import os\nos.system(user_input)  # CWE-78\n"


tool_agent = Agent(
    output_type=SingleTriageOutput,
    system_prompt=(
        "You are a security reviewer. Triage the SAST finding. "
        "Use the read_file tool to read the source, then return your verdict."
    ),
    retries=2,
    deps_type=ToolTestDeps,
)


@tool_agent.tool
async def read_file(ctx: RunContext[ToolTestDeps], file_path: str) -> str:
    """Read a source file."""
    return ctx.deps.file_content


# ---------------------------------------------------------------------------
# Test 3: Complex multi-finding response (matches real pipeline schemas)
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class TriageVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_CONTEXT = "NEEDS_CONTEXT"


class TriagedFinding(BaseModel):
    original_rule_id: str
    original_tool: str
    file_path: str
    line_number: int = Field(ge=1)
    verdict: TriageVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1)

    @field_validator("confidence", mode="before")
    @classmethod
    def normalise_confidence(cls, v) -> float:
        if isinstance(v, (int, float)) and v > 1.0:
            return v / 100.0
        return float(v)


class ComplexTriageResult(BaseModel):
    findings: list[TriagedFinding] = Field(min_length=1)
    total_confirmed: int = Field(ge=0)
    total_false_positive: int = Field(ge=0)
    total_needs_context: int = Field(ge=0)


VULNERABLE_CODE = '''import subprocess
import os
import sqlite3

PASSWORD = "SuperSecret123!"  # Line 4: CWE-798

def run_cmd(user_input):
    subprocess.call(user_input, shell=True)  # Line 8: CWE-78

def query_db(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # Line 13: CWE-89
    return cursor.fetchall()

def process(expr):
    return eval(expr)  # Line 17: CWE-94
'''

COMPLEX_PROMPT = f"""Triage these 4 SAST findings. For each one, determine if it is CONFIRMED, FALSE_POSITIVE, or NEEDS_CONTEXT.

Findings:
1. [bandit] B105 at app.py:4 — Hardcoded password string
2. [bandit] B602 at app.py:8 — subprocess.call with shell=True
3. [bandit] B608 at app.py:13 — SQL injection via string formatting
4. [bandit] B307 at app.py:17 — Use of eval() detected

Source code of app.py:
```python
{VULNERABLE_CODE}
```

Return a TriageResult with exactly 4 findings, one per SAST finding above.
"""

@dataclass
class ComplexDeps:
    pass

complex_agent = Agent(
    output_type=ComplexTriageResult,
    system_prompt=(
        "You are a security code reviewer performing triage on static analysis findings. "
        "For each finding, determine if it is CONFIRMED, FALSE_POSITIVE, or NEEDS_CONTEXT. "
        "Provide a confidence score (0.0-1.0) and rationale for each."
    ),
    retries=3,
    deps_type=ComplexDeps,
)

@complex_agent.output_validator
async def fix_totals(ctx: RunContext[ComplexDeps], output: ComplexTriageResult) -> ComplexTriageResult:
    """Auto-repair totals — same as the real pipeline."""
    output.total_confirmed = sum(1 for f in output.findings if f.verdict == TriageVerdict.CONFIRMED)
    output.total_false_positive = sum(1 for f in output.findings if f.verdict == TriageVerdict.FALSE_POSITIVE)
    output.total_needs_context = sum(1 for f in output.findings if f.verdict == TriageVerdict.NEEDS_CONTEXT)
    return output


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

COPILOT_MODELS = [
    "copilot:claude-opus-4.6",
    "copilot:claude-sonnet-4.6",
    "copilot:claude-sonnet-4.5",
    "copilot:claude-haiku-4.5",
    "copilot:gpt-5.4",
    "copilot:gpt-5.4-mini",
]

CODEX_MODELS = [
    "codex:gpt-5.5",
    "codex:gpt-5.4",
]

API_MODELS = [
    "openai:gpt-4.1",
    "anthropic:claude-sonnet-4-6",
]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    provider_model: str
    test_name: str
    passed: bool
    duration_ms: int
    output: str
    error: str = ""


async def run_test(name: str, coro) -> TestResult:
    start = time.monotonic()
    try:
        result = await coro
        duration = int((time.monotonic() - start) * 1000)
        return TestResult(
            provider_model=result[0],
            test_name=name,
            passed=True,
            duration_ms=duration,
            output=result[1],
        )
    except Exception as e:
        duration = int((time.monotonic() - start) * 1000)
        return TestResult(
            provider_model="",
            test_name=name,
            passed=False,
            duration_ms=duration,
            output="",
            error=str(e)[:200],
        )


async def test_simple(model_string: str) -> tuple[str, str]:
    from security_review.providers import build_model
    agent = Agent(output_type=SimpleResult, retries=2)
    model = build_model(model_string)
    result = await agent.run("What is 2+2? Return answer and confidence.", model=model)
    return (model_string, f"answer={result.output.answer!r} conf={result.output.confidence}")


async def test_tools(model_string: str) -> tuple[str, str]:
    from security_review.providers import build_model
    model = build_model(model_string)
    deps = ToolTestDeps()
    result = await tool_agent.run(
        "Triage: [bandit] B605 at app.py:2 — os.system() with user input. Use read_file to check.",
        model=model, deps=deps,
    )
    f = result.output.findings[0]
    return (model_string, f"findings={len(result.output.findings)} verdict={f.verdict} conf={f.confidence}")


async def test_complex(model_string: str) -> tuple[str, str]:
    from security_review.providers import build_model
    model = build_model(model_string)
    deps = ComplexDeps()
    result = await complex_agent.run(COMPLEX_PROMPT, model=model, deps=deps)
    out = result.output
    verdicts = [f.verdict.value for f in out.findings]
    return (
        model_string,
        f"findings={len(out.findings)} confirmed={out.total_confirmed} "
        f"fp={out.total_false_positive} verdicts={verdicts}",
    )


TESTS = [
    ("simple_output", test_simple),
    ("tool_agent", test_tools),
    ("complex_triage", test_complex),
]


async def run_all(models: list[str]) -> list[TestResult]:
    results: list[TestResult] = []

    for model_string in models:
        print(f"\n{'='*70}")
        print(f"  {model_string}")
        print(f"{'='*70}")

        for i, (name, test_fn) in enumerate(TESTS, 1):
            label = f"  [{i}/{len(TESTS)}] {name}"
            print(f"{label:<35} ...", end=" ", flush=True)

            start = time.monotonic()
            try:
                model_str, output = await test_fn(model_string)
                duration = int((time.monotonic() - start) * 1000)
                r = TestResult(model_string, name, True, duration, output)
                print(f"PASS ({duration:>6}ms)  {output}")
            except Exception as e:
                duration = int((time.monotonic() - start) * 1000)
                error = str(e)[:120]
                r = TestResult(model_string, name, False, duration, "", error)
                print(f"FAIL ({duration:>6}ms)  {error}")

            results.append(r)

    return results


def print_summary(results: list[TestResult]) -> None:
    print(f"\n{'='*70}")
    print("  COMPATIBILITY MATRIX")
    print(f"{'='*70}")
    print(f"  {'Provider:Model':<35} {'Simple':>8} {'Tools':>8} {'Complex':>8}")
    print(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*8}")

    models = []
    seen = set()
    for r in results:
        if r.provider_model not in seen:
            models.append(r.provider_model)
            seen.add(r.provider_model)

    for model in models:
        model_results = {r.test_name: r for r in results if r.provider_model == model}
        cols = []
        for name, _, _ in [("simple_output", None, None), ("tool_agent", None, None), ("complex_triage", None, None)]:
            r = model_results.get(name)
            if r is None:
                cols.append("  --  ")
            elif r.passed:
                cols.append(f"  PASS")
            else:
                cols.append(f"  FAIL")
        print(f"  {model:<35} {''.join(cols)}")

    total_passed = sum(1 for r in results if r.passed)
    total = len(results)
    print(f"\n  Total: {total_passed}/{total} passed")


def resolve_models(args: list[str]) -> list[str]:
    """Resolve CLI args to model list."""
    if not args:
        return COPILOT_MODELS

    models = []
    for arg in args:
        if arg == "--copilot":
            models.extend(COPILOT_MODELS)
        elif arg == "--codex":
            models.extend(CODEX_MODELS)
        elif arg == "--api":
            models.extend(API_MODELS)
        elif arg == "--all":
            models.extend(COPILOT_MODELS + CODEX_MODELS + API_MODELS)
        elif ":" in arg:
            models.append(arg)
        else:
            print(f"Unknown arg: {arg}")
            print("Usage: test_providers.py [--copilot] [--codex] [--api] [--all] [provider:model ...]")
            sys.exit(2)

    return models


def main():
    models = resolve_models(sys.argv[1:])

    print("Security Review — Provider Compatibility Test")
    print(f"Testing {len(models)} provider:model combinations x {len(TESTS)} tests\n")

    results = asyncio.run(run_all(models))
    print_summary(results)

    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
