"""Golden fixture regression tests.

Runs CWE detection against a reference target and compares results
to the golden baseline in config/golden/example-target.yaml.

These tests make real LLM calls — run separately from unit tests:

    pytest tests/regression/ -v                                    # all providers in golden
    pytest tests/regression/ -v -k "copilot"                       # single provider
    pytest tests/regression/ -v --provider copilot:claude-opus     # explicit provider
    pytest tests/regression/ -v --target /path/to/repo             # different target

To update the golden baseline after a verified improvement:

    pytest tests/regression/ -v --save-golden
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent.parent
SCAR_PY = PROJECT_ROOT / "scar.py"
DEFAULT_GOLDEN = PROJECT_ROOT / "config" / "golden" / "example-target.yaml"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def golden_data(request: pytest.FixtureRequest) -> dict:
    path = Path(request.config.getoption("--golden-file"))
    if not path.exists():
        pytest.skip(f"Golden file not found: {path}")
    with open(path) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def target_path(request: pytest.FixtureRequest) -> str:
    target = request.config.getoption("--target")
    if not Path(target).exists():
        pytest.skip(f"Target not found: {target}")
    return target


@pytest.fixture(scope="session")
def selected_provider(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--provider")


@pytest.fixture(scope="session")
def save_golden_flag(request: pytest.FixtureRequest) -> bool:
    return request.config.getoption("--save-golden")


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------


def _run_test_cwe(cwe_id: str, target: str, provider: str) -> tuple[int, list[str], str | None]:
    """Run scar.py test-cwe and return (finding_count, findings, error)."""
    cmd = [sys.executable, str(SCAR_PY), "test-cwe", cwe_id, target, "--provider", provider]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return 0, [], "timeout (180s)"

    if proc.returncode != 0:
        err_lines = [line for line in proc.stderr.splitlines() if line.strip()]
        return 0, [], err_lines[-1] if err_lines else proc.stderr[:200]

    count_match = re.search(r"Findings:\s*(\d+)", proc.stdout)
    finding_count = int(count_match.group(1)) if count_match else 0
    findings = re.findall(r"\[Severity\.\w+\]\s+(.+)", proc.stdout)
    return finding_count, findings, None


# ---------------------------------------------------------------------------
# Parametrised test — one test per (CWE, provider)
# ---------------------------------------------------------------------------


def _collect_test_cases(golden_path: Path, provider_filter: str) -> list[tuple[str, str, dict]]:
    """Build list of (cwe_id, provider, golden_entry) from golden file."""
    if not golden_path.exists():
        return []
    with open(golden_path) as f:
        data = yaml.safe_load(f)

    cases = []
    for cwe_id, cwe_entry in data.get("cwes", {}).items():
        golden_providers = cwe_entry.get("golden", {})
        for provider, g in golden_providers.items():
            if provider_filter and provider_filter != provider:
                continue
            cases.append((cwe_id, provider, g))
    return cases


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Dynamically parametrise test_golden_cwe from the golden YAML."""
    if "cwe_id" not in metafunc.fixturenames:
        return

    golden_path = Path(metafunc.config.getoption("--golden-file", str(DEFAULT_GOLDEN)))
    provider_filter = metafunc.config.getoption("--provider", "")

    cases = _collect_test_cases(golden_path, provider_filter)
    if not cases:
        return

    ids = [f"CWE-{cwe}-{prov.replace(':', '_')}" for cwe, prov, _ in cases]
    metafunc.parametrize(
        "cwe_id,provider,golden_entry",
        cases,
        ids=ids,
    )


def test_golden_cwe(
    cwe_id: str,
    provider: str,
    golden_entry: dict,
    golden_data: dict,
    target_path: str,
    save_golden_flag: bool,
) -> None:
    """Check that a CWE detection result matches or exceeds the golden baseline."""
    cwe_config = golden_data["cwes"][cwe_id]
    min_findings = cwe_config.get("min_findings", 1)
    golden_pass = golden_entry.get("pass", False)
    golden_findings = golden_entry.get("findings", 0)

    finding_count, findings, error = _run_test_cwe(cwe_id, target_path, provider)

    now_pass = error is None and finding_count >= min_findings

    # Update golden if --save-golden and this run passed
    if save_golden_flag and now_pass:
        golden_entry["pass"] = True
        golden_entry["findings"] = finding_count
        golden_path = Path(DEFAULT_GOLDEN)
        with open(golden_path) as f:
            data = yaml.safe_load(f)
        data["cwes"][cwe_id]["golden"][provider] = {
            "pass": True,
            "findings": finding_count,
        }
        with open(golden_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    # Assertion
    if error:
        if golden_pass:
            pytest.fail(
                f"REGRESSION: CWE-{cwe_id} [{provider}] errored but golden was PASS. "
                f"Error: {error}"
            )
        else:
            pytest.skip(f"CWE-{cwe_id} [{provider}] errored (golden was also FAIL): {error}")

    if golden_pass and not now_pass:
        pytest.fail(
            f"REGRESSION: CWE-{cwe_id} [{provider}] was PASS ({golden_findings} findings), "
            f"now FAIL ({finding_count} findings, need {min_findings}+)"
        )

    if not golden_pass and now_pass:
        # Improvement — pass but flag it
        pass

    # Golden was FAIL and still FAIL — expected, not a regression
    if not golden_pass and not now_pass:
        pytest.xfail(
            f"CWE-{cwe_id} [{provider}] known gap: {finding_count} findings "
            f"(need {min_findings}+, golden had {golden_findings})"
        )
