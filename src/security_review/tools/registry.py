"""Security tool specification and registry.

Tool specs are loaded from YAML files in tools/specs/.
The registry resolves which tools apply to a given file manifest.
"""
from __future__ import annotations

import fnmatch
import shutil
from enum import Enum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from security_review.errors import ConfigurationError

_SPECS_DIR = Path(__file__).resolve().parent / "specs"


class OutputFormat(str, Enum):
    SARIF = "sarif"
    JSON = "json"
    JSONL = "jsonl"


class OutputCapture(str, Enum):
    FILE = "file"
    STDOUT = "stdout"


class SecurityToolSpec(BaseModel, extra="forbid"):
    name: str
    binary: str
    version_cmd: list[str]
    output_format: OutputFormat
    sarif_native: bool
    success_exit_codes: list[int] = [0]
    arg_template: list[str]
    default_args: dict[str, str] = {}
    output_capture: OutputCapture = OutputCapture.FILE
    redact_output: bool = False
    timeout_seconds: int = 300
    applies_to: list[str] = []
    target_type: str = "directory"
    cwe_source: Literal["metadata", "rule_id_map", "mapping_file", "none"] = "metadata"
    optional: bool = False

    def build_command(self, target_path: str, output_path: str) -> list[str]:
        """Build the command list by substituting placeholders in arg_template."""
        subs = {
            "binary": self.binary,
            "target_path": target_path,
            "output_path": output_path,
            **self.default_args,
        }
        return [arg.format(**subs) for arg in self.arg_template]

    def is_available(self) -> bool:
        """Check if the tool binary is available on PATH."""
        return shutil.which(self.binary) is not None

    def matches_files(self, file_paths: list[str]) -> bool:
        """Check if any files in the list match this tool's applies_to patterns."""
        if not self.applies_to:
            return True  # tools with no filter run on everything

        for fp in file_paths:
            name = Path(fp).name
            for pattern in self.applies_to:
                if fnmatch.fnmatch(name, pattern):
                    return True
        return False


def load_tool_specs(specs_dir: Path | None = None) -> list[SecurityToolSpec]:
    """Load all tool spec YAML files from the specs directory."""
    directory = specs_dir or _SPECS_DIR
    if not directory.exists():
        raise ConfigurationError(
            f"Tool specs directory not found: {directory}",
            code="SYS_CONFIG_INVALID",
        )

    specs = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        with open(yaml_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data:
            specs.append(SecurityToolSpec.model_validate(data))
    return specs


def resolve_tools_for_manifest(
    specs: list[SecurityToolSpec],
    file_paths: list[str],
    require_available: bool = True,
) -> list[SecurityToolSpec]:
    """Filter tool specs to those applicable to the given files.

    If require_available is True, also checks that the binary exists on PATH.
    """
    resolved = []
    for spec in specs:
        if require_available and not spec.is_available():
            continue
        if spec.matches_files(file_paths):
            resolved.append(spec)
    return resolved
