"""PipelineState: mutable dataclass carrying inter-pass state.

Extracted to its own module so pass functions can import PipelineState
without circular dependencies (each pass no longer needs to defer-import
from pipeline.py).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from code_analysis.models import CallGraph
from security_review.budget import CostTracker
from security_review.checks import FileSelectionTelemetry
from security_review.config_schema import SecurityReviewConfig
from security_review.evidence import EvidenceManifest
from security_review.models.config_review import ConfigReviewResult
from security_review.models.coverage import CoverageReport
from security_review.models.degradation import Degradation
from security_review.models.findings import HolisticReviewResult, TriageResult
from security_review.reporting.common import ReportData
from security_review.models.inventory import FileManifest
from security_review.run_ledger import RunLedger
from security_review.sarif.types import SarifDocument

# Progress callback type: (pass_number, pass_name, status, detail)
ProgressCallback = Callable[[int, str, str, str], None]


def _noop_progress(pass_number: int, pass_name: str, status: str, detail: str) -> None:
    """Default no-op progress callback."""


@dataclass
class PassError:
    """A pass-level failure recorded by run_pipeline().

    Distinct from is_fatal_error()'s per-item/per-batch use inside each pass
    (triage.py, holistic.py, config_review.py already isolate individual
    finding/CWE/batch failures there). This records a failure that escaped
    an entire pass function, so the merge pass can still produce a report
    from whatever completed, and surface the failure visibly instead of the
    whole run silently producing nothing (Principle P6).
    """

    pass_name: str
    error: str
    error_type: str
    fatal: bool


@dataclass
class PipelineState:
    """Carries inter-pass state through the pipeline (7 passes in full mode).

    Created by cli.py, passed to each pass function, mutated in place.
    """

    config: SecurityReviewConfig
    target_path: Path
    work_dir: Path

    # Pass 1 outputs
    manifest: FileManifest | None = None
    coverage: CoverageReport | None = None

    # Pass 2 outputs
    sast_sarif: SarifDocument | None = None

    # Pass 3 outputs
    triage_result: TriageResult | None = None

    # Pass 4 outputs
    holistic_result: HolisticReviewResult | None = None

    # Call graph (built between Pass 3 and Pass 4, consumed by run_holistic's
    # file selection). None means graph-walk selection is unavailable —
    # run_holistic falls back to keyword-only selection, same as before this
    # existed.
    call_graph: CallGraph | None = None
    pagerank: dict[str, float] | None = None
    file_selection_telemetry: list[FileSelectionTelemetry] = field(default_factory=list)

    # Pass 5 outputs
    config_review_result: ConfigReviewResult | None = None

    # Cross-cutting
    run_id: str = field(default_factory=lambda: uuid4().hex[:12])
    cost_tracker: CostTracker = field(default_factory=CostTracker)
    evidence: EvidenceManifest = field(default_factory=EvidenceManifest)
    errors: list[PassError] = field(default_factory=list)
    degradations: list[Degradation] = field(default_factory=list)
    ledger: "RunLedger | None" = None

    # Progress reporting
    on_progress: ProgressCallback = field(default=_noop_progress)

    # Reporting (set by CLI, consumed by merge pass)
    report_formats: list[str] = field(default_factory=lambda: ["summary"])
    report_data: ReportData | None = None

    # Tracing (--trace flag)
    trace_enabled: bool = False

    # Checkpoint/resume (--resume flag): when True, run_pipeline skips passes
    # whose checkpoints were rehydrated by checkpoint.load_into().
    resume: bool = False

    # Streaming (--stream flag): write security-report.partial.sarif after
    # each LLM pass so a killed run still has a readable partial report.
    stream_enabled: bool = False

    @property
    def output_dir(self) -> Path:
        """The output directory for this run (where SARIF, reports, and traces go)."""
        return (self.work_dir / self.config.review.output_sarif).parent

    def degrade(self, d: Degradation) -> None:
        """Record a coverage degradation and mirror it to the run ledger."""
        self.degradations.append(d)
        if self.ledger is not None:
            # d.model_dump() itself has a "kind" key (Degradation.kind) that
            # would collide with append()'s own event-type "kind" positional
            # argument ("degradation") — rename it on the way into the ledger.
            fields = d.model_dump()
            degradation_kind = fields.pop("kind")
            self.ledger.append("degradation", degradation_kind=degradation_kind, **fields)
