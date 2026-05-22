"""Unit tests for priority.py — the finding priority scoring module.

Tests the composite priority formula: severity x confidence x exposure.
Covers edge cases: false positives, unknown files, missing exposure index,
all detection methods, all SARIF levels, and band thresholds.
"""
from __future__ import annotations

import pytest

from security_review.models.inventory import FileEntry, FileManifest
from security_review.priority import (
    PriorityScore,
    build_exposure_index,
    score_finding,
)


# ---------------------------------------------------------------------------
# score_finding — severity component
# ---------------------------------------------------------------------------

def test_severity_error_is_1_0():
    score = score_finding(level="error", file_path="x.py", exposure_index={})
    assert score.severity_score == 1.0


def test_severity_warning_is_0_6():
    score = score_finding(level="warning", file_path="x.py", exposure_index={})
    assert score.severity_score == 0.6


def test_severity_note_is_0_3():
    score = score_finding(level="note", file_path="x.py", exposure_index={})
    assert score.severity_score == 0.3


def test_severity_none_is_0_1():
    score = score_finding(level="none", file_path="x.py", exposure_index={})
    assert score.severity_score == 0.1


def test_severity_unknown_level_defaults_to_0_3():
    score = score_finding(level="banana", file_path="x.py", exposure_index={})
    assert score.severity_score == 0.3


# ---------------------------------------------------------------------------
# score_finding — confidence component
# ---------------------------------------------------------------------------

def test_confidence_confirmed():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        triage_verdict="CONFIRMED",
    )
    assert score.confidence_score == 1.0
    assert score.confidence_label == "confirmed"


def test_confidence_false_positive_is_zero():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        triage_verdict="FALSE_POSITIVE",
    )
    assert score.confidence_score == 0.0
    assert score.priority == 0.0


def test_confidence_needs_context():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        triage_verdict="NEEDS_CONTEXT",
    )
    assert score.confidence_score == 0.5
    assert score.confidence_label == "needs_context"


def test_confidence_sast_only():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        detection_method="sast_only",
    )
    assert score.confidence_score == 0.7
    assert score.confidence_label == "sast_only"


def test_confidence_llm_only():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        detection_method="llm_only",
    )
    assert score.confidence_score == 0.8
    assert score.confidence_label == "llm_only"


def test_confidence_sast_plus_llm():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        detection_method="sast+llm",
    )
    assert score.confidence_score == 0.9


def test_confidence_unvalidated():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        detection_method="unvalidated",
    )
    assert score.confidence_score == 0.6


def test_confidence_unknown_detection_method():
    score = score_finding(
        level="error", file_path="x.py", exposure_index={},
        detection_method="magic",
    )
    assert score.confidence_score == 0.6  # default for unknown


# ---------------------------------------------------------------------------
# score_finding — exposure component
# ---------------------------------------------------------------------------

def test_exposure_from_index():
    idx = {"src/controllers/user.py": 0.8}
    score = score_finding(level="error", file_path="src/controllers/user.py", exposure_index=idx)
    assert score.exposure_score == 0.8


def test_exposure_unknown_file_defaults_to_0_3():
    score = score_finding(level="error", file_path="unknown.py", exposure_index={})
    assert score.exposure_score == 0.3


def test_exposure_empty_index_defaults_to_0_3():
    score = score_finding(level="error", file_path="any.py", exposure_index={})
    assert score.exposure_score == 0.3


# ---------------------------------------------------------------------------
# score_finding — composite priority
# ---------------------------------------------------------------------------

def test_priority_formula():
    """priority = severity * confidence * exposure."""
    idx = {"api.py": 0.8}
    score = score_finding(
        level="error", file_path="api.py", exposure_index=idx,
        triage_verdict="CONFIRMED",
    )
    expected = round(1.0 * 1.0 * 0.8, 3)
    assert score.priority == expected


def test_priority_false_positive_always_zero():
    idx = {"api.py": 1.0}
    score = score_finding(
        level="error", file_path="api.py", exposure_index=idx,
        triage_verdict="FALSE_POSITIVE",
    )
    assert score.priority == 0.0


# ---------------------------------------------------------------------------
# PriorityScore.band — threshold tests
# ---------------------------------------------------------------------------

def test_band_urgent():
    score = PriorityScore(
        priority=0.70, severity_score=1.0, confidence_score=1.0,
        exposure_score=0.7, confidence_label="confirmed",
    )
    assert score.band == "URGENT"


def test_band_elevated():
    score = PriorityScore(
        priority=0.40, severity_score=0.6, confidence_score=0.8,
        exposure_score=0.5, confidence_label="llm_only",
    )
    assert score.band == "ELEVATED"


def test_band_moderate():
    score = PriorityScore(
        priority=0.20, severity_score=0.6, confidence_score=0.7,
        exposure_score=0.3, confidence_label="sast_only",
    )
    assert score.band == "MODERATE"


def test_band_low():
    score = PriorityScore(
        priority=0.19, severity_score=0.3, confidence_score=0.7,
        exposure_score=0.3, confidence_label="sast_only",
    )
    assert score.band == "LOW"


def test_band_zero():
    score = PriorityScore(
        priority=0.0, severity_score=0.0, confidence_score=0.0,
        exposure_score=0.0, confidence_label="false_positive",
    )
    assert score.band == "LOW"


# ---------------------------------------------------------------------------
# build_exposure_index
# ---------------------------------------------------------------------------

def test_build_exposure_index_maps_security_weight():
    manifest = FileManifest(
        files=[
            FileEntry(path="controller.py", language="python", size_bytes=100,
                      security_weight=8, estimated_tokens=25),
            FileEntry(path="utils.py", language="python", size_bytes=50,
                      security_weight=2, estimated_tokens=12),
        ],
        total_files=2,
        total_tokens=37,
        languages={"python": 2},
    )
    idx = build_exposure_index(manifest)
    assert idx["controller.py"] == pytest.approx(0.8)
    assert idx["utils.py"] == pytest.approx(0.2)


def test_build_exposure_index_clamps_minimum_to_0_1():
    manifest = FileManifest(
        files=[
            FileEntry(path="dead.py", language="python", size_bytes=10,
                      security_weight=0, estimated_tokens=2),
        ],
        total_files=1,
        total_tokens=2,
        languages={"python": 1},
    )
    idx = build_exposure_index(manifest)
    assert idx["dead.py"] == 0.1


def test_build_exposure_index_none_manifest():
    idx = build_exposure_index(None)
    assert idx == {}
