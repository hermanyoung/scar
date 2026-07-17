"""Stable finding fingerprints for cross-run deduplication and tracking."""

from __future__ import annotations

import hashlib
import re


def fingerprint_finding(
    cwe_id: str,
    qualified_name: str,
    file_path: str,
    code_snippet: str,
) -> str:
    """Compute a stable fingerprint for a finding.

    Stable across whitespace and comment changes.
    Breaks on structural code changes (which is correct — the finding
    may have been fixed or changed).
    """
    # Strip comments first, while line boundaries are still intact (# and //
    # are anchored to end-of-line) -- then strip ALL whitespace. Whitespace
    # must be removed entirely, not just collapsed to a single space, or
    # purely spacing-different code ("f( x )" vs "f(x)") would still diverge.
    s = re.sub(r"#.*$", "", code_snippet, flags=re.MULTILINE)
    s = re.sub(r"//.*$", "", s, flags=re.MULTILINE)
    s = re.sub(r"\s+", "", s)

    raw = f"{cwe_id}|{qualified_name}|{file_path}|{s}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
