"""Tests for finding fingerprinting."""

from __future__ import annotations

from security_review.fingerprint import fingerprint_finding


def test_same_code_different_whitespace_same_fingerprint():
    a = fingerprint_finding("CWE-89", "App.save", "app.py", "cursor.execute(  query )")
    b = fingerprint_finding("CWE-89", "App.save", "app.py", "cursor.execute(query)")
    assert a == b


def test_same_code_different_python_comment_same_fingerprint():
    a = fingerprint_finding("CWE-89", "App.save", "app.py", "cursor.execute(query)  # unsafe")
    b = fingerprint_finding("CWE-89", "App.save", "app.py", "cursor.execute(query)")
    assert a == b


def test_same_code_different_csharp_comment_same_fingerprint():
    a = fingerprint_finding("CWE-89", "App.Save", "App.cs", "cmd.ExecuteReader(); // unsafe")
    b = fingerprint_finding("CWE-89", "App.Save", "App.cs", "cmd.ExecuteReader();")
    assert a == b


def test_structurally_different_code_different_fingerprint():
    a = fingerprint_finding("CWE-89", "App.save", "app.py", "cursor.execute(query)")
    b = fingerprint_finding("CWE-89", "App.save", "app.py", "cursor.execute(safe_query)")
    assert a != b


def test_cwe_id_affects_fingerprint():
    a = fingerprint_finding("CWE-89", "App.save", "app.py", "x()")
    b = fingerprint_finding("CWE-78", "App.save", "app.py", "x()")
    assert a != b


def test_qualified_name_affects_fingerprint():
    a = fingerprint_finding("CWE-89", "App.save", "app.py", "x()")
    b = fingerprint_finding("CWE-89", "App.other", "app.py", "x()")
    assert a != b


def test_file_path_affects_fingerprint():
    a = fingerprint_finding("CWE-89", "App.save", "app.py", "x()")
    b = fingerprint_finding("CWE-89", "App.save", "other.py", "x()")
    assert a != b
