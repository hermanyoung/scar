"""Tests for the C# parser (mirrors test_python_parser.py)."""

from pathlib import Path

import pytest

from code_analysis.parsers.csharp import CSharpParser

FIXTURES = Path(__file__).parent / "fixtures" / "csharp"


@pytest.fixture
def parser():
    return CSharpParser()


class TestMetrics:
    def test_clean_file_metrics(self, parser):
        result = parser.analyze_file(FIXTURES / "Clean.cs", "Clean.cs")
        assert result is not None
        m = result.metrics
        assert m.language == "csharp"
        assert m.lines > 0
        assert m.classes == 1
        assert m.functions >= 2  # DisplayName, HasValidEmail
        assert m.documented_callables >= 3  # class + 2 documented methods
        assert m.total_callables >= 3
        assert m.naming_violations == 0
        assert m.bare_excepts == 0
        assert m.max_nesting <= 1
        assert not m.unsafe_calls

    def test_complex_file_metrics(self, parser):
        result = parser.analyze_file(FIXTURES / "Complex.cs", "Complex.cs")
        assert result is not None
        m = result.metrics
        assert m.naming_violations >= 2  # badlyNamedService, processData, doWork
        assert m.bare_excepts >= 2  # two typeless empty catch blocks
        assert m.max_nesting >= 4  # deeply nested loops
        assert m.classes == 1
        assert m.functions >= 1

    def test_unsafe_file_metrics(self, parser):
        result = parser.analyze_file(FIXTURES / "Unsafe.cs", "Unsafe.cs")
        assert result is not None
        m = result.metrics
        assert len(m.unsafe_calls) >= 2  # Process.Start, new BinaryFormatter()
        assert any("Process.Start" in call for call in m.unsafe_calls)
        assert any("BinaryFormatter" in call for call in m.unsafe_calls)

    def test_type_coverage(self, parser):
        result = parser.analyze_file(FIXTURES / "Clean.cs", "Clean.cs")
        assert result is not None
        m = result.metrics
        # C# params always carry types.
        # NOTE: annotated_returns is currently always 0 — csharp.py queries the
        # method return type via field "type" but the installed
        # tree-sitter-c-sharp grammar exposes it as field "returns"
        # (pre-existing parser gap, surfaced by this test; flagged in plan 019).
        assert m.annotated_params > 0
        assert m.annotated_params == m.total_params
        assert m.type_coverage > 0

    def test_nonexistent_file_returns_none(self, parser):
        result = parser.analyze_file(Path("/nonexistent.cs"), "nonexistent.cs")
        assert result is None


class TestStructure:
    def test_includes_structure_when_requested(self, parser):
        result = parser.analyze_file(FIXTURES / "Clean.cs", "Clean.cs", include_structure=True)
        assert result is not None
        assert result.module is not None
        assert result.module.language == "csharp"
        assert result.module.path == "Clean.cs"
        # NOTE: imports is currently always [] — csharp.py queries
        # using_directive's "name" field, which the installed
        # tree-sitter-c-sharp grammar does not define (pre-existing parser
        # gap, surfaced by this test; flagged in plan 019).
        assert len(result.module.classes) == 1
        assert result.module.classes[0].name == "User"

    def test_excludes_structure_by_default(self, parser):
        result = parser.analyze_file(FIXTURES / "Clean.cs", "Clean.cs")
        assert result is not None
        assert result.module is None

    def test_class_methods_extracted(self, parser):
        result = parser.analyze_file(FIXTURES / "Clean.cs", "Clean.cs", include_structure=True)
        assert result is not None
        user_cls = result.module.classes[0]
        assert user_cls.name == "User"
        assert len(user_cls.methods) >= 2  # DisplayName, HasValidEmail

    def test_method_params_extracted(self, parser):
        result = parser.analyze_file(FIXTURES / "Clean.cs", "Clean.cs", include_structure=True)
        assert result is not None
        methods = result.module.classes[0].methods
        has_valid_email = next(m for m in methods if m.name == "HasValidEmail")
        assert len(has_valid_email.params) == 1
        assert "email" in has_valid_email.params[0]
