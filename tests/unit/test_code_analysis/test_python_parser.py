"""Tests for the Python parser."""

from pathlib import Path

import pytest

from code_analysis.parsers.python import PythonParser

FIXTURES = Path(__file__).parent / "fixtures" / "python"


@pytest.fixture
def parser():
    return PythonParser()


class TestMetrics:
    def test_clean_file_metrics(self, parser):
        result = parser.analyze_file(FIXTURES / "clean.py", "clean.py")
        assert result is not None
        m = result.metrics
        assert m.language == "python"
        assert m.lines > 0
        assert m.classes == 1
        assert m.functions >= 2  # validate_email, create_user
        assert m.documented_callables >= 3  # class + 2 methods + 2 functions
        assert m.total_callables >= 5
        assert m.naming_violations == 0
        assert m.bare_excepts == 0
        assert m.max_nesting <= 1
        assert not m.unsafe_calls

    def test_complex_file_metrics(self, parser):
        result = parser.analyze_file(FIXTURES / "complex.py", "complex.py")
        assert result is not None
        m = result.metrics
        assert m.naming_violations >= 2  # badlyNamedClass, camelCaseMethod, processData
        assert m.bare_excepts >= 2  # bare except + pass
        assert m.max_nesting >= 4  # deeply nested loops
        assert m.classes == 1
        assert m.functions >= 1

    def test_unsafe_file_metrics(self, parser):
        result = parser.analyze_file(FIXTURES / "unsafe.py", "unsafe.py")
        assert result is not None
        m = result.metrics
        assert len(m.unsafe_calls) >= 4  # eval, os.system, pickle.loads, subprocess shell=True
        assert any("eval" in call for call in m.unsafe_calls)
        assert any("os.system" in call for call in m.unsafe_calls)
        assert any("pickle" in call for call in m.unsafe_calls)
        assert any("shell=True" in call for call in m.unsafe_calls)

    def test_type_coverage(self, parser):
        result = parser.analyze_file(FIXTURES / "clean.py", "clean.py")
        assert result is not None
        m = result.metrics
        # clean.py has type annotations on all params and returns
        assert m.annotated_params > 0
        assert m.annotated_returns > 0
        assert m.type_coverage > 0.5

    def test_nonexistent_file_returns_none(self, parser):
        result = parser.analyze_file(Path("/nonexistent.py"), "nonexistent.py")
        assert result is None

    def test_syntax_error_returns_none(self, tmp_path, parser):
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def broken(:\n    pass")
        result = parser.analyze_file(bad_file, "bad.py")
        assert result is None


class TestStructure:
    def test_includes_structure_when_requested(self, parser):
        result = parser.analyze_file(FIXTURES / "clean.py", "clean.py", include_structure=True)
        assert result is not None
        assert result.module is not None
        assert result.module.language == "python"
        assert result.module.path == "clean.py"
        assert len(result.module.imports) >= 2  # __future__, dataclasses
        assert len(result.module.classes) == 1
        assert result.module.classes[0].name == "User"
        assert len(result.module.functions) >= 2

    def test_excludes_structure_by_default(self, parser):
        result = parser.analyze_file(FIXTURES / "clean.py", "clean.py")
        assert result is not None
        assert result.module is None

    def test_class_bases_extracted(self, parser):
        result = parser.analyze_file(FIXTURES / "clean.py", "clean.py", include_structure=True)
        assert result is not None
        # User class should have no bases (just @dataclass)
        user_cls = result.module.classes[0]
        assert user_cls.name == "User"
        assert len(user_cls.methods) >= 2  # display_name, deactivate

    def test_function_params_extracted(self, parser):
        result = parser.analyze_file(FIXTURES / "clean.py", "clean.py", include_structure=True)
        assert result is not None
        funcs = result.module.functions
        create_user = next(f for f in funcs if f.name == "create_user")
        assert len(create_user.params) == 2
        assert "name" in create_user.params[0]
        assert create_user.return_type == "User"
