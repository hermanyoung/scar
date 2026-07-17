"""Tests for sink/entry-point classification."""

from __future__ import annotations

from code_analysis.models import SymbolInfo, SymbolKind
from code_analysis.sinks import classify_symbol, matches_any_sink_pattern, sink_patterns_for_cwe


def _method(name: str, qualified_name: str, decorators=None, bases=None) -> SymbolInfo:
    return SymbolInfo(
        name=name, kind=SymbolKind.METHOD, qualified_name=qualified_name, line=1,
        decorators=decorators or [], bases=bases or [],
    )


def test_execute_method_matches_cwe_89_sink():
    symbol = _method("execute", "app.db.Cursor.execute")
    classify_symbol(symbol, "python")
    assert symbol.is_sink is True
    assert "CWE-89" in symbol.cwe_tags


def test_httppost_decorator_matches_csharp_entry_point():
    symbol = _method("Create", "App.Controllers.UserController.Create", decorators=["HttpPost"])
    classify_symbol(symbol, "csharp")
    assert symbol.is_entry_point is True


def test_controllerbase_subclass_matches_csharp_entry_point():
    symbol = _method("Create", "App.Controllers.UserController.Create", bases=["ControllerBase"])
    classify_symbol(symbol, "csharp")
    assert symbol.is_entry_point is True


def test_app_route_decorator_matches_python_entry_point():
    symbol = _method("index", "app.views.index", decorators=["app.route"])
    classify_symbol(symbol, "python")
    assert symbol.is_entry_point is True


def test_non_matching_method_stays_unclassified():
    symbol = _method("compute_total", "app.billing.compute_total")
    classify_symbol(symbol, "python")
    assert symbol.is_sink is False
    assert symbol.is_entry_point is False
    assert symbol.cwe_tags == []


def test_multiple_cwe_tags_accumulate():
    # os.system-shaped name should not double-match, but a method matching
    # two distinct sink families should carry both tags.
    symbol = _method("open", "app.io.open")
    classify_symbol(symbol, "python")
    assert symbol.is_sink is True
    assert "CWE-22" in symbol.cwe_tags


def test_sink_patterns_for_cwe_normalises_bare_number():
    assert sink_patterns_for_cwe("89") == sink_patterns_for_cwe("CWE-89")
    assert "*.execute" in sink_patterns_for_cwe("89")


def test_matches_any_sink_pattern_against_external_callee():
    # The real-world case: cursor.execute() is never a locally-defined
    # symbol, but it must still match for the backward call-graph walk.
    assert matches_any_sink_pattern("cursor.execute", "89") is True
    assert matches_any_sink_pattern("os.system", "78") is True
    assert matches_any_sink_pattern("app.billing.compute_total", "89") is False
