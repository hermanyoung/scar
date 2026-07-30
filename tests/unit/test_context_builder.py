"""Unit tests for context_builder.py — file reading, context windows, token-budget inlining."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_review.context_builder import (
    format_context_window,
    format_full_file,
    inline_files,
    is_sensitive_env_path,
    read_file_content,
)


# ---------------------------------------------------------------------------
# read_file_content
# ---------------------------------------------------------------------------

def test_read_file_content_success(tmp_path: Path):
    (tmp_path / "hello.py").write_text("print('hi')", encoding="utf-8")
    content = read_file_content(tmp_path, "hello.py")
    assert content == "print('hi')"


def test_read_file_content_missing_file(tmp_path: Path):
    result = read_file_content(tmp_path, "nonexistent.py")
    assert result is None


def test_read_file_content_subdirectory(tmp_path: Path):
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "app.py").write_text("x = 1", encoding="utf-8")
    content = read_file_content(tmp_path, "src/app.py")
    assert content == "x = 1"


@pytest.mark.parametrize(
    "file_path",
    ["config/.env", ".env.local", "config/production.env", r"config\.env.production"],
)
def test_read_file_content_blocks_sensitive_environment_files(
    tmp_path: Path, file_path: str,
):
    relative = file_path.replace("\\", "/")
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("API_KEY=must-not-enter-a-prompt", encoding="utf-8")

    assert is_sensitive_env_path(file_path)
    assert read_file_content(tmp_path, file_path) is None


@pytest.mark.parametrize(
    "file_path",
    ["config/.env.example", ".env.sample", "deploy/prod.env.template", ".env.dist"],
)
def test_read_file_content_allows_environment_templates(
    tmp_path: Path, file_path: str,
):
    target = tmp_path / file_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("API_KEY=", encoding="utf-8")

    assert not is_sensitive_env_path(file_path)
    assert read_file_content(tmp_path, file_path) == "API_KEY="


# ---------------------------------------------------------------------------
# format_context_window
# ---------------------------------------------------------------------------

def test_format_context_window_marks_target_line():
    content = "\n".join(f"line {i}" for i in range(1, 11))
    result = format_context_window(content, line=5, radius=2)
    lines = result.splitlines()
    # Target line 5 should be marked with >>>
    marked = [l for l in lines if l.startswith(">>>")]
    assert len(marked) == 1
    assert "line 5" in marked[0]


def test_format_context_window_respects_radius():
    content = "\n".join(f"line {i}" for i in range(1, 21))
    result = format_context_window(content, line=10, radius=3)
    lines = result.splitlines()
    # radius=3 means lines 7-13 (3 before + target + 3 after)
    assert len(lines) == 7


def test_format_context_window_clamps_to_start():
    content = "\n".join(f"line {i}" for i in range(1, 6))
    result = format_context_window(content, line=1, radius=5)
    lines = result.splitlines()
    # Should not go before line 1
    assert len(lines) <= 6
    assert ">>>" in lines[0]


def test_format_context_window_clamps_to_end():
    content = "\n".join(f"line {i}" for i in range(1, 6))
    result = format_context_window(content, line=5, radius=5)
    lines = result.splitlines()
    assert len(lines) <= 10
    marked = [l for l in lines if l.startswith(">>>")]
    assert len(marked) == 1


def test_format_context_window_line_numbers():
    content = "a\nb\nc\nd\ne"
    result = format_context_window(content, line=3, radius=1)
    lines = result.splitlines()
    # Should show lines 2, 3, 4
    assert "2" in lines[0]
    assert "3" in lines[1]
    assert "4" in lines[2]


# ---------------------------------------------------------------------------
# format_full_file
# ---------------------------------------------------------------------------

def test_format_full_file_includes_header_and_fence():
    result = format_full_file("src/app.py", "x = 1")
    assert result.startswith("### src/app.py\n")
    assert "```py\n" in result
    assert "x = 1" in result
    assert result.endswith("```\n")


def test_format_full_file_no_extension():
    result = format_full_file("Dockerfile", "FROM python:3.12")
    assert "```\n" in result


# ---------------------------------------------------------------------------
# inline_files
# ---------------------------------------------------------------------------

def test_inline_files_all_fit(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2", encoding="utf-8")
    content, included, omitted = inline_files(
        tmp_path, ["a.py", "b.py"], max_tokens=100_000,
    )
    assert included == ["a.py", "b.py"]
    assert omitted == []
    assert "x = 1" in content
    assert "y = 2" in content


def test_inline_files_budget_truncation(tmp_path: Path):
    # Write a large file that exceeds the budget
    large_content = "x" * 4000  # ~1000 tokens
    (tmp_path / "big.py").write_text(large_content, encoding="utf-8")
    (tmp_path / "small.py").write_text("y = 1", encoding="utf-8")

    # Budget: 200 tokens total, 30k reserved = negative available,
    # but let's set reserve to 0 to test truncation clearly
    content, included, omitted = inline_files(
        tmp_path, ["big.py", "small.py"],
        max_tokens=500, reserve_tokens=0,
    )
    # big.py should be truncated, small.py might be omitted
    assert "big.py" in included
    assert "TRUNCATED" in content


def test_inline_files_file_omitted_when_over_budget(tmp_path: Path):
    (tmp_path / "a.py").write_text("x" * 2000, encoding="utf-8")  # ~500 tokens
    (tmp_path / "b.py").write_text("y" * 2000, encoding="utf-8")  # ~500 tokens
    (tmp_path / "c.py").write_text("z" * 2000, encoding="utf-8")  # ~500 tokens

    content, included, omitted = inline_files(
        tmp_path, ["a.py", "b.py", "c.py"],
        max_tokens=600, reserve_tokens=0,
    )
    # a.py fits (500 tokens), b.py partially fits (truncated), c.py omitted
    assert "a.py" in included
    assert "c.py" in omitted
    assert "omitted due to token budget" in content


def test_inline_files_missing_file_shows_error(tmp_path: Path):
    content, included, omitted = inline_files(
        tmp_path, ["nonexistent.py"], max_tokens=100_000,
    )
    assert "nonexistent.py" in included
    assert "Error: could not read file" in content


def test_inline_files_empty_list(tmp_path: Path):
    content, included, omitted = inline_files(
        tmp_path, [], max_tokens=100_000,
    )
    assert included == []
    assert omitted == []
