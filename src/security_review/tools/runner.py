"""Subprocess execution for security tools.

This is the ONLY module in the codebase that calls asyncio.create_subprocess_exec.
Agents never call subprocess directly.
"""
from __future__ import annotations

import asyncio
import subprocess
import time
from pathlib import Path

import structlog

from security_review.models.report import ToolResult
from security_review.tools.registry import OutputCapture, SecurityToolSpec

logger = structlog.get_logger()


async def run_tool(
    spec: SecurityToolSpec,
    target_path: str,
    output_path: str,
    cwd: str | None = None,
) -> ToolResult:
    """Execute a security tool as a subprocess. Never uses shell=True.

    Returns ToolResult with exit_code, stdout, stderr, duration_ms.
    Timeout -> ToolResult(exit_code=-1, stderr="timed out after {N}s").
    Binary not found -> ToolResult(exit_code=-1, stderr=str(OSError)).
    """
    cmd = spec.build_command(target_path, output_path)
    start = time.monotonic()

    logger.info("tool.started", tool_name=spec.name, target_path=target_path)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=spec.timeout_seconds,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")
        success = proc.returncode in spec.success_exit_codes

        # For tools that write to stdout, capture and write to output_path
        if success and spec.output_capture == OutputCapture.STDOUT:
            Path(output_path).write_text(stdout_str, encoding="utf-8")

        result = ToolResult(
            tool_name=spec.name,
            exit_code=proc.returncode,
            stdout=stdout_str,
            stderr=stderr_str,
            success=success,
            duration_ms=duration_ms,
        )

        if success:
            logger.info(
                "tool.completed",
                tool_name=spec.name,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
            )
        else:
            logger.error(
                "tool.failed",
                tool_name=spec.name,
                exit_code=proc.returncode,
                stderr=stderr_str[:500],
            )

        return result

    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.warning(
            "tool.timeout",
            tool_name=spec.name,
            timeout_seconds=spec.timeout_seconds,
        )
        return ToolResult(
            tool_name=spec.name,
            exit_code=-1,
            stderr=f"timed out after {spec.timeout_seconds}s",
            success=False,
            duration_ms=duration_ms,
        )
    except OSError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error("tool.failed", tool_name=spec.name, error=str(e))
        return ToolResult(
            tool_name=spec.name,
            exit_code=-1,
            stderr=str(e),
            success=False,
            duration_ms=duration_ms,
        )


def run_tool_sync(
    cmd: list[str],
    timeout_seconds: int,
    cwd: str | None = None,
) -> subprocess.CompletedProcess:
    """Run an arbitrary command synchronously. Never uses shell=True.

    For build-time tooling (e.g. tools/roslyn-callgraph) invoked before the
    async pipeline starts -- not for SAST scanners, which use run_tool().
    Never raises: timeout and binary-not-found both come back as a
    CompletedProcess with returncode=-1 and the error in stderr.
    """
    tool_name = cmd[0] if cmd else "<empty>"
    logger.info("tool.sync_started", tool_name=tool_name)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds, cwd=cwd,
        )
        logger.info("tool.sync_completed", tool_name=tool_name, exit_code=result.returncode)
        return result
    except subprocess.TimeoutExpired:
        logger.warning("tool.sync_timeout", tool_name=tool_name, timeout_seconds=timeout_seconds)
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"timed out after {timeout_seconds}s",
        )
    except OSError as e:
        logger.error("tool.sync_failed", tool_name=tool_name, error=str(e))
        return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr=str(e))
