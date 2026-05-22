"""Subprocess execution for security tools.

This is the ONLY module in the codebase that calls asyncio.create_subprocess_exec.
Agents never call subprocess directly.
"""
from __future__ import annotations

import asyncio
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
