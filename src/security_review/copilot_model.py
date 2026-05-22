"""PydanticAI Model adapter for GitHub Copilot SDK.

Routes LLM calls through the Copilot Enterprise subscription.
All models (Claude, GPT) available via Copilot billing.

Architecture:
- Shared CopilotClient singleton (one CLI subprocess)
- Each request() call creates an independent session with local state
- ConcurrencyLimitedModel (applied in providers.py) gates admission
- Session timeout and backoff configurable via ProviderConfig
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelResponseStreamEvent,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters, StreamedResponse
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage

logger = structlog.get_logger()


# =============================================================================
# Message extraction utilities
# =============================================================================


def _repair_json_in_text(text: str) -> str:
    """Attempt to repair malformed JSON in LLM responses.

    Only repairs text that is actually JSON — either fenced ```json blocks
    or text whose non-whitespace content starts with { or [.
    Markdown with incidental curly braces (code evidence) is left untouched.
    """
    try:
        from json_repair import repair_json
    except ImportError:
        logger.debug("copilot.json_repair_unavailable")
        return text

    import re

    # Case 1: Fenced JSON block — repair only the contents inside the fence.
    json_match = re.search(r"```json\s*([\s\S]*?)```", text)
    if json_match:
        raw_json = json_match.group(1).strip()
        repaired = repair_json(raw_json)
        if repaired != raw_json:
            return text[:json_match.start(1)] + repaired + text[json_match.end(1):]
        return text

    # Case 2: Bare JSON — only if the text *starts* with { or [ (after whitespace).
    # This avoids corrupting markdown responses that contain code with curly braces.
    stripped = text.lstrip()
    if stripped and stripped[0] in "{[":
        try:
            json.loads(text)
            return text  # Already valid
        except json.JSONDecodeError as e:
            logger.debug("copilot.json_repair_attempt", error=str(e))
            repaired = repair_json(text)
            if repaired and repaired != text:
                return repaired

    return text


def _extract_messages(messages: list[ModelMessage]) -> tuple[str, str]:
    """Extract system prompt and user message from PydanticAI messages."""
    system_prompt = ""
    history_parts: list[str] = []
    last_user_message = ""

    for msg in messages:
        if isinstance(msg, ModelRequest):
            if msg.instructions:
                system_prompt = msg.instructions
            for part in msg.parts:
                if isinstance(part, UserPromptPart):
                    content = part.content if isinstance(part.content, str) else str(part.content)
                    last_user_message = content
                    history_parts.append(f"User: {content}")
                elif isinstance(part, ToolReturnPart):
                    history_parts.append(
                        f"Tool result ({part.tool_name}): {part.model_response_str()[:1000]}"
                    )
        elif isinstance(msg, ModelResponse):
            for part in msg.parts:
                if isinstance(part, TextPart) and part.content:
                    truncated = part.content[:2000] + ("..." if len(part.content) > 2000 else "")
                    history_parts.append(f"Assistant: {truncated}")
                elif isinstance(part, ToolCallPart):
                    args_str = json.dumps(part.args) if isinstance(part.args, dict) else str(part.args)
                    history_parts.append(f"Tool call: {part.tool_name}({args_str})")

    if len(history_parts) > 1:
        prior = history_parts[:-1]
        user_message = (
            "[Previous conversation]\n"
            + "\n".join(prior)
            + f"\n[End previous conversation]\n\n{last_user_message}"
        )
    else:
        user_message = last_user_message

    return system_prompt, user_message


# =============================================================================
# Streamed response adapter
# =============================================================================


@dataclass
class CopilotStreamedResponse(StreamedResponse):
    _model_response: ModelResponse = field(default=None)
    _model_id: str = ""
    _timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def model_name(self) -> str:
        return f"copilot:{self._model_id}"

    @property
    def provider_name(self) -> str:
        return "copilot"

    @property
    def provider_url(self) -> str:
        return "https://github.com/copilot"

    @property
    def timestamp(self) -> datetime:
        return self._timestamp

    async def _get_event_iterator(self) -> AsyncIterator[ModelResponseStreamEvent]:
        for part in self._model_response.parts:
            event = self._parts_manager.handle_part(vendor_part_id=None, part=part)
            yield event
        self._usage = self._model_response.usage


# =============================================================================
# CopilotModel — concurrent-safe, all state local to each request
# =============================================================================


class CopilotModel(Model):
    """PydanticAI Model backed by GitHub Copilot SDK.

    Structured output uses 'prompted' mode (schema in system prompt).
    Each request() call is fully self-contained — no shared mutable state.
    Concurrent calls are safe (gated by ConcurrencyLimitedModel in providers.py).
    """

    def __init__(
        self,
        model_id: str = "claude-sonnet-4.6",
        session_timeout: float = 90.0,
        backoff_seconds: float = 10.0,
    ) -> None:
        from pydantic_ai.profiles import ModelProfile

        self._profile = ModelProfile(
            supports_json_schema_output=False,
            default_structured_output_mode='prompted',
        )
        self._model_id = model_id
        self._session_timeout = session_timeout
        self._backoff_seconds = backoff_seconds
        self._client: Any = None
        self._started: bool = False
        self._lock: asyncio.Lock | None = None

    @property
    def model_name(self) -> str:
        return f"copilot:{self._model_id}"

    @property
    def system(self) -> str:
        return "copilot"

    async def _ensure_client(self) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._client is None:
                try:
                    from copilot import CopilotClient
                except ImportError:
                    raise ImportError(
                        "github-copilot-sdk is required for copilot: models. "
                        "Install with: pip install github-copilot-sdk"
                    )
                self._client = CopilotClient(auto_start=True)
            if not self._started:
                await self._client.start()
                self._started = True

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        model_settings, model_request_parameters = self.prepare_request(
            model_settings, model_request_parameters,
        )
        await self._ensure_client()

        _, user_message = _extract_messages(messages)
        if not user_message:
            return self._empty_response()

        system_prompt = self._get_instructions(messages, model_request_parameters) or ""

        return await self._execute_request(user_message, system_prompt)

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: Any | None = None,
    ) -> AsyncIterator[StreamedResponse]:
        response = await self.request(messages, model_settings, model_request_parameters)
        streamed = CopilotStreamedResponse(
            model_request_parameters=model_request_parameters,
            _model_response=response,
            _model_id=self._model_id,
        )
        streamed._usage = response.usage
        yield streamed

    async def _execute_request(self, user_message: str, system_prompt: str) -> ModelResponse:
        """Execute a single request with local state. Concurrent-safe.

        Creates an independent session, sends the message, waits for response.
        On timeout: cleans up, waits backoff, retries once with fresh session.
        All state is local — no instance variable mutation.
        """
        # Local state for this request — captured by on_event closure
        response_text = ""
        usage_data: dict[str, int] = {}

        def on_event(event: Any) -> None:
            nonlocal response_text
            # Use .value to get the canonical string ("assistant.message", "assistant.usage")
            # rather than relying on enum __str__ which varies across Python versions.
            etype = getattr(getattr(event, "type", None), "value", str(getattr(event, "type", "")))
            data = getattr(event, "data", None)
            if etype == "assistant.usage" and data is not None:
                usage_data["input"] = int(getattr(data, "input_tokens", 0) or 0)
                usage_data["output"] = int(getattr(data, "output_tokens", 0) or 0)
            elif etype == "assistant.message" and data is not None:
                text = getattr(data, "content", None)
                if text:
                    response_text = str(text)

        session_kwargs: dict[str, Any] = {
            "on_permission_request": lambda *a, **k: True,
            "model": self._model_id,
            "on_event": on_event,
        }
        if system_prompt:
            session_kwargs["system_message"] = {
                "mode": "replace",
                "content": system_prompt,
            }

        logger.debug(
            "copilot.request_start",
            model=self._model_id,
            prompt_chars=len(user_message),
            system_chars=len(system_prompt),
            timeout=self._session_timeout,
        )

        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            # Reset state for each attempt
            response_text = ""
            usage_data.clear()

            t0 = time.monotonic()
            session = await self._client.create_session(**session_kwargs)
            try:
                await session.send_and_wait(user_message, timeout=self._session_timeout)

                # Fallback: if event handler didn't capture text, read from session
                if not response_text:
                    response_text = await self._extract_text_from_session(session)

                if not response_text:
                    logger.warning(
                        "copilot.empty_response",
                        model=self._model_id,
                        attempt=attempt,
                        prompt_chars=len(user_message),
                    )

                elapsed = time.monotonic() - t0
                logger.debug(
                    "copilot.request_complete",
                    model=self._model_id,
                    attempt=attempt,
                    elapsed_seconds=round(elapsed, 1),
                    response_chars=len(response_text),
                    response_preview=response_text[:300] if response_text else "(empty)",
                    tokens_in=usage_data.get("input", 0),
                    tokens_out=usage_data.get("output", 0),
                    used_fallback=bool(response_text and not usage_data),
                )
                return self._build_response(response_text, usage_data)
            except (asyncio.TimeoutError, TimeoutError):
                elapsed = time.monotonic() - t0
                logger.warning(
                    "copilot.session_timeout",
                    model=self._model_id,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    elapsed_seconds=round(elapsed, 1),
                    timeout_seconds=self._session_timeout,
                    will_retry=attempt < max_attempts,
                )
                if attempt >= max_attempts:
                    raise TimeoutError(
                        f"Copilot session timed out after {max_attempts} attempts "
                        f"({self._session_timeout}s each). Likely rate-limited."
                    )
                await asyncio.sleep(self._backoff_seconds)
            finally:
                await self._disconnect(session)

    def _build_response(
        self, response_text: str, usage_data: dict[str, int],
    ) -> ModelResponse:
        """Build ModelResponse from captured event data. Does not manage sessions."""
        text = response_text
        if text:
            text = _repair_json_in_text(text)

        return ModelResponse(
            parts=[TextPart(content=text)],
            usage=RequestUsage(
                input_tokens=usage_data.get("input", 0),
                output_tokens=usage_data.get("output", 0),
            ),
            model_name=self._model_id,
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    async def _extract_text_from_session(session: Any) -> str:
        """Fallback: extract response text from session messages.

        The on_event handler should capture this, but some SDK versions
        or event orderings may miss it. This reads the full message
        history from the session as a safety net.
        """
        try:
            msgs = await session.get_messages()
        except Exception as e:
            logger.warning("copilot.get_messages_failed", error=str(e))
            return ""
        for m in msgs:
            etype = getattr(getattr(m, "type", None), "value", str(getattr(m, "type", "")))
            if etype == "assistant.message":
                data = getattr(m, "data", None)
                text = getattr(data, "content", None)
                if text:
                    logger.debug("copilot.fallback_text_extracted", chars=len(str(text)))
                    return str(text)
        return ""

    @staticmethod
    async def _disconnect(session: Any) -> None:
        """Disconnect a session, swallowing errors."""
        try:
            await session.disconnect()
        except Exception as e:
            logger.debug("copilot.disconnect_failed", error=str(e))

    def _empty_response(self) -> ModelResponse:
        return ModelResponse(
            parts=[TextPart(content="")],
            usage=RequestUsage(),
            model_name=self._model_id,
            timestamp=datetime.now(timezone.utc),
        )

    def _get_instructions(
        self, messages: list[ModelMessage], params: ModelRequestParameters,
    ) -> str:
        """Extract system instructions from messages."""
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, ModelRequest):
                if msg.instructions:
                    parts.append(msg.instructions)
                for part in msg.parts:
                    if hasattr(part, "part_kind") and part.part_kind == "system-prompt":
                        content = getattr(part, "content", "")
                        if content and content not in parts:
                            parts.append(content)
        return "\n\n".join(parts) if parts else ""
