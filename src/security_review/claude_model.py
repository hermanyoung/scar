"""PydanticAI Model adapter for Claude Agent SDK with Max subscription OAuth.

Routes LLM calls through your Claude Max/Pro subscription at $0 incremental cost.
Auth via CLAUDE_CODE_OAUTH_TOKEN environment variable (set by `claude setup-token`).

Architecture:
- Each request() call is a single `query()` invocation with allowed_tools=[]
- No tool bridge, no session state, no multi-turn — one prompt, one response
- The Agent SDK handles OAuth token refresh automatically
- Much simpler than CopilotModel — no streaming workarounds needed

Usage:
    model = ClaudeModel(model_id="claude-sonnet-4-5-20250929")
    # Used via PydanticAI agent.run(model=model)
"""
from __future__ import annotations

import asyncio
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
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters, StreamedResponse
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage

logger = structlog.get_logger()


def _extract_prompt(messages: list[ModelMessage]) -> tuple[str, str]:
    """Extract system prompt and user message from PydanticAI messages.

    Returns (system_prompt, user_message).
    """
    system_prompt = ""
    last_user_message = ""

    for msg in messages:
        if isinstance(msg, ModelRequest):
            if msg.instructions:
                system_prompt = msg.instructions
            for part in msg.parts:
                if isinstance(part, UserPromptPart):
                    content = part.content if isinstance(part.content, str) else str(part.content)
                    last_user_message = content

    return system_prompt, last_user_message


@dataclass
class ClaudeStreamedResponse(StreamedResponse):
    """Wraps a complete response as a single-chunk stream."""

    _response: ModelResponse | None = field(default=None)
    _model_id: str = ""
    _timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def model_name(self) -> str:
        return f"claude:{self._model_id}"

    @property
    def timestamp(self) -> datetime:
        return self._timestamp

    async def _get_event_iterator(self):
        for part in self._response.parts:
            event = self._parts_manager.handle_part(vendor_part_id=None, part=part)
            yield event
        self._usage = self._response.usage


class ClaudeModel(Model):
    """PydanticAI Model backed by Claude Agent SDK with Max/Pro OAuth subscription.

    Zero tools. One prompt in, one text response out. Billed to your subscription.
    """

    def __init__(self, model_id: str) -> None:
        from pydantic_ai.profiles import ModelProfile

        self._model_id = model_id
        self._profile = ModelProfile(
            supports_json_schema_output=False,
            default_structured_output_mode="prompted",
        )

    @property
    def model_name(self) -> str:
        return f"claude:{self._model_id}"

    @property
    def system(self) -> str:
        return "claude"

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        model_settings, model_request_parameters = self.prepare_request(
            model_settings, model_request_parameters,
        )

        system_prompt, user_message = _extract_prompt(messages)
        if not user_message:
            return self._empty_response()

        # Merge system prompt with any PydanticAI-injected instructions
        full_system = self._get_instructions(messages, model_request_parameters) or system_prompt

        response_text = await self._call_agent_sdk(full_system, user_message)

        return ModelResponse(
            parts=[TextPart(content=response_text)],
            usage=RequestUsage(),  # Agent SDK doesn't expose token counts
            model_name=self._model_id,
            timestamp=datetime.now(timezone.utc),
        )

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: Any | None = None,
    ):
        """Stream wrapper — delegates to request() and wraps as single-chunk stream."""
        response = await self.request(messages, model_settings, model_request_parameters)
        streamed = ClaudeStreamedResponse(
            model_request_parameters=model_request_parameters,
            _response=response,
            _model_id=self._model_id,
        )
        streamed._usage = response.usage
        yield streamed

    async def _call_agent_sdk(self, system_prompt: str, user_message: str) -> str:
        """Execute a single query via the Claude Agent SDK.

        No tools, no multi-turn, no file access. Pure prompt → text.
        """
        from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

        options = ClaudeAgentOptions(
            allowed_tools=[],
            model=self._model_id,
            system_prompt=system_prompt if system_prompt else None,
            max_turns=1,
            permission_mode="dontAsk",
            setting_sources=[],  # No CLAUDE.md, no hooks, no skills — clean context
        )

        logger.debug(
            "claude_model.request_start",
            model=self._model_id,
            system_chars=len(system_prompt) if system_prompt else 0,
            prompt_chars=len(user_message),
        )

        response_text = ""
        try:
            async for message in query(prompt=user_message, options=options):
                if isinstance(message, ResultMessage):
                    response_text = message.result or ""
                    break
        except Exception as e:
            logger.error(
                "claude_model.request_failed",
                model=self._model_id,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

        logger.debug(
            "claude_model.request_complete",
            model=self._model_id,
            response_chars=len(response_text),
        )

        return response_text

    def _empty_response(self) -> ModelResponse:
        return ModelResponse(
            parts=[TextPart(content="")],
            usage=RequestUsage(),
            model_name=self._model_id,
            timestamp=datetime.now(timezone.utc),
        )

    def _get_instructions(
        self, messages: list[ModelMessage], params: ModelRequestParameters
    ) -> str | None:
        """Extract combined system instructions from PydanticAI messages."""
        parts = []
        for msg in messages:
            if isinstance(msg, ModelRequest) and msg.instructions:
                parts.append(msg.instructions)
        return "\n\n".join(parts) if parts else None
