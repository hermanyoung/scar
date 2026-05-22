"""PydanticAI Model adapter for Codex app-server with ChatGPT subscription.

Routes LLM calls through the locally-installed Codex CLI (codex app-server).
Auth and billing go through ChatGPT Plus/Pro subscription at $0 API cost.

Requirements:
    brew install codex   # or from github.com/openai/codex releases
    # Authenticate: `codex` will prompt on first run, tokens cached in ~/.codex/

Architecture:
    Each request() starts a fresh Codex app-server subprocess for isolation.
    Server startup is ~500ms (Rust binary); threads inside are lightweight.
    Format instructions are injected by the pass code (same as copilot: / claude:).
    GPT-5.4 reliably follows JSON format instructions, making this effective
    for structured output without native PydanticAI schema enforcement.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters, StreamedResponse
from pydantic_ai.profiles import ModelProfile
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage

logger = structlog.get_logger()


def _extract_prompt(messages: list[ModelMessage]) -> tuple[str, str]:
    """Extract system prompt and last user message from PydanticAI messages."""
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


def _find_codex_bin() -> str:
    """Locate the Codex CLI binary on PATH or raise ConfigurationError."""
    from security_review.errors import ConfigurationError

    codex_bin = shutil.which("codex")
    if not codex_bin:
        raise ConfigurationError(
            "Codex CLI not found on PATH. Install with: brew install codex\n"
            "See: https://github.com/openai/codex",
            code="SYS_DEPENDENCY_MISSING",
        )
    return codex_bin


@dataclass
class CodexStreamedResponse(StreamedResponse):
    """Wraps a complete response as a single-chunk stream (Codex doesn't stream)."""

    _response: ModelResponse = field(default=None)
    _model_id: str = ""
    _timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def model_name(self) -> str:
        return f"codex:{self._model_id}"

    @property
    def timestamp(self) -> datetime:
        return self._timestamp

    async def _get_event_iterator(self):
        for part in self._response.parts:
            event = self._parts_manager.handle_part(vendor_part_id=None, part=part)
            yield event
        self._usage = self._response.usage


class CodexModel(Model):
    """PydanticAI Model backed by Codex app-server SDK (ChatGPT subscription).

    Zero tools. One prompt in, one text response out.
    Format instructions are injected by the pass code via model_capabilities.py —
    GPT-5.4 reliably follows JSON format instructions.
    """

    def __init__(self, model_id: str = "gpt-5.4") -> None:
        self._model_id = model_id
        self._profile = ModelProfile(
            supports_json_schema_output=False,
            default_structured_output_mode="prompted",
        )

    @property
    def model_name(self) -> str:
        return f"codex:{self._model_id}"

    @property
    def system(self) -> str:
        return "codex"

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

        full_system = self._get_instructions(messages, model_request_parameters) or system_prompt
        response_text = await self._call_codex(full_system, user_message)

        return ModelResponse(
            parts=[TextPart(content=response_text)],
            usage=RequestUsage(),
            model_name=self._model_id,
            timestamp=datetime.now(timezone.utc),
        )

    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: Any | None = None,
    ):
        """Stream wrapper — delegates to request() and wraps as single-chunk stream."""
        response = await self.request(messages, model_settings, model_request_parameters)
        streamed = CodexStreamedResponse(
            model_request_parameters=model_request_parameters,
            _response=response,
            _model_id=self._model_id,
        )
        streamed._usage = response.usage
        yield streamed

    async def _call_codex(self, system_prompt: str, user_message: str) -> str:
        """Run a single-turn prompt through the Codex app-server subprocess."""
        from codex_app_server import AppServerConfig, AsyncCodex, AskForApproval

        codex_bin = _find_codex_bin()
        config = AppServerConfig(codex_bin=codex_bin)

        # System prompt prepended to user message — Codex threads are single-turn.
        full_prompt = f"{system_prompt}\n\n{user_message}" if system_prompt else user_message

        logger.debug(
            "codex_model.request_start",
            model=self._model_id,
            system_chars=len(system_prompt) if system_prompt else 0,
            prompt_chars=len(user_message),
        )

        try:
            async with AsyncCodex(config=config) as codex:
                thread = await codex.thread_start(model=self._model_id)
                result = await thread.run(
                    full_prompt,
                    approval_policy=AskForApproval.model_validate("never"),
                )
                response_text = result.final_response or ""
        except Exception as e:
            logger.error(
                "codex_model.request_failed",
                model=self._model_id,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

        logger.debug(
            "codex_model.request_complete",
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
        """Collect combined system instructions from PydanticAI messages."""
        parts = []
        for msg in messages:
            if isinstance(msg, ModelRequest) and msg.instructions:
                parts.append(msg.instructions)
        return "\n\n".join(parts) if parts else None
