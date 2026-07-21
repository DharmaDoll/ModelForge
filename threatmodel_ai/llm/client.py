"""Minimal optional LLM client interfaces."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from threatmodel_ai.errors import ModelForgeError


class LLMConfigurationError(ModelForgeError):
    """Raised when optional LLM support was requested but is not configured."""


class LLMRequestError(ModelForgeError):
    """Raised when an optional LLM request fails."""


class LLMClient(Protocol):
    """Interface used by optional LLM refinement features."""

    def generate_text(self, *, instructions: str, input_text: str) -> str:
        """Generate text from instructions and a user input payload."""


@dataclass(frozen=True)
class OpenAIResponsesClient:
    """Small Responses API client backed by stdlib HTTPS."""

    api_key: str
    model: str
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> OpenAIResponsesClient:
        """Create a client from environment variables."""

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise LLMConfigurationError(
                "OPENAI_API_KEY is required when --llm refine-questions is used.",
                hint=(
                    "Set OPENAI_API_KEY or run without --llm to keep deterministic-only "
                    "analysis."
                ),
            )
        return cls(
            api_key=api_key,
            model=os.environ.get("MODELFORGE_LLM_MODEL", "gpt-5.2"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        )

    def generate_text(self, *, instructions: str, input_text: str) -> str:
        """Call the OpenAI Responses API and return output text."""

        payload = {
            "model": self.model,
            "instructions": instructions,
            "input": input_text,
        }
        request = urllib.request.Request(
            url=f"{self.base_url.rstrip('/')}/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LLMRequestError(
                "OpenAI API request failed.",
                detail=f"HTTP {exc.code}: {_truncate(detail)}",
                hint="Check OPENAI_API_KEY, MODELFORGE_LLM_MODEL, and API access.",
            ) from exc
        except urllib.error.URLError as exc:
            raise LLMRequestError(
                "OpenAI API request failed.",
                detail=str(exc.reason),
                hint="Check network access and OPENAI_BASE_URL.",
            ) from exc

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise LLMRequestError(
                "OpenAI API response was not valid JSON.",
                detail=str(exc),
                hint="Retry or check OPENAI_BASE_URL.",
            ) from exc
        output_text = _extract_output_text(data)
        if not output_text:
            raise LLMRequestError(
                "OpenAI API response did not contain output text.",
                hint="Retry or check the selected model.",
            )
        return output_text


def _extract_output_text(data: dict[str, object]) -> str:
    output = data.get("output")
    if not isinstance(output, list):
        return ""

    chunks: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for content_item in content:
            if not isinstance(content_item, dict):
                continue
            text = content_item.get("text")
            if isinstance(text, str):
                chunks.append(text)
    return "".join(chunks).strip()


def _truncate(value: str, limit: int = 500) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
