"""Optional, validated LLM wording proposals for deterministic questions."""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from threatmodel_ai.errors import ModelForgeError
from threatmodel_ai.llm.client import LLMClient
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.questions.generator import Question

_INSTRUCTIONS = """\
You improve the wording of security clarification questions for a human reviewer.

The input questions are the only source of truth. Never answer a question, invent
architecture or controls, or turn an unknown into an assertion. Return a JSON object
with a questions array. For every input ID, return exactly one object with that same
ID and a single-line wording string. If no improvement is possible, copy the original
question. Do not add, omit, or combine questions.
"""

_REFINEMENT_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "questions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "wording": {"type": "string"},
                },
                "required": ["id", "wording"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["questions"],
    "additionalProperties": False,
}


class LLMQuestionRefinementError(ModelForgeError):
    """Raised when an LLM wording proposal cannot be matched to questions."""


class _RefinedQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(min_length=1)
    wording: str = Field(min_length=1)

    @field_validator("wording")
    @classmethod
    def one_line(cls, value: str) -> str:
        """Keep each proposed wording inside its own Markdown list item."""

        if "\n" in value or "\r" in value:
            raise ValueError("wording must be a single line")
        return value


class _RefinementResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    questions: list[_RefinedQuestion]


def refine_questions(
    *,
    model: SystemModel,
    questions: list[Question],
    client: LLMClient,
) -> str:
    """Render wording proposals without changing deterministic questions.

    The model argument remains for Python API compatibility but is deliberately
    omitted from the outbound payload: wording needs only the questions.
    """

    if not questions:
        return _with_header("No clarification questions were generated.\n")

    payload = {
        "questions": [
            {"id": item.id, "category": item.category, "question": item.question}
            for item in questions
        ]
    }
    response = client.generate_text(
        instructions=_INSTRUCTIONS,
        input_text=json.dumps(payload, sort_keys=True),
        json_schema=_REFINEMENT_SCHEMA,
    )
    try:
        parsed = _RefinementResponse.model_validate_json(response)
    except ValidationError as exc:
        raise LLMQuestionRefinementError(
            "LLM question refinement did not match the required format.",
            hint=(
                "Review questions.md directly. An existing questions_refined.md may be stale; "
                "retry before using it."
            ),
        ) from exc

    expected_ids = {item.id for item in questions}
    actual_ids = [item.id for item in parsed.questions]
    if len(actual_ids) != len(expected_ids) or set(actual_ids) != expected_ids:
        raise LLMQuestionRefinementError(
            "LLM question refinement changed the question IDs.",
            hint=(
                "Review questions.md directly. An existing questions_refined.md may be stale; "
                "retry before using it."
            ),
        )

    wording_by_id = {item.id: item.wording for item in parsed.questions}
    lines: list[str] = []
    for number, item in enumerate(questions, start=1):
        lines.extend(
            [
                f"## Question {number}",
                "",
                f"- ID: `{item.id}`",
                f"- Original: {_escape_markdown(item.question)}",
                f"- Proposed wording: {_escape_markdown(wording_by_id[item.id])}",
                "",
            ]
        )
    return _with_header("\n".join(lines))


def _escape_markdown(value: str) -> str:
    """Prevent a proposed single line from adding Markdown links or formatting."""

    return re.sub(r"([\\`*_\[\]<>])", r"\\\1", value)


def _with_header(markdown: str) -> str:
    header = "\n".join(
        [
            "# Refined Questions",
            "",
            "Optional LLM wording proposals. Compare each proposal with its deterministic "
            "original in `questions.md` before use. This file is not the source of truth.",
            "",
        ]
    )
    return header + markdown.rstrip() + "\n"
