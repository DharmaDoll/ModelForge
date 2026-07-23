"""Optional LLM structured candidate extraction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, ValidationInfo, model_validator

from threatmodel_ai.errors import ModelForgeError
from threatmodel_ai.llm.client import LLMClient
from threatmodel_ai.model.schema import EdgeType, NodeType, SourceType, SystemModel

_INSTRUCTIONS = """\
Extract structured threat-model candidates from a README.

Hard rules:
- Return JSON only. Do not wrap it in Markdown.
- The JSON must match this shape:
  {
    "source_path": "README path",
    "source_type": "readme",
    "nodes": [],
    "edges": [],
    "unknowns": [],
    "warnings": []
  }
- Candidates are not the source of truth.
- Extract only facts directly supported by the README text.
- Do not invent architecture, authentication, authorization, trust boundaries, protocols, or data.
- Unsupported or ambiguous facts must become unknowns or warnings.
- Every candidate must include confidence between 0 and 1.
- Every candidate must include evidence with source_path, detail, optional line, and excerpt.
- Evidence excerpts must be short and copied from the README text.
- IDs must be stable, lowercase, and colon-delimited when possible.
"""


class LLMCandidateValidationError(ModelForgeError):
    """Raised when LLM candidate JSON cannot be validated."""


class CandidateEvidence(BaseModel):
    """Evidence attached to an LLM candidate."""

    model_config = ConfigDict(extra="forbid")

    source_type: Literal[SourceType.README] = SourceType.README
    source_path: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    excerpt: str = Field(min_length=1, max_length=500)
    line: int | None = Field(default=None, ge=1)


class CandidateNode(BaseModel):
    """A possible graph node extracted by an LLM."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    type: NodeType
    description: str = Field(default="unknown", min_length=1)
    confidence: float = Field(ge=0, le=1)
    evidence: list[CandidateEvidence] = Field(min_length=1)


class CandidateEdge(BaseModel):
    """A possible graph edge extracted by an LLM."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    type: EdgeType
    description: str = Field(default="unknown", min_length=1)
    protocol: str = Field(default="unknown", min_length=1)
    authentication: str = Field(default="unknown", min_length=1)
    authorization: str = Field(default="unknown", min_length=1)
    data_assets: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    evidence: list[CandidateEvidence] = Field(min_length=1)


class CandidateUnknown(BaseModel):
    """A possible unknown extracted by an LLM."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_element_id: str | None = None
    confidence: float = Field(ge=0, le=1)
    evidence: list[CandidateEvidence] = Field(min_length=1)


class LLMCandidateModel(BaseModel):
    """Structured LLM candidates that must be reviewed before merge."""

    model_config = ConfigDict(extra="forbid")

    source_path: str = Field(min_length=1)
    source_type: Literal[SourceType.README] = SourceType.README
    nodes: list[CandidateNode] = Field(default_factory=list)
    edges: list[CandidateEdge] = Field(default_factory=list)
    unknowns: list[CandidateUnknown] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    not_source_of_truth: bool = True

    @model_validator(mode="after")
    def validate_candidate_references(self, info: ValidationInfo) -> LLMCandidateModel:
        """Reject internally inconsistent candidate graphs."""

        node_ids = {node.id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("LLM candidates contain duplicate node ids")

        edge_ids = {edge.id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise ValueError("LLM candidates contain duplicate edge ids")

        unknown_ids = {unknown.id for unknown in self.unknowns}
        if len(unknown_ids) != len(self.unknowns):
            raise ValueError("LLM candidates contain duplicate unknown ids")

        allowed_node_ids = _context_set(info, "allowed_node_ids")
        allowed_element_ids = _context_set(info, "allowed_element_ids")
        valid_node_ids = node_ids | allowed_node_ids

        for edge in self.edges:
            if edge.source not in valid_node_ids:
                raise ValueError(
                    f"LLM candidate edge {edge.id!r} references missing source "
                    f"{edge.source!r}"
                )
            if edge.target not in valid_node_ids:
                raise ValueError(
                    f"LLM candidate edge {edge.id!r} references missing target "
                    f"{edge.target!r}"
                )
            missing_assets = [asset for asset in edge.data_assets if asset not in valid_node_ids]
            if missing_assets:
                raise ValueError(
                    f"LLM candidate edge {edge.id!r} references missing data assets "
                    f"{missing_assets!r}"
                )

        candidate_ids = node_ids | edge_ids
        valid_element_ids = candidate_ids | allowed_element_ids
        for unknown in self.unknowns:
            if unknown.related_element_id and unknown.related_element_id not in valid_element_ids:
                raise ValueError(
                    f"LLM candidate unknown {unknown.id!r} references missing element "
                    f"{unknown.related_element_id!r}"
                )
        return self


def extract_readme_candidates(path: Path, client: LLMClient) -> LLMCandidateModel:
    """Extract structured candidates from README text using an optional LLM."""

    readme_text = path.read_text(encoding="utf-8")
    response = client.generate_text(
        instructions=_INSTRUCTIONS,
        input_text=json.dumps(
            {
                "source_path": str(path),
                "source_type": SourceType.README.value,
                "readme_text": readme_text,
            },
            indent=2,
            sort_keys=True,
        ),
    )
    try:
        payload = json.loads(_strip_json_fence(response))
    except json.JSONDecodeError as exc:
        raise LLMCandidateValidationError(
            "LLM README candidates failed validation.",
            detail=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}.",
            hint=(
                "Retry the extraction, inspect the model output, or run without "
                "--llm extract-readme."
            ),
        ) from exc
    try:
        return LLMCandidateModel.model_validate(payload)
    except ValidationError as exc:
        raise LLMCandidateValidationError(
            "LLM README candidates failed validation.",
            detail=_validation_detail(exc),
            hint=(
                "Retry the extraction, inspect the model output, or run without "
                "--llm extract-readme."
            ),
        ) from exc


def read_llm_candidates(
    path: Path,
    *,
    base_model: SystemModel | None = None,
) -> LLMCandidateModel:
    """Load and validate reviewed LLM candidates from disk."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LLMCandidateValidationError(
            "LLM candidate file failed validation.",
            detail=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}.",
            hint="Fix llm_candidates.json before merging it.",
        ) from exc

    context = _validation_context(base_model)
    try:
        return LLMCandidateModel.model_validate(payload, context=context)
    except ValidationError as exc:
        raise LLMCandidateValidationError(
            "LLM candidate file failed validation.",
            detail=_validation_detail(exc),
            hint=(
                "Review candidate IDs, evidence, confidence values, and references "
                "before merging."
            ),
        ) from exc


def _strip_json_fence(value: str) -> str:
    text = value.strip()
    match = re.fullmatch(r"```(?:json)?\s*(?P<body>.*?)\s*```", text, re.DOTALL)
    return match.group("body") if match else text


def _validation_detail(error: ValidationError) -> str:
    details: list[str] = []
    for item in error.errors()[:3]:
        location = ".".join(str(part) for part in item.get("loc", ())) or "model"
        details.append(f"{location}: {item.get('msg', 'invalid value')}")
    remaining = len(error.errors()) - len(details)
    if remaining > 0:
        details.append(f"...and {remaining} more validation error(s)")
    return "; ".join(details)


def _validation_context(base_model: SystemModel | None) -> dict[str, set[str]]:
    if base_model is None:
        return {}
    node_ids = {node.id for node in base_model.nodes}
    edge_ids = {edge.id for edge in base_model.edges}
    return {
        "allowed_node_ids": node_ids,
        "allowed_element_ids": node_ids | edge_ids,
    }


def _context_set(info: ValidationInfo, key: str) -> set[str]:
    if not isinstance(info.context, dict):
        return set()
    values = info.context.get(key, set())
    return {str(value) for value in values}
