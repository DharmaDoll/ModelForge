"""Versioned, non-authoritative threat hypotheses and model-bound validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from threatmodel_ai.model.schema import Edge, Node, SourceType, SystemModel
from threatmodel_ai.model.schema_v02 import EdgeV02, NodeV02, SystemModelV02


class _StrictModel(BaseModel):
    """Reject unexpected fields and whitespace-only strings in hypothesis data."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HypothesisEvidenceRef(_StrictModel):
    """Index into direct Evidence on an existing graph element or attribute."""

    element_id: str = Field(min_length=1)
    evidence_index: int = Field(ge=0)
    attribute_path: str | None = Field(default=None, pattern=r"^/")


class EstablishedPrerequisite(_StrictModel):
    """A claimed existing condition with pointers for a reviewer to verify."""

    statement: str = Field(min_length=1)
    citations: list[HypothesisEvidenceRef] = Field(min_length=1)


class HypothesisProvenance(_StrictModel):
    """Identify the optional generator without granting it authority."""

    origin: Literal["llm"]
    model_name: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)


class ThreatHypothesis(_StrictModel):
    """A conditional security scenario awaiting explicit human disposition."""

    id: str = Field(pattern=r"^hypothesis:[a-z0-9][a-z0-9:-]*$")
    status: Literal["proposed"]
    title: str = Field(min_length=1)
    conditional_scenario: str = Field(min_length=1)
    affected_element_ids: list[str] = Field(min_length=1)
    established_prerequisites: list[EstablishedPrerequisite] = Field(min_length=1)
    assumptions: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(min_length=1)
    provenance: HypothesisProvenance

    @model_validator(mode="after")
    def validate_unique_references(self) -> ThreatHypothesis:
        """Avoid duplicate affected IDs and evidence references."""

        if len(set(self.affected_element_ids)) != len(self.affected_element_ids):
            raise ValueError(f"hypothesis {self.id!r} repeats an affected element")
        for prerequisite in self.established_prerequisites:
            keys = [
                (ref.element_id, ref.attribute_path, ref.evidence_index)
                for ref in prerequisite.citations
            ]
            if len(set(keys)) != len(keys):
                raise ValueError(f"hypothesis {self.id!r} repeats an evidence citation")
        return self


class ThreatHypothesisBatch(_StrictModel):
    """Review-only hypotheses bound to one exact canonical model artifact."""

    schema_version: Literal["0.1"]
    model_id: str = Field(min_length=1)
    model_schema_version: Literal["0.1", "0.2"]
    model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    not_source_of_truth: Literal[True]
    hypotheses: list[ThreatHypothesis] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> ThreatHypothesisBatch:
        """Candidate IDs must be unique within an artifact."""

        ids = [item.id for item in self.hypotheses]
        if len(set(ids)) != len(ids):
            raise ValueError("threat hypotheses contain duplicate ids")
        return self


def model_sha256(model: SystemModel | SystemModelV02) -> str:
    """Fingerprint the exact model snapshot used by evidence-index citations."""

    payload = json.dumps(
        model.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_hypotheses_against_model(
    batch: ThreatHypothesisBatch, model: SystemModel | SystemModelV02
) -> None:
    """Reject stale, missing, or derived-only citations without judging truth."""

    if batch.model_id != model.id or batch.model_schema_version != model.schema_version:
        raise ValueError("threat hypotheses target a different system model")
    if batch.model_sha256 != model_sha256(model):
        raise ValueError("threat hypotheses target a different model snapshot")

    node_ids = {node.id for node in model.nodes}
    edge_ids = {edge.id for edge in model.edges}
    if node_ids & edge_ids:
        raise ValueError("threat hypotheses need unambiguous node and edge IDs")

    elements: dict[str, Node | Edge | NodeV02 | EdgeV02] = {
        **{node.id: node for node in model.nodes},
        **{edge.id: edge for edge in model.edges},
    }
    for hypothesis in batch.hypotheses:
        for element_id in hypothesis.affected_element_ids:
            if element_id not in elements:
                raise ValueError(f"hypothesis {hypothesis.id!r} has missing affected element")

        cited_ids: set[str] = set()
        for prerequisite in hypothesis.established_prerequisites:
            for citation in prerequisite.citations:
                element = elements.get(citation.element_id)
                if element is None:
                    raise ValueError(f"hypothesis {hypothesis.id!r} cites a missing element")
                cited_ids.add(citation.element_id)
                evidence = element.evidence
                if citation.attribute_path is not None:
                    if not isinstance(element, (NodeV02, EdgeV02)):
                        raise ValueError(
                            f"hypothesis {hypothesis.id!r} cites an attribute on a 0.1 model"
                        )
                    evidence = element.attribute_evidence.get(citation.attribute_path, [])
                if citation.evidence_index >= len(evidence):
                    raise ValueError(f"hypothesis {hypothesis.id!r} has missing Evidence")
                if evidence[citation.evidence_index].source_type == SourceType.DERIVED:
                    raise ValueError(f"hypothesis {hypothesis.id!r} cites derived-only Evidence")
        if not cited_ids.intersection(hypothesis.affected_element_ids):
            raise ValueError(f"hypothesis {hypothesis.id!r} has no cited affected element")


def read_threat_hypotheses(
    path: Path, *, model: SystemModel | SystemModelV02
) -> ThreatHypothesisBatch:
    """Load a candidate artifact and verify its references against a model."""

    batch = ThreatHypothesisBatch.model_validate_json(path.read_text(encoding="utf-8"))
    validate_hypotheses_against_model(batch, model)
    return batch


def threat_hypothesis_json_schema() -> dict[str, object]:
    """Export structural schema; model-bound citations need semantic validation."""

    schema = ThreatHypothesisBatch.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$comment"] = (
        "Structural contract only. Validate against the exact system model for "
        "referential integrity and direct Evidence."
    )
    return schema
