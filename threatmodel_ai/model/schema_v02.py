"""Draft 0.2 canonical schema with explicit, evidence-bearing inferences."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import (
    Edge,
    Evidence,
    Node,
    NodeType,
    SystemModel,
)

_MISSING = object()
_NODE_PREDICATES = {"/type", "/trust_boundary_id"}
_EDGE_PREDICATES = {"/protocol", "/authentication", "/authorization", "/data_assets"}
_METADATA_PREDICATES = {
    "/metadata/internet_exposed",
    "/metadata/logging",
    "/metadata/rate_limiting",
    "/metadata/classification",
}
_ATTRIBUTE_POINTERS = (
    _NODE_PREDICATES
    | _EDGE_PREDICATES
    | _METADATA_PREDICATES
    | {
        "/name",
        "/description",
    }
)


class ModelReference(BaseModel):
    """One JSON Pointer into an existing model element."""

    model_config = ConfigDict(extra="forbid")

    element_id: str = Field(min_length=1)
    path: str = Field(pattern=r"^/", min_length=2)


class Inference(BaseModel):
    """A deterministic or reviewed architecture claim, distinct from a fact."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    predicate: str = Field(pattern=r"^/", min_length=2)
    value: Any
    based_on: list[ModelReference] = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    provenance_class: Literal["deterministic", "human_reviewed"]
    evidence: list[Evidence] = Field(min_length=1)


class IdentityAlias(BaseModel):
    """Explicitly reviewed alias from a historical ID to a current element."""

    model_config = ConfigDict(extra="forbid")

    legacy_id: str = Field(min_length=1)
    current_id: str = Field(min_length=1)
    reviewed_by: str = Field(min_length=1)


class NodeV02(Node):
    """Node existence evidence and per-attribute evidence are separate."""

    attribute_evidence: dict[str, list[Evidence]] = Field(default_factory=dict)


class EdgeV02(Edge):
    """Edge existence evidence and per-attribute evidence are separate."""

    attribute_evidence: dict[str, list[Evidence]] = Field(default_factory=dict)


class SystemModelV02(SystemModel):
    """Validated 0.2 model; not yet the default extractor output format."""

    schema_version: Literal["0.2"] = "0.2"
    nodes: list[NodeV02] = Field(default_factory=list)
    edges: list[EdgeV02] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    inferences: list[Inference] = Field(default_factory=list)
    identity_aliases: list[IdentityAlias] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_semantics(self) -> SystemModelV02:
        """Ensure inference claims are bounded, referential, and non-overwriting."""

        node_ids = {node.id for node in self.nodes}
        edge_ids = {edge.id for edge in self.edges}
        if node_ids & edge_ids:
            raise ValueError("0.2 model reuses an id across node and edge kinds")
        elements: dict[str, NodeV02 | EdgeV02] = {
            **{node.id: node for node in self.nodes},
            **{edge.id: edge for edge in self.edges},
        }
        if len({item.id for item in self.inferences}) != len(self.inferences):
            raise ValueError("0.2 model contains duplicate inference ids")
        if {item.id for item in self.inferences} & (
            node_ids | edge_ids | {unknown.id for unknown in self.unknowns}
        ):
            raise ValueError("0.2 model reuses an inference id for another element")

        for element in elements.values():
            for pointer, evidence in element.attribute_evidence.items():
                if pointer not in _ATTRIBUTE_POINTERS:
                    raise ValueError(
                        f"attribute evidence for {element.id} {pointer} is unsupported"
                    )
                if not evidence:
                    raise ValueError(f"attribute evidence for {element.id} {pointer} is empty")
                value = _pointer_value(element, pointer)
                if value is _MISSING or value is None or value == "unknown":
                    raise ValueError(
                        f"attribute evidence for {element.id} {pointer} has no known value"
                    )

        claims: dict[tuple[str, str], list[Inference]] = {}
        for inference in self.inferences:
            subject = elements.get(inference.subject_id)
            if subject is None:
                raise ValueError(f"inference {inference.id!r} has missing subject")
            _validate_inference_value(inference, subject, elements)
            current = _pointer_value(subject, inference.predicate)
            if current is not _MISSING and current not in (None, "unknown", []):
                raise ValueError(f"inference {inference.id!r} would overwrite a known fact")
            for reference in inference.based_on:
                source = elements.get(reference.element_id)
                if source is None or _pointer_value(source, reference.path) is _MISSING:
                    raise ValueError(f"inference {inference.id!r} has missing based_on reference")
            claims.setdefault((inference.subject_id, inference.predicate), []).append(inference)

        unknown_by_id = {unknown.id: unknown for unknown in self.unknowns}
        for (subject_id, predicate), group in claims.items():
            if len({_canonical_value(item.value) for item in group}) <= 1:
                continue
            conflict_id = make_id("unknown", "inference-conflict", subject_id, predicate)
            conflict = unknown_by_id.get(conflict_id)
            if (
                conflict is None
                or conflict.category != "inference_conflict"
                or conflict.related_element_id != subject_id
            ):
                raise ValueError(
                    f"conflicting inferences for {subject_id} {predicate} need "
                    f"unknown {conflict_id}"
                )

        aliases = {(alias.legacy_id, alias.current_id) for alias in self.identity_aliases}
        if len(aliases) != len(self.identity_aliases):
            raise ValueError("0.2 model contains duplicate identity aliases")
        if len({alias.legacy_id for alias in self.identity_aliases}) != len(self.identity_aliases):
            raise ValueError("one legacy id cannot map to multiple current ids")
        for alias in self.identity_aliases:
            if alias.current_id not in elements or alias.legacy_id == alias.current_id:
                raise ValueError("identity alias must point to a distinct current element")

        return self


def _validate_inference_value(
    inference: Inference,
    subject: NodeV02 | EdgeV02,
    elements: dict[str, NodeV02 | EdgeV02],
) -> None:
    """Restrict writable inference paths and their value types."""

    predicate = inference.predicate
    allowed = _NODE_PREDICATES if isinstance(subject, NodeV02) else _EDGE_PREDICATES
    if predicate not in allowed | _METADATA_PREDICATES:
        raise ValueError(f"inference {inference.id!r} has unsupported predicate")
    value = inference.value
    if predicate == "/type":
        if not isinstance(value, str) or value not in {
            item.value for item in NodeType if item != NodeType.UNKNOWN
        }:
            raise ValueError(f"inference {inference.id!r} has invalid node type")
    elif predicate == "/trust_boundary_id":
        boundary = elements.get(value) if isinstance(value, str) else None
        if not isinstance(boundary, NodeV02) or boundary.type != NodeType.TRUST_BOUNDARY:
            raise ValueError(f"inference {inference.id!r} has invalid trust boundary")
    elif predicate == "/data_assets":
        if (
            not isinstance(value, list)
            or not value
            or any(
                not isinstance(item, str) or not isinstance(elements.get(item), NodeV02)
                for item in value
            )
        ):
            raise ValueError(f"inference {inference.id!r} has invalid data assets")
    elif predicate in {
        "/metadata/internet_exposed",
        "/metadata/logging",
        "/metadata/rate_limiting",
    }:
        if not isinstance(value, bool):
            raise ValueError(f"inference {inference.id!r} requires a boolean value")
    elif not isinstance(value, str) or not value or value == "unknown":
        raise ValueError(f"inference {inference.id!r} requires a known string value")


def _pointer_value(element: NodeV02 | EdgeV02, pointer: str) -> Any:
    """Resolve a JSON Pointer without evaluation or attribute access."""

    if not pointer.startswith("/"):
        return _MISSING
    value: Any = element.model_dump(mode="json")
    for raw_part in pointer[1:].split("/"):
        if "~" in raw_part and not all(
            raw_part[index : index + 2] in {"~0", "~1"}
            for index, char in enumerate(raw_part)
            if char == "~"
        ):
            return _MISSING
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdecimal() and int(part) < len(value):
            value = value[int(part)]
        else:
            return _MISSING
    return value


def _canonical_value(value: Any) -> str:
    """Use canonical JSON to compare inference values deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
