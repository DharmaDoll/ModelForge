"""Merge multiple extractor outputs into one deterministic system model."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from threatmodel_ai.model.evidence import merge_evidence
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SystemModel,
    Unknown,
)


def merge_system_models(models: Iterable[SystemModel]) -> SystemModel:
    """Merge extractor-level models into a single validated model."""

    model_list = list(models)
    if not model_list:
        return SystemModel()

    name = _first_known(model.name for model in model_list)
    description = _first_known(model.description for model in model_list)
    metadata: dict[str, object] = {}
    nodes: dict[str, Node] = {}
    edges: dict[str, Edge] = {}
    unknowns: dict[str, Unknown] = {}
    conflicted_fields: dict[str, set[str]] = {}

    for model in model_list:
        metadata.update(model.metadata)
        for node in model.nodes:
            if node.id in nodes:
                nodes[node.id], conflicts = _merge_node(
                    nodes[node.id], node, conflicted_fields.setdefault(node.id, set())
                )
                unknowns.update({conflict.id: conflict for conflict in conflicts})
            else:
                nodes[node.id] = node
        for edge in model.edges:
            if edge.id in edges:
                edges[edge.id], conflicts = _merge_edge(
                    edges[edge.id], edge, conflicted_fields.setdefault(edge.id, set())
                )
                unknowns.update({conflict.id: conflict for conflict in conflicts})
            else:
                edges[edge.id] = edge
        for unknown in model.unknowns:
            unknowns.setdefault(unknown.id, unknown)

    removed_edge_ids = {
        edge_id
        for edge_id, edge in edges.items()
        if edge.metadata.get("derived_from") == "terraform_exposure"
        and nodes[edge.target].metadata.get("internet_exposed") is not True
    }
    for edge_id in removed_edge_ids:
        edges.pop(edge_id)
    removed_actor_ids = {
        node_id
        for node_id, node in nodes.items()
        if node.metadata.get("derived_from") == "terraform_exposure"
        and not any(edge.source == node_id or edge.target == node_id for edge in edges.values())
    }
    for node_id in removed_actor_ids:
        nodes.pop(node_id)
    unknowns = {
        unknown_id: unknown
        for unknown_id, unknown in unknowns.items()
        if unknown.related_element_id not in removed_edge_ids | removed_actor_ids
    }

    for unknown_id, unknown in list(unknowns.items()):
        if unknown.category != "model_conflict" or not unknown.related_element_id:
            continue
        element = nodes.get(unknown.related_element_id) or edges.get(unknown.related_element_id)
        if element is None:
            continue
        evidence = merge_evidence(element.evidence)
        unknowns[unknown_id] = unknown.model_copy(
            update={
                "evidence": evidence[0] if evidence else None,
                "conflicting_evidence": evidence[1:] or None,
            }
        )

    return SystemModel(
        name=name,
        description=description,
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges.values(), key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns.values(), key=lambda unknown: unknown.id),
        metadata=metadata,
    )


def _first_known(values: Iterable[str]) -> str:
    for value in values:
        if value and value != "unknown":
            return value
    return "unknown"


def _merge_node(left: Node, right: Node, blocked: set[str]) -> tuple[Node, list[Unknown]]:
    conflicts: list[Unknown] = []
    name = _prefer_known(left.name, right.name)
    if (
        "name" not in blocked
        and left.name != "unknown"
        and right.name != "unknown"
        and left.name != right.name
    ):
        blocked.add("name")
        conflicts.append(_conflict(left.id, "name", left.evidence, right.evidence))
    if "name" in blocked:
        name = "unknown"
    node_type = right.type if left.type == NodeType.UNKNOWN else left.type
    if (
        left.type != NodeType.UNKNOWN
        and right.type != NodeType.UNKNOWN
        and left.type != right.type
        and "type" not in blocked
    ):
        blocked.add("type")
        conflicts.append(_conflict(left.id, "type", left.evidence, right.evidence))
    if "type" in blocked:
        node_type = NodeType.UNKNOWN
    boundary = left.trust_boundary_id or right.trust_boundary_id
    if "trust_boundary_id" not in blocked and (
        left.trust_boundary_id
        and right.trust_boundary_id
        and left.trust_boundary_id != right.trust_boundary_id
    ):
        blocked.add("trust_boundary_id")
        boundary = None
        conflicts.append(_conflict(left.id, "trust_boundary_id", left.evidence, right.evidence))
    if "trust_boundary_id" in blocked:
        boundary = None
    metadata, metadata_conflicts = _merge_metadata(
        left.id, left.metadata, right.metadata, left.evidence, right.evidence, blocked
    )
    conflicts.extend(metadata_conflicts)
    return left.model_copy(
        update={
            "name": name,
            "description": _prefer_known(left.description, right.description),
            "type": node_type,
            "trust_boundary_id": boundary,
            "metadata": metadata,
            "evidence": merge_evidence([*left.evidence, *right.evidence]),
        }
    ), conflicts


def _merge_edge(left: Edge, right: Edge, blocked: set[str]) -> tuple[Edge, list[Unknown]]:
    if (left.source, left.target) != (right.source, right.target):
        raise ValueError(f"edge {left.id!r} has conflicting endpoints")
    conflicts: list[Unknown] = []
    edge_type = left.type
    if left.type != right.type and "type" not in blocked:
        blocked.add("type")
        conflicts.append(_conflict(left.id, "type", left.evidence, right.evidence))
    if "type" in blocked:
        edge_type = EdgeType.REFERENCES
    attributes: dict[str, str] = {}
    for field in ("protocol", "authentication", "authorization"):
        old, new = getattr(left, field), getattr(right, field)
        attributes[field] = _prefer_known(old, new)
        if (
            field not in blocked
            and old not in {"", "unknown"}
            and new not in {"", "unknown"}
            and old != new
        ):
            blocked.add(field)
            conflicts.append(_conflict(left.id, field, left.evidence, right.evidence))
        if field in blocked:
            attributes[field] = "unknown"
    data_assets = sorted(set(left.data_assets) | set(right.data_assets))
    if (
        "data_assets" not in blocked
        and left.data_assets
        and right.data_assets
        and set(left.data_assets) != set(right.data_assets)
    ):
        blocked.add("data_assets")
        conflicts.append(_conflict(left.id, "data_assets", left.evidence, right.evidence))
    if "data_assets" in blocked:
        data_assets = []
    metadata, metadata_conflicts = _merge_metadata(
        left.id, left.metadata, right.metadata, left.evidence, right.evidence, blocked
    )
    conflicts.extend(metadata_conflicts)
    return left.model_copy(
        update={
            "description": _prefer_known(left.description, right.description),
            "type": edge_type,
            **attributes,
            "data_assets": data_assets,
            "metadata": metadata,
            "evidence": merge_evidence([*left.evidence, *right.evidence]),
        }
    ), conflicts


def _merge_metadata(
    element_id: str,
    left: dict[str, Any],
    right: dict[str, Any],
    left_evidence: list[Evidence],
    right_evidence: list[Evidence],
    blocked: set[str],
) -> tuple[dict[str, Any], list[Unknown]]:
    metadata = dict(left)
    conflicts: list[Unknown] = []
    for key, value in right.items():
        field = f"metadata/{key}"
        if field in blocked:
            metadata.pop(key, None)
            continue
        if key in metadata and metadata[key] != value:
            metadata.pop(key)
            blocked.add(field)
            conflicts.append(_conflict(element_id, field, left_evidence, right_evidence))
        else:
            metadata[key] = value
    return metadata, conflicts


def _conflict(
    element_id: str,
    field: str,
    left_evidence: list[Evidence],
    right_evidence: list[Evidence],
) -> Unknown:
    evidence = merge_evidence([*left_evidence, *right_evidence])
    return Unknown(
        id=make_id("unknown", "conflict", element_id, field),
        category="model_conflict",
        description=(
            f"Conflicting input claims for {element_id} field {field}; review the evidence."
        ),
        related_element_id=element_id,
        evidence=evidence[0] if evidence else None,
        conflicting_evidence=evidence[1:] or None,
    )


def _prefer_known(left: str, right: str) -> str:
    if left and left != "unknown":
        return left
    return right or "unknown"
