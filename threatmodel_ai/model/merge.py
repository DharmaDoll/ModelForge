"""Merge multiple extractor outputs into one deterministic system model."""

from __future__ import annotations

from collections.abc import Iterable

from threatmodel_ai.model.schema import Edge, Evidence, Node, SystemModel, Unknown


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

    for model in model_list:
        metadata.update(model.metadata)
        for node in model.nodes:
            nodes[node.id] = _merge_node(nodes[node.id], node) if node.id in nodes else node
        for edge in model.edges:
            edges[edge.id] = _merge_edge(edges[edge.id], edge) if edge.id in edges else edge
        for unknown in model.unknowns:
            unknowns.setdefault(unknown.id, unknown)

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


def _merge_node(left: Node, right: Node) -> Node:
    return left.model_copy(
        update={
            "name": _prefer_known(left.name, right.name),
            "description": _prefer_known(left.description, right.description),
            "trust_boundary_id": left.trust_boundary_id or right.trust_boundary_id,
            "metadata": {**left.metadata, **right.metadata},
            "evidence": _merge_evidence(left.evidence, right.evidence),
        }
    )


def _merge_edge(left: Edge, right: Edge) -> Edge:
    return left.model_copy(
        update={
            "description": _prefer_known(left.description, right.description),
            "protocol": _prefer_known(left.protocol, right.protocol),
            "authentication": _prefer_known(left.authentication, right.authentication),
            "authorization": _prefer_known(left.authorization, right.authorization),
            "data_assets": sorted(set(left.data_assets) | set(right.data_assets)),
            "metadata": {**left.metadata, **right.metadata},
            "evidence": _merge_evidence(left.evidence, right.evidence),
        }
    )


def _prefer_known(left: str, right: str) -> str:
    if left and left != "unknown":
        return left
    return right or "unknown"


def _merge_evidence(left: list[Evidence], right: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str, str]] = set()
    merged: list[Evidence] = []
    for evidence in [*left, *right]:
        key = (evidence.source_type.value, evidence.source_path, evidence.detail)
        if key not in seen:
            seen.add(key)
            merged.append(evidence)
    return merged
