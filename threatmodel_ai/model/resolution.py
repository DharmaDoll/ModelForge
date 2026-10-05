"""In-memory projection of accepted 0.2 facts and non-conflicting inferences."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass

from threatmodel_ai.model.schema import Edge, Node, NodeType, SystemModel
from threatmodel_ai.model.schema_v02 import Inference, SystemModelV02


@dataclass(frozen=True)
class ResolvedSystemModel:
    """A disposable analysis view with IDs of every applied inference."""

    model: SystemModel
    applied_inferences: dict[tuple[str, str], tuple[str, ...]]


def resolve_system_model_v02(canonical: SystemModelV02) -> ResolvedSystemModel:
    """Apply only non-conflicting inference values without changing canonical facts."""

    nodes = {
        node.id: Node.model_validate(node.model_dump(exclude={"attribute_evidence"}))
        for node in canonical.nodes
    }
    edges = {
        edge.id: Edge.model_validate(edge.model_dump(exclude={"attribute_evidence"}))
        for edge in canonical.edges
    }
    groups: dict[tuple[str, str], list[Inference]] = defaultdict(list)
    for inference in canonical.inferences:
        groups[(inference.subject_id, inference.predicate)].append(inference)

    applied: dict[tuple[str, str], tuple[str, ...]] = {}
    for key, group in sorted(groups.items()):
        values = {json.dumps(item.value, sort_keys=True, separators=(",", ":")) for item in group}
        if len(values) != 1:
            continue
        subject_id, predicate = key
        value = group[0].value
        if subject_id in nodes:
            nodes[subject_id] = _resolve_node(nodes[subject_id], predicate, value)
        else:
            edges[subject_id] = _resolve_edge(edges[subject_id], predicate, value)
        applied[key] = tuple(sorted(item.id for item in group))

    view = SystemModel(
        id=canonical.id,
        name=canonical.name,
        description=canonical.description,
        nodes=sorted(nodes.values(), key=lambda item: (item.type.value, item.id)),
        edges=sorted(edges.values(), key=lambda item: (item.type.value, item.id)),
        unknowns=canonical.unknowns,
        metadata=canonical.metadata,
    )
    return ResolvedSystemModel(model=view, applied_inferences=applied)


def _resolve_node(node: Node, predicate: str, value: object) -> Node:
    if predicate == "/type":
        return node.model_copy(update={"type": NodeType(value)})
    if predicate == "/trust_boundary_id":
        return node.model_copy(update={"trust_boundary_id": value})
    return node.model_copy(update={"metadata": _resolved_metadata(node.metadata, predicate, value)})


def _resolve_edge(edge: Edge, predicate: str, value: object) -> Edge:
    fields = {
        "/protocol": "protocol",
        "/authentication": "authentication",
        "/authorization": "authorization",
        "/data_assets": "data_assets",
    }
    if predicate in fields:
        return edge.model_copy(update={fields[predicate]: value})
    return edge.model_copy(update={"metadata": _resolved_metadata(edge.metadata, predicate, value)})


def _resolved_metadata(
    metadata: dict[str, object], predicate: str, value: object
) -> dict[str, object]:
    key = predicate.removeprefix("/metadata/")
    return {**metadata, key: value}
