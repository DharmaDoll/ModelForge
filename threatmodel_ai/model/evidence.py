"""Utilities for carrying provenance through generated artifacts."""

from __future__ import annotations

from collections.abc import Iterable

from threatmodel_ai.model.schema import Evidence, SystemModel


def merge_evidence(items: Iterable[Evidence]) -> list[Evidence]:
    """Return evidence pointers in first-seen order without duplicates."""

    seen: set[tuple[str, str, str, str, int | None]] = set()
    merged: list[Evidence] = []
    for evidence in items:
        key = (
            evidence.source_type.value,
            evidence.source_path,
            evidence.extractor,
            evidence.detail,
            evidence.line,
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(evidence)
    return merged


def evidence_from_model(model: SystemModel, element_ids: Iterable[str]) -> list[Evidence]:
    """Collect source evidence for graph and unknown IDs in a system model."""

    nodes = {node.id: node for node in model.nodes}
    edges = {edge.id: edge for edge in model.edges}
    unknowns = {unknown.id: unknown for unknown in model.unknowns}
    collected: list[Evidence] = []

    for element_id in element_ids:
        if element_id in edges:
            collected.extend(edges[element_id].evidence)
        elif element_id in nodes:
            collected.extend(nodes[element_id].evidence)
        elif element_id in unknowns and unknowns[element_id].evidence:
            collected.append(unknowns[element_id].evidence)

    return merge_evidence(collected)
