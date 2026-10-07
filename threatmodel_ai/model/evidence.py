"""Utilities for carrying provenance through generated artifacts."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

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


def relativize_project_paths(model: SystemModel, project_root: Path) -> SystemModel:
    """Make in-project provenance portable, leaving explicit external paths intact."""

    root = project_root.resolve()
    payload = model.model_dump(mode="json", exclude_none=True)
    for element in (*payload["nodes"], *payload["edges"]):
        _relativize_evidence(element.get("evidence", []), root)
    for unknown in payload["unknowns"]:
        if unknown.get("evidence"):
            _relativize_evidence([unknown["evidence"]], root)
        _relativize_evidence(unknown.get("conflicting_evidence", []), root)

    metadata = payload["metadata"]
    for key in ("readme_path", "openapi_path"):
        if isinstance(metadata.get(key), str):
            metadata[key] = _project_path(metadata[key], root)
    for key in ("mermaid_files", "terraform_files"):
        if isinstance(metadata.get(key), list):
            metadata[key] = [
                _project_path(path, root) if isinstance(path, str) else path
                for path in metadata[key]
            ]
    return SystemModel.model_validate(payload)


def _relativize_evidence(items: list[dict[str, Any]], root: Path) -> None:
    """Rewrite only file pointers belonging to the analyzed project."""

    for item in items:
        item["source_path"] = _project_path(item["source_path"], root)


def _project_path(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        return value
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return value


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
            collected.extend(unknowns[element_id].conflicting_evidence or [])

    return merge_evidence(collected)
