"""Mermaid DFD extractor for Markdown fenced blocks."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SourceType,
    SystemModel,
    Unknown,
)

_FENCE_START_RE = re.compile(r"^\s*```\s*mermaid\s*$", re.IGNORECASE)
_FENCE_END_RE = re.compile(r"^\s*```\s*$")
_DIAGRAM_HEADER_RE = re.compile(r"^\s*(flowchart|graph)\b", re.IGNORECASE)
_EDGE_RE = re.compile(
    r"^\s*(?P<left>.+?)\s*(?P<arrow>-->|==>|-\.->)\s*"
    r"(?:\|(?P<label>[^|]+)\|)?\s*(?P<right>.+?)\s*$"
)
_NODE_RE = re.compile(r"^(?P<alias>[A-Za-z0-9_][A-Za-z0-9_-]*)(?P<shape>.*)$")
_QUOTED_LABEL_RE = re.compile(r"""["'](?P<label>[^"']+)["']""")
_KNOWN_PROTOCOLS = {
    "HTTP": "HTTP",
    "HTTPS": "HTTPS",
    "GRPC": "gRPC",
}


def extract_mermaid_markdown(path: Path) -> SystemModel:
    """Extract conservative graph facts from Mermaid flowchart blocks in Markdown."""

    text = path.read_text(encoding="utf-8")
    nodes: dict[str, Node] = {}
    edges: dict[str, Edge] = {}
    unknowns: dict[str, Unknown] = {}

    for block_index, block in enumerate(_mermaid_blocks(text), start=1):
        _extract_block(path, block_index, block, nodes, edges, unknowns)

    return SystemModel(
        name="unknown",
        description="unknown",
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges.values(), key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns.values(), key=lambda unknown: unknown.id),
        metadata={"mermaid_files": [str(path)] if nodes or edges else []},
    )


def _mermaid_blocks(text: str) -> Iterator[list[str]]:
    in_block = False
    block: list[str] = []
    for line in text.splitlines():
        if not in_block and _FENCE_START_RE.match(line):
            in_block = True
            block = []
            continue
        if in_block and _FENCE_END_RE.match(line):
            in_block = False
            yield block
            block = []
            continue
        if in_block:
            block.append(line)


def _extract_block(
    path: Path,
    block_index: int,
    block: list[str],
    nodes: dict[str, Node],
    edges: dict[str, Edge],
    unknowns: dict[str, Unknown],
) -> None:
    if not any(_DIAGRAM_HEADER_RE.match(line) for line in block):
        return

    for line_number, raw_line in enumerate(block, start=1):
        line = _strip_comment(raw_line).strip().rstrip(";")
        if not line or _DIAGRAM_HEADER_RE.match(line):
            continue
        match = _EDGE_RE.match(line)
        if not match:
            continue

        left = _parse_node(match.group("left"))
        right = _parse_node(match.group("right"))
        if not left or not right:
            continue

        label = (match.group("label") or "").strip()
        evidence = Evidence(
            source_type=SourceType.MARKDOWN,
            source_path=str(path),
            detail=f"mermaid block {block_index}, line {line_number}",
        )
        source = _node(left, evidence)
        target = _node(right, evidence)
        nodes[source.id] = _merge_node(nodes.get(source.id), source)
        nodes[target.id] = _merge_node(nodes.get(target.id), target)

        protocol = _protocol_from_label(label)
        edge_id = make_id("edge", source.id, target.id, "mermaid")
        edge = Edge(
            id=edge_id,
            source=source.id,
            target=target.id,
            type=EdgeType.COMMUNICATES_WITH,
            description=_edge_description(source.name, target.name, label),
            protocol=protocol,
            metadata={
                "source_format": "mermaid",
                "mermaid_label": label,
                "mermaid_arrow": match.group("arrow"),
            },
            evidence=[evidence],
        )
        edges[edge.id] = _merge_edge(edges.get(edge.id), edge)
        for unknown in _edge_unknowns(edge, source, target, evidence):
            unknowns.setdefault(unknown.id, unknown)


def _strip_comment(line: str) -> str:
    return line.split("%%", maxsplit=1)[0]


class _ParsedNode:
    def __init__(self, alias: str, label: str) -> None:
        self.alias = alias
        self.label = label


def _parse_node(raw: str) -> _ParsedNode | None:
    token = raw.strip()
    match = _NODE_RE.match(token)
    if not match:
        return None

    alias = match.group("alias")
    shape = match.group("shape").strip()
    quoted = _QUOTED_LABEL_RE.search(shape)
    if quoted:
        label = quoted.group("label").strip()
    elif shape:
        label = shape.strip(" [](){}<>/\\")
    else:
        label = alias
    return _ParsedNode(alias=alias, label=label or alias)


def _node(parsed: _ParsedNode, evidence: Evidence) -> Node:
    node_id = make_id("component", "mermaid", parsed.alias)
    return Node(
        id=node_id,
        name=parsed.label,
        type=NodeType.COMPONENT,
        description=f"Mermaid node {parsed.alias}.",
        metadata={"source_format": "mermaid", "mermaid_alias": parsed.alias},
        evidence=[evidence],
    )


def _merge_node(existing: Node | None, incoming: Node) -> Node:
    if not existing:
        return incoming
    existing_alias = str(existing.metadata.get("mermaid_alias") or "")
    incoming_alias = str(incoming.metadata.get("mermaid_alias") or "")
    return existing.model_copy(
        update={
            "name": _prefer_labeled_name(
                existing.name,
                incoming.name,
                existing_alias or incoming_alias,
            ),
            "metadata": {**existing.metadata, **incoming.metadata},
            "evidence": [*existing.evidence, *incoming.evidence],
        }
    )


def _merge_edge(existing: Edge | None, incoming: Edge) -> Edge:
    if not existing:
        return incoming
    return existing.model_copy(
        update={
            "description": existing.description,
            "protocol": existing.protocol if existing.protocol != "unknown" else incoming.protocol,
            "metadata": {**existing.metadata, **incoming.metadata},
            "evidence": [*existing.evidence, *incoming.evidence],
        }
    )


def _prefer_labeled_name(existing_name: str, incoming_name: str, alias: str) -> str:
    if existing_name == alias and incoming_name != alias:
        return incoming_name
    return existing_name


def _edge_description(source_name: str, target_name: str, label: str) -> str:
    if label:
        return f"Mermaid flow from {source_name} to {target_name}: {label}."
    return f"Mermaid flow from {source_name} to {target_name}."


def _protocol_from_label(label: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9]+", label.upper())
    for token in tokens:
        if token in _KNOWN_PROTOCOLS:
            return _KNOWN_PROTOCOLS[token]
    return "unknown"


def _edge_unknowns(edge: Edge, source: Node, target: Node, evidence: Evidence) -> list[Unknown]:
    unknowns = [
        Unknown(
            id=make_id("unknown", "mermaid", edge.id, "authentication"),
            category="authentication",
            description=(
                f"Authentication for Mermaid flow {source.name} to {target.name} is unknown."
            ),
            related_element_id=edge.id,
            evidence=evidence,
        ),
        Unknown(
            id=make_id("unknown", "mermaid", edge.id, "authorization"),
            category="authorization",
            description=(
                f"Authorization for Mermaid flow {source.name} to {target.name} is unknown."
            ),
            related_element_id=edge.id,
            evidence=evidence,
        ),
    ]
    if edge.protocol == "unknown":
        unknowns.append(
            Unknown(
                id=make_id("unknown", "mermaid", edge.id, "protocol"),
                category="protocol",
                description=(
                    f"Protocol for Mermaid flow {source.name} to {target.name} is unknown."
                ),
                related_element_id=edge.id,
                evidence=evidence,
            )
        )
    return unknowns
