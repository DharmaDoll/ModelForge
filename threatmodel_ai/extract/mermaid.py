"""Mermaid DFD extractor for Markdown fenced blocks."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from threatmodel_ai.errors import InputFormatError
from threatmodel_ai.ingest.diagnostics import MermaidParseMetrics
from threatmodel_ai.model.evidence import merge_evidence
from threatmodel_ai.model.ids import make_id, short_hash, slugify
from threatmodel_ai.model.observations import (
    ObservationBatch,
    model_to_observation_batch,
    normalize_observation_batch,
)
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
_SUBGRAPH_RE = re.compile(r"^\s*subgraph\s+(?P<body>.+?)\s*$", re.IGNORECASE)
_END_RE = re.compile(r"^\s*end\s*$", re.IGNORECASE)
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
_TYPE_KEYWORDS: tuple[tuple[NodeType, tuple[str, ...]], ...] = (
    (NodeType.ACTOR, ("user", "client", "customer")),
    (NodeType.DATABASE, ("db", "database", "postgres", "mysql", "rds")),
    (NodeType.DATA_ASSET, ("bucket", "storage", "object store", "s3")),
    (NodeType.EXTERNAL_SERVICE, ("external", "third party", "partner")),
    (NodeType.SECRET, ("secret", "token", "api key", "credential")),
)


def extract_mermaid_markdown(path: Path, *, identity_root: Path | None = None) -> SystemModel:
    """Extract conservative graph facts from Mermaid flowchart blocks in Markdown."""

    return normalize_observation_batch(observe_mermaid_markdown(path, identity_root=identity_root))


def observe_mermaid_markdown(path: Path, *, identity_root: Path | None = None) -> ObservationBatch:
    """Extract evidence-bearing candidate observations from Mermaid Markdown."""

    batch, _ = observe_mermaid_markdown_with_diagnostics(path, identity_root=identity_root)
    return batch


def observe_mermaid_markdown_with_diagnostics(
    path: Path, *, identity_root: Path | None = None
) -> tuple[ObservationBatch, MermaidParseMetrics]:
    """Extract observations and count recognized or skipped Mermaid syntax."""

    evidence = Evidence(
        source_type=SourceType.MARKDOWN,
        source_path=str(path),
        extractor="mermaid",
        detail="Markdown document",
    )
    metrics = MermaidParseMetrics()
    batch = model_to_observation_batch(
        _extract_mermaid_model(path, identity_root=identity_root, metrics=metrics),
        fallback_evidence=[evidence],
    )
    return batch, metrics


def _extract_mermaid_model(
    path: Path, *, identity_root: Path | None, metrics: MermaidParseMetrics
) -> SystemModel:
    """Build the Mermaid adapter's proposed model before normalization."""

    text = path.read_text(encoding="utf-8")
    nodes: dict[str, Node] = {}
    edges: dict[str, Edge] = {}
    unknowns: dict[str, Unknown] = {}
    document_scope = _document_scope(path, identity_root or path.parent)

    block_index = 0
    for block_start_line, block, closed in _mermaid_blocks(text):
        if not closed:
            metrics.unclosed_fences += 1
            continue
        metrics.closed_fences += 1
        if not any(_DIAGRAM_HEADER_RE.match(line) for line in block):
            metrics.unsupported_diagram_blocks += 1
            continue
        metrics.flowchart_blocks += 1
        block_index += 1
        _extract_block(
            path,
            document_scope,
            block_index,
            block_start_line,
            block,
            nodes,
            edges,
            unknowns,
            metrics,
        )

    return SystemModel(
        name="unknown",
        description="unknown",
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges.values(), key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns.values(), key=lambda unknown: unknown.id),
        metadata={
            "mermaid_files": [str(path)] if nodes or edges else [],
            "mermaid_identity_version": 2,
        },
    )


def _document_scope(path: Path, identity_root: Path) -> str:
    """Build a portable scope for project files and a location-bound external fallback."""

    resolved = path.resolve()
    try:
        relative = resolved.relative_to(identity_root.resolve()).as_posix()
    except ValueError:
        return f"external-{slugify(path.name)}-{short_hash(resolved, length=12)}"
    return f"{slugify(relative)}-{short_hash(relative, length=12)}"


def _scoped_id(kind: str, document_scope: str, block_index: int, alias: str) -> str:
    """Keep Mermaid identities independent of inferred node type and display label."""

    return make_id(
        "mermaid",
        kind,
        document_scope,
        f"diagram-{block_index}",
        alias,
        short_hash(alias, length=8),
    )


def _mermaid_blocks(text: str) -> Iterator[tuple[int, list[str], bool]]:
    in_block = False
    block: list[str] = []
    block_start_line = 1
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not in_block and _FENCE_START_RE.match(line):
            in_block = True
            block = []
            block_start_line = line_number + 1
            continue
        if in_block and _FENCE_END_RE.match(line):
            in_block = False
            yield block_start_line, block, True
            block = []
            continue
        if in_block:
            block.append(line)
    if in_block:
        yield block_start_line, block, False


def _extract_block(
    path: Path,
    document_scope: str,
    block_index: int,
    block_start_line: int,
    block: list[str],
    nodes: dict[str, Node],
    edges: dict[str, Edge],
    unknowns: dict[str, Unknown],
    metrics: MermaidParseMetrics,
) -> None:
    boundary_stack: list[str] = []
    for block_line_number, raw_line in enumerate(block, start=1):
        line = _strip_comment(raw_line).strip().rstrip(";")
        if not line or _DIAGRAM_HEADER_RE.match(line):
            continue
        evidence = Evidence(
            source_type=SourceType.MARKDOWN,
            source_path=str(path),
            extractor="mermaid",
            detail=f"mermaid block {block_index}, line {block_line_number}",
            line=block_start_line + block_line_number - 1,
        )
        subgraph_match = _SUBGRAPH_RE.match(line)
        if subgraph_match:
            boundary = _trust_boundary(
                subgraph_match.group("body"), evidence, document_scope, block_index
            )
            nodes[boundary.id] = _merge_node(nodes.get(boundary.id), boundary, path)
            boundary_stack.append(boundary.id)
            metrics.parsed_statements += 1
            continue
        if _END_RE.match(line):
            if boundary_stack:
                boundary_stack.pop()
                metrics.parsed_statements += 1
            else:
                metrics.skipped_statements += 1
            continue

        match = _EDGE_RE.match(line)
        if not match:
            metrics.skipped_statements += 1
            continue

        left = _parse_node(match.group("left"))
        right = _parse_node(match.group("right"))
        if not left or not right:
            metrics.skipped_statements += 1
            continue

        metrics.parsed_statements += 1

        label = (match.group("label") or "").strip()
        trust_boundary_id = boundary_stack[-1] if boundary_stack else None
        source = _node(left, evidence, trust_boundary_id, document_scope, block_index)
        target = _node(right, evidence, trust_boundary_id, document_scope, block_index)
        nodes[source.id] = _merge_node(nodes.get(source.id), source, path)
        nodes[target.id] = _merge_node(nodes.get(target.id), target, path)

        protocol = _protocol_from_label(label)
        edge_id = make_id(
            "edge", source.id, target.id, "mermaid", short_hash(label, match.group("arrow"))
        )
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
                "legacy_mermaid_id_suggestion": make_id(
                    "edge",
                    str(source.metadata["legacy_mermaid_id_suggestion"]),
                    str(target.metadata["legacy_mermaid_id_suggestion"]),
                    "mermaid",
                ),
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


def _trust_boundary(raw: str, evidence: Evidence, document_scope: str, block_index: int) -> Node:
    parsed = _parse_boundary(raw)
    return Node(
        id=_scoped_id("boundary", document_scope, block_index, parsed.alias),
        name=parsed.label,
        type=NodeType.TRUST_BOUNDARY,
        description=f"Mermaid subgraph {parsed.alias}.",
        metadata={
            "source_format": "mermaid",
            "mermaid_alias": parsed.alias,
            "legacy_mermaid_id_suggestion": make_id("trust_boundary", "mermaid", parsed.alias),
        },
        evidence=[evidence],
    )


def _parse_boundary(raw: str) -> _ParsedNode:
    parsed = _parse_node(raw)
    if parsed:
        return parsed

    label = raw.strip().strip("\"'")
    return _ParsedNode(alias=label, label=label or "unknown")


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


def _node(
    parsed: _ParsedNode,
    evidence: Evidence,
    trust_boundary_id: str | None,
    document_scope: str,
    block_index: int,
) -> Node:
    node_type, inference_metadata = _infer_node_type(parsed)
    node_id = _scoped_id("node", document_scope, block_index, parsed.alias)
    return Node(
        id=node_id,
        name=parsed.label,
        type=node_type,
        description=f"Mermaid node {parsed.alias}.",
        metadata={
            "source_format": "mermaid",
            "mermaid_alias": parsed.alias,
            "legacy_mermaid_id_suggestion": make_id(node_type.value, "mermaid", parsed.alias),
            **inference_metadata,
        },
        trust_boundary_id=trust_boundary_id,
        evidence=[evidence],
    )


def _infer_node_type(parsed: _ParsedNode) -> tuple[NodeType, dict[str, str]]:
    matches: list[tuple[NodeType, str, str]] = []
    for source, source_name in ((parsed.label, "mermaid_label"), (parsed.alias, "mermaid_alias")):
        tokens = _tokens(source)
        for node_type, keywords in _TYPE_KEYWORDS:
            for keyword in keywords:
                if _keyword_matches(keyword, tokens):
                    matches.append((node_type, keyword, source_name))

    unique_types = {node_type for node_type, _keyword, _source_name in matches}
    if len(unique_types) != 1:
        return NodeType.COMPONENT, {}

    node_type, keyword, source_name = matches[0]
    return node_type, {
        "type_inferred_from": source_name,
        "type_inference_keyword": keyword,
    }


def _merge_node(existing: Node | None, incoming: Node, path: Path) -> Node:
    if not existing:
        return incoming
    existing_alias = str(existing.metadata.get("mermaid_alias") or "")
    incoming_alias = str(incoming.metadata.get("mermaid_alias") or "")
    alias = existing_alias or incoming_alias
    if existing.name != incoming.name and existing.name != alias and incoming.name != alias:
        raise InputFormatError(
            f"Conflicting Mermaid labels for alias {alias!r} in {path}.",
            hint="Use a distinct alias for each node or boundary in a diagram.",
        )
    existing_inferred = "type_inferred_from" in existing.metadata
    incoming_inferred = "type_inferred_from" in incoming.metadata
    if existing_inferred and incoming_inferred and existing.type != incoming.type:
        raise InputFormatError(
            f"Conflicting Mermaid node types for alias {alias!r} in {path}.",
            hint="Give the alias one unambiguous type in the diagram.",
        )
    if (
        existing.trust_boundary_id
        and incoming.trust_boundary_id
        and existing.trust_boundary_id != incoming.trust_boundary_id
    ):
        raise InputFormatError(
            f"Conflicting Mermaid trust boundaries for alias {alias!r} in {path}.",
            hint="Use a distinct alias or place the node in one boundary.",
        )
    selected_type = incoming.type if incoming_inferred and not existing_inferred else existing.type
    return existing.model_copy(
        update={
            "name": _prefer_labeled_name(
                existing.name,
                incoming.name,
                alias,
            ),
            "type": selected_type,
            "trust_boundary_id": _merge_trust_boundary_id(existing, incoming),
            "metadata": {
                **existing.metadata,
                **incoming.metadata,
                "legacy_mermaid_id_suggestion": make_id(selected_type.value, "mermaid", alias),
            },
            "evidence": merge_evidence([*existing.evidence, *incoming.evidence]),
        }
    )


def _merge_trust_boundary_id(existing: Node, incoming: Node) -> str | None:
    if existing.trust_boundary_id == incoming.trust_boundary_id:
        return existing.trust_boundary_id
    if not existing.trust_boundary_id:
        return incoming.trust_boundary_id
    if not incoming.trust_boundary_id:
        return existing.trust_boundary_id
    return None


def _merge_edge(existing: Edge | None, incoming: Edge) -> Edge:
    if not existing:
        return incoming
    return existing.model_copy(
        update={
            "description": existing.description,
            "protocol": existing.protocol if existing.protocol != "unknown" else incoming.protocol,
            "metadata": {**existing.metadata, **incoming.metadata},
            "evidence": merge_evidence([*existing.evidence, *incoming.evidence]),
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


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[a-z0-9]+", value.lower()))


def _keyword_matches(keyword: str, tokens: tuple[str, ...]) -> bool:
    keyword_tokens = tuple(re.findall(r"[a-z0-9]+", keyword.lower()))
    if not keyword_tokens:
        return False
    if len(keyword_tokens) == 1:
        return keyword_tokens[0] in tokens
    return any(
        tokens[index : index + len(keyword_tokens)] == keyword_tokens
        for index in range(0, len(tokens) - len(keyword_tokens) + 1)
    )


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
