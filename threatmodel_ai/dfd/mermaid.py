"""Mermaid DFD renderer."""

from __future__ import annotations

from threatmodel_ai.model.ids import short_hash
from threatmodel_ai.model.schema import Edge, Node, NodeType, SystemModel


def render_mermaid(model: SystemModel) -> str:
    """Render a deterministic Mermaid flowchart from the system model graph."""

    mermaid_ids = {node.id: _mermaid_id(node.id) for node in model.nodes}
    node_by_id = {node.id: node for node in model.nodes}
    lines = [
        "flowchart LR",
        "  %% Generated from system_model.json. Do not edit manually.",
    ]

    rendered_nodes: set[str] = set()
    trust_boundaries = [node for node in model.nodes if node.type == NodeType.TRUST_BOUNDARY]
    for boundary in sorted(trust_boundaries, key=lambda node: (node.name, node.id)):
        contained = [
            node
            for node in model.nodes
            if node.trust_boundary_id == boundary.id and node.type != NodeType.TRUST_BOUNDARY
        ]
        if not contained:
            continue
        lines.append(f'  subgraph {mermaid_ids[boundary.id]}["{_label(boundary)}"]')
        for node in sorted(contained, key=lambda item: (item.type.value, item.name, item.id)):
            lines.append("    " + _node_statement(node, mermaid_ids[node.id]))
            rendered_nodes.add(node.id)
        lines.append("  end")

    for node in sorted(model.nodes, key=lambda item: (item.type.value, item.name, item.id)):
        if node.type == NodeType.TRUST_BOUNDARY or node.id in rendered_nodes:
            continue
        lines.append("  " + _node_statement(node, mermaid_ids[node.id]))

    for edge in sorted(model.edges, key=lambda item: (item.type.value, item.id)):
        source = node_by_id.get(edge.source)
        target = node_by_id.get(edge.target)
        if not source or not target:
            continue
        if source.type == NodeType.TRUST_BOUNDARY or target.type == NodeType.TRUST_BOUNDARY:
            continue
        lines.append(
            "  " + _edge_statement(edge, mermaid_ids[edge.source], mermaid_ids[edge.target])
        )

    return "\n".join(lines) + "\n"


def _mermaid_id(model_id: str) -> str:
    return f"n_{short_hash(model_id)}"


def _node_statement(node: Node, mermaid_id: str) -> str:
    label = _label(node)
    if node.type == NodeType.ACTOR:
        return f'{mermaid_id}(["{label}"])'
    if node.type in {NodeType.DATABASE, NodeType.DATA_ASSET}:
        return f'{mermaid_id}[("{label}")]'
    if node.type == NodeType.EXTERNAL_SERVICE:
        return f'{mermaid_id}{{"{label}"}}'
    if node.type == NodeType.SECRET:
        return f'{mermaid_id}[/"{label}"/]'
    return f'{mermaid_id}["{label}"]'


def _edge_statement(edge: Edge, source_id: str, target_id: str) -> str:
    label_parts = [edge.type.value]
    if edge.protocol and edge.protocol != "unknown":
        label_parts.append(edge.protocol)
    return f'{source_id} -->|"{_escape(" / ".join(label_parts))}"| {target_id}'


def _label(node: Node) -> str:
    return _escape(f"{node.name}\\n({node.type.value})")


def _escape(value: str) -> str:
    return value.replace('"', "'").replace("|", "/").replace("\n", " ")
