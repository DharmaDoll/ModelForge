"""Evidence-based entry point predicates shared by analysis lenses."""

from __future__ import annotations

from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType


def is_actor_entrypoint(edge: Edge, source: Node, target: Node) -> bool:
    """Return whether a modeled actor invokes a component through a data flow."""

    return (
        edge.type == EdgeType.COMMUNICATES_WITH
        and source.type == NodeType.ACTOR
        and target.type in {NodeType.API, NodeType.COMPONENT, NodeType.EXTERNAL_SERVICE}
    )


def is_explicit_public_entrypoint(edge: Edge, source: Node, target: Node) -> bool:
    """Require an explicit public-network fact for Internet exposure."""

    return is_actor_entrypoint(edge, source, target) and bool(
        source.name.strip().lower() == "internet"
        or source.metadata.get("internet_exposed") is True
        or target.metadata.get("internet_exposed") is True
        or edge.metadata.get("internet_exposed") is True
    )
