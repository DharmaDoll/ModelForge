"""Deterministic risk scoring based on modeled topology and generated candidates."""

from __future__ import annotations

from collections import defaultdict

from threatmodel_ai.attack.models import AttackFinding
from threatmodel_ai.model.evidence import evidence_from_model
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel
from threatmodel_ai.risk.models import RiskFinding, RiskRating
from threatmodel_ai.stride.models import Threat


def score_risks(
    model: SystemModel,
    threats: list[Threat],
    attack_findings: list[AttackFinding],
) -> list[RiskFinding]:
    """Score review-priority risks from topology evidence and generated candidates."""

    node_by_id = {node.id: node for node in model.nodes}
    threats_by_edge = _candidate_ids_by_edge(threats)
    attacks_by_edge = _candidate_ids_by_edge(attack_findings)
    risks: list[RiskFinding] = []

    for edge in sorted(model.edges, key=lambda item: item.id):
        source = node_by_id.get(edge.source)
        target = node_by_id.get(edge.target)
        if not source or not target:
            continue

        if _is_external_entrypoint(edge, source, target):
            risk = _score_entrypoint(
                model,
                edge,
                source,
                target,
                node_by_id,
                threats_by_edge.get(edge.id, []),
                attacks_by_edge.get(edge.id, []),
            )
            risks.append(risk)
            continue

        if edge.type == EdgeType.STORES:
            risk = _score_storage_flow(
                model,
                edge,
                source,
                target,
                threats_by_edge.get(edge.id, []),
                attacks_by_edge.get(edge.id, []),
            )
            risks.append(risk)

    return sorted(risks, key=lambda item: (-item.score, item.id))


def _candidate_ids_by_edge(candidates: list[Threat] | list[AttackFinding]) -> dict[str, list[str]]:
    by_edge: dict[str, list[str]] = defaultdict(list)
    for candidate in candidates:
        for element_id in candidate.affected_elements:
            if element_id.startswith("edge:"):
                by_edge[element_id].append(candidate.id)
    return {edge_id: sorted(ids) for edge_id, ids in by_edge.items()}


def _is_external_entrypoint(edge: Edge, source: Node, target: Node) -> bool:
    return (
        edge.type == EdgeType.COMMUNICATES_WITH
        and source.type == NodeType.ACTOR
        and target.type in {NodeType.API, NodeType.COMPONENT, NodeType.EXTERNAL_SERVICE}
    )


def _score_entrypoint(
    model: SystemModel,
    edge: Edge,
    source: Node,
    target: Node,
    node_by_id: dict[str, Node],
    related_threats: list[str],
    related_attack_findings: list[str],
) -> RiskFinding:
    rationale: list[str] = []
    score = 0

    if _is_public(edge, source, target):
        score += 3
        rationale.append("Entry point is public or internet-exposed.")

    if edge.authentication in {"unknown", "none", ""}:
        score += 2
        rationale.append(f"Authentication is {edge.authentication or 'unknown'}.")

    if edge.authorization in {"unknown", ""}:
        score += 1
        rationale.append("Authorization requirements are unknown.")

    if edge.protocol in {"HTTP", "unknown", ""}:
        score += 1
        rationale.append(f"Transport protection is {edge.protocol or 'unknown'}.")

    data_nodes = _data_nodes(edge, node_by_id)
    if data_nodes:
        score += 2
        rationale.append(
            "Flow references sensitive model element types: "
            + ", ".join(sorted({node.type.value for node in data_nodes}))
            + "."
        )
        if any("classification" not in node.metadata for node in data_nodes):
            score += 1
            rationale.append("Data classification is unknown for referenced data assets.")

    if not model.metadata.get("mentions_rate_limiting"):
        score += 1
        rationale.append("Rate limiting or abuse controls are not proven.")

    affected_elements = [edge.id, source.id, target.id, *[node.id for node in data_nodes]]
    model_elements = _unique_sorted(affected_elements)
    return RiskFinding(
        id=make_id("risk", "entrypoint", edge.id),
        title=f"Review priority for {target.name} entry point",
        rating=_rating(score),
        score=score,
        rationale=rationale,
        related_threats=related_threats,
        related_attack_findings=related_attack_findings,
        affected_elements=model_elements,
        derived_from=_unique_sorted(
            [*model_elements, *related_threats, *related_attack_findings]
        ),
        evidence=evidence_from_model(model, model_elements),
    )


def _score_storage_flow(
    model: SystemModel,
    edge: Edge,
    source: Node,
    target: Node,
    related_threats: list[str],
    related_attack_findings: list[str],
) -> RiskFinding:
    rationale = ["Flow stores or modifies a modeled data asset."]
    score = 2

    if target.type in {NodeType.DATABASE, NodeType.DATA_ASSET, NodeType.SECRET}:
        score += 2
        rationale.append(f"Target is a {target.type.value}.")

    if "classification" not in target.metadata:
        score += 1
        rationale.append("Data classification is unknown for the storage target.")

    model_elements = _unique_sorted([edge.id, source.id, target.id])
    return RiskFinding(
        id=make_id("risk", "storage", edge.id),
        title=f"Review priority for storage path to {target.name}",
        rating=_rating(score),
        score=score,
        rationale=rationale,
        related_threats=related_threats,
        related_attack_findings=related_attack_findings,
        affected_elements=model_elements,
        derived_from=_unique_sorted(
            [*model_elements, *related_threats, *related_attack_findings]
        ),
        evidence=evidence_from_model(model, model_elements),
    )


def _is_public(edge: Edge, source: Node, target: Node) -> bool:
    return bool(
        source.name.lower() in {"internet", "api client", "external user", "customer"}
        or source.type == NodeType.ACTOR
        or target.metadata.get("internet_exposed")
        or edge.metadata.get("internet_exposed")
    )


def _data_nodes(edge: Edge, node_by_id: dict[str, Node]) -> list[Node]:
    nodes = [
        node_by_id[node_id]
        for node_id in edge.data_assets
        if node_id in node_by_id
        and node_by_id[node_id].type in {NodeType.DATABASE, NodeType.DATA_ASSET, NodeType.SECRET}
    ]
    return sorted(nodes, key=lambda node: node.id)


def _rating(score: int) -> RiskRating:
    if score >= 7:
        return RiskRating.HIGH
    if score >= 4:
        return RiskRating.MEDIUM
    return RiskRating.LOW


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))
