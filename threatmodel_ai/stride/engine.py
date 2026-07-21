"""Rule-based STRIDE engine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from threatmodel_ai.model.evidence import evidence_from_model
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel
from threatmodel_ai.stride.models import StrideCategory, Threat


@dataclass(frozen=True)
class _Rule:
    id: str
    category: StrideCategory
    applies: Callable[[SystemModel, Edge, Node, Node], bool]
    build: Callable[[SystemModel, Edge, Node, Node], Threat]


def generate_threats(model: SystemModel) -> list[Threat]:
    """Generate deterministic STRIDE threat candidates from the system model."""

    node_by_id = {node.id: node for node in model.nodes}
    threats: dict[str, Threat] = {}
    for edge in sorted(model.edges, key=lambda item: item.id):
        source = node_by_id.get(edge.source)
        target = node_by_id.get(edge.target)
        if not source or not target:
            continue
        for rule in _RULES:
            if rule.applies(model, edge, source, target):
                threat = rule.build(model, edge, source, target)
                threats.setdefault(threat.id, threat)
    return sorted(threats.values(), key=lambda threat: (threat.category.value, threat.id))


def _is_entrypoint(edge: Edge, source: Node, target: Node) -> bool:
    return (
        edge.type == EdgeType.COMMUNICATES_WITH
        and source.type == NodeType.ACTOR
        and target.type in {NodeType.API, NodeType.COMPONENT, NodeType.EXTERNAL_SERVICE}
    )


def _crosses_boundary(edge: Edge, source: Node, target: Node) -> bool:
    return bool(
        source.trust_boundary_id != target.trust_boundary_id
        or source.type == NodeType.ACTOR
        or target.metadata.get("internet_exposed")
        or edge.metadata.get("internet_exposed")
    )


def _known_none_or_unknown(value: str) -> bool:
    return value in {"unknown", "none", ""}


def _build_entrypoint_threat(
    model: SystemModel,
    rule_id: str,
    category: StrideCategory,
    edge: Edge,
    source: Node,
    target: Node,
    title: str,
    scenario: str,
    impact: str,
    mitigation: str,
    confidence: str = "medium",
) -> Threat:
    derived_from = [edge.id, source.id, target.id]
    return Threat(
        id=make_id("threat", rule_id, edge.id),
        rule_id=rule_id,
        category=category,
        title=title.format(source=source.name, target=target.name),
        scenario=scenario.format(source=source.name, target=target.name),
        impact=impact.format(source=source.name, target=target.name),
        mitigation=mitigation.format(source=source.name, target=target.name),
        affected_elements=derived_from,
        derived_from=derived_from,
        evidence=evidence_from_model(model, derived_from),
        confidence=confidence,
    )


def _spoofing(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    confidence = "high" if _known_none_or_unknown(edge.authentication) else "medium"
    auth_context = (
        "Authentication is not specified for this data flow."
        if edge.authentication == "unknown"
        else f"Authentication is documented as {edge.authentication}."
    )
    return _build_entrypoint_threat(
        model,
        "entrypoint-spoofing",
        StrideCategory.SPOOFING,
        edge,
        source,
        target,
        "Spoofing risk from {source} to {target}",
        f"{auth_context} A caller may impersonate another principal when reaching {{target}}.",
        "Unauthorized access to exposed API behavior may occur if caller identity is weak "
        "or absent.",
        "Require explicit authentication, validate credentials server-side, and document "
        "anonymous access if intentional.",
        confidence,
    )


def _tampering(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    crosses_boundary = _crosses_boundary(edge, source, target)
    confidence = "high" if crosses_boundary else "medium"
    boundary_context = (
        "This flow crosses a trust boundary or starts from an actor. "
        if crosses_boundary
        else ""
    )
    return _build_entrypoint_threat(
        model,
        "entrypoint-tampering",
        StrideCategory.TAMPERING,
        edge,
        source,
        target,
        "Request tampering risk on {target}",
        boundary_context
        + "{source} sends input to {target}. The model does not prove input integrity or "
        "validation.",
        "Malformed or modified requests may change server-side state or bypass business rules.",
        "Validate all inputs, enforce schema constraints, and use integrity protections "
        "where applicable.",
        confidence,
    )


def _repudiation(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    logging_known = bool(
        model.metadata.get("mentions_logging")
        or model.metadata.get("mentions_monitoring")
        or target.metadata.get("logging")
    )
    confidence = "medium" if logging_known else "high"
    return _build_entrypoint_threat(
        model,
        "entrypoint-repudiation",
        StrideCategory.REPUDIATION,
        edge,
        source,
        target,
        "Repudiation risk for {target}",
        "Audit logging for this externally reachable flow is not proven by the system model.",
        "Security-relevant actions may be difficult to investigate or attribute after an incident.",
        "Record authenticated principal, request metadata, decision outcomes, and "
        "tamper-resistant audit logs.",
        confidence,
    )


def _information_disclosure(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    confidence = "high" if edge.protocol in {"unknown", "HTTP"} or edge.data_assets else "medium"
    return _build_entrypoint_threat(
        model,
        "entrypoint-information-disclosure",
        StrideCategory.INFORMATION_DISCLOSURE,
        edge,
        source,
        target,
        "Information disclosure risk on {target}",
        "The flow may expose response data, and transport or data classification details "
        "are incomplete.",
        "Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.",
        "Use TLS, minimize responses, classify referenced data assets, and enforce "
        "authorization before disclosure.",
        confidence,
    )


def _denial_of_service(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    confidence = "high" if not model.metadata.get("mentions_rate_limiting") else "medium"
    return _build_entrypoint_threat(
        model,
        "entrypoint-denial-of-service",
        StrideCategory.DENIAL_OF_SERVICE,
        edge,
        source,
        target,
        "Denial of service risk on {target}",
        "{target} receives requests from {source}, and rate limiting or capacity controls "
        "are not proven.",
        "High request volume or expensive inputs may degrade availability.",
        "Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.",
        confidence,
    )


def _elevation_of_privilege(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    confidence = "high" if edge.authorization == "unknown" else "medium"
    return _build_entrypoint_threat(
        model,
        "entrypoint-elevation-of-privilege",
        StrideCategory.ELEVATION_OF_PRIVILEGE,
        edge,
        source,
        target,
        "Authorization bypass risk on {target}",
        "Authorization requirements for this flow are not fully proven by the system model.",
        "A caller may perform actions outside their intended privilege level.",
        "Define authorization rules per operation and enforce them server-side with "
        "deny-by-default behavior.",
        confidence,
    )


def _store_information_disclosure(
    model: SystemModel,
    edge: Edge,
    source: Node,
    target: Node,
) -> Threat:
    derived_from = [edge.id, source.id, target.id]
    return Threat(
        id=make_id("threat", "store-information-disclosure", edge.id),
        rule_id="store-information-disclosure",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        title=f"Stored data disclosure risk in {target.name}",
        scenario=(
            "Encryption, access control, or data classification for this stored asset "
            "is not proven."
        ),
        impact=(
            "Stored sensitive data may be exposed if the backing service or credentials "
            "are compromised."
        ),
        mitigation=(
            "Classify the data, enforce least-privilege access, and enable encryption at rest."
        ),
        affected_elements=derived_from,
        derived_from=derived_from,
        evidence=evidence_from_model(model, derived_from),
        confidence="medium",
    )


def _store_tampering(model: SystemModel, edge: Edge, source: Node, target: Node) -> Threat:
    derived_from = [edge.id, source.id, target.id]
    return Threat(
        id=make_id("threat", "store-tampering", edge.id),
        rule_id="store-tampering",
        category=StrideCategory.TAMPERING,
        title=f"Stored data tampering risk in {target.name}",
        scenario=f"{source.name} has a modelled storage relationship with {target.name}.",
        impact="Unauthorized writes or weak integrity controls may corrupt stored data.",
        mitigation=(
            "Apply least-privilege write permissions, validation, integrity checks, and backups."
        ),
        affected_elements=derived_from,
        derived_from=derived_from,
        evidence=evidence_from_model(model, derived_from),
        confidence="medium",
    )


_RULES = (
    _Rule(
        id="entrypoint-spoofing",
        category=StrideCategory.SPOOFING,
        applies=lambda _model, edge, source, target: _is_entrypoint(edge, source, target),
        build=_spoofing,
    ),
    _Rule(
        id="entrypoint-tampering",
        category=StrideCategory.TAMPERING,
        applies=lambda _model, edge, source, target: _is_entrypoint(edge, source, target),
        build=_tampering,
    ),
    _Rule(
        id="entrypoint-repudiation",
        category=StrideCategory.REPUDIATION,
        applies=lambda _model, edge, source, target: _is_entrypoint(edge, source, target),
        build=_repudiation,
    ),
    _Rule(
        id="entrypoint-information-disclosure",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        applies=lambda _model, edge, source, target: _is_entrypoint(edge, source, target),
        build=_information_disclosure,
    ),
    _Rule(
        id="entrypoint-denial-of-service",
        category=StrideCategory.DENIAL_OF_SERVICE,
        applies=lambda _model, edge, source, target: _is_entrypoint(edge, source, target),
        build=_denial_of_service,
    ),
    _Rule(
        id="entrypoint-elevation-of-privilege",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        applies=lambda _model, edge, source, target: _is_entrypoint(edge, source, target),
        build=_elevation_of_privilege,
    ),
    _Rule(
        id="store-information-disclosure",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        applies=lambda _model, edge, _source, target: edge.type == EdgeType.STORES
        and target.type in {NodeType.DATABASE, NodeType.DATA_ASSET},
        build=_store_information_disclosure,
    ),
    _Rule(
        id="store-tampering",
        category=StrideCategory.TAMPERING,
        applies=lambda _model, edge, _source, target: edge.type == EdgeType.STORES
        and target.type in {NodeType.DATABASE, NodeType.DATA_ASSET},
        build=_store_tampering,
    ),
)
