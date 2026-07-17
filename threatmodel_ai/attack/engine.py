"""Deterministic MITRE ATT&CK technique candidate engine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from threatmodel_ai.attack.catalog import TECHNIQUES
from threatmodel_ai.attack.models import AttackFinding
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel


@dataclass(frozen=True)
class _EdgeRule:
    id: str
    technique_id: str
    applies: Callable[[SystemModel, Edge, Node, Node], bool]
    build: Callable[[SystemModel, Edge, Node, Node], AttackFinding]


@dataclass(frozen=True)
class _NodeRule:
    id: str
    technique_id: str
    applies: Callable[[SystemModel, Node], bool]
    build: Callable[[SystemModel, Node], AttackFinding]


def generate_attack_findings(model: SystemModel) -> list[AttackFinding]:
    """Generate deterministic ATT&CK technique candidates from the system model."""

    node_by_id = {node.id: node for node in model.nodes}
    findings: dict[str, AttackFinding] = {}

    for edge in sorted(model.edges, key=lambda item: item.id):
        source = node_by_id.get(edge.source)
        target = node_by_id.get(edge.target)
        if not source or not target:
            continue
        for rule in _EDGE_RULES:
            if rule.applies(model, edge, source, target):
                finding = rule.build(model, edge, source, target)
                findings.setdefault(finding.id, finding)

    for node in sorted(model.nodes, key=lambda item: item.id):
        for rule in _NODE_RULES:
            if rule.applies(model, node):
                finding = rule.build(model, node)
                findings.setdefault(finding.id, finding)

    return sorted(
        findings.values(),
        key=lambda finding: (finding.technique.id, finding.rule_id, finding.id),
    )


def _is_entrypoint(edge: Edge, source: Node, target: Node) -> bool:
    return (
        edge.type == EdgeType.COMMUNICATES_WITH
        and source.type == NodeType.ACTOR
        and target.type in {NodeType.API, NodeType.COMPONENT, NodeType.EXTERNAL_SERVICE}
    )


def _is_public_entrypoint(edge: Edge, source: Node, target: Node) -> bool:
    return _is_entrypoint(edge, source, target) and (
        source.name.lower() in {"internet", "api client", "external user", "customer"}
        or target.metadata.get("internet_exposed")
        or edge.metadata.get("internet_exposed")
    )


def _has_auth_surface(edge: Edge) -> bool:
    return edge.authentication not in {"unknown", "none", ""}


def _rate_limit_unknown(model: SystemModel) -> bool:
    return not bool(model.metadata.get("mentions_rate_limiting"))


def _attack_finding(
    rule_id: str,
    technique_id: str,
    title: str,
    scenario: str,
    detection: str,
    mitigation: str,
    affected_elements: list[str],
    confidence: str,
) -> AttackFinding:
    technique = TECHNIQUES[technique_id]
    return AttackFinding(
        id=make_id("attack", technique_id, rule_id, *affected_elements),
        rule_id=rule_id,
        technique=technique,
        title=title,
        scenario=scenario,
        detection=detection,
        mitigation=mitigation,
        affected_elements=affected_elements,
        confidence=confidence,
    )


def _public_facing_application(
    model: SystemModel,
    edge: Edge,
    source: Node,
    target: Node,
) -> AttackFinding:
    confidence = "high" if target.metadata.get("internet_exposed") else "medium"
    return _attack_finding(
        "attack-public-entrypoint",
        "T1190",
        f"Public-facing application technique candidate for {target.name}",
        (
            f"{target.name} is reachable from {source.name}. The model does not prove "
            "patching, WAF coverage, or exploit prevention controls."
        ),
        "Review web/API exploitation telemetry, WAF events, application errors, and ingress logs.",
        "Patch exposed software, minimize exposed endpoints, validate inputs, and deploy "
        "WAF controls.",
        [edge.id, source.id, target.id],
        confidence,
    )


def _endpoint_denial_of_service(
    model: SystemModel,
    edge: Edge,
    source: Node,
    target: Node,
) -> AttackFinding:
    return _attack_finding(
        "attack-entrypoint-dos",
        "T1499",
        f"Endpoint denial-of-service technique candidate for {target.name}",
        (
            f"{target.name} receives traffic from {source.name}, and rate limiting or "
            "capacity controls are not proven in the model."
        ),
        "Monitor request rate, latency, error-rate spikes, queue depth, and saturation metrics.",
        "Apply rate limits, request budgets, autoscaling, backpressure, and upstream filtering.",
        [edge.id, source.id, target.id],
        "high",
    )


def _brute_force(model: SystemModel, edge: Edge, source: Node, target: Node) -> AttackFinding:
    return _attack_finding(
        "attack-authenticated-entrypoint-bruteforce",
        "T1110",
        f"Brute-force technique candidate for {target.name}",
        (
            f"{target.name} has an authentication surface documented as "
            f"{edge.authentication}, but abuse controls are not proven."
        ),
        "Monitor failed authentication bursts, source diversity, credential stuffing "
        "patterns, and lockouts.",
        "Use MFA, throttling, lockouts, credential stuffing detection, and "
        "breached-password checks.",
        [edge.id, source.id, target.id],
        "medium",
    )


def _valid_accounts(model: SystemModel, edge: Edge, source: Node, target: Node) -> AttackFinding:
    return _attack_finding(
        "attack-authenticated-entrypoint-valid-accounts",
        "T1078",
        f"Valid-accounts abuse candidate for {target.name}",
        (
            f"{target.name} requires {edge.authentication}, but authorization requirements "
            "are not proven by the system model."
        ),
        "Monitor anomalous successful logins, privilege changes, impossible travel, and "
        "unusual API usage.",
        "Enforce least privilege, MFA, session controls, and explicit per-operation authorization.",
        [edge.id, source.id, target.id],
        "medium",
    )


def _adversary_in_the_middle(
    model: SystemModel,
    edge: Edge,
    source: Node,
    target: Node,
) -> AttackFinding:
    confidence = "medium" if edge.protocol == "HTTP" else "low"
    return _attack_finding(
        "attack-entrypoint-aitm",
        "T1557",
        f"Adversary-in-the-middle candidate for {target.name}",
        (
            f"Transport protection for traffic from {source.name} to {target.name} "
            f"is {edge.protocol} in the system model."
        ),
        "Monitor TLS downgrade, certificate failures, unexpected proxies, and network "
        "path changes.",
        "Require TLS, certificate validation, HSTS where applicable, and secure "
        "service-to-service channels.",
        [edge.id, source.id, target.id],
        confidence,
    )


def _data_manipulation(model: SystemModel, edge: Edge, source: Node, target: Node) -> AttackFinding:
    return _attack_finding(
        "attack-stored-data-manipulation",
        "T1565",
        f"Data manipulation technique candidate for {target.name}",
        (
            f"{source.name} stores or modifies data in {target.name}. Integrity controls "
            "and recovery behavior are not proven."
        ),
        "Monitor unauthorized writes, abnormal update volume, integrity-check failures, "
        "and restore events.",
        "Use least-privilege writes, validation, immutable audit logs, integrity checks, "
        "and backups.",
        [edge.id, source.id, target.id],
        "medium",
    )


def _unsecured_credentials(model: SystemModel, node: Node) -> AttackFinding:
    return _attack_finding(
        "attack-secret-unsecured-credentials",
        "T1552",
        f"Unsecured credentials technique candidate for {node.name}",
        (
            f"{node.name} is modeled as a secret. Storage location, access path, and "
            "rotation behavior are not proven."
        ),
        "Monitor secret reads, policy changes, unusual callers, and source-code or IaC "
        "secret exposure.",
        "Use a managed secret store, least-privilege access, encryption, rotation, and "
        "secret scanning.",
        [node.id],
        "medium",
    )


_EDGE_RULES = (
    _EdgeRule(
        id="attack-public-entrypoint",
        technique_id="T1190",
        applies=lambda _model, edge, source, target: _is_public_entrypoint(edge, source, target),
        build=_public_facing_application,
    ),
    _EdgeRule(
        id="attack-entrypoint-dos",
        technique_id="T1499",
        applies=lambda model, edge, source, target: _is_public_entrypoint(edge, source, target)
        and _rate_limit_unknown(model),
        build=_endpoint_denial_of_service,
    ),
    _EdgeRule(
        id="attack-authenticated-entrypoint-bruteforce",
        technique_id="T1110",
        applies=lambda model, edge, source, target: _is_public_entrypoint(edge, source, target)
        and _has_auth_surface(edge)
        and _rate_limit_unknown(model),
        build=_brute_force,
    ),
    _EdgeRule(
        id="attack-authenticated-entrypoint-valid-accounts",
        technique_id="T1078",
        applies=lambda _model, edge, source, target: _is_public_entrypoint(edge, source, target)
        and _has_auth_surface(edge)
        and edge.authorization == "unknown",
        build=_valid_accounts,
    ),
    _EdgeRule(
        id="attack-entrypoint-aitm",
        technique_id="T1557",
        applies=lambda _model, edge, source, target: _is_public_entrypoint(edge, source, target)
        and edge.protocol in {"unknown", "HTTP"},
        build=_adversary_in_the_middle,
    ),
    _EdgeRule(
        id="attack-stored-data-manipulation",
        technique_id="T1565",
        applies=lambda _model, edge, _source, target: edge.type == EdgeType.STORES
        and target.type in {NodeType.DATABASE, NodeType.DATA_ASSET},
        build=_data_manipulation,
    ),
)

_NODE_RULES = (
    _NodeRule(
        id="attack-secret-unsecured-credentials",
        technique_id="T1552",
        applies=lambda _model, node: node.type == NodeType.SECRET,
        build=_unsecured_credentials,
    ),
)
