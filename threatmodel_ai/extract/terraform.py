"""Terraform extractor using deterministic HCL block heuristics."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
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

_RESOURCE_START_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
_ATTRIBUTE_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$", re.MULTILINE)
_REFERENCE_RE = re.compile(r"\b([a-z][a-z0-9_]+)\.([A-Za-z0-9_-]+)\b")

_EXACT_NODE_TYPES: dict[str, NodeType] = {
    "aws_api_gateway_rest_api": NodeType.API,
    "aws_apigatewayv2_api": NodeType.API,
    "azurerm_api_management": NodeType.API,
    "google_api_gateway_api": NodeType.API,
    "aws_db_instance": NodeType.DATABASE,
    "aws_rds_cluster": NodeType.DATABASE,
    "aws_dynamodb_table": NodeType.DATABASE,
    "azurerm_postgresql_server": NodeType.DATABASE,
    "azurerm_mssql_server": NodeType.DATABASE,
    "google_sql_database_instance": NodeType.DATABASE,
    "aws_s3_bucket": NodeType.DATA_ASSET,
    "azurerm_storage_account": NodeType.DATA_ASSET,
    "google_storage_bucket": NodeType.DATA_ASSET,
    "aws_secretsmanager_secret": NodeType.SECRET,
    "azurerm_key_vault_secret": NodeType.SECRET,
    "google_secret_manager_secret": NodeType.SECRET,
    "aws_vpc": NodeType.TRUST_BOUNDARY,
    "aws_subnet": NodeType.TRUST_BOUNDARY,
    "azurerm_virtual_network": NodeType.TRUST_BOUNDARY,
    "azurerm_subnet": NodeType.TRUST_BOUNDARY,
    "google_compute_network": NodeType.TRUST_BOUNDARY,
    "google_compute_subnetwork": NodeType.TRUST_BOUNDARY,
    "aws_security_group": NodeType.TRUST_BOUNDARY,
    "azurerm_network_security_group": NodeType.TRUST_BOUNDARY,
    "aws_lambda_function": NodeType.COMPONENT,
    "aws_ecs_service": NodeType.COMPONENT,
    "aws_instance": NodeType.COMPONENT,
    "aws_lb": NodeType.COMPONENT,
    "aws_sqs_queue": NodeType.COMPONENT,
    "aws_sns_topic": NodeType.COMPONENT,
}

_DISPLAY_NAME_KEYS = (
    "name",
    "bucket",
    "identifier",
    "function_name",
    "queue_name",
    "topic_name",
)


def extract_terraform(paths: Iterable[Path]) -> SystemModel:
    """Extract cloud resources and Terraform dependency edges from .tf files."""

    resources = list(_collect_resources(paths))
    nodes: dict[str, Node] = {}
    resource_blocks: dict[str, str] = {}
    unknowns: list[Unknown] = []

    for resource in resources:
        node_type = _node_type_for(resource.resource_type)
        node_id = _resource_id(resource.resource_type, resource.name)
        attributes = _extract_attributes(resource.body)
        display_name = _display_name(resource.resource_type, resource.name, attributes)
        metadata = {
            "terraform_type": resource.resource_type,
            "terraform_name": resource.name,
        }
        if _is_internet_exposed(resource.body):
            metadata["internet_exposed"] = True

        nodes[node_id] = Node(
            id=node_id,
            name=display_name,
            type=node_type,
            description=f"Terraform resource {resource.resource_type}.{resource.name}",
            metadata=metadata,
            evidence=[
                Evidence(
                    source_type=SourceType.TERRAFORM,
                    source_path=str(resource.path),
                    detail=f'resource "{resource.resource_type}" "{resource.name}"',
                )
            ],
        )
        resource_blocks[node_id] = resource.body

    nodes = _assign_trust_boundaries(nodes, resource_blocks)
    edges = _extract_edges(nodes, resource_blocks)
    _add_internet_entrypoints(nodes, edges)

    for node in nodes.values():
        if node.metadata.get("internet_exposed") and node.type in {
            NodeType.API,
            NodeType.COMPONENT,
        }:
            unknowns.append(
                Unknown(
                    id=make_id("unknown", "terraform", node.id, "authentication"),
                    category="authentication",
                    description=(
                        f"Authentication for internet-exposed resource {node.name} is unknown."
                    ),
                    related_element_id=node.id,
                    evidence=node.evidence[0] if node.evidence else None,
                )
            )
            unknowns.append(
                Unknown(
                    id=make_id("unknown", "terraform", node.id, "rate-limiting"),
                    category="rate_limiting",
                    description=(
                        f"Rate limiting for internet-exposed resource {node.name} is unknown."
                    ),
                    related_element_id=node.id,
                    evidence=node.evidence[0] if node.evidence else None,
                )
            )
        if node.type in {NodeType.DATABASE, NodeType.DATA_ASSET, NodeType.SECRET}:
            unknowns.append(
                Unknown(
                    id=make_id("unknown", "terraform", node.id, "encryption"),
                    category="encryption",
                    description=f"Encryption configuration for {node.name} is unknown.",
                    related_element_id=node.id,
                    evidence=node.evidence[0] if node.evidence else None,
                )
            )

    return SystemModel(
        name="unknown",
        description="unknown",
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges.values(), key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns, key=lambda unknown: unknown.id),
        metadata={"terraform_files": sorted(str(path) for path in paths)},
    )


class _TerraformResource:
    def __init__(self, path: Path, resource_type: str, name: str, body: str) -> None:
        self.path = path
        self.resource_type = resource_type
        self.name = name
        self.body = body


def _collect_resources(paths: Iterable[Path]) -> Iterator[_TerraformResource]:
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8")
        for resource_type, name, body in _iter_resource_blocks(text):
            yield _TerraformResource(path=path, resource_type=resource_type, name=name, body=body)


def _iter_resource_blocks(text: str) -> Iterator[tuple[str, str, str]]:
    position = 0
    while match := _RESOURCE_START_RE.search(text, position):
        open_brace_index = match.end() - 1
        close_brace_index = _find_matching_brace(text, open_brace_index)
        if close_brace_index is None:
            position = match.end()
            continue
        yield match.group(1), match.group(2), text[open_brace_index + 1 : close_brace_index]
        position = close_brace_index + 1


def _find_matching_brace(text: str, open_brace_index: int) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(open_brace_index, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _extract_attributes(body: str) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for key, raw_value in _ATTRIBUTE_RE.findall(body):
        value = raw_value.strip().strip(",")
        if "\n" in value or value.startswith(("{", "[")):
            continue
        attributes[key] = value.strip('"')
    return attributes


def _node_type_for(resource_type: str) -> NodeType:
    if resource_type in _EXACT_NODE_TYPES:
        return _EXACT_NODE_TYPES[resource_type]
    if any(token in resource_type for token in ("db", "database", "sql")):
        return NodeType.DATABASE
    if any(token in resource_type for token in ("secret", "key_vault")):
        return NodeType.SECRET
    if any(token in resource_type for token in ("bucket", "storage")):
        return NodeType.DATA_ASSET
    if any(token in resource_type for token in ("vpc", "subnet", "network")):
        return NodeType.TRUST_BOUNDARY
    if "api" in resource_type:
        return NodeType.API
    return NodeType.COMPONENT


def _resource_id(resource_type: str, name: str) -> str:
    return make_id("terraform", resource_type, name)


def _display_name(resource_type: str, name: str, attributes: dict[str, str]) -> str:
    for key in _DISPLAY_NAME_KEYS:
        if attributes.get(key):
            return attributes[key]
    return f"{resource_type}.{name}"


def _is_internet_exposed(body: str) -> bool:
    lowered = body.lower()
    return (
        "0.0.0.0/0" in lowered
        or "::/0" in lowered
        or "publicly_accessible = true" in lowered
        or "internal = false" in lowered
        or "map_public_ip_on_launch = true" in lowered
    )


def _assign_trust_boundaries(
    nodes: dict[str, Node],
    resource_blocks: dict[str, str],
) -> dict[str, Node]:
    trust_boundary_ids = {
        node.id for node in nodes.values() if node.type == NodeType.TRUST_BOUNDARY
    }
    if not trust_boundary_ids:
        return nodes

    updated: dict[str, Node] = {}
    for node_id, node in nodes.items():
        if node.type == NodeType.TRUST_BOUNDARY:
            updated[node_id] = node
            continue
        referenced_boundaries = [
            ref_id
            for ref_id in _reference_ids(resource_blocks.get(node_id, ""))
            if ref_id in trust_boundary_ids
        ]
        updated[node_id] = (
            node.model_copy(update={"trust_boundary_id": sorted(referenced_boundaries)[0]})
            if referenced_boundaries
            else node
        )
    return updated


def _extract_edges(nodes: dict[str, Node], resource_blocks: dict[str, str]) -> dict[str, Edge]:
    edges: dict[str, Edge] = {}
    for source_id, body in resource_blocks.items():
        for target_id in sorted(set(_reference_ids(body))):
            if target_id == source_id or target_id not in nodes:
                continue
            edge_type = (
                EdgeType.STORES
                if nodes[target_id].type in {NodeType.DATABASE, NodeType.DATA_ASSET}
                else EdgeType.INVOKES
            )
            edge_id = make_id("edge", source_id, target_id, edge_type.value)
            edges[edge_id] = Edge(
                id=edge_id,
                source=source_id,
                target=target_id,
                type=edge_type,
                description=(
                    f"Terraform reference from {nodes[source_id].name} "
                    f"to {nodes[target_id].name}."
                ),
                evidence=nodes[source_id].evidence,
            )
    return edges


def _add_internet_entrypoints(nodes: dict[str, Node], edges: dict[str, Edge]) -> None:
    exposed_nodes = [
        node
        for node in nodes.values()
        if node.metadata.get("internet_exposed") and node.type in {NodeType.API, NodeType.COMPONENT}
    ]
    if not exposed_nodes:
        return

    actor_id = make_id("actor", "terraform", "internet")
    nodes.setdefault(
        actor_id,
        Node(
            id=actor_id,
            name="Internet",
            type=NodeType.ACTOR,
            description="External network source implied by public Terraform exposure.",
            evidence=[
                Evidence(
                    source_type=SourceType.TERRAFORM,
                    source_path="derived",
                    detail="internet exposure",
                )
            ],
        ),
    )
    for node in exposed_nodes:
        edge_id = make_id("edge", actor_id, node.id, "public-access")
        edges[edge_id] = Edge(
            id=edge_id,
            source=actor_id,
            target=node.id,
            type=EdgeType.COMMUNICATES_WITH,
            description=f"Public network access to {node.name} is implied by Terraform exposure.",
            evidence=node.evidence,
        )


def _reference_ids(body: str) -> Iterator[str]:
    for resource_type, name in _REFERENCE_RE.findall(body):
        if resource_type in {"var", "local", "data", "module", "each", "count"}:
            continue
        yield _resource_id(resource_type, name)
