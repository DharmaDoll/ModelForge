"""Terraform extractor using deterministic HCL block heuristics."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from threatmodel_ai.errors import InputFormatError
from threatmodel_ai.ingest.diagnostics import TerraformParseMetrics
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

_RESOURCE_START_RE = re.compile(
    r'^[ \t]*resource[ \t]+"([^"]+)"[ \t]+"([^"]+)"[ \t]*\{', re.MULTILINE
)
_ATTRIBUTE_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$", re.MULTILINE)
_REFERENCE_RE = re.compile(r"\b([a-z][a-z0-9_]+)\.([A-Za-z0-9_-]+)\b")
_LOAD_BALANCER_TYPES = {"aws_lb", "aws_alb", "aws_elb"}

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

_BOUNDARY_PRIORITY = {
    "aws-security-group": 0,
    "azurerm-network-security-group": 0,
    "aws-subnet": 1,
    "azurerm-subnet": 1,
    "google-compute-subnetwork": 1,
    "aws-vpc": 2,
    "azurerm-virtual-network": 2,
    "google-compute-network": 2,
}


def extract_terraform(
    paths: Iterable[Path], *, identity_root: Path | None = None
) -> SystemModel:
    """Extract cloud resources and Terraform dependency edges from .tf files."""

    return normalize_observation_batch(observe_terraform(paths, identity_root=identity_root))


def observe_terraform(
    paths: Iterable[Path], *, identity_root: Path | None = None
) -> ObservationBatch:
    """Extract evidence-bearing candidate observations from Terraform files."""

    batch, _ = observe_terraform_with_diagnostics(paths, identity_root=identity_root)
    return batch


def observe_terraform_with_diagnostics(
    paths: Iterable[Path], *, identity_root: Path | None = None
) -> tuple[ObservationBatch, TerraformParseMetrics]:
    """Extract observations and count resource blocks recognized by the adapter."""

    path_list = tuple(paths)
    fallback_evidence = [
        Evidence(
            source_type=SourceType.TERRAFORM,
            source_path=str(path),
            extractor="terraform",
            detail="Terraform file",
        )
        for path in path_list
    ]
    metrics = TerraformParseMetrics()
    root = identity_root or _common_parent(path_list)
    batch = model_to_observation_batch(
        _extract_terraform_model(path_list, identity_root=root, metrics=metrics),
        fallback_evidence=fallback_evidence,
    )
    return batch, metrics


def _extract_terraform_model(
    paths: Iterable[Path], *, identity_root: Path, metrics: TerraformParseMetrics
) -> SystemModel:
    """Build the Terraform adapter's proposed model before normalization."""

    path_list = tuple(paths)
    resources = list(_collect_resources(path_list))
    resource_groups: dict[str, list[_TerraformResource]] = {}
    for resource in resources:
        node_id = _resource_id(
            resource.resource_type,
            resource.name,
            _module_scope(resource.path, identity_root),
        )
        resource_groups.setdefault(node_id, []).append(resource)
    selected_paths = {path.resolve() for path in path_list}
    recognized_paths = {item.path.resolve() for item in resources}
    metrics.files_without_recognized_resources = len(selected_paths - recognized_paths)
    metrics.resource_blocks_recognized = len(resources)
    metrics.distinct_resource_ids = len(resource_groups)
    metrics.colliding_resource_declarations = len(resources) - len(resource_groups)
    nodes: dict[str, Node] = {}
    resource_blocks: dict[str, str] = {}
    resource_scopes: dict[str, str | None] = {}
    unknowns: list[Unknown] = []

    conflicted_ids = {
        node_id for node_id, group in resource_groups.items() if len(group) > 1
    }
    for node_id in sorted(conflicted_ids):
        group = resource_groups[node_id]
        evidence = [_resource_evidence(resource) for resource in group]
        unknowns.append(
            Unknown(
                id=make_id("unknown", "terraform", node_id, "identity-conflict"),
                category="model_conflict",
                description=(
                    f"Multiple Terraform declarations map to {node_id}; "
                    "their attributes and references were not accepted."
                ),
                evidence=evidence[0],
                conflicting_evidence=evidence[1:],
            )
        )

    for resource in resources:
        node_type = _node_type_for(resource.resource_type)
        module_scope = _module_scope(resource.path, identity_root)
        node_id = _resource_id(resource.resource_type, resource.name, module_scope)
        if node_id in conflicted_ids:
            continue
        attributes = _extract_attributes(_strip_hcl_comments(resource.body))
        display_name = _display_name(resource.resource_type, resource.name, attributes)
        metadata = {
            "terraform_type": resource.resource_type,
            "terraform_name": resource.name,
        }
        if _is_internet_exposed(resource.resource_type, attributes):
            metadata["internet_exposed"] = True

        nodes[node_id] = Node(
            id=node_id,
            name=display_name,
            type=node_type,
            description=f"Terraform resource {resource.resource_type}.{resource.name}",
            metadata=metadata,
            evidence=[_resource_evidence(resource)],
        )
        if (
            resource.resource_type in _LOAD_BALANCER_TYPES
            and attributes.get("internal", "").lower() not in {"true", "false"}
        ):
            unknowns.append(
                Unknown(
                    id=make_id("unknown", "terraform", node_id, "internet-exposure"),
                    category="internet_exposure",
                    description=(
                        f"Internet exposure for {display_name} is not established by a "
                        "literal internal setting."
                    ),
                    related_element_id=node_id,
                    evidence=nodes[node_id].evidence[0],
                )
            )
        resource_blocks[node_id] = resource.body
        resource_scopes[node_id] = module_scope

    nodes = _assign_trust_boundaries(nodes, resource_blocks, resource_scopes)
    edges = _extract_edges(nodes, resource_blocks, resource_scopes)
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
        metadata={"terraform_files": sorted(str(path) for path in path_list)},
    )


class _TerraformResource:
    def __init__(
        self,
        path: Path,
        resource_type: str,
        name: str,
        body: str,
        line: int,
    ) -> None:
        self.path = path
        self.resource_type = resource_type
        self.name = name
        self.body = body
        self.line = line


def _resource_evidence(resource: _TerraformResource) -> Evidence:
    """Point to one resource declaration without copying its source text."""

    return Evidence(
        source_type=SourceType.TERRAFORM,
        source_path=str(resource.path),
        extractor="terraform",
        detail=f'resource "{resource.resource_type}" "{resource.name}"',
        line=resource.line,
    )


def _collect_resources(paths: Iterable[Path]) -> Iterator[_TerraformResource]:
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8")
        for resource_type, name, body, line in _iter_resource_blocks(
            _strip_hcl_comments(text), path
        ):
            yield _TerraformResource(
                path=path,
                resource_type=resource_type,
                name=name,
                body=body,
                line=line,
            )


def _iter_resource_blocks(text: str, path: Path) -> Iterator[tuple[str, str, str, int]]:
    position = 0
    while match := _RESOURCE_START_RE.search(text, position):
        line = text.count("\n", 0, match.start()) + 1
        open_brace_index = match.end() - 1
        close_brace_index = _find_matching_brace(text, open_brace_index)
        if close_brace_index is None:
            raise InputFormatError(
                f"Terraform input has an unterminated resource block: {path}",
                detail=(
                    f'resource "{match.group(1)}" "{match.group(2)}" '
                    "is missing a closing brace."
                ),
                hint="Run terraform fmt/validate, then retry the analysis.",
            )
        yield (
            match.group(1),
            match.group(2),
            text[open_brace_index + 1 : close_brace_index],
            line,
        )
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


def _common_parent(paths: tuple[Path, ...]) -> Path:
    """Choose a fallback root when an adapter is called outside the CLI."""

    if not paths:
        return Path.cwd()
    return Path(os.path.commonpath([str(path.resolve().parent) for path in paths]))


def _module_scope(path: Path, identity_root: Path) -> str | None:
    """Scope a Terraform resource to its directory without checkout-specific IDs."""

    parent = path.resolve().parent
    try:
        relative = parent.relative_to(identity_root.resolve())
    except ValueError:
        return f"external-{slugify(parent.name)}-{short_hash(parent, length=10)}"
    if not relative.parts:
        return None
    relative_text = relative.as_posix()
    return f"{slugify(relative_text)}-{short_hash(relative_text, length=10)}"


def _resource_id(resource_type: str, name: str, module_scope: str | None = None) -> str:
    if module_scope is None:
        return make_id("terraform", resource_type, name)
    return make_id("terraform", module_scope, resource_type, name)


def _display_name(resource_type: str, name: str, attributes: dict[str, str]) -> str:
    for key in _DISPLAY_NAME_KEYS:
        if attributes.get(key):
            return attributes[key]
    return f"{resource_type}.{name}"


def _is_internet_exposed(resource_type: str, attributes: dict[str, str]) -> bool:
    """Recognize explicitly internet-facing load balancers, not mere public addresses."""

    if resource_type in _LOAD_BALANCER_TYPES:
        return attributes.get("internal", "").lower() == "false"
    return False


def _assign_trust_boundaries(
    nodes: dict[str, Node],
    resource_blocks: dict[str, str],
    resource_scopes: dict[str, str | None],
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
            for key, value in _ATTRIBUTE_RE.findall(resource_blocks.get(node_id, ""))
            if key in {"vpc_id", "subnet_id", "subnet_ids", "vpc_security_group_ids"}
            for ref_id in _reference_ids(value, resource_scopes[node_id])
            if ref_id in trust_boundary_ids
        ]
        updated[node_id] = (
            node.model_copy(
                update={"trust_boundary_id": _select_trust_boundary(referenced_boundaries)}
            )
            if referenced_boundaries
            else node
        )
    return updated


def _select_trust_boundary(boundary_ids: list[str]) -> str:
    return sorted(boundary_ids, key=lambda item: (_boundary_priority(item), item))[0]


def _boundary_priority(boundary_id: str) -> int:
    parts = boundary_id.split(":")
    resource_type = parts[-2] if len(parts) >= 3 else ""
    return _BOUNDARY_PRIORITY.get(resource_type, 99)


def _extract_edges(
    nodes: dict[str, Node],
    resource_blocks: dict[str, str],
    resource_scopes: dict[str, str | None],
) -> dict[str, Edge]:
    edges: dict[str, Edge] = {}
    for source_id, body in resource_blocks.items():
        for target_id in sorted(set(_reference_ids(body, resource_scopes[source_id]))):
            if target_id == source_id or target_id not in nodes:
                continue
            edge_type = EdgeType.REFERENCES
            edge_id = make_id("edge", source_id, target_id, edge_type.value)
            edges[edge_id] = Edge(
                id=edge_id,
                source=source_id,
                target=target_id,
                type=edge_type,
                description=(
                    f"Terraform configuration for {nodes[source_id].name} references "
                    f"{nodes[target_id].name}; runtime communication is unknown."
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
            metadata={"derived_from": "terraform_exposure"},
            evidence=[
                Evidence(
                    source_type=SourceType.TERRAFORM,
                    source_path="derived",
                    extractor="terraform",
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
            metadata={"derived_from": "terraform_exposure"},
            evidence=node.evidence,
        )


def _reference_ids(body: str, module_scope: str | None = None) -> Iterator[str]:
    for resource_type, name in _REFERENCE_RE.findall(_strip_hcl_comments(body)):
        if resource_type in {"var", "local", "data", "module", "each", "count"}:
            continue
        yield _resource_id(resource_type, name, module_scope)


def _strip_hcl_comments(body: str) -> str:
    """Blank comments while preserving positions, line numbers, and quoted strings."""

    result: list[str] = []
    index = 0
    in_string = False
    while index < len(body):
        char = body[index]
        next_char = body[index + 1] if index + 1 < len(body) else ""
        if char == '"' and (index == 0 or body[index - 1] != "\\"):
            in_string = not in_string
        if not in_string and (char == "#" or (char == "/" and next_char == "/")):
            while index < len(body) and body[index] != "\n":
                result.append(" ")
                index += 1
            continue
        if not in_string and char == "/" and next_char == "*":
            end = body.find("*/", index + 2)
            stop = len(body) if end < 0 else end + 2
            result.extend("\n" if part == "\n" else " " for part in body[index:stop])
            index = stop
            continue
        result.append(char)
        index += 1
    return "".join(result)
