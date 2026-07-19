"""OpenAPI extractor for REST API topology and endpoint data flows."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import yaml
from yaml import YAMLError

from threatmodel_ai.errors import InputFormatError
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

_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}


def extract_openapi(path: Path) -> SystemModel:
    """Extract API endpoints, schemas, and authentication facts from an OpenAPI file."""

    document = _load_document(path)
    if not isinstance(document, Mapping):
        raise InputFormatError(
            f"OpenAPI input must be a YAML or JSON object: {path}",
            detail=f"Found {type(document).__name__}.",
            hint="Provide an OpenAPI/Swagger document with top-level info and paths fields.",
        )
    if "openapi" not in document and "swagger" not in document:
        raise InputFormatError(
            f"OpenAPI input is missing a version field: {path}",
            detail="Expected a top-level 'openapi' or 'swagger' field.",
            hint="Check that --openapi points to an OpenAPI/Swagger file.",
        )
    if not isinstance(document.get("paths"), Mapping):
        raise InputFormatError(
            f"OpenAPI input is missing a paths object: {path}",
            detail="Expected top-level 'paths' to be a mapping of API paths.",
            hint="Add a paths object or pass the correct OpenAPI/Swagger file.",
        )

    info = _mapping(document.get("info"))
    title = str(info.get("title") or path.stem)
    description = str(info.get("description") or "unknown")
    evidence = Evidence(
        source_type=SourceType.OPENAPI,
        source_path=str(path),
        extractor="openapi",
        detail="OpenAPI",
    )
    service_id = make_id("component", "openapi", title)
    actor_id = make_id("actor", "openapi", "api client")

    nodes: dict[str, Node] = {
        service_id: Node(
            id=service_id,
            name=title,
            type=NodeType.COMPONENT,
            description=description,
            evidence=[evidence],
        ),
        actor_id: Node(
            id=actor_id,
            name="API Client",
            type=NodeType.ACTOR,
            description="Client role implied by the OpenAPI contract.",
            evidence=[evidence],
        ),
    }
    edges: dict[str, Edge] = {}
    unknowns: list[Unknown] = []

    security_schemes = _mapping(_mapping(document.get("components")).get("securitySchemes"))
    schema_ids = _extract_schema_nodes(path, document, nodes)
    protocol = _resolve_protocol(document)
    global_security = document.get("security")

    for api_path, path_item in sorted(_mapping(document.get("paths")).items()):
        if not isinstance(path_item, Mapping):
            continue
        for method, operation in sorted(path_item.items()):
            method_lower = str(method).lower()
            if method_lower not in _HTTP_METHODS or not isinstance(operation, Mapping):
                continue

            operation_id = make_id("api", method_lower, api_path)
            operation_name = f"{method_upper(method_lower)} {api_path}"
            nodes[operation_id] = Node(
                id=operation_id,
                name=operation_name,
                type=NodeType.API,
                description=str(
                    operation.get("summary") or operation.get("description") or "unknown"
                ),
                evidence=[
                    Evidence(
                        source_type=SourceType.OPENAPI,
                        source_path=str(path),
                        extractor="openapi",
                        detail=f"{method_upper(method_lower)} {api_path}",
                    )
                ],
            )

            operation_security = operation.get("security", global_security)
            authentication = _resolve_authentication(operation_security, security_schemes)
            authorization = _resolve_authorization(operation_security)
            referenced_assets = sorted(
                {
                    schema_ids[ref]
                    for ref in _schema_refs(operation)
                    if ref in schema_ids
                }
            )

            client_edge_id = make_id("edge", actor_id, operation_id, "request")
            edges[client_edge_id] = Edge(
                id=client_edge_id,
                source=actor_id,
                target=operation_id,
                type=EdgeType.COMMUNICATES_WITH,
                description=f"Client calls {operation_name}.",
                protocol=protocol,
                authentication=authentication,
                authorization=authorization,
                data_assets=referenced_assets,
                evidence=[
                    Evidence(
                        source_type=SourceType.OPENAPI,
                        source_path=str(path),
                        extractor="openapi",
                        detail=f"{method_upper(method_lower)} {api_path}",
                    )
                ],
            )
            edges[make_id("edge", operation_id, service_id, "handler")] = Edge(
                id=make_id("edge", operation_id, service_id, "handler"),
                source=operation_id,
                target=service_id,
                type=EdgeType.INVOKES,
                description=f"{operation_name} is handled by {title}.",
                data_assets=referenced_assets,
                evidence=[
                    Evidence(
                        source_type=SourceType.OPENAPI,
                        source_path=str(path),
                        extractor="openapi",
                        detail=f"{method_upper(method_lower)} {api_path}",
                    )
                ],
            )

            if authentication == "unknown":
                unknowns.append(
                    Unknown(
                        id=make_id("unknown", "openapi", operation_id, "authentication"),
                        category="authentication",
                        description=f"Authentication for {operation_name} is not specified.",
                        related_element_id=client_edge_id,
                        evidence=evidence,
                    )
                )
            if authorization == "unknown" and authentication not in {"none", "unknown"}:
                unknowns.append(
                    Unknown(
                        id=make_id("unknown", "openapi", operation_id, "authorization"),
                        category="authorization",
                        description=(
                            f"Authorization requirements for {operation_name} are not specified."
                        ),
                        related_element_id=client_edge_id,
                        evidence=evidence,
                    )
                )

    for schema_name, schema_id in schema_ids.items():
        schema_node = nodes[schema_id]
        if "classification" not in schema_node.metadata:
            unknowns.append(
                Unknown(
                    id=make_id("unknown", "openapi", schema_name, "data-classification"),
                    category="data_classification",
                    description=f"Data classification for schema {schema_name} is unknown.",
                    related_element_id=schema_id,
                    evidence=evidence,
                )
            )

    return SystemModel(
        name=title,
        description=description,
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges.values(), key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns, key=lambda unknown: unknown.id),
        metadata={
            "openapi_path": str(path),
            "openapi_version": str(document.get("openapi", "unknown")),
        },
    )


def method_upper(method: str) -> str:
    """Return an uppercase HTTP method label."""

    return method.upper()


def _load_document(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() == ".json":
            return json.loads(raw)
        return yaml.safe_load(raw)
    except JSONDecodeError as exc:
        raise InputFormatError(
            f"OpenAPI input is invalid JSON: {path}",
            detail=f"Line {exc.lineno}, column {exc.colno}: {exc.msg}.",
            hint="Fix the JSON syntax or pass a valid OpenAPI YAML/JSON file.",
        ) from exc
    except YAMLError as exc:
        raise InputFormatError(
            f"OpenAPI input is invalid YAML: {path}",
            detail=str(exc),
            hint="Fix the YAML syntax or pass a valid OpenAPI YAML/JSON file.",
        ) from exc


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _resolve_protocol(document: Mapping[str, Any]) -> str:
    servers = document.get("servers")
    if not isinstance(servers, list) or not servers:
        return "unknown"
    protocols: set[str] = set()
    for server in servers:
        if not isinstance(server, Mapping):
            continue
        url = str(server.get("url") or "")
        if url.startswith("https://"):
            protocols.add("HTTPS")
        elif url.startswith("http://"):
            protocols.add("HTTP")
    if len(protocols) == 1:
        return protocols.pop()
    return "unknown"


def _resolve_authentication(security: Any, security_schemes: Mapping[str, Any]) -> str:
    if security is None:
        return "unknown"
    if security == []:
        return "none"
    if not isinstance(security, list):
        return "unknown"

    auth_methods: list[str] = []
    for requirement in security:
        if requirement == {}:
            auth_methods.append("none")
            continue
        if not isinstance(requirement, Mapping):
            continue
        for scheme_name in requirement:
            scheme = _mapping(security_schemes.get(scheme_name))
            auth_methods.append(_format_security_scheme(str(scheme_name), scheme))
    return ", ".join(sorted(set(auth_methods))) if auth_methods else "unknown"


def _resolve_authorization(security: Any) -> str:
    if security is None:
        return "unknown"
    if security == []:
        return "none"
    if not isinstance(security, list):
        return "unknown"

    scopes: set[str] = set()
    for requirement in security:
        if not isinstance(requirement, Mapping):
            continue
        for scheme_scopes in requirement.values():
            if isinstance(scheme_scopes, list):
                scopes.update(str(scope) for scope in scheme_scopes)
    return "oauth2 scopes: " + ", ".join(sorted(scopes)) if scopes else "unknown"


def _format_security_scheme(name: str, scheme: Mapping[str, Any]) -> str:
    scheme_type = str(scheme.get("type") or name)
    if scheme_type == "http":
        return f"http {scheme.get('scheme', 'unknown')}"
    if scheme_type == "apiKey":
        location = scheme.get("in", "unknown")
        header_name = scheme.get("name", name)
        return f"apiKey {location}:{header_name}"
    if scheme_type in {"oauth2", "openIdConnect"}:
        return scheme_type
    return scheme_type


def _extract_schema_nodes(
    path: Path,
    document: Mapping[str, Any],
    nodes: dict[str, Node],
) -> dict[str, str]:
    schema_ids: dict[str, str] = {}
    schemas = _mapping(_mapping(document.get("components")).get("schemas"))
    for schema_name, schema in sorted(schemas.items()):
        schema_id = make_id("data_asset", "openapi", schema_name)
        schema_ids[str(schema_name)] = schema_id
        description = "unknown"
        if isinstance(schema, Mapping):
            description = str(schema.get("description") or "OpenAPI schema")
        nodes[schema_id] = Node(
            id=schema_id,
            name=str(schema_name),
            type=NodeType.DATA_ASSET,
            description=description,
            metadata={"schema_name": str(schema_name)},
            evidence=[
                Evidence(
                    source_type=SourceType.OPENAPI,
                    source_path=str(path),
                    extractor="openapi",
                    detail=f"components.schemas.{schema_name}",
                )
            ],
        )
    return schema_ids


def _schema_refs(value: Any) -> Iterable[str]:
    for ref in _iter_refs(value):
        if ref.startswith("#/components/schemas/"):
            yield ref.rsplit("/", maxsplit=1)[-1]


def _iter_refs(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        ref = value.get("$ref")
        if isinstance(ref, str):
            yield ref
        for child in value.values():
            yield from _iter_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_refs(child)
