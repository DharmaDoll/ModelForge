"""Pydantic schemas for the structured intermediate system model."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SourceType(StrEnum):
    """Supported MVP input source types."""

    README = "readme"
    OPENAPI = "openapi"
    TERRAFORM = "terraform"
    DERIVED = "derived"


class NodeType(StrEnum):
    """Graph node types used by the system model."""

    ACTOR = "actor"
    COMPONENT = "component"
    API = "api"
    DATABASE = "database"
    EXTERNAL_SERVICE = "external_service"
    SECRET = "secret"
    DATA_ASSET = "data_asset"
    TRUST_BOUNDARY = "trust_boundary"


class EdgeType(StrEnum):
    """Graph edge types used by the system model."""

    COMMUNICATES_WITH = "communicates_with"
    STORES = "stores"
    AUTHENTICATES = "authenticates"
    INVOKES = "invokes"
    OWNS = "owns"


class Evidence(BaseModel):
    """A non-sensitive pointer to where a model fact came from."""

    model_config = ConfigDict(extra="forbid")

    source_type: SourceType
    source_path: str
    detail: str = "unknown"


class Unknown(BaseModel):
    """Security-relevant information that was not present in the inputs."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    description: str
    related_element_id: str | None = None
    evidence: Evidence | None = None


class Node(BaseModel):
    """A typed graph node in the intermediate model."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    type: NodeType
    description: str = "unknown"
    trust_boundary_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)


class Edge(BaseModel):
    """A typed graph edge in the intermediate model."""

    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    target: str
    type: EdgeType
    description: str = "unknown"
    protocol: str = "unknown"
    authentication: str = "unknown"
    authorization: str = "unknown"
    data_assets: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)


class SystemModel(BaseModel):
    """The source-of-truth intermediate model consumed by all generators."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.1"
    id: str = "system"
    name: str = "unknown"
    description: str = "unknown"
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    unknowns: list[Unknown] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_references(self) -> SystemModel:
        """Fail fast when generated artifacts reference missing graph elements."""

        node_ids = {node.id for node in self.nodes}
        edge_ids = {edge.id for edge in self.edges}
        all_ids = node_ids | edge_ids

        if len(node_ids) != len(self.nodes):
            raise ValueError("system model contains duplicate node ids")
        if len(edge_ids) != len(self.edges):
            raise ValueError("system model contains duplicate edge ids")

        for node in self.nodes:
            if node.trust_boundary_id and node.trust_boundary_id not in node_ids:
                raise ValueError(
                    f"node {node.id!r} references missing trust boundary "
                    f"{node.trust_boundary_id!r}"
                )

        for edge in self.edges:
            if edge.source not in node_ids:
                raise ValueError(f"edge {edge.id!r} references missing source {edge.source!r}")
            if edge.target not in node_ids:
                raise ValueError(f"edge {edge.id!r} references missing target {edge.target!r}")
            missing_assets = [asset for asset in edge.data_assets if asset not in node_ids]
            if missing_assets:
                raise ValueError(
                    f"edge {edge.id!r} references missing data assets {missing_assets!r}"
                )

        for unknown in self.unknowns:
            if unknown.related_element_id and unknown.related_element_id not in all_ids:
                raise ValueError(
                    f"unknown {unknown.id!r} references missing element "
                    f"{unknown.related_element_id!r}"
                )

        return self
