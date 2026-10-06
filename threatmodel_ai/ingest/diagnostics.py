"""Deterministic counts describing what the selected adapters proposed."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from threatmodel_ai.model.observations import ObservationBatch
from threatmodel_ai.model.schema import SystemModel

AdapterName = Literal["readme", "mermaid", "openapi", "terraform"]
ADAPTER_ORDER: tuple[AdapterName, ...] = (
    "readme",
    "mermaid",
    "openapi",
    "terraform",
)


class ObservationCounts(BaseModel):
    """Counts of proposed observations, not claims of extraction coverage."""

    model_config = ConfigDict(extra="forbid")

    system: int = Field(ge=0)
    node: int = Field(ge=0)
    edge: int = Field(ge=0)
    unknown: int = Field(ge=0)


class AdapterDiagnostics(BaseModel):
    """One adapter's selected input count and structured proposals."""

    model_config = ConfigDict(extra="forbid")

    adapter: AdapterName
    selected_files: int = Field(ge=0)
    batches_used: int = Field(ge=0)
    proposed: ObservationCounts


class ModelCounts(BaseModel):
    """Counts in the normalized model after merging adapter proposals."""

    model_config = ConfigDict(extra="forbid")

    nodes: int = Field(ge=0)
    edges: int = Field(ge=0)
    unknowns: int = Field(ge=0)


class MermaidParseMetrics(BaseModel):
    """Count only Mermaid syntax the current parser can classify honestly."""

    model_config = ConfigDict(extra="forbid")

    closed_fences: int = Field(default=0, ge=0)
    unclosed_fences: int = Field(default=0, ge=0)
    flowchart_blocks: int = Field(default=0, ge=0)
    unsupported_diagram_blocks: int = Field(default=0, ge=0)
    parsed_statements: int = Field(default=0, ge=0)
    skipped_statements: int = Field(default=0, ge=0)

    def add(self, other: MermaidParseMetrics) -> None:
        """Accumulate counts from another scanned Markdown document."""

        for field in type(self).model_fields:
            setattr(self, field, getattr(self, field) + getattr(other, field))


class OpenApiParseMetrics(BaseModel):
    """Count declared OpenAPI paths and HTTP operations handled by the adapter."""

    model_config = ConfigDict(extra="forbid")

    path_items_declared: int = Field(default=0, ge=0)
    path_items_skipped: int = Field(default=0, ge=0)
    http_operations_declared: int = Field(default=0, ge=0)
    http_operations_modeled: int = Field(default=0, ge=0)
    http_operations_skipped: int = Field(default=0, ge=0)


class TerraformParseMetrics(BaseModel):
    """Count resource blocks recognized by the current Terraform heuristic."""

    model_config = ConfigDict(extra="forbid")

    files_without_recognized_resources: int = Field(default=0, ge=0)
    resource_blocks_recognized: int = Field(default=0, ge=0)
    distinct_resource_ids: int = Field(default=0, ge=0)
    colliding_resource_declarations: int = Field(default=0, ge=0)


class IngestionDiagnostics(BaseModel):
    """Privacy-safe, versioned diagnostics for one successful analysis."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"] = "0.1"
    adapters: list[AdapterDiagnostics]
    normalized_model: ModelCounts
    mermaid_parse: MermaidParseMetrics
    openapi_parse: OpenApiParseMetrics
    terraform_parse: TerraformParseMetrics
    interpretation: str = (
        "Counts describe selected files, recognized syntax, and structured proposals; "
        "they do not measure parser coverage or architectural completeness. A file "
        "may be selected by more than one adapter."
    )


def summarize_ingestion(
    *,
    selected_files: dict[AdapterName, int],
    batches_by_adapter: dict[AdapterName, list[ObservationBatch]],
    model: SystemModel,
    mermaid_parse: MermaidParseMetrics,
    openapi_parse: OpenApiParseMetrics,
    terraform_parse: TerraformParseMetrics,
) -> IngestionDiagnostics:
    """Summarize structured batches without exposing paths or source content."""

    adapters: list[AdapterDiagnostics] = []
    for adapter in ADAPTER_ORDER:
        counts = {kind: 0 for kind in ("system", "node", "edge", "unknown")}
        batches = batches_by_adapter.get(adapter, [])
        for batch in batches:
            for observation in batch.observations:
                counts[observation.kind] += 1
        adapters.append(
            AdapterDiagnostics(
                adapter=adapter,
                selected_files=selected_files.get(adapter, 0),
                batches_used=len(batches),
                proposed=ObservationCounts(**counts),
            )
        )
    return IngestionDiagnostics(
        adapters=adapters,
        normalized_model=ModelCounts(
            nodes=len(model.nodes),
            edges=len(model.edges),
            unknowns=len(model.unknowns),
        ),
        mermaid_parse=mermaid_parse,
        openapi_parse=openapi_parse,
        terraform_parse=terraform_parse,
    )
