from pathlib import Path

from threatmodel_ai.extract import (
    extract_mermaid_markdown,
    extract_openapi,
    extract_readme,
    extract_terraform,
)
from threatmodel_ai.model.schema import EdgeType, NodeType

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


def test_openapi_extractor_creates_endpoint_flows_and_data_assets() -> None:
    model = extract_openapi(FIXTURE / "openapi.yaml")

    node_names = {node.name for node in model.nodes}
    assert "API Client" in node_names
    assert "POST /payments" in node_names
    assert "PaymentRequest" in node_names

    external_edges = [
        edge
        for edge in model.edges
        if edge.type == EdgeType.COMMUNICATES_WITH and edge.target.startswith("api:post")
    ]
    assert len(external_edges) == 1
    assert external_edges[0].authentication == "apiKey header:X-API-Key"
    assert external_edges[0].protocol == "HTTPS"
    assert external_edges[0].data_assets


def test_readme_extractor_keeps_explicit_documented_nodes() -> None:
    model = extract_readme(FIXTURE / "README.md")

    assert model.name == "Sample Payments API"
    assert any(node.type == NodeType.ACTOR and node.name == "Customer" for node in model.nodes)
    assert any(
        node.type == NodeType.DATABASE and node.name == "Payments DB" for node in model.nodes
    )
    assert any(unknown.category == "authentication" for unknown in model.unknowns)


def test_terraform_extractor_maps_resources_and_dependencies() -> None:
    model = extract_terraform((FIXTURE / "main.tf",))

    assert any(
        node.type == NodeType.DATABASE and node.name == "payments-db" for node in model.nodes
    )
    assert any(node.type == NodeType.TRUST_BOUNDARY for node in model.nodes)
    assert any(node.type == NodeType.ACTOR and node.name == "Internet" for node in model.nodes)
    assert any(edge.type == EdgeType.STORES for edge in model.edges)


def test_mermaid_extractor_reads_markdown_flowcharts() -> None:
    model = extract_mermaid_markdown(FIXTURE / "docs" / "architecture.md")

    assert any(
        node.type == NodeType.COMPONENT
        and node.name == "Web Client"
        and node.metadata["source_format"] == "mermaid"
        for node in model.nodes
    )
    assert any(
        edge.type == EdgeType.COMMUNICATES_WITH
        and edge.protocol == "HTTPS"
        and edge.metadata["mermaid_label"] == "HTTPS"
        for edge in model.edges
    )
    assert any(unknown.category == "authentication" for unknown in model.unknowns)
    assert any(unknown.category == "protocol" for unknown in model.unknowns)


def test_mermaid_extractor_reads_bare_edges(tmp_path: Path) -> None:
    markdown = tmp_path / "architecture.md"
    markdown.write_text(
        "\n".join(
            [
                "```mermaid",
                "graph LR",
                "  A --> B",
                "```",
            ]
        ),
        encoding="utf-8",
    )

    model = extract_mermaid_markdown(markdown)

    assert {node.name for node in model.nodes} == {"A", "B"}
    assert len(model.edges) == 1
    assert model.edges[0].protocol == "unknown"
