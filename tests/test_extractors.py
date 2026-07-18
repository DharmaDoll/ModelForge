from pathlib import Path

import pytest

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
        node.type == NodeType.ACTOR
        and node.name == "Web Client"
        and node.metadata["source_format"] == "mermaid"
        and node.metadata["type_inference_keyword"] == "client"
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


def test_mermaid_extractor_infers_explicit_node_types(tmp_path: Path) -> None:
    markdown = tmp_path / "architecture.md"
    markdown.write_text(
        "\n".join(
            [
                "```mermaid",
                "flowchart LR",
                '  User["Customer User"] --> Api["Orders API"]',
                '  Api --> Db["Orders Postgres DB"]',
                '  Api --> Bucket["S3 Bucket"]',
                '  Api --> Partner["External Partner"]',
                '  Api --> Secret["API Key Secret"]',
                '  Api --> api_key["Runtime Config"]',
                "```",
            ]
        ),
        encoding="utf-8",
    )

    model = extract_mermaid_markdown(markdown)
    nodes_by_name = {node.name: node for node in model.nodes}

    assert nodes_by_name["Customer User"].type == NodeType.ACTOR
    assert nodes_by_name["Orders Postgres DB"].type == NodeType.DATABASE
    assert nodes_by_name["S3 Bucket"].type == NodeType.DATA_ASSET
    assert nodes_by_name["External Partner"].type == NodeType.EXTERNAL_SERVICE
    assert nodes_by_name["API Key Secret"].type == NodeType.SECRET
    assert nodes_by_name["Runtime Config"].type == NodeType.SECRET
    assert nodes_by_name["Orders API"].type == NodeType.COMPONENT
    assert nodes_by_name["S3 Bucket"].metadata["type_inferred_from"] == "mermaid_label"
    assert nodes_by_name["S3 Bucket"].metadata["type_inference_keyword"] == "bucket"
    assert nodes_by_name["Runtime Config"].metadata["type_inferred_from"] == "mermaid_alias"
    assert nodes_by_name["Runtime Config"].metadata["type_inference_keyword"] == "api key"


def test_mermaid_extractor_keeps_ambiguous_type_as_component(tmp_path: Path) -> None:
    markdown = tmp_path / "architecture.md"
    markdown.write_text(
        "\n".join(
            [
                "```mermaid",
                "flowchart LR",
                '  A["Customer DB"] --> B["Service"]',
                "```",
            ]
        ),
        encoding="utf-8",
    )

    model = extract_mermaid_markdown(markdown)
    ambiguous = next(node for node in model.nodes if node.name == "Customer DB")

    assert ambiguous.type == NodeType.COMPONENT
    assert "type_inferred_from" not in ambiguous.metadata


@pytest.mark.parametrize(
    ("keyword", "expected_type"),
    [
        ("user", NodeType.ACTOR),
        ("client", NodeType.ACTOR),
        ("customer", NodeType.ACTOR),
        ("db", NodeType.DATABASE),
        ("database", NodeType.DATABASE),
        ("postgres", NodeType.DATABASE),
        ("mysql", NodeType.DATABASE),
        ("rds", NodeType.DATABASE),
        ("bucket", NodeType.DATA_ASSET),
        ("storage", NodeType.DATA_ASSET),
        ("object store", NodeType.DATA_ASSET),
        ("s3", NodeType.DATA_ASSET),
        ("external", NodeType.EXTERNAL_SERVICE),
        ("third party", NodeType.EXTERNAL_SERVICE),
        ("partner", NodeType.EXTERNAL_SERVICE),
        ("secret", NodeType.SECRET),
        ("token", NodeType.SECRET),
        ("api key", NodeType.SECRET),
        ("credential", NodeType.SECRET),
    ],
)
def test_mermaid_extractor_infers_each_supported_type_keyword(
    tmp_path: Path,
    keyword: str,
    expected_type: NodeType,
) -> None:
    markdown = tmp_path / "architecture.md"
    label = f"{keyword} node"
    markdown.write_text(
        "\n".join(
            [
                "```mermaid",
                "flowchart LR",
                f'  A["{label}"] --> B["Service"]',
                "```",
            ]
        ),
        encoding="utf-8",
    )

    model = extract_mermaid_markdown(markdown)
    inferred = next(node for node in model.nodes if node.name == label)

    assert inferred.type == expected_type
    assert inferred.metadata["type_inferred_from"] == "mermaid_label"
    assert inferred.metadata["type_inference_keyword"] == keyword
