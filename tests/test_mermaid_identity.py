"""Mermaid identities must not collapse unrelated architecture elements."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.errors import InputFormatError
from threatmodel_ai.extract import extract_mermaid_markdown
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.identity import preview_legacy_mermaid_identities
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.io import read_system_model, write_system_model
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel
from threatmodel_ai.pipeline import analyze_project


def _write_diagram(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"```mermaid\nflowchart LR\n{body}\n```\n", encoding="utf-8")


def test_same_alias_in_separate_documents_has_distinct_ids(tmp_path: Path) -> None:
    first = tmp_path / "docs" / "orders.md"
    second = tmp_path / "docs" / "billing.md"
    _write_diagram(first, 'A["Orders API"] --> B["Orders DB"]')
    _write_diagram(second, 'A["Billing API"] --> B["Billing DB"]')

    model = analyze_project(discover_inputs(tmp_path), tmp_path / "out").model

    named = {node.name: node for node in model.nodes}
    assert named["Orders API"].id != named["Billing API"].id
    assert named["Orders DB"].id != named["Billing DB"].id
    assert len(model.edges) == 2
    assert (
        named["Orders API"].metadata["legacy_mermaid_id_suggestion"]
        == (named["Billing API"].metadata["legacy_mermaid_id_suggestion"])
    )


def test_same_alias_in_separate_diagrams_has_distinct_ids(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    doc.write_text(
        "\n".join(
            [
                "```mermaid",
                "flowchart LR",
                'A["Orders API"] --> B["Orders DB"]',
                "```",
                "```mermaid",
                "flowchart LR",
                'A["Billing API"] --> B["Billing DB"]',
                "```",
            ]
        ),
        encoding="utf-8",
    )

    model = extract_mermaid_markdown(doc)

    assert len(model.nodes) == 4
    assert len(model.edges) == 2


def test_project_relative_mermaid_ids_are_checkout_independent(tmp_path: Path) -> None:
    ids: list[set[str]] = []
    for directory in (tmp_path / "one", tmp_path / "two"):
        doc = directory / "docs" / "architecture.md"
        _write_diagram(doc, 'A["Orders API"] --> B["Orders DB"]')
        model = extract_mermaid_markdown(doc, identity_root=directory)
        ids.append({node.id for node in model.nodes} | {edge.id for edge in model.edges})

    assert ids[0] == ids[1]


def test_unrelated_mermaid_block_does_not_renumber_flowchart(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    _write_diagram(doc, 'A["Orders API"] --> B["Orders DB"]')
    before = extract_mermaid_markdown(doc)
    content = doc.read_text(encoding="utf-8")
    doc.write_text("```mermaid\nsequenceDiagram\nA->>B: hello\n```\n" + content, encoding="utf-8")

    after = extract_mermaid_markdown(doc)

    assert {node.id for node in before.nodes} == {node.id for node in after.nodes}


def test_alias_id_is_stable_when_type_inference_changes(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    _write_diagram(doc, 'A["Orders Service"] --> B["Store"]')
    before = extract_mermaid_markdown(doc)
    _write_diagram(doc, 'A["Orders DB"] --> B["Store"]')
    after = extract_mermaid_markdown(doc)

    before_a = next(node for node in before.nodes if node.metadata["mermaid_alias"] == "A")
    after_a = next(node for node in after.nodes if node.metadata["mermaid_alias"] == "A")
    assert before_a.id == after_a.id
    assert before_a.type == NodeType.COMPONENT
    assert after_a.type == NodeType.DATABASE


def test_distinct_labels_on_one_alias_fail_closed(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    _write_diagram(
        doc,
        "\n".join(
            [
                'A["Orders API"] --> B["Store"]',
                'A["Billing API"] --> C["Queue"]',
            ]
        ),
    )

    with pytest.raises(InputFormatError, match="Conflicting Mermaid labels"):
        extract_mermaid_markdown(doc)


def test_parallel_labeled_edges_are_not_collapsed(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    _write_diagram(
        doc,
        "\n".join(
            [
                'A["Client"] -->|HTTPS| B["API"]',
                "A -->|gRPC| B",
            ]
        ),
    )

    model = extract_mermaid_markdown(doc)

    assert len(model.edges) == 2
    assert {edge.protocol for edge in model.edges} == {"HTTPS", "gRPC"}


def test_identity_preview_suggests_unique_ids_but_never_ambiguous_ids(
    tmp_path: Path,
) -> None:
    first = tmp_path / "orders.md"
    second = tmp_path / "billing.md"
    _write_diagram(first, 'A["Orders API"] --> B["Orders DB"]')
    _write_diagram(second, 'A["Billing API"] --> B["Billing DB"]')
    legacy = _legacy_mermaid_model()
    first_model = extract_mermaid_markdown(first, identity_root=tmp_path)
    combined = analyze_project(discover_inputs(tmp_path), tmp_path / "out").model

    unique_preview = preview_legacy_mermaid_identities(legacy, first_model)
    ambiguous_preview = preview_legacy_mermaid_identities(legacy, combined)

    assert len(unique_preview.suggestions) == 3
    assert not unique_preview.ambiguous
    assert not ambiguous_preview.suggestions
    assert {item.kind for item in ambiguous_preview.ambiguous} == {"node", "edge"}
    assert all(len(item.current_ids) == 2 for item in ambiguous_preview.ambiguous)


def test_identity_preview_cli_writes_separate_read_only_report(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    _write_diagram(doc, 'A["Orders API"] --> B["Orders DB"]')
    legacy_path = tmp_path / "legacy.json"
    current_path = tmp_path / "current.json"
    preview_path = tmp_path / "identity-preview.json"
    write_system_model(_legacy_mermaid_model(), legacy_path)
    write_system_model(extract_mermaid_markdown(doc), current_path)

    result = CliRunner().invoke(
        app,
        [
            "model",
            "identity-preview",
            str(legacy_path),
            str(current_path),
            "--out",
            str(preview_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "3 unique suggestion(s); 0 ambiguous legacy ID(s)." in result.output
    assert preview_path.exists()
    assert read_system_model(legacy_path) == _legacy_mermaid_model()

    refused = CliRunner().invoke(
        app,
        [
            "model",
            "identity-preview",
            str(legacy_path),
            str(current_path),
            "--out",
            str(legacy_path),
        ],
    )
    assert refused.exit_code == 1
    assert "must not overwrite" in refused.output


def _legacy_mermaid_model() -> SystemModel:
    source_id = make_id("component", "mermaid", "A")
    target_id = make_id("database", "mermaid", "B")
    return SystemModel(
        nodes=[
            Node(id=source_id, name="Orders API", type=NodeType.COMPONENT),
            Node(id=target_id, name="Orders DB", type=NodeType.DATABASE),
        ],
        edges=[
            Edge(
                id=make_id("edge", source_id, target_id, "mermaid"),
                source=source_id,
                target=target_id,
                type=EdgeType.COMMUNICATES_WITH,
            )
        ],
    )
