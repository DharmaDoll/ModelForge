"""Read-only, evidence-backed cross-source identity suggestions."""

from threatmodel_ai.dfd import render_mermaid
from threatmodel_ai.model.identity import find_possible_identities
from threatmodel_ai.model.schema import Evidence, Node, NodeType, SourceType, SystemModel
from threatmodel_ai.report import render_review_markdown


def _node(
    node_id: str,
    source_type: SourceType,
    source_path: str,
    *,
    name: str = "Payments API",
    node_type: NodeType = NodeType.COMPONENT,
) -> Node:
    return Node(
        id=node_id,
        name=name,
        type=node_type,
        evidence=[
            Evidence(
                source_type=source_type,
                source_path=source_path,
                extractor=source_type.value,
            )
        ],
    )


def test_exact_cross_source_pair_is_review_only_and_paths_are_compact() -> None:
    model = SystemModel(
        nodes=[
            _node("node:readme", SourceType.README, "/private/alice/docs/README.md"),
            _node("node:openapi", SourceType.OPENAPI, "/private/alice/api/openapi.yaml"),
        ]
    )
    original = model.model_dump(mode="json")
    dfd_before = render_mermaid(model)

    groups = find_possible_identities(model)
    review = render_review_markdown(model, [], [], [], [])

    assert len(groups) == 1
    assert not groups[0].ambiguous
    assert {member.id for member in groups[0].members} == {
        "node:readme", "node:openapi"
    }
    assert "possible pair" in review
    assert "readme:README.md" in review
    assert "openapi:openapi.yaml" in review
    assert "/private/alice" not in review
    assert "no nodes, flows, or reviewer decisions were merged" in review
    assert model.model_dump(mode="json") == original
    assert render_mermaid(model) == dfd_before


def test_three_candidates_are_ambiguous_and_type_difference_is_visible() -> None:
    model = SystemModel(
        nodes=[
            _node("node:readme", SourceType.README, "README.md"),
            _node("node:openapi", SourceType.OPENAPI, "openapi.yaml"),
            _node(
                "node:terraform",
                SourceType.TERRAFORM,
                "main.tf",
                node_type=NodeType.API,
            ),
        ]
    )

    groups = find_possible_identities(model)
    review = render_review_markdown(model, [], [], [], [])

    assert len(groups) == 1
    assert groups[0].ambiguous
    assert len(groups[0].members) == 3
    assert "ambiguous (3 separate nodes; node types differ)" in review


def test_same_document_and_synthetic_only_names_are_not_suggested() -> None:
    model = SystemModel(
        nodes=[
            _node("node:a", SourceType.README, "README.md"),
            _node("node:b", SourceType.MARKDOWN, "README.md"),
            _node("node:c", SourceType.DERIVED, "derived"),
            _node("node:unknown-a", SourceType.README, "one.md", name="unknown"),
            _node("node:unknown-b", SourceType.OPENAPI, "two.yaml", name="Unknown"),
        ]
    )

    assert not find_possible_identities(model)
