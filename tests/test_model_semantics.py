"""Regression cases for conservative, evidence-backed model semantics."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from threatmodel_ai.attack import generate_attack_findings
from threatmodel_ai.extract import extract_readme, extract_terraform
from threatmodel_ai.model.merge import merge_system_models
from threatmodel_ai.model.schema import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SourceType,
    SystemModel,
)
from threatmodel_ai.questions import generate_questions
from threatmodel_ai.risk import score_risks


def _evidence(detail: str) -> Evidence:
    return Evidence(
        source_type=SourceType.README,
        source_path=f"{detail}.md",
        extractor="readme",
        detail=detail,
    )


def test_conflicting_claims_remain_unknown_after_third_input() -> None:
    models = [
        SystemModel(
            nodes=[
                Node(
                    id="service",
                    name="Service",
                    type=node_type,
                    metadata={"internet_exposed": exposed},
                    evidence=[_evidence(label)],
                )
            ]
        )
        for label, node_type, exposed in [
            ("first", NodeType.API, True),
            ("second", NodeType.DATABASE, False),
            ("third", NodeType.API, True),
        ]
    ]

    merged = merge_system_models(models)

    assert merged.nodes[0].type == NodeType.UNKNOWN
    assert "internet_exposed" not in merged.nodes[0].metadata
    conflicts = [unknown for unknown in merged.unknowns if unknown.category == "model_conflict"]
    assert len(conflicts) == 2
    assert {unknown.evidence.source_path for unknown in conflicts if unknown.evidence} == {
        "first.md"
    }
    assert all(len(unknown.conflicting_evidence or []) == 2 for unknown in conflicts)
    assert any(
        "Which conflicting source claim is correct" in question.question
        for question in generate_questions(merged)
    )


def test_conflicting_edge_control_remains_unknown_after_third_input() -> None:
    nodes = [
        Node(id="actor", name="Internet", type=NodeType.ACTOR),
        Node(id="api", name="API", type=NodeType.API),
    ]
    models = [
        SystemModel(
            nodes=nodes,
            edges=[
                Edge(
                    id="edge",
                    source="actor",
                    target="api",
                    type=EdgeType.COMMUNICATES_WITH,
                    authentication=auth,
                    evidence=[_evidence(label)],
                )
            ],
        )
        for label, auth in [("first", "none"), ("second", "basic"), ("third", "none")]
    ]

    merged = merge_system_models(models)

    assert merged.edges[0].authentication == "unknown"
    assert any(unknown.category == "model_conflict" for unknown in merged.unknowns)


def test_same_element_id_with_different_names_is_not_silently_deduplicated() -> None:
    models = [
        SystemModel(
            nodes=[
                Node(
                    id="component:mermaid:a",
                    name=name,
                    type=NodeType.COMPONENT,
                    evidence=[_evidence(name)],
                )
            ]
        )
        for name in ("Orders API", "Billing API")
    ]

    merged = merge_system_models(models)

    assert merged.nodes[0].name == "unknown"
    assert any(
        unknown.category == "model_conflict" and "field name" in unknown.description
        for unknown in merged.unknowns
    )


def test_conflicting_exposure_removes_derived_public_access() -> None:
    exposed = SystemModel(
        nodes=[
            Node(
                id="actor",
                name="Internet",
                type=NodeType.ACTOR,
                metadata={"derived_from": "terraform_exposure"},
            ),
            Node(
                id="api",
                name="API",
                type=NodeType.API,
                metadata={"internet_exposed": True},
                evidence=[_evidence("public")],
            ),
        ],
        edges=[
            Edge(
                id="public-access",
                source="actor",
                target="api",
                type=EdgeType.COMMUNICATES_WITH,
                metadata={"derived_from": "terraform_exposure"},
            )
        ],
    )
    private = SystemModel(
        nodes=[
            Node(
                id="api",
                name="API",
                type=NodeType.API,
                metadata={"internet_exposed": False},
                evidence=[_evidence("private")],
            )
        ]
    )

    merged = merge_system_models([exposed, private])

    assert [node.id for node in merged.nodes] == ["api"]
    assert not merged.edges
    assert any(unknown.category == "model_conflict" for unknown in merged.unknowns)


def test_terraform_comments_and_dependencies_do_not_create_runtime_flow(
    tmp_path: Path,
) -> None:
    terraform = tmp_path / "main.tf"
    terraform.write_text(
        "\n".join(
            [
                '/* resource "aws_lb" "ghost" { internal = false } */',
                'resource "aws_db_instance" "db" {}',
                'resource "aws_lb" "private" {',
                "  internal = true # internal = false",
                "  depends_on = [aws_db_instance.db]",
                "  /* publicly_accessible = true */",
                "}",
                'resource "aws_lb" "public" {',
                "  internal = false",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    model = extract_terraform((terraform,))

    assert not any(node.name.endswith("ghost") for node in model.nodes)
    private = next(node for node in model.nodes if node.name == "aws_lb.private")
    public = next(node for node in model.nodes if node.name == "aws_lb.public")
    assert private.metadata.get("internet_exposed") is not True
    assert public.metadata["internet_exposed"] is True
    assert any(edge.type == EdgeType.REFERENCES for edge in model.edges)
    assert not any(edge.type == EdgeType.STORES for edge in model.edges)
    risks = score_risks(model, [], [])
    assert all("private" not in risk.title for risk in risks)


def test_negated_readme_control_remains_unknown(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Service\n\nNo rate limiting or authentication is configured.\n",
        encoding="utf-8",
    )

    model = extract_readme(readme)

    assert model.metadata["mentions_rate_limiting"] is False
    assert model.metadata["mentions_authentication"] is False
    assert {unknown.category for unknown in model.unknowns} >= {
        "rate_limiting",
        "authentication",
    }


def test_unknown_transport_does_not_imply_aitm_technique() -> None:
    model = SystemModel(
        nodes=[
            Node(id="actor", name="Internet", type=NodeType.ACTOR),
            Node(id="api", name="API", type=NodeType.API),
        ],
        edges=[
            Edge(
                id="edge",
                source="actor",
                target="api",
                type=EdgeType.COMMUNICATES_WITH,
                protocol="unknown",
            )
        ],
    )

    assert "T1557" not in {finding.technique.id for finding in generate_attack_findings(model)}


def test_reference_edge_does_not_become_entrypoint_question() -> None:
    model = SystemModel(
        nodes=[
            Node(id="actor", name="Internet", type=NodeType.ACTOR),
            Node(id="api", name="API", type=NodeType.API),
        ],
        edges=[Edge(id="reference", source="actor", target="api", type=EdgeType.REFERENCES)],
    )

    assert not generate_questions(model)


def test_unknown_controls_alone_do_not_create_review_priority() -> None:
    model = SystemModel(
        nodes=[
            Node(id="actor", name="Internal User", type=NodeType.ACTOR),
            Node(id="api", name="API", type=NodeType.API),
        ],
        edges=[
            Edge(
                id="flow",
                source="actor",
                target="api",
                type=EdgeType.COMMUNICATES_WITH,
            )
        ],
    )

    assert not score_risks(model, [], [])
    assert generate_questions(model)


def test_unsupported_system_model_version_fails_closed() -> None:
    with pytest.raises(ValidationError):
        SystemModel.model_validate({"schema_version": "0.2"})
