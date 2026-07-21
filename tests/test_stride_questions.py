from pathlib import Path

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel
from threatmodel_ai.pipeline import analyze_project
from threatmodel_ai.questions import generate_questions
from threatmodel_ai.stride import StrideCategory, generate_threats

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


def test_stride_engine_generates_all_entrypoint_categories(tmp_path: Path) -> None:
    model = analyze_project(discover_inputs(FIXTURE), tmp_path).model

    threats = generate_threats(model)
    categories = {threat.category for threat in threats}

    assert StrideCategory.SPOOFING in categories
    assert StrideCategory.TAMPERING in categories
    assert StrideCategory.REPUDIATION in categories
    assert StrideCategory.INFORMATION_DISCLOSURE in categories
    assert StrideCategory.DENIAL_OF_SERVICE in categories
    assert StrideCategory.ELEVATION_OF_PRIVILEGE in categories
    assert all(threat.derived_from for threat in threats)
    assert all(threat.evidence for threat in threats)


def test_question_generator_turns_unknowns_into_review_questions(tmp_path: Path) -> None:
    model = analyze_project(discover_inputs(FIXTURE), tmp_path).model

    questions = generate_questions(model)

    assert any(question.category == "authorization" for question in questions)
    assert any(question.category == "data_classification" for question in questions)
    assert any("rate limits" in question.question.lower() for question in questions)
    assert all(question.derived_from for question in questions)
    assert all(question.evidence for question in questions)


def test_question_generator_asks_for_unknown_entrypoint_boundary() -> None:
    model = SystemModel(
        nodes=[
            Node(id="actor:user", name="User", type=NodeType.ACTOR),
            Node(id="api:orders", name="Orders API", type=NodeType.API),
        ],
        edges=[
            Edge(
                id="edge:user-orders",
                source="actor:user",
                target="api:orders",
                type=EdgeType.COMMUNICATES_WITH,
            )
        ],
    )

    questions = generate_questions(model)
    boundary_questions = [
        question for question in questions if question.category == "trust_boundary"
    ]

    assert len(boundary_questions) == 1
    assert boundary_questions[0].question == "Which trust boundary contains Orders API?"
    assert boundary_questions[0].related_elements == [
        "edge:user-orders",
        "actor:user",
        "api:orders",
    ]


def test_stride_tampering_scenario_mentions_boundary_crossing() -> None:
    model = SystemModel(
        nodes=[
            Node(id="actor:user", name="User", type=NodeType.ACTOR),
            Node(
                id="boundary:private",
                name="Private Zone",
                type=NodeType.TRUST_BOUNDARY,
            ),
            Node(
                id="api:orders",
                name="Orders API",
                type=NodeType.API,
                trust_boundary_id="boundary:private",
            ),
        ],
        edges=[
            Edge(
                id="edge:user-orders",
                source="actor:user",
                target="api:orders",
                type=EdgeType.COMMUNICATES_WITH,
            )
        ],
    )

    tampering = next(
        threat
        for threat in generate_threats(model)
        if threat.category == StrideCategory.TAMPERING
    )

    assert tampering.confidence == "high"
    assert "crosses a trust boundary" in tampering.scenario
