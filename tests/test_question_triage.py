"""Question triage changes presentation without merging model facts."""

from threatmodel_ai.model.schema import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SourceType,
    SystemModel,
)
from threatmodel_ai.questions.generator import Question
from threatmodel_ai.questions.triage import group_questions, starting_question_groups
from threatmodel_ai.report import render_questions_markdown, render_review_markdown
from threatmodel_ai.risk.models import RiskFinding, RiskRating


def _question(
    question_id: str,
    subject_id: str,
    *,
    category: str = "authentication",
    text: str = "How is this authenticated?",
    source: str = "README.md",
    related: list[str] | None = None,
) -> Question:
    return Question(
        id=question_id,
        category=category,
        question=text,
        rationale="The design does not specify this control.",
        related_elements=related if related is not None else [subject_id],
        derived_from=[subject_id],
        evidence=[Evidence(source_type=SourceType.README, source_path=source, extractor="readme")],
    )


def _model() -> SystemModel:
    return SystemModel(
        nodes=[
            Node(id="actor:user", name="User", type=NodeType.ACTOR),
            Node(id="api:one", name="Orders API", type=NodeType.API),
            Node(id="api:two", name="Billing API", type=NodeType.API),
        ],
        edges=[
            Edge(
                id="edge:one",
                source="actor:user",
                target="api:one",
                type=EdgeType.COMMUNICATES_WITH,
            ),
            Edge(
                id="edge:two",
                source="actor:user",
                target="api:two",
                type=EdgeType.COMMUNICATES_WITH,
            ),
        ],
    )


def test_grouping_preserves_all_evidence_and_separates_distinct_subjects() -> None:
    questions = [
        _question("q:readme", "edge:one", source="README.md"),
        _question(
            "q:openapi",
            "edge:one",
            text="How does Orders API authenticate User?",
            source="openapi.yaml",
        ),
        _question("q:other", "edge:two"),
        _question("q:authorization", "edge:one", category="authorization"),
        _question(
            "q:anonymous",
            "edge:one",
            text="Is unauthenticated access to Orders API intentional?",
        ),
    ]

    groups = group_questions(questions, _model())
    grouped_ids = [[question.id for question in group.questions] for group in groups]
    assert len(groups) == 4
    assert ["q:openapi", "q:readme"] in grouped_ids
    assert ["q:other"] in grouped_ids
    assert ["q:authorization"] in grouped_ids
    assert ["q:anonymous"] in grouped_ids
    assert groups == group_questions(list(reversed(questions)), _model())

    rendered = render_questions_markdown(questions, _model())
    assert "Total questions: 5" in rendered
    assert "Grouped review tasks: 4" in rendered
    assert "README.md" in rendered
    assert "openapi.yaml" in rendered
    for question in questions:
        assert rendered.count(f"- ID: `{question.id}`") == 1
    for group in groups:
        assert f'<a id="{group.anchor}"></a>' in rendered


def test_starting_queue_follows_direct_risk_subjects_and_keeps_links() -> None:
    model = _model()
    questions = [
        _question("q:one-auth", "edge:one", related=["edge:one", "actor:user", "api:one"]),
        _question("q:one-authz", "edge:one", category="authorization"),
        _question("q:two-auth", "edge:two", related=["edge:two", "actor:user", "api:two"]),
        _question("q:two-authz", "edge:two", category="authorization"),
        _question("q:unlinked", "api:one", category="logging"),
    ]
    risks = [
        RiskFinding(
            id="risk:one",
            title="One",
            rating=RiskRating.MEDIUM,
            score=4,
            affected_elements=["edge:one", "actor:user", "api:one"],
        ),
        RiskFinding(
            id="risk:two",
            title="Two",
            rating=RiskRating.LOW,
            score=2,
            affected_elements=["edge:two", "actor:user", "api:two"],
        ),
    ]
    groups = group_questions(questions, model)
    queue = starting_question_groups(groups, risks, limit=3)

    assert [group.subject_id for group in queue] == ["edge:one", "edge:two", "edge:one"]
    assert [group.category for group in queue] == [
        "authentication",
        "authentication",
        "authorization",
    ]
    review = render_review_markdown(model, [], [], risks, questions)
    detail = render_questions_markdown(questions, model)
    for group in queue:
        assert f"questions.md#{group.anchor}" in review
        assert f'<a id="{group.anchor}"></a>' in detail
