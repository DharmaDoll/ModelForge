import pytest
from pydantic import ValidationError

from threatmodel_ai.attack.models import AttackFinding, AttackTechnique
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel, Unknown
from threatmodel_ai.questions import Question
from threatmodel_ai.report import (
    render_attack_markdown,
    render_questions_markdown,
    render_threats_markdown,
)
from threatmodel_ai.stride import StrideCategory, Threat


def test_system_model_rejects_edges_with_missing_nodes() -> None:
    with pytest.raises(ValidationError):
        SystemModel(
            nodes=[Node(id="actor:user", name="User", type=NodeType.ACTOR)],
            edges=[
                Edge(
                    id="edge:missing",
                    source="actor:user",
                    target="api:missing",
                    type=EdgeType.COMMUNICATES_WITH,
                )
            ],
        )


def test_system_model_rejects_duplicate_graph_ids() -> None:
    with pytest.raises(ValidationError, match="duplicate node ids"):
        SystemModel(
            nodes=[
                Node(id="actor:user", name="User", type=NodeType.ACTOR),
                Node(id="actor:user", name="Duplicate User", type=NodeType.ACTOR),
            ]
        )

    with pytest.raises(ValidationError, match="duplicate edge ids"):
        SystemModel(
            nodes=[
                Node(id="actor:user", name="User", type=NodeType.ACTOR),
                Node(id="api:orders", name="Orders API", type=NodeType.API),
            ],
            edges=[
                Edge(
                    id="edge:user-api",
                    source="actor:user",
                    target="api:orders",
                    type=EdgeType.COMMUNICATES_WITH,
                ),
                Edge(
                    id="edge:user-api",
                    source="actor:user",
                    target="api:orders",
                    type=EdgeType.COMMUNICATES_WITH,
                ),
            ],
        )

    with pytest.raises(ValidationError, match="duplicate unknown ids"):
        SystemModel(
            unknowns=[
                Unknown(id="unknown:auth", category="authentication", description="Auth unknown."),
                Unknown(id="unknown:auth", category="authentication", description="Auth unknown."),
            ]
        )


def test_system_model_rejects_missing_related_references() -> None:
    with pytest.raises(ValidationError, match="missing trust boundary"):
        SystemModel(
            nodes=[
                Node(
                    id="api:orders",
                    name="Orders API",
                    type=NodeType.API,
                    trust_boundary_id="boundary:missing",
                )
            ]
        )

    with pytest.raises(ValidationError, match="missing data assets"):
        SystemModel(
            nodes=[
                Node(id="actor:user", name="User", type=NodeType.ACTOR),
                Node(id="api:orders", name="Orders API", type=NodeType.API),
            ],
            edges=[
                Edge(
                    id="edge:user-api",
                    source="actor:user",
                    target="api:orders",
                    type=EdgeType.COMMUNICATES_WITH,
                    data_assets=["data:missing"],
                )
            ],
        )

    with pytest.raises(ValidationError, match="references missing element"):
        SystemModel(
            unknowns=[
                Unknown(
                    id="unknown:auth",
                    category="authentication",
                    description="Authentication is unknown.",
                    related_element_id="edge:missing",
                )
            ]
        )


def test_model_required_fields_reject_blank_values() -> None:
    with pytest.raises(ValidationError):
        Node(id="", name="User", type=NodeType.ACTOR)

    with pytest.raises(ValidationError):
        Edge(
            id="edge:user-api",
            source="",
            target="api:orders",
            type=EdgeType.COMMUNICATES_WITH,
        )

    with pytest.raises(ValidationError):
        SystemModel(id="")


def test_system_model_json_schema_exposes_graph_fields() -> None:
    schema = SystemModel.model_json_schema()

    assert "nodes" in schema["properties"]
    assert "edges" in schema["properties"]
    assert "unknowns" in schema["properties"]


def test_markdown_reports_are_reviewable() -> None:
    attack = AttackFinding(
        id="attack:1",
        rule_id="attack-rule",
        technique=AttackTechnique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactics=["Initial Access"],
            url="https://attack.mitre.org/techniques/T1190/",
        ),
        title="Public-facing application technique candidate",
        scenario="Scenario",
        detection="Detection",
        mitigation="Mitigation",
        affected_elements=["edge:1"],
    )
    threat = Threat(
        id="threat:1",
        rule_id="rule",
        category=StrideCategory.SPOOFING,
        title="Spoofing risk",
        scenario="Scenario",
        impact="Impact",
        mitigation="Mitigation",
        affected_elements=["edge:1"],
    )
    question = Question(
        id="question:1",
        category="authentication",
        question="How is the API authenticated?",
        rationale="Authentication is unknown.",
        related_elements=["edge:1"],
    )

    attack_md = render_attack_markdown([attack])
    threats_md = render_threats_markdown([threat])
    questions_md = render_questions_markdown([question])

    assert "MITRE ATT&CK Technique Candidates" in attack_md
    assert "T1190 Exploit Public-Facing Application" in attack_md
    assert "Detection: Detection" in attack_md
    assert "| `threat:1` | Spoofing | Spoofing risk | medium |" in threats_md
    assert "Mitigation: Mitigation" in threats_md
    assert "| `question:1` | authentication | How is the API authenticated? |" in questions_md
    assert "Rationale: Authentication is unknown." in questions_md
