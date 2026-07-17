import pytest
from pydantic import ValidationError

from threatmodel_ai.attack.models import AttackFinding, AttackTechnique
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel
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
