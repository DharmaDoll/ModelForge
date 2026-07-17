from threatmodel_ai.attack.models import AttackFinding, AttackTechnique
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel
from threatmodel_ai.risk import RiskRating, score_risks
from threatmodel_ai.stride import StrideCategory, Threat


def test_risk_scoring_prioritizes_public_unknown_entrypoints() -> None:
    model = SystemModel(
        nodes=[
            Node(id="actor:internet", name="Internet", type=NodeType.ACTOR),
            Node(id="api:payments", name="Payments API", type=NodeType.API),
            Node(id="data:payment", name="Payment", type=NodeType.DATA_ASSET),
        ],
        edges=[
            Edge(
                id="edge:internet-payments",
                source="actor:internet",
                target="api:payments",
                type=EdgeType.COMMUNICATES_WITH,
                protocol="unknown",
                authentication="unknown",
                authorization="unknown",
                data_assets=["data:payment"],
            )
        ],
    )
    threat = Threat(
        id="threat:spoofing",
        rule_id="entrypoint-spoofing",
        category=StrideCategory.SPOOFING,
        title="Spoofing risk",
        scenario="Scenario",
        impact="Impact",
        mitigation="Mitigation",
        affected_elements=["edge:internet-payments"],
    )
    attack = AttackFinding(
        id="attack:t1190",
        rule_id="attack-public-entrypoint",
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
        affected_elements=["edge:internet-payments"],
    )

    risks = score_risks(model, [threat], [attack])

    assert len(risks) == 1
    assert risks[0].rating == RiskRating.HIGH
    assert risks[0].score >= 7
    assert "threat:spoofing" in risks[0].related_threats
    assert "attack:t1190" in risks[0].related_attack_findings
    assert any("Authentication is unknown" in item for item in risks[0].rationale)
    assert any("Data classification is unknown" in item for item in risks[0].rationale)


def test_risk_scoring_scores_storage_paths_without_inventing_classification() -> None:
    model = SystemModel(
        nodes=[
            Node(id="component:api", name="API", type=NodeType.COMPONENT),
            Node(id="database:payments", name="Payments DB", type=NodeType.DATABASE),
        ],
        edges=[
            Edge(
                id="edge:api-db",
                source="component:api",
                target="database:payments",
                type=EdgeType.STORES,
            )
        ],
    )

    risks = score_risks(model, [], [])

    assert len(risks) == 1
    assert risks[0].rating == RiskRating.MEDIUM
    assert any("Data classification is unknown" in item for item in risks[0].rationale)
