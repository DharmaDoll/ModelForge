from pathlib import Path

from threatmodel_ai.attack import generate_attack_findings
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.schema import Node, NodeType, SystemModel
from threatmodel_ai.pipeline import analyze_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


def test_attack_engine_generates_topology_based_techniques(tmp_path: Path) -> None:
    model = analyze_project(discover_inputs(FIXTURE), tmp_path).model

    findings = generate_attack_findings(model)
    technique_ids = {finding.technique.id for finding in findings}

    assert "T1190" in technique_ids
    assert "T1499" in technique_ids
    assert "T1110" in technique_ids
    assert "T1078" in technique_ids
    assert "T1557" in technique_ids
    assert "T1565" in technique_ids
    assert all(finding.affected_elements for finding in findings)
    assert all(finding.derived_from for finding in findings)
    assert all(finding.evidence for finding in findings)


def test_attack_engine_maps_secret_nodes_to_unsecured_credentials() -> None:
    model = SystemModel(
        nodes=[
            Node(
                id="secret:api-key",
                name="API Key",
                type=NodeType.SECRET,
            )
        ]
    )

    findings = generate_attack_findings(model)

    assert [finding.technique.id for finding in findings] == ["T1552"]
