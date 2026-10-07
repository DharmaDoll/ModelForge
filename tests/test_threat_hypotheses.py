"""Review-only threat hypothesis schema and model-bound reference checks."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.llm.hypotheses import (
    ThreatHypothesisBatch,
    model_sha256,
    read_threat_hypotheses,
    threat_hypothesis_json_schema,
    validate_hypotheses_against_model,
)
from threatmodel_ai.model.schema import Evidence, Node, NodeType, SourceType, SystemModel
from threatmodel_ai.model.schema_v02 import NodeV02, SystemModelV02

RUNNER = CliRunner()


def _model(*, derived: bool = False) -> SystemModel:
    return SystemModel(
        id="service",
        nodes=[
            Node(
                id="api:payments",
                name="Payments API",
                type=NodeType.API,
                evidence=[
                    Evidence(
                        source_type=SourceType.DERIVED if derived else SourceType.OPENAPI,
                        source_path="openapi.yaml",
                        detail="POST /payments",
                    )
                ],
            )
        ],
    )


def _payload(model: SystemModel | SystemModelV02) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "model_id": model.id,
        "model_schema_version": model.schema_version,
        "model_sha256": model_sha256(model),
        "not_source_of_truth": True,
        "hypotheses": [
            {
                "id": "hypothesis:payments-replay",
                "status": "proposed",
                "title": "Payment request replay",
                "conditional_scenario": (
                    "If replay protection is absent, repeated payment requests may be accepted."
                ),
                "affected_element_ids": ["api:payments"],
                "established_prerequisites": [
                    {
                        "statement": "A payment API endpoint exists.",
                        "citations": [{"element_id": "api:payments", "evidence_index": 0}],
                    }
                ],
                "assumptions": ["A caller can repeat the request."],
                "missing_facts": ["Is replay protection implemented?"],
                "verification_steps": ["Ask the developer how duplicate requests are handled."],
                "provenance": {
                    "origin": "llm",
                    "model_name": "test-model",
                    "prompt_version": "v1",
                },
            }
        ],
    }


def _validated(payload: dict[str, object], model: SystemModel | SystemModelV02) -> None:
    validate_hypotheses_against_model(ThreatHypothesisBatch.model_validate(payload), model)


def test_review_only_hypothesis_cites_exact_model_snapshot(tmp_path: Path) -> None:
    model = _model()
    path = tmp_path / "threat_hypotheses.json"
    path.write_text(json.dumps(_payload(model)), encoding="utf-8")

    batch = read_threat_hypotheses(path, model=model)

    assert batch.hypotheses[0].status == "proposed"
    assert batch.hypotheses[0].missing_facts
    assert batch.not_source_of_truth is True
    assert model.nodes[0].name == "Payments API"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda p: p.update(model_id="other"), "different system model"),
        (lambda p: p.update(model_sha256="0" * 64), "different model snapshot"),
        (
            lambda p: p["hypotheses"][0].update(affected_element_ids=["missing"]),
            "missing affected element",
        ),
        (
            lambda p: p["hypotheses"][0]["established_prerequisites"][0]["citations"][0].update(
                element_id="missing"
            ),
            "cites a missing element",
        ),
        (
            lambda p: p["hypotheses"][0]["established_prerequisites"][0]["citations"][0].update(
                evidence_index=1
            ),
            "missing Evidence",
        ),
    ],
)
def test_rejects_stale_or_nonexistent_model_references(change, message: str) -> None:
    model = _model()
    payload = deepcopy(_payload(model))
    change(payload)

    with pytest.raises(ValueError, match=message):
        _validated(payload, model)


def test_rejects_derived_only_evidence() -> None:
    model = _model(derived=True)

    with pytest.raises(ValueError, match="derived-only Evidence"):
        _validated(_payload(model), model)


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["hypotheses"].append(deepcopy(p["hypotheses"][0])),
        lambda p: p["hypotheses"][0].update(status="confirmed"),
        lambda p: p.update(not_source_of_truth=False),
        lambda p: p["hypotheses"][0].update(invented_component="secret-store"),
        lambda p: p["hypotheses"][0]["established_prerequisites"][0].update(citations=[]),
    ],
)
def test_rejects_duplicate_authoritative_or_uncited_candidates(change) -> None:
    payload = deepcopy(_payload(_model()))
    change(payload)

    with pytest.raises(ValidationError):
        ThreatHypothesisBatch.model_validate(payload)


def test_v02_attribute_citation_must_exist_on_exact_element() -> None:
    direct = Evidence(
        source_type=SourceType.OPENAPI,
        source_path="openapi.yaml",
        detail="POST /payments",
    )
    model = SystemModelV02(
        id="service",
        nodes=[
            NodeV02(
                id="api:payments",
                name="Payments API",
                type=NodeType.API,
                evidence=[direct],
                attribute_evidence={"/type": [direct]},
            )
        ],
    )
    payload = _payload(model)
    citation = payload["hypotheses"][0]["established_prerequisites"][0]["citations"][0]
    citation["attribute_path"] = "/type"

    _validated(payload, model)
    citation["attribute_path"] = "/authentication"
    with pytest.raises(ValueError, match="missing Evidence"):
        _validated(payload, model)


def test_cli_validates_read_only_and_exports_structural_schema(tmp_path: Path) -> None:
    model = _model()
    model_path = tmp_path / "model.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    hypotheses_path = tmp_path / "hypotheses.json"
    hypotheses_path.write_text(json.dumps(_payload(model)), encoding="utf-8")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    result = RUNNER.invoke(
        app, ["hypotheses", "validate", str(hypotheses_path), "--model", str(model_path)]
    )

    assert result.exit_code == 0, result.output
    assert "review-only hypotheses: 1 candidate" in result.output
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    schema_path = tmp_path / "schema.json"
    schema_result = RUNNER.invoke(app, ["hypotheses", "schema", "--out", str(schema_path)])
    assert schema_result.exit_code == 0, schema_result.output
    assert json.loads(schema_path.read_text(encoding="utf-8")) == (threat_hypothesis_json_schema())
    assert RUNNER.invoke(app, ["hypotheses", "schema", "--out", str(schema_path)]).exit_code == 1


def test_cli_rejects_stale_artifact_without_echoing_hypothesis_text(tmp_path: Path) -> None:
    model = _model()
    model_path = tmp_path / "model.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    payload = _payload(model)
    payload["model_sha256"] = "0" * 64
    path = tmp_path / "hypotheses.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = RUNNER.invoke(app, ["hypotheses", "validate", str(path), "--model", str(model_path)])

    assert result.exit_code == 1
    assert "different model snapshot" in result.output
    assert "Payment request replay" not in result.output
