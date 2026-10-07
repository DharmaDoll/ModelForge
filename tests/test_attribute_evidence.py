"""Strict 0.2 evidence audit complements legacy-compatible model validation."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.model.io import write_system_model
from threatmodel_ai.model.migration import migrate_system_model
from threatmodel_ai.model.schema import EdgeType, Evidence, NodeType, SourceType
from threatmodel_ai.model.schema_v02 import (
    EdgeV02,
    EvidenceGap,
    Inference,
    ModelReference,
    NodeV02,
    SystemModelV02,
    audit_attribute_evidence,
)


def _evidence() -> Evidence:
    return Evidence(source_type=SourceType.README, source_path="README.md", extractor="test")


def test_audit_reports_known_claims_without_attribute_evidence() -> None:
    evidence = _evidence()
    model = SystemModelV02(
        name="Service",
        nodes=[
            NodeV02(id="actor", name="Client", type=NodeType.ACTOR),
            NodeV02(
                id="api",
                name="API",
                type=NodeType.API,
                metadata={"internet_exposed": False},
                evidence=[evidence],
                attribute_evidence={"/type": [evidence]},
            ),
        ],
        edges=[
            EdgeV02(
                id="request",
                source="actor",
                target="api",
                type=EdgeType.COMMUNICATES_WITH,
                authentication="none",
                evidence=[evidence],
            )
        ],
    )

    assert audit_attribute_evidence(model) == [
        EvidenceGap("actor", "/evidence"),
        EvidenceGap("actor", "/type"),
        EvidenceGap("api", "/metadata/internet_exposed"),
        EvidenceGap("request", "/authentication"),
        EvidenceGap("system", "/evidence"),
    ]


def test_audit_accepts_direct_evidence_and_ignores_unknown_values(tmp_path: Path) -> None:
    evidence = _evidence()
    model = SystemModelV02(
        evidence=[evidence],
        name="Service",
        nodes=[
            NodeV02(
                id="actor",
                name="Client",
                type=NodeType.ACTOR,
                evidence=[evidence],
                attribute_evidence={"/type": [evidence]},
            ),
            NodeV02(
                id="api",
                name="API",
                type=NodeType.API,
                evidence=[evidence],
                attribute_evidence={"/type": [evidence]},
            ),
        ],
        edges=[
            EdgeV02(
                id="request",
                source="actor",
                target="api",
                type=EdgeType.COMMUNICATES_WITH,
                protocol="HTTPS",
                authentication="none",
                evidence=[evidence],
                attribute_evidence={
                    "/protocol": [evidence],
                    "/authentication": [evidence],
                },
            )
        ],
    )
    assert audit_attribute_evidence(model) == []

    path = tmp_path / "model.json"
    write_system_model(model, path)
    result = CliRunner().invoke(
        app, ["model", "validate", str(path), "--require-attribute-evidence"]
    )
    assert result.exit_code == 0, result.output
    assert "Attribute evidence check passed" in result.output


def test_cli_strict_evidence_is_opt_in_and_requires_v02(tmp_path: Path) -> None:
    runner = CliRunner()
    model = SystemModelV02(nodes=[NodeV02(id="api", name="API", type=NodeType.API)])
    path = tmp_path / "model.json"
    write_system_model(model, path)

    assert runner.invoke(app, ["model", "validate", str(path)]).exit_code == 0
    strict = runner.invoke(
        app, ["model", "validate", str(path), "--require-attribute-evidence"]
    )
    assert strict.exit_code == 1
    assert "Attribute evidence check failed" in strict.output
    assert "api /evidence" in strict.output
    assert "api /type" in strict.output

    legacy = tmp_path / "legacy.json"
    legacy.write_text('{"schema_version":"0.1"}', encoding="utf-8")
    old = runner.invoke(
        app, ["model", "validate", str(legacy), "--require-attribute-evidence"]
    )
    assert old.exit_code == 1
    assert "requires a 0.2 model" in old.output


def test_migrated_legacy_claims_need_review_before_strict_evidence_passes(
    tmp_path: Path,
) -> None:
    legacy = {
        "schema_version": "0.1",
        "nodes": [
            {
                "id": "api",
                "name": "API",
                "type": "api",
                "evidence": [_evidence().model_dump(mode="json")],
            }
        ],
    }
    path = tmp_path / "migrated.json"
    path.write_text(json.dumps(migrate_system_model(legacy)), encoding="utf-8")
    runner = CliRunner()

    assert runner.invoke(app, ["model", "validate", str(path)]).exit_code == 0
    strict = runner.invoke(
        app, ["model", "validate", str(path), "--require-attribute-evidence"]
    )
    assert strict.exit_code == 1
    assert "api /type" in strict.output


@pytest.mark.parametrize("basis_path", ["/name", "/metadata/mermaid_alias"])
def test_strict_audit_requires_direct_evidence_for_inference_basis(
    basis_path: str, tmp_path: Path
) -> None:
    evidence = _evidence()
    inference = Inference(
        id="inference:db-type",
        subject_id="node:db",
        predicate="/type",
        value="database",
        based_on=[ModelReference(element_id="node:db", path=basis_path)],
        rule_id="mermaid-label-type-v1",
        confidence=0.7,
        provenance_class="deterministic",
        evidence=[evidence],
    )
    node = NodeV02(
        id="node:db",
        name="Orders DB",
        type=NodeType.UNKNOWN,
        metadata={"mermaid_alias": "Db"},
        evidence=[evidence],
    )
    model = SystemModelV02(nodes=[node], inferences=[inference])

    assert audit_attribute_evidence(model) == [EvidenceGap("node:db", basis_path)]
    path = tmp_path / "model.json"
    write_system_model(model, path)
    strict = CliRunner().invoke(
        app, ["model", "validate", str(path), "--require-attribute-evidence"]
    )
    assert strict.exit_code == 1
    assert f"node:db {basis_path}" in strict.output

    reviewed = SystemModelV02(
        nodes=[node.model_copy(update={"attribute_evidence": {basis_path: [evidence]}})],
        inferences=[inference],
    )
    assert audit_attribute_evidence(reviewed) == []
    write_system_model(reviewed, path)
    accepted = CliRunner().invoke(
        app, ["model", "validate", str(path), "--require-attribute-evidence"]
    )
    assert accepted.exit_code == 0, accepted.output


def test_derived_only_pointers_do_not_pass_direct_evidence_audit() -> None:
    derived = Evidence(
        source_type=SourceType.DERIVED,
        source_path="legacy-system-model",
        extractor="migration-0.1-to-0.2",
    )
    model = SystemModelV02(
        name="Service",
        evidence=[derived],
        nodes=[
            NodeV02(
                id="api",
                name="API",
                type=NodeType.API,
                evidence=[derived],
                attribute_evidence={"/type": [derived]},
            )
        ],
    )

    assert audit_attribute_evidence(model) == [
        EvidenceGap("api", "/evidence"),
        EvidenceGap("api", "/type"),
        EvidenceGap("system", "/evidence"),
    ]
