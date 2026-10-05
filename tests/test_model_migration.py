"""0.1-to-0.2 compatibility and fact-versus-inference validation."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from threatmodel_ai.dfd import render_mermaid
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.migration import migrate_system_model
from threatmodel_ai.model.resolution import resolve_system_model_v02
from threatmodel_ai.model.schema import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SourceType,
    SystemModel,
    Unknown,
)
from threatmodel_ai.model.schema_v02 import (
    IdentityAlias,
    Inference,
    ModelReference,
    NodeV02,
    SystemModelV02,
)


def _evidence() -> Evidence:
    return Evidence(
        source_type=SourceType.MARKDOWN,
        source_path="docs/architecture.md",
        extractor="mermaid",
        detail="diagram 1",
        line=3,
    )


def _legacy_model() -> SystemModel:
    return SystemModel(
        name="Orders",
        nodes=[
            Node(
                id="mermaid:node:orders-db",
                name="Orders DB",
                type=NodeType.DATABASE,
                metadata={
                    "mermaid_alias": "Db",
                    "type_inferred_from": "mermaid_label",
                    "type_inference_keyword": "db",
                },
                evidence=[_evidence()],
            ),
            Node(
                id="component:readme:api",
                name="Orders API",
                type=NodeType.COMPONENT,
                evidence=[_evidence()],
            ),
        ],
        edges=[
            Edge(
                id="edge:api-db",
                source="component:readme:api",
                target="mermaid:node:orders-db",
                type=EdgeType.STORES,
                evidence=[_evidence()],
            )
        ],
        unknowns=[
            Unknown(
                id="unknown:auth",
                category="authentication",
                description="Authentication unknown.",
                related_element_id="component:readme:api",
                evidence=_evidence(),
            )
        ],
    )


def test_migration_moves_legacy_mermaid_type_to_inference_without_mutation() -> None:
    original = _legacy_model().model_dump(mode="json", exclude_none=True)
    snapshot = deepcopy(original)

    migrated = migrate_system_model(original)
    restored = SystemModelV02.model_validate(migrated)

    assert original == snapshot
    assert restored.schema_version == "0.2"
    database = next(node for node in restored.nodes if node.name == "Orders DB")
    assert database.type == NodeType.UNKNOWN
    assert "type_inferred_from" not in database.metadata
    assert restored.inferences[0].subject_id == database.id
    assert restored.inferences[0].predicate == "/type"
    assert restored.inferences[0].value == NodeType.DATABASE.value
    assert restored.inferences[0].based_on[0].path == "/name"
    assert any(unknown.id == "unknown:auth" for unknown in restored.unknowns)
    assert any(unknown.category == "migration_review" for unknown in restored.unknowns)
    migrated_snapshot = deepcopy(migrated)
    assert migrated == migrate_system_model(migrated)
    assert migrated == migrated_snapshot


def test_migration_rejects_missing_and_future_versions() -> None:
    with pytest.raises(ValueError, match="supported: 0.1, 0.2"):
        migrate_system_model({"nodes": []})
    with pytest.raises(ValueError, match="supported: 0.1, 0.2"):
        migrate_system_model({"schema_version": "0.3"})


def test_unrecognized_legacy_type_rule_becomes_unknown() -> None:
    legacy = SystemModel(
        nodes=[
            Node(
                id="node:guess",
                name="Guessed Database",
                type=NodeType.DATABASE,
                metadata={"type_inferred_from": "unrecognized_rule"},
                evidence=[_evidence()],
            )
        ]
    )

    migrated = SystemModelV02.model_validate(
        migrate_system_model(legacy.model_dump(mode="json", exclude_none=True))
    )

    assert migrated.nodes[0].type == NodeType.UNKNOWN
    assert not migrated.inferences
    assert any(unknown.category == "migration_review" for unknown in migrated.unknowns)


def test_resolved_view_preserves_legacy_dfd_without_rewriting_fact() -> None:
    legacy = _legacy_model()
    canonical = SystemModelV02.model_validate(
        migrate_system_model(legacy.model_dump(mode="json", exclude_none=True))
    )

    resolved = resolve_system_model_v02(canonical)

    assert render_mermaid(resolved.model) == render_mermaid(legacy)
    assert next(node for node in canonical.nodes if node.name == "Orders DB").type == (
        NodeType.UNKNOWN
    )
    assert next(node for node in resolved.model.nodes if node.name == "Orders DB").type == (
        NodeType.DATABASE
    )
    assert resolved.applied_inferences == {
        ("mermaid:node:orders-db", "/type"): (
            make_id("inference", "legacy-mermaid-type", "mermaid:node:orders-db"),
        )
    }


def test_sample_system_migrates_and_resolves_without_dfd_regression() -> None:
    legacy_path = (
        Path(__file__).parent / "fixtures" / "golden" / "sample-system" / "system_model.json"
    )
    payload = json.loads(legacy_path.read_text(encoding="utf-8"))
    legacy = SystemModel.model_validate(payload)

    canonical = SystemModelV02.model_validate(migrate_system_model(payload))
    resolved = resolve_system_model_v02(canonical)

    assert canonical.inferences
    assert render_mermaid(resolved.model) == render_mermaid(legacy)
    assert {node.id for node in canonical.nodes} == {node.id for node in legacy.nodes}


def test_v02_schema_rejects_inference_that_overwrites_fact() -> None:
    with pytest.raises(ValidationError, match="overwrite a known fact"):
        SystemModelV02(
            nodes=[
                NodeV02(id="node:db", name="DB", type=NodeType.DATABASE, evidence=[_evidence()])
            ],
            inferences=[_type_inference("node:db")],
        )


def test_v02_schema_rejects_missing_inference_reference() -> None:
    inference = _type_inference("node:db").model_copy(
        update={"based_on": [ModelReference(element_id="missing", path="/name")]}
    )
    with pytest.raises(ValidationError, match="missing based_on reference"):
        SystemModelV02(
            nodes=[NodeV02(id="node:db", name="DB", type=NodeType.UNKNOWN)],
            inferences=[inference],
        )


def test_v02_schema_rejects_invalid_inference_target_and_value() -> None:
    node = NodeV02(id="node:db", name="DB", type=NodeType.UNKNOWN)
    bad_value = _type_inference(node.id).model_copy(update={"value": ["database"]})
    with pytest.raises(ValidationError, match="invalid node type"):
        SystemModelV02(nodes=[node], inferences=[bad_value])

    wrong_boundary = _type_inference(node.id).model_copy(
        update={
            "predicate": "/trust_boundary_id",
            "value": node.id,
        }
    )
    with pytest.raises(ValidationError, match="invalid trust boundary"):
        SystemModelV02(nodes=[node], inferences=[wrong_boundary])


def test_v02_schema_requires_explicit_unknown_for_conflicting_inferences() -> None:
    first = _type_inference("node:db")
    second = first.model_copy(update={"id": "inference:second", "value": NodeType.DATA_ASSET.value})
    model = SystemModelV02(
        nodes=[NodeV02(id="node:db", name="DB", type=NodeType.UNKNOWN)],
        inferences=[first],
    )
    with pytest.raises(ValidationError, match="need unknown"):
        SystemModelV02.model_validate(
            model.model_dump(mode="json") | {"inferences": [first, second]}
        )
    conflict_id = make_id("unknown", "inference-conflict", "node:db", "/type")
    accepted = SystemModelV02(
        nodes=model.nodes,
        inferences=[first, second],
        unknowns=[
            Unknown(
                id=conflict_id,
                category="inference_conflict",
                description="Conflicting inferred node types.",
                related_element_id="node:db",
            )
        ],
    )
    assert len(accepted.inferences) == 2
    resolved = resolve_system_model_v02(accepted)
    assert resolved.model.nodes[0].type == NodeType.UNKNOWN
    assert not resolved.applied_inferences


def test_v02_attribute_evidence_requires_a_known_value() -> None:
    supported = SystemModelV02(
        nodes=[
            NodeV02(
                id="node:db",
                name="DB",
                type=NodeType.DATABASE,
                attribute_evidence={"/type": [_evidence()]},
            )
        ]
    )
    assert supported.nodes[0].attribute_evidence["/type"]

    with pytest.raises(ValidationError, match="has no known value"):
        SystemModelV02(
            nodes=[
                NodeV02(
                    id="node:db",
                    name="DB",
                    type=NodeType.UNKNOWN,
                    attribute_evidence={"/type": [_evidence()]},
                )
            ]
        )


def test_v02_identity_alias_requires_review_and_unique_legacy_id() -> None:
    with pytest.raises(ValidationError):
        IdentityAlias(legacy_id="old", current_id="new", reviewed_by="")
    with pytest.raises(ValidationError, match="one legacy id"):
        SystemModelV02(
            nodes=[
                NodeV02(id="new-a", name="A", type=NodeType.COMPONENT),
                NodeV02(id="new-b", name="B", type=NodeType.COMPONENT),
            ],
            identity_aliases=[
                IdentityAlias(legacy_id="old", current_id="new-a", reviewed_by="reviewer"),
                IdentityAlias(legacy_id="old", current_id="new-b", reviewed_by="reviewer"),
            ],
        )


def test_v02_json_schema_exposes_version_and_inferences() -> None:
    schema = SystemModelV02.model_json_schema()

    assert schema["properties"]["schema_version"]["default"] == "0.2"
    assert "inferences" in schema["properties"]
    assert "identity_aliases" in schema["properties"]


def _type_inference(subject_id: str) -> Inference:
    return Inference(
        id="inference:type",
        subject_id=subject_id,
        predicate="/type",
        value=NodeType.DATABASE.value,
        based_on=[ModelReference(element_id=subject_id, path="/name")],
        rule_id="mermaid-label-type-v1",
        confidence=0.7,
        provenance_class="deterministic",
        evidence=[_evidence()],
    )
