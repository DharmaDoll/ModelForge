from pathlib import Path

import pytest
from pydantic import ValidationError

from threatmodel_ai.errors import ObservationPolicyError
from threatmodel_ai.extract import observe_readme
from threatmodel_ai.model.observations import (
    CandidateNodeObservation,
    ObservationBatch,
    ProvenanceClass,
    model_to_observation_batch,
    normalize_observation_batch,
)
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

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


def test_model_observation_round_trip_preserves_the_canonical_model() -> None:
    evidence = _evidence()
    model = SystemModel(
        name="Orders",
        description="Order service.",
        nodes=[
            Node(id="actor:user", name="User", type=NodeType.ACTOR, evidence=[evidence]),
            Node(id="api:orders", name="Orders API", type=NodeType.API, evidence=[evidence]),
        ],
        edges=[
            Edge(
                id="edge:user-orders",
                source="actor:user",
                target="api:orders",
                type=EdgeType.COMMUNICATES_WITH,
                evidence=[evidence],
            )
        ],
        unknowns=[
            Unknown(
                id="unknown:auth",
                category="authentication",
                description="Authentication is unknown.",
                related_element_id="edge:user-orders",
                evidence=evidence,
            )
        ],
        metadata={"source": "fixture"},
    )

    batch = model_to_observation_batch(model)
    normalized = normalize_observation_batch(batch)

    assert normalized == model
    assert {observation.kind for observation in batch.observations} == {
        "system",
        "node",
        "edge",
        "unknown",
    }
    assert all(
        observation.provenance_class == ProvenanceClass.DETERMINISTIC
        for observation in batch.observations
    )
    assert all(observation.confidence == 1.0 for observation in batch.observations)


def test_observation_batch_has_a_round_trip_json_schema() -> None:
    batch = model_to_observation_batch(
        SystemModel(
            name="Orders",
            nodes=[
                Node(
                    id="api:orders",
                    name="Orders API",
                    type=NodeType.API,
                    evidence=[_evidence()],
                )
            ],
        )
    )

    restored = ObservationBatch.model_validate_json(batch.model_dump_json())
    schema = ObservationBatch.model_json_schema()

    assert restored == batch
    assert "observations" in schema["properties"]
    assert schema["properties"]["schema_version"]["default"] == "0.1"


def test_generated_observations_cannot_be_normalized_as_facts() -> None:
    model = SystemModel(
        name="Generated proposal",
        nodes=[
            Node(
                id="api:generated",
                name="Generated API",
                type=NodeType.API,
                evidence=[_evidence()],
            )
        ],
    )
    batch = model_to_observation_batch(
        model,
        provenance_class=ProvenanceClass.GENERATED,
        confidence=0.8,
    )

    with pytest.raises(ObservationPolicyError, match="require review"):
        normalize_observation_batch(
            batch,
            accepted_provenance=frozenset({ProvenanceClass.GENERATED}),
        )


def test_human_reviewed_observations_require_an_explicit_policy() -> None:
    model = SystemModel(
        name="Reviewed proposal",
        nodes=[
            Node(
                id="api:reviewed",
                name="Reviewed API",
                type=NodeType.API,
                evidence=[_evidence()],
            )
        ],
    )
    batch = model_to_observation_batch(
        model,
        provenance_class=ProvenanceClass.HUMAN_REVIEWED,
        confidence=0.9,
    )

    with pytest.raises(ObservationPolicyError):
        normalize_observation_batch(batch)

    normalized = normalize_observation_batch(
        batch,
        accepted_provenance=frozenset({ProvenanceClass.HUMAN_REVIEWED}),
    )
    assert normalized.nodes[0].id == "api:reviewed"


def test_deterministic_observation_requires_full_confidence() -> None:
    with pytest.raises(ValidationError, match="confidence 1.0"):
        CandidateNodeObservation(
            id="observation:node",
            provenance_class=ProvenanceClass.DETERMINISTIC,
            confidence=0.9,
            evidence=[_evidence()],
            proposed=Node(id="api:orders", name="Orders API", type=NodeType.API),
        )


def test_observation_batch_rejects_duplicate_proposed_elements() -> None:
    first = CandidateNodeObservation(
        id="observation:first",
        provenance_class=ProvenanceClass.DETERMINISTIC,
        confidence=1.0,
        evidence=[_evidence()],
        proposed=Node(id="api:orders", name="Orders API", type=NodeType.API),
    )
    second = first.model_copy(update={"id": "observation:second"})

    with pytest.raises(ValidationError, match="duplicate proposed element ids"):
        ObservationBatch(observations=[first, second])


def test_readme_adapter_emits_evidence_bearing_observations() -> None:
    batch = observe_readme(FIXTURE / "README.md")

    assert batch.observations
    assert all(observation.evidence for observation in batch.observations)
    assert all(
        observation.provenance_class == ProvenanceClass.DETERMINISTIC
        for observation in batch.observations
    )
    assert any(
        observation.kind == "node" and observation.proposed.name == "Customer"
        for observation in batch.observations
    )


def _evidence() -> Evidence:
    return Evidence(
        source_type=SourceType.OPENAPI,
        source_path="openapi.yaml",
        extractor="openapi",
        detail="GET /orders",
        line=12,
    )
