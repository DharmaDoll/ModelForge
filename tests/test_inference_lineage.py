"""0.2 inferences are cited only when they change a generated candidate."""

from threatmodel_ai.analysis import analyze_canonical_model
from threatmodel_ai.model.schema import EdgeType, Evidence, NodeType, SourceType
from threatmodel_ai.model.schema_v02 import (
    EdgeV02,
    Inference,
    ModelReference,
    NodeV02,
    SystemModelV02,
)
from threatmodel_ai.pipeline import build_artifact_preview


def _evidence() -> Evidence:
    return Evidence(
        source_type=SourceType.MARKDOWN,
        source_path="docs/architecture.md",
        extractor="mermaid",
        detail="diagram 1",
    )


def _inference(
    inference_id: str, subject_id: str, predicate: str, value: str, based_on: str
) -> Inference:
    return Inference(
        id=inference_id,
        subject_id=subject_id,
        predicate=predicate,
        value=value,
        based_on=[ModelReference(element_id=subject_id, path=based_on)],
        rule_id="test-rule-v1",
        confidence=0.7,
        provenance_class="deterministic",
        evidence=[_evidence()],
    )


def test_inference_lineage_tracks_candidate_changes_not_just_related_elements() -> None:
    canonical = SystemModelV02(
        nodes=[
            NodeV02(id="node:internet", name="Internet", type=NodeType.ACTOR),
            NodeV02(id="node:api", name="Payments API", type=NodeType.UNKNOWN),
            NodeV02(id="node:other", name="Unrelated DB", type=NodeType.UNKNOWN),
        ],
        edges=[
            EdgeV02(
                id="edge:request",
                source="node:internet",
                target="node:api",
                type=EdgeType.COMMUNICATES_WITH,
                description="Anonymous requests are allowed.",
            )
        ],
        inferences=[
            _inference("inference:api-type", "node:api", "/type", "api", "/name"),
            _inference(
                "inference:no-auth-a",
                "edge:request",
                "/authentication",
                "none",
                "/description",
            ),
            _inference(
                "inference:no-auth-b",
                "edge:request",
                "/authentication",
                "none",
                "/description",
            ),
            _inference("inference:other-type", "node:other", "/type", "database", "/name"),
        ],
    )

    result = analyze_canonical_model(canonical)
    spoofing = next(item for item in result.threats if item.rule_id == "entrypoint-spoofing")
    public_attack = next(
        item for item in result.attack_findings if item.rule_id == "attack-public-entrypoint"
    )
    auth_question = next(item for item in result.questions if item.category == "authentication")

    assert canonical.nodes[1].type == NodeType.UNKNOWN
    assert canonical.edges[0].authentication == "unknown"
    assert "inference:api-type" in spoofing.derived_from
    assert "inference:no-auth-a" in spoofing.derived_from
    assert "inference:no-auth-b" in spoofing.derived_from
    assert "inference:other-type" not in spoofing.derived_from
    assert "inference:api-type" in public_attack.derived_from
    assert "inference:no-auth-a" not in public_attack.derived_from
    assert "inference:no-auth-b" not in public_attack.derived_from
    assert "inference:api-type" in result.risks[0].derived_from
    assert "inference:no-auth-a" in result.risks[0].derived_from
    assert "inference:api-type" in auth_question.derived_from
    assert "inference:no-auth-a" in auth_question.derived_from
    assert "inference:other-type" not in auth_question.derived_from

    preview = build_artifact_preview(canonical)
    assert "inference:api-type" in preview.threats
    assert "inference:no-auth-a" in preview.risk
    assert "inference:other-type" in preview.questions_markdown
