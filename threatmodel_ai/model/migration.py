"""Pure, versioned migrations for canonical system-model payloads."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import (
    Evidence,
    Node,
    NodeType,
    SourceType,
    SystemModel,
    Unknown,
)
from threatmodel_ai.model.schema_v02 import Inference, ModelReference, SystemModelV02

CURRENT_DRAFT_SCHEMA_VERSION = "0.2"


def migrate_system_model(
    payload: dict[str, Any], *, target_version: str = CURRENT_DRAFT_SCHEMA_VERSION
) -> dict[str, Any]:
    """Return a validated, deterministic 0.2 payload without changing the input."""

    if target_version != CURRENT_DRAFT_SCHEMA_VERSION:
        raise ValueError(f"unsupported migration target {target_version!r}; supported: 0.2")
    version = payload.get("schema_version")
    if version == CURRENT_DRAFT_SCHEMA_VERSION:
        return _canonical_payload(SystemModelV02.model_validate(payload))
    if version != "0.1":
        raise ValueError(f"unsupported model schema_version {version!r}; supported: 0.1, 0.2")

    legacy = SystemModel.model_validate(payload)
    migrated = deepcopy(legacy.model_dump(mode="json", exclude_none=True))
    migrated["schema_version"] = CURRENT_DRAFT_SCHEMA_VERSION
    migrated["evidence"] = []
    migrated["inferences"] = []
    migrated["identity_aliases"] = []
    unknowns = {unknown.id: unknown for unknown in legacy.unknowns}

    for node_payload, node in zip(migrated["nodes"], legacy.nodes, strict=True):
        node_payload["attribute_evidence"] = {}
        inference_source = node.metadata.get("type_inferred_from")
        if (
            isinstance(inference_source, str)
            and inference_source
            in {
                "mermaid_label",
                "mermaid_alias",
            }
            and node.type
            not in {
                NodeType.COMPONENT,
                NodeType.UNKNOWN,
            }
        ):
            _migrate_inferred_type(node_payload, node, inference_source, migrated)
        elif inference_source and node.type not in {NodeType.COMPONENT, NodeType.UNKNOWN}:
            node_payload["type"] = NodeType.UNKNOWN.value
            warning = _unrecognized_type_warning(node)
            unknowns.setdefault(warning.id, warning)
        elif node.type == NodeType.COMPONENT:
            warning = _component_type_warning(node)
            unknowns.setdefault(warning.id, warning)

    for edge_payload in migrated["edges"]:
        edge_payload["attribute_evidence"] = {}

    migrated["unknowns"] = [
        unknown.model_dump(mode="json", exclude_none=True)
        for unknown in sorted(unknowns.values(), key=lambda item: item.id)
    ]
    return _canonical_payload(SystemModelV02.model_validate(migrated))


def _migrate_inferred_type(
    node_payload: dict[str, Any],
    node: Node,
    inference_source: str,
    migrated: dict[str, Any],
) -> None:
    """Move one legacy Mermaid type guess out of the accepted fact field."""

    node_payload["type"] = NodeType.UNKNOWN.value
    node_payload["metadata"].pop("type_inferred_from", None)
    node_payload["metadata"].pop("type_inference_keyword", None)
    based_on_path = "/metadata/mermaid_alias" if inference_source == "mermaid_alias" else "/name"
    if based_on_path == "/metadata/mermaid_alias" and not node.metadata.get("mermaid_alias"):
        based_on_path = "/name"
    inference = Inference(
        id=make_id("inference", "legacy-mermaid-type", node.id),
        subject_id=node.id,
        predicate="/type",
        value=node.type.value,
        based_on=[ModelReference(element_id=node.id, path=based_on_path)],
        rule_id=f"legacy-mermaid-{inference_source}-type-v1",
        confidence=0.7,
        provenance_class="deterministic",
        evidence=node.evidence or [_legacy_pointer(node.id)],
    )
    migrated["inferences"].append(inference.model_dump(mode="json"))


def _component_type_warning(node: Node) -> Unknown:
    """Retain a review marker where legacy component typing was ambiguous."""

    return Unknown(
        id=make_id("unknown", "migration", "component-type", node.id),
        category="migration_review",
        description=(
            f"Legacy component type for {node.id} may be explicit or a fallback; "
            "review the original source."
        ),
        related_element_id=node.id,
        evidence=node.evidence[0] if node.evidence else _legacy_pointer(node.id),
    )


def _unrecognized_type_warning(node: Node) -> Unknown:
    """Flag a legacy type marker that has no recognized deterministic rule."""

    return Unknown(
        id=make_id("unknown", "migration", "unrecognized-type", node.id),
        category="migration_review",
        description=(
            f"Legacy inferred type for {node.id} was not recognized by the 0.2 "
            "migration; verify it against the original source."
        ),
        related_element_id=node.id,
        evidence=node.evidence[0] if node.evidence else _legacy_pointer(node.id),
    )


def _canonical_payload(model: SystemModelV02) -> dict[str, Any]:
    """Sort model collections before serializing a migrated artifact."""

    model.nodes.sort(key=lambda item: (item.type.value, item.id))
    model.edges.sort(key=lambda item: (item.type.value, item.id))
    model.unknowns.sort(key=lambda item: item.id)
    model.inferences.sort(key=lambda item: item.id)
    model.identity_aliases.sort(key=lambda item: (item.legacy_id, item.current_id))
    return model.model_dump(mode="json", exclude_none=True)


def _legacy_pointer(element_id: str) -> Evidence:
    """Point to the legacy model claim when original source evidence is unavailable."""

    return Evidence(
        source_type=SourceType.DERIVED,
        source_path="legacy-system-model",
        extractor="migration-0.1-to-0.2",
        detail=f"Legacy model element {element_id}; underlying source is unverified.",
    )
