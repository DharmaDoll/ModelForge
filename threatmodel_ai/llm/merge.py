"""Deterministically merge reviewed LLM candidates into a system model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from threatmodel_ai.errors import ModelForgeError
from threatmodel_ai.llm.candidates import (
    CandidateEdge,
    CandidateEvidence,
    CandidateNode,
    CandidateUnknown,
    LLMCandidateModel,
)
from threatmodel_ai.model.ids import make_id, short_hash
from threatmodel_ai.model.schema import Edge, Evidence, Node, SystemModel, Unknown

CandidateKind = Literal["node", "edge", "unknown"]


class CandidateMergeError(ModelForgeError):
    """Raised when reviewed LLM candidates cannot be merged safely."""


@dataclass(frozen=True)
class CandidateMergeRejection:
    """A candidate that was not merged as a model fact."""

    kind: CandidateKind
    id: str
    reason: str


@dataclass(frozen=True)
class CandidateMergeResult:
    """Merged model and candidate merge summary counts."""

    model: SystemModel
    merged_nodes: int
    merged_edges: int
    merged_unknowns: int
    review_unknowns: int
    rejected: tuple[CandidateMergeRejection, ...]


def merge_llm_candidates(
    base_model: SystemModel,
    candidates: LLMCandidateModel,
    *,
    min_confidence: float = 0.75,
) -> CandidateMergeResult:
    """Merge reviewed LLM candidates without overwriting deterministic facts."""

    if min_confidence < 0 or min_confidence > 1:
        raise CandidateMergeError(
            "Invalid candidate merge confidence threshold.",
            detail=f"min_confidence must be between 0 and 1, got {min_confidence}.",
            hint="Pass --min-confidence with a value from 0.0 to 1.0.",
        )

    nodes = {node.id: node for node in base_model.nodes}
    edges = {edge.id: edge for edge in base_model.edges}
    unknowns = {unknown.id: unknown for unknown in base_model.unknowns}
    rejections: list[CandidateMergeRejection] = []
    review_unknowns = 0
    merged_nodes = 0
    merged_edges = 0
    merged_unknowns = 0

    for candidate in candidates.nodes:
        reason = _node_rejection_reason(candidate, nodes, edges, unknowns, min_confidence)
        if reason:
            review_unknowns += _add_review_unknown(
                unknowns,
                kind="node",
                candidate_id=candidate.id,
                reason=reason,
                evidence=candidate.evidence,
                related_element_id=_existing_element_id(candidate.id, nodes, edges),
            )
            rejections.append(CandidateMergeRejection("node", candidate.id, reason))
            continue
        nodes[candidate.id] = _node_from_candidate(candidate)
        merged_nodes += 1

    for candidate in candidates.edges:
        reason = _edge_rejection_reason(candidate, nodes, edges, unknowns, min_confidence)
        if reason:
            review_unknowns += _add_review_unknown(
                unknowns,
                kind="edge",
                candidate_id=candidate.id,
                reason=reason,
                evidence=candidate.evidence,
                related_element_id=_existing_element_id(candidate.id, nodes, edges),
            )
            rejections.append(CandidateMergeRejection("edge", candidate.id, reason))
            continue
        edges[candidate.id] = _edge_from_candidate(candidate)
        merged_edges += 1

    for candidate in candidates.unknowns:
        reason = _unknown_rejection_reason(candidate, nodes, edges, unknowns, min_confidence)
        if reason:
            review_unknowns += _add_review_unknown(
                unknowns,
                kind="unknown",
                candidate_id=candidate.id,
                reason=reason,
                evidence=candidate.evidence,
            )
            rejections.append(CandidateMergeRejection("unknown", candidate.id, reason))
            continue
        unknowns[candidate.id] = _unknown_from_candidate(candidate, nodes, edges)
        merged_unknowns += 1

    model = SystemModel(
        schema_version=base_model.schema_version,
        id=base_model.id,
        name=base_model.name,
        description=base_model.description,
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges.values(), key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns.values(), key=lambda unknown: unknown.id),
        metadata=_merge_metadata(
            base_model,
            candidates,
            min_confidence=min_confidence,
            merged_nodes=merged_nodes,
            merged_edges=merged_edges,
            merged_unknowns=merged_unknowns,
            review_unknowns=review_unknowns,
            rejections=tuple(rejections),
        ),
    )

    return CandidateMergeResult(
        model=model,
        merged_nodes=merged_nodes,
        merged_edges=merged_edges,
        merged_unknowns=merged_unknowns,
        review_unknowns=review_unknowns,
        rejected=tuple(rejections),
    )


def _node_rejection_reason(
    candidate: CandidateNode,
    nodes: dict[str, Node],
    edges: dict[str, Edge],
    unknowns: dict[str, Unknown],
    min_confidence: float,
) -> str | None:
    if candidate.confidence < min_confidence:
        return _confidence_reason(candidate.confidence, min_confidence)
    if candidate.id in nodes or candidate.id in edges or candidate.id in unknowns:
        return "candidate ID already exists in the system model"
    return None


def _edge_rejection_reason(
    candidate: CandidateEdge,
    nodes: dict[str, Node],
    edges: dict[str, Edge],
    unknowns: dict[str, Unknown],
    min_confidence: float,
) -> str | None:
    if candidate.confidence < min_confidence:
        return _confidence_reason(candidate.confidence, min_confidence)
    if candidate.id in nodes or candidate.id in edges or candidate.id in unknowns:
        return "candidate ID already exists in the system model"

    missing = []
    if candidate.source not in nodes:
        missing.append(f"source {candidate.source!r}")
    if candidate.target not in nodes:
        missing.append(f"target {candidate.target!r}")
    missing.extend(f"data asset {asset!r}" for asset in candidate.data_assets if asset not in nodes)
    if missing:
        return "candidate references missing " + ", ".join(missing)
    return None


def _unknown_rejection_reason(
    candidate: CandidateUnknown,
    nodes: dict[str, Node],
    edges: dict[str, Edge],
    unknowns: dict[str, Unknown],
    min_confidence: float,
) -> str | None:
    if candidate.confidence < min_confidence:
        return _confidence_reason(candidate.confidence, min_confidence)
    if candidate.id in nodes or candidate.id in edges or candidate.id in unknowns:
        return "candidate ID already exists in the system model"
    return None


def _confidence_reason(confidence: float, min_confidence: float) -> str:
    return f"candidate confidence {confidence:.2f} is below threshold {min_confidence:.2f}"


def _node_from_candidate(candidate: CandidateNode) -> Node:
    return Node(
        id=candidate.id,
        name=candidate.name,
        type=candidate.type,
        description=candidate.description,
        metadata=_candidate_metadata(candidate.confidence),
        evidence=_candidate_evidence(candidate.evidence),
    )


def _edge_from_candidate(candidate: CandidateEdge) -> Edge:
    return Edge(
        id=candidate.id,
        source=candidate.source,
        target=candidate.target,
        type=candidate.type,
        description=candidate.description,
        protocol=candidate.protocol,
        authentication=candidate.authentication,
        authorization=candidate.authorization,
        data_assets=candidate.data_assets,
        metadata=_candidate_metadata(candidate.confidence),
        evidence=_candidate_evidence(candidate.evidence),
    )


def _unknown_from_candidate(
    candidate: CandidateUnknown,
    nodes: dict[str, Node],
    edges: dict[str, Edge],
) -> Unknown:
    related_element_id = candidate.related_element_id
    description = candidate.description
    if related_element_id and related_element_id not in nodes and related_element_id not in edges:
        description = (
            f"{description} Original related element {related_element_id!r} was not merged "
            "or does not exist."
        )
        related_element_id = None
    return Unknown(
        id=candidate.id,
        category=candidate.category,
        description=description,
        related_element_id=related_element_id,
        evidence=_candidate_evidence(candidate.evidence)[0],
    )


def _add_review_unknown(
    unknowns: dict[str, Unknown],
    *,
    kind: CandidateKind,
    candidate_id: str,
    reason: str,
    evidence: list[CandidateEvidence],
    related_element_id: str | None = None,
) -> int:
    review_id = make_id(
        "unknown",
        "llm-candidate-review",
        kind,
        candidate_id,
        short_hash(kind, candidate_id, reason),
    )
    if review_id in unknowns:
        return 0
    unknowns[review_id] = Unknown(
        id=review_id,
        category="llm_candidate_review",
        description=f"Review LLM {kind} candidate {candidate_id!r}: {reason}.",
        related_element_id=related_element_id,
        evidence=_candidate_evidence(evidence)[0],
    )
    return 1


def _candidate_evidence(items: list[CandidateEvidence]) -> list[Evidence]:
    return [
        Evidence(
            source_type=item.source_type,
            source_path=item.source_path,
            extractor="llm-readme",
            detail=item.detail,
            line=item.line,
        )
        for item in items
    ]


def _candidate_metadata(confidence: float) -> dict[str, object]:
    return {
        "candidate_confidence": confidence,
        "candidate_source": "llm_candidates.json",
        "extractor": "llm-readme",
    }


def _existing_element_id(
    candidate_id: str,
    nodes: dict[str, Node],
    edges: dict[str, Edge],
) -> str | None:
    if candidate_id in nodes or candidate_id in edges:
        return candidate_id
    return None


def _merge_metadata(
    base_model: SystemModel,
    candidates: LLMCandidateModel,
    *,
    min_confidence: float,
    merged_nodes: int,
    merged_edges: int,
    merged_unknowns: int,
    review_unknowns: int,
    rejections: tuple[CandidateMergeRejection, ...],
) -> dict[str, object]:
    metadata = dict(base_model.metadata)
    existing = metadata.get("llm_candidate_merges", [])
    history = existing if isinstance(existing, list) else []
    metadata["llm_candidate_merges"] = [
        *history,
        {
            "source_path": candidates.source_path,
            "source_type": candidates.source_type.value,
            "min_confidence": min_confidence,
            "merged_nodes": merged_nodes,
            "merged_edges": merged_edges,
            "merged_unknowns": merged_unknowns,
            "review_unknowns": review_unknowns,
            "warnings": candidates.warnings,
            "rejected": [
                {"kind": rejection.kind, "id": rejection.id, "reason": rejection.reason}
                for rejection in rejections
            ],
        },
    ]
    return metadata
