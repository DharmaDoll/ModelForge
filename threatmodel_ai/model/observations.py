"""Candidate observation contract and deterministic normalization policy."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from threatmodel_ai.errors import ObservationPolicyError
from threatmodel_ai.model.evidence import merge_evidence
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.merge import merge_system_models
from threatmodel_ai.model.schema import Edge, Evidence, Node, SystemModel, Unknown


class ProvenanceClass(StrEnum):
    """Trust class assigned to an observation before normalization."""

    DETERMINISTIC = "deterministic"
    HUMAN_REVIEWED = "human_reviewed"
    GENERATED = "generated"


class SystemContext(BaseModel):
    """Proposed top-level system fields carried by a system observation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="0.1", min_length=1)
    id: str = Field(default="system", min_length=1)
    name: str = Field(default="unknown", min_length=1)
    description: str = Field(default="unknown", min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class _CandidateObservationBase(BaseModel):
    """Fields shared by every proposed model change."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    provenance_class: ProvenanceClass
    confidence: float = Field(ge=0, le=1)
    evidence: list[Evidence] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_deterministic_confidence(self) -> _CandidateObservationBase:
        """Reserve deterministic provenance for fully confident parser output."""

        if (
            self.provenance_class == ProvenanceClass.DETERMINISTIC
            and self.confidence != 1.0
        ):
            raise ValueError("deterministic observations must have confidence 1.0")
        return self


class CandidateSystemObservation(_CandidateObservationBase):
    """Candidate change to top-level system context."""

    kind: Literal["system"] = "system"
    proposed: SystemContext


class CandidateNodeObservation(_CandidateObservationBase):
    """Candidate graph-node fact."""

    kind: Literal["node"] = "node"
    proposed: Node


class CandidateEdgeObservation(_CandidateObservationBase):
    """Candidate graph-edge fact."""

    kind: Literal["edge"] = "edge"
    proposed: Edge


class CandidateUnknownObservation(_CandidateObservationBase):
    """Candidate security-relevant unknown."""

    kind: Literal["unknown"] = "unknown"
    proposed: Unknown


CandidateObservation = Annotated[
    CandidateSystemObservation
    | CandidateNodeObservation
    | CandidateEdgeObservation
    | CandidateUnknownObservation,
    Field(discriminator="kind"),
]


class ObservationBatch(BaseModel):
    """Candidate observations emitted by one input adapter invocation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="0.1", min_length=1)
    observations: list[CandidateObservation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_observations(self) -> ObservationBatch:
        """Reject duplicate observation and proposed-element identities."""

        observation_ids = [observation.id for observation in self.observations]
        if len(set(observation_ids)) != len(observation_ids):
            raise ValueError("observation batch contains duplicate observation ids")

        proposal_keys = [_proposal_key(observation) for observation in self.observations]
        if len(set(proposal_keys)) != len(proposal_keys):
            raise ValueError("observation batch contains duplicate proposed element ids")
        return self


def model_to_observation_batch(
    model: SystemModel,
    *,
    fallback_evidence: Iterable[Evidence] = (),
    provenance_class: ProvenanceClass = ProvenanceClass.DETERMINISTIC,
    confidence: float = 1.0,
) -> ObservationBatch:
    """Convert one adapter model into an evidence-bearing observation batch."""

    fallbacks = merge_evidence(fallback_evidence)
    system_evidence = merge_evidence([*_model_evidence(model), *fallbacks])
    if not system_evidence:
        raise ValueError("an observation batch requires source evidence")

    observations: list[CandidateObservation] = [
        CandidateSystemObservation(
            id=_observation_id("system", model.id, system_evidence),
            provenance_class=provenance_class,
            confidence=confidence,
            evidence=system_evidence,
            proposed=SystemContext(
                schema_version=model.schema_version,
                id=model.id,
                name=model.name,
                description=model.description,
                metadata=model.metadata,
            ),
        )
    ]

    for node in model.nodes:
        evidence = _required_evidence(node.evidence, fallbacks, "node", node.id)
        observations.append(
            CandidateNodeObservation(
                id=_observation_id("node", node.id, evidence),
                provenance_class=provenance_class,
                confidence=confidence,
                evidence=evidence,
                proposed=node.model_copy(update={"evidence": []}),
            )
        )
    for edge in model.edges:
        evidence = _required_evidence(edge.evidence, fallbacks, "edge", edge.id)
        observations.append(
            CandidateEdgeObservation(
                id=_observation_id("edge", edge.id, evidence),
                provenance_class=provenance_class,
                confidence=confidence,
                evidence=evidence,
                proposed=edge.model_copy(update={"evidence": []}),
            )
        )
    for unknown in model.unknowns:
        evidence = _required_evidence(
            [unknown.evidence] if unknown.evidence else [],
            fallbacks,
            "unknown",
            unknown.id,
        )
        observations.append(
            CandidateUnknownObservation(
                id=_observation_id("unknown", unknown.id, evidence),
                provenance_class=provenance_class,
                confidence=confidence,
                evidence=evidence,
                proposed=unknown.model_copy(update={"evidence": None}),
            )
        )

    return ObservationBatch(observations=observations)


def normalize_observation_batch(
    batch: ObservationBatch,
    *,
    accepted_provenance: frozenset[ProvenanceClass] = frozenset(
        {ProvenanceClass.DETERMINISTIC}
    ),
) -> SystemModel:
    """Promote eligible observations from one batch into a validated model."""

    _validate_normalization_policy(batch.observations, accepted_provenance)
    context = _system_context(batch.observations)
    nodes: list[Node] = []
    edges: list[Edge] = []
    unknowns: list[Unknown] = []

    for observation in batch.observations:
        if isinstance(observation, CandidateNodeObservation):
            nodes.append(
                observation.proposed.model_copy(
                    update={
                        "evidence": merge_evidence(
                            [*observation.evidence, *observation.proposed.evidence]
                        )
                    }
                )
            )
        elif isinstance(observation, CandidateEdgeObservation):
            edges.append(
                observation.proposed.model_copy(
                    update={
                        "evidence": merge_evidence(
                            [*observation.evidence, *observation.proposed.evidence]
                        )
                    }
                )
            )
        elif isinstance(observation, CandidateUnknownObservation):
            evidence = merge_evidence(
                [
                    *observation.evidence,
                    *([observation.proposed.evidence] if observation.proposed.evidence else []),
                ]
            )
            unknowns.append(
                observation.proposed.model_copy(
                    update={"evidence": evidence[0]}
                )
            )

    return SystemModel(
        schema_version=context.schema_version,
        id=context.id,
        name=context.name,
        description=context.description,
        nodes=sorted(nodes, key=lambda node: (node.type.value, node.id)),
        edges=sorted(edges, key=lambda edge: (edge.type.value, edge.id)),
        unknowns=sorted(unknowns, key=lambda unknown: unknown.id),
        metadata=context.metadata,
    )


def normalize_observation_batches(
    batches: Iterable[ObservationBatch],
    *,
    accepted_provenance: frozenset[ProvenanceClass] = frozenset(
        {ProvenanceClass.DETERMINISTIC}
    ),
) -> SystemModel:
    """Normalize and merge adapter batches into the canonical system model."""

    models = [
        normalize_observation_batch(batch, accepted_provenance=accepted_provenance)
        for batch in batches
    ]
    return merge_system_models(models)


def _validate_normalization_policy(
    observations: Iterable[CandidateObservation],
    accepted_provenance: frozenset[ProvenanceClass],
) -> None:
    rejected = [
        observation.id
        for observation in observations
        if observation.provenance_class == ProvenanceClass.GENERATED
        or observation.provenance_class not in accepted_provenance
    ]
    if rejected:
        raise ObservationPolicyError(
            "Candidate observations require review before normalization.",
            detail=f"Rejected observation IDs: {', '.join(sorted(rejected))}.",
            hint="Review the candidates and mark them human_reviewed before normalization.",
        )


def _system_context(observations: Iterable[CandidateObservation]) -> SystemContext:
    contexts = [
        observation.proposed
        for observation in observations
        if isinstance(observation, CandidateSystemObservation)
    ]
    if len(contexts) != 1:
        raise ValueError("observation batch must contain exactly one system observation")
    return contexts[0]


def _model_evidence(model: SystemModel) -> list[Evidence]:
    evidence: list[Evidence] = []
    for node in model.nodes:
        evidence.extend(node.evidence)
    for edge in model.edges:
        evidence.extend(edge.evidence)
    for unknown in model.unknowns:
        if unknown.evidence:
            evidence.append(unknown.evidence)
    return merge_evidence(evidence)


def _required_evidence(
    evidence: Iterable[Evidence],
    fallbacks: Iterable[Evidence],
    kind: str,
    proposal_id: str,
) -> list[Evidence]:
    merged = merge_evidence(evidence)
    if not merged:
        merged = merge_evidence(fallbacks)
    if not merged:
        raise ValueError(f"{kind} observation {proposal_id!r} requires evidence")
    return merged


def _observation_id(kind: str, proposal_id: str, evidence: list[Evidence]) -> str:
    first = evidence[0]
    return make_id(
        "observation",
        kind,
        proposal_id,
        first.source_type.value,
        first.source_path,
        first.extractor,
        first.detail,
        str(first.line or "unknown"),
    )


def _proposal_key(observation: CandidateObservation) -> tuple[str, str]:
    return observation.kind, observation.proposed.id
