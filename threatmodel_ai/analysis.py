"""Deterministic assessments with conservative inference lineage."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from threatmodel_ai.attack import AttackFinding, generate_attack_findings
from threatmodel_ai.model.resolution import resolve_system_model_v02
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.model.schema_v02 import SystemModelV02
from threatmodel_ai.questions import Question, generate_questions
from threatmodel_ai.risk import RiskFinding, score_risks
from threatmodel_ai.stride import Threat, generate_threats

type Assessment = Threat | AttackFinding | RiskFinding | Question


@dataclass(frozen=True)
class AssessmentResults:
    """All deterministic lens candidates for one in-memory model view."""

    model: SystemModel
    threats: list[Threat]
    attack_findings: list[AttackFinding]
    risks: list[RiskFinding]
    questions: list[Question]


def analyze_model(model: SystemModel) -> AssessmentResults:
    """Run the four assessment lenses without modifying model facts."""

    threats = generate_threats(model)
    attack_findings = generate_attack_findings(model)
    return AssessmentResults(
        model=model,
        threats=threats,
        attack_findings=attack_findings,
        risks=score_risks(model, threats, attack_findings),
        questions=generate_questions(model),
    )


def analyze_canonical_model(canonical: SystemModelV02) -> AssessmentResults:
    """Trace each applied inference to candidates it actually changes.

    For each resolved subject/predicate group, compare candidates against a
    counterfactual model with that whole group omitted. This is conservative:
    an inference is not cited merely because its subject appears in a finding.
    """

    resolved = resolve_system_model_v02(canonical)
    results = analyze_model(resolved.model)
    for key, inference_ids in sorted(resolved.applied_inferences.items()):
        remaining = [
            inference
            for inference in canonical.inferences
            if (inference.subject_id, inference.predicate) != key
        ]
        counterfactual = resolve_system_model_v02(
            canonical.model_copy(update={"inferences": remaining})
        )
        without = analyze_model(counterfactual.model)
        _trace_candidates(results.threats, without.threats, inference_ids)
        _trace_candidates(results.attack_findings, without.attack_findings, inference_ids)
        _trace_candidates(results.risks, without.risks, inference_ids)
        _trace_candidates(results.questions, without.questions, inference_ids)
    return results


def _trace_candidates(
    candidates: Sequence[Assessment],
    without: Sequence[Assessment],
    inference_ids: tuple[str, ...],
) -> None:
    """Cite a claim only when removing it changes a candidate's semantic payload."""

    counterfactual_by_id = {item.id: _semantic_payload(item) for item in without}
    for candidate in candidates:
        if _semantic_payload(candidate) != counterfactual_by_id.get(candidate.id):
            candidate.derived_from = list(dict.fromkeys([*candidate.derived_from, *inference_ids]))


def _semantic_payload(candidate: Assessment) -> dict[str, object]:
    """Ignore already-attached lineage and source pointers when comparing output."""

    return candidate.model_dump(mode="json", exclude={"derived_from", "evidence"})
