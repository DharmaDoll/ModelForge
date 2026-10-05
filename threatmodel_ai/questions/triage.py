"""Presentation-only grouping and navigation for clarification questions."""

from __future__ import annotations

from dataclasses import dataclass

from threatmodel_ai.model.ids import short_hash
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.questions.generator import Question
from threatmodel_ai.risk.models import RiskFinding

_CATEGORY_ORDER = (
    "authentication",
    "authorization",
    "data_classification",
    "encryption",
    "rate_limiting",
    "trust_boundary",
    "logging_monitoring",
)


@dataclass(frozen=True)
class QuestionGroup:
    """One review task with every underlying question retained."""

    anchor: str
    category: str
    intent: str
    subject_id: str
    subject_label: str
    representative: Question
    questions: tuple[Question, ...]


def group_questions(
    questions: list[Question], model: SystemModel | None = None
) -> list[QuestionGroup]:
    """Group only questions with the same category and primary model element."""

    by_key: dict[tuple[str, str, str], list[Question]] = {}
    for question in questions:
        subject_id = question.related_elements[0] if question.related_elements else question.id
        intent = _review_intent(question)
        by_key.setdefault((question.category, subject_id, intent), []).append(question)

    groups = []
    for (category, subject_id, intent), members in by_key.items():
        ordered = tuple(sorted(members, key=lambda item: item.id))
        representative = min(
            ordered,
            key=lambda item: (-len(item.question), item.question, item.id),
        )
        groups.append(
            QuestionGroup(
                anchor=f"question-group-{short_hash(category, subject_id, intent)}",
                category=category,
                intent=intent,
                subject_id=subject_id,
                subject_label=_subject_label(subject_id, model),
                representative=representative,
                questions=ordered,
            )
        )
    return sorted(
        groups,
        key=lambda group: (
            group.category,
            group.subject_label.casefold(),
            group.subject_id,
            group.intent,
        ),
    )


def starting_question_groups(
    groups: list[QuestionGroup], risks: list[RiskFinding], *, limit: int = 5
) -> list[QuestionGroup]:
    """Select a small, varied navigation queue from existing review priorities."""

    if limit <= 0:
        return []
    risk_order = sorted(risks, key=lambda item: (-item.score, item.id))
    by_risk: dict[str, list[QuestionGroup]] = {risk.id: [] for risk in risk_order}
    unlinked: list[QuestionGroup] = []
    for group in groups:
        risk = _related_risk(group, risks)
        if risk:
            by_risk[risk.id].append(group)
        else:
            unlinked.append(group)
    for risk in risk_order:
        by_risk[risk.id].sort(key=lambda group: _risk_group_key(group, risk))

    selected: list[QuestionGroup] = []
    while len(selected) < limit:
        added = False
        for risk in risk_order:
            candidates = by_risk[risk.id]
            if candidates:
                selected.append(candidates.pop(0))
                added = True
                if len(selected) == limit:
                    return selected
        if not added:
            break

    selected.extend(sorted(unlinked, key=_unlinked_group_key)[: limit - len(selected)])
    return selected


def _category_rank(category: str) -> int:
    """Stable navigation order, not a security score."""

    return _CATEGORY_ORDER.index(category) if category in _CATEGORY_ORDER else len(_CATEGORY_ORDER)


def _review_intent(question: Question) -> str:
    """Keep a documented absence distinct from an unknown authentication method."""

    if question.category == "authentication" and question.question.startswith(
        "Is unauthenticated access"
    ):
        return "anonymous_access_intentionality"
    return question.category


def _risk_group_key(group: QuestionGroup, risk: RiskFinding) -> tuple[int, int, str]:
    direct_edge = (
        group.subject_id.startswith("edge:") and group.subject_id in risk.affected_elements
    )
    return (0 if direct_edge else 1, _category_rank(group.category), group.anchor)


def _unlinked_group_key(group: QuestionGroup) -> tuple[int, str]:
    return (_category_rank(group.category), group.anchor)


def _related_risk(group: QuestionGroup, risks: list[RiskFinding]) -> RiskFinding | None:
    related = {
        element_id for question in group.questions for element_id in question.related_elements
    }
    matches = [risk for risk in risks if related.intersection(risk.affected_elements)]
    return (
        min(
            matches,
            key=lambda risk: (
                0 if group.subject_id in risk.affected_elements else 1,
                -risk.score,
                risk.id,
            ),
        )
        if matches
        else None
    )


def _subject_label(subject_id: str, model: SystemModel | None) -> str:
    if model is None:
        return subject_id
    nodes = {node.id: node.name for node in model.nodes}
    if subject_id in nodes:
        return nodes[subject_id]
    for edge in model.edges:
        if edge.id == subject_id:
            return f"{nodes.get(edge.source, edge.source)} → {nodes.get(edge.target, edge.target)}"
    return subject_id
