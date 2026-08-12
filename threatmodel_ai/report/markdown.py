"""Markdown renderers for generated MVP artifacts."""

from __future__ import annotations

from collections import Counter

from threatmodel_ai.attack.models import AttackFinding
from threatmodel_ai.model.schema import Evidence, SystemModel
from threatmodel_ai.questions.generator import Question
from threatmodel_ai.risk.models import RiskFinding, RiskRating
from threatmodel_ai.stride.models import Threat


def render_review_markdown(
    model: SystemModel,
    threats: list[Threat],
    attack_findings: list[AttackFinding],
    risks: list[RiskFinding],
    questions: list[Question],
) -> str:
    """Render a compact deterministic summary for CI and pull-request review."""

    rating_counts = Counter(risk.rating for risk in risks)
    question_counts = Counter(question.category for question in questions)
    ordered_risks = sorted(risks, key=lambda risk: (-risk.score, risk.id))
    lines = [
        "<!-- modelforge-review -->",
        "# ModelForge Review Summary",
        "",
        "Generated deterministically from `system_model.json`. All findings are review "
        "candidates, not confirmed vulnerabilities.",
        "",
        "## Coverage",
        "",
        "| Nodes | Data flows | Unknowns | STRIDE | ATT&CK | Questions |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {len(model.nodes)} | {len(model.edges)} | {len(model.unknowns)} | "
        f"{len(threats)} | {len(attack_findings)} | {len(questions)} |",
        "",
        "## Risk Priorities",
        "",
        "| High | Medium | Low | Total |",
        "| ---: | ---: | ---: | ---: |",
        f"| {rating_counts[RiskRating.HIGH]} | {rating_counts[RiskRating.MEDIUM]} | "
        f"{rating_counts[RiskRating.LOW]} | {len(risks)} |",
        "",
    ]

    if ordered_risks:
        lines.extend(
            [
                "### Highest Priorities",
                "",
                "| Rating | Score | Finding |",
                "| --- | ---: | --- |",
            ]
        )
        for risk in ordered_risks[:5]:
            lines.append(
                f"| {risk.rating.value} | {risk.score} | {_escape_table(risk.title)} |"
            )
        lines.append("")
    else:
        lines.extend(["No deterministic risk priorities were generated.", ""])

    if question_counts:
        lines.extend(
            [
                "## Open Question Categories",
                "",
                "| Category | Count |",
                "| --- | ---: |",
            ]
        )
        for category, count in sorted(question_counts.items()):
            lines.append(f"| {_escape_table(category)} | {count} |")
        lines.append("")

    lines.extend(
        [
            "Review `system_model.json` first, then `risk.md`, `threats.md`, `attack.md`, "
            "and `questions.md` for details.",
            "",
        ]
    )
    return "\n".join(lines)


def render_attack_markdown(findings: list[AttackFinding]) -> str:
    """Render MITRE ATT&CK technique candidates as review-ready Markdown."""

    lines = [
        "# MITRE ATT&CK Technique Candidates",
        "",
        "Generated deterministically from `system_model.json`. These are candidate "
        "TTP mappings, not evidence that an attack occurred.",
        "",
        f"Total ATT&CK findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.extend(["No ATT&CK technique candidates were generated.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | Technique | Tactics | Title | Confidence |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        technique = f"{finding.technique.id} {finding.technique.name}"
        tactics = ", ".join(finding.technique.tactics)
        lines.append(
            f"| `{finding.id}` | [{_escape_table(technique)}]({finding.technique.url}) | "
            f"{_escape_table(tactics)} | {_escape_table(finding.title)} | "
            f"{finding.confidence} |"
        )
    lines.append("")

    for finding in findings:
        technique = finding.technique
        lines.extend(
            [
                f"## {finding.title}",
                "",
                f"- ID: `{finding.id}`",
                f"- Rule: `{finding.rule_id}`",
                f"- Technique: [{technique.id} {technique.name}]({technique.url})",
                f"- Tactics: {', '.join(technique.tactics)}",
                f"- Matrix: {technique.matrix}",
                f"- Confidence: {finding.confidence}",
                f"- Status: {finding.status}",
                "- Affected elements: "
                f"{', '.join(f'`{item}`' for item in finding.affected_elements)}",
                f"- Derived from: {_format_optional_ids(finding.derived_from)}",
                f"- Evidence: {_format_evidence(finding.evidence)}",
                "",
                f"Scenario: {finding.scenario}",
                "",
                f"Detection: {finding.detection}",
                "",
                f"Mitigation: {finding.mitigation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_threats_markdown(threats: list[Threat]) -> str:
    """Render STRIDE threat candidates as review-ready Markdown."""

    lines = [
        "# Threats",
        "",
        "Generated deterministically from `system_model.json`. Review before acceptance.",
        "",
        f"Total threats: {len(threats)}",
        "",
    ]
    if not threats:
        lines.extend(["No deterministic threat candidates were generated.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | STRIDE | Title | Confidence |",
            "| --- | --- | --- | --- |",
        ]
    )
    for threat in threats:
        lines.append(
            f"| `{threat.id}` | {threat.category.value} | {_escape_table(threat.title)} | "
            f"{threat.confidence} |"
        )
    lines.append("")

    for threat in threats:
        lines.extend(
            [
                f"## {threat.title}",
                "",
                f"- ID: `{threat.id}`",
                f"- Rule: `{threat.rule_id}`",
                f"- STRIDE: {threat.category.value}",
                f"- Confidence: {threat.confidence}",
                f"- Status: {threat.status}",
                "- Affected elements: "
                f"{', '.join(f'`{item}`' for item in threat.affected_elements)}",
                f"- Derived from: {_format_optional_ids(threat.derived_from)}",
                f"- Evidence: {_format_evidence(threat.evidence)}",
                "",
                f"Scenario: {threat.scenario}",
                "",
                f"Impact: {threat.impact}",
                "",
                f"Mitigation: {threat.mitigation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_risks_markdown(risks: list[RiskFinding]) -> str:
    """Render deterministic risk priorities as review-ready Markdown."""

    lines = [
        "# Risk Priorities",
        "",
        "Generated deterministically from `system_model.json`, STRIDE candidates, "
        "and MITRE ATT&CK candidates.",
        "",
        f"Total risk findings: {len(risks)}",
        "",
    ]
    if not risks:
        lines.extend(["No deterministic risk priorities were generated.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | Rating | Score | Title |",
            "| --- | --- | --- | --- |",
        ]
    )
    for risk in risks:
        lines.append(
            f"| `{risk.id}` | {risk.rating.value} | {risk.score} | "
            f"{_escape_table(risk.title)} |"
        )
    lines.append("")

    for risk in risks:
        lines.extend(
            [
                f"## {risk.title}",
                "",
                f"- ID: `{risk.id}`",
                f"- Rating: {risk.rating.value}",
                f"- Score: {risk.score}",
                f"- Status: {risk.status}",
                "- Affected elements: "
                f"{', '.join(f'`{item}`' for item in risk.affected_elements)}",
                "- Related STRIDE threats: "
                f"{_format_optional_ids(risk.related_threats)}",
                "- Related ATT&CK findings: "
                f"{_format_optional_ids(risk.related_attack_findings)}",
                f"- Derived from: {_format_optional_ids(risk.derived_from)}",
                f"- Evidence: {_format_evidence(risk.evidence)}",
                "",
                "Rationale:",
                "",
            ]
        )
        lines.extend(f"- {item}" for item in risk.rationale)
        lines.append("")
    return "\n".join(lines)


def render_questions_markdown(questions: list[Question]) -> str:
    """Render clarification questions as Markdown."""

    lines = [
        "# Questions",
        "",
        "Questions generated from unknown or incomplete model facts.",
        "",
        f"Total questions: {len(questions)}",
        "",
    ]
    if not questions:
        lines.extend(["No clarification questions were generated.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | Category | Question |",
            "| --- | --- | --- |",
        ]
    )
    for question in questions:
        lines.append(
            f"| `{question.id}` | {question.category} | {_escape_table(question.question)} |"
        )
    lines.append("")

    for question in questions:
        lines.extend(
            [
                f"## {question.question}",
                "",
                f"- ID: `{question.id}`",
                f"- Category: {question.category}",
                "- Related elements: "
                f"{', '.join(f'`{item}`' for item in question.related_elements)}",
                f"- Derived from: {_format_optional_ids(question.derived_from)}",
                f"- Evidence: {_format_evidence(question.evidence)}",
                "",
                f"Rationale: {question.rationale}",
                "",
            ]
        )
    return "\n".join(lines)


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _format_optional_ids(values: list[str]) -> str:
    return ", ".join(f"`{item}`" for item in values) if values else "none"


def _format_evidence(values: list[Evidence]) -> str:
    if not values:
        return "none"

    displayed = values[:3]
    formatted = "; ".join(_format_evidence_item(item) for item in displayed)
    remaining = len(values) - len(displayed)
    if remaining > 0:
        formatted += f"; +{remaining} more"
    return formatted


def _format_evidence_item(value: Evidence) -> str:
    location = value.source_path
    if value.line is not None:
        location = f"{location}:{value.line}"
    detail = "" if value.detail == "unknown" else f", {value.detail}"
    return f"`{location}` ({value.extractor}/{value.source_type.value}{detail})"
