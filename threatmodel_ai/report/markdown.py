"""Markdown renderers for generated MVP artifacts."""

from __future__ import annotations

from threatmodel_ai.attack.models import AttackFinding
from threatmodel_ai.questions.generator import Question
from threatmodel_ai.risk.models import RiskFinding
from threatmodel_ai.stride.models import Threat


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
