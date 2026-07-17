"""End-to-end MVP analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from threatmodel_ai.attack import generate_attack_findings
from threatmodel_ai.dfd import render_mermaid
from threatmodel_ai.extract import extract_openapi, extract_readme, extract_terraform
from threatmodel_ai.ingest import AnalysisInputs
from threatmodel_ai.model.io import write_system_model
from threatmodel_ai.model.merge import merge_system_models
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.questions import generate_questions
from threatmodel_ai.report import (
    render_attack_markdown,
    render_questions_markdown,
    render_threats_markdown,
)
from threatmodel_ai.stride import generate_threats


@dataclass(frozen=True)
class AnalysisResult:
    """Artifact paths written by the analysis pipeline."""

    model: SystemModel
    system_model_path: Path
    dfd_path: Path
    threats_path: Path
    attack_path: Path
    questions_path: Path


def analyze_project(inputs: AnalysisInputs, out_dir: Path) -> AnalysisResult:
    """Run deterministic extraction and write all MVP artifacts."""

    models: list[SystemModel] = []
    if inputs.readme:
        models.append(extract_readme(inputs.readme))
    if inputs.openapi:
        models.append(extract_openapi(inputs.openapi))
    if inputs.terraform:
        models.append(extract_terraform(inputs.terraform))
    if not models:
        raise ValueError(
            "No supported input files were found. Provide README, OpenAPI, or Terraform."
        )

    model = merge_system_models(models)
    threats = generate_threats(model)
    attack_findings = generate_attack_findings(model)
    questions = generate_questions(model)

    out_dir.mkdir(parents=True, exist_ok=True)
    system_model_path = out_dir / "system_model.json"
    dfd_path = out_dir / "dfd.mmd"
    threats_path = out_dir / "threats.md"
    attack_path = out_dir / "attack.md"
    questions_path = out_dir / "questions.md"

    write_system_model(model, system_model_path)
    dfd_path.write_text(render_mermaid(model), encoding="utf-8")
    threats_path.write_text(render_threats_markdown(threats), encoding="utf-8")
    attack_path.write_text(render_attack_markdown(attack_findings), encoding="utf-8")
    questions_path.write_text(render_questions_markdown(questions), encoding="utf-8")

    return AnalysisResult(
        model=model,
        system_model_path=system_model_path,
        dfd_path=dfd_path,
        threats_path=threats_path,
        attack_path=attack_path,
        questions_path=questions_path,
    )
