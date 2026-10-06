"""End-to-end MVP analysis pipeline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from threatmodel_ai.analysis import analyze_canonical_model, analyze_model
from threatmodel_ai.dfd import render_mermaid
from threatmodel_ai.errors import AnalysisInputError
from threatmodel_ai.extract import (
    observe_readme,
)
from threatmodel_ai.extract.mermaid import observe_mermaid_markdown_with_diagnostics
from threatmodel_ai.extract.openapi import observe_openapi_with_diagnostics
from threatmodel_ai.extract.terraform import observe_terraform_with_diagnostics
from threatmodel_ai.ingest import AnalysisInputs
from threatmodel_ai.ingest.diagnostics import (
    ADAPTER_ORDER,
    AdapterName,
    MermaidParseMetrics,
    OpenApiParseMetrics,
    TerraformParseMetrics,
    summarize_ingestion,
)
from threatmodel_ai.llm import (
    LLMClient,
    OpenAIResponsesClient,
    extract_readme_candidates,
    refine_questions,
)
from threatmodel_ai.model.io import write_system_model
from threatmodel_ai.model.observations import ObservationBatch, normalize_observation_batches
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.model.schema_v02 import SystemModelV02
from threatmodel_ai.questions import Question
from threatmodel_ai.report import (
    render_attack_markdown,
    render_questions_markdown,
    render_review_markdown,
    render_risks_markdown,
    render_threats_markdown,
)


@dataclass(frozen=True)
class RenderResult:
    """Artifact paths written from a validated system model."""

    model: SystemModel
    system_model_path: Path
    dfd_path: Path
    threats_path: Path
    attack_path: Path
    risk_path: Path
    questions_path: Path
    review_path: Path
    questions: tuple[Question, ...]


@dataclass(frozen=True)
class AnalysisResult:
    """Artifact paths written by the analysis pipeline."""

    model: SystemModel
    system_model_path: Path
    dfd_path: Path
    threats_path: Path
    attack_path: Path
    risk_path: Path
    questions_path: Path
    review_path: Path
    ingestion_path: Path
    questions_refined_path: Path | None = None
    llm_candidates_path: Path | None = None


@dataclass(frozen=True)
class ArtifactPreview:
    """Deterministic artifact bodies built without writing or calling an LLM."""

    dfd: str
    threats: str
    attack: str
    risk: str
    questions_markdown: str
    review: str
    questions: tuple[Question, ...]


def analyze_project(
    inputs: AnalysisInputs,
    out_dir: Path,
    *,
    llm_mode: str | None = None,
    llm_client: LLMClient | None = None,
) -> AnalysisResult:
    """Run deterministic extraction and write all MVP artifacts."""

    observation_batches: list[ObservationBatch] = []
    batches_by_adapter: dict[AdapterName, list[ObservationBatch]] = {
        adapter: [] for adapter in ADAPTER_ORDER
    }
    mermaid_parse = MermaidParseMetrics()
    openapi_parse = OpenApiParseMetrics()
    terraform_parse = TerraformParseMetrics()
    markdown_paths = _markdown_paths(inputs)
    if inputs.readme:
        batch = observe_readme(inputs.readme)
        observation_batches.append(batch)
        batches_by_adapter["readme"].append(batch)
    for markdown_path in markdown_paths:
        mermaid_observations, document_metrics = observe_mermaid_markdown_with_diagnostics(
            markdown_path, identity_root=inputs.target
        )
        mermaid_parse.add(document_metrics)
        if _has_topology_observations(mermaid_observations):
            observation_batches.append(mermaid_observations)
            batches_by_adapter["mermaid"].append(mermaid_observations)
    if inputs.openapi:
        batch, openapi_parse = observe_openapi_with_diagnostics(inputs.openapi)
        observation_batches.append(batch)
        batches_by_adapter["openapi"].append(batch)
    if inputs.terraform:
        batch, terraform_parse = observe_terraform_with_diagnostics(
            inputs.terraform, identity_root=inputs.target
        )
        observation_batches.append(batch)
        batches_by_adapter["terraform"].append(batch)
    if not observation_batches:
        raise AnalysisInputError(
            f"No supported input files were found under {inputs.target}.",
            detail="ModelForge needs at least one README, OpenAPI/Swagger, or Terraform input.",
            hint=(
                "Add README.md, Markdown docs with Mermaid, openapi.yaml, swagger.yaml, "
                "or .tf files under the target, or pass --readme, --doc, --openapi, "
                "or --terraform explicitly."
            ),
        )

    model = normalize_observation_batches(observation_batches)
    render_result = render_model_artifacts(model, out_dir)
    diagnostics = summarize_ingestion(
        selected_files={
            "readme": int(inputs.readme is not None),
            "mermaid": len(markdown_paths),
            "openapi": int(inputs.openapi is not None),
            "terraform": len(inputs.terraform),
        },
        batches_by_adapter=batches_by_adapter,
        model=model,
        mermaid_parse=mermaid_parse,
        openapi_parse=openapi_parse,
        terraform_parse=terraform_parse,
    )
    ingestion_path = out_dir / "ingestion.json"
    ingestion_path.write_text(
        json.dumps(diagnostics.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    questions_refined_path: Path | None = None
    llm_candidates_path: Path | None = None

    if llm_mode:
        if llm_mode not in {"refine-questions", "extract-readme"}:
            raise AnalysisInputError(
                f"Unsupported LLM mode: {llm_mode}.",
                detail="Supported modes: refine-questions, extract-readme.",
                hint="Use --llm refine-questions, --llm extract-readme, or omit --llm.",
            )
        client = llm_client or OpenAIResponsesClient.from_env()
        if llm_mode == "refine-questions":
            questions_refined_path = out_dir / "questions_refined.md"
            questions_refined_path.write_text(
                refine_questions(
                    model=model,
                    questions=list(render_result.questions),
                    client=client,
                ),
                encoding="utf-8",
            )
        if llm_mode == "extract-readme":
            if not inputs.readme:
                raise AnalysisInputError(
                    "README input is required when --llm extract-readme is used.",
                    hint="Add README.md, pass --readme, or run without --llm extract-readme.",
                )
            candidates = extract_readme_candidates(inputs.readme, client)
            llm_candidates_path = out_dir / "llm_candidates.json"
            llm_candidates_path.write_text(
                json.dumps(
                    candidates.model_dump(mode="json"),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

    return AnalysisResult(
        model=model,
        system_model_path=render_result.system_model_path,
        dfd_path=render_result.dfd_path,
        threats_path=render_result.threats_path,
        attack_path=render_result.attack_path,
        risk_path=render_result.risk_path,
        questions_path=render_result.questions_path,
        review_path=render_result.review_path,
        ingestion_path=ingestion_path,
        questions_refined_path=questions_refined_path,
        llm_candidates_path=llm_candidates_path,
    )


def render_model_artifacts(model: SystemModel, out_dir: Path) -> RenderResult:
    """Write deterministic artifacts from a validated system model."""

    if isinstance(model, SystemModelV02):
        raise ValueError("0.2 report writing is not enabled; use the in-memory preview")
    preview = build_artifact_preview(model)

    out_dir.mkdir(parents=True, exist_ok=True)
    system_model_path = out_dir / "system_model.json"
    dfd_path = out_dir / "dfd.mmd"
    threats_path = out_dir / "threats.md"
    attack_path = out_dir / "attack.md"
    risk_path = out_dir / "risk.md"
    questions_path = out_dir / "questions.md"
    review_path = out_dir / "review.md"

    write_system_model(model, system_model_path)
    dfd_path.write_text(preview.dfd, encoding="utf-8")
    threats_path.write_text(preview.threats, encoding="utf-8")
    attack_path.write_text(preview.attack, encoding="utf-8")
    risk_path.write_text(preview.risk, encoding="utf-8")
    questions_path.write_text(preview.questions_markdown, encoding="utf-8")
    review_path.write_text(preview.review, encoding="utf-8")

    return RenderResult(
        model=model,
        system_model_path=system_model_path,
        dfd_path=dfd_path,
        threats_path=threats_path,
        attack_path=attack_path,
        risk_path=risk_path,
        questions_path=questions_path,
        review_path=review_path,
        questions=preview.questions,
    )


def build_artifact_preview(model: SystemModel | SystemModelV02) -> ArtifactPreview:
    """Exercise every deterministic generator without persisting a resolved view."""

    results = (
        analyze_canonical_model(model)
        if isinstance(model, SystemModelV02)
        else analyze_model(model)
    )
    analysis_model = results.model
    return ArtifactPreview(
        dfd=render_mermaid(analysis_model),
        threats=render_threats_markdown(results.threats),
        attack=render_attack_markdown(results.attack_findings),
        risk=render_risks_markdown(results.risks),
        questions_markdown=render_questions_markdown(results.questions, analysis_model),
        review=render_review_markdown(
            analysis_model,
            results.threats,
            results.attack_findings,
            results.risks,
            results.questions,
        ),
        questions=tuple(results.questions),
    )


def _markdown_paths(inputs: AnalysisInputs) -> tuple[Path, ...]:
    paths: dict[Path, Path] = {}
    if inputs.readme:
        paths[inputs.readme.resolve()] = inputs.readme
    for path in inputs.docs:
        paths[path.resolve()] = path
    return tuple(paths[key] for key in sorted(paths))


def _has_topology_observations(batch: ObservationBatch) -> bool:
    """Return whether a Markdown batch proposed at least one node or edge."""

    return any(observation.kind in {"node", "edge"} for observation in batch.observations)
