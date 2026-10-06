"""Typer CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from threatmodel_ai.attack import generate_attack_findings
from threatmodel_ai.errors import ModelForgeError
from threatmodel_ai.evaluation import evaluate_manifest
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.llm import merge_llm_candidates, read_llm_candidates
from threatmodel_ai.model.identity import preview_legacy_mermaid_identities
from threatmodel_ai.model.io import (
    read_system_model,
    read_versioned_system_model,
    write_system_model,
)
from threatmodel_ai.model.migration import migrate_system_model
from threatmodel_ai.pipeline import (
    analyze_project,
    build_artifact_preview,
    render_model_artifacts,
)
from threatmodel_ai.risk import RiskThreshold, risks_at_or_above, score_risks
from threatmodel_ai.stride import generate_threats

app = typer.Typer(help="Generate threat modeling artifacts from repository inputs.")
candidates_app = typer.Typer(help="Review and merge LLM candidate artifacts.")
model_app = typer.Typer(help="Validate and inspect system model artifacts.")
app.add_typer(candidates_app, name="candidates")
app.add_typer(model_app, name="model")


@app.callback()
def main() -> None:
    """ModelForge threat modeling CLI."""


@app.command()
def analyze(
    target: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Project directory to analyze.",
        ),
    ],
    readme: Annotated[
        Path | None,
        typer.Option("--readme", help="README path. Auto-discovered when omitted."),
    ] = None,
    openapi: Annotated[
        Path | None,
        typer.Option("--openapi", help="OpenAPI/Swagger file. Auto-discovered when omitted."),
    ] = None,
    terraform: Annotated[
        list[Path] | None,
        typer.Option("--terraform", "-t", help="Terraform .tf file. Repeat for multiple files."),
    ] = None,
    doc: Annotated[
        list[Path] | None,
        typer.Option("--doc", "-d", help="Markdown doc to scan for Mermaid. Repeatable."),
    ] = None,
    out: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output directory for generated artifacts."),
    ] = Path("out"),
    llm: Annotated[
        str | None,
        typer.Option(
            "--llm",
            help=(
                "Optional LLM mode. Supported: refine-questions, extract-readme. Default: disabled."
            ),
        ),
    ] = None,
) -> None:
    """Analyze inputs and write deterministic threat modeling artifacts."""

    try:
        inputs = discover_inputs(
            target,
            readme=readme,
            openapi=openapi,
            terraform=tuple(terraform) if terraform else None,
            docs=tuple(doc) if doc else None,
        )
        result = analyze_project(inputs, out, llm_mode=llm)
    except ModelForgeError as exc:
        _echo_error(exc.message, detail=exc.detail, hint=exc.hint)
        raise typer.Exit(code=1) from exc
    except FileNotFoundError as exc:
        _echo_error(
            "Input file was not found.",
            detail=str(exc),
            hint="Check the path passed to --readme, --doc, --openapi, or --terraform.",
        )
        raise typer.Exit(code=1) from exc
    except ValidationError as exc:
        _echo_error(
            "Generated system_model.json failed validation.",
            detail=_validation_detail(exc),
            hint="Fix the extractor output or input facts that produced invalid references.",
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _echo_error("Analysis failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    typer.echo(f"Wrote {result.system_model_path}")
    typer.echo(f"Wrote {result.dfd_path}")
    typer.echo(f"Wrote {result.threats_path}")
    typer.echo(f"Wrote {result.attack_path}")
    typer.echo(f"Wrote {result.risk_path}")
    typer.echo(f"Wrote {result.questions_path}")
    typer.echo(f"Wrote {result.review_path}")
    typer.echo(f"Wrote {result.ingestion_path}")
    if result.questions_refined_path:
        typer.echo(f"Wrote {result.questions_refined_path}")
    if result.llm_candidates_path:
        typer.echo(f"Wrote {result.llm_candidates_path}")
    _echo_next_steps(result.review_path, result.questions_path)
    if result.questions_refined_path:
        typer.echo(
            "LLM: question wording proposals require human review; "
            "questions.md is authoritative."
        )
    elif result.llm_candidates_path:
        typer.echo("LLM: README candidates require human review and explicit merge.")
    else:
        typer.echo("LLM: off; no external API was called.")


@app.command()
def render(
    system_model: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Validated system model JSON to render.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output directory for generated artifacts."),
    ] = Path("out"),
) -> None:
    """Render deterministic artifacts from an existing system model."""

    try:
        model = read_system_model(system_model)
        result = render_model_artifacts(model, out)
    except ValidationError as exc:
        _echo_error(
            "Input system model failed validation.",
            detail=_validation_detail(exc),
            hint="Fix the system model JSON before rendering artifacts.",
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _echo_error("Render failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    typer.echo(f"Wrote {result.system_model_path}")
    typer.echo(f"Wrote {result.dfd_path}")
    typer.echo(f"Wrote {result.threats_path}")
    typer.echo(f"Wrote {result.attack_path}")
    typer.echo(f"Wrote {result.risk_path}")
    typer.echo(f"Wrote {result.questions_path}")
    typer.echo(f"Wrote {result.review_path}")
    _echo_next_steps(result.review_path, result.questions_path)


@app.command()
def check(
    system_model: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Validated system model JSON to evaluate.",
        ),
    ],
    fail_on: Annotated[
        RiskThreshold,
        typer.Option(
            "--fail-on",
            help="Minimum risk rating that fails the check: high, medium, or low.",
        ),
    ] = RiskThreshold.HIGH,
) -> None:
    """Fail when deterministic risk candidates meet a configured threshold."""

    try:
        model = read_system_model(system_model)
        threats = generate_threats(model)
        attack_findings = generate_attack_findings(model)
        risks = score_risks(model, threats, attack_findings)
        violations = risks_at_or_above(risks, fail_on)
    except ValidationError as exc:
        _echo_error(
            "Input system model failed validation.",
            detail=_validation_detail(exc),
            hint="Fix the system model JSON before evaluating the risk gate.",
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _echo_error("Risk check failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    if violations:
        _echo_error(
            f"Risk gate failed at threshold {fail_on.value}.",
            detail=(
                f"{len(violations)} risk candidate(s) met or exceeded the threshold. "
                f"Highest rating: {violations[0].rating.value}; "
                f"highest score: {violations[0].score}."
            ),
            hint="Review risk.md and system_model.json before accepting these candidates.",
        )
        raise typer.Exit(code=1)

    typer.echo(f"Risk gate passed: no risk candidates met or exceeded {fail_on.value}.")


@app.command()
def evaluate(
    manifest: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Versioned evaluation manifest with authored labels.",
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the complete machine-readable report."),
    ] = False,
) -> None:
    """Measure deterministic outputs against labeled probes without calling an LLM."""

    try:
        report = evaluate_manifest(manifest)
    except ValidationError as exc:
        _echo_error(
            "Evaluation manifest failed validation.",
            detail=_validation_detail(exc),
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _echo_error("Evaluation failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    typer.echo(
        f"Evaluated {report.case_count} case(s), {report.labeled_probe_count} labeled probe(s)."
    )
    typer.echo(
        f"Expert-reviewed probes: {report.expert_reviewed_probe_count}; "
        "seed labels are not a gold standard."
    )
    typer.echo(
        f"Labeled-probe mismatches: {report.micro.fp + report.micro.fn} "
        "(informational; no CLI failure threshold)."
    )
    for lens, metrics in report.by_lens.items():
        typer.echo(f"{lens.value}: TP={metrics.tp} FP={metrics.fp} TN={metrics.tn} FN={metrics.fn}")


@candidates_app.command("merge")
def merge_candidates(
    system_model: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Existing system_model.json to merge into.",
        ),
    ],
    llm_candidates: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Reviewed llm_candidates.json file.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            "-o",
            help="Output path for the merged system model. The input model is not overwritten.",
        ),
    ],
    min_confidence: Annotated[
        float,
        typer.Option(
            "--min-confidence",
            min=0.0,
            max=1.0,
            help="Minimum confidence required to merge candidates as model facts.",
        ),
    ] = 0.75,
) -> None:
    """Merge reviewed LLM candidates into a new validated system model."""

    try:
        base_model = read_system_model(system_model)
        candidates = read_llm_candidates(llm_candidates, base_model=base_model)
        result = merge_llm_candidates(
            base_model,
            candidates,
            min_confidence=min_confidence,
        )
        write_system_model(result.model, out)
    except ModelForgeError as exc:
        _echo_error(exc.message, detail=exc.detail, hint=exc.hint)
        raise typer.Exit(code=1) from exc
    except ValidationError as exc:
        _echo_error(
            "system_model.json failed validation.",
            detail=_validation_detail(exc),
            hint="Use a valid ModelForge system_model.json before merging candidates.",
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _echo_error("Candidate merge failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    typer.echo(f"Wrote {out}")
    typer.echo(
        "Merged "
        f"{result.merged_nodes} node(s), "
        f"{result.merged_edges} edge(s), "
        f"{result.merged_unknowns} unknown(s)."
    )
    if result.review_unknowns:
        typer.echo(f"Added {result.review_unknowns} review unknown(s) for rejected candidates.")


@model_app.command("identity-preview")
def identity_preview(
    legacy_model: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
    ],
    current_model: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
    ],
    out: Annotated[Path, typer.Option("--out", "-o", help="Preview JSON output path.")],
) -> None:
    """Preview old Mermaid ID mappings without changing either model."""

    try:
        if out.resolve() in {legacy_model.resolve(), current_model.resolve()}:
            raise ValueError("Preview output must not overwrite an input model.")
        preview = preview_legacy_mermaid_identities(
            read_system_model(legacy_model), read_system_model(current_model)
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(preview.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except ValidationError as exc:
        _echo_error(
            "Input system model failed validation.",
            detail=_validation_detail(exc),
            hint="Use valid ModelForge system models for the identity preview.",
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _echo_error("Identity preview failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    typer.echo(f"Wrote {out}")
    typer.echo(
        f"{len(preview.suggestions)} unique suggestion(s); "
        f"{len(preview.ambiguous)} ambiguous legacy ID(s)."
    )


@model_app.command("validate")
def validate_model(
    system_model: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
    ],
    check_generators: Annotated[
        bool,
        typer.Option(
            "--check-generators",
            help="Exercise all deterministic artifact generators in memory; write nothing.",
        ),
    ] = False,
) -> None:
    """Validate a 0.1 or 0.2 model without modifying it."""

    try:
        model = read_versioned_system_model(system_model)
    except ValidationError as exc:
        _echo_error("Input system model failed validation.", detail=_validation_detail(exc))
        raise typer.Exit(code=1) from exc
    except (ValueError, OSError) as exc:
        _echo_error("Input system model failed validation.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    if check_generators:
        try:
            build_artifact_preview(model)
        except Exception as exc:
            _echo_error("Generator compatibility check failed.", detail=str(exc))
            raise typer.Exit(code=1) from exc

    typer.echo(f"Valid system model: schema {model.schema_version}.")
    if check_generators:
        typer.echo("All deterministic artifact generators passed; no files were written.")


@model_app.command("migrate")
def migrate_model(
    system_model: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
    ],
    target_version: Annotated[str, typer.Option("--to", help="Target schema version: 0.2.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="New output JSON path.")],
) -> None:
    """Write a deterministic 0.2 model without overwriting existing files."""

    try:
        if out.resolve() == system_model.resolve():
            raise ValueError("Migration output must not overwrite the input model.")
        model = read_versioned_system_model(system_model)
        migrated = migrate_system_model(
            model.model_dump(mode="json", exclude_none=True), target_version=target_version
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8") as destination:
            destination.write(json.dumps(migrated, indent=2, sort_keys=True) + "\n")
    except ValidationError as exc:
        _echo_error("Input system model failed validation.", detail=_validation_detail(exc))
        raise typer.Exit(code=1) from exc
    except FileExistsError as exc:
        _echo_error("Migration output already exists.", hint="Choose a new --out path.")
        raise typer.Exit(code=1) from exc
    except (ValueError, OSError) as exc:
        _echo_error("Model migration failed.", detail=str(exc))
        raise typer.Exit(code=1) from exc

    typer.echo(f"Wrote {out} (schema {target_version}).")


def _echo_error(message: str, *, detail: str | None = None, hint: str | None = None) -> None:
    """Print a compact, user-facing CLI error without source content."""

    typer.echo(f"Error: {message}", err=True)
    if detail:
        typer.echo(f"Detail: {detail}", err=True)
    if hint:
        typer.echo(f"Hint: {hint}", err=True)


def _echo_next_steps(review_path: Path, questions_path: Path) -> None:
    """Point first-time users to the two most actionable artifacts."""

    typer.echo(f"Next: open {review_path} for the summary, then {questions_path} for unknowns.")


def _validation_detail(error: ValidationError) -> str:
    """Summarize pydantic validation failures for CLI output."""

    details: list[str] = []
    for item in error.errors()[:3]:
        location = ".".join(str(part) for part in item.get("loc", ())) or "model"
        details.append(f"{location}: {item.get('msg', 'invalid value')}")
    remaining = len(error.errors()) - len(details)
    if remaining > 0:
        details.append(f"...and {remaining} more validation error(s)")
    return "; ".join(details)


if __name__ == "__main__":
    app()
