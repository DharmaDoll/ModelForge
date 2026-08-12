"""Typer CLI entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from threatmodel_ai.attack import generate_attack_findings
from threatmodel_ai.errors import ModelForgeError
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.llm import merge_llm_candidates, read_llm_candidates
from threatmodel_ai.model.io import read_system_model, write_system_model
from threatmodel_ai.pipeline import analyze_project, render_model_artifacts
from threatmodel_ai.risk import RiskThreshold, risks_at_or_above, score_risks
from threatmodel_ai.stride import generate_threats

app = typer.Typer(help="Generate threat modeling artifacts from repository inputs.")
candidates_app = typer.Typer(help="Review and merge LLM candidate artifacts.")
app.add_typer(candidates_app, name="candidates")


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
                "Optional LLM mode. Supported: refine-questions, extract-readme. "
                "Default: disabled."
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
    if result.questions_refined_path:
        typer.echo(f"Wrote {result.questions_refined_path}")
    if result.llm_candidates_path:
        typer.echo(f"Wrote {result.llm_candidates_path}")


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

    typer.echo(
        f"Risk gate passed: no risk candidates met or exceeded {fail_on.value}."
    )


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


def _echo_error(message: str, *, detail: str | None = None, hint: str | None = None) -> None:
    """Print a compact, user-facing CLI error without source content."""

    typer.echo(f"Error: {message}", err=True)
    if detail:
        typer.echo(f"Detail: {detail}", err=True)
    if hint:
        typer.echo(f"Hint: {hint}", err=True)


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
