"""Typer CLI entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from threatmodel_ai.errors import ModelForgeError
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.pipeline import analyze_project

app = typer.Typer(help="Generate threat modeling artifacts from repository inputs.")


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
    out: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output directory for generated artifacts."),
    ] = Path("out"),
) -> None:
    """Analyze inputs and write deterministic threat modeling artifacts."""

    try:
        inputs = discover_inputs(
            target,
            readme=readme,
            openapi=openapi,
            terraform=tuple(terraform) if terraform else None,
        )
        result = analyze_project(inputs, out)
    except ModelForgeError as exc:
        _echo_error(exc.message, detail=exc.detail, hint=exc.hint)
        raise typer.Exit(code=1) from exc
    except FileNotFoundError as exc:
        _echo_error(
            "Input file was not found.",
            detail=str(exc),
            hint="Check the path passed to --readme, --openapi, or --terraform.",
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
