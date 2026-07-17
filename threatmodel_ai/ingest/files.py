"""File discovery for README, OpenAPI, Terraform, and Markdown doc inputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AnalysisInputs:
    """Concrete input files selected for one analysis run."""

    target: Path
    readme: Path | None
    openapi: Path | None
    terraform: tuple[Path, ...]
    docs: tuple[Path, ...]


def discover_inputs(
    target: Path,
    *,
    readme: Path | None = None,
    openapi: Path | None = None,
    terraform: tuple[Path, ...] | None = None,
    docs: tuple[Path, ...] | None = None,
) -> AnalysisInputs:
    """Resolve explicit or auto-discovered MVP input files."""

    target = target.resolve()
    readme_path = (
        _resolve_existing_file(readme, "README")
        if readme
        else _find_first(target, ("README.md", "readme.md"))
    )
    openapi_path = (
        _resolve_existing_file(openapi, "OpenAPI")
        if openapi
        else _find_first(
            target,
            (
                "openapi.yaml",
                "openapi.yml",
                "openapi.json",
                "swagger.yaml",
                "swagger.yml",
                "swagger.json",
            ),
        )
    )
    terraform_paths = (
        tuple(_resolve_existing_file(path, "Terraform") for path in terraform)
        if terraform
        else tuple(
            sorted(
                path.resolve()
                for path in target.rglob("*.tf")
                if ".terraform" not in path.parts
            )
        )
    )
    docs_paths = (
        tuple(_resolve_existing_file(path, "Markdown doc") for path in docs)
        if docs
        else _find_markdown_docs(target, readme_path)
    )
    return AnalysisInputs(
        target=target,
        readme=readme_path if readme_path and readme_path.exists() else None,
        openapi=openapi_path if openapi_path and openapi_path.exists() else None,
        terraform=terraform_paths,
        docs=docs_paths,
    )


def _find_first(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def _resolve_existing_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"{label} input does not exist: {path}")
    if not resolved.is_file():
        raise ValueError(f"{label} input is not a file: {path}")
    return resolved


def _find_markdown_docs(root: Path, readme_path: Path | None) -> tuple[Path, ...]:
    readme_resolved = readme_path.resolve() if readme_path else None
    docs: list[Path] = []
    for path in root.rglob("*.md"):
        resolved = path.resolve()
        if resolved == readme_resolved:
            continue
        if _is_ignored_path(resolved):
            continue
        docs.append(resolved)
    return tuple(sorted(docs))


def _is_ignored_path(path: Path) -> bool:
    ignored_parts = {".git", ".terraform", ".venv", "node_modules", "__pycache__"}
    return any(part in ignored_parts for part in path.parts)
