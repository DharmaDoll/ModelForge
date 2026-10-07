"""Project-local provenance is portable without obscuring external inputs."""

import shutil
from pathlib import Path

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.evidence import relativize_project_paths
from threatmodel_ai.model.schema import Evidence, SourceType, SystemModel, Unknown
from threatmodel_ai.pipeline import analyze_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"
ARTIFACTS = (
    "system_model.json",
    "dfd.mmd",
    "threats.md",
    "attack.md",
    "risk.md",
    "questions.md",
    "review.md",
    "ingestion.json",
)


def test_relocated_project_produces_identical_artifacts_without_local_paths(
    tmp_path: Path,
) -> None:
    projects = (tmp_path / "first", tmp_path / "second")
    outputs = (tmp_path / "out-first", tmp_path / "out-second")
    for project, output in zip(projects, outputs, strict=True):
        shutil.copytree(FIXTURE, project)
        analyze_project(discover_inputs(project), output)
        for artifact in ARTIFACTS:
            assert str(project) not in (output / artifact).read_text(encoding="utf-8")

    for artifact in ARTIFACTS:
        assert (outputs[0] / artifact).read_bytes() == (outputs[1] / artifact).read_bytes()


def test_conflicting_evidence_paths_are_relativized_without_mutating_input(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = str(project / "main.tf")
    model = SystemModel(
        unknowns=[
            Unknown(
                id="unknown:conflict",
                category="model_conflict",
                description="Contradictory declarations.",
                evidence=Evidence(source_type=SourceType.TERRAFORM, source_path=source),
                conflicting_evidence=[
                    Evidence(source_type=SourceType.TERRAFORM, source_path=source, line=2)
                ],
            )
        ],
        metadata={"terraform_files": [source]},
    )

    portable = relativize_project_paths(model, project)

    assert portable.unknowns[0].evidence.source_path == "main.tf"
    assert portable.unknowns[0].conflicting_evidence[0].source_path == "main.tf"
    assert portable.metadata["terraform_files"] == ["main.tf"]
    assert model.unknowns[0].evidence.source_path == source


def test_explicit_input_outside_project_retains_absolute_pointer(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external" / "README.md"
    external.parent.mkdir()
    external.write_text("# External service\n", encoding="utf-8")

    result = analyze_project(
        discover_inputs(project, readme=external), tmp_path / "out"
    )

    assert result.model.metadata["readme_path"] == str(external)
    assert str(external) in result.system_model_path.read_text(encoding="utf-8")
