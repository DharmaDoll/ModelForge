"""Terraform identities and references stay inside their source module."""

import json
from pathlib import Path

from threatmodel_ai.extract.terraform import (
    extract_terraform,
    observe_terraform_with_diagnostics,
)
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import EdgeType, NodeType
from threatmodel_ai.pipeline import analyze_project


def _write_two_modules(root: Path) -> tuple[Path, Path]:
    files: list[Path] = []
    for name in ("orders", "payments"):
        directory = root / "modules" / name
        directory.mkdir(parents=True)
        path = directory / "main.tf"
        path.write_text(
            '\n'.join(
                [
                    'resource "aws_vpc" "shared" {}',
                    'resource "aws_instance" "web" {',
                    '  vpc_id = aws_vpc.shared.id',
                    '}',
                ]
            ),
            encoding="utf-8",
        )
        files.append(path)
    return files[0], files[1]


def test_same_named_resources_in_distinct_modules_have_distinct_ids(
    tmp_path: Path,
) -> None:
    files = _write_two_modules(tmp_path)
    batch, metrics = observe_terraform_with_diagnostics(files, identity_root=tmp_path)
    model = extract_terraform(files, identity_root=tmp_path)

    assert batch.observations
    assert metrics.resource_blocks_recognized == 4
    assert metrics.distinct_resource_ids == 4
    assert metrics.colliding_resource_declarations == 0
    vpcs = [node for node in model.nodes if node.type == NodeType.TRUST_BOUNDARY]
    instances = [
        node for node in model.nodes if node.metadata.get("terraform_type") == "aws_instance"
    ]
    references = [edge for edge in model.edges if edge.type == EdgeType.REFERENCES]
    assert len(vpcs) == len(instances) == len(references) == 2
    assert len({node.id for node in vpcs}) == 2
    assert len({node.id for node in instances}) == 2
    assert {node.trust_boundary_id for node in instances} == {node.id for node in vpcs}
    assert {edge.source for edge in references} == {node.id for node in instances}
    assert {edge.target for edge in references} == {node.id for node in vpcs}


def test_module_ids_are_checkout_independent_and_root_ids_unchanged(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_files = _write_two_modules(first_root)
    second_files = _write_two_modules(second_root)
    for root in (first_root, second_root):
        (root / "main.tf").write_text('resource "aws_s3_bucket" "root" {}\n', encoding="utf-8")

    first = extract_terraform((*first_files, first_root / "main.tf"), identity_root=first_root)
    second = extract_terraform((*second_files, second_root / "main.tf"), identity_root=second_root)

    assert {node.id for node in first.nodes} == {node.id for node in second.nodes}
    assert make_id("terraform", "aws_s3_bucket", "root") in {node.id for node in first.nodes}


def test_pipeline_keeps_module_resources_distinct(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_two_modules(project)

    result = analyze_project(discover_inputs(project), tmp_path / "out")
    metrics = json.loads(result.ingestion_path.read_text(encoding="utf-8"))

    assert len([node for node in result.model.nodes if node.type == NodeType.TRUST_BOUNDARY]) == 2
    assert metrics["terraform_parse"]["colliding_resource_declarations"] == 0


def test_pipeline_turns_same_module_collision_into_question(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.tf").write_text('resource "aws_vpc" "shared" {}\n', encoding="utf-8")
    (project / "b.tf").write_text('resource "aws_vpc" "shared" {}\n', encoding="utf-8")

    result = analyze_project(discover_inputs(project), tmp_path / "out")

    conflict = next(item for item in result.model.unknowns if item.category == "model_conflict")
    assert conflict.conflicting_evidence is not None
    assert not [node for node in result.model.nodes if node.type == NodeType.TRUST_BOUNDARY]
    assert "Which conflicting source claim is correct?" in result.questions_path.read_text(
        encoding="utf-8"
    )
