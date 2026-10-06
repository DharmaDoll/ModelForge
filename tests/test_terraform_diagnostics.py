"""Terraform diagnostics report recognized blocks without claiming HCL coverage."""

from pathlib import Path

from threatmodel_ai.extract.terraform import observe_terraform_with_diagnostics
from threatmodel_ai.model.observations import normalize_observation_batch
from threatmodel_ai.model.schema import NodeType


def test_terraform_diagnostics_count_resources_and_identity_collisions(
    tmp_path: Path,
) -> None:
    first = tmp_path / "main.tf"
    second = tmp_path / "module.tf"
    variables = tmp_path / "variables.tf"
    first.write_text('resource "aws_s3_bucket" "shared" {\n}\n', encoding="utf-8")
    second.write_text('resource "aws_s3_bucket" "shared" {\n}\n', encoding="utf-8")
    variables.write_text('variable "region" {\n  type = string\n}\n', encoding="utf-8")

    batch, metrics = observe_terraform_with_diagnostics((first, second, variables))
    model = normalize_observation_batch(batch)

    assert metrics.resource_blocks_recognized == 2
    assert metrics.distinct_resource_ids == 1
    assert metrics.colliding_resource_declarations == 1
    assert metrics.files_without_recognized_resources == 1
    assert not [node for node in model.nodes if node.type == NodeType.DATA_ASSET]
    conflict = next(item for item in model.unknowns if item.category == "model_conflict")
    assert conflict.evidence is not None
    assert conflict.conflicting_evidence is not None
    assert {conflict.evidence.source_path, conflict.conflicting_evidence[0].source_path} == {
        str(first),
        str(second),
    }


def test_terraform_collision_does_not_leave_edges_to_contested_resource(
    tmp_path: Path,
) -> None:
    first = tmp_path / "a.tf"
    second = tmp_path / "b.tf"
    first.write_text('resource "aws_vpc" "shared" {}\n', encoding="utf-8")
    second.write_text(
        'resource "aws_vpc" "shared" {}\n'
        'resource "aws_instance" "web" {\n  vpc_id = aws_vpc.shared.id\n}\n',
        encoding="utf-8",
    )

    batch, metrics = observe_terraform_with_diagnostics((first, second))
    model = normalize_observation_batch(batch)

    assert metrics.colliding_resource_declarations == 1
    assert not [node for node in model.nodes if node.type == NodeType.TRUST_BOUNDARY]
    assert len([node for node in model.nodes if node.type == NodeType.COMPONENT]) == 1
    assert not model.edges
    assert len([item for item in model.unknowns if item.category == "model_conflict"]) == 1


def test_terraform_diagnostics_do_not_count_non_resource_blocks_as_resources(
    tmp_path: Path,
) -> None:
    variables = tmp_path / "variables.tf"
    variables.write_text('variable "region" {\n  type = string\n}\n', encoding="utf-8")

    _, metrics = observe_terraform_with_diagnostics((variables,))

    assert metrics.resource_blocks_recognized == 0
    assert metrics.files_without_recognized_resources == 1
