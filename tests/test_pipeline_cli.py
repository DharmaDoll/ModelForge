from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.io import read_system_model
from threatmodel_ai.pipeline import analyze_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


def test_pipeline_writes_all_mvp_artifacts(tmp_path: Path) -> None:
    inputs = discover_inputs(FIXTURE)
    result = analyze_project(inputs, tmp_path)
    model = read_system_model(result.system_model_path)

    assert result.system_model_path.exists()
    assert result.dfd_path.exists()
    assert result.threats_path.exists()
    assert result.attack_path.exists()
    assert result.risk_path.exists()
    assert result.questions_path.exists()
    assert model.nodes
    assert any(node.name == "Payments Gateway" for node in model.nodes)
    assert "flowchart LR" in result.dfd_path.read_text(encoding="utf-8")
    assert "Spoofing" in result.threats_path.read_text(encoding="utf-8")
    assert "MITRE ATT&CK" in result.attack_path.read_text(encoding="utf-8")
    assert "Risk Priorities" in result.risk_path.read_text(encoding="utf-8")
    assert "authentication" in result.questions_path.read_text(encoding="utf-8")


def test_cli_analyze_writes_artifacts(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["analyze", str(FIXTURE), "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "system_model.json").exists()
    assert (tmp_path / "dfd.mmd").exists()
    assert (tmp_path / "threats.md").exists()
    assert (tmp_path / "attack.md").exists()
    assert (tmp_path / "risk.md").exists()
    assert (tmp_path / "questions.md").exists()
    assert not (tmp_path / "questions_refined.md").exists()
    assert not (tmp_path / "llm_candidates.json").exists()


def test_cli_accepts_explicit_markdown_doc_with_mermaid(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    doc = project / "architecture.md"
    doc.write_text(
        "\n".join(
            [
                "```mermaid",
                "flowchart LR",
                '  Client["Client"] -->|gRPC| Api["API"]',
                "```",
            ]
        ),
        encoding="utf-8",
    )
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["analyze", str(project), "--doc", str(doc), "--out", str(tmp_path / "out")],
    )

    assert result.exit_code == 0, result.output
    model = read_system_model(tmp_path / "out" / "system_model.json")
    assert any(node.name == "API" for node in model.nodes)
    assert any(edge.protocol == "gRPC" for edge in model.edges)


def test_cli_llm_refinement_requires_api_key_after_deterministic_outputs(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["analyze", str(FIXTURE), "--out", str(tmp_path), "--llm", "refine-questions"],
        env={"OPENAI_API_KEY": ""},
    )

    assert result.exit_code == 1
    assert "OPENAI_API_KEY is required" in result.output
    assert (tmp_path / "system_model.json").exists()
    assert (tmp_path / "questions.md").exists()
    assert not (tmp_path / "questions_refined.md").exists()


def test_cli_llm_readme_extraction_requires_api_key_after_deterministic_outputs(
    tmp_path: Path,
) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["analyze", str(FIXTURE), "--out", str(tmp_path), "--llm", "extract-readme"],
        env={"OPENAI_API_KEY": ""},
    )

    assert result.exit_code == 1
    assert "OPENAI_API_KEY is required" in result.output
    assert (tmp_path / "system_model.json").exists()
    assert (tmp_path / "questions.md").exists()
    assert not (tmp_path / "llm_candidates.json").exists()


def test_cli_reports_missing_supported_inputs(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["analyze", str(tmp_path), "--out", str(tmp_path / "out")])

    assert result.exit_code == 1
    assert "No supported input files were found" in result.output
    assert "Hint:" in result.output


def test_cli_reports_missing_explicit_input_file(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURE),
            "--readme",
            str(tmp_path / "missing.md"),
            "--out",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 1
    assert "Input file was not found." in result.output
    assert "--readme" in result.output


def test_cli_reports_invalid_openapi_input(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "openapi.yaml").write_text(
        "info:\n  title: Missing version\npaths: {}\n",
        encoding="utf-8",
    )
    runner = CliRunner()

    result = runner.invoke(app, ["analyze", str(project), "--out", str(tmp_path / "out")])

    assert result.exit_code == 1
    assert "OpenAPI input is missing a version field" in result.output
    assert "Hint:" in result.output


def test_cli_reports_invalid_terraform_input(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.tf").write_text(
        'resource "aws_instance" "web" {\n  ami = "ami-123456"\n',
        encoding="utf-8",
    )
    runner = CliRunner()

    result = runner.invoke(app, ["analyze", str(project), "--out", str(tmp_path / "out")])

    assert result.exit_code == 1
    assert "Terraform input has an unterminated resource block" in result.output
    assert "terraform fmt/validate" in result.output


def test_discover_inputs_rejects_missing_explicit_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        discover_inputs(FIXTURE, readme=tmp_path / "missing.md")
