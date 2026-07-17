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

    assert result.system_model_path.exists()
    assert result.dfd_path.exists()
    assert result.threats_path.exists()
    assert result.attack_path.exists()
    assert result.questions_path.exists()
    assert read_system_model(result.system_model_path).nodes
    assert "flowchart LR" in result.dfd_path.read_text(encoding="utf-8")
    assert "Spoofing" in result.threats_path.read_text(encoding="utf-8")
    assert "MITRE ATT&CK" in result.attack_path.read_text(encoding="utf-8")
    assert "authentication" in result.questions_path.read_text(encoding="utf-8")


def test_cli_analyze_writes_artifacts(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["analyze", str(FIXTURE), "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "system_model.json").exists()
    assert (tmp_path / "dfd.mmd").exists()
    assert (tmp_path / "threats.md").exists()
    assert (tmp_path / "attack.md").exists()
    assert (tmp_path / "questions.md").exists()


def test_discover_inputs_rejects_missing_explicit_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        discover_inputs(FIXTURE, readme=tmp_path / "missing.md")
