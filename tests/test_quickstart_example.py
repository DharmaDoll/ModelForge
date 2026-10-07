"""Keep the public Quick Start walkthrough aligned with the bundled example."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-system"


def test_quickstart_example_supports_review_scenarios(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sample produces the evidence, questions, and gate behavior in the guide."""

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    runner = CliRunner()
    output = tmp_path / "sample-system"

    analysis = runner.invoke(app, ["analyze", str(EXAMPLE), "--out", str(output)])

    assert analysis.exit_code == 0, analysis.output
    assert f"Next: open {output / 'review.md'}" in analysis.output
    assert "LLM: off; no external API was called." in analysis.output
    artifacts = (
        "system_model.json",
        "dfd.mmd",
        "threats.md",
        "attack.md",
        "risk.md",
        "questions.md",
        "review.md",
        "ingestion.json",
    )
    assert all((output / artifact).exists() for artifact in artifacts)
    assert "payments-public-lb" in (output / "risk.md").read_text(encoding="utf-8")
    dfd = (output / "dfd.mmd").read_text(encoding="utf-8")
    assert "Application Boundary" in dfd
    assert "aws_subnet.private" in dfd
    questions = (output / "questions.md").read_text(encoding="utf-8")
    assert "What authorization checks protect GET /payments/{paymentId}?" in questions
    assert "What rate limits protect POST /payments?" in questions

    model_path = str(output / "system_model.json")
    validation = runner.invoke(app, ["model", "validate", model_path])
    assert validation.exit_code == 0, validation.output
    assert "Valid system model: schema 0.1." in validation.output

    context_path = output / "challenger_context.preview.json"
    context_preview = runner.invoke(
        app,
        [
            "hypotheses",
            "preview-context",
            model_path,
            "--element",
            "api:post:payments",
            "--out",
            str(context_path),
        ],
    )
    assert context_preview.exit_code == 0, context_preview.output
    assert "No external API was called" in context_preview.output
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert "api:post:payments" in {node["id"] for node in context["nodes"]}
    assert "source_path" not in context_path.read_text(encoding="utf-8")

    rerun = tmp_path / "sample-system-rerun"
    repeat = runner.invoke(app, ["analyze", str(EXAMPLE), "--out", str(rerun)])
    assert repeat.exit_code == 0, repeat.output
    assert all((output / name).read_bytes() == (rerun / name).read_bytes() for name in artifacts)

    high = runner.invoke(app, ["check", model_path, "--fail-on", "high"])
    low = runner.invoke(app, ["check", model_path, "--fail-on", "low"])

    assert high.exit_code == 0, high.output
    assert low.exit_code == 1, low.output
