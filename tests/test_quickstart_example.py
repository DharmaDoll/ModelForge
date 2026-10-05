"""Keep the public Quick Start walkthrough aligned with the bundled example."""

from pathlib import Path

from typer.testing import CliRunner

from threatmodel_ai.cli.app import app

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-system"


def test_quickstart_example_supports_review_scenarios(tmp_path: Path) -> None:
    """The sample produces the evidence, questions, and gate behavior in the guide."""

    runner = CliRunner()
    output = tmp_path / "sample-system"

    analysis = runner.invoke(app, ["analyze", str(EXAMPLE), "--out", str(output)])

    assert analysis.exit_code == 0, analysis.output
    assert f"Next: open {output / 'review.md'}" in analysis.output
    assert "LLM: off; no external API was called." in analysis.output
    assert "payments-public-lb" in (output / "risk.md").read_text(encoding="utf-8")
    dfd = (output / "dfd.mmd").read_text(encoding="utf-8")
    assert "Application Boundary" in dfd
    assert "aws_subnet.private" in dfd
    questions = (output / "questions.md").read_text(encoding="utf-8")
    assert "What authorization checks protect GET /payments/{paymentId}?" in questions
    assert "What rate limits protect POST /payments?" in questions

    model_path = str(output / "system_model.json")
    high = runner.invoke(app, ["check", model_path, "--fail-on", "high"])
    low = runner.invoke(app, ["check", model_path, "--fail-on", "low"])

    assert high.exit_code == 0, high.output
    assert low.exit_code == 1, low.output
