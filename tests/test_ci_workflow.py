from pathlib import Path

import yaml

WORKFLOW_PATH = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"


def test_ci_workflow_enforces_deterministic_quality_gate() -> None:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    quality_job = workflow["jobs"]["quality"]
    steps = quality_job["steps"]
    commands = [step["run"] for step in steps if "run" in step]

    assert workflow["permissions"] == {"contents": "read"}
    assert quality_job["timeout-minutes"] == 10
    assert "uv sync --frozen --all-groups" in commands
    assert "uv run --frozen ruff check ." in commands
    assert "uv run --frozen pytest" in commands
    assert not any("--llm" in command for command in commands)

    action_step = next(step for step in steps if step.get("uses") == "./")
    assert action_step["with"] == {
        "target": "./examples/sample-system",
        "output-directory": "./ci-artifacts",
    }


def test_ci_workflow_uploads_generated_sample_artifacts() -> None:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["quality"]["steps"]
    upload_step = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")
    )

    assert upload_step["with"]["path"] == "${{ steps.model-forge.outputs.artifact-path }}"
    assert upload_step["with"]["if-no-files-found"] == "error"
