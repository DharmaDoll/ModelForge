from pathlib import Path

import yaml

ACTION_PATH = Path(__file__).parents[1] / "action.yml"


def test_github_action_exposes_stable_paths() -> None:
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))

    assert action["inputs"]["target"]["default"] == "."
    assert action["inputs"]["output-directory"]["default"] == "model-forge-out"
    assert action["inputs"]["job-summary"]["default"] == "true"
    assert action["inputs"]["pr-comment"]["default"] == "false"
    assert action["inputs"]["github-token"]["default"] == ""
    assert action["inputs"]["fail-on-risk"]["default"] == "none"
    assert action["outputs"]["artifact-path"]["value"] == (
        "${{ steps.analyze.outputs.artifact-path }}"
    )
    assert action["outputs"]["system-model-path"]["value"] == (
        "${{ steps.analyze.outputs.system-model-path }}"
    )
    assert action["outputs"]["review-summary-path"]["value"] == (
        "${{ steps.analyze.outputs.review-summary-path }}"
    )


def test_github_action_runs_locked_deterministic_analysis() -> None:
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"

    steps = action["runs"]["steps"]
    setup_step = next(step for step in steps if step.get("uses", "").startswith("astral-sh/"))
    analyze_step = next(step for step in steps if step.get("id") == "analyze")

    assert setup_step["with"]["version"] == "0.11.21"
    assert setup_step["with"]["python-version"] == "3.12"
    assert setup_step["with"]["working-directory"] == "${{ github.action_path }}"
    assert 'uv run --frozen --project "$GITHUB_ACTION_PATH"' in analyze_step["run"]
    assert 'tm-ai analyze "$MODELFORGE_TARGET" --out "$MODELFORGE_OUTPUT"' in (
        analyze_step["run"]
    )
    assert "--llm" not in analyze_step["run"]


def test_github_action_pr_comment_is_opt_in_and_marker_scoped() -> None:
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    summary_step = next(step for step in steps if step["name"] == "Add ModelForge job summary")
    comment_step = next(
        step
        for step in steps
        if step["name"] == "Create or update ModelForge pull-request comment"
    )

    assert summary_step["if"] == "${{ inputs.job-summary == 'true' }}"
    assert summary_step["run"] == 'cat "$MODELFORGE_REVIEW" >> "$GITHUB_STEP_SUMMARY"'
    assert comment_step["if"] == "${{ inputs.pr-comment == 'true' }}"
    assert comment_step["env"]["GH_TOKEN"] == "${{ inputs.github-token }}"
    assert "<!-- modelforge-review -->" in comment_step["run"]
    assert "gh api --method PATCH" in comment_step["run"]
    assert "gh api --method POST" in comment_step["run"]
    assert "gh pr comment --edit-last" not in comment_step["run"]


def test_github_action_risk_gate_is_disabled_by_default_and_validated() -> None:
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    gate_step = next(
        step for step in action["runs"]["steps"] if step["name"] == "Enforce ModelForge risk gate"
    )

    assert gate_step["if"] == "${{ inputs.fail-on-risk != 'none' }}"
    assert gate_step["env"]["MODELFORGE_MODEL"] == (
        "${{ steps.analyze.outputs.system-model-path }}"
    )
    assert "high|medium|low" in gate_step["run"]
    assert 'tm-ai check "$MODELFORGE_MODEL" --fail-on "$MODELFORGE_THRESHOLD"' in (
        gate_step["run"]
    )
