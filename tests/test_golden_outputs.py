from __future__ import annotations

import re
from difflib import unified_diff
from pathlib import Path

import pytest

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.pipeline import analyze_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"
GOLDEN = Path(__file__).parent / "fixtures" / "golden" / "sample-system"
ARTIFACTS = (
    "system_model.json",
    "dfd.mmd",
    "threats.md",
    "attack.md",
    "risk.md",
    "questions.md",
    "review.md",
)
NORMALIZED_FIXTURE_PATH = "tests/fixtures/sample-system"


@pytest.fixture(scope="module")
def generated_artifacts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate sample-system artifacts once for golden output comparisons."""

    output_dir = tmp_path_factory.mktemp("sample-system-golden-output")
    analyze_project(discover_inputs(FIXTURE), output_dir)
    return output_dir


@pytest.mark.parametrize("artifact", ARTIFACTS)
def test_sample_system_outputs_match_golden(generated_artifacts: Path, artifact: str) -> None:
    expected = _normalized_text(GOLDEN / artifact)
    actual = _normalized_text(generated_artifacts / artifact)

    assert actual == expected, _unified_diff(expected, actual, artifact)


def test_sample_starting_question_links_resolve_without_losing_questions(
    generated_artifacts: Path,
) -> None:
    review = (generated_artifacts / "review.md").read_text(encoding="utf-8")
    questions = (generated_artifacts / "questions.md").read_text(encoding="utf-8")

    links = re.findall(r"\[Open\]\(questions\.md#(question-group-[a-f0-9]+)\)", review)
    anchors = set(re.findall(r'<a id="(question-group-[a-f0-9]+)"></a>', questions))
    detail_ids = re.findall(r"^- ID: `(question:[^`]+)`$", questions, flags=re.MULTILINE)

    assert len(links) == 5
    assert set(links) <= anchors
    assert len(detail_ids) == len(set(detail_ids)) == 45


def test_sample_identity_suggestion_does_not_merge_dfd_nodes(
    generated_artifacts: Path,
) -> None:
    review = (generated_artifacts / "review.md").read_text(encoding="utf-8")
    dfd = (generated_artifacts / "dfd.mmd").read_text(encoding="utf-8")

    assert "Unresolved Identity Candidates" in review
    assert "Sample Payments API — possible pair (2 separate nodes)" in review
    assert "component:openapi:sample-payments-api" in review
    assert "component:readme:sample-payments-api" in review
    assert dfd.count("Sample Payments API\\n(component)") == 2


def _normalized_text(path: Path) -> str:
    """Normalize environment-specific paths before comparing golden outputs."""

    text = path.read_text(encoding="utf-8")
    return text.replace(str(FIXTURE.resolve()), NORMALIZED_FIXTURE_PATH)


def _unified_diff(expected: str, actual: str, artifact: str) -> str:
    diff = unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile=f"golden/{artifact}",
        tofile=f"actual/{artifact}",
    )
    return "\n" + "".join(diff)
