from __future__ import annotations

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
    "questions.md",
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
