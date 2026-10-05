"""Regenerate deterministic sample-system goldens after reviewing semantic changes."""

from pathlib import Path
from tempfile import TemporaryDirectory

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


def main() -> None:
    """Rebuild artifacts and remove environment-specific fixture prefixes."""

    with TemporaryDirectory() as temporary_directory:
        output = Path(temporary_directory)
        analyze_project(discover_inputs(FIXTURE), output)
        for artifact in ARTIFACTS:
            content = (output / artifact).read_text(encoding="utf-8")
            normalized = content.replace(str(FIXTURE.resolve()), "tests/fixtures/sample-system")
            (GOLDEN / artifact).write_text(normalized, encoding="utf-8")


if __name__ == "__main__":
    main()
