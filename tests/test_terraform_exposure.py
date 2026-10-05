"""Exposure uncertainty must remain explicit in Terraform-derived models."""

from pathlib import Path

import pytest

from threatmodel_ai.extract.terraform import extract_terraform
from threatmodel_ai.questions import generate_questions

FIXTURES = Path(__file__).parent / "fixtures" / "evaluation"


@pytest.mark.parametrize(
    ("case", "expected_unknown"),
    [("ambiguous-lb", True), ("private-lb", False), ("public-lb", False)],
)
def test_load_balancer_exposure_question_only_when_internal_is_unresolved(
    case: str, expected_unknown: bool
) -> None:
    """Names never decide exposure, while literal true and false settle it."""

    model = extract_terraform([FIXTURES / case / "main.tf"])
    unknowns = [item for item in model.unknowns if item.category == "internet_exposure"]
    questions = [
        item for item in generate_questions(model) if item.category == "internet_exposure"
    ]

    assert bool(unknowns) is expected_unknown
    assert bool(questions) is expected_unknown
    if expected_unknown:
        assert len(unknowns) == 1
        assert unknowns[0].evidence is not None
        assert questions[0].question == "Is public-facing-name-only internet-facing?"
