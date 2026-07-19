from pathlib import Path

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.pipeline import analyze_project
from threatmodel_ai.questions import generate_questions
from threatmodel_ai.stride import StrideCategory, generate_threats

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


def test_stride_engine_generates_all_entrypoint_categories(tmp_path: Path) -> None:
    model = analyze_project(discover_inputs(FIXTURE), tmp_path).model

    threats = generate_threats(model)
    categories = {threat.category for threat in threats}

    assert StrideCategory.SPOOFING in categories
    assert StrideCategory.TAMPERING in categories
    assert StrideCategory.REPUDIATION in categories
    assert StrideCategory.INFORMATION_DISCLOSURE in categories
    assert StrideCategory.DENIAL_OF_SERVICE in categories
    assert StrideCategory.ELEVATION_OF_PRIVILEGE in categories
    assert all(threat.derived_from for threat in threats)
    assert all(threat.evidence for threat in threats)


def test_question_generator_turns_unknowns_into_review_questions(tmp_path: Path) -> None:
    model = analyze_project(discover_inputs(FIXTURE), tmp_path).model

    questions = generate_questions(model)

    assert any(question.category == "authorization" for question in questions)
    assert any(question.category == "data_classification" for question in questions)
    assert any("rate limits" in question.question.lower() for question in questions)
    assert all(question.derived_from for question in questions)
    assert all(question.evidence for question in questions)
