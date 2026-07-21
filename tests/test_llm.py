from pathlib import Path

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.llm import refine_questions
from threatmodel_ai.pipeline import analyze_project
from threatmodel_ai.questions import generate_questions

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


class FakeLLMClient:
    def __init__(self, response: str = "## Refined\n\n- Keep question IDs intact.") -> None:
        self.response = response
        self.instructions = ""
        self.input_text = ""

    def generate_text(self, *, instructions: str, input_text: str) -> str:
        self.instructions = instructions
        self.input_text = input_text
        return self.response


def test_refine_questions_uses_model_summary_and_preserves_non_authoritative_header(
    tmp_path: Path,
) -> None:
    result = analyze_project(discover_inputs(FIXTURE), tmp_path)
    questions = generate_questions(result.model)
    client = FakeLLMClient()

    refined = refine_questions(model=result.model, questions=questions, client=client)

    assert refined.startswith("# Refined Questions")
    assert "not the source of truth" in refined
    assert "Do not invent architecture" in client.instructions
    assert questions[0].id in client.input_text
    assert "nodes" in client.input_text
    assert "edges" in client.input_text
    assert "Sample service that accepts payment requests" not in client.input_text


def test_pipeline_writes_optional_refined_questions_artifact(tmp_path: Path) -> None:
    client = FakeLLMClient("## Review Questions\n\n- `question:1`: Confirm authentication.")

    result = analyze_project(
        discover_inputs(FIXTURE),
        tmp_path,
        llm_mode="refine-questions",
        llm_client=client,
    )

    assert result.questions_path.exists()
    assert result.questions_refined_path is not None
    assert result.questions_refined_path.exists()
    assert "Questions generated from unknown" in result.questions_path.read_text(
        encoding="utf-8"
    )
    refined = result.questions_refined_path.read_text(encoding="utf-8")
    assert "not the source of truth" in refined
    assert "Confirm authentication" in refined
