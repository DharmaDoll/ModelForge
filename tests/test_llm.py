import json
from pathlib import Path

import pytest

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.llm import (
    LLMCandidateValidationError,
    extract_readme_candidates,
    refine_questions,
)
from threatmodel_ai.llm.questions import LLMQuestionRefinementError
from threatmodel_ai.model.io import read_system_model
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.pipeline import analyze_project
from threatmodel_ai.questions import generate_questions

FIXTURE = Path(__file__).parent / "fixtures" / "sample-system"


class FakeLLMClient:
    def __init__(self, response: str | None = None) -> None:
        self.response = response
        self.instructions = ""
        self.input_text = ""
        self.json_schema: dict[str, object] | None = None

    def generate_text(
        self,
        *,
        instructions: str,
        input_text: str,
        json_schema: dict[str, object] | None = None,
    ) -> str:
        self.instructions = instructions
        self.input_text = input_text
        self.json_schema = json_schema
        if self.response is None:
            questions = json.loads(input_text)["questions"]
            return json.dumps(
                {
                    "questions": [
                        {"id": item["id"], "wording": f"Please clarify: {item['question']}"}
                        for item in questions
                    ]
                }
            )
        return self.response


def test_refine_questions_sends_minimal_payload_and_preserves_originals(
    tmp_path: Path,
) -> None:
    result = analyze_project(discover_inputs(FIXTURE), tmp_path)
    questions = generate_questions(result.model)
    client = FakeLLMClient()

    refined = refine_questions(model=result.model, questions=questions, client=client)

    assert refined.startswith("# Refined Questions")
    assert "not the source of truth" in refined
    assert "invent" in client.instructions
    assert questions[0].id in client.input_text
    assert questions[0].question in refined
    assert "Proposed wording" in refined
    assert client.json_schema is not None
    assert client.json_schema["additionalProperties"] is False
    assert "nodes" not in client.input_text
    assert "edges" not in client.input_text
    assert "source_path" not in client.input_text
    assert "Sample service that accepts payment requests" not in client.input_text


def test_pipeline_writes_optional_refined_questions_artifact(tmp_path: Path) -> None:
    client = FakeLLMClient()

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
    assert "Please clarify:" in refined


@pytest.mark.parametrize(
    "response",
    [
        "not json",
        '{"questions": []}',
        '{"questions": [{"id": "question:invented", "wording": "Invented?"}]}',
        '{"questions": [{"id": "question:invented", "wording": "First?"}, '
        '{"id": "question:invented", "wording": "Again?"}]}',
        '{"questions": [{"id": "question:invented", "wording": "Line one\\nLine two"}]}',
    ],
)
def test_refine_questions_rejects_unmatched_or_malformed_output(
    tmp_path: Path, response: str
) -> None:
    result = analyze_project(discover_inputs(FIXTURE), tmp_path / "source")

    with pytest.raises(LLMQuestionRefinementError):
        refine_questions(
            model=result.model,
            questions=generate_questions(result.model),
            client=FakeLLMClient(response),
        )


def test_refine_questions_rejects_duplicate_id_in_full_sized_response(tmp_path: Path) -> None:
    result = analyze_project(discover_inputs(FIXTURE), tmp_path / "source")
    questions = generate_questions(result.model)
    proposals = [{"id": item.id, "wording": item.question} for item in questions]
    proposals[1]["id"] = proposals[0]["id"]

    with pytest.raises(LLMQuestionRefinementError, match="changed the question IDs"):
        refine_questions(
            model=result.model,
            questions=questions,
            client=FakeLLMClient(json.dumps({"questions": proposals})),
        )


def test_refine_questions_skips_llm_when_no_questions() -> None:
    client = FakeLLMClient("not json")

    refined = refine_questions(model=SystemModel(), questions=[], client=client)

    assert "No clarification questions" in refined
    assert client.input_text == ""


def test_pipeline_keeps_deterministic_artifacts_when_refinement_is_invalid(tmp_path: Path) -> None:
    with pytest.raises(LLMQuestionRefinementError):
        analyze_project(
            discover_inputs(FIXTURE),
            tmp_path,
            llm_mode="refine-questions",
            llm_client=FakeLLMClient("not json"),
        )

    assert (tmp_path / "questions.md").exists()
    assert (tmp_path / "system_model.json").exists()
    assert not (tmp_path / "questions_refined.md").exists()


def test_extract_readme_candidates_validates_structured_llm_output() -> None:
    client = FakeLLMClient(
        """
        {
          "source_path": "README.md",
          "source_type": "readme",
          "nodes": [
            {
              "id": "actor:llm:customer",
              "name": "Customer",
              "type": "actor",
              "description": "Customer role stated in the README.",
              "confidence": 0.91,
              "evidence": [
                {
                  "source_type": "readme",
                  "source_path": "README.md",
                  "detail": "Actors",
                  "excerpt": "- Customer",
                  "line": 7
                }
              ]
            },
            {
              "id": "component:llm:payments-api",
              "name": "Payments API",
              "type": "component",
              "description": "Handles payment requests.",
              "confidence": 0.86,
              "evidence": [
                {
                  "source_type": "readme",
                  "source_path": "README.md",
                  "detail": "Components",
                  "excerpt": "- Payments API: handles payment requests.",
                  "line": 11
                }
              ]
            }
          ],
          "edges": [
            {
              "id": "edge:llm:customer-payments-api",
              "source": "actor:llm:customer",
              "target": "component:llm:payments-api",
              "type": "communicates_with",
              "description": "Customer interacts with the Payments API.",
              "protocol": "unknown",
              "authentication": "unknown",
              "authorization": "unknown",
              "data_assets": [],
              "confidence": 0.62,
              "evidence": [
                {
                  "source_type": "readme",
                  "source_path": "README.md",
                  "detail": "README summary",
                  "excerpt": "accepts payment requests",
                  "line": 3
                }
              ]
            }
          ],
          "unknowns": [
            {
              "id": "unknown:llm:authentication",
              "category": "authentication",
              "description": "Authentication is not specified in the README.",
              "related_element_id": "edge:llm:customer-payments-api",
              "confidence": 0.8,
              "evidence": [
                {
                  "source_type": "readme",
                  "source_path": "README.md",
                  "detail": "README",
                  "excerpt": "No authentication details are stated."
                }
              ]
            }
          ],
          "warnings": ["Review before merging into system_model.json."]
        }
        """
    )

    candidates = extract_readme_candidates(FIXTURE / "README.md", client)

    assert candidates.not_source_of_truth is True
    assert candidates.nodes[0].name == "Customer"
    assert candidates.edges[0].authentication == "unknown"
    assert candidates.unknowns[0].category == "authentication"
    assert "readme_text" in client.input_text


def test_extract_readme_candidates_rejects_invalid_json() -> None:
    client = FakeLLMClient("not json")

    with pytest.raises(LLMCandidateValidationError):
        extract_readme_candidates(FIXTURE / "README.md", client)


def test_pipeline_writes_llm_candidates_without_changing_system_model(tmp_path: Path) -> None:
    client = FakeLLMClient(
        """
        {
          "source_path": "README.md",
          "source_type": "readme",
          "nodes": [
            {
              "id": "component:llm:review-only-service",
              "name": "Review Only Service",
              "type": "component",
              "description": "LLM candidate only.",
              "confidence": 0.7,
              "evidence": [
                {
                  "source_type": "readme",
                  "source_path": "README.md",
                  "detail": "README",
                  "excerpt": "Sample service"
                }
              ]
            }
          ],
          "edges": [],
          "unknowns": [],
          "warnings": []
        }
        """
    )

    result = analyze_project(
        discover_inputs(FIXTURE),
        tmp_path,
        llm_mode="extract-readme",
        llm_client=client,
    )
    model = read_system_model(result.system_model_path)

    assert result.llm_candidates_path is not None
    assert result.llm_candidates_path.exists()
    assert "Review Only Service" in result.llm_candidates_path.read_text(encoding="utf-8")
    assert all(node.name != "Review Only Service" for node in model.nodes)
    assert result.questions_refined_path is None
