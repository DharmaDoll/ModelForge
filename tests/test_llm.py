from pathlib import Path

import pytest

from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.llm import (
    LLMCandidateValidationError,
    extract_readme_candidates,
    refine_questions,
)
from threatmodel_ai.model.io import read_system_model
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
