import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.llm import (
    LLMCandidateModel,
    LLMCandidateValidationError,
    merge_llm_candidates,
    read_llm_candidates,
)
from threatmodel_ai.model.io import read_system_model, write_system_model
from threatmodel_ai.model.schema import Evidence, Node, NodeType, SourceType, SystemModel
from threatmodel_ai.questions import generate_questions


def test_merge_candidates_adds_reviewed_facts_and_preserves_base_model() -> None:
    base = _base_model()
    candidates = _candidate_model(
        {
            "nodes": [_candidate_node("component:llm:payments-api", "Payments API")],
            "edges": [
                _candidate_edge(
                    "edge:llm:customer-payments-api",
                    source="actor:readme:customer",
                    target="component:llm:payments-api",
                )
            ],
            "unknowns": [
                _candidate_unknown(
                    "unknown:llm:payments-api-auth",
                    related_element_id="edge:llm:customer-payments-api",
                )
            ],
        },
        base,
    )

    result = merge_llm_candidates(base, candidates, min_confidence=0.75)

    assert result.merged_nodes == 1
    assert result.merged_edges == 1
    assert result.merged_unknowns == 1
    assert result.review_unknowns == 0
    assert any(node.id == "component:llm:payments-api" for node in result.model.nodes)
    assert any(edge.source == "actor:readme:customer" for edge in result.model.edges)
    assert any(
        unknown.related_element_id == "edge:llm:customer-payments-api"
        for unknown in result.model.unknowns
    )
    assert next(node for node in result.model.nodes if node.id == "actor:readme:customer").name == (
        "Customer"
    )
    merge_metadata = result.model.metadata["llm_candidate_merges"][0]
    assert merge_metadata["merged_nodes"] == 1


def test_merge_candidates_questionizes_conflicts_and_low_confidence_candidates() -> None:
    base = _base_model(
        extra_nodes=[
            Node(
                id="component:llm:payments-api",
                name="Existing Payments API",
                type=NodeType.COMPONENT,
                evidence=[_evidence()],
            )
        ]
    )
    candidates = _candidate_model(
        {
            "nodes": [
                _candidate_node("component:llm:payments-api", "LLM Payments API"),
                _candidate_node("component:llm:low-confidence", "Low Confidence", confidence=0.4),
            ],
            "edges": [
                _candidate_edge(
                    "edge:llm:customer-low-confidence",
                    source="actor:readme:customer",
                    target="component:llm:low-confidence",
                    confidence=0.9,
                )
            ],
            "unknowns": [],
        },
        base,
    )

    result = merge_llm_candidates(base, candidates, min_confidence=0.75)

    assert result.merged_nodes == 0
    assert result.merged_edges == 0
    assert result.review_unknowns == 3
    assert next(
        node for node in result.model.nodes if node.id == "component:llm:payments-api"
    ).name == "Existing Payments API"
    assert all(node.id != "component:llm:low-confidence" for node in result.model.nodes)
    questions = generate_questions(result.model)
    assert any(
        question.category == "llm_candidate_review"
        and "Should this LLM candidate be accepted" in question.question
        for question in questions
    )
    assert {rejection.kind for rejection in result.rejected} == {"node", "edge"}


def test_read_llm_candidates_allows_base_model_references(tmp_path: Path) -> None:
    base = _base_model()
    candidate_path = tmp_path / "llm_candidates.json"
    _write_candidates(
        candidate_path,
        {
            "nodes": [_candidate_node("component:llm:payments-api", "Payments API")],
            "edges": [
                _candidate_edge(
                    "edge:llm:customer-payments-api",
                    source="actor:readme:customer",
                    target="component:llm:payments-api",
                )
            ],
            "unknowns": [],
        },
    )

    candidates = read_llm_candidates(candidate_path, base_model=base)

    assert candidates.edges[0].source == "actor:readme:customer"


def test_read_llm_candidates_rejects_missing_references(tmp_path: Path) -> None:
    candidate_path = tmp_path / "llm_candidates.json"
    _write_candidates(
        candidate_path,
        {
            "nodes": [_candidate_node("component:llm:payments-api", "Payments API")],
            "edges": [
                _candidate_edge(
                    "edge:llm:customer-payments-api",
                    source="actor:missing",
                    target="component:llm:payments-api",
                )
            ],
            "unknowns": [],
        },
    )

    with pytest.raises(LLMCandidateValidationError) as exc_info:
        read_llm_candidates(candidate_path, base_model=_base_model())

    assert "missing source" in str(exc_info.value.detail)


def test_cli_candidates_merge_writes_new_model_without_overwriting_input(tmp_path: Path) -> None:
    base_path = tmp_path / "system_model.json"
    candidate_path = tmp_path / "llm_candidates.json"
    out_path = tmp_path / "system_model.merged.json"
    write_system_model(_base_model(), base_path)
    _write_candidates(
        candidate_path,
        {
            "nodes": [_candidate_node("component:llm:payments-api", "Payments API")],
            "edges": [],
            "unknowns": [],
        },
    )
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["candidates", "merge", str(base_path), str(candidate_path), "--out", str(out_path)],
    )

    assert result.exit_code == 0, result.output
    assert "Merged 1 node(s), 0 edge(s), 0 unknown(s)." in result.output
    merged_model = read_system_model(out_path)
    base_model = read_system_model(base_path)
    assert any(node.id == "component:llm:payments-api" for node in merged_model.nodes)
    assert all(
        node.id != "component:llm:payments-api" for node in base_model.nodes
    )


def test_cli_candidates_merge_reports_invalid_candidate_file(tmp_path: Path) -> None:
    base_path = tmp_path / "system_model.json"
    candidate_path = tmp_path / "llm_candidates.json"
    write_system_model(_base_model(), base_path)
    candidate_path.write_text("{not json", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "candidates",
            "merge",
            str(base_path),
            str(candidate_path),
            "--out",
            str(tmp_path / "merged.json"),
        ],
    )

    assert result.exit_code == 1
    assert "LLM candidate file failed validation." in result.output
    assert "Hint:" in result.output


def _base_model(*, extra_nodes: list[Node] | None = None) -> SystemModel:
    return SystemModel(
        name="Sample API",
        nodes=[
            Node(
                id="actor:readme:customer",
                name="Customer",
                type=NodeType.ACTOR,
                evidence=[_evidence()],
            ),
            *(extra_nodes or []),
        ],
    )


def _candidate_model(
    overrides: dict[str, object],
    base_model: SystemModel,
) -> LLMCandidateModel:
    payload = _candidate_payload(overrides)
    node_ids = {node.id for node in base_model.nodes}
    edge_ids = {edge.id for edge in base_model.edges}
    return LLMCandidateModel.model_validate(
        payload,
        context={
            "allowed_node_ids": node_ids,
            "allowed_element_ids": node_ids | edge_ids,
        },
    )


def _write_candidates(path: Path, overrides: dict[str, object]) -> None:
    path.write_text(
        json.dumps(_candidate_payload(overrides), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _candidate_payload(overrides: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {
        "source_path": "README.md",
        "source_type": "readme",
        "nodes": [],
        "edges": [],
        "unknowns": [],
        "warnings": [],
    }
    payload.update(overrides)
    return payload


def _candidate_node(
    candidate_id: str,
    name: str,
    *,
    confidence: float = 0.9,
) -> dict[str, object]:
    return {
        "id": candidate_id,
        "name": name,
        "type": "component",
        "description": f"{name} described in README.",
        "confidence": confidence,
        "evidence": [_candidate_evidence()],
    }


def _candidate_edge(
    candidate_id: str,
    *,
    source: str,
    target: str,
    confidence: float = 0.9,
) -> dict[str, object]:
    return {
        "id": candidate_id,
        "source": source,
        "target": target,
        "type": "communicates_with",
        "description": "Customer calls the API.",
        "protocol": "unknown",
        "authentication": "unknown",
        "authorization": "unknown",
        "data_assets": [],
        "confidence": confidence,
        "evidence": [_candidate_evidence()],
    }


def _candidate_unknown(
    candidate_id: str,
    *,
    related_element_id: str | None,
    confidence: float = 0.9,
) -> dict[str, object]:
    return {
        "id": candidate_id,
        "category": "authentication",
        "description": "Authentication is not specified.",
        "related_element_id": related_element_id,
        "confidence": confidence,
        "evidence": [_candidate_evidence()],
    }


def _candidate_evidence() -> dict[str, object]:
    return {
        "source_type": "readme",
        "source_path": "README.md",
        "detail": "README",
        "excerpt": "Payments API",
        "line": 1,
    }


def _evidence() -> Evidence:
    return Evidence(
        source_type=SourceType.README,
        source_path="README.md",
        extractor="readme",
        detail="README",
        line=1,
    )
