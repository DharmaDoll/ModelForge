"""Human hypothesis triage stays separate from facts and confirmed findings."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.llm.hypotheses import ThreatHypothesisBatch, model_sha256
from threatmodel_ai.llm.review import (
    HypothesisDisposition,
    effective_dispositions,
    read_review_state,
    record_hypothesis_decision,
    write_review_state,
)
from threatmodel_ai.model.schema import Evidence, Node, NodeType, SourceType, SystemModel

RUNNER = CliRunner()


def _model() -> SystemModel:
    return SystemModel(
        id="service",
        nodes=[
            Node(
                id="api:payments",
                name="Payments API",
                type=NodeType.API,
                evidence=[
                    Evidence(
                        source_type=SourceType.OPENAPI,
                        source_path="openapi.yaml",
                        detail="POST /payments",
                    )
                ],
            )
        ],
    )


def _batch(model: SystemModel) -> ThreatHypothesisBatch:
    return ThreatHypothesisBatch.model_validate(
        {
            "schema_version": "0.1",
            "model_id": model.id,
            "model_schema_version": model.schema_version,
            "model_sha256": model_sha256(model),
            "not_source_of_truth": True,
            "hypotheses": [
                {
                    "id": "hypothesis:payment-replay",
                    "status": "proposed",
                    "title": "Payment replay",
                    "conditional_scenario": "If replay protection is absent, requests may repeat.",
                    "affected_element_ids": ["api:payments"],
                    "established_prerequisites": [
                        {
                            "statement": "The API accepts payment requests.",
                            "citations": [{"element_id": "api:payments", "evidence_index": 0}],
                        }
                    ],
                    "assumptions": [],
                    "missing_facts": ["Is replay protection present?"],
                    "verification_steps": ["Ask the developer."],
                    "provenance": {
                        "origin": "llm",
                        "model_name": "test-model",
                        "prompt_version": "v1",
                    },
                }
            ],
        }
    )


def test_decision_history_is_model_bound_and_not_a_finding(tmp_path: Path) -> None:
    model = _model()
    batch = _batch(model)
    reviewed_at = datetime(2026, 10, 7, 8, 30, tzinfo=UTC)
    first = record_hypothesis_decision(
        batch=batch,
        model=model,
        state=None,
        hypothesis_id="hypothesis:payment-replay",
        disposition=HypothesisDisposition.NEEDS_CONTEXT,
        reviewer="alice",
        rationale="Replay protection has not been described.",
        reviewed_at=reviewed_at,
    )
    second = record_hypothesis_decision(
        batch=batch,
        model=model,
        state=first,
        hypothesis_id="hypothesis:payment-replay",
        disposition=HypothesisDisposition.INVESTIGATE,
        reviewer="bob",
        rationale="Developer supplied a design note; verify implementation.",
        reviewed_at=reviewed_at,
    )
    path = tmp_path / "hypothesis_review.json"

    write_review_state(second, path)
    restored = read_review_state(path, batch=batch, model=model)

    assert len(restored.events) == 2
    assert restored.events[0].disposition == HypothesisDisposition.NEEDS_CONTEXT
    assert effective_dispositions(restored) == {
        "hypothesis:payment-replay": HypothesisDisposition.INVESTIGATE
    }
    assert batch.hypotheses[0].status == "proposed"
    assert model.nodes[0].name == "Payments API"


@pytest.mark.parametrize("field", ["reviewer", "rationale"])
def test_blank_human_attribution_or_reason_is_rejected(field: str) -> None:
    model = _model()
    kwargs = {"reviewer": "alice", "rationale": "Needs investigation."}
    kwargs[field] = "   "

    with pytest.raises(ValidationError):
        record_hypothesis_decision(
            batch=_batch(model),
            model=model,
            state=None,
            hypothesis_id="hypothesis:payment-replay",
            disposition=HypothesisDisposition.INVESTIGATE,
            **kwargs,
        )


def test_stale_model_or_changed_batch_cannot_inherit_review(tmp_path: Path) -> None:
    model = _model()
    batch = _batch(model)
    state = record_hypothesis_decision(
        batch=batch,
        model=model,
        state=None,
        hypothesis_id="hypothesis:payment-replay",
        disposition=HypothesisDisposition.REJECTED,
        reviewer="alice",
        rationale="No meaningful attack path in the reviewed design.",
    )
    path = tmp_path / "review.json"
    write_review_state(state, path)

    changed_model = _model()
    changed_model.nodes[0].name = "Renamed API"
    with pytest.raises(ValueError, match="different model snapshot"):
        read_review_state(path, batch=batch, model=changed_model)

    changed_batch = _batch(model).model_copy(deep=True)
    changed_batch.hypotheses[0].title = "Updated hypothesis"
    with pytest.raises(ValueError, match="different hypothesis batch"):
        read_review_state(path, batch=changed_batch, model=model)


def test_missing_hypothesis_id_is_rejected() -> None:
    model = _model()
    with pytest.raises(ValueError, match="missing hypothesis"):
        record_hypothesis_decision(
            batch=_batch(model),
            model=model,
            state=None,
            hypothesis_id="hypothesis:missing",
            disposition=HypothesisDisposition.INVESTIGATE,
            reviewer="alice",
            rationale="Check this.",
        )


def test_cli_records_and_reads_triage_without_llm_or_model_mutation(tmp_path: Path) -> None:
    model = _model()
    batch = _batch(model)
    model_path = tmp_path / "model.json"
    hypotheses_path = tmp_path / "threat_hypotheses.json"
    state_path = tmp_path / "hypothesis_review.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    hypotheses_path.write_text(batch.model_dump_json(), encoding="utf-8")
    model_before = model_path.read_bytes()
    hypotheses_before = hypotheses_path.read_bytes()

    unreviewed = RUNNER.invoke(
        app,
        [
            "hypotheses",
            "review-status",
            str(hypotheses_path),
            "--model",
            str(model_path),
        ],
    )
    assert unreviewed.exit_code == 0, unreviewed.output
    assert "hypothesis:payment-replay: unreviewed" in unreviewed.output

    result = RUNNER.invoke(
        app,
        [
            "hypotheses",
            "decide",
            str(hypotheses_path),
            "--model",
            str(model_path),
            "--id",
            "hypothesis:payment-replay",
            "--disposition",
            "needs_context",
            "--reviewer",
            "alice",
            "--rationale",
            "Ask for implementation evidence.",
            "--state",
            str(state_path),
        ],
    )
    summary = RUNNER.invoke(
        app,
        [
            "hypotheses",
            "review-status",
            str(hypotheses_path),
            "--model",
            str(model_path),
            "--state",
            str(state_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert summary.exit_code == 0, summary.output
    assert "hypothesis:payment-replay: needs_context" in summary.output
    assert "no finding was accepted" in summary.output
    assert json.loads(state_path.read_text(encoding="utf-8"))["events"][0]["reviewer"] == "alice"
    assert model_path.read_bytes() == model_before
    assert hypotheses_path.read_bytes() == hypotheses_before


def test_cli_refuses_invalid_state_without_overwriting_it(tmp_path: Path) -> None:
    model = _model()
    batch = _batch(model)
    model_path = tmp_path / "model.json"
    hypotheses_path = tmp_path / "hypotheses.json"
    state_path = tmp_path / "review.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    hypotheses_path.write_text(batch.model_dump_json(), encoding="utf-8")
    state_path.write_text('{"invalid": true}', encoding="utf-8")
    original = state_path.read_bytes()

    result = RUNNER.invoke(
        app,
        [
            "hypotheses",
            "decide",
            str(hypotheses_path),
            "--model",
            str(model_path),
            "--id",
            "hypothesis:payment-replay",
            "--disposition",
            "investigate",
            "--reviewer",
            "alice",
            "--rationale",
            "Review this.",
            "--state",
            str(state_path),
        ],
    )

    assert result.exit_code == 1
    assert state_path.read_bytes() == original
