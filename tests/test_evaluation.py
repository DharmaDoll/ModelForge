"""Labeled-probe metrics and deterministic seed-case evaluation."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.evaluation import evaluate_manifest
from threatmodel_ai.evaluation.engine import _probe_value, _valid_model_selector
from threatmodel_ai.evaluation.models import (
    EvaluationCase,
    EvaluationManifest,
    Lens,
    Metrics,
    Probe,
    ProbeResult,
)

MANIFEST = Path(__file__).parent / "fixtures" / "evaluation" / "manifest.json"


def test_seed_cases_have_no_labeled_probe_mismatches() -> None:
    report = evaluate_manifest(MANIFEST)

    assert report.case_count == 6
    assert report.labeled_probe_count == 61
    assert report.expert_reviewed_probe_count == 0
    assert all(result.expected == result.actual for result in report.results)
    assert report.micro.fp == 0
    assert report.micro.fn == 0
    assert report.by_lens[Lens.MODEL].precision == 1.0
    assert report.by_lens[Lens.ATTACK].fpr == 0.0
    assert any(
        result.case_id == "terraform-ambiguous-lb-exposure"
        and result.lens == Lens.QUESTION
        and result.selector == "internet_exposure"
        and result.actual
        for result in report.results
    )


def test_evaluation_is_deterministic_and_never_calls_an_llm() -> None:
    first = evaluate_manifest(MANIFEST)
    second = evaluate_manifest(MANIFEST)

    assert first == second


def test_evaluation_cli_reports_seed_status_and_json() -> None:
    summary = CliRunner().invoke(app, ["evaluate", str(MANIFEST)])
    details = CliRunner().invoke(app, ["evaluate", str(MANIFEST), "--json"])

    assert summary.exit_code == 0, summary.output
    assert "61 labeled probe(s)" in summary.output
    assert "Expert-reviewed probes: 0" in summary.output
    assert "seed labels are not a gold standard" in summary.output
    assert "Labeled-probe mismatches: 0" in summary.output
    assert details.exit_code == 0, details.output
    assert '"expert_reviewed_probe_count": 0' in details.output


def test_metrics_use_correct_denominators_and_undefined_ratios() -> None:
    results = [
        _result(expected=True, actual=True),
        _result(expected=False, actual=True),
        _result(expected=False, actual=False),
        _result(expected=True, actual=False),
    ]

    metrics = Metrics.from_results(results)

    assert (metrics.tp, metrics.fp, metrics.tn, metrics.fn) == (1, 1, 1, 1)
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.false_candidate_rate == 0.5
    assert metrics.fpr == 0.5
    assert metrics.fnr == 0.5

    no_predictions = Metrics.from_results([_result(expected=False, actual=False)])
    assert no_predictions.precision is None
    assert no_predictions.recall is None
    assert no_predictions.false_candidate_rate is None
    assert no_predictions.fpr == 0.0
    assert no_predictions.fnr is None


def test_manifest_rejects_duplicate_or_unreviewed_expert_labels() -> None:
    probe = Probe(
        lens=Lens.ATTACK,
        selector="T1190",
        expected=False,
        rationale="No public entry point is evidenced.",
    )
    with pytest.raises(ValidationError, match="require a reviewer"):
        EvaluationCase(
            id="case-one",
            project="private-lb",
            review_status="expert_reviewed",
            probes=[probe],
        )
    with pytest.raises(ValidationError, match="duplicate probes"):
        EvaluationCase(id="case-one", project="private-lb", probes=[probe, probe])
    case = EvaluationCase(id="case-one", project="private-lb", probes=[probe])
    with pytest.raises(ValidationError, match="duplicate case ids"):
        EvaluationManifest(cases=[case, case])
    with pytest.raises(ValidationError):
        EvaluationCase(id="../escape", project="private-lb", probes=[probe])


def test_authentication_selector_requires_a_concrete_edge_and_state() -> None:
    assert _valid_model_selector("auth:edge:actor-client:api-get-orders:request:known")
    assert not _valid_model_selector("auth:edge::known")
    assert not _valid_model_selector("auth:edge:actor-client:api-get-orders:request:maybe")


@pytest.mark.parametrize(
    ("lens", "selector"),
    [(Lens.STRIDE, "entrypoint-spofing"), (Lens.ATTACK, "T119O")],
)
def test_evaluation_rejects_typoed_rule_and_technique_selectors(
    lens: Lens, selector: str
) -> None:
    probe = Probe(lens=lens, selector=selector, expected=False, rationale="A typo must fail.")

    with pytest.raises(ValueError, match="unsupported"):
        _probe_value(probe, {item: set() for item in Lens})


def _result(*, expected: bool, actual: bool) -> ProbeResult:
    return ProbeResult(
        case_id="case",
        review_status="seed",
        lens=Lens.MODEL,
        selector="public_entrypoint",
        expected=expected,
        actual=actual,
        rationale="Synthetic confusion-matrix test.",
    )
