"""Run deterministic projects against authored, explicitly bounded probes."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from threatmodel_ai.attack import generate_attack_findings
from threatmodel_ai.attack.catalog import TECHNIQUES
from threatmodel_ai.evaluation.models import (
    EvaluationManifest,
    EvaluationReport,
    Lens,
    Metrics,
    Probe,
    ProbeResult,
)
from threatmodel_ai.ingest import discover_inputs
from threatmodel_ai.model.exposure import is_explicit_public_entrypoint
from threatmodel_ai.model.schema import EdgeType, NodeType, SystemModel
from threatmodel_ai.pipeline import analyze_project
from threatmodel_ai.questions import generate_questions
from threatmodel_ai.risk import score_risks
from threatmodel_ai.stride import generate_threats
from threatmodel_ai.stride.engine import _RULES as STRIDE_RULES

_MODEL_SELECTORS = {
    "public_entrypoint",
    "configuration_reference",
    "runtime_storage",
    "known_authentication",
    "trust_boundary",
    "authentication_unknown",
}
_RISK_SELECTORS = {"any", "high", "medium", "low"}
_AUTH_STATES = {"known", "none", "unknown"}
_STRIDE_SELECTORS = {rule.id for rule in STRIDE_RULES}


def evaluate_manifest(path: Path) -> EvaluationReport:
    """Evaluate only authored probes; never treat unlabeled output as negative."""

    manifest = EvaluationManifest.model_validate_json(path.read_text(encoding="utf-8"))
    root = path.resolve().parent
    results: list[ProbeResult] = []
    with TemporaryDirectory(prefix="modelforge-eval-") as temporary_dir:
        for case in manifest.cases:
            project = (root / case.project).resolve()
            if not project.is_relative_to(root) or not project.is_dir():
                raise ValueError(f"evaluation case {case.id!r} has invalid project path")
            model = analyze_project(discover_inputs(project), Path(temporary_dir) / case.id).model
            predictions = _predictions(model)
            for probe in case.probes:
                actual = _probe_value(probe, predictions)
                results.append(
                    ProbeResult(
                        case_id=case.id,
                        review_status=case.review_status,
                        lens=probe.lens,
                        selector=probe.selector,
                        expected=probe.expected,
                        actual=actual,
                        rationale=probe.rationale,
                    )
                )

    by_lens = {
        lens: Metrics.from_results([result for result in results if result.lens == lens])
        for lens in Lens
    }
    return EvaluationReport(
        case_count=len(manifest.cases),
        labeled_probe_count=len(results),
        expert_reviewed_probe_count=sum(
            result.review_status == "expert_reviewed" for result in results
        ),
        by_lens=by_lens,
        micro=Metrics.from_results(results),
        results=results,
    )


def _predictions(model: SystemModel) -> dict[Lens, set[str]]:
    """Project candidate outputs to stable, coarse selectors for seed evaluation."""

    node_by_id = {node.id: node for node in model.nodes}
    model_selectors: set[str] = set()
    model_selectors.update(f"node:{node.id}:{node.type.value}" for node in model.nodes)
    if any(node.type == NodeType.TRUST_BOUNDARY for node in model.nodes):
        model_selectors.add("trust_boundary")
    if any(unknown.category == "authentication" for unknown in model.unknowns):
        model_selectors.add("authentication_unknown")
    for edge in model.edges:
        model_selectors.add(f"edge:{edge.source}->{edge.target}:{edge.type.value}")
        authentication_state = (
            "unknown"
            if edge.authentication in {"unknown", ""}
            else "none" if edge.authentication == "none" else "known"
        )
        model_selectors.add(f"auth:{edge.id}:{authentication_state}")
        if edge.type == EdgeType.REFERENCES:
            model_selectors.add("configuration_reference")
        if edge.type == EdgeType.STORES:
            model_selectors.add("runtime_storage")
        if edge.type == EdgeType.COMMUNICATES_WITH and edge.authentication not in {
            "unknown",
            "none",
            "",
        }:
            model_selectors.add("known_authentication")
        source = node_by_id[edge.source]
        target = node_by_id[edge.target]
        if is_explicit_public_entrypoint(edge, source, target):
            model_selectors.add("public_entrypoint")

    threats = generate_threats(model)
    attacks = generate_attack_findings(model)
    questions = generate_questions(model)
    risks = score_risks(model, threats, attacks)
    risk_selectors = {risk.rating.value.lower() for risk in risks}
    if risks:
        risk_selectors.add("any")
    return {
        Lens.MODEL: model_selectors,
        Lens.STRIDE: {threat.rule_id for threat in threats},
        Lens.ATTACK: {finding.technique.id for finding in attacks},
        Lens.QUESTION: {question.category for question in questions},
        Lens.RISK: risk_selectors,
    }


def _probe_value(probe: Probe, predictions: dict[Lens, set[str]]) -> bool:
    """Validate selector vocabulary before checking candidate presence."""

    if probe.lens == Lens.MODEL and not _valid_model_selector(probe.selector):
        raise ValueError(f"unsupported model evaluation selector {probe.selector!r}")
    if probe.lens == Lens.RISK and probe.selector not in _RISK_SELECTORS:
        raise ValueError(f"unsupported risk evaluation selector {probe.selector!r}")
    if probe.lens == Lens.STRIDE and probe.selector not in _STRIDE_SELECTORS:
        raise ValueError(f"unsupported STRIDE evaluation selector {probe.selector!r}")
    if probe.lens == Lens.ATTACK and probe.selector not in TECHNIQUES:
        raise ValueError(f"unsupported ATT&CK evaluation selector {probe.selector!r}")
    return probe.selector in predictions[probe.lens]


def _valid_model_selector(selector: str) -> bool:
    """Accept documented summary or exact node/edge selectors only."""

    if selector in _MODEL_SELECTORS:
        return True
    if selector.startswith("node:"):
        body, separator, node_type = selector[5:].rpartition(":")
        return bool(separator and body and node_type in {item.value for item in NodeType})
    if selector.startswith("edge:"):
        body, separator, edge_type = selector[5:].rpartition(":")
        source, arrow, target = body.partition("->")
        return bool(
            separator
            and arrow
            and source
            and target
            and edge_type in {item.value for item in EdgeType}
        )
    if selector.startswith("auth:"):
        edge_id, separator, state = selector[5:].rpartition(":")
        return bool(
            separator
            and edge_id.startswith("edge:")
            and len(edge_id) > len("edge:")
            and state in _AUTH_STATES
        )
    return False
