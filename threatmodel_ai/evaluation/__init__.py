"""Deterministic, labeled-probe evaluation for model and analysis outputs."""

from threatmodel_ai.evaluation.engine import evaluate_manifest
from threatmodel_ai.evaluation.models import EvaluationReport

__all__ = ["EvaluationReport", "evaluate_manifest"]
