"""Deterministic risk scoring."""

from threatmodel_ai.risk.engine import score_risks
from threatmodel_ai.risk.models import RiskFinding, RiskRating

__all__ = ["RiskFinding", "RiskRating", "score_risks"]
