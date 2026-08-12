"""Deterministic risk-threshold evaluation for CI quality gates."""

from __future__ import annotations

from enum import StrEnum

from threatmodel_ai.risk.models import RiskFinding, RiskRating


class RiskThreshold(StrEnum):
    """Minimum risk rating that causes a configured gate to fail."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_RATING_LEVEL = {
    RiskRating.LOW: 1,
    RiskRating.MEDIUM: 2,
    RiskRating.HIGH: 3,
}

_THRESHOLD_LEVEL = {
    RiskThreshold.LOW: 1,
    RiskThreshold.MEDIUM: 2,
    RiskThreshold.HIGH: 3,
}


def risks_at_or_above(
    risks: list[RiskFinding],
    threshold: RiskThreshold,
) -> list[RiskFinding]:
    """Return risks meeting a threshold in deterministic priority order."""

    minimum_level = _THRESHOLD_LEVEL[threshold]
    matching = [risk for risk in risks if _RATING_LEVEL[risk.rating] >= minimum_level]
    return sorted(matching, key=lambda risk: (-risk.score, risk.id))
