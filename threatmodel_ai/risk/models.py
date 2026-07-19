"""Risk scoring output schemas."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from threatmodel_ai.model.schema import Evidence


class RiskRating(StrEnum):
    """Qualitative deterministic risk ratings."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class RiskFinding(BaseModel):
    """A deterministic review-priority finding derived from model topology."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    rating: RiskRating
    score: int
    rationale: list[str] = Field(default_factory=list)
    related_threats: list[str] = Field(default_factory=list)
    related_attack_findings: list[str] = Field(default_factory=list)
    affected_elements: list[str] = Field(default_factory=list)
    derived_from: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    status: str = "candidate"
