"""MITRE ATT&CK output schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threatmodel_ai.model.schema import Evidence


class AttackTechnique(BaseModel):
    """A curated ATT&CK Enterprise technique reference."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    tactics: list[str]
    url: str
    matrix: str = "Enterprise ATT&CK"


class AttackFinding(BaseModel):
    """A deterministic ATT&CK technique candidate derived from the system model."""

    model_config = ConfigDict(extra="forbid")

    id: str
    rule_id: str
    technique: AttackTechnique
    title: str
    scenario: str
    detection: str
    mitigation: str
    affected_elements: list[str] = Field(default_factory=list)
    derived_from: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: str = "medium"
    status: str = "candidate"
