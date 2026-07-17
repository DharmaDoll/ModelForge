"""STRIDE threat output schemas."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class StrideCategory(StrEnum):
    """STRIDE categories."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Threat(BaseModel):
    """A deterministic threat candidate generated from rules."""

    model_config = ConfigDict(extra="forbid")

    id: str
    rule_id: str
    category: StrideCategory
    title: str
    scenario: str
    impact: str
    mitigation: str
    affected_elements: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    status: str = "candidate"
