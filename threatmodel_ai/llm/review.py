"""Local, history-preserving reviewer dispositions for threat hypotheses."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatmodel_ai.llm.hypotheses import (
    ThreatHypothesisBatch,
    model_sha256,
    validate_hypotheses_against_model,
)
from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.model.schema_v02 import SystemModelV02


class HypothesisDisposition(StrEnum):
    """Human triage outcomes; none is an accepted vulnerability finding."""

    INVESTIGATE = "investigate"
    NEEDS_CONTEXT = "needs_context"
    REJECTED = "rejected"


class HypothesisReviewEvent(BaseModel):
    """One reviewer decision tied to a specific hypothesis artifact."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=1)
    disposition: HypothesisDisposition
    reviewer: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    reviewed_at: datetime

    @field_validator("reviewed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        """Keep timestamps comparable across workstations."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reviewed_at must include a timezone")
        return value


class HypothesisReviewState(BaseModel):
    """Versioned decision history separate from model facts and hypotheses."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"]
    model_id: str = Field(min_length=1)
    model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hypothesis_batch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    events: list[HypothesisReviewEvent] = Field(default_factory=list)


def hypothesis_batch_sha256(batch: ThreatHypothesisBatch) -> str:
    """Fingerprint canonical candidate content, independent of JSON formatting."""

    payload = json.dumps(
        batch.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def read_review_state(
    path: Path,
    *,
    batch: ThreatHypothesisBatch,
    model: SystemModel | SystemModelV02,
) -> HypothesisReviewState:
    """Reject decisions tied to a different model or hypothesis snapshot."""

    validate_hypotheses_against_model(batch, model)
    state = HypothesisReviewState.model_validate_json(path.read_text(encoding="utf-8"))
    validate_review_state(state, batch=batch, model=model)
    return state


def validate_review_state(
    state: HypothesisReviewState,
    *,
    batch: ThreatHypothesisBatch,
    model: SystemModel | SystemModelV02,
) -> None:
    """Validate all decision IDs and immutable source fingerprints."""

    if state.model_id != model.id or state.model_sha256 != model_sha256(model):
        raise ValueError("hypothesis review state targets a different model snapshot")
    if state.hypothesis_batch_sha256 != hypothesis_batch_sha256(batch):
        raise ValueError("hypothesis review state targets a different hypothesis batch")
    valid_ids = {item.id for item in batch.hypotheses}
    if any(event.hypothesis_id not in valid_ids for event in state.events):
        raise ValueError("hypothesis review state references a missing hypothesis")


def record_hypothesis_decision(
    *,
    batch: ThreatHypothesisBatch,
    model: SystemModel | SystemModelV02,
    state: HypothesisReviewState | None,
    hypothesis_id: str,
    disposition: HypothesisDisposition,
    reviewer: str,
    rationale: str,
    reviewed_at: datetime | None = None,
) -> HypothesisReviewState:
    """Append a human decision without promoting any hypothesis to a finding."""

    validate_hypotheses_against_model(batch, model)
    valid_ids = {item.id for item in batch.hypotheses}
    if hypothesis_id not in valid_ids:
        raise ValueError("review decision references a missing hypothesis")
    if state is not None:
        validate_review_state(state, batch=batch, model=model)
    event = HypothesisReviewEvent(
        hypothesis_id=hypothesis_id,
        disposition=disposition,
        reviewer=reviewer,
        rationale=rationale,
        reviewed_at=reviewed_at or datetime.now(UTC),
    )
    events = list(state.events) if state is not None else []
    if events and events[-1] == event:
        raise ValueError("review decision exactly duplicates the previous event")
    events.append(event)
    return HypothesisReviewState(
        schema_version="0.1",
        model_id=model.id,
        model_sha256=model_sha256(model),
        hypothesis_batch_sha256=hypothesis_batch_sha256(batch),
        events=events,
    )


def effective_dispositions(state: HypothesisReviewState) -> dict[str, HypothesisDisposition]:
    """Return each hypothesis's latest decision while keeping full event history."""

    return {event.hypothesis_id: event.disposition for event in state.events}


def write_review_state(state: HypothesisReviewState, path: Path) -> None:
    """Atomically publish local review history; never touch model or hypotheses."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".hypothesis-review-", delete=False
        ) as destination:
            temporary_path = Path(destination.name)
            destination.write(
                json.dumps(state.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
            )
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
