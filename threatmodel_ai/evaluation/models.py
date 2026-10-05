"""Schemas and confusion-matrix metrics for explicitly labeled evaluation probes."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Lens(StrEnum):
    """Independent output families evaluated without translating between lenses."""

    MODEL = "model"
    STRIDE = "stride"
    ATTACK = "attack"
    QUESTION = "question"
    RISK = "risk"


class Probe(BaseModel):
    """One authored positive or negative claim about a case's output."""

    model_config = ConfigDict(extra="forbid")

    lens: Lens
    selector: str = Field(min_length=1)
    expected: bool
    rationale: str = Field(min_length=1)


class EvaluationCase(BaseModel):
    """A fixture and its independently authored, explicitly scoped labels."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    project: str = Field(min_length=1)
    review_status: Literal["seed", "expert_reviewed"] = "seed"
    reviewer: str | None = None
    probes: list[Probe] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_labels(self) -> EvaluationCase:
        """Prevent duplicate probes and unsupported expert-review claims."""

        keys = [(probe.lens, probe.selector) for probe in self.probes]
        if len(keys) != len(set(keys)):
            raise ValueError(f"evaluation case {self.id!r} contains duplicate probes")
        if self.review_status == "expert_reviewed" and not self.reviewer:
            raise ValueError("expert-reviewed cases require a reviewer")
        return self


class EvaluationManifest(BaseModel):
    """A versioned collection of cases with no implicit unlabeled negatives."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"] = "0.1"
    cases: list[EvaluationCase] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_cases(self) -> EvaluationManifest:
        """Keep every fixture identity unambiguous within one evaluation run."""

        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("evaluation manifest contains duplicate case ids")
        return self


class ProbeResult(BaseModel):
    """Observed value for one labeled probe; not an expert quality judgment."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    review_status: Literal["seed", "expert_reviewed"]
    lens: Lens
    selector: str
    expected: bool
    actual: bool
    rationale: str


class Metrics(BaseModel):
    """Binary classification metrics over labeled probes only."""

    model_config = ConfigDict(extra="forbid")

    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    tn: int = Field(ge=0)
    fn: int = Field(ge=0)
    precision: float | None
    recall: float | None
    false_candidate_rate: float | None
    fpr: float | None
    fnr: float | None

    @classmethod
    def from_results(cls, results: list[ProbeResult]) -> Metrics:
        """Use undefined ratios when the relevant denominator is zero."""

        tp = sum(result.expected and result.actual for result in results)
        fp = sum(not result.expected and result.actual for result in results)
        tn = sum(not result.expected and not result.actual for result in results)
        fn = sum(result.expected and not result.actual for result in results)
        predicted_positive = tp + fp
        labeled_positive = tp + fn
        labeled_negative = fp + tn
        return cls(
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            precision=tp / predicted_positive if predicted_positive else None,
            recall=tp / labeled_positive if labeled_positive else None,
            false_candidate_rate=fp / predicted_positive if predicted_positive else None,
            fpr=fp / labeled_negative if labeled_negative else None,
            fnr=fn / labeled_positive if labeled_positive else None,
        )


class EvaluationReport(BaseModel):
    """Metrics with label provenance so seed fixtures cannot masquerade as a gold standard."""

    model_config = ConfigDict(extra="forbid")

    case_count: int = Field(ge=0)
    labeled_probe_count: int = Field(ge=0)
    expert_reviewed_probe_count: int = Field(ge=0)
    by_lens: dict[Lens, Metrics]
    micro: Metrics
    results: list[ProbeResult]
