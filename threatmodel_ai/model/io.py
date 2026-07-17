"""Read and write system model artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from threatmodel_ai.model.schema import SystemModel


def write_system_model(model: SystemModel, path: Path) -> None:
    """Write a deterministic JSON representation of the system model."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = model.model_dump(mode="json", exclude_none=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_system_model(path: Path) -> SystemModel:
    """Load and validate a system model from disk."""

    return SystemModel.model_validate_json(path.read_text(encoding="utf-8"))
