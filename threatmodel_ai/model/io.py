"""Read and write system model artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from threatmodel_ai.model.schema import SystemModel
from threatmodel_ai.model.schema_v02 import SystemModelV02


def read_versioned_system_model(path: Path) -> SystemModel | SystemModelV02:
    """Read a model using its explicit schema version, without migrating it."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("system model must be a JSON object")
    version = payload.get("schema_version")
    if version == "0.1":
        return SystemModel.model_validate(payload)
    if version == "0.2":
        return SystemModelV02.model_validate(payload)
    raise ValueError(
        f"unsupported model schema_version {version!r}; supported: 0.1, 0.2. "
        "Use 'tm-ai model migrate INPUT --to 0.2 --out OUTPUT' for a 0.1 model."
    )


def write_system_model(model: SystemModel, path: Path) -> None:
    """Write a deterministic JSON representation of the system model."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = model.model_dump(mode="json", exclude_none=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_system_model(path: Path) -> SystemModel:
    """Load and validate a system model from disk."""

    return SystemModel.model_validate_json(path.read_text(encoding="utf-8"))
