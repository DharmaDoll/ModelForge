"""Version-aware model CLI contract and safe migration output."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.model.io import read_versioned_system_model
from threatmodel_ai.model.migration import migrate_system_model
from threatmodel_ai.model.schema_v02 import SystemModelV02

LEGACY = Path(__file__).parent / "fixtures" / "golden" / "sample-system" / "system_model.json"
RUNNER = CliRunner()


def test_validate_accepts_both_versions_without_writing(tmp_path: Path) -> None:
    migrated = tmp_path / "system_model.v0.2.json"
    payload = migrate_system_model(json.loads(LEGACY.read_text(encoding="utf-8")))
    migrated.write_text(json.dumps(payload), encoding="utf-8")
    original = migrated.read_bytes()

    legacy_result = RUNNER.invoke(app, ["model", "validate", str(LEGACY)])
    current_result = RUNNER.invoke(app, ["model", "validate", str(migrated)])

    assert legacy_result.exit_code == 0, legacy_result.output
    assert "schema 0.1" in legacy_result.output
    assert current_result.exit_code == 0, current_result.output
    assert "schema 0.2" in current_result.output
    assert migrated.read_bytes() == original
    assert isinstance(read_versioned_system_model(migrated), SystemModelV02)


@pytest.mark.parametrize("version", [None, "0.0", "0.3"])
def test_validate_rejects_missing_old_and_future_versions(
    tmp_path: Path, version: str | None
) -> None:
    model_path = tmp_path / "model.json"
    payload = {"schema_version": version} if version is not None else {}
    model_path.write_text(json.dumps(payload), encoding="utf-8")

    result = RUNNER.invoke(app, ["model", "validate", str(model_path)])

    assert result.exit_code == 1
    assert "supported: 0.1, 0.2" in result.output


def test_validate_rejects_invalid_json_and_invalid_model(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    path.write_text("{", encoding="utf-8")
    assert RUNNER.invoke(app, ["model", "validate", str(path)]).exit_code == 1
    path.write_text('{"schema_version":"0.2","nodes":[{}]}', encoding="utf-8")
    result = RUNNER.invoke(app, ["model", "validate", str(path)])
    assert result.exit_code == 1
    assert "Input system model failed validation" in result.output
    with pytest.raises(ValidationError):
        read_versioned_system_model(path)


def test_migrate_writes_canonical_model_and_is_idempotent(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    legacy_bytes = LEGACY.read_bytes()

    result = RUNNER.invoke(
        app, ["model", "migrate", str(LEGACY), "--to", "0.2", "--out", str(first)]
    )
    repeated = RUNNER.invoke(
        app, ["model", "migrate", str(first), "--to", "0.2", "--out", str(second)]
    )

    assert result.exit_code == 0, result.output
    assert repeated.exit_code == 0, repeated.output
    assert first.read_bytes() == second.read_bytes()
    assert LEGACY.read_bytes() == legacy_bytes
    assert isinstance(read_versioned_system_model(first), SystemModelV02)


def test_migrate_refuses_input_and_existing_output(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.json"
    legacy.write_bytes(LEGACY.read_bytes())
    before = legacy.read_bytes()
    same_path = RUNNER.invoke(
        app, ["model", "migrate", str(legacy), "--to", "0.2", "--out", str(legacy)]
    )
    assert same_path.exit_code == 1
    assert "must not overwrite" in same_path.output
    assert legacy.read_bytes() == before

    existing = tmp_path / "existing.json"
    existing.write_text("keep me", encoding="utf-8")
    existing_result = RUNNER.invoke(
        app, ["model", "migrate", str(legacy), "--to", "0.2", "--out", str(existing)]
    )
    assert existing_result.exit_code == 1
    assert "already exists" in existing_result.output
    assert existing.read_text(encoding="utf-8") == "keep me"


def test_migrate_rejects_unsupported_target_without_writing(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    result = RUNNER.invoke(
        app, ["model", "migrate", str(LEGACY), "--to", "0.3", "--out", str(out)]
    )
    assert result.exit_code == 1
    assert "unsupported migration target" in result.output
    assert not out.exists()
