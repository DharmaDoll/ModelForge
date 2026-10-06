"""OpenAPI diagnostics distinguish declared operations from modeled ones."""

from pathlib import Path

from threatmodel_ai.extract.openapi import observe_openapi_with_diagnostics
from threatmodel_ai.model.observations import normalize_observation_batch


def test_openapi_diagnostics_count_skipped_path_items_and_operations(tmp_path: Path) -> None:
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "\n".join(
            [
                "openapi: 3.0.3",
                "info:",
                "  title: Example API",
                "paths:",
                "  /valid:",
                "    get:",
                "      responses:",
                "        '200':",
                "          description: OK",
                "    post: null",
                "    parameters: []",
                "  /invalid: []",
            ]
        ),
        encoding="utf-8",
    )

    batch, metrics = observe_openapi_with_diagnostics(spec)
    model = normalize_observation_batch(batch)

    assert metrics.path_items_declared == 2
    assert metrics.path_items_skipped == 1
    assert metrics.http_operations_declared == 2
    assert metrics.http_operations_modeled == 1
    assert metrics.http_operations_skipped == 1
    assert [node.name for node in model.nodes if node.type.value == "api"] == ["GET /valid"]


def test_openapi_diagnostics_count_empty_paths_without_claiming_coverage(
    tmp_path: Path,
) -> None:
    spec = tmp_path / "openapi.yaml"
    spec.write_text("openapi: 3.0.3\npaths: {}\n", encoding="utf-8")

    _, metrics = observe_openapi_with_diagnostics(spec)

    assert metrics.path_items_declared == 0
    assert metrics.http_operations_declared == 0
    assert metrics.http_operations_modeled == 0
