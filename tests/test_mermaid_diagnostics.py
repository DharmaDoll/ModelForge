"""Mermaid ingestion diagnostics must match the parser's actual decisions."""

from pathlib import Path

from threatmodel_ai.extract.mermaid import observe_mermaid_markdown_with_diagnostics
from threatmodel_ai.model.observations import normalize_observation_batch


def test_mermaid_diagnostics_count_supported_and_skipped_syntax(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    doc.write_text(
        "\n".join(
            [
                "```mermaid",
                "sequenceDiagram",
                "A->>B: hello",
                "```",
                "```mermaid",
                "flowchart LR",
                "A --> B",
                "classDef hidden fill:#fff",
                "broken --> !!!",
                "end",
                "```",
                "```mermaid",
                "flowchart LR",
                "C --> D",
            ]
        ),
        encoding="utf-8",
    )

    batch, metrics = observe_mermaid_markdown_with_diagnostics(doc)
    model = normalize_observation_batch(batch)

    assert metrics.closed_fences == 2
    assert metrics.unclosed_fences == 1
    assert metrics.flowchart_blocks == 1
    assert metrics.unsupported_diagram_blocks == 1
    assert metrics.parsed_statements == 1
    assert metrics.skipped_statements == 3
    assert len(model.edges) == 1


def test_mermaid_diagnostics_ignore_blank_and_comment_lines(tmp_path: Path) -> None:
    doc = tmp_path / "architecture.md"
    doc.write_text(
        "```mermaid\nflowchart LR\n\n%% note\nA --> B\n```\n", encoding="utf-8"
    )

    _, metrics = observe_mermaid_markdown_with_diagnostics(doc)

    assert metrics.parsed_statements == 1
    assert metrics.skipped_statements == 0
