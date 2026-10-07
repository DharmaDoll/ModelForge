"""Opt-in shadow challenger safety and schema behavior with a mocked provider."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatmodel_ai.cli.app import app
from threatmodel_ai.llm.challenger import (
    ThreatChallengerError,
    build_challenger_context,
    propose_threat_hypotheses,
)
from threatmodel_ai.llm.client import OpenAIResponsesClient
from threatmodel_ai.model.schema import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SourceType,
    SystemModel,
)

RUNNER = CliRunner()


class FakeClient:
    model = "mock-model"

    def __init__(self, response: dict | str) -> None:
        self.response = response
        self.calls = 0
        self.input_text = ""
        self.instructions = ""
        self.json_schema: dict[str, object] | None = None

    def generate_text(
        self,
        *,
        instructions: str,
        input_text: str,
        json_schema: dict[str, object] | None = None,
    ) -> str:
        self.calls += 1
        self.input_text = input_text
        self.instructions = instructions
        self.json_schema = json_schema
        return self.response if isinstance(self.response, str) else json.dumps(self.response)


def _model() -> SystemModel:
    return SystemModel(
        id="payments",
        description="PRIVATE SOURCE DESCRIPTION",
        nodes=[
            Node(
                id="actor:customer",
                name="Customer",
                type=NodeType.ACTOR,
                evidence=[
                    Evidence(
                        source_type=SourceType.README,
                        source_path="private/README.md",
                        detail="PRIVATE EVIDENCE DETAIL",
                    )
                ],
            ),
            Node(
                id="api:payments",
                name="Payments API",
                type=NodeType.API,
                evidence=[
                    Evidence(
                        source_type=SourceType.OPENAPI,
                        source_path="private/openapi.yaml",
                        detail="PRIVATE OPERATION DETAIL",
                    )
                ],
            ),
        ],
        edges=[
            Edge(
                id="edge:customer-payments",
                source="actor:customer",
                target="api:payments",
                type=EdgeType.COMMUNICATES_WITH,
                protocol="HTTPS",
                authentication="unknown",
                evidence=[
                    Evidence(
                        source_type=SourceType.DERIVED,
                        source_path="private/rule",
                        detail="PRIVATE DERIVED DETAIL",
                    ),
                    Evidence(
                        source_type=SourceType.OPENAPI,
                        source_path="private/openapi.yaml",
                        detail="PRIVATE REQUEST DETAIL",
                    ),
                ],
            )
        ],
        metadata={"secret": "PRIVATE METADATA"},
    )


def _response() -> dict:
    return {
        "hypotheses": [
            {
                "title": "Payment replay",
                "conditional_scenario": (
                    "If replay protection is absent, a caller may repeat a payment request."
                ),
                "affected_element_ids": ["edge:customer-payments"],
                "established_prerequisites": [
                    {
                        "statement": "A customer sends requests to the payments API.",
                        "citations": [
                            {
                                "element_id": "edge:customer-payments",
                                "evidence_index": 1,
                            }
                        ],
                    }
                ],
                "assumptions": ["The same request can be repeated."],
                "missing_facts": ["Is replay protection enforced?"],
                "verification_steps": ["Review duplicate-request handling."],
            }
        ]
    }


def test_challenger_sends_bounded_context_and_returns_review_only_batch() -> None:
    model = _model()
    client = FakeClient(_response())

    batch = propose_threat_hypotheses(
        model=model,
        element_ids=["api:payments"],
        client=client,
        model_name=client.model,
    )

    assert client.calls == 1
    assert "untrusted data" in client.instructions
    assert client.json_schema is not None
    assert client.json_schema["additionalProperties"] is False
    outbound = json.loads(client.input_text)
    assert outbound["scope_element_ids"] == ["api:payments"]
    assert len(outbound["nodes"]) == 2
    assert outbound["edges"][0]["direct_evidence_indices"] == [1]
    assert "source_path" not in client.input_text
    assert "PRIVATE" not in client.input_text
    assert "description" not in client.input_text
    assert "metadata" not in client.input_text
    assert batch.hypotheses[0].id.startswith("hypothesis:")
    assert batch.hypotheses[0].status == "proposed"
    assert batch.hypotheses[0].provenance.model_name == "mock-model"
    assert batch.not_source_of_truth is True
    assert (
        batch.hypotheses[0].id
        == propose_threat_hypotheses(
            model=model,
            element_ids=["api:payments"],
            client=FakeClient(_response()),
            model_name="mock-model",
        )
        .hypotheses[0]
        .id
    )


@pytest.mark.parametrize(
    ("response", "expected_calls"),
    [
        ("not JSON", 1),
        ({"hypotheses": [{**_response()["hypotheses"][0], "status": "confirmed"}]}, 1),
        (
            {"hypotheses": [{**_response()["hypotheses"][0], "affected_element_ids": ["missing"]}]},
            1,
        ),
        (
            {
                "hypotheses": [
                    {
                        **_response()["hypotheses"][0],
                        "established_prerequisites": [
                            {
                                "statement": "Derived-only claim.",
                                "citations": [
                                    {"element_id": "edge:customer-payments", "evidence_index": 0}
                                ],
                            }
                        ],
                    }
                ]
            },
            1,
        ),
    ],
)
def test_challenger_rejects_invalid_provider_output(response, expected_calls: int) -> None:
    client = FakeClient(response)

    with pytest.raises(ThreatChallengerError, match="failed validation"):
        propose_threat_hypotheses(
            model=_model(),
            element_ids=["api:payments"],
            client=client,
            model_name=client.model,
        )
    assert client.calls == expected_calls


def test_challenger_rejects_missing_scope_before_call() -> None:
    client = FakeClient(_response())
    with pytest.raises(ThreatChallengerError, match="unknown model element IDs"):
        propose_threat_hypotheses(
            model=_model(), element_ids=["missing"], client=client, model_name=client.model
        )
    assert client.calls == 0


def test_challenger_accepts_no_supported_hypotheses() -> None:
    batch = propose_threat_hypotheses(
        model=_model(),
        element_ids=["api:payments"],
        client=FakeClient({"hypotheses": []}),
        model_name="mock-model",
    )
    assert batch.hypotheses == []


def test_challenger_rejects_out_of_scope_existing_element() -> None:
    model = _model()
    model.nodes.append(
        Node(
            id="api:unrelated",
            name="Unrelated API",
            type=NodeType.API,
            evidence=[
                Evidence(
                    source_type=SourceType.OPENAPI,
                    source_path="unrelated.yaml",
                    detail="GET /unrelated",
                )
            ],
        )
    )
    response = _response()
    response["hypotheses"][0]["affected_element_ids"] = ["api:unrelated"]
    response["hypotheses"][0]["established_prerequisites"][0]["citations"] = [
        {"element_id": "api:unrelated", "evidence_index": 0}
    ]

    with pytest.raises(ThreatChallengerError, match="failed validation"):
        propose_threat_hypotheses(
            model=model,
            element_ids=["api:payments"],
            client=FakeClient(response),
            model_name="mock-model",
        )


def test_challenger_context_budget_fails_closed() -> None:
    model = _model()
    model.nodes[1].name = "x" * 33_000
    with pytest.raises(ThreatChallengerError, match="too large"):
        build_challenger_context(model, ["api:payments"])


def test_cli_requires_approval_and_writes_only_new_hypothesis_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = _model()
    model_path = tmp_path / "model.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    out = tmp_path / "threat_hypotheses.json"
    client = FakeClient(_response())
    monkeypatch.setattr(OpenAIResponsesClient, "from_env", classmethod(lambda cls: client))
    args = [
        "hypotheses",
        "propose",
        str(model_path),
        "--element",
        "api:payments",
        "--classification",
        "internal-approved",
        "--out",
        str(out),
    ]

    denied = RUNNER.invoke(app, args)
    assert denied.exit_code == 1
    assert "External LLM approval is required" in denied.output
    assert client.calls == 0
    assert not out.exists()

    accepted = RUNNER.invoke(app, [*args, "--allow-external-llm"])
    assert accepted.exit_code == 0, accepted.output
    assert client.calls == 1
    assert "review-only hypothesis" in accepted.output
    assert json.loads(out.read_text(encoding="utf-8"))["hypotheses"][0]["status"] == "proposed"
    assert model_path.read_text(encoding="utf-8") == model.model_dump_json()
    assert RUNNER.invoke(app, [*args, "--allow-external-llm"]).exit_code == 1
    assert client.calls == 1


def test_cli_validation_failure_does_not_publish_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = _model()
    model_path = tmp_path / "model.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    out = tmp_path / "threat_hypotheses.json"
    client = FakeClient("invalid JSON with PRIVATE CONTENT")
    monkeypatch.setattr(OpenAIResponsesClient, "from_env", classmethod(lambda cls: client))

    result = RUNNER.invoke(
        app,
        [
            "hypotheses",
            "propose",
            str(model_path),
            "--element",
            "api:payments",
            "--classification",
            "public",
            "--out",
            str(out),
            "--allow-external-llm",
        ],
    )

    assert result.exit_code == 1
    assert not out.exists()
    assert "PRIVATE CONTENT" not in result.output


def test_cli_previews_exact_outbound_context_without_api_key(tmp_path: Path) -> None:
    model = _model()
    model_path = tmp_path / "model.json"
    model_path.write_text(model.model_dump_json(), encoding="utf-8")
    out = tmp_path / "context.json"

    result = RUNNER.invoke(
        app,
        [
            "hypotheses",
            "preview-context",
            str(model_path),
            "--element",
            "api:payments",
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "No external API was called" in result.output
    assert json.loads(out.read_text(encoding="utf-8")) == build_challenger_context(
        model, ["api:payments"]
    )
    assert "PRIVATE" not in out.read_text(encoding="utf-8")
