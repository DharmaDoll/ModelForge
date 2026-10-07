"""Verify optional Responses API request shape without network access."""

import io
import json
import urllib.request

from threatmodel_ai.llm.client import OpenAIResponsesClient


def test_structured_response_request_uses_text_format(monkeypatch) -> None:
    """Question refinement asks the API for schema-constrained output."""

    requests: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, *, timeout: float) -> io.BytesIO:
        assert timeout == 60.0
        requests.append(request)
        return io.BytesIO(
            json.dumps({"output": [{"content": [{"text": '{"questions": []}'}]}]}).encode("utf-8")
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = OpenAIResponsesClient(api_key="test-key", model="test-model")
    schema: dict[str, object] = {
        "type": "object",
        "properties": {
            "questions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["questions"],
        "additionalProperties": False,
    }

    output = client.generate_text(instructions="Return JSON", input_text="{}", json_schema=schema)

    assert output == '{"questions": []}'
    assert len(requests) == 1
    request = requests[0]
    assert request.full_url == "https://api.openai.com/v1/responses"
    payload = json.loads(request.data or b"{}")
    assert payload["text"]["format"] == {
        "type": "json_schema",
        "name": "model_forge_output",
        "strict": True,
        "schema": schema,
    }


def test_plain_text_request_has_no_structured_format(monkeypatch) -> None:
    """Other optional LLM flows retain their existing request shape."""

    requests: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, *, timeout: float) -> io.BytesIO:
        requests.append(request)
        return io.BytesIO(b'{"output": [{"content": [{"text": "ok"}]}]}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = OpenAIResponsesClient(api_key="test-key", model="test-model")

    assert client.generate_text(instructions="Test", input_text="hello") == "ok"
    assert "text" not in json.loads(requests[0].data or b"{}")
