"""The HTTP providers against a local stub server. This proves the wire format, not any real model's quality."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from alertlens.config import get_settings
from alertlens.llm.mock import MockLLM
from alertlens.llm.provider import HttpChatLLM, OllamaLLM
from alertlens.pipeline.orchestrator import Options, analyze


class Stub(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Stub.seen.append((self.path, dict(self.headers), body))
        sys_msg, user_msg = body["messages"][0]["content"], body["messages"][1]["content"]
        schema = _schema_for(sys_msg, user_msg)
        text = MockLLM().complete(sys_msg, user_msg, schema=schema).text
        out = ({"message": {"content": text}, "eval_count": 5, "prompt_eval_count": 7} if self.path == "/api/chat"
               else {"choices": [{"message": {"content": text}}], "usage": {"total_tokens": 12}})
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _schema_for(system, user):
    from alertlens.schemas import AgentNote, ExplanationDraft, ExtractedFacts

    if "extract facts" in system:
        return ExtractedFacts
    return AgentNote if " agent in a security" in system else ExplanationDraft


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_openai_compatible_end_to_end(server, hero):
    p = HttpChatLLM(name="openai_compat", base_url=server, model="m", api_key="placeholder")
    Stub.seen.clear()
    r = analyze(hero[1], Options(deep=True, persist=False, provider=p, extractor=p))
    assert not r.explanation.safe_fallback and r.explanation.claims
    path, headers, body = Stub.seen[0]
    assert path == "/chat/completions" and headers["Authorization"] == "Bearer placeholder"
    assert body["temperature"] == 0 and body["response_format"] == {"type": "json_object"}


def test_ollama_end_to_end(server, hero):
    p = OllamaLLM(base_url=server, model="m")
    Stub.seen.clear()
    r = analyze(hero[0], Options(deep=True, persist=False, provider=p, extractor=p))
    assert not r.explanation.safe_fallback
    path, _, body = Stub.seen[0]
    assert path == "/api/chat" and body["format"]["type"] == "object" and body["stream"] is False


def test_key_not_in_repr():
    assert "secret-value" not in repr(HttpChatLLM(name="x", base_url="u", model="m", api_key="secret-value"))
    assert "llm_api_key" not in repr(get_settings())
