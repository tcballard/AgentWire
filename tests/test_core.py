from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentwire.core import (
    REDACTED,
    TraceRecorder,
    classify_message,
    load_trace,
    redact,
    rewrite_response_id,
    summarize,
)


class RedactionTests(unittest.TestCase):
    def test_redacts_nested_secrets_and_inline_values(self) -> None:
        value = {
            "authorization": "Bearer abcdefghijklmnop",
            "nested": {"api_key": "sk-abcdefghijklmnop", "safe": "hello"},
            "command": "OPENAI_API_KEY=secret-value run",
        }
        redacted = redact(value)
        self.assertEqual(redacted["authorization"], REDACTED)
        self.assertEqual(redacted["nested"]["api_key"], REDACTED)
        self.assertEqual(redacted["nested"]["safe"], "hello")
        self.assertEqual(redacted["command"], f"OPENAI_API_KEY={REDACTED} run")


class ProtocolTests(unittest.TestCase):
    def test_classifies_json_rpc_shapes_without_jsonrpc_header(self) -> None:
        self.assertEqual(classify_message({"id": 1, "method": "initialize"})[0], "request")
        self.assertEqual(classify_message({"method": "initialized"})[0], "notification")
        self.assertEqual(classify_message({"id": 1, "result": {}})[0], "response")

    def test_rewrites_recorded_response_id(self) -> None:
        payload = {"id": 4, "result": {"ok": True}}
        rewritten = rewrite_response_id(payload, {json.dumps(4): "client-id"})
        self.assertEqual(rewritten["id"], "client-id")
        self.assertEqual(payload["id"], 4)


class TraceTests(unittest.TestCase):
    def test_records_jsonl_with_private_permissions_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            recorder = TraceRecorder(path, ["codex", "app-server"])
            recorder.record_line("client_to_server", b'{"id":1,"method":"initialize","params":{}}\n')
            recorder.record_line("server_to_client", b'{"id":1,"result":{}}\n')
            recorder.close(0)
            events = load_trace(path)
            summary = summarize(events)
            self.assertEqual(summary.events, 2)
            self.assertEqual(summary.client_messages, 1)
            self.assertEqual(summary.server_messages, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
