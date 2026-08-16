from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from agentwire.core import TraceRecorder
from agentwire.web import create_server, server_url


class InspectorTests(unittest.TestCase):
    def test_serves_page_and_trace_events_on_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            recorder = TraceRecorder(trace, ["mock-server"])
            recorder.record_line("client_to_server", b'{"id":1,"method":"initialize"}\n')
            recorder.close(0)

            server = create_server(trace, "127.0.0.1:0")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urllib.request.urlopen(server_url(server), timeout=5) as response:
                    page = response.read().decode()
                    self.assertIn("AgentWire", page)
                    self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                with urllib.request.urlopen(f"{server_url(server)}/api/events", timeout=5) as response:
                    events = json.load(response)
                    self.assertEqual(events[1]["method"], "initialize")
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
