from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def environment() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return env


def client_input() -> str:
    messages = [
        {"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "test", "version": "0.1"}}},
        {"method": "initialized"},
        {"id": 2, "method": "thread/start", "params": {"cwd": str(ROOT)}},
        {"id": 3, "method": "turn/start", "params": {"threadId": "thread-demo", "input": [{"type": "text", "text": "hello"}]}},
    ]
    return "".join(json.dumps(message, separators=(",", ":")) + "\n" for message in messages)


class EndToEndTests(unittest.TestCase):
    def test_record_inspect_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "demo.jsonl"
            record = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agentwire",
                    "record",
                    "--trace",
                    str(trace),
                    "--",
                    sys.executable,
                    str(ROOT / "examples" / "mock_app_server.py"),
                ],
                cwd=ROOT,
                env=environment(),
                input=client_input(),
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(record.returncode, 0, record.stderr)
            self.assertTrue(trace.exists())
            self.assertIn("turn/completed", record.stdout)

            inspect = subprocess.run(
                [sys.executable, "-m", "agentwire", "inspect", str(trace), "--json"],
                cwd=ROOT,
                env=environment(),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(inspect.returncode, 0, inspect.stderr)
            summary = json.loads(inspect.stdout)
            self.assertEqual(summary["client_messages"], 4)
            self.assertGreaterEqual(summary["server_messages"], 7)

            replay = subprocess.run(
                [sys.executable, "-m", "agentwire", "replay", str(trace)],
                cwd=ROOT,
                env=environment(),
                input=client_input(),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(replay.stdout, record.stdout)


if __name__ == "__main__":
    unittest.main()
