#!/usr/bin/env python3
"""Tiny JSONL server used to demonstrate codex-tap without a Codex login."""

import json
import sys


def emit(message: dict) -> None:
    print(json.dumps(message, separators=(",", ":")), flush=True)


for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        emit({"id": request_id, "result": {"serverInfo": {"name": "mock-codex", "version": "0.1"}}})
    elif method == "initialized":
        continue
    elif method == "thread/start":
        emit({"id": request_id, "result": {"thread": {"id": "thread-demo", "status": "idle"}}})
        emit({"method": "thread/started", "params": {"thread": {"id": "thread-demo", "status": "idle"}}})
    elif method == "turn/start":
        emit({"id": request_id, "result": {"turn": {"id": "turn-demo", "status": "inProgress"}}})
        emit({"method": "turn/started", "params": {"threadId": "thread-demo", "turn": {"id": "turn-demo"}}})
        emit({"method": "item/agentMessage/delta", "params": {"threadId": "thread-demo", "turnId": "turn-demo", "delta": "Hello from the mock server."}})
        emit({"method": "turn/completed", "params": {"threadId": "thread-demo", "turn": {"id": "turn-demo", "status": "completed"}}})
    else:
        emit({"id": request_id, "error": {"code": -32601, "message": f"unknown method: {method}"}})
