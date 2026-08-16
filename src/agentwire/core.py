from __future__ import annotations

import copy
import json
import os
import re
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, TextIO

TRACE_VERSION = 1
REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "accesstoken",
    "apikey",
    "authorization",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "password",
    "refreshtoken",
    "secret",
    "sessiontoken",
    "token",
}

_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
_ENV_SECRET_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY))=([^\s]+)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def redact_string(value: str) -> str:
    value = _BEARER_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", value)
    value = _OPENAI_KEY_RE.sub(REDACTED, value)
    return _ENV_SECRET_RE.sub(lambda match: f"{match.group(1)}={REDACTED}", value)


def redact(value: Any, parent_key: str | None = None) -> Any:
    if parent_key is not None and _normalized_key(parent_key) in _SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, dict):
        return {key: redact(item, str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def parse_message(line: bytes | str) -> tuple[dict[str, Any] | None, str]:
    if isinstance(line, bytes):
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
    else:
        text = line.rstrip("\r\n")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None, text
    if not isinstance(parsed, dict):
        return None, text
    return parsed, text


def classify_message(message: dict[str, Any] | None) -> tuple[str, str | None, Any]:
    if message is None:
        return "invalid", None, None
    method = message.get("method")
    message_id = message.get("id")
    if isinstance(method, str):
        return ("request" if "id" in message else "notification"), method, message_id
    if "id" in message and ("result" in message or "error" in message):
        return "response", None, message_id
    return "message", None, message_id


def _safe_command(command: list[str]) -> list[str]:
    safe: list[str] = []
    hide_next = False
    for arg in command:
        lowered = arg.lower()
        if hide_next:
            safe.append(REDACTED)
            hide_next = False
            continue
        if any(marker in lowered for marker in ("token", "secret", "password", "api-key", "api_key")):
            if "=" in arg:
                safe.append(f"{arg.split('=', 1)[0]}={REDACTED}")
            else:
                safe.append(arg)
                hide_next = True
            continue
        safe.append(redact_string(arg))
    return safe


class TraceRecorder:
    def __init__(self, path: Path, command: list[str]) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(path, flags, 0o600)
        self._file: TextIO = os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._seq = 0
        self.session_id = str(uuid.uuid4())
        self.record_meta("session_start", {"command": _safe_command(command)})

    def _write(self, event: dict[str, Any]) -> None:
        with self._lock:
            event["seq"] = self._seq
            self._seq += 1
            self._file.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")
            self._file.flush()

    def record_meta(self, kind: str, payload: dict[str, Any]) -> None:
        self._write(
            {
                "trace_version": TRACE_VERSION,
                "session_id": self.session_id,
                "timestamp": utc_now(),
                "elapsed_ms": round((time.monotonic() - self._started) * 1000, 3),
                "direction": "meta",
                "kind": kind,
                "method": None,
                "id": None,
                "payload": redact(payload),
            }
        )

    def record_line(self, direction: str, line: bytes) -> None:
        message, _ = parse_message(line)
        kind, method, message_id = classify_message(message)
        if message is None:
            payload: Any = {
                "omitted": "non-JSON protocol line",
                "length": len(line),
            }
        else:
            payload = redact(message)
        self._write(
            {
                "trace_version": TRACE_VERSION,
                "session_id": self.session_id,
                "timestamp": utc_now(),
                "elapsed_ms": round((time.monotonic() - self._started) * 1000, 3),
                "direction": direction,
                "kind": kind,
                "method": method,
                "id": redact(message_id),
                "payload": payload,
            }
        )

    def close(self, exit_code: int | None = None) -> None:
        if not self._file.closed:
            self.record_meta("session_end", {"exit_code": exit_code})
            self._file.close()

    def __enter__(self) -> "TraceRecorder":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close(None)


def load_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid trace JSON on line {line_number}: {error}") from error
            if not isinstance(event, dict):
                raise ValueError(f"invalid trace event on line {line_number}: expected an object")
            if event.get("trace_version") != TRACE_VERSION:
                raise ValueError(
                    f"unsupported trace version on line {line_number}: {event.get('trace_version')!r}"
                )
            events.append(event)
    return events


def method_of(payload: Any) -> str | None:
    if isinstance(payload, dict) and isinstance(payload.get("method"), str):
        return payload["method"]
    return None


def request_id_of(payload: Any) -> Any:
    if isinstance(payload, dict):
        return payload.get("id")
    return None


def rewrite_response_id(payload: Any, id_map: dict[str, Any]) -> Any:
    if not isinstance(payload, dict) or "method" in payload or "id" not in payload:
        return payload
    key = json.dumps(payload["id"], sort_keys=True)
    if key not in id_map:
        return payload
    rewritten = copy.deepcopy(payload)
    rewritten["id"] = id_map[key]
    return rewritten


@dataclass(frozen=True)
class TraceSummary:
    events: int
    duration_ms: float
    client_messages: int
    server_messages: int
    invalid_messages: int
    methods: dict[str, int]
    errors: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "duration_ms": self.duration_ms,
            "client_messages": self.client_messages,
            "server_messages": self.server_messages,
            "invalid_messages": self.invalid_messages,
            "methods": self.methods,
            "errors": self.errors,
        }


def summarize(events: Iterable[dict[str, Any]]) -> TraceSummary:
    material = list(events)
    protocol_events = [event for event in material if event.get("direction") != "meta"]
    methods = Counter(
        event["method"] for event in protocol_events if isinstance(event.get("method"), str)
    )
    elapsed = [float(event.get("elapsed_ms", 0.0)) for event in material]
    errors = sum(
        1
        for event in protocol_events
        if isinstance(event.get("payload"), dict) and "error" in event["payload"]
    )
    return TraceSummary(
        events=len(protocol_events),
        duration_ms=max(elapsed, default=0.0),
        client_messages=sum(1 for event in protocol_events if event.get("direction") == "client_to_server"),
        server_messages=sum(1 for event in protocol_events if event.get("direction") == "server_to_client"),
        invalid_messages=sum(1 for event in protocol_events if event.get("kind") == "invalid"),
        methods=dict(methods.most_common()),
        errors=errors,
    )
