# AgentWire

**A protocol tap and deterministic replay server for Codex App Server.**

AgentWire sits transparently between a Codex App Server client and the
`codex app-server` process. It records both directions of the newline-delimited
JSON protocol, redacts common credentials, provides a live browser inspector,
and replays the captured server behaviour without another model call.

This is an independent community project. It is not affiliated with or endorsed
by OpenAI.

## Why

Codex App Server makes rich coding-agent clients possible, but protocol bugs are
difficult to reproduce from screenshots or ordinary logs. A trace should be a
small fixture that a maintainer can inspect, attach to an issue, and replay into
the client that failed.

## Quick start

Run a client with this command in place of `codex app-server`:

```bash
agentwire record --ui -- codex app-server
```

The child process still receives the client's stdin and writes directly to the
client's stdout. The tap writes a private, redacted JSONL trace and serves the
inspector at `http://127.0.0.1:4777`.

Use an explicit trace path when creating a fixture:

```bash
agentwire record --trace login-flow.jsonl -- codex app-server
agentwire inspect login-flow.jsonl
agentwire serve login-flow.jsonl
```

Replay the trace as a fake App Server:

```bash
agentwire replay login-flow.jsonl
```

Point the original client at that command. AgentWire validates the sequence of
client methods, rewrites recorded response IDs to the IDs used by the current
client, and emits the captured server messages deterministically.

## Try it without Codex

The repository includes a tiny JSONL server:

```bash
PYTHONPATH=src python -m agentwire record --trace demo.jsonl -- \
  python examples/mock_app_server.py
```

Paste these messages, then send EOF:

```jsonl
{"id":1,"method":"initialize","params":{"clientInfo":{"name":"demo","version":"0.1"}}}
{"method":"initialized"}
{"id":2,"method":"thread/start","params":{"cwd":"."}}
{"id":3,"method":"turn/start","params":{"threadId":"thread-demo","input":[{"type":"text","text":"hello"}]}}
```

Then inspect and replay:

```bash
PYTHONPATH=src python -m agentwire inspect demo.jsonl
PYTHONPATH=src python -m agentwire serve demo.jsonl
PYTHONPATH=src python -m agentwire replay demo.jsonl
```

## Trace format

Each line is an independently readable event:

```json
{
  "trace_version": 1,
  "session_id": "…",
  "seq": 2,
  "timestamp": "2026-08-16T20:00:00.000Z",
  "elapsed_ms": 12.4,
  "direction": "server_to_client",
  "kind": "notification",
  "method": "turn/completed",
  "id": null,
  "payload": {"method": "turn/completed", "params": {}}
}
```

The format intentionally preserves the protocol message rather than inventing
an observability schema. That makes a trace useful as both evidence and a replay
fixture.

## Security boundary

- Traces are created with owner-only permissions (`0600`) where supported.
- Keys named like tokens, passwords, secrets, cookies, credentials, and API keys
  are replaced before writing.
- Bearer tokens, OpenAI-style secret keys, and secret-looking environment
  assignments are redacted inside strings.
- Original protocol bytes are forwarded in memory but are not retained.
- Invalid non-JSON lines are represented only by their length; their contents
  are not retained.
- The inspector binds to loopback by default and sends restrictive browser
  security headers.

Redaction is defense in depth, not a guarantee. Review a trace before sharing it.

## Current limits

- Codex App Server's JSONL stdio transport only.
- Replay validates method order, not full application state.
- Timing is immediate by default; use `--speed 1` to preserve recorded delays.
- Binary attachments and experimental WebSocket transports are out of scope.
- The browser inspector polls the trace file rather than using a live socket.

## Development

The runtime has no third-party dependencies.

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m agentwire doctor
```

## License

MIT
