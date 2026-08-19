# AgentWire

**tcpdump + VCR for coding-agent protocols — starting with Codex App Server.**

[![CI](https://github.com/tcballard/AgentWire/actions/workflows/ci.yml/badge.svg)](https://github.com/tcballard/AgentWire/actions/workflows/ci.yml)

AgentWire is a native Rust protocol tap for developers building coding-agent
clients. It proxies the exact JSONL bytes between a client and `codex app-server`,
writes private redacted traces, diffs runs down to the changed payload path, and
replays recorded server behaviour deterministically—without another model call.

This is an independent community project. It is not affiliated with or endorsed
by OpenAI.

## Install

```bash
cargo install --git https://github.com/tcballard/AgentWire
```

## Quick start

Run a client with this command in place of `codex app-server`:

```bash
agentwire record --ui -- codex app-server
```

The child process still receives the client's stdin and writes directly to the
client's stdout. AgentWire writes a private, redacted JSONL trace and serves the
inspector at `http://127.0.0.1:4777`.

Use an explicit path when creating a fixture:

```bash
agentwire record --trace login-flow.jsonl -- codex app-server
agentwire inspect login-flow.jsonl
agentwire serve login-flow.jsonl
```

Compare two runs like protocol captures. Request IDs are ignored by default,
and the two duplex streams are compared independently so thread scheduling does
not create false differences:

```bash
agentwire diff before.jsonl after.jsonl
```

```diff
traces differ: 1 protocol event(s) differ (11 left, 11 right)

@@ client → server event 4 · changed @@
- client → server  request  turn/start
+ client → server  request  turn/start
  /payload/params/input/0/text
    - "hello"
    + "goodbye"
```

`diff` exits `0` for protocol-equivalent traces, `1` for a difference, and `2`
for an invalid trace or command. Use `--json` in CI and `--strict-ids` when
transport request IDs are themselves significant.

Replay the trace as a fake App Server:

```bash
agentwire replay login-flow.jsonl
```

AgentWire validates the sequence of client methods, rewrites recorded response
IDs to those used by the current client, and emits captured server messages
deterministically.

## Try it without Codex

Build the binary and opt-in test server:

```bash
cargo build --bins --features test-support
```

On macOS or Linux:

```bash
target/debug/agentwire record --trace demo.jsonl -- \
  target/debug/agentwire-mock-server
```

On Windows, add `.exe` to both executable paths.

Paste these messages, then send EOF:

```jsonl
{"id":1,"method":"initialize","params":{"clientInfo":{"name":"demo","version":"0.1"}}}
{"method":"initialized"}
{"id":2,"method":"thread/start","params":{"cwd":"."}}
{"id":3,"method":"turn/start","params":{"threadId":"thread-demo","input":[{"type":"text","text":"hello"}]}}
```

Then inspect and replay:

```bash
target/debug/agentwire inspect demo.jsonl
target/debug/agentwire serve demo.jsonl
target/debug/agentwire replay demo.jsonl
```

## Trace format

Trace format version 1 is unchanged from the prototype. Each line is an
independently readable event:

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

## Security boundary

- Trace files use owner-only permissions (`0600`) on Unix.
- Fields whose names end in token, secret, password, passphrase, cookie,
  credential, authorization, API key, or private key are redacted —
  `client_secret`, `refresh_token`, and `sshPrivateKey` all match.
- Bearer tokens, OpenAI-style keys, and secret environment assignments are
  redacted inside strings.
- Original protocol bytes are forwarded in memory but are not retained.
- Invalid non-JSON lines retain only their length.
- The inspector binds to loopback by default and sends restrictive headers.

Redaction is defense in depth, not a guarantee. Review a trace before sharing it.

## Current limits

- Codex App Server's JSONL stdio transport only.
- Replay validates method order, not full application state.
- Diff compares order within each protocol direction, not scheduler-dependent
  interleaving between the two directions.
- Timing is immediate by default; use `--speed 1` for recorded delays.
- Binary attachments and experimental WebSocket transports are out of scope.
- The browser inspector polls the trace rather than using a live socket.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

CI runs the same gates on Linux, macOS, and Windows.

## License

MIT
