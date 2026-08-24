# AgentWire

**tcpdump + VCR for coding-agent protocols — Codex App Server and ACP.**

[![CI](https://github.com/tcballard/AgentWire/actions/workflows/ci.yml/badge.svg)](https://github.com/tcballard/AgentWire/actions/workflows/ci.yml)

AgentWire is a native Rust protocol tap for developers building coding-agent
clients. It proxies the exact JSONL bytes between a client and a coding-agent
process — `codex app-server` or any [ACP](https://agentclientprotocol.com)
agent — writes private redacted traces, diffs runs down to the changed payload
path, and replays recorded server behaviour deterministically—without another
model call.

This is an independent community project. It is not affiliated with or endorsed
by OpenAI or Zed Industries.

## Install

```bash
cargo install --locked agentwire
```

Prebuilt binaries for Linux, macOS, and Windows are attached to each
[GitHub release](https://github.com/tcballard/AgentWire/releases). To build
the latest development version instead:

```bash
cargo install --locked --git https://github.com/tcballard/AgentWire
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

Real agents generate fresh thread IDs, turn IDs, and timestamps on every run,
so two recordings of the same scripted session differ in values that do not
matter. Mark those with `--ignore`: a bare key name matches that key at any
depth; a JSON pointer exactly as diff prints it matches one location, with
`*` matching any single segment.

```bash
agentwire diff --ignore threadId --ignore turnId \
  --ignore "/payload/params/cwd" before.jsonl after.jsonl
```

Ignored values compare as `[ignored]`, so a field that disappears entirely is
still reported.

Replay the trace as a fake App Server:

```bash
agentwire replay login-flow.jsonl
```

AgentWire validates the sequence of client methods, rewrites recorded response
IDs to those used by the current client, and emits captured server messages
deterministically.

Replay does not trust the recorded interleaving between the two streams, which
depends on thread scheduling. Server messages are emitted in recorded server
order, but each response waits until the live client has sent the matching
request, and notifications wait with the response recorded before them. A
trace recorded from a pipelining client therefore replays correctly against an
interactive client that blocks on each response, and vice versa.

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

## Fixture-driven client tests

Record a session once, commit the trace, and run your client's test suite
against the recording — deterministic server behaviour on every run, with
no Codex install, no API key, and no model spend in CI.

Record the fixture from a real session:

```bash
agentwire record --trace tests/fixtures/login-flow.jsonl -- codex app-server
```

Then have the test suite launch AgentWire in place of `codex app-server`:

```bash
agentwire replay tests/fixtures/login-flow.jsonl
```

Replay checks that the client sends the recorded methods in the recorded
order and exits non-zero on drift, so the fixture doubles as a protocol
assertion; add `--strict-payload` to require byte-identical requests. Pair
it with `diff` to catch behavioural drift
between client versions or Codex releases, ignoring the values the server
generates freshly on every run:

```bash
agentwire record --trace current.jsonl -- codex app-server < scripted-session.jsonl
agentwire diff --json --ignore threadId --ignore turnId \
  tests/fixtures/login-flow.jsonl current.jsonl
```

`diff` exits `0` for protocol-equivalent traces and `1` on any difference,
so both commands drop straight into a CI gate. Traces are redacted on
write, but review a fixture before committing it to a shared repository
(see [Security boundary](#security-boundary)).

## ACP agents

Nothing in the tap is specific to Codex: record, inspect, diff, and replay
operate on newline-delimited JSON-RPC over stdio, which is also the
transport of the [Agent Client Protocol](https://agentclientprotocol.com)
used by Zed and a growing set of agents. Wrap the agent command your editor
launches:

```bash
agentwire record --trace acp-session.jsonl -- some-acp-agent
```

The ACP agent is the server side of the trace. Agent-initiated requests
such as `session/request_permission` record, diff, and replay like any
other message: on replay, AgentWire emits the recorded request and holds
the output that followed it until the live client answers.

The test-support build also produces `agentwire-mock-acp-agent`, a mock
ACP agent with a permission round trip, driven by
`tests/fixtures/acp-client.jsonl` the same way as the App Server mock
above.

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

- Newline-delimited JSON-RPC over stdio only. Codex App Server and ACP are
  covered by tests; other agents using the same framing should work
  unchanged.
- Replay validates client method order and response causality, not full
  application state. It assumes a client's next message depends only on
  responses to its own requests, not on the timing of unrelated notifications.
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
