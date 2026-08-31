use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const CLIENT_INPUT: &str = include_str!("fixtures/client.jsonl");
const CHANGED_CLIENT_INPUT: &str = include_str!("fixtures/client-changed.jsonl");
const ACP_CLIENT_INPUT: &str = include_str!("fixtures/acp-client.jsonl");
const MCP_CLIENT_INPUT: &str = include_str!("fixtures/mcp-client.jsonl");

fn run_with_input(command: &mut Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Record `input` against a mock server, pipelining every client message up
/// front, so most client events land in the trace before the server output
/// they causally follow.
fn record_trace(mock: &str, input: &str, trace: &Path) -> Output {
    let record = run_with_input(
        Command::new(env!("CARGO_BIN_EXE_agentwire"))
            .arg("record")
            .arg("--trace")
            .arg(trace)
            .arg("--")
            .arg(mock),
        input,
    );
    assert!(
        record.status.success(),
        "{}",
        String::from_utf8_lossy(&record.stderr)
    );
    record
}

struct InteractiveReplay {
    child: Child,
    input: ChildStdin,
    receiver: Receiver<String>,
}

/// Drive replay as an interactive client: send one message at a time and
/// block on the matching output before continuing.
fn spawn_interactive_replay(trace: &Path) -> InteractiveReplay {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentwire"))
        .arg("replay")
        .arg(trace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = child.stdin.take().unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in output.lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    InteractiveReplay {
        child,
        input,
        receiver,
    }
}

fn receive(receiver: &Receiver<String>) -> Value {
    let line = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("replay stalled instead of emitting the next server message");
    serde_json::from_str(&line).unwrap()
}

fn send(input: &mut ChildStdin, message: &str) {
    input.write_all(message.as_bytes()).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
}

#[test]
fn doctor_resolves_a_selected_target_without_launching_it() {
    let target = std::env::current_exe().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentwire"))
        .arg("doctor")
        .arg("--")
        .arg(&target)
        .arg("--argument-that-must-not-run")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!(
        "target       {} --argument-that-must-not-run",
        target.display()
    )));
    assert!(stdout.contains(&format!("executable   {}", target.display())));
    assert!(stdout.contains("transport    JSONL over stdio"));
    assert!(stdout.contains("protocol compatibility is not verified"));
}

#[test]
fn doctor_reports_a_missing_selected_target() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentwire"))
        .arg("doctor")
        .arg("--")
        .arg("agentwire-target-that-does-not-exist")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("target       agentwire-target-that-does-not-exist"));
    assert!(stdout.contains("executable   not found"));
    assert!(stdout.contains("live capture for this target is unavailable"));
}

#[test]
fn record_inspect_and_replay_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("round-trip.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");

    let record = record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-server"),
        CLIENT_INPUT,
        &trace,
    );
    assert!(String::from_utf8_lossy(&record.stdout).contains("turn/completed"));

    let inspect = Command::new(agentwire)
        .arg("inspect")
        .arg(&trace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let summary: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(summary["client_messages"], 4);
    assert_eq!(summary["server_messages"], 7);

    let replay = run_with_input(
        Command::new(agentwire).arg("replay").arg(&trace),
        CLIENT_INPUT,
    );
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(replay.stdout, record.stdout);
}

#[test]
fn replay_serves_interactive_client_from_pipelined_recording() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("pipelined.jsonl");
    record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-server"),
        CLIENT_INPUT,
        &trace,
    );

    let mut session = spawn_interactive_replay(&trace);
    send(
        &mut session.input,
        r#"{"id":"live-1","method":"initialize","params":{}}"#,
    );
    assert_eq!(receive(&session.receiver)["id"], "live-1");
    send(&mut session.input, r#"{"method":"initialized"}"#);
    send(
        &mut session.input,
        r#"{"id":"live-2","method":"thread/start","params":{}}"#,
    );
    assert_eq!(receive(&session.receiver)["id"], "live-2");
    assert_eq!(receive(&session.receiver)["method"], "thread/started");
    send(
        &mut session.input,
        r#"{"id":"live-3","method":"turn/start","params":{}}"#,
    );
    assert_eq!(receive(&session.receiver)["id"], "live-3");
    assert_eq!(receive(&session.receiver)["method"], "turn/started");
    assert_eq!(
        receive(&session.receiver)["method"],
        "item/agentMessage/delta"
    );
    assert_eq!(receive(&session.receiver)["method"], "turn/completed");
    drop(session.input);
    assert!(session.child.wait().unwrap().success());
}

#[test]
fn acp_record_inspect_and_replay_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("acp.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");

    let record = record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-acp-agent"),
        ACP_CLIENT_INPUT,
        &trace,
    );
    assert!(String::from_utf8_lossy(&record.stdout).contains("end_turn"));

    let inspect = Command::new(agentwire)
        .arg("inspect")
        .arg(&trace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let summary: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(summary["client_messages"], 4);
    assert_eq!(summary["server_messages"], 6);
    assert_eq!(summary["methods"]["session/request_permission"], 1);

    let replay = run_with_input(
        Command::new(agentwire).arg("replay").arg(&trace),
        ACP_CLIENT_INPUT,
    );
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(replay.stdout, record.stdout);
}

#[test]
fn acp_replay_forwards_permission_request_to_interactive_client() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("acp-pipelined.jsonl");
    record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-acp-agent"),
        ACP_CLIENT_INPUT,
        &trace,
    );

    let mut session = spawn_interactive_replay(&trace);
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"live-1","method":"initialize","params":{"protocolVersion":1}}"#,
    );
    let response = receive(&session.receiver);
    assert_eq!(response["id"], "live-1");
    assert_eq!(response["result"]["protocolVersion"], 1);
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"live-2","method":"session/new","params":{"cwd":"/workspace","mcpServers":[]}}"#,
    );
    assert_eq!(receive(&session.receiver)["id"], "live-2");
    assert_eq!(receive(&session.receiver)["method"], "session/update");
    // The agent-initiated request arrives with its recorded ID, and the
    // output that followed it stays held until the client answers.
    let permission = receive(&session.receiver);
    assert_eq!(permission["method"], "session/request_permission");
    assert_eq!(permission["id"], "perm-1");
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"live-3","method":"session/prompt","params":{"sessionId":"sess-demo","prompt":[{"type":"text","text":"update the config"}]}}"#,
    );
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"perm-1","result":{"outcome":{"outcome":"selected","optionId":"allow"}}}"#,
    );
    assert_eq!(receive(&session.receiver)["method"], "session/update");
    let done = receive(&session.receiver);
    assert_eq!(done["id"], "live-3");
    assert_eq!(done["result"]["stopReason"], "end_turn");
    drop(session.input);
    assert!(session.child.wait().unwrap().success());
}

#[test]
fn mcp_record_inspect_and_replay_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("mcp.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");

    let record = record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-mcp-server"),
        MCP_CLIENT_INPUT,
        &trace,
    );
    assert!(String::from_utf8_lossy(&record.stdout).contains("A protocol tap."));

    let inspect = Command::new(agentwire)
        .arg("inspect")
        .arg(&trace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let summary: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(summary["client_messages"], 5);
    assert_eq!(summary["server_messages"], 5);
    assert_eq!(summary["methods"]["sampling/createMessage"], 1);

    let replay = run_with_input(
        Command::new(agentwire).arg("replay").arg(&trace),
        MCP_CLIENT_INPUT,
    );
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(replay.stdout, record.stdout);
}

#[test]
fn mcp_replay_forwards_sampling_request_to_interactive_client() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("mcp-pipelined.jsonl");
    record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-mcp-server"),
        MCP_CLIENT_INPUT,
        &trace,
    );

    let mut session = spawn_interactive_replay(&trace);
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"live-1","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{}},"clientInfo":{"name":"live","version":"0.1"}}}"#,
    );
    let response = receive(&session.receiver);
    assert_eq!(response["id"], "live-1");
    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"live-2","method":"tools/list"}"#,
    );
    let tools = receive(&session.receiver);
    assert_eq!(tools["id"], "live-2");
    assert_eq!(tools["result"]["tools"][0]["name"], "summarize");
    assert_eq!(
        receive(&session.receiver)["method"],
        "notifications/message"
    );
    // The server-initiated sampling request arrives with its recorded ID,
    // and the tool result stays held until the client answers it.
    let sampling = receive(&session.receiver);
    assert_eq!(sampling["method"], "sampling/createMessage");
    assert_eq!(sampling["id"], "samp-1");
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"live-3","method":"tools/call","params":{"name":"summarize","arguments":{"text":"AgentWire records agent protocols."}}}"#,
    );
    send(
        &mut session.input,
        r#"{"jsonrpc":"2.0","id":"samp-1","result":{"role":"assistant","content":{"type":"text","text":"A protocol tap."},"model":"mock-model","stopReason":"endTurn"}}"#,
    );
    let result = receive(&session.receiver);
    assert_eq!(result["id"], "live-3");
    assert_eq!(result["result"]["content"][0]["text"], "A protocol tap.");
    assert_eq!(result["result"]["isError"], false);
    drop(session.input);
    assert!(session.child.wait().unwrap().success());
}

#[test]
fn diff_ignores_run_varying_fields() {
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("run-1.jsonl");
    let right = directory.path().join("run-2.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");
    let mock = env!("CARGO_BIN_EXE_agentwire-mock-server");

    // The same scripted session with a freshly generated thread ID, as a
    // real agent produces on every run.
    let varied = CLIENT_INPUT.replace("thread-demo", "thread-other");
    record_trace(mock, CLIENT_INPUT, &left);
    record_trace(mock, &varied, &right);

    let strict = Command::new(agentwire)
        .arg("diff")
        .arg(&left)
        .arg(&right)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(strict.status.code(), Some(1));
    let comparison: Value = serde_json::from_slice(&strict.stdout).unwrap();
    assert_eq!(
        comparison["differences"][0]["changes"][0]["path"],
        "/payload/params/threadId"
    );

    let ignored = Command::new(agentwire)
        .arg("diff")
        .arg(&left)
        .arg(&right)
        .arg("--ignore")
        .arg("threadId")
        .output()
        .unwrap();
    assert!(
        ignored.status.success(),
        "{}",
        String::from_utf8_lossy(&ignored.stdout)
    );
    assert!(String::from_utf8_lossy(&ignored.stdout).contains("1 ignore rule(s) applied"));
}

#[test]
fn replay_strict_payload_ignores_transport_ids() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("strict.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");
    record_trace(
        env!("CARGO_BIN_EXE_agentwire-mock-server"),
        CLIENT_INPUT,
        &trace,
    );

    // Identical payloads under fresh transport IDs must pass strict mode.
    let remapped = CLIENT_INPUT
        .replace(r#""id":1"#, r#""id":"live-a""#)
        .replace(r#""id":2"#, r#""id":"live-b""#)
        .replace(r#""id":3"#, r#""id":"live-c""#);
    let replay = run_with_input(
        Command::new(agentwire)
            .arg("replay")
            .arg(&trace)
            .arg("--strict-payload"),
        &remapped,
    );
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );

    // A genuinely changed payload must still fail.
    let changed = run_with_input(
        Command::new(agentwire)
            .arg("replay")
            .arg(&trace)
            .arg("--strict-payload"),
        CHANGED_CLIENT_INPUT,
    );
    assert_eq!(changed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&changed.stderr).contains("payload mismatch"));
}

#[test]
fn diff_identifies_protocol_payload_regression() {
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("before.jsonl");
    let right = directory.path().join("after.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");
    let mock = env!("CARGO_BIN_EXE_agentwire-mock-server");

    for (trace, input) in [(&left, CLIENT_INPUT), (&right, CHANGED_CLIENT_INPUT)] {
        record_trace(mock, input, trace);
    }

    let equal = Command::new(agentwire)
        .arg("diff")
        .arg(&left)
        .arg(&left)
        .output()
        .unwrap();
    assert!(equal.status.success());
    assert!(String::from_utf8_lossy(&equal.stdout).contains("protocol-equivalent"));

    let changed = Command::new(agentwire)
        .arg("diff")
        .arg(&left)
        .arg(&right)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(changed.status.code(), Some(1));
    let comparison: Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(comparison["equal"], false);
    assert_eq!(comparison["differences_found"], 1);
    assert_eq!(
        comparison["differences"][0]["changes"][0]["path"],
        "/payload/params/input/0/text"
    );
}
