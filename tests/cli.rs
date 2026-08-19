use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const CLIENT_INPUT: &str = include_str!("fixtures/client.jsonl");
const CHANGED_CLIENT_INPUT: &str = include_str!("fixtures/client-changed.jsonl");

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

#[test]
fn record_inspect_and_replay_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("round-trip.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");
    let mock = env!("CARGO_BIN_EXE_agentwire-mock-server");

    let record = run_with_input(
        Command::new(agentwire)
            .arg("record")
            .arg("--trace")
            .arg(&trace)
            .arg("--")
            .arg(mock),
        CLIENT_INPUT,
    );
    assert!(
        record.status.success(),
        "{}",
        String::from_utf8_lossy(&record.stderr)
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
    let agentwire = env!("CARGO_BIN_EXE_agentwire");
    let mock = env!("CARGO_BIN_EXE_agentwire-mock-server");

    // The fixture pipelines every client message up front, so most client
    // events are recorded before the server output they causally follow.
    let record = run_with_input(
        Command::new(agentwire)
            .arg("record")
            .arg("--trace")
            .arg(&trace)
            .arg("--")
            .arg(mock),
        CLIENT_INPUT,
    );
    assert!(
        record.status.success(),
        "{}",
        String::from_utf8_lossy(&record.stderr)
    );

    // Drive replay as an interactive client: send one message, then block on
    // the matching response before continuing, using fresh request IDs.
    let mut replay = Command::new(agentwire)
        .arg("replay")
        .arg(&trace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = replay.stdin.take().unwrap();
    let output = BufReader::new(replay.stdout.take().unwrap());
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in output.lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let receive = |receiver: &Receiver<String>| -> Value {
        let line = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("replay stalled instead of emitting the next server message");
        serde_json::from_str(&line).unwrap()
    };
    let send = |input: &mut std::process::ChildStdin, message: &str| {
        input.write_all(message.as_bytes()).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    };

    send(
        &mut input,
        r#"{"id":"live-1","method":"initialize","params":{}}"#,
    );
    assert_eq!(receive(&receiver)["id"], "live-1");
    send(&mut input, r#"{"method":"initialized"}"#);
    send(
        &mut input,
        r#"{"id":"live-2","method":"thread/start","params":{}}"#,
    );
    assert_eq!(receive(&receiver)["id"], "live-2");
    assert_eq!(receive(&receiver)["method"], "thread/started");
    send(
        &mut input,
        r#"{"id":"live-3","method":"turn/start","params":{}}"#,
    );
    assert_eq!(receive(&receiver)["id"], "live-3");
    assert_eq!(receive(&receiver)["method"], "turn/started");
    assert_eq!(receive(&receiver)["method"], "item/agentMessage/delta");
    assert_eq!(receive(&receiver)["method"], "turn/completed");
    drop(input);
    let status = replay.wait().unwrap();
    assert!(status.success());
}

#[test]
fn diff_identifies_protocol_payload_regression() {
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("before.jsonl");
    let right = directory.path().join("after.jsonl");
    let agentwire = env!("CARGO_BIN_EXE_agentwire");
    let mock = env!("CARGO_BIN_EXE_agentwire-mock-server");

    for (trace, input) in [(&left, CLIENT_INPUT), (&right, CHANGED_CLIENT_INPUT)] {
        let record = run_with_input(
            Command::new(agentwire)
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
