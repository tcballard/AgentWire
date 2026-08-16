use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const CLIENT_INPUT: &str = concat!(
    "{\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"test\",\"version\":\"0.1\"}}}\n",
    "{\"method\":\"initialized\"}\n",
    "{\"id\":2,\"method\":\"thread/start\",\"params\":{\"cwd\":\".\"}}\n",
    "{\"id\":3,\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-demo\",\"input\":[{\"type\":\"text\",\"text\":\"hello\"}]}}\n",
);

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
