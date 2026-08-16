use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn emit(message: Value) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &message).unwrap();
    output.write_all(b"\n").unwrap();
    output.flush().unwrap();
}

fn main() {
    for line in io::stdin().lock().lines() {
        let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        match method {
            Some("initialize") => emit(
                json!({ "id": id, "result": { "serverInfo": { "name": "mock-codex", "version": "0.1" } } }),
            ),
            Some("initialized") => {}
            Some("thread/start") => {
                emit(
                    json!({ "id": id, "result": { "thread": { "id": "thread-demo", "status": "idle" } } }),
                );
                emit(
                    json!({ "method": "thread/started", "params": { "thread": { "id": "thread-demo", "status": "idle" } } }),
                );
            }
            Some("turn/start") => {
                emit(
                    json!({ "id": id, "result": { "turn": { "id": "turn-demo", "status": "inProgress" } } }),
                );
                emit(
                    json!({ "method": "turn/started", "params": { "threadId": "thread-demo", "turn": { "id": "turn-demo" } } }),
                );
                emit(
                    json!({ "method": "item/agentMessage/delta", "params": { "threadId": "thread-demo", "turnId": "turn-demo", "delta": "Hello from the mock server." } }),
                );
                emit(
                    json!({ "method": "turn/completed", "params": { "threadId": "thread-demo", "turn": { "id": "turn-demo", "status": "completed" } } }),
                );
            }
            _ => emit(
                json!({ "id": id, "error": { "code": -32601, "message": format!("unknown method: {method:?}") } }),
            ),
        }
    }
}
