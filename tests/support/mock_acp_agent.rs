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
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(line) = lines.next() {
        let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        match method {
            Some("initialize") => emit(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": 1,
                    "agentCapabilities": { "loadSession": false },
                    "authMethods": []
                }
            })),
            Some("session/new") => emit(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "sessionId": "sess-demo" }
            })),
            Some("session/prompt") => {
                let session = message
                    .pointer("/params/sessionId")
                    .cloned()
                    .unwrap_or(Value::Null);
                emit(json!({
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": { "sessionId": session, "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": { "type": "text", "text": "Let me update that file." }
                    } }
                }));
                emit(json!({
                    "jsonrpc": "2.0",
                    "id": "perm-1",
                    "method": "session/request_permission",
                    "params": {
                        "sessionId": session,
                        "toolCall": { "toolCallId": "tool-1", "title": "Write config" },
                        "options": [
                            { "optionId": "allow", "name": "Allow", "kind": "allow_once" },
                            { "optionId": "reject", "name": "Reject", "kind": "reject_once" }
                        ]
                    }
                }));
                // A real ACP agent blocks here until the client decides.
                let reply: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
                let allowed = reply
                    .pointer("/result/outcome/optionId")
                    .and_then(Value::as_str)
                    == Some("allow");
                emit(json!({
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": { "sessionId": session, "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": { "type": "text", "text": if allowed { "Done." } else { "Skipped." } }
                    } }
                }));
                emit(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "stopReason": "end_turn" }
                }));
            }
            Some(_) => emit(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "method not found" }
            })),
            None => {}
        }
    }
}
