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
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mock-mcp", "version": "0.1" }
                }
            })),
            Some("notifications/initialized") => {}
            Some("tools/list") => emit(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": [{
                    "name": "summarize",
                    "description": "Summarize text with the client's model",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "text": { "type": "string" } },
                        "required": ["text"]
                    }
                }] }
            })),
            Some("tools/call") => {
                let text = message
                    .pointer("/params/arguments/text")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                emit(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "info",
                        "logger": "mock-mcp",
                        "data": "Summarizing via client sampling."
                    }
                }));
                emit(json!({
                    "jsonrpc": "2.0",
                    "id": "samp-1",
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [{
                            "role": "user",
                            "content": { "type": "text", "text": format!("Summarize: {text}") }
                        }],
                        "maxTokens": 64
                    }
                }));
                // A real MCP server blocks here until the client's model
                // returns a completion.
                let reply: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
                let summary = reply
                    .pointer("/result/content/text")
                    .and_then(Value::as_str)
                    .unwrap_or("(no summary)")
                    .to_owned();
                emit(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": summary }],
                        "isError": false
                    }
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
