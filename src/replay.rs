//! Planning for deterministic replay.
//!
//! The recorded interleaving between the two duplex streams depends on thread
//! scheduling, so replay must not trust it: a trace recorded from a pipelining
//! client would deadlock an interactive client that waits for each response.
//! Instead, replay preserves per-stream order and gates each server message on
//! JSON-RPC causality — the only cross-stream ordering the protocol guarantees:
//!
//! - a server response waits until the live client has sent the matching
//!   request;
//! - a server notification (or server-initiated request) waits with the last
//!   gated server message recorded before it;
//! - a client reply to a server-initiated request also gates later server
//!   output, because the recorded client could only answer a request the
//!   server had already sent.

use crate::core::{classify_message, id_key, request_id_of};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub struct ClientStep {
    pub payload: Value,
    pub method: Option<String>,
    pub elapsed_ms: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerStep {
    pub payload: Value,
    pub elapsed_ms: f64,
    /// Number of client messages that must have arrived before this emits.
    pub gate: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReplayPlan {
    pub client: Vec<ClientStep>,
    pub server: Vec<ServerStep>,
}

pub fn plan_replay(events: &[Value]) -> ReplayPlan {
    let mut plan = ReplayPlan::default();
    let mut request_positions: HashMap<String, usize> = HashMap::new();
    let mut pending_gate = 0;
    let mut elapsed = 0.0;
    for event in events {
        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
        let (kind, method, _) = classify_message(Some(&payload));
        elapsed = event
            .get("elapsed_ms")
            .and_then(Value::as_f64)
            .unwrap_or(elapsed);
        match event.get("direction").and_then(Value::as_str) {
            Some("client_to_server") => {
                let position = plan.client.len();
                if kind == "request" {
                    if let Some(id) = request_id_of(&payload) {
                        request_positions.insert(id_key(id), position);
                    }
                } else if kind == "response" {
                    pending_gate = pending_gate.max(position + 1);
                }
                plan.client.push(ClientStep {
                    method: method.map(str::to_owned),
                    payload,
                    elapsed_ms: elapsed,
                });
            }
            Some("server_to_client") => {
                let mut gate = pending_gate;
                if kind == "response" {
                    if let Some(position) =
                        request_id_of(&payload).and_then(|id| request_positions.get(&id_key(id)))
                    {
                        gate = gate.max(position + 1);
                    }
                }
                pending_gate = gate;
                plan.server.push(ServerStep {
                    payload,
                    elapsed_ms: elapsed,
                    gate,
                });
            }
            _ => {}
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(direction: &str, payload: Value) -> Value {
        json!({
            "trace_version": 1,
            "direction": direction,
            "elapsed_ms": 0.0,
            "payload": payload,
        })
    }

    #[test]
    fn gates_responses_on_their_requests_despite_pipelined_recording() {
        // All client messages were recorded before any server output, as a
        // pipelining client produces.
        let events = vec![
            event(
                "client_to_server",
                json!({ "id": 1, "method": "initialize" }),
            ),
            event("client_to_server", json!({ "method": "initialized" })),
            event(
                "client_to_server",
                json!({ "id": 2, "method": "thread/start" }),
            ),
            event(
                "client_to_server",
                json!({ "id": 3, "method": "turn/start" }),
            ),
            event("server_to_client", json!({ "id": 1, "result": {} })),
            event("server_to_client", json!({ "id": 2, "result": {} })),
            event("server_to_client", json!({ "method": "thread/started" })),
            event("server_to_client", json!({ "id": 3, "result": {} })),
            event("server_to_client", json!({ "method": "turn/completed" })),
        ];
        let plan = plan_replay(&events);
        let gates: Vec<usize> = plan.server.iter().map(|step| step.gate).collect();
        // The initialize response needs only the initialize request, not the
        // whole pipelined batch; each later message waits for its own cause.
        assert_eq!(gates, vec![1, 3, 3, 4, 4]);
    }

    #[test]
    fn notification_recorded_after_next_request_does_not_wait_for_it() {
        // Scheduling recorded turn/start before the thread/started
        // notification that the client waits for; replay must still emit the
        // notification first.
        let events = vec![
            event(
                "client_to_server",
                json!({ "id": 1, "method": "thread/start" }),
            ),
            event("server_to_client", json!({ "id": 1, "result": {} })),
            event(
                "client_to_server",
                json!({ "id": 2, "method": "turn/start" }),
            ),
            event("server_to_client", json!({ "method": "thread/started" })),
            event("server_to_client", json!({ "id": 2, "result": {} })),
        ];
        let plan = plan_replay(&events);
        let gates: Vec<usize> = plan.server.iter().map(|step| step.gate).collect();
        assert_eq!(gates, vec![1, 1, 2]);
    }

    #[test]
    fn client_reply_to_server_request_gates_later_output() {
        let events = vec![
            event(
                "client_to_server",
                json!({ "id": 1, "method": "turn/start" }),
            ),
            event("server_to_client", json!({ "id": 1, "result": {} })),
            event(
                "server_to_client",
                json!({ "id": "approval-1", "method": "execCommandApproval" }),
            ),
            event(
                "client_to_server",
                json!({ "id": "approval-1", "result": { "decision": "approved" } }),
            ),
            event("server_to_client", json!({ "method": "turn/completed" })),
        ];
        let plan = plan_replay(&events);
        let gates: Vec<usize> = plan.server.iter().map(|step| step.gate).collect();
        // turn/completed was only observed after the approval reply, so it
        // must wait for both client messages.
        assert_eq!(gates, vec![1, 1, 2]);
    }
}
