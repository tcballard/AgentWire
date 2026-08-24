use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

pub const IGNORED: &str = "[ignored]";

/// A user-supplied rule marking payload values that legitimately vary
/// between runs (generated thread IDs, timestamps) so they compare equal.
#[derive(Clone, Debug)]
pub struct IgnoreRule {
    source: String,
    matcher: Matcher,
}

#[derive(Clone, Debug)]
enum Matcher {
    /// Bare key name: matches an object member with this key at any depth.
    Key(String),
    /// JSON pointer segments as printed in diff output (starting with
    /// /payload); a `*` segment matches any single key or array index.
    Path(Vec<String>),
}

impl IgnoreRule {
    pub fn parse(rule: &str) -> Result<IgnoreRule, String> {
        if rule.is_empty() {
            return Err("ignore rule cannot be empty".into());
        }
        let matcher = if let Some(pointer) = rule.strip_prefix('/') {
            let segments: Vec<String> = pointer
                .split('/')
                .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
                .collect();
            if segments.iter().any(String::is_empty) {
                return Err(format!("ignore path {rule} has an empty segment"));
            }
            Matcher::Path(segments)
        } else {
            Matcher::Key(rule.to_owned())
        };
        Ok(IgnoreRule {
            source: rule.to_owned(),
            matcher,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    fn matches(&self, key: Option<&str>, path: &[String]) -> bool {
        match &self.matcher {
            Matcher::Key(name) => key == Some(name.as_str()),
            Matcher::Path(segments) => {
                segments.len() == path.len()
                    && segments
                        .iter()
                        .zip(path)
                        .all(|(segment, part)| segment == "*" || segment == part)
            }
        }
    }
}

fn apply_ignores_at(value: &mut Value, path: &mut Vec<String>, rules: &[IgnoreRule]) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                path.push(key.clone());
                if rules.iter().any(|rule| rule.matches(Some(key), path)) {
                    *child = Value::String(IGNORED.into());
                } else {
                    apply_ignores_at(child, path, rules);
                }
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                path.push(index.to_string());
                if rules.iter().any(|rule| rule.matches(None, path)) {
                    *child = Value::String(IGNORED.into());
                } else {
                    apply_ignores_at(child, path, rules);
                }
                path.pop();
            }
        }
        _ => {}
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ComparableEvent {
    pub direction: String,
    pub kind: String,
    pub method: Option<String>,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ValueChange {
    pub path: String,
    pub left: Option<Value>,
    pub right: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EventDifference {
    pub stream: String,
    pub event: usize,
    pub kind: String,
    pub left: Option<ComparableEvent>,
    pub right: Option<ComparableEvent>,
    pub changes: Vec<ValueChange>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TraceDiff {
    pub equal: bool,
    pub left_events: usize,
    pub right_events: usize,
    pub differences_found: usize,
    pub ignored_request_ids: bool,
    pub ignored: Vec<String>,
    pub truncated: bool,
    pub differences: Vec<EventDifference>,
}

fn protocol_events(
    events: &[Value],
    strict_ids: bool,
    ignores: &[IgnoreRule],
) -> Vec<ComparableEvent> {
    events
        .iter()
        .filter_map(|event| {
            let direction = event.get("direction")?.as_str()?;
            if !matches!(direction, "client_to_server" | "server_to_client") {
                return None;
            }
            let mut payload = event.get("payload").cloned().unwrap_or(Value::Null);
            if !strict_ids {
                if let Some(object) = payload.as_object_mut() {
                    object.remove("id");
                }
            }
            if !ignores.is_empty() {
                let mut path = vec!["payload".to_owned()];
                apply_ignores_at(&mut payload, &mut path, ignores);
            }
            Some(ComparableEvent {
                direction: direction.to_owned(),
                kind: event
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("message")
                    .to_owned(),
                method: event
                    .get("method")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                payload,
            })
        })
        .collect()
}

fn pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn child_path(path: &str, segment: &str) -> String {
    if path.is_empty() {
        format!("/{}", pointer_segment(segment))
    } else {
        format!("{path}/{}", pointer_segment(segment))
    }
}

fn collect_value_changes(
    path: &str,
    left: Option<&Value>,
    right: Option<&Value>,
    changes: &mut Vec<ValueChange>,
    limit: usize,
) {
    if changes.len() >= limit || left == right {
        return;
    }
    match (left, right) {
        (Some(Value::Object(left)), Some(Value::Object(right))) => {
            let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
            for key in keys {
                collect_value_changes(
                    &child_path(path, key),
                    left.get(key),
                    right.get(key),
                    changes,
                    limit,
                );
                if changes.len() >= limit {
                    break;
                }
            }
        }
        (Some(Value::Array(left)), Some(Value::Array(right))) => {
            for index in 0..left.len().max(right.len()) {
                collect_value_changes(
                    &child_path(path, &index.to_string()),
                    left.get(index),
                    right.get(index),
                    changes,
                    limit,
                );
                if changes.len() >= limit {
                    break;
                }
            }
        }
        _ => changes.push(ValueChange {
            path: if path.is_empty() {
                "/".into()
            } else {
                path.into()
            },
            left: left.cloned(),
            right: right.cloned(),
        }),
    }
}

pub fn compare_traces(
    left: &[Value],
    right: &[Value],
    strict_ids: bool,
    max_differences: usize,
    ignores: &[IgnoreRule],
) -> TraceDiff {
    let left = protocol_events(left, strict_ids, ignores);
    let right = protocol_events(right, strict_ids, ignores);
    let mut differences = Vec::new();
    let mut differences_found = 0;

    for direction in ["client_to_server", "server_to_client"] {
        let left_stream: Vec<&ComparableEvent> = left
            .iter()
            .filter(|event| event.direction == direction)
            .collect();
        let right_stream: Vec<&ComparableEvent> = right
            .iter()
            .filter(|event| event.direction == direction)
            .collect();
        for index in 0..left_stream.len().max(right_stream.len()) {
            let left_event = left_stream.get(index).copied();
            let right_event = right_stream.get(index).copied();
            if left_event == right_event {
                continue;
            }
            differences_found += 1;
            if differences.len() >= max_differences {
                continue;
            }
            let kind = match (left_event, right_event) {
                (Some(_), Some(_)) => "changed",
                (Some(_), None) => "left_only",
                (None, Some(_)) => "right_only",
                (None, None) => unreachable!(),
            };
            let mut changes = Vec::new();
            if let (Some(left_event), Some(right_event)) = (left_event, right_event) {
                if left_event.kind != right_event.kind {
                    changes.push(ValueChange {
                        path: "/kind".into(),
                        left: Some(Value::String(left_event.kind.clone())),
                        right: Some(Value::String(right_event.kind.clone())),
                    });
                }
                if left_event.method != right_event.method {
                    changes.push(ValueChange {
                        path: "/method".into(),
                        left: left_event.method.clone().map(Value::String),
                        right: right_event.method.clone().map(Value::String),
                    });
                }
                collect_value_changes(
                    "/payload",
                    Some(&left_event.payload),
                    Some(&right_event.payload),
                    &mut changes,
                    12,
                );
            }
            differences.push(EventDifference {
                stream: direction.into(),
                event: index + 1,
                kind: kind.into(),
                left: left_event.cloned(),
                right: right_event.cloned(),
                changes,
            });
        }
    }

    TraceDiff {
        equal: differences_found == 0,
        left_events: left.len(),
        right_events: right.len(),
        differences_found,
        ignored_request_ids: !strict_ids,
        ignored: ignores
            .iter()
            .map(|rule| rule.source().to_owned())
            .collect(),
        truncated: differences_found > differences.len(),
        differences,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(direction: &str, kind: &str, method: Option<&str>, payload: Value) -> Value {
        json!({
            "trace_version": 1,
            "direction": direction,
            "kind": kind,
            "method": method,
            "payload": payload,
        })
    }

    #[test]
    fn ignores_transport_request_ids_by_default() {
        let left = vec![event(
            "client_to_server",
            "request",
            Some("initialize"),
            json!({ "id": 1, "method": "initialize", "params": {} }),
        )];
        let right = vec![event(
            "client_to_server",
            "request",
            Some("initialize"),
            json!({ "id": "new-id", "method": "initialize", "params": {} }),
        )];
        assert!(compare_traces(&left, &right, false, 20, &[]).equal);
        assert!(!compare_traces(&left, &right, true, 20, &[]).equal);
    }

    #[test]
    fn reports_nested_payload_path() {
        let left = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            json!({ "id": 1, "method": "turn/start", "params": { "input": [{ "text": "hello" }] } }),
        )];
        let right = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            json!({ "id": 2, "method": "turn/start", "params": { "input": [{ "text": "goodbye" }] } }),
        )];
        let comparison = compare_traces(&left, &right, false, 20, &[]);
        assert_eq!(comparison.differences_found, 1);
        assert_eq!(
            comparison.differences[0].changes[0].path,
            "/payload/params/input/0/text"
        );
    }

    fn rules(sources: &[&str]) -> Vec<IgnoreRule> {
        sources
            .iter()
            .map(|source| IgnoreRule::parse(source).unwrap())
            .collect()
    }

    #[test]
    fn ignores_run_varying_values_by_key_anywhere() {
        let left = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            json!({ "method": "turn/start", "params": { "threadId": "thread-a", "input": [] } }),
        )];
        let right = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            json!({ "method": "turn/start", "params": { "threadId": "thread-b", "input": [] } }),
        )];
        assert!(!compare_traces(&left, &right, false, 20, &[]).equal);
        let comparison = compare_traces(&left, &right, false, 20, &rules(&["threadId"]));
        assert!(comparison.equal);
        assert_eq!(comparison.ignored, vec!["threadId"]);
    }

    #[test]
    fn ignored_key_still_reports_presence_mismatch() {
        let left = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            json!({ "method": "turn/start", "params": { "threadId": "thread-a" } }),
        )];
        let right = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            json!({ "method": "turn/start", "params": {} }),
        )];
        let comparison = compare_traces(&left, &right, false, 20, &rules(&["threadId"]));
        assert_eq!(comparison.differences_found, 1);
        let change = &comparison.differences[0].changes[0];
        assert_eq!(change.path, "/payload/params/threadId");
        assert_eq!(change.left, Some(Value::String(IGNORED.into())));
        assert_eq!(change.right, None);
    }

    #[test]
    fn ignores_values_by_pointer_with_wildcard_segments() {
        let payload = |text: &str, cwd: &str| {
            json!({ "method": "turn/start", "params": {
                "input": [{ "type": "text", "text": text }],
                "cwd": cwd
            } })
        };
        let left = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            payload("hello", "/tmp/run-1"),
        )];
        let right = vec![event(
            "client_to_server",
            "request",
            Some("turn/start"),
            payload("goodbye", "/tmp/run-2"),
        )];
        let text_only = rules(&["/payload/params/input/*/text"]);
        let comparison = compare_traces(&left, &right, false, 20, &text_only);
        // The text difference is ignored; the cwd difference still surfaces.
        assert_eq!(comparison.differences_found, 1);
        assert_eq!(
            comparison.differences[0].changes[0].path,
            "/payload/params/cwd"
        );
        let both = rules(&["/payload/params/input/*/text", "/payload/params/cwd"]);
        assert!(compare_traces(&left, &right, false, 20, &both).equal);
    }

    #[test]
    fn ignore_rule_parsing_rejects_malformed_input() {
        assert!(IgnoreRule::parse("").is_err());
        assert!(IgnoreRule::parse("/payload//text").is_err());
        let escaped = IgnoreRule::parse("/payload/a~1b").unwrap();
        assert!(escaped.matches(Some("a/b"), &["payload".into(), "a/b".into()]));
    }

    #[test]
    fn ignores_scheduler_dependent_duplex_interleaving() {
        let request = event(
            "client_to_server",
            "request",
            Some("initialize"),
            json!({ "id": 1, "method": "initialize" }),
        );
        let notification = event(
            "client_to_server",
            "notification",
            Some("initialized"),
            json!({ "method": "initialized" }),
        );
        let response = event(
            "server_to_client",
            "response",
            None,
            json!({ "id": 1, "result": {} }),
        );
        let left = vec![request.clone(), response.clone(), notification.clone()];
        let right = vec![request, notification, response];
        assert!(compare_traces(&left, &right, false, 20, &[]).equal);
    }
}
