use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use regex::{Captures, Regex};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const TRACE_VERSION: u64 = 1;
pub const REDACTED: &str = "[REDACTED]";

fn bearer_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}").unwrap())
}

fn openai_key_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(r"\bsk-[A-Za-z0-9_-]{8,}").unwrap())
}

fn env_secret_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY))=([^\s]+)").unwrap()
    })
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Compared against the end of the normalized key so that prefixed variants
/// (`client_secret`, `refresh_token`, `sshPrivateKey`, `X-Api-Key`) match.
/// Bare `key` and plural `tokens` are deliberately absent: they would swallow
/// structural fields such as `cacheKey`, `sortKey`, and LLM usage counters
/// like `inputTokens`.
const SENSITIVE_KEY_SUFFIXES: &[&str] = &[
    "apikey",
    "apikeys",
    "authorization",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "passphrase",
    "password",
    "privatekey",
    "secret",
    "secrets",
    "token",
];

fn sensitive_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    SENSITIVE_KEY_SUFFIXES
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

pub fn redact_string(value: &str) -> String {
    let value = bearer_re()
        .replace_all(value, |captures: &Captures<'_>| {
            format!("{}{}", &captures[1], REDACTED)
        })
        .into_owned();
    let value = openai_key_re().replace_all(&value, REDACTED).into_owned();
    env_secret_re()
        .replace_all(&value, |captures: &Captures<'_>| {
            format!("{}={}", &captures[1], REDACTED)
        })
        .into_owned()
}

pub fn redact(value: &Value) -> Value {
    redact_at(value, None)
}

fn redact_at(value: &Value, parent_key: Option<&str>) -> Value {
    if parent_key.is_some_and(sensitive_key) {
        return Value::String(REDACTED.into());
    }
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), redact_at(value, Some(key))))
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.iter().map(|value| redact_at(value, None)).collect())
        }
        Value::String(value) => Value::String(redact_string(value)),
        _ => value.clone(),
    }
}

pub fn parse_message(line: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(line)
        .ok()
        .filter(Value::is_object)
}

pub fn classify_message(message: Option<&Value>) -> (&'static str, Option<&str>, Value) {
    let Some(object) = message.and_then(Value::as_object) else {
        return ("invalid", None, Value::Null);
    };
    let method = object.get("method").and_then(Value::as_str);
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    if let Some(method) = method {
        return (
            if object.contains_key("id") {
                "request"
            } else {
                "notification"
            },
            Some(method),
            id,
        );
    }
    if object.contains_key("id") && (object.contains_key("result") || object.contains_key("error"))
    {
        return ("response", None, id);
    }
    ("message", None, id)
}

fn safe_command(command: &[OsString]) -> Vec<String> {
    let mut safe = Vec::with_capacity(command.len());
    let mut hide_next = false;
    for argument in command {
        let argument = argument.to_string_lossy();
        if hide_next {
            safe.push(REDACTED.into());
            hide_next = false;
            continue;
        }
        let lowered = argument.to_lowercase();
        if ["token", "secret", "password", "api-key", "api_key"]
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            if let Some((name, _)) = argument.split_once('=') {
                safe.push(format!("{name}={REDACTED}"));
            } else {
                safe.push(argument.into_owned());
                hide_next = true;
            }
        } else {
            safe.push(redact_string(&argument));
        }
    }
    safe
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn session_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}-{:x}", std::process::id(), nanos)
}

struct RecorderState {
    writer: Option<BufWriter<File>>,
    sequence: u64,
}

pub struct TraceRecorder {
    path: PathBuf,
    session_id: String,
    started: Instant,
    state: Mutex<RecorderState>,
}

impl TraceRecorder {
    pub fn new(path: impl Into<PathBuf>, command: &[OsString]) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("could not create trace directory {}", parent.display())
            })?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .with_context(|| format!("could not create trace {}", path.display()))?;
        let recorder = Self {
            path,
            session_id: session_id(),
            started: Instant::now(),
            state: Mutex::new(RecorderState {
                writer: Some(BufWriter::new(file)),
                sequence: 0,
            }),
        };
        recorder.record_meta("session_start", json!({ "command": safe_command(command) }))?;
        Ok(recorder)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_event(&self, mut event: Map<String, Value>) -> Result<()> {
        let mut state = self.state.lock().expect("trace recorder mutex poisoned");
        if state.writer.is_none() {
            return Ok(());
        }
        let sequence = state.sequence;
        state.sequence += 1;
        event.insert("seq".into(), Value::from(sequence));
        let writer = state.writer.as_mut().expect("writer checked above");
        serde_json::to_writer(&mut *writer, &Value::Object(event))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    pub fn record_meta(&self, kind: &str, payload: Value) -> Result<()> {
        let event = json!({
            "trace_version": TRACE_VERSION,
            "session_id": self.session_id,
            "timestamp": utc_now(),
            "elapsed_ms": self.started.elapsed().as_secs_f64() * 1000.0,
            "direction": "meta",
            "kind": kind,
            "method": null,
            "id": null,
            "payload": redact(&payload),
        });
        self.write_event(event.as_object().unwrap().clone())
    }

    pub fn record_line(&self, direction: &str, line: &[u8]) -> Result<()> {
        let message = parse_message(line);
        let (kind, method, id) = classify_message(message.as_ref());
        let payload = message.as_ref().map(redact).unwrap_or_else(
            || json!({ "omitted": "non-JSON protocol line", "length": line.len() }),
        );
        let event = json!({
            "trace_version": TRACE_VERSION,
            "session_id": self.session_id,
            "timestamp": utc_now(),
            "elapsed_ms": self.started.elapsed().as_secs_f64() * 1000.0,
            "direction": direction,
            "kind": kind,
            "method": method,
            "id": redact(&id),
            "payload": payload,
        });
        self.write_event(event.as_object().unwrap().clone())
    }

    pub fn close(&self, exit_code: Option<i32>) -> Result<()> {
        self.record_meta("session_end", json!({ "exit_code": exit_code }))?;
        let mut state = self.state.lock().expect("trace recorder mutex poisoned");
        if let Some(mut writer) = state.writer.take() {
            writer.flush()?;
        }
        Ok(())
    }
}

pub fn load_trace(path: &Path) -> Result<Vec<Value>> {
    let file =
        File::open(path).with_context(|| format!("could not open trace {}", path.display()))?;
    let mut events = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(&line)
            .with_context(|| format!("invalid trace JSON on line {}", index + 1))?;
        if !event.is_object() {
            bail!(
                "invalid trace event on line {}: expected an object",
                index + 1
            );
        }
        if event.get("trace_version").and_then(Value::as_u64) != Some(TRACE_VERSION) {
            bail!("unsupported trace version on line {}", index + 1);
        }
        events.push(event);
    }
    Ok(events)
}

pub fn method_of(payload: &Value) -> Option<&str> {
    payload.get("method").and_then(Value::as_str)
}

pub fn request_id_of(payload: &Value) -> Option<&Value> {
    payload.as_object()?.get("id")
}

pub(crate) fn id_key(value: &Value) -> String {
    serde_json::to_string(value).expect("JSON value must serialize")
}

pub fn rewrite_response_id(payload: &Value, id_map: &HashMap<String, Value>) -> Value {
    let Some(object) = payload.as_object() else {
        return payload.clone();
    };
    if object.contains_key("method") || !object.contains_key("id") {
        return payload.clone();
    }
    let Some(new_id) = object.get("id").and_then(|id| id_map.get(&id_key(id))) else {
        return payload.clone();
    };
    let mut rewritten = object.clone();
    rewritten.insert("id".into(), new_id.clone());
    Value::Object(rewritten)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct TraceSummary {
    pub events: usize,
    pub duration_ms: f64,
    pub client_messages: usize,
    pub server_messages: usize,
    pub invalid_messages: usize,
    pub methods: BTreeMap<String, usize>,
    pub errors: usize,
}

pub fn summarize(events: &[Value]) -> TraceSummary {
    let protocol: Vec<&Value> = events
        .iter()
        .filter(|event| event.get("direction").and_then(Value::as_str) != Some("meta"))
        .collect();
    let mut methods = BTreeMap::new();
    for method in protocol
        .iter()
        .filter_map(|event| event.get("method").and_then(Value::as_str))
    {
        *methods.entry(method.to_owned()).or_insert(0) += 1;
    }
    TraceSummary {
        events: protocol.len(),
        duration_ms: events
            .iter()
            .filter_map(|event| event.get("elapsed_ms").and_then(Value::as_f64))
            .fold(0.0, f64::max),
        client_messages: protocol
            .iter()
            .filter(|event| {
                event.get("direction").and_then(Value::as_str) == Some("client_to_server")
            })
            .count(),
        server_messages: protocol
            .iter()
            .filter(|event| {
                event.get("direction").and_then(Value::as_str) == Some("server_to_client")
            })
            .count(),
        invalid_messages: protocol
            .iter()
            .filter(|event| event.get("kind").and_then(Value::as_str) == Some("invalid"))
            .count(),
        errors: protocol
            .iter()
            .filter(|event| event.pointer("/payload/error").is_some())
            .count(),
        methods,
    }
}

pub fn remember_request_id(
    recorded: &Value,
    incoming: &Value,
    id_map: &mut HashMap<String, Value>,
) {
    if let (Some(recorded_id), Some(incoming_id)) =
        (request_id_of(recorded), request_id_of(incoming))
    {
        id_map.insert(id_key(recorded_id), incoming_id.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_nested_and_inline_secrets() {
        let value = json!({
            "authorization": "Bearer abcdefghijklmnop",
            "nested": { "api_key": "sk-abcdefghijklmnop", "safe": "hello" },
            "command": "OPENAI_API_KEY=secret-value run"
        });
        let redacted = redact(&value);
        assert_eq!(redacted["authorization"], REDACTED);
        assert_eq!(redacted["nested"]["api_key"], REDACTED);
        assert_eq!(redacted["nested"]["safe"], "hello");
        assert_eq!(
            redacted["command"],
            format!("OPENAI_API_KEY={REDACTED} run")
        );
    }

    #[test]
    fn redacts_keys_by_suffix_without_swallowing_structural_fields() {
        let value = json!({
            "client_secret": "oauth-secret",
            "id_token": "eyJhbGciOi.payload.signature",
            "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "X-Api-Key": "service-key",
            "secrets": { "DEPLOY_KEY": "value" },
            "max_tokens": 4096,
            "input_tokens": 128,
            "cacheKey": "thread-42",
            "text": "hello"
        });
        let redacted = redact(&value);
        assert_eq!(redacted["client_secret"], REDACTED);
        assert_eq!(redacted["id_token"], REDACTED);
        assert_eq!(redacted["sshPrivateKey"], REDACTED);
        assert_eq!(redacted["X-Api-Key"], REDACTED);
        assert_eq!(redacted["secrets"], REDACTED);
        assert_eq!(redacted["max_tokens"], 4096);
        assert_eq!(redacted["input_tokens"], 128);
        assert_eq!(redacted["cacheKey"], "thread-42");
        assert_eq!(redacted["text"], "hello");
    }

    #[test]
    fn classifies_headerless_json_rpc() {
        let request = json!({ "id": 1, "method": "initialize" });
        let notification = json!({ "method": "initialized" });
        let response = json!({ "id": 1, "result": {} });
        assert_eq!(classify_message(Some(&request)).0, "request");
        assert_eq!(classify_message(Some(&notification)).0, "notification");
        assert_eq!(classify_message(Some(&response)).0, "response");
    }

    #[test]
    fn rewrites_recorded_response_id() {
        let payload = json!({ "id": 4, "result": { "ok": true } });
        let mut map = HashMap::new();
        map.insert("4".into(), json!("client-id"));
        assert_eq!(rewrite_response_id(&payload, &map)["id"], "client-id");
        assert_eq!(payload["id"], 4);
    }

    #[test]
    fn records_private_trace_and_summary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let recorder = TraceRecorder::new(&path, &[OsString::from("codex")]).unwrap();
        recorder
            .record_line(
                "client_to_server",
                b"{\"id\":1,\"method\":\"initialize\"}\n",
            )
            .unwrap();
        recorder
            .record_line("server_to_client", b"{\"id\":1,\"result\":{}}\n")
            .unwrap();
        recorder.close(Some(0)).unwrap();
        let summary = summarize(&load_trace(&path).unwrap());
        assert_eq!(summary.events, 2);
        assert_eq!(summary.client_messages, 1);
        assert_eq!(summary.server_messages, 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
