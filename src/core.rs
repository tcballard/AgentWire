use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
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
pub const INSPECTOR_API_VERSION: u64 = 1;
pub const INSPECTOR_SESSION_ID_LIMIT: usize = 128;
pub const INSPECTOR_STARTED_AT_LIMIT: usize = 64;
pub const INSPECTOR_LAST_METHOD_LIMIT: usize = 256;
pub const REDACTED: &str = "[REDACTED]";

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectorMode {
    LiveRecord,
    ServedTrace,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InspectorSummary {
    pub api_version: u64,
    pub trace_version: u64,
    pub mode: InspectorMode,
    pub active: bool,
    pub session_id: String,
    pub started_at: String,
    pub ended: bool,
    pub exit_code: Option<i32>,
    pub events: usize,
    pub duration_ms: f64,
    pub client_messages: usize,
    pub server_messages: usize,
    pub invalid_messages: usize,
    pub errors: usize,
    pub last_method: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InspectorSnapshot {
    pub trace: PathBuf,
    pub summary: InspectorSummary,
}

impl InspectorSnapshot {
    pub fn validate(&self) -> Result<()> {
        let summary = &self.summary;
        if summary.api_version != INSPECTOR_API_VERSION || summary.trace_version != TRACE_VERSION {
            bail!("unsupported inspector snapshot version");
        }
        if summary.session_id.chars().count() > INSPECTOR_SESSION_ID_LIMIT
            || summary.started_at.chars().count() > INSPECTOR_STARTED_AT_LIMIT
            || summary
                .last_method
                .as_deref()
                .is_some_and(|value| value.chars().count() > INSPECTOR_LAST_METHOD_LIMIT)
        {
            bail!("inspector snapshot contains an oversized string");
        }
        if !summary.duration_ms.is_finite() || summary.duration_ms < 0.0 {
            bail!("inspector snapshot contains an invalid duration");
        }
        if summary.active != (summary.mode == InspectorMode::LiveRecord && !summary.ended) {
            bail!("inspector snapshot lifecycle is inconsistent");
        }
        if self.trace.as_os_str().is_empty() || !self.trace.is_absolute() {
            bail!("inspector snapshot trace path must be absolute");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct InspectorAggregate {
    session_id: String,
    started_at: String,
    ended: bool,
    exit_code: Option<i32>,
    events: usize,
    duration_ms: f64,
    client_messages: usize,
    server_messages: usize,
    invalid_messages: usize,
    errors: usize,
    last_method: Option<String>,
}

impl InspectorAggregate {
    fn observe(&mut self, event: &Value) {
        if self.session_id.is_empty() {
            if let Some(value) = event.get("session_id").and_then(Value::as_str) {
                self.session_id = bounded(value, INSPECTOR_SESSION_ID_LIMIT);
            }
        }
        if let Some(elapsed) = event.get("elapsed_ms").and_then(Value::as_f64) {
            if elapsed.is_finite() {
                self.duration_ms = self.duration_ms.max(elapsed.max(0.0));
            }
        }
        let direction = event.get("direction").and_then(Value::as_str);
        if direction == Some("meta") {
            match event.get("kind").and_then(Value::as_str) {
                Some("session_start") if self.started_at.is_empty() => {
                    if let Some(value) = event.get("timestamp").and_then(Value::as_str) {
                        self.started_at = bounded(value, INSPECTOR_STARTED_AT_LIMIT);
                    }
                }
                Some("session_end") => {
                    self.ended = true;
                    self.exit_code = event
                        .pointer("/payload/exit_code")
                        .and_then(Value::as_i64)
                        .and_then(|value| i32::try_from(value).ok());
                }
                _ => {}
            }
            return;
        }
        self.events += 1;
        match direction {
            Some("client_to_server") => self.client_messages += 1,
            Some("server_to_client") => self.server_messages += 1,
            _ => {}
        }
        if event.get("kind").and_then(Value::as_str) == Some("invalid") {
            self.invalid_messages += 1;
        }
        if event.pointer("/payload/error").is_some() {
            self.errors += 1;
        }
        if let Some(method) = event.get("method").and_then(Value::as_str) {
            self.last_method = Some(bounded(method, INSPECTOR_LAST_METHOD_LIMIT));
        }
    }

    fn summary(&self, mode: InspectorMode) -> InspectorSummary {
        InspectorSummary {
            api_version: INSPECTOR_API_VERSION,
            trace_version: TRACE_VERSION,
            mode,
            active: mode == InspectorMode::LiveRecord && !self.ended,
            session_id: self.session_id.clone(),
            started_at: self.started_at.clone(),
            ended: self.ended,
            exit_code: self.exit_code,
            events: self.events,
            duration_ms: self.duration_ms,
            client_messages: self.client_messages,
            server_messages: self.server_messages,
            invalid_messages: self.invalid_messages,
            errors: self.errors,
            last_method: self.last_method.clone(),
        }
    }
}

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
    inspector: InspectorAggregate,
}

pub struct TraceRecorder {
    path: PathBuf,
    session_id: String,
    started: Instant,
    snapshot_path: Option<PathBuf>,
    state: Mutex<RecorderState>,
}

impl TraceRecorder {
    pub fn new(path: impl Into<PathBuf>, command: &[OsString]) -> Result<Self> {
        Self::new_inner(path.into(), command, None)
    }

    pub fn new_published(
        path: impl Into<PathBuf>,
        command: &[OsString],
        snapshot_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::new_inner(path.into(), command, Some(snapshot_path.into()))
    }

    fn new_inner(
        path: PathBuf,
        command: &[OsString],
        snapshot_path: Option<PathBuf>,
    ) -> Result<Self> {
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
            snapshot_path,
            state: Mutex::new(RecorderState {
                writer: Some(BufWriter::new(file)),
                sequence: 0,
                inspector: InspectorAggregate::default(),
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
        let event = Value::Object(event);
        serde_json::to_writer(&mut *writer, &event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        state.inspector.observe(&event);
        let summary = state.inspector.summary(InspectorMode::LiveRecord);
        drop(state);
        self.publish_snapshot(&summary)?;
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
        let mut state = self.state.lock().expect("trace recorder mutex poisoned");
        if state.writer.is_none() {
            return Ok(());
        }
        let mut event = json!({
            "trace_version": TRACE_VERSION,
            "session_id": self.session_id,
            "timestamp": utc_now(),
            "elapsed_ms": self.started.elapsed().as_secs_f64() * 1000.0,
            "direction": "meta",
            "kind": "session_end",
            "method": null,
            "id": null,
            "payload": { "exit_code": exit_code },
        })
        .as_object()
        .unwrap()
        .clone();
        event.insert("seq".into(), Value::from(state.sequence));
        state.sequence += 1;
        let value = Value::Object(event);
        let writer = state.writer.as_mut().expect("writer checked above");
        serde_json::to_writer(&mut *writer, &value)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        state.inspector.observe(&value);
        let summary = state.inspector.summary(InspectorMode::LiveRecord);
        if let Some(mut writer) = state.writer.take() {
            writer.flush()?;
        }
        drop(state);
        self.publish_snapshot(&summary)?;
        Ok(())
    }

    pub fn inspector_summary(&self) -> InspectorSummary {
        self.state
            .lock()
            .expect("trace recorder mutex poisoned")
            .inspector
            .summary(InspectorMode::LiveRecord)
    }

    fn publish_snapshot(&self, summary: &InspectorSummary) -> Result<()> {
        let Some(path) = self.snapshot_path.as_deref() else {
            return Ok(());
        };
        let trace = self
            .path
            .canonicalize()
            .with_context(|| format!("could not resolve trace {}", self.path.display()))?;
        write_inspector_snapshot(
            path,
            &InspectorSnapshot {
                trace,
                summary: summary.clone(),
            },
        )
    }
}

pub fn write_inspector_snapshot(path: &Path, snapshot: &InspectorSnapshot) -> Result<()> {
    snapshot.validate()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("inspector snapshot path needs a parent directory")?;
    if !parent.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(parent)
            .with_context(|| format!("could not create snapshot directory {}", parent.display()))?;
    }
    if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
        bail!("inspector snapshot directory must not be a symlink");
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{nonce}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("inspector"),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("could not create snapshot {}", temporary.display()))?;
        serde_json::to_writer(&mut file, snapshot)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("could not publish snapshot {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn load_inspector_snapshot(path: &Path) -> Result<InspectorSnapshot> {
    const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect snapshot {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
        bail!("inspector snapshot is not a bounded regular file");
    }
    let snapshot: InspectorSnapshot = serde_json::from_reader(BufReader::new(
        File::open(path).with_context(|| format!("could not open snapshot {}", path.display()))?,
    ))?;
    snapshot.validate()?;
    Ok(snapshot)
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

pub fn inspector_summary(events: &[Value], mode: InspectorMode) -> InspectorSummary {
    let mut aggregate = InspectorAggregate::default();
    for event in events {
        aggregate.observe(event);
    }
    aggregate.summary(mode)
}

pub fn load_inspector_summary(path: &Path) -> Result<InspectorSummary> {
    Ok(inspector_summary(
        &load_trace(path)?,
        InspectorMode::ServedTrace,
    ))
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

    #[test]
    fn inspector_summary_matches_the_canonical_v1_example() {
        let expected: Value = serde_json::from_str(include_str!(
            "../contracts/inspector-summary-v1.example.json"
        ))
        .unwrap();
        let summary = InspectorSummary {
            api_version: 1,
            trace_version: 1,
            mode: InspectorMode::LiveRecord,
            active: true,
            session_id: "1a2b-18d0b32a2bbe6d98".into(),
            started_at: "2026-08-30T21:40:45.786Z".into(),
            ended: false,
            exit_code: None,
            events: 11,
            duration_ms: 12.4,
            client_messages: 4,
            server_messages: 7,
            invalid_messages: 0,
            errors: 0,
            last_method: Some("turn/completed".into()),
        };
        assert_eq!(serde_json::to_value(summary).unwrap(), expected);
    }

    #[test]
    fn live_summary_tracks_lifecycle_and_protocol_counts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let recorder = TraceRecorder::new(&path, &[OsString::from("mock")]).unwrap();
        recorder
            .record_line("client_to_server", b"not json\n")
            .unwrap();
        recorder
            .record_line(
                "server_to_client",
                b"{\"method\":\"turn/completed\",\"error\":null}\n",
            )
            .unwrap();
        let live = recorder.inspector_summary();
        assert!(live.active);
        assert!(!live.ended);
        assert_eq!(live.events, 2);
        assert_eq!(live.invalid_messages, 1);
        assert_eq!(live.errors, 1);
        assert_eq!(live.last_method.as_deref(), Some("turn/completed"));
        recorder.close(Some(-9)).unwrap();
        let closed = recorder.inspector_summary();
        assert!(!closed.active);
        assert!(closed.ended);
        assert_eq!(closed.exit_code, Some(-9));
    }

    #[test]
    fn close_is_idempotent_and_preserves_the_first_status() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let recorder = TraceRecorder::new(&path, &[]).unwrap();
        recorder.close(Some(7)).unwrap();
        recorder.close(Some(2)).unwrap();
        recorder
            .record_line("client_to_server", b"{\"method\":\"ignored\"}\n")
            .unwrap();
        let events = load_trace(&path).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.get("kind") == Some(&json!("session_end")))
                .count(),
            1
        );
        assert_eq!(recorder.inspector_summary().exit_code, Some(7));
        assert_eq!(recorder.inspector_summary().events, 0);
    }

    #[test]
    fn published_snapshot_tracks_live_and_completed_recording() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        let snapshot = directory.path().join("runtime/inspector.json");
        let recorder = TraceRecorder::new_published(&trace, &[], &snapshot).unwrap();
        let initial = load_inspector_snapshot(&snapshot).unwrap();
        assert_eq!(initial.trace, trace.canonicalize().unwrap());
        assert!(initial.summary.active);
        assert_eq!(initial.summary.events, 0);

        recorder
            .record_line("client_to_server", b"{\"method\":\"initialize\"}\n")
            .unwrap();
        let live = load_inspector_snapshot(&snapshot).unwrap();
        assert_eq!(live.summary.events, 1);
        assert_eq!(live.summary.last_method.as_deref(), Some("initialize"));

        recorder.close(Some(-9)).unwrap();
        let completed = load_inspector_snapshot(&snapshot).unwrap();
        assert!(!completed.summary.active);
        assert!(completed.summary.ended);
        assert_eq!(completed.summary.exit_code, Some(-9));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn snapshot_loader_rejects_unbounded_or_inconsistent_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        std::fs::write(&path, vec![b'x'; 64 * 1024 + 1]).unwrap();
        assert!(load_inspector_snapshot(&path).is_err());

        let trace = directory.path().join("trace.jsonl");
        std::fs::write(&trace, b"").unwrap();
        let bad = InspectorSnapshot {
            trace: trace.canonicalize().unwrap(),
            summary: InspectorSummary {
                api_version: 1,
                trace_version: 1,
                mode: InspectorMode::LiveRecord,
                active: false,
                session_id: "session".into(),
                started_at: "now".into(),
                ended: false,
                exit_code: None,
                events: 0,
                duration_ms: 0.0,
                client_messages: 0,
                server_messages: 0,
                invalid_messages: 0,
                errors: 0,
                last_method: None,
            },
        };
        assert!(write_inspector_snapshot(&path, &bad).is_err());
    }

    #[test]
    fn served_summary_is_inactive_and_bounds_external_strings() {
        let long = "🦀".repeat(300);
        let events = vec![
            json!({
                "trace_version": 1,
                "session_id": long,
                "timestamp": "x".repeat(100),
                "elapsed_ms": 1.25,
                "direction": "meta",
                "kind": "session_start",
                "payload": {}
            }),
            json!({
                "trace_version": 1,
                "session_id": "ignored",
                "elapsed_ms": 2.5,
                "direction": "server_to_client",
                "kind": "notification",
                "method": "m".repeat(400),
                "payload": {}
            }),
        ];
        let summary = inspector_summary(&events, InspectorMode::ServedTrace);
        assert!(!summary.active);
        assert_eq!(summary.session_id.chars().count(), 128);
        assert_eq!(summary.started_at.chars().count(), 64);
        assert_eq!(summary.last_method.unwrap().chars().count(), 256);
    }

    #[test]
    fn out_of_range_external_exit_code_is_null() {
        let summary = inspector_summary(
            &[json!({
                "trace_version": 1,
                "direction": "meta",
                "kind": "session_end",
                "payload": { "exit_code": 2147483648_i64 }
            })],
            InspectorMode::ServedTrace,
        );
        assert!(summary.ended);
        assert_eq!(summary.exit_code, None);
    }
}
