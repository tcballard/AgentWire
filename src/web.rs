use crate::core::write_auth_token;
use crate::core::{
    load_inspector_snapshot, load_inspector_summary, load_trace, InspectorSnapshot, TraceRecorder,
    INSPECTOR_API_VERSION, MAX_INSPECTOR_EVENTS, MAX_INSPECTOR_EVENTS_BYTES,
};
use crate::secure_fs::random_hex;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentWire</title>
<style>:root{color-scheme:dark;--bg:#0b0d10;--panel:#12161b;--line:#252c35;--ink:#e8edf2;--muted:#8793a1;--in:#7dd3fc;--out:#a7f3d0;--accent:#fbbf24;--bad:#fb7185}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}header{position:sticky;top:0;z-index:2;display:flex;gap:18px;align-items:center;padding:14px 18px;background:rgba(11,13,16,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}h1{font-size:15px;margin:0;color:var(--accent)}.stats{color:var(--muted)}label{display:flex;gap:7px;align-items:center}select,input{background:var(--panel);border:1px solid var(--line);border-radius:6px;color:var(--ink);padding:6px 8px}main{padding:12px 18px 40px}.event{display:grid;grid-template-columns:80px 28px 110px minmax(180px,1fr);gap:10px;border-bottom:1px solid var(--line);padding:9px 4px;align-items:start}.event:hover{background:#101419}.time{color:var(--muted)}.arrow{font-weight:800}.in{color:var(--in)}.out{color:var(--out)}.method{color:var(--ink);overflow:hidden;text-overflow:ellipsis}.kind{color:var(--muted);font-size:12px}details{min-width:0}summary{cursor:pointer;list-style:none}pre{white-space:pre-wrap;word-break:break-word;color:#cbd5e1;background:var(--panel);border:1px solid var(--line);padding:10px;border-radius:6px;margin:8px 0 0}.error{color:var(--bad)}.empty{color:var(--muted);padding:50px 0;text-align:center}@media(max-width:760px){header{flex-wrap:wrap}.event{grid-template-columns:66px 24px 1fr}.event details{grid-column:1/-1}.kind{display:none}}</style></head>
<body><header><h1>AgentWire</h1><span class="stats" id="stats">connecting…</span><label>direction <select id="direction"><option value="all">all</option><option value="client_to_server">client → server</option><option value="server_to_client">server → client</option></select></label><label>filter <input id="query" placeholder="method or payload"></label></header><main id="events"><div class="empty">Waiting for trace events…</div></main>
<script>const root=document.querySelector('#events'),stats=document.querySelector('#stats'),direction=document.querySelector('#direction'),query=document.querySelector('#query'),token=new URLSearchParams(location.hash.slice(1)).get('token')||'';history.replaceState(null,'',location.pathname);let events=[];const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));function render(){const q=query.value.toLowerCase(),d=direction.value,visible=events.filter(e=>e.direction!=='meta'&&(d==='all'||e.direction===d)&&(!q||JSON.stringify(e).toLowerCase().includes(q)));stats.textContent=`${visible.length}/${events.filter(e=>e.direction!=='meta').length} recent protocol events`;root.innerHTML=visible.length?visible.map(e=>{const incoming=e.direction==='client_to_server',arrow=incoming?'→':'←',klass=incoming?'in':'out',method=e.method||e.kind,id=e.id===null||e.id===undefined?'':` #${e.id}`,bad=e.payload&&e.payload.error?' error':'';return `<div class="event${bad}"><span class="time">${Number(e.elapsed_ms).toFixed(1)}ms</span><span class="arrow ${klass}">${arrow}</span><span><span class="method">${esc(method)}${esc(id)}</span><br><span class="kind">${esc(e.kind)}</span></span><details><summary>payload</summary><pre>${esc(JSON.stringify(e.payload,null,2))}</pre></details></div>`}).join(''):'<div class="empty">No matching events.</div>'}async function refresh(){try{if(!token)throw new Error('missing token');const response=await fetch('/api/events',{cache:'no-store',headers:{Authorization:`Bearer ${token}`}});if(!response.ok)throw new Error('request denied');events=await response.json();render()}catch(error){stats.textContent='inspector authorization required'}setTimeout(refresh,1000)}direction.onchange=render;query.oninput=render;refresh();</script></body></html>"#;

pub fn parse_listen(value: &str) -> Result<SocketAddr> {
    value
        .parse()
        .with_context(|| "listen address must be an IP address in HOST:PORT form")
}

fn response(status: &str, content_type: &str, body: &[u8], no_store: bool) -> Vec<u8> {
    response_with_headers(status, content_type, body, no_store, "")
}

fn response_with_headers(
    status: &str,
    content_type: &str,
    body: &[u8],
    no_store: bool,
    extra_headers: &str,
) -> Vec<u8> {
    let cache = if no_store {
        "Cache-Control: no-store\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nContent-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'\r\n{cache}{extra_headers}Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}

impl FileIdentity {
    fn read(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("could not inspect trace {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        Ok(Self {
            created: metadata.created().ok(),
        })
    }
}

impl FileFingerprint {
    fn read(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("could not inspect trace {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                created: metadata.created().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
        })
    }
}

enum SummarySource {
    Live {
        recorder: Arc<TraceRecorder>,
        identity: FileIdentity,
    },
    Served {
        cache: Mutex<Option<(FileFingerprint, Vec<u8>)>>,
    },
    Hub {
        snapshot: PathBuf,
    },
}

struct ServerState {
    trace: Option<PathBuf>,
    summary: SummarySource,
    auth_token: String,
    served_events_cache: Mutex<Option<(FileFingerprint, Vec<u8>)>>,
}

impl ServerState {
    fn hub_snapshot(&self) -> Result<InspectorSnapshot> {
        match &self.summary {
            SummarySource::Hub { snapshot } => load_inspector_snapshot(snapshot),
            _ => bail!("server is not using a hub snapshot"),
        }
    }

    fn summary_json(&self) -> Result<Vec<u8>> {
        match &self.summary {
            SummarySource::Live { recorder, identity } => {
                let trace = self
                    .trace
                    .as_deref()
                    .context("live trace path is unavailable")?;
                if &FileIdentity::read(trace)? != identity {
                    bail!("live trace path identity changed");
                }
                Ok(serde_json::to_vec(&recorder.inspector_summary())?)
            }
            SummarySource::Served { cache } => {
                let trace = self
                    .trace
                    .as_deref()
                    .context("served trace path is unavailable")?;
                let fingerprint = FileFingerprint::read(trace)?;
                let mut cache = cache.lock().expect("summary cache mutex poisoned");
                if let Some((cached_fingerprint, body)) = cache.as_ref() {
                    if cached_fingerprint == &fingerprint {
                        return Ok(body.clone());
                    }
                }
                let body = serde_json::to_vec(&load_inspector_summary(trace)?)?;
                *cache = Some((fingerprint, body.clone()));
                Ok(body)
            }
            SummarySource::Hub { .. } => Ok(serde_json::to_vec(&self.hub_snapshot()?.summary)?),
        }
    }

    fn events_json(&self) -> Result<Vec<u8>> {
        match &self.summary {
            SummarySource::Live { recorder, .. } => {
                serde_json::to_vec(&recorder.inspector_events()).map_err(Into::into)
            }
            SummarySource::Hub { .. } => {
                serde_json::to_vec(&self.hub_snapshot()?.events).map_err(Into::into)
            }
            SummarySource::Served { .. } => {
                let trace = self
                    .trace
                    .as_deref()
                    .context("served trace path is unavailable")?;
                let fingerprint = FileFingerprint::read(trace)?;
                let mut cache = self
                    .served_events_cache
                    .lock()
                    .expect("events cache mutex poisoned");
                if let Some((cached_fingerprint, body)) = cache.as_ref() {
                    if cached_fingerprint == &fingerprint {
                        return Ok(body.clone());
                    }
                }
                let body = bounded_events_json(load_trace(trace)?)?;
                *cache = Some((fingerprint, body.clone()));
                Ok(body)
            }
        }
    }
}

fn bounded_events_json(events: Vec<serde_json::Value>) -> Result<Vec<u8>> {
    let mut kept = VecDeque::new();
    let mut bytes = 2_usize;
    for event in events.into_iter().rev() {
        let event_bytes = serde_json::to_vec(&event)?.len() + 1;
        if event_bytes > MAX_INSPECTOR_EVENTS_BYTES {
            continue;
        }
        if kept.len() >= MAX_INSPECTOR_EVENTS || bytes + event_bytes > MAX_INSPECTOR_EVENTS_BYTES {
            break;
        }
        bytes += event_bytes;
        kept.push_front(event);
    }
    Ok(serde_json::to_vec(&kept)?)
}

#[derive(Serialize)]
struct ApiError<'a> {
    api_version: u64,
    error: ApiErrorBody<'a>,
}

#[derive(Serialize)]
struct ApiErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

fn unavailable_response() -> Vec<u8> {
    let body = serde_json::to_vec(&ApiError {
        api_version: INSPECTOR_API_VERSION,
        error: ApiErrorBody {
            code: "trace_unavailable",
            message: "trace unavailable",
        },
    })
    .expect("static API error must serialize");
    response("500 Internal Server Error", "application/json", &body, true)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn api_authorized(request: &str, state: &ServerState, origin: &str) -> bool {
    let mut authorization = None;
    let mut request_origin = None;
    let mut fetch_site = None;
    for line in request.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value.trim()),
            "origin" => request_origin = Some(value.trim()),
            "sec-fetch-site" => fetch_site = Some(value.trim()),
            _ => {}
        }
    }
    if request_origin.is_some_and(|value| value != origin)
        || fetch_site.is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
    {
        return false;
    }
    let expected = format!("Bearer {}", state.auth_token);
    authorization.is_some_and(|value| constant_time_equal(value.as_bytes(), expected.as_bytes()))
}

fn handle(mut stream: TcpStream, state: &ServerState, origin: &str) -> Result<()> {
    // Sockets accepted from a non-blocking listener inherit the flag on
    // macOS and the BSDs (unlike Linux); reading would then fail with
    // WouldBlock before the request arrives and reset the connection.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while request.len() < 8192 {
        let length = stream.read(&mut chunk)?;
        if length == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..length]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request_text = String::from_utf8_lossy(&request);
    let first_line = request_text.lines().next().unwrap_or("");
    let method = first_line.split_whitespace().next().unwrap_or("");
    let path = first_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let output = if method != "GET" {
        response(
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed\n",
            true,
        )
    } else if path.starts_with("/api/") && !api_authorized(&request_text, state, origin) {
        response_with_headers(
            "401 Unauthorized",
            "application/json",
            b"{\"error\":\"authorization required\"}",
            true,
            "WWW-Authenticate: Bearer\r\n",
        )
    } else {
        match path {
            "/" => response("200 OK", "text/html; charset=utf-8", HTML.as_bytes(), false),
            "/api/events" => match state.events_json() {
                Ok(body) => response("200 OK", "application/json", &body, true),
                Err(_) => unavailable_response(),
            },
            "/api/summary" => match state.summary_json() {
                Ok(body) => response("200 OK", "application/json", &body, true),
                Err(_) => unavailable_response(),
            },
            _ => response(
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found\n",
                false,
            ),
        }
    };
    stream.write_all(&output)?;
    Ok(())
}

pub struct WebServer {
    address: SocketAddr,
    auth_token: String,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

fn inspector_url(address: SocketAddr) -> String {
    let ip = if address.ip().is_unspecified() {
        if address.is_ipv6() {
            "::1".parse().expect("loopback IPv6 must parse")
        } else {
            "127.0.0.1".parse().expect("loopback IPv4 must parse")
        }
    } else {
        address.ip()
    };
    let host = if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    format!("http://{host}:{}", address.port())
}

impl WebServer {
    pub fn start(trace: PathBuf, listen: &str) -> Result<Self> {
        let auth_token = random_hex(32)?;
        Self::start_with_state(
            ServerState {
                trace: Some(trace),
                summary: SummarySource::Served {
                    cache: Mutex::new(None),
                },
                auth_token,
                served_events_cache: Mutex::new(None),
            },
            listen,
        )
    }

    pub fn start_live(recorder: Arc<TraceRecorder>, listen: &str) -> Result<Self> {
        let auth_token = random_hex(32)?;
        let trace = recorder.path().to_path_buf();
        let identity = FileIdentity::read(&trace)?;
        Self::start_with_state(
            ServerState {
                trace: Some(trace),
                summary: SummarySource::Live { recorder, identity },
                auth_token,
                served_events_cache: Mutex::new(None),
            },
            listen,
        )
    }

    pub fn start_hub(snapshot: PathBuf, listen: &str) -> Result<Self> {
        let auth_token = random_hex(32)?;
        Self::start_with_state(
            ServerState {
                trace: None,
                summary: SummarySource::Hub { snapshot },
                auth_token,
                served_events_cache: Mutex::new(None),
            },
            listen,
        )
    }

    pub fn start_hub_with_auth_file(
        snapshot: PathBuf,
        listen: &str,
        auth_file: &Path,
    ) -> Result<Self> {
        let auth_token = write_auth_token(auth_file)?;
        Self::start_with_state(
            ServerState {
                trace: None,
                summary: SummarySource::Hub { snapshot },
                auth_token,
                served_events_cache: Mutex::new(None),
            },
            listen,
        )
    }

    fn start_with_state(state: ServerState, listen: &str) -> Result<Self> {
        let listener = TcpListener::bind(parse_listen(listen)?)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let origin = inspector_url(address);
        let state = Arc::new(state);
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for _ in 0..4 {
            let listener = listener.try_clone()?;
            let thread_stop = Arc::clone(&stop);
            let thread_state = Arc::clone(&state);
            let thread_origin = origin.clone();
            threads.push(thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = handle(stream, &thread_state, &thread_origin);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(_) => break,
                    }
                }
            }));
        }
        Ok(Self {
            address,
            auth_token: state.auth_token.clone(),
            stop,
            threads,
        })
    }

    pub fn url(&self) -> String {
        format!("{}/#token={}", inspector_url(self.address), self.auth_token)
    }

    pub fn origin(&self) -> String {
        inspector_url(self.address)
    }

    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }

    pub fn wait(mut self) {
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

pub fn serve_forever(trace: PathBuf, listen: &str) -> Result<()> {
    if !trace.exists() {
        bail!("trace does not exist: {}", trace.display());
    }
    let server = WebServer::start(trace, listen)?;
    eprintln!("AgentWire inspector: {}", server.url());
    server.wait();
    Ok(())
}

pub fn hub_forever(snapshot: PathBuf, listen: &str, auth_file: Option<&Path>) -> Result<()> {
    let server = match auth_file {
        Some(path) => WebServer::start_hub_with_auth_file(snapshot, listen, path)?,
        None => WebServer::start_hub(snapshot, listen)?,
    };
    eprintln!("AgentWire hub: {}", server.url());
    server.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TraceRecorder;
    use std::ffi::OsString;
    use std::io::{Read, Write};

    fn get(server: &WebServer, path: &str) -> String {
        request(
            server.address,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
                server.auth_token()
            ),
        )
    }

    fn request(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn serves_inspector_and_trace_with_security_headers() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        let recorder = TraceRecorder::new(&trace, &[OsString::from("mock")]).unwrap();
        recorder
            .record_line(
                "client_to_server",
                b"{\"id\":1,\"method\":\"initialize\"}\n",
            )
            .unwrap();
        recorder.close(Some(0)).unwrap();
        let server = WebServer::start(trace, "127.0.0.1:0").unwrap();
        let page = get(&server, "/");
        assert!(page.contains("AgentWire"));
        assert!(page.contains("X-Content-Type-Options: nosniff"));
        let events = get(&server, "/api/events");
        assert!(events.contains("initialize"));
        assert!(events.contains("Cache-Control: no-store"));
    }

    #[test]
    fn api_requires_capability_and_rejects_cross_origin_requests() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        let recorder = TraceRecorder::new(&trace, &[]).unwrap();
        recorder.close(Some(0)).unwrap();
        let server = WebServer::start(trace, "127.0.0.1:0").unwrap();

        let missing = request(
            server.address,
            "GET /api/events HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(missing.starts_with("HTTP/1.1 401 Unauthorized"));

        let cross_origin = request(
            server.address,
            &format!(
                "GET /api/events HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nOrigin: https://attacker.invalid\r\n\r\n",
                server.auth_token()
            ),
        );
        assert!(cross_origin.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn live_summary_uses_the_recorder_aggregate() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        let recorder = Arc::new(TraceRecorder::new(&trace, &[]).unwrap());
        let server = WebServer::start_live(Arc::clone(&recorder), "127.0.0.1:0").unwrap();
        recorder
            .record_line("client_to_server", b"{\"method\":\"initialize\"}\n")
            .unwrap();
        let summary = get(&server, "/api/summary");
        assert!(summary.starts_with("HTTP/1.1 200 OK"));
        assert!(summary.contains("\"mode\":\"live_record\""));
        assert!(summary.contains("\"active\":true"));
        assert!(summary.contains("\"events\":1"));
    }

    #[test]
    fn served_summary_is_cached_and_refreshes_after_growth() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        let recorder = TraceRecorder::new(&trace, &[]).unwrap();
        recorder.close(Some(0)).unwrap();
        let server = WebServer::start(trace.clone(), "127.0.0.1:0").unwrap();
        let first = get(&server, "/api/summary");
        assert!(first.contains("\"events\":0"));
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&trace)
            .unwrap();
        writeln!(file, "{{\"trace_version\":1,\"direction\":\"server_to_client\",\"kind\":\"notification\",\"method\":\"late\",\"elapsed_ms\":9,\"payload\":{{}}}}")
            .unwrap();
        let second = get(&server, "/api/summary");
        assert!(second.contains("\"events\":1"));
        assert!(second.contains("\"last_method\":\"late\""));
    }

    #[test]
    fn hub_follows_atomically_published_recordings() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("runtime/inspector.json");
        let server = WebServer::start_hub(snapshot.clone(), "127.0.0.1:0").unwrap();
        assert!(get(&server, "/api/summary").starts_with("HTTP/1.1 500 Internal Server Error"));

        let first_trace = directory.path().join("first.jsonl");
        let first = TraceRecorder::new_published(&first_trace, &[], &snapshot).unwrap();
        first
            .record_line("client_to_server", b"{\"method\":\"initialize\"}\n")
            .unwrap();
        let first_summary = get(&server, "/api/summary");
        assert!(first_summary.contains("\"active\":true"));
        assert!(first_summary.contains("\"last_method\":\"initialize\""));
        assert!(get(&server, "/api/events").contains("initialize"));

        let second_trace = directory.path().join("second.jsonl");
        let second = TraceRecorder::new_published(&second_trace, &[], &snapshot).unwrap();
        second
            .record_line("server_to_client", b"{\"method\":\"turn/completed\"}\n")
            .unwrap();
        second.close(Some(0)).unwrap();
        let second_summary = get(&server, "/api/summary");
        assert!(second_summary.contains("\"ended\":true"));
        assert!(second_summary.contains("\"last_method\":\"turn/completed\""));
        let events = get(&server, "/api/events");
        assert!(events.contains("turn/completed"));
        assert!(!events.contains("initialize"));
    }

    #[test]
    fn invalid_trace_has_a_stable_summary_error() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        std::fs::write(&trace, b"not json\n").unwrap();
        let server = WebServer::start(trace, "127.0.0.1:0").unwrap();
        let summary = get(&server, "/api/summary");
        assert!(summary.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(summary.ends_with("{\"api_version\":1,\"error\":{\"code\":\"trace_unavailable\",\"message\":\"trace unavailable\"}}"));
    }

    #[cfg(unix)]
    #[test]
    fn live_summary_rejects_a_replaced_trace_path() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("trace.jsonl");
        let recorder = Arc::new(TraceRecorder::new(&trace, &[]).unwrap());
        let server = WebServer::start_live(recorder, "127.0.0.1:0").unwrap();
        std::fs::rename(&trace, directory.path().join("original.jsonl")).unwrap();
        std::fs::write(&trace, b"").unwrap();
        assert!(get(&server, "/api/summary").starts_with("HTTP/1.1 500 Internal Server Error"));
    }

    #[test]
    fn formats_ipv6_inspector_urls_with_brackets() {
        assert_eq!(
            inspector_url("[::1]:4777".parse().unwrap()),
            "http://[::1]:4777"
        );
        assert_eq!(
            inspector_url("[::]:4777".parse().unwrap()),
            "http://[::1]:4777"
        );
    }
}
