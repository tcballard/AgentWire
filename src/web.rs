use crate::core::load_trace;
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentWire</title>
<style>:root{color-scheme:dark;--bg:#0b0d10;--panel:#12161b;--line:#252c35;--ink:#e8edf2;--muted:#8793a1;--in:#7dd3fc;--out:#a7f3d0;--accent:#fbbf24;--bad:#fb7185}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}header{position:sticky;top:0;z-index:2;display:flex;gap:18px;align-items:center;padding:14px 18px;background:rgba(11,13,16,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}h1{font-size:15px;margin:0;color:var(--accent)}.stats{color:var(--muted)}label{display:flex;gap:7px;align-items:center}select,input{background:var(--panel);border:1px solid var(--line);border-radius:6px;color:var(--ink);padding:6px 8px}main{padding:12px 18px 40px}.event{display:grid;grid-template-columns:80px 28px 110px minmax(180px,1fr);gap:10px;border-bottom:1px solid var(--line);padding:9px 4px;align-items:start}.event:hover{background:#101419}.time{color:var(--muted)}.arrow{font-weight:800}.in{color:var(--in)}.out{color:var(--out)}.method{color:var(--ink);overflow:hidden;text-overflow:ellipsis}.kind{color:var(--muted);font-size:12px}details{min-width:0}summary{cursor:pointer;list-style:none}pre{white-space:pre-wrap;word-break:break-word;color:#cbd5e1;background:var(--panel);border:1px solid var(--line);padding:10px;border-radius:6px;margin:8px 0 0}.error{color:var(--bad)}.empty{color:var(--muted);padding:50px 0;text-align:center}@media(max-width:760px){header{flex-wrap:wrap}.event{grid-template-columns:66px 24px 1fr}.event details{grid-column:1/-1}.kind{display:none}}</style></head>
<body><header><h1>AgentWire</h1><span class="stats" id="stats">connecting…</span><label>direction <select id="direction"><option value="all">all</option><option value="client_to_server">client → server</option><option value="server_to_client">server → client</option></select></label><label>filter <input id="query" placeholder="method or payload"></label></header><main id="events"><div class="empty">Waiting for trace events…</div></main>
<script>const root=document.querySelector('#events'),stats=document.querySelector('#stats'),direction=document.querySelector('#direction'),query=document.querySelector('#query');let events=[];const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));function render(){const q=query.value.toLowerCase(),d=direction.value,visible=events.filter(e=>e.direction!=='meta'&&(d==='all'||e.direction===d)&&(!q||JSON.stringify(e).toLowerCase().includes(q)));stats.textContent=`${visible.length}/${events.filter(e=>e.direction!=='meta').length} protocol events`;root.innerHTML=visible.length?visible.map(e=>{const incoming=e.direction==='client_to_server',arrow=incoming?'→':'←',klass=incoming?'in':'out',method=e.method||e.kind,id=e.id===null||e.id===undefined?'':` #${e.id}`,bad=e.payload&&e.payload.error?' error':'';return `<div class="event${bad}"><span class="time">${Number(e.elapsed_ms).toFixed(1)}ms</span><span class="arrow ${klass}">${arrow}</span><span><span class="method">${esc(method)}${esc(id)}</span><br><span class="kind">${esc(e.kind)}</span></span><details><summary>payload</summary><pre>${esc(JSON.stringify(e.payload,null,2))}</pre></details></div>`}).join(''):'<div class="empty">No matching events.</div>'}async function refresh(){try{const response=await fetch('/api/events',{cache:'no-store'});events=await response.json();render()}catch(error){stats.textContent='trace unavailable'}setTimeout(refresh,500)}direction.onchange=render;query.oninput=render;refresh();</script></body></html>"#;

pub fn parse_listen(value: &str) -> Result<SocketAddr> {
    value
        .parse()
        .with_context(|| "listen address must be an IP address in HOST:PORT form")
}

fn response(status: &str, content_type: &str, body: &[u8], no_store: bool) -> Vec<u8> {
    let cache = if no_store {
        "Cache-Control: no-store\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'\r\n{cache}Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn handle(mut stream: TcpStream, trace: &Path) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
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
    let first_line = String::from_utf8_lossy(&request);
    let path = first_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let output = match path {
        "/" => response("200 OK", "text/html; charset=utf-8", HTML.as_bytes(), false),
        "/api/events" => {
            let events = load_trace(trace).unwrap_or_default();
            let body = serde_json::to_vec(&events)?;
            response("200 OK", "application/json", &body, true)
        }
        _ => response(
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
            false,
        ),
    };
    stream.write_all(&output)?;
    Ok(())
}

pub struct WebServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WebServer {
    pub fn start(trace: PathBuf, listen: &str) -> Result<Self> {
        let listener = TcpListener::bind(parse_listen(listen)?)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle(stream, &trace);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    pub fn url(&self) -> String {
        let host = if self.address.ip().is_unspecified() {
            "127.0.0.1".to_owned()
        } else {
            self.address.ip().to_string()
        };
        format!("http://{host}:{}", self.address.port())
    }

    pub fn wait(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TraceRecorder;
    use std::ffi::OsString;
    use std::io::{Read, Write};

    fn get(address: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
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
        let page = get(server.address, "/");
        assert!(page.contains("AgentWire"));
        assert!(page.contains("X-Content-Type-Options: nosniff"));
        let events = get(server.address, "/api/events");
        assert!(events.contains("initialize"));
        assert!(events.contains("Cache-Control: no-store"));
    }
}
