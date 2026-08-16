from __future__ import annotations

import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .core import load_trace

_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentWire</title>
<style>
:root{color-scheme:dark;--bg:#0b0d10;--panel:#12161b;--line:#252c35;--ink:#e8edf2;--muted:#8793a1;--in:#7dd3fc;--out:#a7f3d0;--accent:#fbbf24;--bad:#fb7185}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{position:sticky;top:0;z-index:2;display:flex;gap:18px;align-items:center;padding:14px 18px;background:rgba(11,13,16,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}
h1{font-size:15px;margin:0;color:var(--accent)}.stats{color:var(--muted)}label{display:flex;gap:7px;align-items:center}select,input{background:var(--panel);border:1px solid var(--line);border-radius:6px;color:var(--ink);padding:6px 8px}
main{padding:12px 18px 40px}.event{display:grid;grid-template-columns:80px 28px 110px minmax(180px,1fr);gap:10px;border-bottom:1px solid var(--line);padding:9px 4px;align-items:start}.event:hover{background:#101419}.time{color:var(--muted)}.arrow{font-weight:800}.in{color:var(--in)}.out{color:var(--out)}.method{color:var(--ink);overflow:hidden;text-overflow:ellipsis}.kind{color:var(--muted);font-size:12px}details{min-width:0}summary{cursor:pointer;list-style:none}pre{white-space:pre-wrap;word-break:break-word;color:#cbd5e1;background:var(--panel);border:1px solid var(--line);padding:10px;border-radius:6px;margin:8px 0 0}.error{color:var(--bad)}.empty{color:var(--muted);padding:50px 0;text-align:center}@media(max-width:760px){header{flex-wrap:wrap}.event{grid-template-columns:66px 24px 1fr}.event details{grid-column:1/-1}.kind{display:none}}
</style>
</head>
<body>
<header><h1>AgentWire</h1><span class="stats" id="stats">connecting…</span><label>direction <select id="direction"><option value="all">all</option><option value="client_to_server">client → server</option><option value="server_to_client">server → client</option></select></label><label>filter <input id="query" placeholder="method or payload"></label></header>
<main id="events"><div class="empty">Waiting for trace events…</div></main>
<script>
const root=document.querySelector('#events'),stats=document.querySelector('#stats'),direction=document.querySelector('#direction'),query=document.querySelector('#query');let events=[];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
function render(){const q=query.value.toLowerCase(),d=direction.value,visible=events.filter(e=>e.direction!=='meta'&&(d==='all'||e.direction===d)&&(!q||JSON.stringify(e).toLowerCase().includes(q)));stats.textContent=`${visible.length}/${events.filter(e=>e.direction!=='meta').length} protocol events`;root.innerHTML=visible.length?visible.map(e=>{const incoming=e.direction==='client_to_server',arrow=incoming?'→':'←',klass=incoming?'in':'out',method=e.method||e.kind,id=e.id===null||e.id===undefined?'':` #${e.id}`,bad=e.payload&&e.payload.error?' error':'';return `<div class="event${bad}"><span class="time">${Number(e.elapsed_ms).toFixed(1)}ms</span><span class="arrow ${klass}">${arrow}</span><span><span class="method">${esc(method)}${esc(id)}</span><br><span class="kind">${esc(e.kind)}</span></span><details><summary>payload</summary><pre>${esc(JSON.stringify(e.payload,null,2))}</pre></details></div>`}).join(''):'<div class="empty">No matching events.</div>'}
async function refresh(){try{const response=await fetch('/api/events',{cache:'no-store'});events=await response.json();render()}catch(error){stats.textContent='trace unavailable'}setTimeout(refresh,500)}direction.onchange=render;query.oninput=render;refresh();
</script>
</body></html>"""


def parse_listen(value: str) -> tuple[str, int]:
    if ":" not in value:
        raise ValueError("listen address must be HOST:PORT")
    host, port_text = value.rsplit(":", 1)
    port = int(port_text)
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return host, port


def make_handler(trace_path: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/":
                self._send(HTTPStatus.OK, "text/html; charset=utf-8", _HTML.encode())
                return
            if path == "/api/events":
                try:
                    events = load_trace(trace_path)
                    body = json.dumps(events, separators=(",", ":")).encode()
                except (OSError, ValueError):
                    body = b"[]"
                self._send(HTTPStatus.OK, "application/json", body, no_store=True)
                return
            self._send(HTTPStatus.NOT_FOUND, "text/plain", b"not found\n")

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status: HTTPStatus, content_type: str, body: bytes, no_store: bool = False) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            if no_store:
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def create_server(trace_path: Path, listen: str) -> ThreadingHTTPServer:
    host, port = parse_listen(listen)
    return ThreadingHTTPServer((host, port), make_handler(trace_path))


def server_url(server: ThreadingHTTPServer) -> str:
    host, port = server.server_address[:2]
    display_host = "127.0.0.1" if host in {"", "0.0.0.0"} else host
    return f"http://{display_host}:{port}"


def serve_in_thread(trace_path: Path, listen: str) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = create_server(trace_path, listen)
    thread = threading.Thread(target=server.serve_forever, name="agentwire-ui", daemon=True)
    thread.start()
    return server, thread
