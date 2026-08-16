from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .core import (
    TraceRecorder,
    load_trace,
    method_of,
    parse_message,
    request_id_of,
    rewrite_response_id,
    summarize,
)
from .web import create_server, serve_in_thread, server_url


def default_trace_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(f"agentwire-{stamp}.jsonl")


def _pump_client_to_server(source: Any, destination: Any, recorder: TraceRecorder) -> None:
    try:
        while True:
            line = source.readline()
            if not line:
                break
            recorder.record_line("client_to_server", line)
            destination.write(line)
            destination.flush()
    except BrokenPipeError:
        pass
    finally:
        try:
            destination.close()
        except (BrokenPipeError, OSError):
            pass


def record_command(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("agentwire: record requires a child command after --", file=sys.stderr)
        return 2

    trace_path = args.trace or default_trace_path()
    server = None
    with TraceRecorder(trace_path, command) as recorder:
        if args.ui:
            server, _ = serve_in_thread(trace_path, args.ui)
            print(f"AgentWire inspector: {server_url(server)}", file=sys.stderr)
        print(f"AgentWire trace: {trace_path.resolve()}", file=sys.stderr)

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                bufsize=0,
            )
        except OSError as error:
            recorder.record_meta("spawn_error", {"error": str(error)})
            print(f"agentwire: failed to start {command[0]!r}: {error}", file=sys.stderr)
            if server:
                server.shutdown()
            return 127

        assert process.stdin is not None
        assert process.stdout is not None
        input_thread = threading.Thread(
            target=_pump_client_to_server,
            args=(sys.stdin.buffer, process.stdin, recorder),
            name="agentwire-client-input",
            daemon=True,
        )
        input_thread.start()
        try:
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                recorder.record_line("server_to_client", line)
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
        except BrokenPipeError:
            process.terminate()
        exit_code = process.wait()
        input_thread.join(timeout=1)
        recorder.close(exit_code)
        if server:
            server.shutdown()
        return exit_code


def inspect_command(args: argparse.Namespace) -> int:
    try:
        events = load_trace(args.trace)
    except (OSError, ValueError) as error:
        print(f"agentwire: {error}", file=sys.stderr)
        return 2
    summary = summarize(events)
    if args.json:
        print(json.dumps(summary.as_dict(), indent=2))
        return 0
    print(f"trace       {args.trace}")
    print(f"events      {summary.events}")
    print(f"duration    {summary.duration_ms:.1f} ms")
    print(f"client →    {summary.client_messages}")
    print(f"server →    {summary.server_messages}")
    print(f"errors      {summary.errors}")
    print(f"invalid     {summary.invalid_messages}")
    if summary.methods:
        print("methods")
        for method, count in summary.methods.items():
            print(f"  {count:>4}  {method}")
    return 0


def _protocol_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if event.get("direction") in {"client_to_server", "server_to_client"}]


def replay_command(args: argparse.Namespace) -> int:
    try:
        events = _protocol_events(load_trace(args.trace))
    except (OSError, ValueError) as error:
        print(f"agentwire: {error}", file=sys.stderr)
        return 2
    index = 0
    id_map: dict[str, Any] = {}
    previous_elapsed = 0.0

    def emit_until_client_event() -> None:
        nonlocal index, previous_elapsed
        while index < len(events) and events[index].get("direction") == "server_to_client":
            event = events[index]
            elapsed = float(event.get("elapsed_ms", previous_elapsed))
            if args.speed > 0:
                time.sleep(max(0.0, elapsed - previous_elapsed) / 1000 / args.speed)
            previous_elapsed = elapsed
            payload = rewrite_response_id(event.get("payload"), id_map)
            sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
            index += 1

    emit_until_client_event()
    for line_number, line in enumerate(sys.stdin, start=1):
        incoming, _ = parse_message(line)
        if incoming is None:
            print(f"agentwire replay: client line {line_number} is not a JSON object", file=sys.stderr)
            return 2
        while index < len(events) and events[index].get("direction") != "client_to_server":
            emit_until_client_event()
        if index >= len(events):
            print("agentwire replay: client sent more messages than the trace contains", file=sys.stderr)
            return 3
        recorded = events[index].get("payload")
        incoming_method = method_of(incoming)
        recorded_method = method_of(recorded)
        if incoming_method != recorded_method:
            print(
                f"agentwire replay: expected client method {recorded_method!r}, got {incoming_method!r}",
                file=sys.stderr,
            )
            return 3
        recorded_id = request_id_of(recorded)
        incoming_id = request_id_of(incoming)
        if recorded_id is not None and incoming_id is not None:
            id_map[json.dumps(recorded_id, sort_keys=True)] = incoming_id
        if args.strict_payload and incoming != recorded:
            print(f"agentwire replay: payload mismatch for {incoming_method!r}", file=sys.stderr)
            return 3
        previous_elapsed = float(events[index].get("elapsed_ms", previous_elapsed))
        index += 1
        emit_until_client_event()

    remaining_client = sum(1 for event in events[index:] if event.get("direction") == "client_to_server")
    if remaining_client:
        print(f"agentwire replay: client ended with {remaining_client} recorded messages remaining", file=sys.stderr)
        return 3
    emit_until_client_event()
    return 0


def serve_command(args: argparse.Namespace) -> int:
    if not args.trace.exists():
        print(f"agentwire: trace does not exist: {args.trace}", file=sys.stderr)
        return 2
    try:
        server = create_server(args.trace, args.listen)
    except (OSError, ValueError) as error:
        print(f"agentwire: could not start inspector: {error}", file=sys.stderr)
        return 2
    print(f"AgentWire inspector: {server_url(server)}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def doctor_command(_: argparse.Namespace) -> int:
    codex = shutil.which("codex")
    print(f"python       {sys.version.split()[0]}")
    if codex is None:
        print("codex        not found")
        print("status       record/replay fixtures work; live Codex capture is unavailable")
        return 1
    result = subprocess.run([codex, "--version"], capture_output=True, text=True, timeout=10)
    version = (result.stdout or result.stderr).strip() or "version unavailable"
    print(f"codex        {codex}")
    print(f"version      {version}")
    print("transport    JSONL over stdio")
    print("status       ready")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentwire", description="Record and replay Codex App Server JSONL traffic.")
    parser.add_argument("--version", action="version", version=f"AgentWire {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    record = subparsers.add_parser("record", help="run a child app-server and record both protocol directions")
    record.add_argument("--trace", type=Path, help="trace output path (default: timestamped JSONL)")
    record.add_argument("--ui", nargs="?", const="127.0.0.1:4777", help="serve the live inspector, optionally at HOST:PORT")
    record.add_argument("command", nargs=argparse.REMAINDER, help="child command, normally: -- codex app-server")
    record.set_defaults(func=record_command)

    inspect = subparsers.add_parser("inspect", help="summarize a recorded trace")
    inspect.add_argument("trace", type=Path)
    inspect.add_argument("--json", action="store_true", help="emit a JSON summary")
    inspect.set_defaults(func=inspect_command)

    replay = subparsers.add_parser("replay", help="act as a deterministic fake app-server from a trace")
    replay.add_argument("trace", type=Path)
    replay.add_argument("--speed", type=float, default=0.0, help="timing multiplier; 0 emits immediately")
    replay.add_argument("--strict-payload", action="store_true", help="require exact client payloads")
    replay.set_defaults(func=replay_command)

    serve = subparsers.add_parser("serve", help="open the trace inspector")
    serve.add_argument("trace", type=Path)
    serve.add_argument("--listen", default="127.0.0.1:4777")
    serve.set_defaults(func=serve_command)

    doctor = subparsers.add_parser("doctor", help="check whether live capture can run")
    doctor.set_defaults(func=doctor_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "speed", 0.0) < 0:
        parser.error("--speed cannot be negative")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
