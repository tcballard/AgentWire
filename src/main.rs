use agentwire::core::{
    load_trace, method_of, parse_message, remember_request_id, rewrite_response_id, summarize,
    TraceRecorder,
};
use agentwire::diff::{compare_traces, ComparableEvent, IgnoreRule, TraceDiff};
use agentwire::replay::plan_replay;
use agentwire::web::{hub_forever, serve_forever, WebServer};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "agentwire",
    version,
    about = "Record and replay Codex App Server JSONL traffic"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a child App Server and record both protocol directions.
    Record {
        /// Trace output path (default: timestamped JSONL).
        #[arg(long)]
        trace: Option<PathBuf>,
        /// Serve the live inspector, optionally at HOST:PORT.
        #[arg(long, num_args = 0..=1, default_missing_value = "127.0.0.1:4777")]
        ui: Option<String>,
        /// Atomically publish the live summary for an AgentWire hub.
        #[arg(long, value_name = "PATH", conflicts_with = "ui")]
        publish_summary: Option<PathBuf>,
        /// Child command, normally: -- codex app-server
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Summarize a recorded trace.
    Inspect {
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare two traces at the protocol event and payload level.
    Diff {
        left: PathBuf,
        right: PathBuf,
        /// Emit a machine-readable comparison.
        #[arg(long)]
        json: bool,
        /// Compare transport request IDs instead of ignoring them.
        #[arg(long)]
        strict_ids: bool,
        /// Maximum number of event differences to print.
        #[arg(long, default_value_t = 20)]
        max_differences: usize,
        /// Treat a run-varying payload value as equal: a bare key name
        /// (threadId) matches that key anywhere; a JSON pointer as printed
        /// by diff (/payload/params/cwd) matches one location, with *
        /// matching any single segment. Repeatable.
        #[arg(long = "ignore", value_name = "KEY|POINTER")]
        ignore: Vec<String>,
    },
    /// Act as a deterministic fake App Server from a trace.
    Replay {
        trace: PathBuf,
        /// Timing multiplier; zero emits immediately.
        #[arg(long, default_value_t = 0.0)]
        speed: f64,
        /// Require exact client payloads (transport request IDs excepted).
        #[arg(long)]
        strict_payload: bool,
    },
    /// Open the trace inspector.
    Serve {
        trace: PathBuf,
        #[arg(long, default_value = "127.0.0.1:4777")]
        listen: String,
    },
    /// Serve the latest session published by recording processes.
    Hub {
        /// Bounded current-session snapshot written by `record --publish-summary`.
        #[arg(long, value_name = "PATH")]
        state: PathBuf,
        #[arg(long, default_value = "127.0.0.1:4777")]
        listen: String,
    },
    /// Check whether live capture can run.
    Doctor,
}

fn default_trace_path() -> PathBuf {
    PathBuf::from(format!(
        "agentwire-{}.jsonl",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
    ))
}

fn record(
    trace: Option<PathBuf>,
    ui: Option<String>,
    publish_summary: Option<PathBuf>,
    command: Vec<OsString>,
) -> Result<i32> {
    let trace = trace.unwrap_or_else(default_trace_path);
    let recorder = Arc::new(match publish_summary {
        Some(snapshot) => TraceRecorder::new_published(&trace, &command, snapshot)?,
        None => TraceRecorder::new(&trace, &command)?,
    });
    let inspector = ui
        .as_deref()
        .map(|listen| WebServer::start_live(Arc::clone(&recorder), listen))
        .transpose()?;
    if let Some(inspector) = inspector.as_ref() {
        eprintln!("AgentWire inspector: {}", inspector.url());
    }
    eprintln!(
        "AgentWire trace: {}",
        recorder.path().canonicalize()?.display()
    );

    let child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            recorder.record_meta(
                "spawn_error",
                serde_json::json!({ "error": error.to_string() }),
            )?;
            recorder.close(None)?;
            return Err(error).with_context(|| format!("failed to start {:?}", command[0]));
        }
    };
    let mut child_input = child.stdin.take().context("child stdin unavailable")?;
    let child_output = child.stdout.take().context("child stdout unavailable")?;
    let input_recorder = Arc::clone(&recorder);
    let (input_done_tx, input_done_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut line = Vec::new();
        loop {
            line.clear();
            match input.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let _ = input_recorder.record_line("client_to_server", &line);
                    if child_input
                        .write_all(&line)
                        .and_then(|_| child_input.flush())
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = input_done_tx.send(());
    });

    let mut output = BufReader::new(child_output);
    let stdout = io::stdout();
    let mut client_output = stdout.lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        if output.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        recorder.record_line("server_to_client", &line)?;
        client_output.write_all(&line)?;
        client_output.flush()?;
    }
    let status = child.wait()?;
    let _ = input_done_rx.recv_timeout(Duration::from_secs(1));
    recorder.close(status.code())?;
    drop(inspector);
    Ok(status.code().unwrap_or(1))
}

fn inspect(trace: PathBuf, as_json: bool) -> Result<i32> {
    let summary = summarize(&load_trace(&trace)?);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("trace       {}", trace.display());
        println!("events      {}", summary.events);
        println!("duration    {:.1} ms", summary.duration_ms);
        println!("client →    {}", summary.client_messages);
        println!("server →    {}", summary.server_messages);
        println!("errors      {}", summary.errors);
        println!("invalid     {}", summary.invalid_messages);
        if !summary.methods.is_empty() {
            println!("methods");
            for (method, count) in summary.methods {
                println!("  {count:>4}  {method}");
            }
        }
    }
    Ok(0)
}

fn event_label(event: Option<&ComparableEvent>) -> String {
    let Some(event) = event else {
        return "∅".into();
    };
    let direction = match event.direction.as_str() {
        "client_to_server" => "client → server",
        "server_to_client" => "server → client",
        other => other,
    };
    let method = event.method.as_deref().unwrap_or("—");
    format!("{direction}  {}  {method}", event.kind)
}

fn display_value(value: Option<&Value>) -> String {
    value
        .map(|value| serde_json::to_string(value).expect("JSON value must serialize"))
        .unwrap_or_else(|| "∅".into())
}

fn print_trace_diff(comparison: &TraceDiff) {
    if comparison.equal {
        let id_note = if comparison.ignored_request_ids {
            "; request IDs ignored"
        } else {
            ""
        };
        let ignore_note = if comparison.ignored.is_empty() {
            String::new()
        } else {
            format!("; {} ignore rule(s) applied", comparison.ignored.len())
        };
        println!(
            "traces are protocol-equivalent ({} events{id_note}{ignore_note})",
            comparison.left_events
        );
        return;
    }
    println!(
        "traces differ: {} protocol event(s) differ ({} left, {} right)",
        comparison.differences_found, comparison.left_events, comparison.right_events
    );
    for difference in &comparison.differences {
        let stream = match difference.stream.as_str() {
            "client_to_server" => "client → server",
            "server_to_client" => "server → client",
            other => other,
        };
        println!(
            "\n@@ {stream} event {} · {} @@",
            difference.event, difference.kind
        );
        println!("- {}", event_label(difference.left.as_ref()));
        println!("+ {}", event_label(difference.right.as_ref()));
        for change in &difference.changes {
            println!("  {}", change.path);
            println!("    - {}", display_value(change.left.as_ref()));
            println!("    + {}", display_value(change.right.as_ref()));
        }
    }
    if comparison.truncated {
        println!(
            "\n… {} more event difference(s); raise --max-differences to show them",
            comparison.differences_found - comparison.differences.len()
        );
    }
}

fn diff(
    left: PathBuf,
    right: PathBuf,
    as_json: bool,
    strict_ids: bool,
    max_differences: usize,
    ignore: Vec<String>,
) -> Result<i32> {
    if max_differences == 0 {
        bail!("--max-differences must be at least 1");
    }
    let ignores = ignore
        .iter()
        .map(|rule| IgnoreRule::parse(rule))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow!("{error}"))?;
    let comparison = compare_traces(
        &load_trace(&left)?,
        &load_trace(&right)?,
        strict_ids,
        max_differences,
        &ignores,
    );
    if as_json {
        println!("{}", serde_json::to_string_pretty(&comparison)?);
    } else {
        print_trace_diff(&comparison);
    }
    Ok(if comparison.equal { 0 } else { 1 })
}

fn payload_without_transport_id(payload: &Value) -> Value {
    let Some(object) = payload.as_object() else {
        return payload.clone();
    };
    let mut object = object.clone();
    object.remove("id");
    Value::Object(object)
}

fn replay(trace: PathBuf, speed: f64, strict_payload: bool) -> Result<i32> {
    if speed < 0.0 {
        bail!("--speed cannot be negative");
    }
    let plan = plan_replay(&load_trace(&trace)?);
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut id_map = HashMap::new();
    let mut received = 0;
    let mut emitted = 0;
    let mut previous_elapsed: f64 = 0.0;

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        while emitted < plan.server.len() && plan.server[emitted].gate <= received {
            let step = &plan.server[emitted];
            if speed > 0.0 {
                thread::sleep(Duration::from_secs_f64(
                    ((step.elapsed_ms - previous_elapsed).max(0.0) / 1000.0) / speed,
                ));
            }
            previous_elapsed = previous_elapsed.max(step.elapsed_ms);
            let payload = rewrite_response_id(&step.payload, &id_map);
            serde_json::to_writer(&mut output, &payload)?;
            output.write_all(b"\n")?;
            output.flush()?;
            emitted += 1;
        }
        if received == plan.client.len() {
            break;
        }
        let Some(line) = lines.next() else {
            bail!(
                "client ended with {} recorded messages remaining",
                plan.client.len() - received
            );
        };
        let incoming = parse_message(line?.as_bytes())
            .with_context(|| format!("client line {} is not a JSON object", received + 1))?;
        let expected = &plan.client[received];
        let incoming_method = method_of(&incoming);
        if incoming_method != expected.method.as_deref() {
            bail!(
                "expected client method {:?}, got {incoming_method:?}",
                expected.method.as_deref()
            );
        }
        remember_request_id(&expected.payload, &incoming, &mut id_map);
        if strict_payload
            && payload_without_transport_id(&incoming)
                != payload_without_transport_id(&expected.payload)
        {
            bail!("payload mismatch for {incoming_method:?}");
        }
        previous_elapsed = previous_elapsed.max(expected.elapsed_ms);
        received += 1;
    }
    if lines.next().transpose()?.is_some() {
        bail!("client sent more messages than the trace contains");
    }
    Ok(0)
}

fn doctor() -> Result<i32> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let executable = if cfg!(windows) { "codex.exe" } else { "codex" };
    let codex = std::env::split_paths(&path)
        .map(|directory| directory.join(executable))
        .find(|candidate| candidate.is_file());
    println!("agentwire    {}", env!("CARGO_PKG_VERSION"));
    println!("runtime      native Rust binary");
    let Some(codex) = codex else {
        println!("codex        not found");
        println!("status       replay works; live Codex capture is unavailable");
        return Ok(1);
    };
    let output = Command::new(&codex).arg("--version").output()?;
    let version = String::from_utf8_lossy(if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    });
    println!("codex        {}", codex.display());
    println!("version      {}", version.trim());
    println!("transport    JSONL over stdio");
    println!("status       ready");
    Ok(0)
}

fn run() -> Result<i32> {
    match Cli::parse().command {
        Commands::Record {
            trace,
            ui,
            publish_summary,
            command,
        } => record(trace, ui, publish_summary, command),
        Commands::Inspect { trace, json } => inspect(trace, json),
        Commands::Diff {
            left,
            right,
            json,
            strict_ids,
            max_differences,
            ignore,
        } => diff(left, right, json, strict_ids, max_differences, ignore),
        Commands::Replay {
            trace,
            speed,
            strict_payload,
        } => replay(trace, speed, strict_payload),
        Commands::Serve { trace, listen } => serve_forever(trace, &listen).map(|_| 0),
        Commands::Hub { state, listen } => hub_forever(state, &listen).map(|_| 0),
        Commands::Doctor => doctor(),
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("agentwire: {error:#}");
            std::process::exit(2);
        }
    }
}
