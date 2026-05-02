use crate::model::Session;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const DEFAULT_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveIngestRequest {
    pub executable_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_functions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_strings: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_procedures: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_objective_c: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_swift: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_exceptions: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_after_export: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for_analysis: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_export: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_pseudocode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pseudocode_functions: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LiveIngestResult {
    pub session: Session,
    pub launch: Value,
    pub diagnostics: Value,
}

#[derive(Debug, Clone)]
pub struct NodeLiveBridge {
    command: OsString,
    args: Vec<OsString>,
}

impl NodeLiveBridge {
    pub fn new<I, S>(command: impl Into<OsString>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            command: command.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn from_env() -> Self {
        if let Some(command) = std::env::var_os("HOPPER_MCP_LIVE_BRIDGE") {
            return Self::new(command, std::iter::empty::<OsString>());
        }
        Self::new("node", [default_bridge_script().into_os_string()])
    }

    pub fn from_root(root: impl AsRef<Path>) -> Self {
        Self::new(
            "node",
            [bridge_script_for_root(root.as_ref()).into_os_string()],
        )
    }

    pub fn diagnostics(&self) -> Value {
        let reason = self.unavailable_reason();
        json!({
            "backend": "node-live-bridge",
            "available": reason.is_none(),
            "reason": reason,
            "command": self.command.to_string_lossy(),
            "args": self.args.iter().map(|arg| arg.to_string_lossy().to_string()).collect::<Vec<_>>()
        })
    }

    pub fn ingest(&self, request: &LiveIngestRequest) -> Result<LiveIngestResult, LiveBridgeError> {
        let timeout =
            Duration::from_millis(request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).max(1));
        let started = Instant::now();
        let mut command = Command::new(&self.command);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn().map_err(LiveBridgeError::Spawn)?;
        let stdout = child.stdout.take().ok_or(LiveBridgeError::MissingStdout)?;
        let stderr = child.stderr.take().ok_or(LiveBridgeError::MissingStderr)?;
        let stdout_reader = drain_pipe(stdout);
        let stderr_reader = drain_pipe(stderr);

        {
            let mut stdin = child.stdin.take().ok_or(LiveBridgeError::MissingStdin)?;
            serde_json::to_writer(&mut stdin, request).map_err(LiveBridgeError::Encode)?;
            stdin
                .write_all(b"\n")
                .map_err(LiveBridgeError::WriteStdin)?;
        }

        let status = if let Some(status) =
            child.wait_timeout(timeout).map_err(LiveBridgeError::Wait)?
        {
            status
        } else {
            terminate_bridge_process(&mut child);
            let _ = child.wait().map_err(LiveBridgeError::Wait)?;
            let stderr = join_pipe(stderr_reader)
                .map(|bytes| tail_text(&bytes))
                .unwrap_or_else(|error| format!("failed to read stderr after timeout: {error}"));
            let _ = join_pipe(stdout_reader);
            return Err(LiveBridgeError::Timeout {
                timeout_ms: timeout.as_millis() as u64,
                stderr,
            });
        };

        let elapsed_ms = started.elapsed().as_millis() as u64;
        let stdout_bytes = join_pipe(stdout_reader)?;
        let stderr_bytes = join_pipe(stderr_reader)?;
        let stdout = String::from_utf8(stdout_bytes).map_err(LiveBridgeError::StdoutUtf8)?;
        let stderr = tail_text(&stderr_bytes);
        if let Some(error) = parse_remote_error(&stdout)? {
            return Err(error);
        }
        if !status.success() {
            return Err(LiveBridgeError::Exit {
                code: status.code(),
                stderr,
                stdout: tail_str(&stdout),
            });
        }

        let envelope: BridgeEnvelope =
            serde_json::from_str(&stdout).map_err(LiveBridgeError::Decode)?;
        if let Some(error) = envelope.error {
            return Err(remote_error(error));
        }
        let session = envelope.session.ok_or(LiveBridgeError::MissingSession)?;
        Ok(LiveIngestResult {
            session,
            launch: envelope.launch.unwrap_or_else(|| json!({})),
            diagnostics: merge_diagnostics(envelope.diagnostics, elapsed_ms),
        })
    }
}

fn drain_pipe<R>(mut pipe: R) -> JoinHandle<Result<Vec<u8>, std::io::Error>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = Vec::new();
        pipe.read_to_end(&mut buffer)?;
        Ok(buffer)
    })
}

fn join_pipe(
    handle: JoinHandle<Result<Vec<u8>, std::io::Error>>,
) -> Result<Vec<u8>, LiveBridgeError> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(LiveBridgeError::ReadOutput(error)),
        Err(_) => Err(LiveBridgeError::ReadThreadPanic),
    }
}

impl NodeLiveBridge {
    fn unavailable_reason(&self) -> Option<String> {
        if !command_available(&self.command) {
            return Some(format!(
                "live bridge command not found: {}",
                self.command.to_string_lossy()
            ));
        }
        for arg in &self.args {
            let path = PathBuf::from(arg);
            if path.components().count() > 1 && !path.exists() {
                return Some(format!(
                    "live bridge argument path not found: {}",
                    path.display()
                ));
            }
        }
        None
    }
}

fn parse_remote_error(stdout: &str) -> Result<Option<LiveBridgeError>, LiveBridgeError> {
    if stdout.trim().is_empty() {
        return Ok(None);
    }
    let envelope: BridgeEnvelope = serde_json::from_str(stdout).map_err(LiveBridgeError::Decode)?;
    Ok(envelope.error.map(remote_error))
}

fn remote_error(error: BridgeErrorPayload) -> LiveBridgeError {
    LiveBridgeError::Remote {
        code: error
            .code
            .unwrap_or_else(|| "live_bridge_failed".to_string()),
        message: error.message,
    }
}

pub fn default_bridge_script() -> std::path::PathBuf {
    if let Some(script) = std::env::var_os("HOPPER_MCP_LIVE_BRIDGE_SCRIPT") {
        return PathBuf::from(script);
    }
    for root in candidate_roots() {
        let script = bridge_script_for_root(&root);
        if script.is_file() {
            return script;
        }
    }
    bridge_script_for_root(&compile_time_repo_root())
}

fn candidate_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(root) = std::env::var_os("HOPPER_MCP_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(root) = runtime_bundle_root() {
        roots.push(root);
    }
    if let Ok(root) = std::env::current_dir() {
        roots.push(root);
    }
    roots.push(compile_time_repo_root());
    roots
}

fn runtime_bundle_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?;
    let target_dir = profile_dir.parent()?;
    if target_dir.file_name().is_some_and(|name| name == "target") {
        return target_dir.parent().map(Path::to_path_buf);
    }
    None
}

fn bridge_script_for_root(root: &Path) -> PathBuf {
    root.join("src").join("live-bridge-cli.js")
}

fn compile_time_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn terminate_bridge_process(child: &mut Child) {
    #[cfg(unix)]
    {
        let process_group = format!("-{}", child.id());
        let _ = Command::new("/bin/kill")
            .args(["-TERM", &process_group])
            .status();
    }
    let _ = child.kill();
}

fn command_available(command: &OsString) -> bool {
    let path = PathBuf::from(command);
    if path.components().count() > 1 {
        return path.exists();
    }
    let Some(command) = command.to_str() else {
        return false;
    };
    Command::new("/usr/bin/which")
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[derive(Debug, Deserialize)]
struct BridgeEnvelope {
    #[serde(default)]
    session: Option<Session>,
    #[serde(default)]
    launch: Option<Value>,
    #[serde(default)]
    diagnostics: Option<Value>,
    #[serde(default)]
    error: Option<BridgeErrorPayload>,
}

#[derive(Debug, Deserialize)]
struct BridgeErrorPayload {
    message: String,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LiveBridgeError {
    #[error("failed to spawn live bridge: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("live bridge stdin was unavailable")]
    MissingStdin,
    #[error("live bridge stdout was unavailable")]
    MissingStdout,
    #[error("live bridge stderr was unavailable")]
    MissingStderr,
    #[error("failed to encode live bridge request: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("failed to write live bridge request: {0}")]
    WriteStdin(#[source] std::io::Error),
    #[error("failed while waiting for live bridge: {0}")]
    Wait(#[source] std::io::Error),
    #[error("failed to read live bridge output: {0}")]
    ReadOutput(#[source] std::io::Error),
    #[error("live bridge output reader panicked")]
    ReadThreadPanic,
    #[error("live bridge timed out after {timeout_ms}ms. stderr tail: {stderr}")]
    Timeout { timeout_ms: u64, stderr: String },
    #[error("live bridge exited with code {code:?}. stderr tail: {stderr}; stdout tail: {stdout}")]
    Exit {
        code: Option<i32>,
        stderr: String,
        stdout: String,
    },
    #[error("live bridge stdout was not utf-8: {0}")]
    StdoutUtf8(#[source] std::string::FromUtf8Error),
    #[error("live bridge returned malformed JSON: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("live bridge returned an error [{code}]: {message}")]
    Remote { code: String, message: String },
    #[error("live bridge response did not include a session")]
    MissingSession,
}

fn merge_diagnostics(diagnostics: Option<Value>, elapsed_ms: u64) -> Value {
    let mut value = diagnostics.unwrap_or_else(|| json!({}));
    if let Value::Object(map) = &mut value {
        map.entry("backend")
            .or_insert_with(|| Value::String("node-live-bridge".to_string()));
        map.insert("elapsedMs".to_string(), Value::Number(elapsed_ms.into()));
        return value;
    }
    json!({
        "backend": "node-live-bridge",
        "elapsedMs": elapsed_ms,
        "bridgeDiagnostics": value
    })
}

fn tail_text(bytes: &[u8]) -> String {
    tail_str(&String::from_utf8_lossy(bytes))
}

fn tail_str(text: &str) -> String {
    const LIMIT: usize = 4000;
    if text.len() <= LIMIT {
        text.to_string()
    } else {
        let start = text
            .char_indices()
            .find_map(|(index, _)| (text.len() - index <= LIMIT).then_some(index))
            .unwrap_or(0);
        text[start..].to_string()
    }
}
