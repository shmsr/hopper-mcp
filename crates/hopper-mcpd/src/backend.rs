use hopper_wire::{
    AgentRequest, AgentResponse, AgentStatus, HandshakeRequest, HandshakeResponse, WIRE_VERSION,
    decode, encode,
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendCapabilities {
    pub current_document: bool,
    pub procedures: bool,
    pub writes: bool,
    pub private_api: bool,
    pub injected: bool,
    pub status: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatus {
    pub name: String,
    pub available: bool,
    pub reason: Option<String>,
    pub backend_mode: Option<String>,
    pub readiness: Option<String>,
    pub hopper_version: Option<String>,
    pub hopper_build: Option<String>,
    pub capabilities: Option<BackendCapabilities>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendDocument {
    pub document_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendProcedure {
    pub addr: String,
    pub name: Option<String>,
    pub size: Option<u64>,
}

pub trait Backend {
    fn name(&self) -> &str;

    fn status(&self) -> BackendStatus;

    fn current_document(&self) -> Result<BackendDocument, String>;

    fn list_procedures(&self, max_results: Option<u64>) -> Result<Vec<BackendProcedure>, String>;
}

#[derive(Debug, Clone)]
pub struct MockBackend {
    status: BackendStatus,
    document: Option<BackendDocument>,
}

impl MockBackend {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: BackendStatus {
                name: "mock".to_string(),
                available: false,
                reason: Some(reason.into()),
                backend_mode: None,
                readiness: None,
                hopper_version: None,
                hopper_build: None,
                capabilities: None,
            },
            document: None,
        }
    }

    pub fn with_document(document_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            status: BackendStatus {
                name: "mock".to_string(),
                available: true,
                reason: None,
                backend_mode: None,
                readiness: None,
                hopper_version: None,
                hopper_build: None,
                capabilities: None,
            },
            document: Some(BackendDocument {
                document_id: document_id.into(),
                name: name.into(),
            }),
        }
    }
}

impl Backend for MockBackend {
    fn name(&self) -> &str {
        &self.status.name
    }

    fn status(&self) -> BackendStatus {
        self.status.clone()
    }

    fn current_document(&self) -> Result<BackendDocument, String> {
        self.document.clone().ok_or_else(|| {
            self.status
                .reason
                .clone()
                .unwrap_or_else(|| "No current document".to_string())
        })
    }

    fn list_procedures(&self, _max_results: Option<u64>) -> Result<Vec<BackendProcedure>, String> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone)]
pub struct UnixWireBackend {
    socket_path: PathBuf,
    daemon_version: String,
    timeout: Duration,
}

impl UnixWireBackend {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn from_env() -> Option<Self> {
        std::env::var_os("HOPPER_MCP_PRIVATE_AGENT_SOCKET").map(Self::new)
    }

    fn open(&self) -> Result<WireConnection, WireBackendError> {
        let stream =
            UnixStream::connect(&self.socket_path).map_err(|source| WireBackendError::Connect {
                path: self.socket_path.clone(),
                source,
            })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|source| WireBackendError::Configure {
                path: self.socket_path.clone(),
                source,
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|source| WireBackendError::Configure {
                path: self.socket_path.clone(),
                source,
            })?;
        let writer = stream
            .try_clone()
            .map_err(|source| WireBackendError::Configure {
                path: self.socket_path.clone(),
                source,
            })?;
        Ok(WireConnection {
            reader: BufReader::new(stream),
            writer,
        })
    }

    fn handshake(
        &self,
        connection: &mut WireConnection,
    ) -> Result<HandshakeResponse, WireBackendError> {
        connection.send(&AgentRequest::Handshake(HandshakeRequest {
            wire_version: WIRE_VERSION,
            daemon_version: self.daemon_version.clone(),
        }))?;
        match connection.receive()? {
            AgentResponse::Handshake(response)
                if response.accepted && response.wire_version == WIRE_VERSION =>
            {
                Ok(response)
            }
            AgentResponse::Handshake(response) => Err(WireBackendError::HandshakeRejected {
                wire_version: response.wire_version,
                reason: response
                    .unsupported_reason
                    .unwrap_or_else(|| "agent rejected handshake".to_string()),
            }),
            AgentResponse::Error { code, message } => {
                Err(WireBackendError::Remote { code, message })
            }
            other => Err(WireBackendError::UnexpectedResponse {
                expected: "handshake",
                actual: format!("{other:?}"),
            }),
        }
    }
}

impl Backend for UnixWireBackend {
    fn name(&self) -> &str {
        "private"
    }

    fn status(&self) -> BackendStatus {
        let result = self.open().and_then(|mut connection| {
            let handshake = self.handshake(&mut connection)?;
            if !handshake.capabilities.status {
                return Ok(StatusSource::LegacyHandshake(handshake));
            }
            connection.send(&AgentRequest::Status)?;
            match connection.receive()? {
                AgentResponse::Status(status) => Ok(StatusSource::AgentStatus(status)),
                AgentResponse::Error { code, message } => {
                    Err(WireBackendError::Remote { code, message })
                }
                other => Err(WireBackendError::UnexpectedResponse {
                    expected: "status",
                    actual: format!("{other:?}"),
                }),
            }
        });
        match result {
            Ok(StatusSource::LegacyHandshake(handshake)) => {
                self.translate_handshake_status(handshake)
            }
            Ok(StatusSource::AgentStatus(status)) => self.translate_status(status),
            Err(error) => BackendStatus {
                name: self.name().to_string(),
                available: false,
                reason: Some(error.to_string()),
                backend_mode: None,
                readiness: None,
                hopper_version: None,
                hopper_build: None,
                capabilities: None,
            },
        }
    }

    fn current_document(&self) -> Result<BackendDocument, String> {
        let mut connection = self.open().map_err(|error| error.to_string())?;
        self.handshake(&mut connection)
            .map_err(|error| error.to_string())?;
        connection
            .send(&AgentRequest::CurrentDocument)
            .map_err(|error| error.to_string())?;
        match connection.receive().map_err(|error| error.to_string())? {
            AgentResponse::CurrentDocument { document_id, name } => {
                Ok(BackendDocument { document_id, name })
            }
            AgentResponse::Error { code, message } => Err(format!("{code}: {message}")),
            other => Err(format!(
                "private backend returned unexpected response: {other:?}"
            )),
        }
    }

    fn list_procedures(&self, max_results: Option<u64>) -> Result<Vec<BackendProcedure>, String> {
        let mut connection = self.open().map_err(|error| error.to_string())?;
        self.handshake(&mut connection)
            .map_err(|error| error.to_string())?;
        connection
            .send(&AgentRequest::ListProcedures { max_results })
            .map_err(|error| error.to_string())?;
        match connection.receive().map_err(|error| error.to_string())? {
            AgentResponse::Procedures { procedures, .. } => Ok(procedures
                .into_iter()
                .map(|procedure| BackendProcedure {
                    addr: procedure.addr,
                    name: procedure.name,
                    size: procedure.size,
                })
                .collect()),
            AgentResponse::Error { code, message } => Err(format!("{code}: {message}")),
            other => Err(format!(
                "private backend returned unexpected response: {other:?}"
            )),
        }
    }
}

impl UnixWireBackend {
    fn translate_handshake_status(&self, handshake: HandshakeResponse) -> BackendStatus {
        BackendStatus {
            name: self.name().to_string(),
            available: true,
            reason: handshake.unsupported_reason,
            backend_mode: None,
            readiness: None,
            hopper_version: handshake.hopper_version,
            hopper_build: None,
            capabilities: Some(self.translate_capabilities(handshake.capabilities)),
        }
    }

    fn translate_status(&self, status: AgentStatus) -> BackendStatus {
        let available = match status.readiness {
            hopper_wire::ReadinessState::Ready
            | hopper_wire::ReadinessState::Analyzing
            | hopper_wire::ReadinessState::NoDocument => true,
            hopper_wire::ReadinessState::Injecting
            | hopper_wire::ReadinessState::Unavailable
            | hopper_wire::ReadinessState::Unsupported
            | hopper_wire::ReadinessState::Failed => false,
        };
        BackendStatus {
            name: self.name().to_string(),
            available,
            reason: status.unsupported_reason,
            backend_mode: Some(backend_mode_name(status.backend_mode)),
            readiness: Some(readiness_name(status.readiness)),
            hopper_version: status.hopper_version,
            hopper_build: status.hopper_build,
            capabilities: Some(self.translate_capabilities(status.capabilities)),
        }
    }

    fn translate_capabilities(
        &self,
        capabilities: hopper_wire::AgentCapabilities,
    ) -> BackendCapabilities {
        BackendCapabilities {
            current_document: capabilities.current_document,
            procedures: capabilities.procedures,
            writes: capabilities.writes,
            private_api: capabilities.private_api,
            injected: capabilities.injected,
            status: capabilities.status,
        }
    }
}

enum StatusSource {
    LegacyHandshake(HandshakeResponse),
    AgentStatus(AgentStatus),
}

fn backend_mode_name(mode: hopper_wire::BackendMode) -> String {
    match mode {
        hopper_wire::BackendMode::Fixture => "fixture".to_string(),
        hopper_wire::BackendMode::OfficialMcp => "official_mcp".to_string(),
        hopper_wire::BackendMode::PluginBridge => "plugin_bridge".to_string(),
        hopper_wire::BackendMode::InjectedPrivate => "injected_private".to_string(),
    }
}

fn readiness_name(readiness: hopper_wire::ReadinessState) -> String {
    match readiness {
        hopper_wire::ReadinessState::Unavailable => "unavailable".to_string(),
        hopper_wire::ReadinessState::Injecting => "injecting".to_string(),
        hopper_wire::ReadinessState::Ready => "ready".to_string(),
        hopper_wire::ReadinessState::Analyzing => "analyzing".to_string(),
        hopper_wire::ReadinessState::NoDocument => "no_document".to_string(),
        hopper_wire::ReadinessState::Unsupported => "unsupported".to_string(),
        hopper_wire::ReadinessState::Failed => "failed".to_string(),
    }
}

struct WireConnection {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl WireConnection {
    fn send(&mut self, request: &AgentRequest) -> Result<(), WireBackendError> {
        let text = encode(request)?;
        self.writer
            .write_all(text.as_bytes())
            .map_err(WireBackendError::Write)?;
        self.writer
            .write_all(b"\n")
            .map_err(WireBackendError::Write)?;
        self.writer.flush().map_err(WireBackendError::Write)
    }

    fn receive(&mut self) -> Result<AgentResponse, WireBackendError> {
        let mut line = String::new();
        let bytes = self
            .reader
            .read_line(&mut line)
            .map_err(WireBackendError::Read)?;
        if bytes == 0 {
            return Err(WireBackendError::Eof);
        }
        Ok(decode(&line)?)
    }
}

#[derive(Debug, thiserror::Error)]
enum WireBackendError {
    #[error("failed to connect to private backend socket {}: {source}", path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to configure private backend socket {}: {source}", path.display())]
    Configure {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write private backend request: {0}")]
    Write(#[source] std::io::Error),
    #[error("failed to read private backend response: {0}")]
    Read(#[source] std::io::Error),
    #[error("private backend closed the connection without a response")]
    Eof,
    #[error("private backend wire error: {0}")]
    Wire(#[from] hopper_wire::WireError),
    #[error("private backend handshake rejected for wire version {wire_version}: {reason}")]
    HandshakeRejected { wire_version: u32, reason: String },
    #[error("private backend returned an error [{code}]: {message}")]
    Remote { code: String, message: String },
    #[error("private backend returned {actual} while waiting for {expected}")]
    UnexpectedResponse {
        expected: &'static str,
        actual: String,
    },
}
