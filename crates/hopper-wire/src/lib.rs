use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("failed to serialize wire message: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("failed to deserialize wire message: {0}")]
    Decode(#[source] serde_json::Error),
}

pub fn encode<T: Serialize>(message: &T) -> Result<String, WireError> {
    serde_json::to_string(message).map_err(WireError::Encode)
}

pub fn decode<T: DeserializeOwned>(text: &str) -> Result<T, WireError> {
    serde_json::from_str(text).map_err(WireError::Decode)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeRequest {
    pub wire_version: u32,
    pub daemon_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeResponse {
    pub accepted: bool,
    pub wire_version: u32,
    pub agent_version: String,
    pub hopper_version: Option<String>,
    pub capabilities: AgentCapabilities,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    pub current_document: bool,
    pub procedures: bool,
    pub writes: bool,
    #[serde(default)]
    pub private_api: bool,
    #[serde(default)]
    pub injected: bool,
    #[serde(default)]
    pub status: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    Fixture,
    OfficialMcp,
    PluginBridge,
    InjectedPrivate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Unavailable,
    Injecting,
    Ready,
    Analyzing,
    NoDocument,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    pub backend_mode: BackendMode,
    pub readiness: ReadinessState,
    pub hopper_version: Option<String>,
    pub hopper_build: Option<String>,
    pub capabilities: AgentCapabilities,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AgentRequest {
    Handshake(HandshakeRequest),
    Status,
    CurrentDocument,
    ListProcedures { max_results: Option<u64> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AgentResponse {
    Handshake(HandshakeResponse),
    Status(AgentStatus),
    CurrentDocument {
        document_id: String,
        name: String,
    },
    Procedures {
        procedures: Vec<WireProcedure>,
        truncated: bool,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireProcedure {
    pub addr: String,
    pub name: Option<String>,
    pub size: Option<u64>,
}
