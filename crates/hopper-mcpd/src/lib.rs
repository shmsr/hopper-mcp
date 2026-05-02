pub mod address;
pub mod backend;
pub mod content;
pub mod doctor;
pub mod live;
pub mod model;
pub mod persistence;
pub mod prompts;
pub mod protocol;
pub mod query;
pub mod resources;
pub mod store;
pub mod tools;
pub mod transactions;

use backend::{Backend, MockBackend, UnixWireBackend};
use live::NodeLiveBridge;
use persistence::{load_store, save_store};
use protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use store::SnapshotStore;
use tools::{call_tool, list_tools};

pub struct Daemon {
    store: SnapshotStore,
    server_info: ServerInfo,
    backend: Box<dyn Backend + Send + Sync>,
    live_bridge: NodeLiveBridge,
    store_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub title: String,
    pub version: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "hopper-mcpd".to_string(),
            title: "Hopper MCP Rust Daemon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl Daemon {
    pub fn new() -> Self {
        Self::with_backend(default_backend())
    }

    pub fn with_mock_backend_document(id: &str, name: &str) -> Self {
        Self::with_backend(Box::new(MockBackend::with_document(id, name)))
    }

    pub fn with_backend(backend: Box<dyn Backend + Send + Sync>) -> Self {
        Self {
            store: SnapshotStore::default(),
            server_info: ServerInfo::default(),
            backend,
            live_bridge: NodeLiveBridge::from_env(),
            store_path: None,
        }
    }

    pub fn with_live_bridge(live_bridge: NodeLiveBridge) -> Self {
        Self {
            store: SnapshotStore::default(),
            server_info: ServerInfo::default(),
            backend: Box::new(MockBackend::unavailable("private backend not installed")),
            live_bridge,
            store_path: None,
        }
    }

    pub fn with_store_path(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let store = load_store(&path)?;
        Ok(Self::with_store_backend(
            store,
            Some(path),
            default_backend(),
            NodeLiveBridge::from_env(),
        ))
    }

    pub fn with_store_path_and_live_bridge(
        path: impl Into<PathBuf>,
        live_bridge: NodeLiveBridge,
    ) -> anyhow::Result<Self> {
        let path = path.into();
        let store = load_store(&path)?;
        Ok(Self::with_store_backend(
            store,
            Some(path),
            default_backend(),
            live_bridge,
        ))
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let path = std::env::var_os("HOPPER_MCP_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(default_store_path);
        Self::with_store_path(path)
    }

    fn with_store_backend(
        store: SnapshotStore,
        store_path: Option<PathBuf>,
        backend: Box<dyn Backend + Send + Sync>,
        live_bridge: NodeLiveBridge,
    ) -> Self {
        Self {
            store,
            server_info: ServerInfo::default(),
            backend,
            live_bridge,
            store_path,
        }
    }

    pub fn handle(&mut self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let id_value = request.id.clone()?;
        if id_value.is_null() {
            return Some(JsonRpcResponse::error(
                None,
                JsonRpcError::invalid_request("JSON-RPC id must not be null"),
            ));
        }
        let id = Some(id_value);
        let result = match request.method.as_str() {
            "initialize" => self.initialize(request.params),
            "tools/list" => Ok(json!({ "tools": list_tools() })),
            "tools/call" => self.tools_call(request.params),
            "resources/list" => Ok(resources::list_resources()),
            "resources/read" => self.resources_read(request.params),
            "prompts/list" => Ok(prompts::list_prompts()),
            "prompts/get" => self.prompts_get(request.params),
            other => Err(JsonRpcError::method_not_found(format!(
                "Unknown method: {other}"
            ))),
        };
        Some(match result {
            Ok(value) => JsonRpcResponse::success(id, value),
            Err(error) => JsonRpcResponse::error(id, error),
        })
    }

    fn initialize(&self, _params: Option<Value>) -> Result<Value, JsonRpcError> {
        Ok(json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false },
                "prompts": { "listChanged": false }
            },
            "serverInfo": {
                "name": self.server_info.name,
                "title": self.server_info.title,
                "version": self.server_info.version
            },
            "instructions": "Use Hopper-derived snapshots only. This Rust daemon intentionally exposes no local otool/nm/strings/codesign fallback analysis."
        }))
    }

    fn tools_call(&mut self, params: Option<Value>) -> Result<Value, JsonRpcError> {
        let params = expect_object(params, "tools/call params")?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("tools/call requires string name"))?;
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let mutates_store = tool_mutates_store(name);
        let before_mutation = mutates_store.then(|| self.store.clone());
        let result = call_tool(
            &mut self.store,
            self.backend.as_ref(),
            &self.live_bridge,
            name,
            args,
        )?;
        if mutates_store
            && result.get("isError") != Some(&Value::Bool(true))
            && let Err(error) = self.persist_store()
        {
            if let Some(store) = before_mutation {
                self.store = store;
            }
            return Err(error);
        }
        Ok(result)
    }

    fn persist_store(&self) -> Result<(), JsonRpcError> {
        if let Some(path) = &self.store_path {
            save_store(path, &self.store).map_err(|err| {
                JsonRpcError::internal(format!(
                    "failed to persist store {}: {err:#}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    fn resources_read(&self, params: Option<Value>) -> Result<Value, JsonRpcError> {
        let params = expect_object(params, "resources/read params")?;
        let uri = params
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("resources/read requires string uri"))?;
        let value = self.store.resource(uri)?;
        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".to_string())
            }]
        }))
    }

    fn prompts_get(&self, params: Option<Value>) -> Result<Value, JsonRpcError> {
        let params = expect_object(params, "prompts/get params")?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("prompts/get requires string name"))?;
        let arguments = params.get("arguments").unwrap_or(&Value::Null);
        prompts::get_prompt(name, arguments)
    }
}

pub fn default_store_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| Path::new(".").to_path_buf())
        .join("data")
        .join("knowledge-store.json")
}

fn tool_mutates_store(name: &str) -> bool {
    matches!(
        name,
        "open_session"
            | "ingest_current_hopper"
            | "ingest_live_hopper"
            | "begin_transaction"
            | "queue"
            | "commit_transaction"
            | "rollback_transaction"
    )
}

fn default_backend() -> Box<dyn Backend + Send + Sync> {
    UnixWireBackend::from_env()
        .map(|backend| Box::new(backend) as Box<dyn Backend + Send + Sync>)
        .unwrap_or_else(|| {
            Box::new(MockBackend::unavailable("private backend not installed"))
                as Box<dyn Backend + Send + Sync>
        })
}

impl Default for Daemon {
    fn default() -> Self {
        Self::new()
    }
}

fn expect_object(
    params: Option<Value>,
    label: &str,
) -> Result<serde_json::Map<String, Value>, JsonRpcError> {
    match params {
        Some(Value::Object(map)) => Ok(map),
        Some(_) => Err(JsonRpcError::invalid_params(format!(
            "{label} must be an object"
        ))),
        None => Ok(serde_json::Map::new()),
    }
}
