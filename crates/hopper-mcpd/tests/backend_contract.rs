use hopper_mcpd::Daemon;
use hopper_mcpd::backend::{Backend, MockBackend, UnixWireBackend};
use hopper_mcpd::live::NodeLiveBridge;
use hopper_mcpd::protocol::JsonRpcRequest;
use hopper_wire::{
    AgentCapabilities, AgentRequest, AgentResponse, HandshakeResponse, WIRE_VERSION,
};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

#[test]
fn mock_backend_reports_private_unavailable_by_default() {
    let backend = MockBackend::unavailable("private backend not installed");
    let status = backend.status();
    assert_eq!(status.name, "mock");
    assert!(!status.available);
    assert_eq!(
        status.reason.as_deref(),
        Some("private backend not installed")
    );
}

#[test]
fn mock_backend_can_return_current_document() {
    let backend = MockBackend::with_document("doc-1", "Calculator");
    let doc = backend.current_document().unwrap();
    assert_eq!(doc.document_id, "doc-1");
    assert_eq!(doc.name, "Calculator");
}

#[test]
fn private_wire_backend_reports_available_after_handshake() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_handshake_agent(&socket);

    let backend = UnixWireBackend::new(&socket);
    let status = backend.status();

    assert_eq!(status.name, "private");
    assert!(status.available, "{status:?}");
    assert_eq!(status.reason, None);
    server.join().unwrap();
}

#[test]
fn private_wire_backend_reports_available_for_legacy_handshake_only_agent() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_legacy_handshake_only_agent(&socket);

    let backend = UnixWireBackend::new(&socket);
    let status = backend.status();

    assert_eq!(status.name, "private");
    assert!(status.available, "{status:?}");
    assert_eq!(status.reason, None);
    assert_eq!(status.backend_mode, None);
    assert_eq!(status.readiness, None);
    assert_eq!(status.hopper_version.as_deref(), Some("6.test"));
    assert_eq!(status.hopper_build, None);
    assert_eq!(
        status.capabilities.as_ref().map(|caps| caps.status),
        Some(false)
    );
    server.join().unwrap();
}

#[test]
fn private_wire_backend_reads_current_document() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_current_document_agent(&socket, "doc-private", "HopperTarget");

    let backend = UnixWireBackend::new(&socket);
    let doc = backend.current_document().unwrap();

    assert_eq!(doc.document_id, "doc-private");
    assert_eq!(doc.name, "HopperTarget");
    server.join().unwrap();
}

#[test]
fn private_wire_backend_reads_procedures() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_procedure_agent(&socket);

    let backend = UnixWireBackend::new(&socket);
    let procedures = backend.list_procedures(Some(10)).unwrap();

    assert_eq!(procedures.len(), 1);
    assert_eq!(procedures[0].addr, "0x1000");
    assert_eq!(procedures[0].name.as_deref(), Some("private_main"));
    assert_eq!(procedures[0].size, Some(64));
    server.join().unwrap();
}

#[test]
fn private_wire_backend_fails_closed_when_socket_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let backend = UnixWireBackend::new(temp.path().join("missing.sock"));

    let status = backend.status();

    assert_eq!(status.name, "private");
    assert!(!status.available);
    assert!(
        status
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("connect")),
        "{status:?}"
    );
}

#[test]
fn backend_tools_are_registered_as_strict_read_only_tools() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/list", json!({}));
    let tools = result["tools"].as_array().unwrap();

    for name in ["backend_status", "backend_diagnostics"] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
    }
}

#[test]
fn ingest_current_hopper_is_registered_as_strict_read_write_tool() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/list", json!({}));
    let tools = result["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "ingest_current_hopper")
        .expect("missing ingest_current_hopper");

    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        tool["inputSchema"]["properties"]["backend"]["enum"],
        json!(["auto", "mock", "private"])
    );
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
}

#[test]
fn ingest_live_hopper_is_registered_as_strict_read_write_tool() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/list", json!({}));
    let tools = result["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "ingest_live_hopper")
        .expect("missing ingest_live_hopper");

    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    assert_eq!(tool["inputSchema"]["required"][0], json!("executable_path"));
    assert_eq!(
        tool["inputSchema"]["properties"]["timeout_ms"]["maximum"],
        600_000
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["max_functions"]["maximum"],
        50_000
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["max_strings"]["maximum"],
        250_000
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["max_pseudocode_functions"]["maximum"],
        1_000
    );
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
}

#[test]
fn backend_status_reports_default_mock_backend() {
    let mut daemon = Daemon::new();
    let status = call(&mut daemon, "backend_status", json!({}));

    assert_eq!(status["backend"], "mock");
    assert_eq!(status["available"], false);
    assert_eq!(status["reason"], "private backend not installed");
}

#[test]
fn backend_diagnostics_reports_backend_status_and_wire_version() {
    let mut daemon = Daemon::new();
    let diagnostics = call(&mut daemon, "backend_diagnostics", json!({}));

    assert_eq!(diagnostics["backend"], "mock");
    assert_eq!(diagnostics["available"], false);
    assert_eq!(diagnostics["reason"], "private backend not installed");
    assert_eq!(diagnostics["wireVersion"], hopper_wire::WIRE_VERSION);
    assert_eq!(diagnostics["liveBridge"]["backend"], "node-live-bridge");
    assert_eq!(diagnostics["liveBridge"]["available"], true);
}

#[test]
fn backend_diagnostics_reports_private_backend_mode_and_readiness() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_status_agent(
        &socket,
        hopper_wire::BackendMode::InjectedPrivate,
        hopper_wire::ReadinessState::Ready,
    );
    let mut daemon = Daemon::with_backend(Box::new(UnixWireBackend::new(&socket)));

    let diagnostics = call(&mut daemon, "backend_diagnostics", json!({}));

    assert_eq!(diagnostics["backend"], "private");
    assert_eq!(diagnostics["backendMode"], "injected_private");
    assert_eq!(diagnostics["readiness"], "ready");
    assert_eq!(diagnostics["capabilities"]["privateApi"], true);
    assert_eq!(diagnostics["capabilities"]["injected"], true);
    server.join().unwrap();
}

#[test]
fn backend_status_reports_unavailable_for_failed_readiness() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_status_agent(
        &socket,
        hopper_wire::BackendMode::InjectedPrivate,
        hopper_wire::ReadinessState::Failed,
    );
    let mut daemon = Daemon::with_backend(Box::new(UnixWireBackend::new(&socket)));

    let status = call(&mut daemon, "backend_status", json!({}));

    assert_eq!(status["backend"], "private");
    assert_eq!(status["readiness"], "failed");
    assert_eq!(status["available"], false);
    server.join().unwrap();
}

#[test]
fn capabilities_report_rust_live_ingest_bridge() {
    let mut daemon = Daemon::new();
    let capabilities = call(&mut daemon, "capabilities", json!({}));

    assert_eq!(capabilities["implementation"], "rust");
    assert_eq!(capabilities["liveIngest"]["available"], true);
    assert_eq!(capabilities["liveIngest"]["backend"], "node-live-bridge");
    assert_eq!(capabilities["localFallbackTools"], false);
}

#[test]
fn capabilities_report_unavailable_live_bridge_command() {
    let mut daemon = Daemon::with_live_bridge(NodeLiveBridge::new(
        "/definitely/not/hopper-live-bridge",
        std::iter::empty::<&str>(),
    ));
    let capabilities = call(&mut daemon, "capabilities", json!({}));

    assert_eq!(capabilities["liveIngest"]["available"], false);
    assert!(
        capabilities["liveIngest"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("not found")),
        "{}",
        capabilities["liveIngest"]
    );
}

#[test]
fn ingest_current_hopper_uses_backend_boundary() {
    let mut daemon = Daemon::with_mock_backend_document("doc-1", "Calculator");
    let ingested = call(
        &mut daemon,
        "ingest_current_hopper",
        json!({ "backend": "mock" }),
    );
    assert_eq!(ingested["sessionId"], "live-doc-1");
    let caps = call(&mut daemon, "backend_status", json!({}));
    assert_eq!(caps["available"], true);
}

#[test]
fn ingest_current_hopper_can_require_private_wire_backend() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_document_and_procedure_agent(&socket, Vec::new());
    let mut daemon = Daemon::with_backend(Box::new(UnixWireBackend::new(&socket)));

    let ingested = call(
        &mut daemon,
        "ingest_current_hopper",
        json!({ "backend": "private" }),
    );

    assert_eq!(ingested["sessionId"], "live-doc-private");
    assert_eq!(ingested["binary"]["name"], "PrivateDoc");
    server.join().unwrap();
}

#[test]
fn ingest_current_hopper_populates_private_wire_procedures() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_document_and_procedure_agent(&socket, private_procedures());
    let mut daemon = Daemon::with_backend(Box::new(UnixWireBackend::new(&socket)));

    let ingested = call(
        &mut daemon,
        "ingest_current_hopper",
        json!({ "backend": "private" }),
    );

    assert_eq!(ingested["sessionId"], "live-doc-private");
    assert_eq!(ingested["counts"]["functions"], 1);
    let procedure = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x1000" }),
    );
    assert_eq!(procedure["name"], "private_main");
    assert_eq!(procedure["size"], 64);
    server.join().unwrap();
}

#[test]
fn ingest_current_hopper_rejects_private_when_backend_is_not_private() {
    let mut daemon = Daemon::new();
    let error = tool_error(
        &mut daemon,
        "ingest_current_hopper",
        json!({ "backend": "private" }),
    );

    assert_eq!(error.code, -32602);
    assert!(
        error.message.contains("private backend requested"),
        "{}",
        error.message
    );
}

#[test]
fn backend_tools_reject_unknown_arguments() {
    for name in [
        "backend_status",
        "backend_diagnostics",
        "ingest_current_hopper",
    ] {
        let mut daemon = Daemon::new();
        let error = tool_error(&mut daemon, name, json!({ "typo": true }));

        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("Unrecognized key: typo"),
            "{}",
            error.message
        );
    }
}

#[test]
fn ingest_live_hopper_rejects_unknown_arguments() {
    let mut daemon = Daemon::new();
    let error = tool_error(
        &mut daemon,
        "ingest_live_hopper",
        json!({ "executable_path": "/bin/echo", "typo": true }),
    );

    assert_eq!(error.code, -32602);
    assert!(
        error.message.contains("Unrecognized key: typo"),
        "{}",
        error.message
    );
}

#[test]
fn ingest_live_hopper_requires_executable_path() {
    let mut daemon = Daemon::new();
    let error = tool_error(&mut daemon, "ingest_live_hopper", json!({}));

    assert_eq!(error.code, -32602);
    assert!(
        error
            .message
            .contains("ingest_live_hopper requires executable_path"),
        "{}",
        error.message
    );
}

#[test]
fn ingest_live_hopper_rejects_values_above_runtime_caps() {
    for (key, value, maximum) in [
        ("timeout_ms", 600_001, "600000"),
        ("max_functions", 50_001, "50000"),
        ("max_strings", 250_001, "250000"),
        ("max_pseudocode_functions", 1_001, "1000"),
    ] {
        let mut daemon = Daemon::new();
        let error = tool_error(
            &mut daemon,
            "ingest_live_hopper",
            json!({ "executable_path": "/bin/echo", key: value }),
        );

        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains(key) && error.message.contains(maximum),
            "{}",
            error.message
        );
    }
}

#[test]
fn ingest_current_hopper_rejects_unsupported_backend_argument() {
    let mut daemon = Daemon::new();
    let error = tool_error(
        &mut daemon,
        "ingest_current_hopper",
        json!({ "backend": "official" }),
    );

    assert_eq!(error.code, -32602);
    assert!(
        error.message.contains("backend must be one of"),
        "{}",
        error.message
    );
}

fn start_handshake_agent(socket: &Path) -> JoinHandle<()> {
    let socket = socket.to_path_buf();
    start_agent(socket, |stream| {
        expect_handshake(&stream);
        send_response(&stream, handshake_response());
        let request = read_request(&stream);
        assert_eq!(request, AgentRequest::Status);
        send_response(
            &stream,
            status_response(
                hopper_wire::BackendMode::PluginBridge,
                hopper_wire::ReadinessState::Ready,
            ),
        );
    })
}

fn start_legacy_handshake_only_agent(socket: &Path) -> JoinHandle<()> {
    let socket = socket.to_path_buf();
    start_agent(socket, |stream| {
        expect_handshake(&stream);
        send_response(
            &stream,
            handshake_response_with_capabilities(AgentCapabilities {
                current_document: true,
                procedures: true,
                writes: false,
                private_api: false,
                injected: false,
                status: false,
            }),
        );
    })
}

fn start_current_document_agent(
    socket: &Path,
    document_id: &'static str,
    name: &'static str,
) -> JoinHandle<()> {
    let socket = socket.to_path_buf();
    start_agent(socket, move |stream| {
        expect_handshake(&stream);
        send_response(&stream, handshake_response());
        let request = read_request(&stream);
        assert_eq!(request, AgentRequest::CurrentDocument);
        send_response(
            &stream,
            AgentResponse::CurrentDocument {
                document_id: document_id.to_string(),
                name: name.to_string(),
            },
        );
    })
}

fn start_procedure_agent(socket: &Path) -> JoinHandle<()> {
    let socket = socket.to_path_buf();
    start_agent(socket, move |stream| {
        expect_handshake(&stream);
        send_response(&stream, handshake_response());
        let request = read_request(&stream);
        assert_eq!(
            request,
            AgentRequest::ListProcedures {
                max_results: Some(10)
            }
        );
        send_response(
            &stream,
            AgentResponse::Procedures {
                procedures: private_procedures(),
                truncated: false,
            },
        );
    })
}

fn start_status_agent(
    socket: &Path,
    backend_mode: hopper_wire::BackendMode,
    readiness: hopper_wire::ReadinessState,
) -> JoinHandle<()> {
    let socket = socket.to_path_buf();
    start_agent(socket, move |stream| {
        expect_handshake(&stream);
        send_response(&stream, handshake_response());
        let request = read_request(&stream);
        assert_eq!(request, AgentRequest::Status);
        send_response(&stream, status_response(backend_mode, readiness));
    })
}

fn start_document_and_procedure_agent(
    socket: &Path,
    procedures: Vec<hopper_wire::WireProcedure>,
) -> JoinHandle<()> {
    let socket = socket.to_path_buf();
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        expect_handshake(&stream);
        send_response(&stream, handshake_response());
        let request = read_request(&stream);
        assert_eq!(request, AgentRequest::CurrentDocument);
        send_response(
            &stream,
            AgentResponse::CurrentDocument {
                document_id: "doc-private".to_string(),
                name: "PrivateDoc".to_string(),
            },
        );

        let (stream, _) = listener.accept().unwrap();
        expect_handshake(&stream);
        send_response(&stream, handshake_response());
        let request = read_request(&stream);
        assert_eq!(
            request,
            AgentRequest::ListProcedures {
                max_results: Some(50_000)
            }
        );
        send_response(
            &stream,
            AgentResponse::Procedures {
                procedures,
                truncated: false,
            },
        );
    })
}

fn private_procedures() -> Vec<hopper_wire::WireProcedure> {
    vec![hopper_wire::WireProcedure {
        addr: "0x1000".to_string(),
        name: Some("private_main".to_string()),
        size: Some(64),
    }]
}

fn start_agent(
    socket: PathBuf,
    handler: impl FnOnce(UnixStream) + Send + 'static,
) -> JoinHandle<()> {
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handler(stream);
    })
}

fn expect_handshake(stream: &UnixStream) {
    match read_request(stream) {
        AgentRequest::Handshake(request) => {
            assert_eq!(request.wire_version, WIRE_VERSION);
            assert!(!request.daemon_version.is_empty());
        }
        other => panic!("expected handshake, got {other:?}"),
    }
}

fn read_request(stream: &UnixStream) -> AgentRequest {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn send_response(mut stream: &UnixStream, response: AgentResponse) {
    let text = serde_json::to_string(&response).unwrap();
    writeln!(stream, "{text}").unwrap();
    stream.flush().unwrap();
}

fn handshake_response() -> AgentResponse {
    handshake_response_with_capabilities(AgentCapabilities {
        current_document: true,
        procedures: true,
        writes: false,
        private_api: false,
        injected: false,
        status: true,
    })
}

fn handshake_response_with_capabilities(capabilities: AgentCapabilities) -> AgentResponse {
    AgentResponse::Handshake(HandshakeResponse {
        accepted: true,
        wire_version: WIRE_VERSION,
        agent_version: "test-agent".to_string(),
        hopper_version: Some("6.test".to_string()),
        capabilities,
        unsupported_reason: None,
    })
}

fn status_response(
    backend_mode: hopper_wire::BackendMode,
    readiness: hopper_wire::ReadinessState,
) -> AgentResponse {
    AgentResponse::Status(hopper_wire::AgentStatus {
        backend_mode,
        readiness,
        hopper_version: Some("6.test".to_string()),
        hopper_build: Some("build.test".to_string()),
        capabilities: hopper_wire::AgentCapabilities {
            current_document: true,
            procedures: true,
            writes: false,
            private_api: true,
            injected: true,
            status: true,
        },
        unsupported_reason: None,
    })
}

fn rpc(daemon: &mut Daemon, method: &str, params: Value) -> Value {
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: method.to_string(),
            params: Some(params),
        })
        .expect("request response");
    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    response.result.expect("result")
}

fn call(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    let result = rpc(
        daemon,
        "tools/call",
        json!({ "name": name, "arguments": arguments }),
    );
    result
        .get("structuredContent")
        .expect("missing structuredContent")
        .clone()
}

fn tool_error(
    daemon: &mut Daemon,
    name: &str,
    arguments: Value,
) -> hopper_mcpd::protocol::JsonRpcError {
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({ "name": name, "arguments": arguments })),
        })
        .unwrap();
    response.error.expect("expected error")
}
