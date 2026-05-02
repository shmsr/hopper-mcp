use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

#[test]
fn initializes_and_hides_local_fallback_tools() {
    let mut daemon = Daemon::new();
    let init = rpc(&mut daemon, "initialize", json!({}));
    assert_eq!(init["protocolVersion"], "2025-11-25");

    let tools = rpc(&mut daemon, "tools/list", json!({}));
    let names: Vec<_> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();

    for expected in [
        "open_session",
        "list",
        "search",
        "resolve",
        "procedure",
        "xrefs",
        "containing_function",
        "get_graph_slice",
        "analyze_function_deep",
        "compute_fingerprints",
        "find_similar_functions",
        "diff_sessions",
        "query",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
    for removed in [
        "import_macho",
        "disassemble_range",
        "find_xrefs",
        "find_functions",
    ] {
        assert!(!names.contains(&removed), "{removed} must not be exposed");
    }
}

#[test]
fn exposes_agent_level_analysis_tools() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({ "session": sample_session() }),
    );
    call(
        &mut daemon,
        "open_session",
        json!({ "session": second_session() }),
    );

    let graph = call(
        &mut daemon,
        "get_graph_slice",
        json!({ "seed": "_main", "kind": "callees", "radius": 1, "session_id": "sample" }),
    );
    assert_eq!(graph["seed"], "0x100004120");
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 2);

    let deep = call(
        &mut daemon,
        "analyze_function_deep",
        json!({ "addr": "0x100003f50", "session_id": "sample" }),
    );
    assert_eq!(deep["provenance"]["source"], "hopper-snapshot");
    assert_eq!(
        deep["graph"]["callers"].as_array().unwrap()[0]["known"],
        true
    );

    let fingerprints = call(
        &mut daemon,
        "compute_fingerprints",
        json!({ "session_id": "sample" }),
    );
    assert_eq!(fingerprints["updated"], 3);
    assert!(fingerprints["fingerprints"]["0x100003f50"]["imphash"].is_string());

    let similar = call(
        &mut daemon,
        "find_similar_functions",
        json!({
            "addr": "0x100003f50",
            "session_id": "sample",
            "target_session_id": "sample-copy",
            "min_similarity": 0.4
        }),
    );
    assert_eq!(
        similar["matches"].as_array().unwrap()[0]["addr"],
        "0x100003f50"
    );

    let diff = call(
        &mut daemon,
        "diff_sessions",
        json!({ "left_session_id": "sample", "right_session_id": "sample-copy" }),
    );
    assert_eq!(diff["summary"]["functionsAdded"], 1);

    let query = call(
        &mut daemon,
        "query",
        json!({ "expression": "imports:_ptrace", "session_id": "sample" }),
    );
    assert_eq!(query["count"], 1);
    assert_eq!(query["matches"].as_array().unwrap()[0]["name"], "_main");
}

#[test]
fn opens_snapshot_and_answers_core_read_tools() {
    let mut daemon = Daemon::new();
    let opened = call(
        &mut daemon,
        "open_session",
        json!({ "session": sample_session() }),
    );
    assert_eq!(opened["sessionId"], "sample");
    assert_eq!(opened["counts"]["functions"], 3);

    let procedures = call(&mut daemon, "list", json!({ "kind": "procedures" }));
    assert_eq!(procedures["0x100004120"]["name"], "_main");

    let strings = call(
        &mut daemon,
        "search",
        json!({ "kind": "strings", "pattern": "license" }),
    );
    assert_eq!(strings["0x100008000"], "license_key");

    let resolved = call(&mut daemon, "resolve", json!({ "query": "_main" }));
    assert_eq!(resolved.as_array().unwrap()[0]["kind"], "function");

    let info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100003f50" }),
    );
    assert_eq!(info["name"], "sub_100003f50");
    assert_eq!(info["basicBlockCount"], 2);

    let callees = call(
        &mut daemon,
        "procedure",
        json!({ "field": "callees", "procedure": "_main" }),
    );
    assert_eq!(callees.as_array().unwrap()[0], "0x100003f50");

    let xrefs = call(&mut daemon, "xrefs", json!({ "address": "0x100003f50" }));
    assert_eq!(xrefs.as_array().unwrap()[0]["from"], "0x100004120");

    let containing = call(
        &mut daemon,
        "containing_function",
        json!({ "address": "0x100003f70" }),
    );
    assert_eq!(containing["match"], "containment");
    assert_eq!(containing["offset"], 0x20);
}

#[test]
fn rejects_unknown_tool_arguments() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({ "session": sample_session() }),
    );
    let err = tool_error(
        &mut daemon,
        "list",
        json!({ "kind": "procedures", "typo": true }),
    );
    assert!(err.contains("Unrecognized key: typo"), "{err}");
}

fn rpc(daemon: &mut Daemon, method: &str, params: Value) -> Value {
    let request = JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: method.to_string(),
        params: Some(params),
    };
    let response = daemon
        .handle(request)
        .expect("notification returned no response");
    if let Some(error) = response.error {
        panic!("rpc error: {}", error.message);
    }
    response.result.expect("missing result")
}

fn call(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    let result = rpc(
        daemon,
        "tools/call",
        json!({ "name": name, "arguments": arguments }),
    );
    let structured = result
        .get("structuredContent")
        .expect("missing structuredContent");
    structured.clone()
}

fn tool_error(daemon: &mut Daemon, name: &str, arguments: Value) -> String {
    let request = JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": name, "arguments": arguments })),
    };
    let response = daemon.handle(request).unwrap();
    response.error.expect("expected error").message
}

fn sample_session() -> Value {
    json!({
        "sessionId": "sample",
        "binaryId": "sample-macho",
        "binary": {
            "name": "SampleMachO",
            "format": "Mach-O",
            "arch": "arm64",
            "baseAddress": "0x100000000",
            "segments": [
                { "name": "__TEXT", "start": "0x100000000", "length": 32768, "executable": true }
            ]
        },
        "imports": ["_SecItemCopyMatching", "_CC_SHA256", "_ptrace"],
        "exports": ["_main"],
        "strings": [
            { "addr": "0x100008000", "value": "license_key" },
            { "addr": "0x100008020", "value": "debugger detected" }
        ],
        "names": [
            { "addr": "0x100003f50", "name": "sub_100003f50", "demangled": null },
            { "addr": "0x100004120", "name": "_main", "demangled": null }
        ],
        "cursor": { "address": "0x100003f50", "procedure": "0x100003f50", "selection": [] },
        "functions": [
            {
                "addr": "0x100003f50",
                "name": "sub_100003f50",
                "size": 192,
                "summary": "Checks local license material.",
                "callers": ["0x100004120"],
                "callees": ["0x100004010"],
                "strings": ["license_key"],
                "imports": ["_SecItemCopyMatching", "_CC_SHA256"],
                "pseudocode": "return validate_license();",
                "basicBlocks": [
                    { "addr": "0x100003f50", "summary": "Load keychain query." },
                    { "addr": "0x100003fa8", "summary": "Hash candidate bytes." }
                ]
            },
            {
                "addr": "0x100004010",
                "name": "sub_100004010",
                "size": 80,
                "callers": ["0x100003f50"],
                "callees": [],
                "basicBlocks": [{ "addr": "0x100004010", "summary": "Compare digest." }]
            },
            {
                "addr": "0x100004120",
                "name": "_main",
                "size": 144,
                "callers": [],
                "callees": ["0x100003f50"],
                "strings": ["debugger detected"],
                "imports": ["_ptrace"],
                "basicBlocks": [{ "addr": "0x100004120", "summary": "Entry point." }]
            }
        ]
    })
}

fn second_session() -> Value {
    let mut session = sample_session();
    session["sessionId"] = json!("sample-copy");
    session["functions"].as_array_mut().unwrap().push(json!({
        "addr": "0x100005000",
        "name": "extra_network_fn",
        "size": 64,
        "summary": "Additional function only in the right snapshot.",
        "callers": [],
        "callees": [],
        "strings": ["https://api.example.invalid/auth"],
        "imports": [],
        "basicBlocks": [{ "addr": "0x100005000", "summary": "Extra block." }]
    }));
    session
}
