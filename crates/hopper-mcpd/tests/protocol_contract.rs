use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

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

fn rpc_error(daemon: &mut Daemon, method: &str, params: Value) -> i64 {
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: method.to_string(),
            params: Some(params),
        })
        .expect("request response");
    response.error.expect("expected error").code
}

#[test]
fn initialize_uses_current_protocol_and_declares_capabilities() {
    let mut daemon = Daemon::new();
    let result = rpc(
        &mut daemon,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "contract-test", "version": "0.0.0" }
        }),
    );
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(result["serverInfo"]["name"], "hopper-mcpd");
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["capabilities"]["resources"].is_object());
    assert!(result["capabilities"]["prompts"].is_object());
}

#[test]
fn tool_results_include_text_and_structured_content() {
    let mut daemon = Daemon::new();
    let result = rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "capabilities",
            "arguments": {}
        }),
    );
    assert_eq!(result["content"][0]["type"], "text");
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hopper-mcpd")
    );
    assert_eq!(result["structuredContent"]["server"], "hopper-mcpd");
    assert_eq!(result["isError"], false);
}

#[test]
fn tool_registry_is_strict_and_hides_local_fallbacks() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/list", json!({}));
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    for expected in [
        "capabilities",
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
    for tool in tools {
        assert_eq!(
            tool["inputSchema"]["additionalProperties"], false,
            "tool {} is not strict",
            tool["name"]
        );
    }
    for (tool_name, field_name) in [
        ("list", "max_results"),
        ("search", "max_results"),
        ("resolve", "max_results"),
        ("procedure", "max_lines"),
        ("get_graph_slice", "max_nodes"),
        ("find_similar_functions", "max_results"),
        ("diff_sessions", "max_per_bucket"),
        ("query", "max_results"),
    ] {
        let tool = tools.iter().find(|tool| tool["name"] == tool_name).unwrap();
        let field = &tool["inputSchema"]["properties"][field_name];
        assert_eq!(field["type"], "integer");
        assert_eq!(field["minimum"], 0);
    }
}

#[test]
fn resources_and_prompts_are_exposed() {
    let mut daemon = Daemon::new();
    let resources = rpc(&mut daemon, "resources/list", json!({}));
    let uris: Vec<_> = resources["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"hopper://session/current"));
    assert!(uris.contains(&"hopper://functions"));
    for (uri, name) in [
        ("hopper://session/current", "Current Hopper session"),
        ("hopper://functions", "Functions"),
        ("hopper://strings", "Strings"),
        ("hopper://names", "Names"),
        ("hopper://transactions/pending", "Pending transactions"),
    ] {
        let resource = resources["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["uri"] == uri)
            .unwrap();
        assert_eq!(resource["name"], name);
    }

    let prompts = rpc(&mut daemon, "prompts/list", json!({}));
    let names: Vec<_> = prompts["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"function_triage"));
    assert!(names.contains(&"hypothesis_workspace"));
}

#[test]
fn prompts_get_returns_templates_and_rejects_unknown_names() {
    let mut daemon = Daemon::new();

    let triage = rpc(
        &mut daemon,
        "prompts/get",
        json!({
            "name": "function_triage",
            "arguments": { "addr": "0x100001000" }
        }),
    );
    assert!(triage["description"].as_str().unwrap().contains("function"));
    assert_eq!(triage["messages"][0]["role"], "user");
    assert!(
        triage["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("0x100001000")
    );

    let hypothesis = rpc(
        &mut daemon,
        "prompts/get",
        json!({
            "name": "hypothesis_workspace",
            "arguments": { "topic": "anti-debugging" }
        }),
    );
    assert!(
        hypothesis["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("anti-debugging")
    );

    assert_eq!(
        rpc_error(
            &mut daemon,
            "prompts/get",
            json!({ "name": "unknown_prompt", "arguments": {} }),
        ),
        -32602
    );
}

#[test]
fn listed_resources_are_readable() {
    let mut daemon = Daemon::new();
    rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "open_session",
            "arguments": { "session": limited_session() }
        }),
    );

    let resources = rpc(&mut daemon, "resources/list", json!({}));
    let uris: Vec<_> = resources["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap().to_string())
        .collect();

    for uri in uris {
        let result = rpc(&mut daemon, "resources/read", json!({ "uri": uri }));
        assert_eq!(result["contents"][0]["mimeType"], "application/json");
    }
}

#[test]
fn list_like_resources_are_capped_with_metadata() {
    let mut daemon = Daemon::new();
    rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "open_session",
            "arguments": { "session": large_session(501) }
        }),
    );

    for uri in ["hopper://functions", "hopper://strings", "hopper://names"] {
        let result = rpc(&mut daemon, "resources/read", json!({ "uri": uri }));
        let body: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(body["total"], 501, "{uri}");
        assert_eq!(body["truncated"], true, "{uri}");
        assert_eq!(body["items"].as_array().unwrap().len(), 500, "{uri}");
    }
}

#[test]
fn procedure_max_lines_limits_textual_outputs() {
    let mut daemon = Daemon::new();
    rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "open_session",
            "arguments": { "session": limited_session() }
        }),
    );

    let assembly = tool(
        &mut daemon,
        "procedure",
        json!({ "field": "assembly", "procedure": "_main", "max_lines": 2 }),
    );
    assert_eq!(assembly.as_str().unwrap().lines().count(), 2);

    let callers = tool(
        &mut daemon,
        "procedure",
        json!({ "field": "callers", "procedure": "_main", "max_lines": 1 }),
    );
    assert_eq!(callers.as_array().unwrap().len(), 1);

    let callees = tool(
        &mut daemon,
        "procedure",
        json!({ "field": "callees", "procedure": "_main", "max_lines": 1 }),
    );
    assert_eq!(callees.as_array().unwrap().len(), 1);

    let pseudo_code = tool(
        &mut daemon,
        "procedure",
        json!({ "field": "pseudo_code", "procedure": "_main", "max_lines": 2 }),
    );
    assert_eq!(pseudo_code.as_str().unwrap().lines().count(), 2);
}

#[test]
fn integer_limit_arguments_reject_non_u64_values() {
    let mut daemon = Daemon::new();
    rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "open_session",
            "arguments": { "session": limited_session() }
        }),
    );

    for max_results in [json!(-1), json!(1.5)] {
        assert_eq!(
            rpc_error(
                &mut daemon,
                "tools/call",
                json!({
                    "name": "list",
                    "arguments": { "kind": "procedures", "max_results": max_results }
                }),
            ),
            -32602
        );
    }
}

#[test]
fn explicit_null_id_is_rejected_instead_of_treated_as_notification() {
    let request: JsonRpcRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": null,
        "method": "initialize",
        "params": {}
    }))
    .expect("request parses");
    let mut daemon = Daemon::new();

    let response = daemon.handle(request).expect("null id gets error response");

    let error = response.error.expect("invalid request error");
    assert_eq!(error.code, -32600);
    assert_eq!(response.id, None);
}

fn tool(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    rpc(
        daemon,
        "tools/call",
        json!({ "name": name, "arguments": arguments }),
    )["structuredContent"]
        .clone()
}

fn limited_session() -> Value {
    json!({
        "sessionId": "limits",
        "binaryId": "limits-bin",
        "binary": {
            "name": "Limits",
            "format": "Mach-O",
            "arch": "arm64",
            "baseAddress": "0x100000000",
            "segments": []
        },
        "functions": [
            {
                "addr": "0x100001000",
                "name": "_main",
                "pseudocode": "line 1\nline 2\nline 3",
                "callers": ["0x100000100", "0x100000200"],
                "callees": ["0x100002000", "0x100003000"],
                "basicBlocks": [
                    {
                        "addr": "0x100001000",
                        "summary": "entry",
                        "instructions": ["mov x0, x0", "ret"]
                    }
                ]
            }
        ]
    })
}

fn large_session(count: usize) -> Value {
    let functions: Vec<_> = (0..count)
        .map(|index| {
            json!({
                "addr": format!("0x{:x}", 0x100001000_u64 + index as u64 * 0x10),
                "name": format!("sub_{index}"),
                "basicBlocks": []
            })
        })
        .collect();
    let strings: Vec<_> = (0..count)
        .map(|index| {
            json!({
                "addr": format!("0x{:x}", 0x100008000_u64 + index as u64 * 0x10),
                "value": format!("string_{index}")
            })
        })
        .collect();
    let names: Vec<_> = (0..count)
        .map(|index| {
            json!({
                "addr": format!("0x{:x}", 0x100010000_u64 + index as u64 * 0x10),
                "name": format!("name_{index}"),
                "demangled": null
            })
        })
        .collect();

    json!({
        "sessionId": "large",
        "binaryId": "large-bin",
        "binary": {
            "name": "Large",
            "format": "Mach-O",
            "arch": "arm64",
            "baseAddress": "0x100000000",
            "segments": []
        },
        "functions": functions,
        "strings": strings,
        "names": names
    })
}
