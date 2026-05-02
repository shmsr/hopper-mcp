mod fixtures;

use hopper_mcpd::Daemon;
use hopper_mcpd::address::{format_addr, normalize_addr, parse_addr};
use hopper_mcpd::model::{AddressString, Bookmark, Comment, Function, NameEntry, Session};
use hopper_mcpd::protocol::JsonRpcRequest;
use hopper_mcpd::store::SnapshotStore;
use serde_json::{Value, json};

fn call(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({ "name": name, "arguments": arguments })),
        })
        .unwrap();
    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    response.result.unwrap()["structuredContent"].clone()
}

fn tool_error(daemon: &mut Daemon, name: &str, arguments: Value) -> String {
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({ "name": name, "arguments": arguments })),
        })
        .unwrap();
    response.error.expect("expected error").message
}

#[test]
fn addresses_normalize_to_lowercase_hex() {
    assert_eq!(parse_addr("0x1000").unwrap(), 0x1000);
    assert_eq!(parse_addr("4096").unwrap(), 4096);
    assert_eq!(format_addr(0xABC), "0xabc");
    assert_eq!(normalize_addr("0XABC").unwrap(), "0xabc");
    assert!(parse_addr("not-an-address").is_none());
}

#[test]
fn open_session_sets_current_and_indexes_functions() {
    let mut store = SnapshotStore::default();
    let session = fixtures::sample_session();
    let opened = store.open_session(session, true).expect("open session");
    assert_eq!(opened["sessionId"], "sample");
    assert_eq!(opened["counts"]["functions"], 2);
    assert_eq!(store.current_session_id(), Some("sample"));
    assert_eq!(
        store.function("0x100003f50", None).unwrap().name.as_deref(),
        Some("sub_100003f50")
    );
}

#[test]
fn map_form_functions_can_omit_addr_and_use_map_key() {
    let session: Session = serde_json::from_value(json!({
        "sessionId": "sample",
        "functions": {
            "0X1000": { "name": "main", "size": 16 }
        }
    }))
    .expect("deserialize session");

    let function = session.functions.get("0x1000").expect("function indexed");
    assert_eq!(function.addr, "0x1000");
    assert_eq!(function.name.as_deref(), Some("main"));
}

#[test]
fn hopper_instruction_objects_deserialize_and_render_as_assembly() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({
            "session": {
                "sessionId": "instruction-objects",
                "functions": [
                    {
                        "addr": "0x1000",
                        "name": "_main",
                        "basicBlocks": [
                            {
                                "addr": "0x1000",
                                "summary": "entry",
                                "instructions": [
                                    { "addr": "0x1000", "text": "mov", "args": ["x0", "x0"] },
                                    { "addr": "0x1004", "text": "ret", "args": [] }
                                ]
                            }
                        ]
                    }
                ]
            }
        }),
    );

    let assembly = call(
        &mut daemon,
        "procedure",
        json!({ "field": "assembly", "procedure": "_main" }),
    );
    let assembly = assembly.as_str().unwrap();
    assert!(assembly.contains("0x1000: mov x0, x0"), "{assembly}");
    assert!(assembly.contains("0x1004: ret"), "{assembly}");
}

#[test]
fn open_session_normalizes_all_address_bearing_session_fields() {
    let mut session = fixtures::sample_session();
    session.strings = vec![
        AddressString {
            addr: "0XABC".to_string(),
            value: "upper hex".to_string(),
        },
        AddressString {
            addr: "2748".to_string(),
            value: "decimal".to_string(),
        },
    ];
    session.names = vec![NameEntry {
        addr: "0X100003F50".to_string(),
        name: "sub_100003f50".to_string(),
        demangled: None,
    }];
    session.bookmarks = vec![Bookmark {
        addr: "4294983504".to_string(),
        name: Some("entry".to_string()),
    }];
    session.comments = vec![Comment {
        addr: "0X100004120".to_string(),
        comment: Some("comment".to_string()),
        value: None,
    }];
    session.inline_comments = vec![Comment {
        addr: "4294983504".to_string(),
        comment: None,
        value: Some("inline".to_string()),
    }];
    session.cursor.address = Some("0X100003F50".to_string());
    session.cursor.procedure = Some("0X100004120".to_string());

    let mut store = SnapshotStore::default();
    store.open_session(session, true).expect("open session");
    let current = store.current_session(None).expect("current session");

    assert_eq!(current.strings[0].addr, "0xabc");
    assert_eq!(current.strings[1].addr, "0xabc");
    assert_eq!(current.names[0].addr, "0x100003f50");
    assert_eq!(current.bookmarks[0].addr, "0x100003f50");
    assert_eq!(current.comments[0].addr, "0x100004120");
    assert_eq!(current.inline_comments[0].addr, "0x100003f50");
    assert_eq!(current.cursor.address.as_deref(), Some("0x100003f50"));
    assert_eq!(current.cursor.procedure.as_deref(), Some("0x100004120"));
}

#[test]
fn containing_function_prefers_tightest_range_then_lowest_entry_address() {
    let session = Session {
        session_id: "overlap".to_string(),
        functions: [
            (
                "0x1000".to_string(),
                Function {
                    addr: "0x1000".to_string(),
                    name: Some("wide".to_string()),
                    size: Some(0x100),
                    ..Function::default()
                },
            ),
            (
                "0x1040".to_string(),
                Function {
                    addr: "0x1040".to_string(),
                    name: Some("same_size_higher_start".to_string()),
                    size: Some(0x20),
                    ..Function::default()
                },
            ),
            (
                "0x1050".to_string(),
                Function {
                    addr: "0x1050".to_string(),
                    name: Some("tightest".to_string()),
                    size: Some(0x10),
                    ..Function::default()
                },
            ),
            (
                "0x1038_tie".to_string(),
                Function {
                    addr: "0x1038".to_string(),
                    name: Some("same_size_lower_start".to_string()),
                    size: Some(0x20),
                    ..Function::default()
                },
            ),
        ]
        .into(),
        ..Session::default()
    };

    assert_eq!(
        session.containing_function(0x1054).unwrap().name.as_deref(),
        Some("tightest")
    );
    assert_eq!(
        session.containing_function(0x1048).unwrap().name.as_deref(),
        Some("same_size_lower_start")
    );
}

#[test]
fn read_tools_return_snapshot_data() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({ "session": fixtures::sample_session() }),
    );

    let procedures = call(&mut daemon, "list", json!({ "kind": "procedures" }));
    assert_eq!(procedures["0x100003f50"]["name"], "sub_100003f50");

    let search = call(
        &mut daemon,
        "search",
        json!({ "kind": "procedures", "pattern": "main" }),
    );
    assert_eq!(search["0x100004120"]["name"], "_main");

    let resolved = call(&mut daemon, "resolve", json!({ "query": "_main" }));
    assert_eq!(resolved[0]["addr"], "0x100004120");

    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100003f50" }),
    );
    assert_eq!(proc_info["addr"], "0x100003f50");

    let callers = call(
        &mut daemon,
        "procedure",
        json!({ "field": "callers", "procedure": "0x100003f50" }),
    );
    assert_eq!(callers[0], "0x100004120");
}

#[test]
fn analysis_tools_work_from_snapshot() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({ "session": fixtures::sample_session() }),
    );

    let containing = call(
        &mut daemon,
        "containing_function",
        json!({ "address": "0x100003f60" }),
    );
    assert_eq!(containing["function"]["addr"], "0x100003f50");
    assert_eq!(containing["match"], "containment");

    let graph = call(
        &mut daemon,
        "get_graph_slice",
        json!({ "seed": "_main", "kind": "callees", "radius": 1 }),
    );
    assert_eq!(graph["nodes"][0]["addr"], "0x100004120");

    let graph_from_mid_function = call(
        &mut daemon,
        "get_graph_slice",
        json!({ "seed": "0x100003f60", "kind": "callers", "radius": 1 }),
    );
    assert_eq!(graph_from_mid_function["seed"], "0x100003f50");

    let capped_graph = call(
        &mut daemon,
        "get_graph_slice",
        json!({ "seed": "_main", "kind": "callees", "radius": 2, "max_nodes": 1 }),
    );
    assert_eq!(capped_graph["nodes"].as_array().unwrap().len(), 1);
    assert!(capped_graph["edges"].as_array().unwrap().is_empty());
    assert_eq!(capped_graph["truncated"], true);

    let deep = call(
        &mut daemon,
        "analyze_function_deep",
        json!({ "addr": "0x100003f50" }),
    );
    assert_eq!(deep["function"]["addr"], "0x100003f50");
    assert!(!deep["evidenceAnchors"].as_array().unwrap().is_empty());

    let fingerprints = call(&mut daemon, "compute_fingerprints", json!({}));
    assert_eq!(fingerprints["updated"], 2);
    let stable_hash = fingerprints["fingerprints"]["0x100003f50"]["stableHash"]
        .as_str()
        .expect("stable hash should be returned");
    assert!(!stable_hash.is_empty());
    let fingerprints_again = call(&mut daemon, "compute_fingerprints", json!({}));
    assert_eq!(
        fingerprints_again["fingerprints"]["0x100003f50"]["stableHash"],
        fingerprints["fingerprints"]["0x100003f50"]["stableHash"]
    );

    let query = call(&mut daemon, "query", json!({ "expression": "name:_main" }));
    assert_eq!(query["count"], 1);
}

#[test]
fn fingerprint_hashes_encode_evidence_without_separator_ambiguity() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({
            "session": {
                "sessionId": "ambiguous",
                "functions": {
                    "0x1000": {
                        "name": "left",
                        "imports": ["a,b", "c"],
                        "strings": ["abcd,efgh", "ijkl"]
                    },
                    "0x2000": {
                        "name": "right",
                        "imports": ["a", "b,c"],
                        "strings": ["abcd", "efgh,ijkl"]
                    }
                }
            }
        }),
    );

    let fingerprints = call(&mut daemon, "compute_fingerprints", json!({}));
    assert_ne!(
        fingerprints["fingerprints"]["0x1000"]["imphash"],
        fingerprints["fingerprints"]["0x2000"]["imphash"]
    );
    assert_ne!(
        fingerprints["fingerprints"]["0x1000"]["stringhash"],
        fingerprints["fingerprints"]["0x2000"]["stringhash"]
    );
}

#[test]
fn diff_sessions_reports_function_name_set_changes() {
    let mut daemon = Daemon::new();
    let mut left = fixtures::sample_session();
    left.session_id = "left".to_string();
    call(&mut daemon, "open_session", json!({ "session": left }));

    let mut right = fixtures::sample_session();
    right.session_id = "right".to_string();
    right.functions.insert(
        "0x100005000".to_string(),
        Function {
            addr: "0x100005000".to_string(),
            name: Some("_helper_new".to_string()),
            size: Some(32),
            ..Function::default()
        },
    );
    call(&mut daemon, "open_session", json!({ "session": right }));

    let diff = call(
        &mut daemon,
        "diff_sessions",
        json!({ "left_session_id": "left", "right_session_id": "right" }),
    );

    assert_eq!(diff["summary"]["functionNamesAdded"], 1);
    assert_eq!(diff["summary"]["functionNamesRemoved"], 0);
    assert_eq!(diff["functionNames"]["added"]["items"][0], "_helper_new");
}

#[test]
fn search_rejects_patterns_longer_than_512_bytes() {
    let mut daemon = Daemon::new();
    call(
        &mut daemon,
        "open_session",
        json!({ "session": fixtures::sample_session() }),
    );

    let err = tool_error(
        &mut daemon,
        "search",
        json!({ "kind": "procedures", "pattern": "a".repeat(513) }),
    );

    assert!(err.contains("512 bytes or fewer"), "{err}");
}

#[test]
fn tools_list_schema_exposes_search_pattern_cap() {
    let mut daemon = Daemon::new();
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: "tools/list".to_string(),
            params: Some(json!({})),
        })
        .unwrap();
    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    let result = response.result.unwrap();
    let search = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "search")
        .expect("missing search tool");

    assert_eq!(
        search["inputSchema"]["properties"]["pattern"]["maxLength"],
        512
    );
}
