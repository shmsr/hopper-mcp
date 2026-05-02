mod fixtures;

use hopper_mcpd::Daemon;
use hopper_mcpd::live::NodeLiveBridge;
use hopper_mcpd::persistence::{load_store, save_store};
use hopper_mcpd::protocol::JsonRpcRequest;
use hopper_mcpd::store::SnapshotStore;
use serde_json::Value;
use serde_json::json;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

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

fn tool_call_result(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
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
        "unexpected JSON-RPC error: {:?}",
        response.error
    );
    response.result.expect("expected tool result")
}

#[test]
fn store_round_trips_through_atomic_json_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    let mut store = SnapshotStore::default();
    store
        .open_session(fixtures::sample_session(), true)
        .unwrap();
    save_store(&path, &store).unwrap();
    let loaded = load_store(&path).unwrap();
    assert_eq!(loaded.current_session_id(), Some("sample"));
    assert_eq!(loaded.function("_main", None).unwrap().addr, "0x100004120");
}

#[test]
fn legacy_store_json_missing_internal_fields_loads_with_defaults() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    fs::write(
        &path,
        serde_json::to_string_pretty(&json!({
            "sessions": {
                "sample": fixtures::sample_session()
            },
            "current_session_id": "sample"
        }))
        .unwrap(),
    )
    .unwrap();

    let mut loaded = load_store(&path).unwrap();

    assert_eq!(loaded.current_session_id(), Some("sample"));
    assert_eq!(loaded.function("_main", None).unwrap().addr, "0x100004120");
    loaded
        .begin_transaction(Some("legacy-compatible".to_string()))
        .unwrap();
}

#[test]
fn daemon_with_store_path_persists_successful_tool_calls() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nested").join("knowledge-store.json");
    {
        let mut daemon = Daemon::with_store_path(&path).unwrap();
        call(
            &mut daemon,
            "open_session",
            json!({ "session": fixtures::sample_session() }),
        );
    }

    let mut daemon = Daemon::with_store_path(&path).unwrap();
    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120" }),
    );

    assert_eq!(proc_info["name"], "_main");
}

#[test]
fn daemon_with_store_path_does_not_persist_read_only_tool_calls() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    let mut daemon = Daemon::with_store_path(&path).unwrap();
    call(
        &mut daemon,
        "open_session",
        json!({ "session": fixtures::sample_session() }),
    );

    let before_bytes = fs::read(&path).unwrap();
    let before_modified = fs::metadata(&path).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(20));

    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120" }),
    );

    let after_bytes = fs::read(&path).unwrap();
    let after_modified = fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(proc_info["name"], "_main");
    assert_eq!(after_bytes, before_bytes);
    assert_eq!(after_modified, before_modified);
}

#[test]
fn daemon_with_store_path_persists_successful_live_ingest() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    {
        let mut daemon =
            Daemon::with_store_path_and_live_bridge(&path, fixture_live_bridge()).unwrap();
        call(
            &mut daemon,
            "ingest_live_hopper",
            json!({ "executable_path": "/bin/echo" }),
        );
    }

    let mut daemon = Daemon::with_store_path(&path).unwrap();
    let current = call(&mut daemon, "list", json!({ "kind": "procedures" }));
    assert_eq!(current, json!({}));
}

#[test]
fn daemon_with_store_path_does_not_persist_failed_live_ingest() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    let mut daemon = Daemon::with_store_path_and_live_bridge(&path, failing_live_bridge()).unwrap();

    let result = tool_call_result(
        &mut daemon,
        "ingest_live_hopper",
        json!({ "executable_path": "/bin/echo" }),
    );

    assert_eq!(result["isError"], true);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Live Hopper ingest failed")),
        "{}",
        result
    );
    assert!(
        !path.exists(),
        "failed live ingest must not create a store file"
    );
}

#[test]
fn daemon_rolls_back_in_memory_state_when_persist_fails() {
    let dir = tempdir().unwrap();
    let blocked_parent = dir.path().join("not-a-directory");
    let path = blocked_parent.join("store.json");
    let mut daemon = Daemon::with_store_path(&path).unwrap();
    fs::write(&blocked_parent, "blocks create_dir_all").unwrap();

    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "open_session",
                "arguments": {
                    "session": fixtures::sample_session()
                }
            })),
        })
        .unwrap();
    assert!(response.error.is_some(), "persist failure must surface");

    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(2)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "list",
                "arguments": { "kind": "procedures" }
            })),
        })
        .unwrap();
    let error = response
        .error
        .expect("rolled-back store has no current session");
    assert!(
        error.message.contains("No current session"),
        "{}",
        error.message
    );
}

fn fixture_live_bridge() -> NodeLiveBridge {
    NodeLiveBridge::new(
        "/bin/sh",
        [
            "-c",
            "cat >/dev/null; printf '%s\n' '{\"session\":{\"sessionId\":\"live-fixture\",\"binary\":{\"name\":\"fixture\",\"format\":\"hopper-live\",\"arch\":\"arm64\"},\"functions\":{}},\"launch\":{\"mode\":\"fixture\"}}'",
        ],
    )
}

fn failing_live_bridge() -> NodeLiveBridge {
    NodeLiveBridge::new(
        "/bin/sh",
        [
            "-c",
            "cat >/dev/null; printf '%s\n' '{\"error\":{\"code\":\"fixture_failed\",\"message\":\"boom\"}}'; exit 1",
        ],
    )
}
