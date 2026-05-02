mod fixtures;

use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

const PENDING_TRANSACTIONS_URI: &str = "hopper://transactions/pending";

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

fn resource(daemon: &mut Daemon, uri: &str) -> Value {
    let response = daemon
        .handle(JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(json!(1)),
            method: "resources/read".to_string(),
            params: Some(json!({ "uri": uri })),
        })
        .unwrap();
    assert!(
        response.error.is_none(),
        "unexpected error: {:?}",
        response.error
    );
    let text = response.result.unwrap()["contents"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    serde_json::from_str(&text).unwrap()
}

fn open_sample(daemon: &mut Daemon) {
    call(
        daemon,
        "open_session",
        json!({ "session": fixtures::sample_session() }),
    );
}

fn begin(daemon: &mut Daemon, name: &str) -> String {
    let txn = call(daemon, "begin_transaction", json!({ "name": name }));
    txn["transactionId"].as_str().unwrap().to_string()
}

#[test]
fn local_rename_transaction_previews_and_commits() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "rename main");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "main_entry"
        }),
    );
    let preview = call(
        &mut daemon,
        "preview_transaction",
        json!({ "transaction_id": transaction_id }),
    );
    assert_eq!(preview["operations"][0]["kind"], "rename");
    let committed = call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": transaction_id }),
    );
    assert_eq!(committed["applied"], true);
    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120" }),
    );
    assert_eq!(proc_info["name"], "main_entry");
}

#[test]
fn failed_commit_is_atomic_and_transaction_remains_open() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "partially invalid");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "renamed_before_failure"
        }),
    );
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0xdeadbeef",
            "value": "missing_function"
        }),
    );

    let error = tool_error(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": transaction_id }),
    );
    assert!(error.contains("Unknown procedure address"));

    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120" }),
    );
    assert_eq!(proc_info["name"], "_main");
    let preview = call(
        &mut daemon,
        "preview_transaction",
        json!({ "transaction_id": transaction_id }),
    );
    assert_eq!(preview["status"], "open");
}

#[test]
fn transaction_commits_against_session_bound_at_begin() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "rename sample");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "sample_main"
        }),
    );

    let mut second = fixtures::sample_session();
    second.session_id = "second".to_string();
    call(&mut daemon, "open_session", json!({ "session": second }));
    call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": transaction_id }),
    );

    let sample_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120", "session_id": "sample" }),
    );
    let second_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120", "session_id": "second" }),
    );
    assert_eq!(sample_info["name"], "sample_main");
    assert_eq!(second_info["name"], "_main");
}

#[test]
fn transaction_rejects_same_session_id_replacement_before_commit() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "rename original sample");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "queued_main"
        }),
    );

    let mut replacement = fixtures::sample_session();
    replacement.functions.get_mut("0x100004120").unwrap().name =
        Some("replacement_main".to_string());
    call(
        &mut daemon,
        "open_session",
        json!({ "session": replacement, "overwrite": true }),
    );

    let preview_error = tool_error(
        &mut daemon,
        "preview_transaction",
        json!({ "transaction_id": transaction_id }),
    );
    assert!(preview_error.contains("session generation changed"));

    let queue_error = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "comment",
            "addr": "0x100004120",
            "value": "too late"
        }),
    );
    assert!(queue_error.contains("session generation changed"));

    let commit_error = tool_error(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": transaction_id }),
    );
    assert!(commit_error.contains("session generation changed"));

    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120", "session_id": "sample" }),
    );
    assert_eq!(proc_info["name"], "replacement_main");
}

#[test]
fn stale_parallel_transaction_cannot_commit_after_session_mutates() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let first = begin(&mut daemon, "first rename");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": first,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "first_main"
        }),
    );
    let second = begin(&mut daemon, "second rename");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": second,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "second_main"
        }),
    );

    call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": first }),
    );
    let commit_error = tool_error(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": second }),
    );
    assert!(commit_error.contains("session generation changed"));

    let proc_info = call(
        &mut daemon,
        "procedure",
        json!({ "field": "info", "procedure": "0x100004120" }),
    );
    assert_eq!(proc_info["name"], "first_main");
}

#[test]
fn invalid_rename_and_comment_values_are_rejected() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "validation");

    let empty_rename = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": ""
        }),
    );
    assert!(empty_rename.contains("rename value"));

    let whitespace_rename = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "bad name"
        }),
    );
    assert!(whitespace_rename.contains("whitespace"));

    let long_rename = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "x".repeat(257)
        }),
    );
    assert!(long_rename.contains("256"));

    let nul_comment = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "comment",
            "addr": "0x100004120",
            "value": "bad\u{0}comment"
        }),
    );
    assert!(nul_comment.contains("control"));

    let long_comment = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "inline_comment",
            "addr": "0x100004120",
            "value": "x".repeat(8193)
        }),
    );
    assert!(long_comment.contains("8192"));
}

#[test]
fn terminal_transactions_cannot_be_reused() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let committed_id = begin(&mut daemon, "commit once");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": committed_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "main_once"
        }),
    );
    call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": committed_id }),
    );
    assert!(
        tool_error(
            &mut daemon,
            "commit_transaction",
            json!({ "transaction_id": committed_id })
        )
        .contains("not open")
    );
    assert!(
        tool_error(
            &mut daemon,
            "queue",
            json!({
                "transaction_id": committed_id,
                "kind": "comment",
                "addr": "0x100004120",
                "value": "too late"
            })
        )
        .contains("not open")
    );

    let rolled_back_id = begin(&mut daemon, "rollback once");
    call(
        &mut daemon,
        "rollback_transaction",
        json!({ "transaction_id": rolled_back_id }),
    );
    assert!(
        tool_error(
            &mut daemon,
            "rollback_transaction",
            json!({ "transaction_id": rolled_back_id })
        )
        .contains("not open")
    );
}

#[test]
fn unsupported_kind_and_invalid_address_are_rejected() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "bad queue");
    let unsupported = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "type_patch",
            "addr": "0x100004120",
            "value": "int main()"
        }),
    );
    assert!(unsupported.contains("Unsupported queue kind"));

    let invalid_addr = tool_error(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "comment",
            "addr": "not-an-address",
            "value": "comment"
        }),
    );
    assert!(invalid_addr.contains("numeric address"));
}

#[test]
fn comments_and_inline_comments_are_applied_and_can_be_cleared() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let transaction_id = begin(&mut daemon, "comments");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "comment",
            "addr": "0x100004120",
            "value": "prefix note"
        }),
    );
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": transaction_id,
            "kind": "inline_comment",
            "addr": "0x100004120",
            "value": "inline note"
        }),
    );
    call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": transaction_id }),
    );

    let comments = call(
        &mut daemon,
        "procedure",
        json!({ "field": "comments", "procedure": "0x100004120" }),
    );
    assert_eq!(comments["prefix"]["0x100004120"], "prefix note");
    assert_eq!(comments["inline"]["0x100004120"], "inline note");

    let clear_id = begin(&mut daemon, "clear comments");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": clear_id,
            "kind": "comment",
            "addr": "0x100004120",
            "value": ""
        }),
    );
    call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": clear_id }),
    );
    let comments = call(
        &mut daemon,
        "procedure",
        json!({ "field": "comments", "procedure": "0x100004120" }),
    );
    assert_eq!(comments["prefix"]["0x100004120"], "");
}

#[test]
fn pending_resource_tracks_open_transactions_only() {
    let mut daemon = Daemon::new();
    open_sample(&mut daemon);
    let committed_id = begin(&mut daemon, "commit");
    let rolled_back_id = begin(&mut daemon, "rollback");
    let open_id = begin(&mut daemon, "still open");
    call(
        &mut daemon,
        "queue",
        json!({
            "transaction_id": committed_id,
            "kind": "rename",
            "addr": "0x100004120",
            "value": "pending_check"
        }),
    );
    call(
        &mut daemon,
        "commit_transaction",
        json!({ "transaction_id": committed_id }),
    );
    call(
        &mut daemon,
        "rollback_transaction",
        json!({ "transaction_id": rolled_back_id }),
    );

    let pending = resource(&mut daemon, PENDING_TRANSACTIONS_URI);
    let ids = pending["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|txn| txn["transactionId"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec![open_id]);
}
