use hopper_mcpd::Daemon;
use hopper_mcpd::live::{LiveBridgeError, LiveIngestRequest, NodeLiveBridge};
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};
use std::fs;
use std::time::{Duration, Instant};
use tempfile::tempdir;

#[test]
fn live_bridge_ingests_fixture_session_json() {
    let bridge = NodeLiveBridge::new(
        "/bin/sh",
        [
            "-c",
            "cat >/dev/null; printf '%s\n' '{\"session\":{\"sessionId\":\"live-fixture\",\"binary\":{\"name\":\"fixture\",\"format\":\"hopper-live\",\"arch\":\"arm64\"},\"functions\":{}},\"launch\":{\"mode\":\"fixture\"}}'",
        ],
    );

    let result = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            ..LiveIngestRequest::default()
        })
        .expect("fixture bridge should ingest");

    assert_eq!(result.session.session_id, "live-fixture");
    assert_eq!(result.launch["mode"], "fixture");
}

#[test]
fn live_bridge_from_root_uses_bundled_script_path() {
    let temp = tempdir().unwrap();
    let bridge_script = temp.path().join("src").join("live-bridge-cli.js");
    fs::create_dir_all(bridge_script.parent().unwrap()).unwrap();
    fs::write(&bridge_script, "#!/usr/bin/env node\n").unwrap();

    let bridge = NodeLiveBridge::from_root(temp.path());
    let diagnostics = bridge.diagnostics();

    assert_eq!(diagnostics["available"], true);
    assert_eq!(diagnostics["command"], "node");
    assert_eq!(
        diagnostics["args"][0].as_str(),
        Some(bridge_script.to_string_lossy().as_ref())
    );
}

#[test]
fn live_bridge_reports_malformed_json() {
    let bridge = NodeLiveBridge::new(
        "/bin/sh",
        ["-c", "cat >/dev/null; printf '%s\n' '{not json}'"],
    );

    let error = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            ..LiveIngestRequest::default()
        })
        .expect_err("malformed bridge JSON must fail");

    assert!(matches!(error, LiveBridgeError::Decode(_)), "{error}");
}

#[test]
fn live_bridge_reports_nonzero_exit() {
    let bridge = NodeLiveBridge::new(
        "/bin/sh",
        ["-c", "cat >/dev/null; printf 'boom' >&2; exit 7"],
    );

    let error = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            ..LiveIngestRequest::default()
        })
        .expect_err("non-zero bridge exit must fail");

    match error {
        LiveBridgeError::Exit { code, stderr, .. } => {
            assert_eq!(code, Some(7));
            assert!(stderr.contains("boom"), "{stderr}");
        }
        other => panic!("expected exit error, got {other}"),
    }
}

#[test]
fn live_bridge_preserves_structured_error_on_nonzero_exit() {
    let bridge = NodeLiveBridge::new(
        "/bin/sh",
        [
            "-c",
            "cat >/dev/null; printf '%s\n' '{\"error\":{\"code\":\"fixture_failed\",\"message\":\"boom\"}}'; exit 1",
        ],
    );

    let error = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            ..LiveIngestRequest::default()
        })
        .expect_err("structured bridge error must fail");

    match error {
        LiveBridgeError::Remote { code, message } => {
            assert_eq!(code, "fixture_failed");
            assert_eq!(message, "boom");
        }
        other => panic!("expected remote bridge error, got {other}"),
    }
}

#[test]
fn live_bridge_reports_timeout() {
    let bridge = NodeLiveBridge::new("/bin/sh", ["-c", "cat >/dev/null; sleep 2"]);
    let started = Instant::now();

    let error = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            timeout_ms: Some(50),
            ..LiveIngestRequest::default()
        })
        .expect_err("timed-out bridge must fail");

    match error {
        LiveBridgeError::Timeout { timeout_ms, .. } => assert_eq!(timeout_ms, 50),
        other => panic!("expected timeout error, got {other}"),
    }
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "timeout should terminate the bridge process group promptly"
    );
}

#[test]
fn live_bridge_drains_large_stdout_without_deadlock() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("large-bridge.mjs");
    fs::write(
        &script,
        r#"
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", () => {
  const filler = "x".repeat(1024 * 1024);
  process.stdout.write(JSON.stringify({
    session: {
      sessionId: "large-fixture",
      binary: { name: "fixture", format: "hopper-live", arch: "arm64" },
      functions: {},
      strings: [{ addr: "0x1000", value: filler }]
    },
    launch: { mode: "large" }
  }) + "\n");
});
"#,
    )
    .unwrap();
    let bridge = NodeLiveBridge::new("node", [script.to_string_lossy().to_string()]);

    let result = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            timeout_ms: Some(2_000),
            ..LiveIngestRequest::default()
        })
        .expect("large bridge stdout should not deadlock");

    assert_eq!(result.session.session_id, "large-fixture");
    assert_eq!(
        result
            .session
            .strings
            .first()
            .map(|value| value.value.len()),
        Some(1024 * 1024)
    );
}

#[test]
fn live_bridge_tails_multibyte_stderr_without_panic() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("unicode-stderr.mjs");
    fs::write(
        &script,
        r#"
process.stdin.resume();
process.stdin.on("end", () => {
  process.stderr.write("€".repeat(1400));
  process.exit(7);
});
"#,
    )
    .unwrap();
    let bridge = NodeLiveBridge::new("node", [script.to_string_lossy().to_string()]);

    let error = bridge
        .ingest(&LiveIngestRequest {
            executable_path: "/bin/echo".to_string(),
            timeout_ms: Some(2_000),
            ..LiveIngestRequest::default()
        })
        .expect_err("non-zero bridge exit must fail without panicking");

    match error {
        LiveBridgeError::Exit { code, stderr, .. } => {
            assert_eq!(code, Some(7));
            assert!(stderr.contains('€'), "{stderr}");
        }
        other => panic!("expected exit error, got {other}"),
    }
}

#[test]
fn daemon_ingest_live_hopper_uses_live_bridge_and_opens_session() {
    let mut daemon = Daemon::with_live_bridge(fixture_bridge());

    let result = rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "ingest_live_hopper",
            "arguments": {
                "executable_path": "/bin/echo",
                "close_after_export": true
            }
        }),
    );
    let content = result["structuredContent"].clone();

    assert_eq!(content["session"]["sessionId"], "live-fixture");
    assert_eq!(content["launch"]["mode"], "fixture");
    assert_eq!(content["diagnostics"]["backend"], "node-live-bridge");
}

#[test]
fn daemon_default_live_bridge_ingests_echo_when_enabled() {
    if std::env::var("HOPPER_MCP_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let target =
        std::env::var("HOPPER_MCP_LIVE_TARGET").unwrap_or_else(|_| "/bin/echo".to_string());
    let mut daemon = Daemon::new();

    let result = rpc(
        &mut daemon,
        "tools/call",
        json!({
            "name": "ingest_live_hopper",
            "arguments": {
                "executable_path": target,
                "timeout_ms": 90000,
                "max_functions": 5,
                "max_strings": 20,
                "close_after_export": true
            }
        }),
    );
    let content = result["structuredContent"].clone();

    assert!(
        content["session"]["sessionId"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(content["diagnostics"]["backend"], "node-live-bridge");
}

fn fixture_bridge() -> NodeLiveBridge {
    NodeLiveBridge::new(
        "/bin/sh",
        [
            "-c",
            "cat >/dev/null; printf '%s\n' '{\"session\":{\"sessionId\":\"live-fixture\",\"binary\":{\"name\":\"fixture\",\"format\":\"hopper-live\",\"arch\":\"arm64\"},\"functions\":{}},\"launch\":{\"mode\":\"fixture\"}}'",
        ],
    )
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
