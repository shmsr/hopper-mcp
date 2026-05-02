use assert_cmd::Command;
use hopper_wire::{
    AgentCapabilities, AgentRequest, AgentResponse, AgentStatus, BackendMode, HandshakeResponse,
    ReadinessState, WIRE_VERSION, encode,
};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;
use tempfile::tempdir;

#[test]
fn doctor_json_passes_with_optional_missing_hopper() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let missing_hopper = temp.path().join("Missing Hopper.app");

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--hopper-app",
            missing_hopper.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "storeWritable", "pass");
    assert_check(&report, "nodeAvailable", "pass");
    assert_check(&report, "liveBridgeScript", "pass");
    assert_check(&report, "hopperInstalled", "warn");
}

#[test]
fn doctor_json_fails_when_required_hopper_is_missing() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let missing_hopper = temp.path().join("Missing Hopper.app");

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--require-hopper",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--hopper-app",
            missing_hopper.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "hopperInstalled", "fail");
}

#[test]
fn doctor_json_fails_when_store_parent_is_missing() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("missing-dir").join("store.json");

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "storeWritable", "fail");
}

#[test]
fn doctor_json_fails_when_configured_private_agent_socket_is_missing() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let missing_socket = temp.path().join("missing-agent.sock");

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--private-agent-socket",
            missing_socket.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateAgentSocket", "fail");
}

#[test]
fn doctor_json_warns_when_git_worktree_is_dirty() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let git = temp.path().join("git");
    write_executable(
        &git,
        "#!/bin/sh\nif [ \"$1\" = \"status\" ] && [ \"$2\" = \"--porcelain\" ]; then\n  printf ' M README.md\\n'\n  exit 0\nfi\nexit 1\n",
    );

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--git-command",
            git.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "gitTreeClean", "warn");
}

#[test]
fn doctor_json_fails_when_clean_git_tree_is_required_but_dirty() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let git = temp.path().join("git");
    write_executable(
        &git,
        "#!/bin/sh\nif [ \"$1\" = \"status\" ] && [ \"$2\" = \"--porcelain\" ]; then\n  printf ' M README.md\\n'\n  exit 0\nfi\nexit 1\n",
    );

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--require-clean-git-tree",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--git-command",
            git.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "gitTreeClean", "fail");
}

#[test]
fn doctor_json_passes_when_clean_git_tree_is_required_and_clean() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let git = temp.path().join("git");
    write_executable(
        &git,
        "#!/bin/sh\nif [ \"$1\" = \"status\" ] && [ \"$2\" = \"--porcelain\" ]; then\n  exit 0\nfi\nexit 1\n",
    );

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--require-clean-git-tree",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--git-command",
            git.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "gitTreeClean", "pass");
}

#[test]
fn doctor_json_warns_when_no_codesigning_identity_is_available() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let security = temp.path().join("security");
    fs::write(&security, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&security).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&security, perms).unwrap();

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--security-command",
            security.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "codesignIdentity", "warn");
    assert_check_remediation_contains(
        &report,
        "codesignIdentity",
        "security find-identity -p codesigning -v",
    );
}

#[test]
fn doctor_json_fails_when_plugin_identity_is_required_but_missing() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let security = temp.path().join("security");
    fs::write(&security, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&security).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&security, perms).unwrap();

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--require-plugin-identity",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--security-command",
            security.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "codesignIdentity", "fail");
    assert_check_remediation_contains(
        &report,
        "codesignIdentity",
        "security find-identity -p codesigning -v",
    );
}

#[test]
fn doctor_json_warns_when_no_developer_id_identity_is_available_for_distribution() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let security = temp.path().join("security");
    fs::write(
        &security,
        "#!/bin/sh\nprintf '  1) ABCDEF1234567890 \"Apple Development: Example Corp (TEAM1234)\"\\n'\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&security).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&security, perms).unwrap();

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--security-command",
            security.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "codesignIdentity", "pass");
    assert_check(&report, "distributionIdentity", "warn");
    assert_check_remediation_contains(
        &report,
        "distributionIdentity",
        "HOPPER_MCP_CODESIGN_IDENTITY",
    );
}

#[test]
fn doctor_json_fails_when_distribution_identity_is_required_but_missing() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let security = temp.path().join("security");
    fs::write(
        &security,
        "#!/bin/sh\nprintf '  1) ABCDEF1234567890 \"Apple Development: Example Corp (TEAM1234)\"\\n'\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&security).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&security, perms).unwrap();

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .args([
            "doctor",
            "--json",
            "--require-distribution-identity",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
            "--security-command",
            security.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "distributionIdentity", "fail");
    assert_check_remediation_contains(&report, "distributionIdentity", "Developer ID Application");
}

#[test]
fn doctor_json_fails_when_notary_credentials_are_required_but_missing() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .env_remove("HOPPER_MCP_NOTARY_PROFILE")
        .env_remove("APPLE_ID")
        .env_remove("APPLE_TEAM_ID")
        .env_remove("APPLE_PASSWORD")
        .args([
            "doctor",
            "--json",
            "--require-notary-credentials",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "notaryCredentials", "fail");
    assert_check_remediation_contains(&report, "notaryCredentials", "HOPPER_MCP_NOTARY_PROFILE");
}

#[test]
fn doctor_json_passes_when_notary_profile_is_configured() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");

    let output = Command::cargo_bin("hopper-mcpd")
        .unwrap()
        .env("HOPPER_MCP_NOTARY_PROFILE", "ci-profile")
        .env_remove("APPLE_ID")
        .env_remove("APPLE_TEAM_ID")
        .env_remove("APPLE_PASSWORD")
        .args([
            "doctor",
            "--json",
            "--store",
            store.to_str().unwrap(),
            "--node-command",
            "/bin/sh",
            "--live-bridge-script",
            bridge.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "notaryCredentials", "pass");
}

#[test]
fn doctor_json_passes_when_private_host_is_required_with_detected_sip_disabled() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let csrutil = temp.path().join("csrutil");
    write_executable(
        &csrutil,
        "#!/bin/sh\nprintf 'System Integrity Protection status: disabled.\\n'\n",
    );

    let output = doctor_command(&store, &bridge)
        .env_remove("HOPPER_MCP_ASSUME_SIP_DISABLED")
        .env("HOPPER_MCP_CSRUTIL", csrutil.to_str().unwrap())
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args(["--require-hopper", "--require-private-host"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "hopperInstalled", "pass");
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "warn");
}

#[test]
fn doctor_json_fails_when_private_backend_is_required_without_host_opt_in_or_socket() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let csrutil = temp.path().join("csrutil");
    write_executable(
        &csrutil,
        "#!/bin/sh\nprintf 'System Integrity Protection status: enabled.\\n'\n",
    );

    let output = doctor_command(&store, &bridge)
        .env_remove("HOPPER_MCP_ASSUME_SIP_DISABLED")
        .env("HOPPER_MCP_CSRUTIL", csrutil.to_str().unwrap())
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args(["--require-private-backend"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateBackendReady", "fail");
    assert_check(&report, "privateAgentSocket", "fail");
}

#[test]
fn doctor_json_fails_when_private_backend_is_required_with_detected_sip_disabled_but_missing_socket()
 {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let csrutil = temp.path().join("csrutil");
    write_executable(
        &csrutil,
        "#!/bin/sh\nprintf 'System Integrity Protection status: disabled.\\n'\n",
    );

    let output = doctor_command(&store, &bridge)
        .env_remove("HOPPER_MCP_ASSUME_SIP_DISABLED")
        .env("HOPPER_MCP_CSRUTIL", csrutil.to_str().unwrap())
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args(["--require-private-backend"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "fail");
}

#[test]
fn doctor_json_fails_when_private_backend_is_required_with_host_opt_in_but_missing_socket() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");

    let output = doctor_command(&store, &bridge)
        .env("HOPPER_MCP_ASSUME_SIP_DISABLED", "1")
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args(["--require-private-backend"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "fail");
}

#[test]
fn doctor_json_passes_when_private_backend_is_required_with_host_opt_in_and_ready_socket() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let socket = temp.path().join("hopper-agent.sock");
    let server = spawn_ready_private_backend(&socket);

    let output = doctor_command(&store, &bridge)
        .env("HOPPER_MCP_ASSUME_SIP_DISABLED", "1")
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args([
            "--require-private-backend",
            "--private-agent-socket",
            socket.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    server.join().unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "pass");
}

#[test]
fn doctor_json_fails_when_private_backend_is_required_with_host_opt_in_and_no_document_socket() {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let socket = temp.path().join("hopper-agent.sock");
    let server = spawn_backend(
        &socket,
        BackendMode::InjectedPrivate,
        true,
        ReadinessState::NoDocument,
    );

    let output = doctor_command(&store, &bridge)
        .env("HOPPER_MCP_ASSUME_SIP_DISABLED", "1")
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args([
            "--require-private-backend",
            "--private-agent-socket",
            socket.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    server.join().unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "fail");
}

#[test]
fn doctor_json_fails_when_private_backend_is_required_with_host_opt_in_and_ready_non_private_socket()
 {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let socket = temp.path().join("hopper-agent.sock");
    let server = spawn_ready_backend(&socket, BackendMode::OfficialMcp, false);

    let output = doctor_command(&store, &bridge)
        .env("HOPPER_MCP_ASSUME_SIP_DISABLED", "1")
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args([
            "--require-private-backend",
            "--private-agent-socket",
            socket.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    server.join().unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "fail");
}

#[test]
fn doctor_json_fails_when_private_backend_is_required_with_host_opt_in_and_legacy_handshake_only_agent()
 {
    let temp = tempdir().unwrap();
    let bridge = temp.path().join("live-bridge-cli.js");
    fs::write(&bridge, "#!/usr/bin/env node\n").unwrap();
    let store = temp.path().join("store.json");
    let socket = temp.path().join("hopper-agent.sock");
    let server = spawn_legacy_handshake_backend(&socket);

    let output = doctor_command(&store, &bridge)
        .env("HOPPER_MCP_ASSUME_SIP_DISABLED", "1")
        .env_remove("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
        .args([
            "--require-private-backend",
            "--private-agent-socket",
            socket.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    server.join().unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_check(&report, "privateBackendReady", "pass");
    assert_check(&report, "privateAgentSocket", "fail");
}

fn doctor_command(store: &std::path::Path, bridge: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("hopper-mcpd").unwrap();
    command.args([
        "doctor",
        "--json",
        "--store",
        store.to_str().unwrap(),
        "--node-command",
        "/bin/sh",
        "--live-bridge-script",
        bridge.to_str().unwrap(),
    ]);
    command
}

fn spawn_ready_private_backend(socket: &std::path::Path) -> thread::JoinHandle<()> {
    spawn_backend(
        socket,
        BackendMode::InjectedPrivate,
        true,
        ReadinessState::Ready,
    )
}

fn spawn_ready_backend(
    socket: &std::path::Path,
    backend_mode: BackendMode,
    injected: bool,
) -> thread::JoinHandle<()> {
    spawn_backend(socket, backend_mode, injected, ReadinessState::Ready)
}

fn spawn_legacy_handshake_backend(socket: &std::path::Path) -> thread::JoinHandle<()> {
    let socket = socket.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket).unwrap();
        ready_tx.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let reader_stream = stream.try_clone().unwrap();
        let mut reader = BufReader::new(reader_stream);

        let handshake = read_request(&mut reader);
        assert!(matches!(handshake, AgentRequest::Handshake(_)));
        write_response(
            &mut stream,
            AgentResponse::Handshake(HandshakeResponse {
                accepted: true,
                wire_version: WIRE_VERSION,
                agent_version: "test-agent".to_string(),
                hopper_version: Some("5.0".to_string()),
                capabilities: AgentCapabilities {
                    status: false,
                    private_api: true,
                    injected: true,
                    ..AgentCapabilities::default()
                },
                unsupported_reason: None,
            }),
        );
    });
    ready_rx.recv().unwrap();
    handle
}

fn spawn_backend(
    socket: &std::path::Path,
    backend_mode: BackendMode,
    injected: bool,
    readiness: ReadinessState,
) -> thread::JoinHandle<()> {
    let socket = socket.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket).unwrap();
        ready_tx.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let reader_stream = stream.try_clone().unwrap();
        let mut reader = BufReader::new(reader_stream);

        let handshake = read_request(&mut reader);
        assert!(matches!(handshake, AgentRequest::Handshake(_)));
        write_response(
            &mut stream,
            AgentResponse::Handshake(HandshakeResponse {
                accepted: true,
                wire_version: WIRE_VERSION,
                agent_version: "test-agent".to_string(),
                hopper_version: Some("5.0".to_string()),
                capabilities: AgentCapabilities {
                    status: true,
                    private_api: true,
                    injected,
                    ..AgentCapabilities::default()
                },
                unsupported_reason: None,
            }),
        );

        let status = read_request(&mut reader);
        assert!(matches!(status, AgentRequest::Status));
        write_response(
            &mut stream,
            AgentResponse::Status(AgentStatus {
                backend_mode,
                readiness,
                hopper_version: Some("5.0".to_string()),
                hopper_build: Some("1234".to_string()),
                capabilities: AgentCapabilities {
                    status: true,
                    private_api: true,
                    injected,
                    ..AgentCapabilities::default()
                },
                unsupported_reason: None,
            }),
        );
    });
    ready_rx.recv().unwrap();
    handle
}

fn read_request(reader: &mut BufReader<std::os::unix::net::UnixStream>) -> AgentRequest {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn write_response(stream: &mut std::os::unix::net::UnixStream, response: AgentResponse) {
    let text = encode(&response).unwrap();
    stream.write_all(text.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

fn write_executable(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

fn assert_check(report: &Value, name: &str, status: &str) {
    let checks = report["checks"].as_array().unwrap();
    let check = checks
        .iter()
        .find(|check| check["name"] == name)
        .unwrap_or_else(|| panic!("missing check {name}: {report}"));
    assert_eq!(check["status"], status);
}

fn assert_check_remediation_contains(report: &Value, name: &str, needle: &str) {
    let checks = report["checks"].as_array().unwrap();
    let check = checks
        .iter()
        .find(|check| check["name"] == name)
        .unwrap_or_else(|| panic!("missing check {name}: {report}"));
    let remediation = check["remediation"]
        .as_str()
        .unwrap_or_else(|| panic!("missing remediation for {name}: {report}"));
    assert!(
        remediation.contains(needle),
        "remediation for {name} did not contain {needle:?}: {remediation}"
    );
}
