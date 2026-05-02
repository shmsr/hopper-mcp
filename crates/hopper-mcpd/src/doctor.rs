use crate::backend::{Backend, UnixWireBackend};
use serde::Serialize;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub store_path: PathBuf,
    pub node_command: OsString,
    pub git_command: OsString,
    pub security_command: OsString,
    pub csrutil_command: OsString,
    pub live_bridge_script: PathBuf,
    pub hopper_app: PathBuf,
    pub private_agent_socket: Option<PathBuf>,
    pub require_hopper: bool,
    pub require_plugin_identity: bool,
    pub require_distribution_identity: bool,
    pub require_notary_credentials: bool,
    pub require_clean_git_tree: bool,
    pub require_private_host: bool,
    pub require_private_backend: bool,
}

impl DoctorOptions {
    pub fn from_env() -> Self {
        Self {
            store_path: std::env::var_os("HOPPER_MCP_STORE")
                .map(PathBuf::from)
                .unwrap_or_else(crate::default_store_path),
            node_command: std::env::var_os("HOPPER_MCP_NODE")
                .unwrap_or_else(|| OsString::from("node")),
            git_command: std::env::var_os("HOPPER_MCP_GIT")
                .unwrap_or_else(|| OsString::from("git")),
            security_command: std::env::var_os("HOPPER_MCP_SECURITY")
                .unwrap_or_else(|| OsString::from("security")),
            csrutil_command: std::env::var_os("HOPPER_MCP_CSRUTIL")
                .unwrap_or_else(|| OsString::from("csrutil")),
            live_bridge_script: crate::live::default_bridge_script(),
            hopper_app: default_hopper_app(),
            private_agent_socket: std::env::var_os("HOPPER_MCP_PRIVATE_AGENT_SOCKET")
                .map(PathBuf::from),
            require_hopper: false,
            require_plugin_identity: false,
            require_distribution_identity: false,
            require_notary_credentials: false,
            require_clean_git_tree: false,
            require_private_host: false,
            require_private_backend: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub status: DoctorStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl DoctorReport {
    pub fn new(checks: Vec<DoctorCheck>) -> Self {
        let ok = checks
            .iter()
            .all(|check| check.status != DoctorStatus::Fail);
        Self { ok, checks }
    }
}

pub fn run_doctor(options: &DoctorOptions) -> DoctorReport {
    let git_tree_probe = probe_git_tree(&options.git_command);
    let codesign_probe = probe_codesign_identities(&options.security_command);
    DoctorReport::new(vec![
        check_store_writable(&options.store_path),
        check_node_available(&options.node_command),
        check_live_bridge_script(&options.live_bridge_script),
        check_hopper_installed(&options.hopper_app, options.require_hopper),
        check_git_tree_clean(&git_tree_probe, options.require_clean_git_tree),
        check_codesign_identity(&codesign_probe, options.require_plugin_identity),
        check_distribution_identity(&codesign_probe, options.require_distribution_identity),
        check_notary_credentials(options.require_notary_credentials),
        check_private_backend_ready(
            &options.csrutil_command,
            options.require_private_host || options.require_private_backend,
        ),
        check_private_agent_socket(
            options.private_agent_socket.as_deref(),
            options.require_private_backend,
        ),
    ])
}

pub fn render_text(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str(if report.ok {
        "hopper-mcp doctor: ok\n"
    } else {
        "hopper-mcp doctor: failed\n"
    });
    for check in &report.checks {
        output.push_str(&format!(
            "- {}: {:?}: {}\n",
            check.name, check.status, check.message
        ));
        if let Some(remediation) = &check.remediation {
            output.push_str(&format!("  next: {remediation}\n"));
        }
    }
    output
}

fn check_store_writable(path: &Path) -> DoctorCheck {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        return DoctorCheck {
            name: "storeWritable",
            status: DoctorStatus::Fail,
            message: format!("store parent does not exist: {}", parent.display()),
            remediation: None,
        };
    }
    if !parent.is_dir() {
        return DoctorCheck {
            name: "storeWritable",
            status: DoctorStatus::Fail,
            message: format!("store parent is not a directory: {}", parent.display()),
            remediation: None,
        };
    }

    let probe = parent.join(format!(".hopper-mcp-doctor-{}", std::process::id()));
    let result = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
        .and_then(|mut file| file.write_all(b"ok"));
    let _ = fs::remove_file(&probe);
    match result {
        Ok(()) => DoctorCheck {
            name: "storeWritable",
            status: DoctorStatus::Pass,
            message: format!("store parent is writable: {}", parent.display()),
            remediation: None,
        },
        Err(err) => DoctorCheck {
            name: "storeWritable",
            status: DoctorStatus::Fail,
            message: format!("store parent is not writable: {}: {err}", parent.display()),
            remediation: None,
        },
    }
}

fn check_node_available(command: &OsString) -> DoctorCheck {
    if command_available(command) {
        DoctorCheck {
            name: "nodeAvailable",
            status: DoctorStatus::Pass,
            message: format!("node command is available: {}", command.to_string_lossy()),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "nodeAvailable",
            status: DoctorStatus::Fail,
            message: format!("node command not found: {}", command.to_string_lossy()),
            remediation: None,
        }
    }
}

fn check_live_bridge_script(path: &Path) -> DoctorCheck {
    if path.is_file() {
        DoctorCheck {
            name: "liveBridgeScript",
            status: DoctorStatus::Pass,
            message: format!("live bridge script exists: {}", path.display()),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "liveBridgeScript",
            status: DoctorStatus::Fail,
            message: format!("live bridge script not found: {}", path.display()),
            remediation: None,
        }
    }
}

fn check_hopper_installed(path: &Path, required: bool) -> DoctorCheck {
    if path.exists() {
        return DoctorCheck {
            name: "hopperInstalled",
            status: DoctorStatus::Pass,
            message: format!("Hopper app found: {}", path.display()),
            remediation: None,
        };
    }

    DoctorCheck {
        name: "hopperInstalled",
        status: if required {
            DoctorStatus::Fail
        } else {
            DoctorStatus::Warn
        },
        message: format!("Hopper app not found: {}", path.display()),
        remediation: None,
    }
}

enum CodesignProbe {
    Ready(Vec<String>),
    Failed(String),
}

enum GitTreeProbe {
    Clean,
    Dirty,
    Failed(String),
}

fn probe_git_tree(command: &OsString) -> GitTreeProbe {
    let output = Command::new(command)
        .args(["status", "--porcelain"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let Ok(output) = output else {
        return GitTreeProbe::Failed(format!(
            "git worktree probe could not start: {}",
            command.to_string_lossy()
        ));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return GitTreeProbe::Failed(format!(
            "git worktree probe failed via {}: {}",
            command.to_string_lossy(),
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        ));
    }

    if output.stdout.is_empty() {
        GitTreeProbe::Clean
    } else {
        GitTreeProbe::Dirty
    }
}

fn probe_codesign_identities(command: &OsString) -> CodesignProbe {
    let output = Command::new(command)
        .args(["find-identity", "-p", "codesigning", "-v"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let Ok(output) = output else {
        return CodesignProbe::Failed(format!(
            "codesigning identity probe could not start: {}",
            command.to_string_lossy()
        ));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return CodesignProbe::Failed(format!(
            "codesigning identity probe failed via {}: {}",
            command.to_string_lossy(),
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    CodesignProbe::Ready(parse_codesign_identities(&stdout))
}

fn check_codesign_identity(probe: &CodesignProbe, required: bool) -> DoctorCheck {
    let failure_status = if required {
        DoctorStatus::Fail
    } else {
        DoctorStatus::Warn
    };

    let identities = match probe {
        CodesignProbe::Ready(identities) => identities,
        CodesignProbe::Failed(message) => {
            return DoctorCheck {
                name: "codesignIdentity",
                status: failure_status,
                message: message.clone(),
                remediation: Some(codesign_identity_remediation()),
            };
        }
    };

    if identities.is_empty() {
        return DoctorCheck {
            name: "codesignIdentity",
            status: failure_status,
            message: "no valid Apple codesigning identities found; Hopper Tool Plugin live-loading requires a real Apple developer certificate on macOS 11+".to_string(),
            remediation: Some(codesign_identity_remediation()),
        };
    }

    let developer_id = identities
        .iter()
        .find(|identity| identity.contains("Developer ID Application:"))
        .cloned();
    DoctorCheck {
        name: "codesignIdentity",
        status: DoctorStatus::Pass,
        message: if let Some(identity) = developer_id {
            format!("codesigning identities available; Developer ID found: {identity}")
        } else {
            format!(
                "codesigning identities available ({}); no Developer ID Application identity detected",
                identities.len()
            )
        },
        remediation: None,
    }
}

fn check_git_tree_clean(probe: &GitTreeProbe, required: bool) -> DoctorCheck {
    let failure_status = if required {
        DoctorStatus::Fail
    } else {
        DoctorStatus::Warn
    };

    match probe {
        GitTreeProbe::Clean => DoctorCheck {
            name: "gitTreeClean",
            status: DoctorStatus::Pass,
            message: "git worktree is clean".to_string(),
            remediation: None,
        },
        GitTreeProbe::Dirty => DoctorCheck {
            name: "gitTreeClean",
            status: failure_status,
            message: "git worktree has uncommitted changes; signed distribution packaging requires a clean checkout".to_string(),
            remediation: Some(
                "commit or stash local changes before signed distribution or public-release runs"
                    .to_string(),
            ),
        },
        GitTreeProbe::Failed(message) => DoctorCheck {
            name: "gitTreeClean",
            status: failure_status,
            message: format!(
                "git worktree status could not be determined; signed distribution packaging requires git provenance: {message}"
            ),
            remediation: Some(
                "ensure git is available and the release host is building from a git checkout"
                    .to_string(),
            ),
        },
    }
}

fn check_distribution_identity(probe: &CodesignProbe, required: bool) -> DoctorCheck {
    let failure_status = if required {
        DoctorStatus::Fail
    } else {
        DoctorStatus::Warn
    };

    let identities = match probe {
        CodesignProbe::Ready(identities) => identities,
        CodesignProbe::Failed(message) => {
            return DoctorCheck {
                name: "distributionIdentity",
                status: failure_status,
                message: format!(
                    "{message}; public distribution builds require HOPPER_MCP_CODESIGN_IDENTITY to resolve to a Developer ID Application identity"
                ),
                remediation: Some(distribution_identity_remediation()),
            };
        }
    };

    let developer_id = identities
        .iter()
        .find(|identity| identity.contains("Developer ID Application:"))
        .cloned();
    match developer_id {
        Some(identity) => DoctorCheck {
            name: "distributionIdentity",
            status: DoctorStatus::Pass,
            message: format!(
                "Developer ID Application identity available for public distribution: {identity}"
            ),
            remediation: None,
        },
        None if identities.is_empty() => DoctorCheck {
            name: "distributionIdentity",
            status: failure_status,
            message: "no valid Apple codesigning identities found; public distribution builds require HOPPER_MCP_CODESIGN_IDENTITY to reference a Developer ID Application identity".to_string(),
            remediation: Some(distribution_identity_remediation()),
        },
        None => DoctorCheck {
            name: "distributionIdentity",
            status: failure_status,
            message: format!(
                "codesigning identities available ({}), but no Developer ID Application identity detected; public distribution builds require HOPPER_MCP_CODESIGN_IDENTITY to reference one",
                identities.len()
            ),
            remediation: Some(distribution_identity_remediation()),
        },
    }
}

fn check_notary_credentials(required: bool) -> DoctorCheck {
    let failure_status = if required {
        DoctorStatus::Fail
    } else {
        DoctorStatus::Warn
    };

    if let Some(profile) = non_empty_env("HOPPER_MCP_NOTARY_PROFILE") {
        return DoctorCheck {
            name: "notaryCredentials",
            status: DoctorStatus::Pass,
            message: format!(
                "Apple notary credentials available via HOPPER_MCP_NOTARY_PROFILE: {profile}"
            ),
            remediation: None,
        };
    }

    let apple_id = non_empty_env("APPLE_ID");
    let team_id = non_empty_env("APPLE_TEAM_ID");
    let password = non_empty_env("APPLE_PASSWORD");
    if apple_id.is_some() && team_id.is_some() && password.is_some() {
        return DoctorCheck {
            name: "notaryCredentials",
            status: DoctorStatus::Pass,
            message:
                "Apple notary credentials available via APPLE_ID, APPLE_TEAM_ID, and APPLE_PASSWORD"
                    .to_string(),
            remediation: None,
        };
    }

    DoctorCheck {
        name: "notaryCredentials",
        status: failure_status,
        message: "Apple notarization credentials are not configured; set HOPPER_MCP_NOTARY_PROFILE, or set APPLE_ID, APPLE_TEAM_ID, and APPLE_PASSWORD".to_string(),
        remediation: Some(notary_credentials_remediation()),
    }
}

fn check_private_backend_ready(csrutil_command: &OsString, required: bool) -> DoctorCheck {
    let sip_disabled = std::env::var("HOPPER_MCP_ASSUME_SIP_DISABLED")
        .ok()
        .as_deref()
        == Some("1");
    if sip_disabled {
        return DoctorCheck {
            name: "privateBackendReady",
            status: DoctorStatus::Pass,
            message: "private backend prerequisites explicitly enabled for this host".to_string(),
            remediation: None,
        };
    }

    if probe_sip_disabled(csrutil_command) {
        return DoctorCheck {
            name: "privateBackendReady",
            status: DoctorStatus::Pass,
            message: format!(
                "private backend prerequisites detected on this host: SIP is disabled via {}",
                csrutil_command.to_string_lossy()
            ),
            remediation: None,
        };
    }

    DoctorCheck {
        name: "privateBackendReady",
        status: if required {
            DoctorStatus::Fail
        } else {
            DoctorStatus::Warn
        },
        message: format!(
            "private injected backend requires a SIP-disabled host plus explicit injector setup; {} did not report SIP disabled",
            csrutil_command.to_string_lossy()
        ),
        remediation: Some("run the private gate on a SIP-disabled Hopper host, or set HOPPER_MCP_ASSUME_SIP_DISABLED=1 only for a designated runner when host detection is unavailable".to_string()),
    }
}

fn check_private_agent_socket(path: Option<&Path>, required: bool) -> DoctorCheck {
    let Some(path) = path else {
        return DoctorCheck {
            name: "privateAgentSocket",
            status: if required {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            },
            message: "private backend socket is not configured; set HOPPER_MCP_PRIVATE_AGENT_SOCKET to enable the native/private backend".to_string(),
            remediation: Some(
                "export HOPPER_MCP_PRIVATE_AGENT_SOCKET=/path/to/hopper-agent.sock before private-backend runs"
                    .to_string(),
            ),
        };
    };

    let backend = UnixWireBackend::new(path);
    let status = backend.status();
    let injected_private = status.backend_mode.as_deref() == Some("injected_private");
    let ready_injected_private = injected_private && status.readiness.as_deref() == Some("ready");
    let passes = status.available && (!required || ready_injected_private);
    DoctorCheck {
        name: "privateAgentSocket",
        status: if passes {
            DoctorStatus::Pass
        } else {
            DoctorStatus::Fail
        },
        message: if !status.available {
            format!(
                "private backend socket is configured but unavailable: {}: {}",
                path.display(),
                status
                    .reason
                    .unwrap_or_else(|| "unknown private backend error".to_string())
            )
        } else if required && !injected_private {
            format!(
                "private backend socket is reachable but reports {} instead of injected_private: {}",
                status
                    .backend_mode
                    .as_deref()
                    .unwrap_or("an unknown backend mode"),
                path.display()
            )
        } else if required {
            format!(
                "private backend socket is reachable but reports readiness {} instead of ready: {}",
                status.readiness.as_deref().unwrap_or("unknown"),
                path.display()
            )
        } else {
            format!("private backend socket is available: {}", path.display())
        },
        remediation: if passes {
            None
        } else if status.available {
            Some(
                "point HOPPER_MCP_PRIVATE_AGENT_SOCKET at the injected private hopper-agent socket before private-backend runs"
                    .to_string(),
            )
        } else {
            Some(
                "start hopper-agent or configure the correct HOPPER_MCP_PRIVATE_AGENT_SOCKET path before private-backend runs"
                    .to_string(),
            )
        },
    }
}

fn codesign_identity_remediation() -> String {
    "install a real Apple developer certificate, then verify with `security find-identity -p codesigning -v`".to_string()
}

fn distribution_identity_remediation() -> String {
    "install a `Developer ID Application` identity, set `HOPPER_MCP_CODESIGN_IDENTITY` to its full name, and verify with `security find-identity -p codesigning -v`".to_string()
}

fn notary_credentials_remediation() -> String {
    "set `HOPPER_MCP_NOTARY_PROFILE`, or set `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_PASSWORD`, then retry `npm run --silent release:check:public-release`".to_string()
}

fn probe_sip_disabled(command: &OsString) -> bool {
    if !command_available(command) {
        return false;
    }
    let Ok(output) = Command::new(command).arg("status").output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    combined.contains("system integrity protection status: disabled")
}

fn parse_codesign_identities(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let first_quote = line.find('"')?;
            let rest = &line[first_quote + 1..];
            let second_quote = rest.find('"')?;
            Some(rest[..second_quote].to_string())
        })
        .collect()
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn command_available(command: &OsString) -> bool {
    let path = PathBuf::from(command);
    if path.components().count() > 1 {
        return path.exists();
    }
    let Some(command) = command.to_str() else {
        return false;
    };
    Command::new("/usr/bin/which")
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn default_hopper_app() -> PathBuf {
    for path in [
        "/Applications/Hopper Disassembler.app",
        "/Applications/Hopper Disassembler v5.app",
        "/Applications/Hopper.app",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("/Applications/Hopper Disassembler v5.app")
}
