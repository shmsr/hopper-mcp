use hopper_mcpd::Daemon;
use hopper_mcpd::doctor::{DoctorOptions, render_text, run_doctor};
use hopper_mcpd::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "doctor") {
        std::process::exit(run_doctor_command(&args[1..]));
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut daemon = match Daemon::from_env() {
        Ok(daemon) => daemon,
        Err(err) => {
            eprintln!("failed to initialize hopper-mcpd: {err:#}");
            std::process::exit(1);
        }
    };

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                let response =
                    JsonRpcResponse::error(None, JsonRpcError::internal(err.to_string()));
                write_response(&mut stdout, &response);
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let request: Result<JsonRpcRequest, _> = serde_json::from_str(&line);
        match request {
            Ok(request) => {
                if let Some(response) = daemon.handle(request) {
                    write_response(&mut stdout, &response);
                }
            }
            Err(err) => {
                let response =
                    JsonRpcResponse::error(None, JsonRpcError::parse_error(err.to_string()));
                write_response(&mut stdout, &response);
            }
        }
    }
}

fn run_doctor_command(args: &[OsString]) -> i32 {
    let mut options = DoctorOptions::from_env();
    let mut json = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.to_string_lossy().as_ref() {
            "--json" => json = true,
            "--require-hopper" => options.require_hopper = true,
            "--require-plugin-identity" => options.require_plugin_identity = true,
            "--require-distribution-identity" => options.require_distribution_identity = true,
            "--require-notary-credentials" => options.require_notary_credentials = true,
            "--require-clean-git-tree" => options.require_clean_git_tree = true,
            "--require-private-host" => options.require_private_host = true,
            "--require-private-backend" => options.require_private_backend = true,
            "--store" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --store requires a path");
                    return 2;
                };
                options.store_path = PathBuf::from(value);
            }
            "--node-command" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --node-command requires a command");
                    return 2;
                };
                options.node_command = value.clone();
            }
            "--git-command" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --git-command requires a command");
                    return 2;
                };
                options.git_command = value.clone();
            }
            "--security-command" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --security-command requires a command");
                    return 2;
                };
                options.security_command = value.clone();
            }
            "--csrutil-command" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --csrutil-command requires a command");
                    return 2;
                };
                options.csrutil_command = value.clone();
            }
            "--live-bridge-script" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --live-bridge-script requires a path");
                    return 2;
                };
                options.live_bridge_script = PathBuf::from(value);
            }
            "--hopper-app" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --hopper-app requires a path");
                    return 2;
                };
                options.hopper_app = PathBuf::from(value);
            }
            "--private-agent-socket" => {
                let Some(value) = iter.next() else {
                    eprintln!("doctor: --private-agent-socket requires a path");
                    return 2;
                };
                options.private_agent_socket = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                println!("{}", doctor_help());
                return 0;
            }
            other => {
                eprintln!("doctor: unknown argument: {other}");
                return 2;
            }
        }
    }

    let report = run_doctor(&options);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("doctor: failed to encode JSON report: {err}");
                return 2;
            }
        }
    } else {
        print!("{}", render_text(&report));
    }
    if report.ok { 0 } else { 1 }
}

fn doctor_help() -> &'static str {
    "Usage: hopper-mcpd doctor [--json] [--require-hopper] [--require-plugin-identity] [--require-distribution-identity] [--require-notary-credentials] [--require-clean-git-tree] [--require-private-host] [--require-private-backend] [--store PATH] [--node-command CMD] [--git-command CMD] [--security-command CMD] [--csrutil-command CMD] [--live-bridge-script PATH] [--hopper-app PATH] [--private-agent-socket PATH]"
}

fn write_response(stdout: &mut io::Stdout, response: &JsonRpcResponse) {
    if let Ok(line) = serde_json::to_string(response) {
        let _ = writeln!(stdout, "{line}");
        let _ = stdout.flush();
    }
}
