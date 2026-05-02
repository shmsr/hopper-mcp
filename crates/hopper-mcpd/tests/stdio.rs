use assert_cmd::Command;
use serde_json::Value;

#[test]
fn binary_speaks_newline_delimited_json_rpc() {
    let mut cmd = Command::cargo_bin("hopper-mcpd").expect("binary exists");
    let input = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
"#;
    let output = cmd.write_stdin(input).output().expect("process exits");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "stdout={stdout}");

    let init: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "hopper-mcpd");

    let tools: Value = serde_json::from_str(lines[1]).unwrap();
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"open_session"));
    assert!(names.contains(&"ingest_current_hopper"));
    assert!(names.contains(&"backend_status"));
    assert!(names.contains(&"backend_diagnostics"));
    assert!(!names.contains(&"import_macho"));
    assert!(!names.contains(&"disassemble_range"));
}
