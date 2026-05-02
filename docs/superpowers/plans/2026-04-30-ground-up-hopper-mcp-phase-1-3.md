# Ground-Up Hopper MCP Phase 1-3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the JavaScript production path with a Rust MCP daemon that has snapshot parity, persistence, transactions, resources, prompts, and a versioned backend boundary ready for a native Hopper private agent.

**Architecture:** `hopper-mcpd` remains the only MCP server and owns protocol handling, persistence, indexing, query, resources, prompts, and transactions. `hopper-wire` defines a versioned daemon-to-agent protocol with a mock transport first; Objective-C++ private agent work starts only after this boundary is tested. JavaScript remains a migration oracle until Rust reaches parity.

**Tech Stack:** Rust 2024, `serde`, `serde_json`, `thiserror`, `regex`, `tempfile`, `assert_cmd`, Unix domain socket protocol design, newline-delimited JSON-RPC MCP stdio.

---

## Research Notes

- MCP uses JSON-RPC 2.0 and the current official schema is protocol revision `2025-11-25`: https://modelcontextprotocol.io/specification/2025-11-25/schema
- The official Rust MCP SDK exists: https://github.com/modelcontextprotocol/rust-sdk
- Decision: keep a small audited MCP core in `hopper-mcpd` for now. This avoids SDK churn and lets us optimize the exact stdio/content/result shape clients need. Use official schema and contract tests as the correctness source.
- Hopper official docs confirm Hopper has built-in MCP and Python scripting, but private backend work will be separate from this plan.

## Scope

This plan implements Phase 1 through Phase 3 from the approved design:

- Phase 1: Rust daemon parity for snapshot reads and local transactions.
- Phase 2: Rust daemon owns persistence, resources, prompts, query engine, fingerprints, diffs, and protocol tests.
- Phase 3: Introduce `hopper-wire`, a mock agent, and daemon backend abstraction.

This plan does not implement Objective-C++ injection or private Hopper selectors. That is the next plan after the wire boundary is stable.

## File Map

Create:

- `crates/hopper-mcpd/src/address.rs`: address parse/format/normalization helpers.
- `crates/hopper-mcpd/src/content.rs`: MCP tool result content and structured-content helpers.
- `crates/hopper-mcpd/src/model.rs`: normalized session, function, graph, transaction, and capability types.
- `crates/hopper-mcpd/src/query.rs`: query DSL parser/evaluator.
- `crates/hopper-mcpd/src/resources.rs`: `hopper://` resource registry and read handlers.
- `crates/hopper-mcpd/src/transactions.rs`: transaction lifecycle and local apply logic.
- `crates/hopper-mcpd/src/persistence.rs`: atomic JSON store load/save.
- `crates/hopper-mcpd/src/backend.rs`: backend trait and backend selection.
- `crates/hopper-mcpd/src/prompts.rs`: prompt registry.
- `crates/hopper-mcpd/tests/fixtures.rs`: shared Rust test fixtures.
- `crates/hopper-mcpd/tests/protocol_contract.rs`: MCP initialize/tools/resources/prompts protocol tests.
- `crates/hopper-mcpd/tests/store_contract.rs`: snapshot/store/query tests.
- `crates/hopper-mcpd/tests/transaction_contract.rs`: transaction tests.
- `crates/hopper-mcpd/tests/persistence_contract.rs`: atomic persistence tests.
- `crates/hopper-mcpd/tests/backend_contract.rs`: mock backend tests.
- `crates/hopper-wire/Cargo.toml`: shared wire crate manifest.
- `crates/hopper-wire/src/lib.rs`: wire protocol types and version negotiation.
- `crates/hopper-wire/tests/wire_contract.rs`: wire serialization and negotiation tests.

Modify:

- `Cargo.toml`: add `hopper-wire` workspace member and shared dependencies.
- `crates/hopper-mcpd/Cargo.toml`: add `tempfile`, `sha2`, and path dependency on `hopper-wire`.
- `crates/hopper-mcpd/src/lib.rs`: expose new modules and daemon constructor.
- `crates/hopper-mcpd/src/main.rs`: keep stdio entrypoint but delegate to tested daemon.
- `crates/hopper-mcpd/src/protocol.rs`: complete MCP response/error/content types.
- `crates/hopper-mcpd/src/store.rs`: shrink to store orchestration or replace with `model` + focused modules.
- `crates/hopper-mcpd/src/tools.rs`: split implementation behind focused modules while preserving public registry.
- `README.md`: document Rust as production path after tests are green.
- `package.json`: keep JS scripts temporarily but make Rust scripts first-class.

## Task 1: Lock Protocol Core Shape

**Files:**
- Modify: `crates/hopper-mcpd/src/protocol.rs`
- Create: `crates/hopper-mcpd/src/content.rs`
- Modify: `crates/hopper-mcpd/src/lib.rs`
- Create: `crates/hopper-mcpd/tests/protocol_contract.rs`

- [ ] **Step 1: Write failing protocol content tests**

Create `crates/hopper-mcpd/tests/protocol_contract.rs` with:

```rust
use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

fn rpc(daemon: &mut Daemon, method: &str, params: Value) -> Value {
    let response = daemon.handle(JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: method.to_string(),
        params: Some(params),
    }).expect("request response");
    assert!(response.error.is_none(), "unexpected error: {:?}", response.error);
    response.result.expect("result")
}

#[test]
fn initialize_uses_current_protocol_and_declares_capabilities() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "initialize", json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "contract-test", "version": "0.0.0" }
    }));
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(result["serverInfo"]["name"], "hopper-mcpd");
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["capabilities"]["resources"].is_object());
    assert!(result["capabilities"]["prompts"].is_object());
}

#[test]
fn tool_results_include_text_and_structured_content() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/call", json!({
        "name": "capabilities",
        "arguments": {}
    }));
    assert_eq!(result["content"][0]["type"], "text");
    assert!(result["content"][0]["text"].as_str().unwrap().contains("hopper-mcpd"));
    assert_eq!(result["structuredContent"]["server"], "hopper-mcpd");
    assert_eq!(result["isError"], false);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test protocol_contract
```

Expected: FAIL because `content` / `structuredContent` shape is not fully implemented for Rust tool calls.

- [ ] **Step 3: Add MCP content helpers**

Create `crates/hopper-mcpd/src/content.rs`:

```rust
use serde_json::{Value, json};

pub fn tool_result(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": false
    })
}

pub fn tool_error(message: impl Into<String>) -> Value {
    let message = message.into();
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}
```

Modify `crates/hopper-mcpd/src/lib.rs`:

```rust
pub mod address;
pub mod backend;
pub mod content;
pub mod model;
pub mod persistence;
pub mod prompts;
pub mod protocol;
pub mod query;
pub mod resources;
pub mod store;
pub mod tools;
pub mod transactions;
```

- [ ] **Step 4: Use `tool_result` in `tools.rs`**

Modify `crates/hopper-mcpd/src/tools.rs` so every successful `call_tool` branch returns `crate::content::tool_result(payload)`.

For `capabilities`, use this exact payload:

```rust
json!({
    "server": "hopper-mcpd",
    "implementation": "rust",
    "privateBackend": { "available": false, "reason": "hopper-wire backend not configured" },
    "localFallbackTools": false
})
```

- [ ] **Step 5: Run test to verify it passes**

Run:

```bash
cargo test -p hopper-mcpd --test protocol_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/src/protocol.rs crates/hopper-mcpd/src/content.rs crates/hopper-mcpd/src/lib.rs crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/tests/protocol_contract.rs
git commit -m "feat: normalize rust mcp tool results"
```

## Task 2: Extract Address and Snapshot Model

**Files:**
- Create: `crates/hopper-mcpd/src/address.rs`
- Create: `crates/hopper-mcpd/src/model.rs`
- Modify: `crates/hopper-mcpd/src/store.rs`
- Create: `crates/hopper-mcpd/tests/fixtures.rs`
- Create: `crates/hopper-mcpd/tests/store_contract.rs`

- [ ] **Step 1: Write failing model tests**

Create `crates/hopper-mcpd/tests/store_contract.rs`:

```rust
mod fixtures;

use hopper_mcpd::address::{format_addr, normalize_addr, parse_addr};
use hopper_mcpd::store::SnapshotStore;

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
    assert_eq!(opened.session_id, "sample");
    assert_eq!(store.current_session_id(), Some("sample"));
    assert_eq!(store.function("0x100003f50", None).unwrap().name.as_deref(), Some("sub_100003f50"));
}
```

Create `crates/hopper-mcpd/tests/fixtures.rs`:

```rust
use hopper_mcpd::model::{Function, Session};

pub fn sample_session() -> Session {
    Session {
        session_id: "sample".to_string(),
        functions: vec![
            Function {
                addr: "0x100003f50".to_string(),
                name: Some("sub_100003f50".to_string()),
                size: Some(128),
                callers: vec!["0x100004120".to_string()],
                callees: vec!["0x100004010".to_string()],
                assembly: Some("0x100003f50: stp x29, x30, [sp, #-0x10]!".to_string()),
                pseudo_code: Some("int candidate() { return 1; }".to_string()),
                ..Function::default()
            },
            Function {
                addr: "0x100004120".to_string(),
                name: Some("_main".to_string()),
                size: Some(96),
                callees: vec!["0x100003f50".to_string()],
                ..Function::default()
            },
        ],
        ..Session::default()
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test store_contract
```

Expected: FAIL because `address`, `model`, and the new store API do not exist.

- [ ] **Step 3: Implement `address.rs`**

Create `crates/hopper-mcpd/src/address.rs`:

```rust
pub fn parse_addr(value: &str) -> Option<u64> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

pub fn format_addr(value: u64) -> String {
    format!("0x{value:x}")
}

pub fn normalize_addr(value: &str) -> Option<String> {
    parse_addr(value).map(format_addr)
}
```

- [ ] **Step 4: Implement `model.rs`**

Create `crates/hopper-mcpd/src/model.rs` with:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session_id: String,
    #[serde(default)]
    pub binary: Binary,
    #[serde(default)]
    pub functions: Vec<Function>,
    #[serde(default)]
    pub strings: Vec<AddressString>,
    #[serde(default)]
    pub names: Vec<NameEntry>,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub exports: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binary {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    pub addr: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub callers: Vec<String>,
    #[serde(default)]
    pub callees: Vec<String>,
    #[serde(default)]
    pub assembly: Option<String>,
    #[serde(default, alias = "pseudocode")]
    pub pseudo_code: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressString {
    pub addr: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameEntry {
    pub addr: String,
    pub name: String,
    #[serde(default)]
    pub demangled: Option<String>,
}
```

- [ ] **Step 5: Implement store API**

Modify `crates/hopper-mcpd/src/store.rs` so `SnapshotStore` stores `BTreeMap<String, Session>` and has:

```rust
pub fn current_session_id(&self) -> Option<&str>;
pub fn open_session(&mut self, session: Session, overwrite: bool) -> Result<Session, JsonRpcError>;
pub fn current_session(&self, session_id: Option<&str>) -> Result<&Session, JsonRpcError>;
pub fn function(&self, procedure: &str, session_id: Option<&str>) -> Result<&Function, JsonRpcError>;
```

`function()` must normalize address input and also match by exact function name.

- [ ] **Step 6: Run test to verify it passes**

Run:

```bash
cargo test -p hopper-mcpd --test store_contract
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/hopper-mcpd/src/address.rs crates/hopper-mcpd/src/model.rs crates/hopper-mcpd/src/store.rs crates/hopper-mcpd/tests/fixtures.rs crates/hopper-mcpd/tests/store_contract.rs
git commit -m "feat: add rust snapshot model"
```

## Task 3: Rebuild Tool Registry on Focused Modules

**Files:**
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Modify: `crates/hopper-mcpd/tests/protocol_contract.rs`

- [ ] **Step 1: Add failing tool registry test**

Append to `crates/hopper-mcpd/tests/protocol_contract.rs`:

```rust
#[test]
fn tool_registry_is_strict_and_hides_local_fallbacks() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/list", json!({}));
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<_> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
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
    for removed in ["import_macho", "disassemble_range", "find_xrefs", "find_functions"] {
        assert!(!names.contains(&removed), "{removed} must not be exposed");
    }
    for tool in tools {
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "tool {} is not strict", tool["name"]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails if schemas are incomplete**

Run:

```bash
cargo test -p hopper-mcpd --test protocol_contract tool_registry_is_strict_and_hides_local_fallbacks
```

Expected: FAIL until every listed tool has a strict schema.

- [ ] **Step 3: Implement strict registry**

Modify `crates/hopper-mcpd/src/tools.rs` to define:

```rust
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

pub fn registry() -> &'static [ToolDef] {
    &[
        ToolDef { name: "capabilities", description: "Report daemon capabilities.", input_schema: json!({"type":"object","properties":{},"additionalProperties":false}) },
        ToolDef { name: "open_session", description: "Create or replace a normalized Hopper snapshot.", input_schema: json!({"type":"object","properties":{"session":{"type":"object"},"overwrite":{"type":"boolean"}},"required":["session"],"additionalProperties":false}) },
        ToolDef { name: "list", description: "List snapshot items.", input_schema: json!({"type":"object","properties":{"kind":{"enum":["procedures","strings","names","segments","bookmarks","imports","exports"]},"session_id":{"type":"string"},"max_results":{"type":"number"}},"required":["kind"],"additionalProperties":false}) },
        ToolDef { name: "search", description: "Search snapshot strings, procedures, or names.", input_schema: json!({"type":"object","properties":{"kind":{"enum":["strings","procedures","names"]},"pattern":{"type":"string"},"case_sensitive":{"type":"boolean"},"session_id":{"type":"string"},"max_results":{"type":"number"}},"required":["kind","pattern"],"additionalProperties":false}) },
        ToolDef { name: "resolve", description: "Resolve address, name, string, or import.", input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"session_id":{"type":"string"},"max_results":{"type":"number"}},"required":["query"],"additionalProperties":false}) },
        ToolDef { name: "procedure", description: "Read procedure info, assembly, pseudo_code, callers, callees, or comments.", input_schema: json!({"type":"object","properties":{"field":{"enum":["info","assembly","pseudo_code","callers","callees","comments"]},"procedure":{"type":"string"},"session_id":{"type":"string"},"max_lines":{"type":"number"}},"required":["field"],"additionalProperties":false}) },
        ToolDef { name: "xrefs", description: "Return cross-references for an address.", input_schema: json!({"type":"object","properties":{"address":{"type":"string"},"session_id":{"type":"string"}},"additionalProperties":false}) },
        ToolDef { name: "containing_function", description: "Find function containing an address.", input_schema: json!({"type":"object","properties":{"address":{"type":"string"},"session_id":{"type":"string"}},"required":["address"],"additionalProperties":false}) },
        ToolDef { name: "get_graph_slice", description: "Return caller/callee graph slice.", input_schema: json!({"type":"object","properties":{"seed":{"type":"string"},"radius":{"type":"number"},"kind":{"enum":["calls","callers","callees"]},"max_nodes":{"type":"number"},"session_id":{"type":"string"}},"required":["seed"],"additionalProperties":false}) },
        ToolDef { name: "analyze_function_deep", description: "Return function purpose, graph context, and evidence.", input_schema: json!({"type":"object","properties":{"addr":{"type":"string"},"detail_level":{"enum":["standard","full"]},"session_id":{"type":"string"}},"required":["addr"],"additionalProperties":false}) },
        ToolDef { name: "compute_fingerprints", description: "Compute function fingerprints.", input_schema: json!({"type":"object","properties":{"session_id":{"type":"string"}},"additionalProperties":false}) },
        ToolDef { name: "find_similar_functions", description: "Find similar functions by fingerprint.", input_schema: json!({"type":"object","properties":{"addr":{"type":"string"},"session_id":{"type":"string"},"target_session_id":{"type":"string"},"min_similarity":{"type":"number"},"max_results":{"type":"number"}},"additionalProperties":false}) },
        ToolDef { name: "diff_sessions", description: "Diff two sessions.", input_schema: json!({"type":"object","properties":{"left_session_id":{"type":"string"},"right_session_id":{"type":"string"},"max_per_bucket":{"type":"number"}},"required":["left_session_id","right_session_id"],"additionalProperties":false}) },
        ToolDef { name: "query", description: "Run structured query DSL.", input_schema: json!({"type":"object","properties":{"expression":{"type":"string"},"session_id":{"type":"string"},"max_results":{"type":"number"}},"required":["expression"],"additionalProperties":false}) },
    ]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cargo test -p hopper-mcpd --test protocol_contract
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/tests/protocol_contract.rs
git commit -m "feat: define strict rust tool registry"
```

## Task 4: Implement Core Snapshot Read Tools

**Files:**
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Modify: `crates/hopper-mcpd/src/store.rs`
- Modify: `crates/hopper-mcpd/tests/store_contract.rs`

- [ ] **Step 1: Write failing read-tool tests**

Append to `crates/hopper-mcpd/tests/store_contract.rs`:

```rust
use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

fn call(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    let response = daemon.handle(JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": name, "arguments": arguments })),
    }).unwrap();
    assert!(response.error.is_none(), "unexpected error: {:?}", response.error);
    response.result.unwrap()["structuredContent"].clone()
}

#[test]
fn read_tools_return_snapshot_data() {
    let mut daemon = Daemon::new();
    call(&mut daemon, "open_session", json!({ "session": fixtures::sample_session() }));

    let procedures = call(&mut daemon, "list", json!({ "kind": "procedures" }));
    assert_eq!(procedures["0x100003f50"]["name"], "sub_100003f50");

    let search = call(&mut daemon, "search", json!({ "kind": "procedures", "pattern": "main" }));
    assert_eq!(search["0x100004120"]["name"], "_main");

    let resolved = call(&mut daemon, "resolve", json!({ "query": "_main" }));
    assert_eq!(resolved[0]["addr"], "0x100004120");

    let proc_info = call(&mut daemon, "procedure", json!({ "field": "info", "procedure": "0x100003f50" }));
    assert_eq!(proc_info["addr"], "0x100003f50");

    let callers = call(&mut daemon, "procedure", json!({ "field": "callers", "procedure": "0x100003f50" }));
    assert_eq!(callers[0], "0x100004120");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test store_contract read_tools_return_snapshot_data
```

Expected: FAIL until tool handlers use the new store API.

- [ ] **Step 3: Implement read handlers**

In `crates/hopper-mcpd/src/tools.rs`, route:

- `open_session`: deserialize `Session`, call `store.open_session(session, overwrite)`, return opened session metadata.
- `list`: return address-keyed object for procedures/strings/names and arrays for imports/exports.
- `search`: compile a bounded regex with optional case-insensitive mode; reject patterns longer than 512 bytes.
- `resolve`: exact address, exact name, substring string match, import match.
- `procedure`: return selected field for the resolved function.

Use helper extraction functions:

```rust
fn string_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

fn bool_arg(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(Value::as_bool)
}

fn usize_arg(args: &Value, key: &str, default: usize) -> usize {
    args.get(key).and_then(Value::as_u64).map(|v| v as usize).unwrap_or(default)
}
```

- [ ] **Step 4: Run read tests**

Run:

```bash
cargo test -p hopper-mcpd --test store_contract
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/src/store.rs crates/hopper-mcpd/tests/store_contract.rs
git commit -m "feat: implement rust snapshot read tools"
```

## Task 5: Query, Graph, Fingerprints, Similarity, and Diff

**Files:**
- Create: `crates/hopper-mcpd/src/query.rs`
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Modify: `crates/hopper-mcpd/src/model.rs`
- Modify: `crates/hopper-mcpd/tests/store_contract.rs`

- [ ] **Step 1: Write failing analysis-tool tests**

Append to `crates/hopper-mcpd/tests/store_contract.rs`:

```rust
#[test]
fn analysis_tools_work_from_snapshot() {
    let mut daemon = Daemon::new();
    call(&mut daemon, "open_session", json!({ "session": fixtures::sample_session() }));

    let containing = call(&mut daemon, "containing_function", json!({ "address": "0x100003f60" }));
    assert_eq!(containing["function"]["addr"], "0x100003f50");
    assert_eq!(containing["match"], "containment");

    let graph = call(&mut daemon, "get_graph_slice", json!({ "seed": "_main", "kind": "callees", "radius": 1 }));
    assert_eq!(graph["nodes"][0]["addr"], "0x100004120");

    let deep = call(&mut daemon, "analyze_function_deep", json!({ "addr": "0x100003f50" }));
    assert_eq!(deep["function"]["addr"], "0x100003f50");
    assert!(deep["evidenceAnchors"].as_array().unwrap().len() >= 1);

    let fingerprints = call(&mut daemon, "compute_fingerprints", json!({}));
    assert_eq!(fingerprints["updated"], 2);

    let query = call(&mut daemon, "query", json!({ "expression": "name:_main" }));
    assert_eq!(query["count"], 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test store_contract analysis_tools_work_from_snapshot
```

Expected: FAIL until analysis tools are implemented.

- [ ] **Step 3: Implement query DSL**

Create `crates/hopper-mcpd/src/query.rs` with support for these predicates:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Name(String),
    Imports(String),
    String(String),
    Addr(String),
}

pub fn parse_expression(expression: &str) -> Result<Predicate, String> {
    let trimmed = expression.trim();
    let Some((kind, value)) = trimmed.split_once(':') else {
        return Err("Query must use predicate:value syntax.".to_string());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("Query predicate value must not be empty.".to_string());
    }
    match kind.trim() {
        "name" => Ok(Predicate::Name(value.to_string())),
        "imports" => Ok(Predicate::Imports(value.to_string())),
        "string" => Ok(Predicate::String(value.to_string())),
        "addr" => Ok(Predicate::Addr(value.to_string())),
        other => Err(format!("Unsupported query predicate: {other}")),
    }
}
```

- [ ] **Step 4: Implement graph and analysis handlers**

In `tools.rs`:

- `containing_function`: compare normalized address against `fn.addr <= address < fn.addr + size`.
- `get_graph_slice`: BFS over callers/callees with `max_nodes` default `200`.
- `analyze_function_deep`: return function, callers, callees, assembly/pseudocode evidence anchors.
- `compute_fingerprints`: compute deterministic hash from address, name, callees, callers, strings, imports.
- `find_similar_functions`: compare exact fingerprint first; then token overlap score.
- `diff_sessions`: compare function address/name sets and string values.
- `query`: use `query::parse_expression`.

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p hopper-mcpd --test store_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/src/query.rs crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/src/model.rs crates/hopper-mcpd/tests/store_contract.rs
git commit -m "feat: add rust analysis tools"
```

## Task 6: Resources and Prompts

**Files:**
- Create: `crates/hopper-mcpd/src/resources.rs`
- Create: `crates/hopper-mcpd/src/prompts.rs`
- Modify: `crates/hopper-mcpd/src/lib.rs`
- Modify: `crates/hopper-mcpd/tests/protocol_contract.rs`

- [ ] **Step 1: Write failing resource/prompt tests**

Append to `crates/hopper-mcpd/tests/protocol_contract.rs`:

```rust
#[test]
fn resources_and_prompts_are_exposed() {
    let mut daemon = Daemon::new();
    let resources = rpc(&mut daemon, "resources/list", json!({}));
    let uris: Vec<_> = resources["resources"].as_array().unwrap().iter().map(|r| r["uri"].as_str().unwrap()).collect();
    assert!(uris.contains(&"hopper://session/current"));
    assert!(uris.contains(&"hopper://functions"));

    let prompts = rpc(&mut daemon, "prompts/list", json!({}));
    let names: Vec<_> = prompts["prompts"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"function_triage"));
    assert!(names.contains(&"hypothesis_workspace"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test protocol_contract resources_and_prompts_are_exposed
```

Expected: FAIL because prompts are not implemented and resources are incomplete.

- [ ] **Step 3: Implement resources**

Create `crates/hopper-mcpd/src/resources.rs` with static resource descriptors:

```rust
use serde_json::{Value, json};

pub fn list_resources() -> Value {
    json!({ "resources": [
        { "uri": "hopper://session/current", "name": "Current Hopper session", "mimeType": "application/json" },
        { "uri": "hopper://binary/metadata", "name": "Binary metadata", "mimeType": "application/json" },
        { "uri": "hopper://functions", "name": "Functions", "mimeType": "application/json" },
        { "uri": "hopper://strings", "name": "Strings", "mimeType": "application/json" },
        { "uri": "hopper://names", "name": "Names", "mimeType": "application/json" },
        { "uri": "hopper://transactions/pending", "name": "Pending transactions", "mimeType": "application/json" }
    ]})
}
```

- [ ] **Step 4: Implement prompts**

Create `crates/hopper-mcpd/src/prompts.rs`:

```rust
use serde_json::{Value, json};

pub fn list_prompts() -> Value {
    json!({ "prompts": [
        {
            "name": "function_triage",
            "description": "Analyze a Hopper function using procedure, xrefs, graph, and evidence tools.",
            "arguments": [{ "name": "addr", "description": "Function entrypoint address.", "required": true }]
        },
        {
            "name": "hypothesis_workspace",
            "description": "Maintain reverse-engineering hypotheses with evidence links.",
            "arguments": [{ "name": "topic", "description": "Hypothesis topic.", "required": true }]
        }
    ]})
}
```

Update `Daemon::handle` so `prompts/list` returns `prompts::list_prompts()`.

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p hopper-mcpd --test protocol_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/src/resources.rs crates/hopper-mcpd/src/prompts.rs crates/hopper-mcpd/src/lib.rs crates/hopper-mcpd/src/main.rs crates/hopper-mcpd/tests/protocol_contract.rs
git commit -m "feat: add rust resources and prompts"
```

## Task 7: Local Transactions

**Files:**
- Create: `crates/hopper-mcpd/src/transactions.rs`
- Modify: `crates/hopper-mcpd/src/model.rs`
- Modify: `crates/hopper-mcpd/src/store.rs`
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Create: `crates/hopper-mcpd/tests/transaction_contract.rs`

- [ ] **Step 1: Write failing transaction tests**

Create `crates/hopper-mcpd/tests/transaction_contract.rs`:

```rust
mod fixtures;

use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

fn call(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    let response = daemon.handle(JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": name, "arguments": arguments })),
    }).unwrap();
    assert!(response.error.is_none(), "unexpected error: {:?}", response.error);
    response.result.unwrap()["structuredContent"].clone()
}

#[test]
fn local_rename_transaction_previews_and_commits() {
    let mut daemon = Daemon::new();
    call(&mut daemon, "open_session", json!({ "session": fixtures::sample_session() }));
    let txn = call(&mut daemon, "begin_transaction", json!({ "name": "rename main" }));
    let transaction_id = txn["transactionId"].as_str().unwrap().to_string();
    call(&mut daemon, "queue", json!({
        "transaction_id": transaction_id,
        "kind": "rename",
        "addr": "0x100004120",
        "value": "main_entry"
    }));
    let preview = call(&mut daemon, "preview_transaction", json!({ "transaction_id": transaction_id }));
    assert_eq!(preview["operations"][0]["kind"], "rename");
    let committed = call(&mut daemon, "commit_transaction", json!({ "transaction_id": transaction_id }));
    assert_eq!(committed["applied"], true);
    let proc_info = call(&mut daemon, "procedure", json!({ "field": "info", "procedure": "0x100004120" }));
    assert_eq!(proc_info["name"], "main_entry");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test transaction_contract
```

Expected: FAIL because transaction tools are not implemented.

- [ ] **Step 3: Implement transaction model**

Add to `model.rs`:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub transaction_id: String,
    pub name: Option<String>,
    pub status: TransactionStatus,
    pub operations: Vec<TransactionOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Open,
    Committed,
    RolledBack,
}

impl Default for TransactionStatus {
    fn default() -> Self { Self::Open }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionOperation {
    pub kind: String,
    pub addr: String,
    pub value: String,
}
```

- [ ] **Step 4: Implement transaction handlers**

Create `transactions.rs` with:

```rust
use crate::model::{Transaction, TransactionOperation, TransactionStatus};

pub fn new_transaction(id: String, name: Option<String>) -> Transaction {
    Transaction { transaction_id: id, name, status: TransactionStatus::Open, operations: vec![] }
}

pub fn rename_op(addr: String, value: String) -> TransactionOperation {
    TransactionOperation { kind: "rename".to_string(), addr, value }
}
```

Store pending transactions in `SnapshotStore`. Implement tool handlers for `begin_transaction`, `queue`, `preview_transaction`, `commit_transaction`, and `rollback_transaction`. Start with local `rename`, `comment`, and `inline_comment`.

- [ ] **Step 5: Run transaction tests**

Run:

```bash
cargo test -p hopper-mcpd --test transaction_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/src/transactions.rs crates/hopper-mcpd/src/model.rs crates/hopper-mcpd/src/store.rs crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/tests/transaction_contract.rs
git commit -m "feat: add rust local transactions"
```

## Task 8: Atomic Persistence

**Files:**
- Create: `crates/hopper-mcpd/src/persistence.rs`
- Modify: `crates/hopper-mcpd/src/lib.rs`
- Modify: `crates/hopper-mcpd/src/main.rs`
- Modify: `crates/hopper-mcpd/Cargo.toml`
- Create: `crates/hopper-mcpd/tests/persistence_contract.rs`

- [ ] **Step 1: Add dependency**

Modify `crates/hopper-mcpd/Cargo.toml`:

```toml
[dependencies]
anyhow = "1.0"
regex = "1.12"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
tempfile = "3.23"
thiserror = "2.0"
hopper-wire = { path = "../hopper-wire" }
```

If `hopper-wire` does not exist yet, add `tempfile` now and add `hopper-wire` in Task 9.

- [ ] **Step 2: Write failing persistence test**

Create `crates/hopper-mcpd/tests/persistence_contract.rs`:

```rust
mod fixtures;

use hopper_mcpd::persistence::{load_store, save_store};
use hopper_mcpd::store::SnapshotStore;
use tempfile::tempdir;

#[test]
fn store_round_trips_through_atomic_json_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    let mut store = SnapshotStore::default();
    store.open_session(fixtures::sample_session(), true).unwrap();
    save_store(&path, &store).unwrap();
    let loaded = load_store(&path).unwrap();
    assert_eq!(loaded.current_session_id(), Some("sample"));
    assert_eq!(loaded.function("_main", None).unwrap().addr, "0x100004120");
}
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test persistence_contract
```

Expected: FAIL because persistence module is missing.

- [ ] **Step 4: Implement atomic persistence**

Create `crates/hopper-mcpd/src/persistence.rs`:

```rust
use crate::store::SnapshotStore;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn load_store(path: &Path) -> anyhow::Result<SnapshotStore> {
    if !path.exists() {
        return Ok(SnapshotStore::default());
    }
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_store(path: &Path, store: &SnapshotStore) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(serde_json::to_string_pretty(store)?.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}
```

Derive `Serialize` and `Deserialize` for `SnapshotStore`.

- [ ] **Step 5: Run test**

Run:

```bash
cargo test -p hopper-mcpd --test persistence_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/Cargo.toml crates/hopper-mcpd/src/persistence.rs crates/hopper-mcpd/src/lib.rs crates/hopper-mcpd/src/main.rs crates/hopper-mcpd/src/store.rs crates/hopper-mcpd/tests/persistence_contract.rs
git commit -m "feat: add rust atomic persistence"
```

## Task 9: Add `hopper-wire` Protocol Crate

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/hopper-wire/Cargo.toml`
- Create: `crates/hopper-wire/src/lib.rs`
- Create: `crates/hopper-wire/tests/wire_contract.rs`
- Modify: `crates/hopper-mcpd/Cargo.toml`

- [ ] **Step 1: Write wire crate manifest**

Modify workspace `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/hopper-mcpd",
    "crates/hopper-wire",
]
resolver = "3"
```

Create `crates/hopper-wire/Cargo.toml`:

```toml
[package]
name = "hopper-wire"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "Versioned daemon-to-Hopper-agent protocol for Hopper MCP."

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
```

- [ ] **Step 2: Write failing wire tests**

Create `crates/hopper-wire/tests/wire_contract.rs`:

```rust
use hopper_wire::{AgentCapabilities, HandshakeRequest, HandshakeResponse, WIRE_VERSION};

#[test]
fn handshake_round_trips_and_reports_capabilities() {
    let request = HandshakeRequest {
        wire_version: WIRE_VERSION,
        daemon_version: "0.1.0".to_string(),
    };
    let text = serde_json::to_string(&request).unwrap();
    let decoded: HandshakeRequest = serde_json::from_str(&text).unwrap();
    assert_eq!(decoded.wire_version, 1);

    let response = HandshakeResponse {
        accepted: true,
        wire_version: WIRE_VERSION,
        agent_version: "0.1.0".to_string(),
        hopper_version: Some("6.x".to_string()),
        capabilities: AgentCapabilities { current_document: true, procedures: true, writes: false },
        unsupported_reason: None,
    };
    assert!(response.capabilities.procedures);
}
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-wire
```

Expected: FAIL because wire types are missing.

- [ ] **Step 4: Implement wire types**

Create `crates/hopper-wire/src/lib.rs`:

```rust
use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeRequest {
    pub wire_version: u32,
    pub daemon_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeResponse {
    pub accepted: bool,
    pub wire_version: u32,
    pub agent_version: String,
    pub hopper_version: Option<String>,
    pub capabilities: AgentCapabilities,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    pub current_document: bool,
    pub procedures: bool,
    pub writes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    Handshake(HandshakeRequest),
    CurrentDocument,
    ListProcedures { max_results: Option<u64> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    Handshake(HandshakeResponse),
    CurrentDocument { document_id: String, name: String },
    Procedures { procedures: Vec<WireProcedure>, truncated: bool },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireProcedure {
    pub addr: String,
    pub name: Option<String>,
    pub size: Option<u64>,
}
```

- [ ] **Step 5: Run wire tests**

Run:

```bash
cargo test -p hopper-wire
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/hopper-wire/Cargo.toml crates/hopper-wire/src/lib.rs crates/hopper-wire/tests/wire_contract.rs crates/hopper-mcpd/Cargo.toml
git commit -m "feat: add hopper wire protocol crate"
```

## Task 10: Backend Trait and Mock Agent

**Files:**
- Create: `crates/hopper-mcpd/src/backend.rs`
- Modify: `crates/hopper-mcpd/src/lib.rs`
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Create: `crates/hopper-mcpd/tests/backend_contract.rs`

- [ ] **Step 1: Write failing backend tests**

Create `crates/hopper-mcpd/tests/backend_contract.rs`:

```rust
use hopper_mcpd::backend::{Backend, BackendStatus, MockBackend};

#[test]
fn mock_backend_reports_private_unavailable_by_default() {
    let backend = MockBackend::unavailable("private backend not installed");
    let status = backend.status();
    assert_eq!(status.name, "mock");
    assert_eq!(status.available, false);
    assert_eq!(status.reason.as_deref(), Some("private backend not installed"));
}

#[test]
fn mock_backend_can_return_current_document() {
    let backend = MockBackend::with_document("doc-1", "Calculator");
    let doc = backend.current_document().unwrap();
    assert_eq!(doc.document_id, "doc-1");
    assert_eq!(doc.name, "Calculator");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test backend_contract
```

Expected: FAIL because backend module is missing.

- [ ] **Step 3: Implement backend trait**

Create `crates/hopper-mcpd/src/backend.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendStatus {
    pub name: String,
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDocument {
    pub document_id: String,
    pub name: String,
}

pub trait Backend {
    fn status(&self) -> BackendStatus;
    fn current_document(&self) -> Result<BackendDocument, String>;
}

#[derive(Debug, Clone)]
pub struct MockBackend {
    status: BackendStatus,
    document: Option<BackendDocument>,
}

impl MockBackend {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: BackendStatus { name: "mock".to_string(), available: false, reason: Some(reason.into()) },
            document: None,
        }
    }

    pub fn with_document(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            status: BackendStatus { name: "mock".to_string(), available: true, reason: None },
            document: Some(BackendDocument { document_id: id.into(), name: name.into() }),
        }
    }
}

impl Backend for MockBackend {
    fn status(&self) -> BackendStatus {
        self.status.clone()
    }

    fn current_document(&self) -> Result<BackendDocument, String> {
        self.document.clone().ok_or_else(|| self.status.reason.clone().unwrap_or_else(|| "No current document".to_string()))
    }
}
```

- [ ] **Step 4: Add backend tools**

Add tool definitions and handlers:

- `backend_status`: returns backend status.
- `backend_diagnostics`: returns backend status plus wire version when available.

Return structured JSON:

```json
{
  "backend": "mock",
  "available": false,
  "reason": "private backend not installed"
}
```

- [ ] **Step 5: Run backend tests**

Run:

```bash
cargo test -p hopper-mcpd --test backend_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/src/backend.rs crates/hopper-mcpd/src/lib.rs crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/tests/backend_contract.rs
git commit -m "feat: add rust backend abstraction"
```

## Task 11: Wire-Backed Mock Ingest

**Files:**
- Modify: `crates/hopper-mcpd/src/backend.rs`
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Modify: `crates/hopper-mcpd/tests/backend_contract.rs`

- [ ] **Step 1: Write failing ingest test**

Append to `crates/hopper-mcpd/tests/backend_contract.rs`:

```rust
use hopper_mcpd::Daemon;
use hopper_mcpd::protocol::JsonRpcRequest;
use serde_json::{Value, json};

fn call(daemon: &mut Daemon, name: &str, arguments: Value) -> Value {
    let response = daemon.handle(JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": name, "arguments": arguments })),
    }).unwrap();
    assert!(response.error.is_none(), "unexpected error: {:?}", response.error);
    response.result.unwrap()["structuredContent"].clone()
}

#[test]
fn ingest_current_hopper_uses_backend_boundary() {
    let mut daemon = Daemon::with_mock_backend_document("doc-1", "Calculator");
    let ingested = call(&mut daemon, "ingest_current_hopper", json!({ "backend": "mock" }));
    assert_eq!(ingested["sessionId"], "live-doc-1");
    let caps = call(&mut daemon, "backend_status", json!({}));
    assert_eq!(caps["available"], true);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p hopper-mcpd --test backend_contract ingest_current_hopper_uses_backend_boundary
```

Expected: FAIL because `Daemon::with_mock_backend_document` and `ingest_current_hopper` do not exist.

- [ ] **Step 3: Add daemon backend constructor**

Modify `Daemon` to hold `Box<dyn Backend + Send + Sync>`.

Add:

```rust
impl Daemon {
    pub fn with_mock_backend_document(id: &str, name: &str) -> Self {
        Self::with_backend(Box::new(crate::backend::MockBackend::with_document(id, name)))
    }

    pub fn with_backend(backend: Box<dyn crate::backend::Backend + Send + Sync>) -> Self {
        Self {
            store: SnapshotStore::default(),
            server_info: ServerInfo::default(),
            backend,
        }
    }
}
```

Update `Daemon::new()` to use `MockBackend::unavailable("private backend not installed")`.

- [ ] **Step 4: Implement mock ingest handler**

Add `ingest_current_hopper` to the registry and handler:

```rust
let doc = daemon.backend.current_document()?;
let session = Session {
    session_id: format!("live-{}", doc.document_id),
    binary: Binary { name: Some(doc.name), format: Some("hopper-live".to_string()), ..Binary::default() },
    ..Session::default()
};
store.open_session(session, true)?;
```

- [ ] **Step 5: Run backend tests**

Run:

```bash
cargo test -p hopper-mcpd --test backend_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hopper-mcpd/src/backend.rs crates/hopper-mcpd/src/lib.rs crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/tests/backend_contract.rs
git commit -m "feat: add backend-backed current hopper ingest"
```

## Task 12: Final Rust Parity Gate

**Files:**
- Modify: `README.md`
- Modify: `package.json`
- Modify: `crates/hopper-mcpd/tests/stdio.rs`

- [ ] **Step 1: Update stdio test for required tools**

Modify `crates/hopper-mcpd/tests/stdio.rs` to assert:

```rust
assert!(names.contains(&"open_session"));
assert!(names.contains(&"ingest_current_hopper"));
assert!(names.contains(&"backend_status"));
assert!(names.contains(&"backend_diagnostics"));
assert!(!names.contains(&"import_macho"));
assert!(!names.contains(&"disassemble_range"));
```

- [ ] **Step 2: Run all Rust tests**

Run:

```bash
cargo fmt --check
cargo test --workspace
```

Expected: PASS for `hopper-mcpd` and `hopper-wire`.

- [ ] **Step 3: Update docs**

Modify `README.md` Rust section to say:

```markdown
The production rewrite is `crates/hopper-mcpd`. It owns MCP stdio, snapshot indexing, query, resources, prompts, local transactions, persistence, and the versioned `hopper-wire` backend boundary. The JavaScript server is retained only as a migration reference until Rust reaches live/private backend parity.
```

Modify `package.json` scripts so Rust commands are visible:

```json
"start:rust": "cargo run -p hopper-mcpd --",
"build:rust": "cargo build --workspace",
"check:rust": "cargo check --workspace",
"fmt:rust": "cargo fmt --check",
"test:rust": "cargo test --workspace"
```

- [ ] **Step 4: Run final verification**

Run:

```bash
npm run fmt:rust
npm run check:rust
npm run test:rust
npm test
```

Expected: all pass. If `npm test` fails due legacy JavaScript tests from removed local Mach-O tools, update those tests to assert the tools are absent rather than restoring fallback behavior.

- [ ] **Step 5: Commit**

```bash
git add README.md package.json crates/hopper-mcpd/tests/stdio.rs
git commit -m "docs: mark rust daemon as production path"
```

## Completion Criteria

Phase 1-3 are complete when:

- `cargo test --workspace` passes.
- `hopper-mcpd` speaks MCP stdio and exposes strict schemas.
- Rust supports snapshot ingest, read tools, analysis tools, resources, prompts, persistence, and local transactions.
- `hopper-wire` serializes versioned daemon-agent requests and responses.
- Mock backend supports `backend_status`, `backend_diagnostics`, and `ingest_current_hopper`.
- Public tool surface still excludes `import_macho`, `disassemble_range`, `find_xrefs`, and `find_functions`.
- JavaScript is no longer described as the production architecture.

## Next Plan After This

Write a separate Objective-C++ private agent plan covering:

- Hopper runtime discovery.
- Selector table generation and version gating.
- Read-only document/procedure extraction.
- Agent launch/injection/install mechanics.
- Unix socket server inside or beside Hopper.
- Private live test harness.
