# Production Live Ingest v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route live Hopper ingestion through the Rust MCP daemon while preserving the existing Node live exporter as a v1 bridge.

**Architecture:** Rust owns the MCP tool schema, store persistence, error handling, and diagnostics. A small Rust bridge adapter invokes a configured command that returns a normalized Hopper session JSON payload. The existing Node live implementation remains the behavior oracle until a native backend replaces it.

**Tech Stack:** Rust (`hopper-mcpd`, `serde_json`, `std::process`), existing Node bridge (`src/hopper-live.js` through a thin CLI helper), MCP stdio contract tests, gated live Hopper tests.

---

### Task 1: Add Rust Live Ingest Tool Contract

**Files:**
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Test: `crates/hopper-mcpd/tests/backend_contract.rs`

- [ ] **Step 1: Write the failing tool-list test**

Add this test to `crates/hopper-mcpd/tests/backend_contract.rs`:

```rust
#[test]
fn ingest_live_hopper_is_registered_as_strict_read_write_tool() {
    let mut daemon = Daemon::new();
    let result = rpc(&mut daemon, "tools/list", json!({}));
    let tools = result["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "ingest_live_hopper")
        .expect("missing ingest_live_hopper");

    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    assert_eq!(tool["inputSchema"]["required"][0], "executable_path");
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
}
```

- [ ] **Step 2: Verify the test fails**

Run:

```bash
cargo test -p hopper-mcpd ingest_live_hopper_is_registered_as_strict_read_write_tool
```

Expected: fail with `missing ingest_live_hopper`.

- [ ] **Step 3: Register the tool schema**

In `crates/hopper-mcpd/src/tools.rs`, add `ingest_live_hopper` to `TOOL_REGISTRY`, mark it as mutating in `tool()`, and add this schema:

```rust
fn schema_ingest_live_hopper() -> Value {
    strict_schema(
        json!({
            "executable_path": { "type": "string" },
            "timeout_ms": limit_schema(),
            "max_functions": limit_schema(),
            "max_strings": limit_schema(),
            "analysis": { "type": "boolean" },
            "loader": { "type": "string", "pattern": "^[A-Za-z0-9_.-]+$" },
            "only_procedures": { "type": "boolean" },
            "parse_objective_c": { "type": "boolean" },
            "parse_swift": { "type": "boolean" },
            "parse_exceptions": { "type": "boolean" },
            "close_after_export": { "type": "boolean" },
            "wait_for_analysis": { "type": "boolean" },
            "full_export": { "type": "boolean" },
            "include_pseudocode": { "type": "boolean" },
            "max_pseudocode_functions": limit_schema(),
            "overwrite": { "type": "boolean" }
        }),
        &["executable_path"],
    )
}
```

- [ ] **Step 4: Verify the tool-list test passes**

Run:

```bash
cargo test -p hopper-mcpd ingest_live_hopper_is_registered_as_strict_read_write_tool
```

Expected: pass.

### Task 2: Add Bridge Adapter Interface

**Files:**
- Create: `crates/hopper-mcpd/src/live.rs`
- Modify: `crates/hopper-mcpd/src/lib.rs`
- Test: `crates/hopper-mcpd/tests/live_bridge_contract.rs`

- [ ] **Step 1: Write fake-bridge ingest test**

Create `crates/hopper-mcpd/tests/live_bridge_contract.rs` with a test that runs a fixture shell command emitting:

```json
{
  "session": {
    "sessionId": "live-fixture",
    "binary": { "name": "fixture", "format": "hopper-live", "arch": "arm64" },
    "functions": {}
  },
  "launch": { "mode": "fixture" }
}
```

The test should assert the adapter returns session id `live-fixture`.

- [ ] **Step 2: Verify the test fails**

Run:

```bash
cargo test -p hopper-mcpd --test live_bridge_contract
```

Expected: fail because `live` module does not exist.

- [ ] **Step 3: Implement `LiveIngestRequest`, `LiveIngestResult`, and `NodeLiveBridge`**

Add request fields matching the tool schema, spawn the configured command with a JSON request on stdin, require a zero exit code, parse JSON stdout, and return `Session` plus launch metadata.

- [ ] **Step 4: Verify adapter test passes**

Run:

```bash
cargo test -p hopper-mcpd --test live_bridge_contract
```

Expected: pass.

### Task 3: Wire Rust Tool To Bridge And Store

**Files:**
- Modify: `crates/hopper-mcpd/src/lib.rs`
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Test: `crates/hopper-mcpd/tests/backend_contract.rs`
- Test: `crates/hopper-mcpd/tests/persistence_contract.rs`

- [ ] **Step 1: Write failing tool-call tests**

Add tests proving:

```rust
// Unknown argument rejects.
let error = tool_error(&mut daemon, "ingest_live_hopper", json!({
    "executable_path": "/bin/echo",
    "typo": true
}));
assert_eq!(error.code, -32602);

// Missing executable_path rejects.
let error = tool_error(&mut daemon, "ingest_live_hopper", json!({}));
assert_eq!(error.code, -32602);
```

- [ ] **Step 2: Verify tests fail**

Run:

```bash
cargo test -p hopper-mcpd ingest_live_hopper
```

Expected: fail until handler exists.

- [ ] **Step 3: Implement handler**

Parse args into `LiveIngestRequest`, call the bridge, open the returned session with `overwrite`, and return:

```json
{
  "session": { "...": "store descriptor" },
  "launch": { "...": "bridge launch metadata" },
  "diagnostics": { "backend": "node-live-bridge" }
}
```

- [ ] **Step 4: Verify tool-call tests pass**

Run:

```bash
cargo test -p hopper-mcpd ingest_live_hopper
```

Expected: pass.

### Task 4: Add Node Bridge CLI

**Files:**
- Create: `src/live-bridge-cli.js`
- Modify: `package.json`
- Test: `test/live-bridge-cli.mjs`

- [ ] **Step 1: Write failing CLI test**

Create a Node test that runs `node src/live-bridge-cli.js`, sends invalid JSON on stdin, and asserts non-zero exit plus a JSON error.

- [ ] **Step 2: Verify the test fails**

Run:

```bash
node --test test/live-bridge-cli.mjs
```

Expected: fail because the CLI does not exist.

- [ ] **Step 3: Implement CLI**

Read JSON from stdin, call `ingestWithLiveHopper`, and print one JSON object:

```json
{ "session": { "...": "normalized session" }, "launch": { "...": "launch data" } }
```

On error, print:

```json
{ "error": { "message": "...", "code": "live_bridge_failed" } }
```

and exit non-zero.

- [ ] **Step 4: Verify CLI tests pass**

Run:

```bash
node --test test/live-bridge-cli.mjs
```

Expected: pass.

### Task 5: Add Live End-To-End Gate

**Files:**
- Modify: `test/live.mjs`
- Create: `crates/hopper-mcpd/tests/live_ingest_ignored.rs` or equivalent gated test helper
- Modify: `package.json`

- [ ] **Step 1: Add gated Rust live command**

Add a command that sets `HOPPER_MCP_LIVE=1`, launches `hopper-mcpd`, calls `ingest_live_hopper` with:

```json
{
  "executable_path": "/bin/echo",
  "timeout_ms": 90000,
  "max_functions": 5,
  "close_after_export": true
}
```

- [ ] **Step 2: Verify live gate passes locally**

Run:

```bash
npm run test:live
cargo test --workspace
```

Expected: both pass, with Hopper windows cleaned when `close_after_export` is true.

### Task 6: Release Gate And Completion Audit

**Files:**
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`

- [ ] **Step 1: Document production live ingest**

Update docs to state that Rust is the MCP entrypoint and live ingest routes through Rust. Document `close_after_export`, timeout behavior, and the full release gate.

- [ ] **Step 2: Run full verification**

Run:

```bash
npm test
cargo fmt --check
cargo test --workspace
npm run test:live
```

Expected: all commands pass.

- [ ] **Step 3: Completion audit**

Create a checklist mapping the production-grade criteria in `docs/superpowers/specs/2026-05-01-production-live-ingest-v1-design.md` to code, tests, and command output. Any missing item keeps the milestone open.
