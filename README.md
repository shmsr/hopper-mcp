# Hopper MCP Knowledge Engine

This is the first runnable scaffold for a stateful Hopper reversing system with MCP as the outer protocol.
It is not a thin wrapper around Hopper UI commands. The server keeps an indexed local knowledge store,
exposes resources first, provides compound analysis tools, and makes annotation writes transactional.

## What Works Now

- MCP over stdio with `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, and `prompts/get`.
- Resource-first browsing for binary metadata, functions, strings, imports, exports, ObjC classes, Swift symbols, and function evidence.
- Compound read tools: `resolve`, `analyze_function_deep`, `get_graph_slice`, and `search_strings`.
- Transactional writes: `begin_transaction`, `queue_rename`, `queue_comment`, `queue_inline_comment`, `queue_type_patch`, `preview_transaction`, `commit_transaction`, and `rollback_transaction`.
- A local JSON knowledge store under `data/knowledge-store.json`.
- Live Hopper ingest via AppleScript and Hopper's official Python scripting with `ingest_live_hopper`.
- A Hopper adapter boundary ready for a persistent in-process plugin bridge.

## Run

```bash
npm run start
```

For a quick local validation:

```bash
npm run smoke
```

The smoke test starts the MCP server, ingests a sample Mach-O session, lists resources, and verifies
that deep function analysis includes evidence anchors.

To test the MCP layer with a real installed application:

```bash
npm run test:real
```

By default this imports `/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler`
with local macOS tools, opens that imported session through the MCP `open_session` tool, reads resources,
runs semantic queries, analyzes an evidence cluster, previews a transactional annotation, and rolls it back.
Set `REAL_APP_BINARY=/path/to/app` to point it at a different Mach-O executable.

To test the live Hopper bridge itself:

```bash
npm run test:live
```

For small command-line binaries, these settings avoid unnecessary ObjC/Swift parsing:

```bash
LIVE_HOPPER_PARSE_OBJC=0 LIVE_HOPPER_PARSE_SWIFT=0 LIVE_HOPPER_TIMEOUT_MS=90000 LIVE_HOPPER_MAX_FUNCTIONS=20 LIVE_HOPPER_MAX_STRINGS=50 npm run test:live
```

If macOS reports that the caller is not authorized to send Apple Events to Hopper, grant the terminal host
Automation access to Hopper in System Settings > Privacy & Security > Automation. In this workspace the
host app may appear as `Ghostty`.

To audit every MCP tool against a real live Hopper-ingested binary:

```bash
LIVE_HOPPER_PARSE_OBJC=0 LIVE_HOPPER_PARSE_SWIFT=0 LIVE_HOPPER_TIMEOUT_MS=120000 LIVE_HOPPER_MAX_FUNCTIONS=80 LIVE_HOPPER_MAX_STRINGS=200 npm run test:tools
```

This test currently exercises tool discovery, prompts, `capabilities`, `ingest_live_hopper`, resource reads,
`resolve`, `analyze_function_deep`, `get_graph_slice`, `search_strings`, transaction rollback/commit,
inline comments, type patches, `open_session`, and `ingest_sample`.

## Suggested MCP Client Config

Use the absolute path to this workspace:

```json
{
  "mcpServers": {
    "hopper": {
      "command": "node",
      "args": ["/path/to/hopper-mcp/src/mcp-server.js"]
    }
  }
}
```

## Architecture

```text
MCP Client / Agent
        |
        | MCP stdio
        v
Node MCP Facade
        |
        | resources, compound tools, transactions
        v
JSON Knowledge Store
        ^
        |
        | normalized session document
        |
Live Hopper Exporter
        ^
        |
        | AppleScript open executable + execute Python script
        |
Hopper Disassembler
```

The current daemon is implemented in dependency-free Node.js because this machine has Node installed
but not Rust/Cargo. The interfaces are deliberately narrow so a Rust daemon can replace the Node daemon
later without changing the MCP surface.

## Live Hopper Ingest

The `ingest_live_hopper` tool opens an executable in Hopper via AppleScript, waits for Hopper analysis,
runs an exporter script inside Hopper's official Python environment, and ingests the resulting live document
into the knowledge store.

Example MCP tool arguments:

```json
{
  "executable_path": "/bin/ls",
  "timeout_ms": 180000,
  "max_functions": 2000,
  "max_strings": 5000,
  "parse_objective_c": false,
  "parse_swift": false
}
```

This is intentionally read-first. Transaction commits still update the knowledge store only until we add a
persistent in-process bridge that can apply previews back to the already-open Hopper document.

## Main MCP Surface

Resources:

- `hopper://session/current`
- `hopper://binary/metadata`
- `hopper://binary/imports`
- `hopper://binary/exports`
- `hopper://binary/strings`
- `hopper://functions`
- `hopper://function/{addr}`
- `hopper://function/{addr}/summary`
- `hopper://function/{addr}/evidence`
- `hopper://graph/callers/{addr}`
- `hopper://graph/callees/{addr}`
- `hopper://objc/classes`
- `hopper://swift/symbols`
- `hopper://transactions/pending`

Read tools:

- `ingest_live_hopper`
- `open_session`
- `ingest_sample`
- `capabilities`
- `resolve`
- `analyze_function_deep`
- `get_graph_slice`
- `search_strings`

Write tools:

- `begin_transaction`
- `queue_rename`
- `queue_comment`
- `queue_inline_comment`
- `queue_type_patch`
- `preview_transaction`
- `commit_transaction`
- `rollback_transaction`

Current write behavior: commits apply to the local knowledge store and return `appliedToHopper: false` until
the persistent in-process Hopper bridge is added.

## Near-Term Next Steps

1. Add a persistent in-process Hopper adapter for applying transaction commits back into already-open Hopper documents.
2. Replace JSON persistence with SQLite once dependencies are allowed.
3. Add token-budget-aware evidence packing and semantic function fingerprints.
4. Add session-scoped hypothesis workspaces before committing annotations into Hopper.
5. Add optional dynamic debugger state behind a separate capability flag.
