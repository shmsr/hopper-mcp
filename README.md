# Hopper MCP

MCP server for Hopper. It can import Mach-O data with local macOS tools, or open a binary in Hopper and export indexed state through Hopper's Python scripting API.

Default write behavior is local-only: transaction commits update the JSON store and return `appliedToHopper: false`. Comment/rename write-back can be routed through Hopper's installed official MCP server, but only when `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` is set and the commit passes `confirm_live_write: true`.

## Requirements

- macOS
- Hopper installed
- Node.js 20+
- macOS Automation permission for the terminal or app that launches Hopper

## Run

```bash
npm run start     # launch the MCP server over stdio
npm test          # run the offline test suite (119 tests, ~12s)
npm run test:live # run the live-Hopper suite (HOPPER_MCP_LIVE=1, requires Hopper installed)
npm run test:all  # offline + live, when both are available
```

If macOS blocks Automation, allow the launcher app to control Hopper in `System Settings > Privacy & Security > Automation`.

For large binaries, start with the faster local importer:

```json
{
  "executable_path": "/path/to/binary",
  "max_strings": 10000
}
```

Call that as `import_macho`. The local Mach-O tools auto-select an architecture by default, preferring `arm64e`, then `arm64`, then `x86_64`. Pass `arch` only when you need a specific slice. If `arch: "arm64"` is requested for an `arm64e`-only system binary, the importer selects `arm64e` and records both `requestedArch` and the selected `arch` in the session metadata.

Use `ingest_live_hopper` when you need a Hopper Python export for a specific executable path. Exporting the frontmost Hopper document is not exposed yet; that needs the future in-process Hopper adapter.

Live Hopper export modes:

```json
{
  "executable_path": "/path/to/binary",
  "wait_for_analysis": true,
  "full_export": true
}
```

`full_export: true` forces `wait_for_analysis: true`, removes the function/string/basic-block/instruction caps unless you pass explicit caps, and adds `capabilities.liveExport` metadata with totals, exported counts, and truncation flags. If a cap is passed with `full_export: true`, truncation fails the export by default. Set `fail_on_truncation: false` only when a partial export is acceptable.

To capture pseudocode in the snapshot, opt in explicitly:

```json
{
  "executable_path": "/path/to/binary",
  "wait_for_analysis": true,
  "include_pseudocode": true,
  "max_pseudocode_functions": 25
}
```

Pseudocode export can be slow, so it is off by default. Without it, `procedure(field: pseudo_code)` returns a clear "not captured" result.

Deep local import:

```json
{
  "executable_path": "/path/to/binary",
  "deep": true,
  "max_functions": 5000,
  "max_strings": 50000
}
```

With `deep: true`, `import_macho` also scans ARM64 disassembly with `otool`, discovers frame-prologue functions, builds call edges from `bl` instructions, and links ADRP+ADD/LDR string references where they can be resolved.

Local helper tools:

- `disassemble_range`: disassemble a VM address range with `otool`.
- `find_xrefs`: scan for direct branches/calls and ADRP+ADD/LDR references to an address.
- `find_functions`: discover ARM64 frame-prologue functions, optionally with `merge_session: true`.

For official tools that are not mirrored, use `official_hopper_call`. Write/navigation official tools are blocked by default; enabling them requires both `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` in the server environment and `confirm_live_write: true` on the call.

Direct official calls cap large text results by default so a single decompile does not overwhelm the client. Pass `max_result_chars` to tune the preview size, or `include_full_result: true` if the client can safely handle the full result in `structuredContent`.

To refresh this server's local snapshot from Hopper's official live backend, call:

```json
{
  "max_procedures": 500,
  "include_procedure_info": true,
  "include_assembly": false,
  "include_pseudocode": false,
  "include_call_graph": false
}
```

as `ingest_official_hopper`. This gives our resource/cache layer a current official-Hopper snapshot without relying on private Hopper APIs. Keep `include_assembly`, `include_pseudocode`, and `include_call_graph` off unless needed; they require per-procedure official backend calls and can be slow on large documents.

To commit a reviewed local transaction through the official backend:

```json
{
  "transaction_id": "txn-id",
  "backend": "official",
  "confirm_live_write": true
}
```

The server must also be started with `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1`. Operations with no official-backend equivalent (such as `queue(kind: type_patch)`) are rejected rather than silently applied only to the local cache.

## Add To Clients

Replace `/path/to/hopper-mcp` with the absolute path to this repo.

Generic MCP JSON:

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

Claude Code:

```bash
claude mcp remove hopper -s user
claude mcp add -s user hopper -- node /path/to/hopper-mcp/src/mcp-server.js
claude mcp list
```

Codex:

```bash
codex mcp remove hopper
codex mcp add hopper -- node /path/to/hopper-mcp/src/mcp-server.js
codex mcp list
```

Cursor:

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "hopper": {
      "command": "node",
      "args": ["/path/to/hopper-mcp/src/mcp-server.js"],
      "env": {}
    }
  }
}
```

Claude Desktop:

Edit the Claude Desktop config and add the same server entry under `mcpServers`:

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

MCP Inspector:

```bash
npx @modelcontextprotocol/inspector node /path/to/hopper-mcp/src/mcp-server.js
```

To remove older Hopper entries, delete any other `hopper`, `HopperMCPServer`, or Hopper-related server blocks from the same client config before adding this one.

## MCP Surface

Tools follow a strict invariant: every tool is one of (a) a snapshot reader,
(b) the live passthrough `official_hopper_call`, or (c) a mutator. There is no
per-tool `backend:` flag — live access goes through `official_hopper_call`,
and live writes go through `commit_transaction(backend:"official")` (gated by
`HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` and `confirm_live_write: true`).

**Meta (2)**
- `capabilities`
- `official_hopper_call`

**Lifecycle / ingest (6)**
- `import_macho`
- `ingest_live_hopper`
- `ingest_official_hopper`
- `open_session`
- `close_session`
- `set_current_session`

**Local binary helpers (3)**
- `disassemble_range`
- `find_xrefs`
- `find_functions`

**Snapshot reads (9)**
- `procedure(field: info|assembly|pseudo_code|callers|callees|comments)`
- `search(kind: strings|procedures|names)`
- `list(kind: procedures|strings|names|segments|bookmarks|imports|exports)`
- `xrefs`, `containing_function`, `resolve`, `query`, `analyze_function_deep`, `get_graph_slice`

**Transactions (6)**
- `begin_transaction`, `queue(kind: …)`, `hypothesis(action: …)`, `preview_transaction`, `commit_transaction`, `rollback_transaction`

**Forensics (4)**
- `analyze_binary(kind: capabilities|anti_analysis|entropy|code_signing|objc)`
- `compute_fingerprints`, `find_similar_functions`, `diff_sessions`

**Resources** — 30 entries; see `src/server-resources.js`.

**Prompts** — `function_triage`, `hypothesis_workspace`.

## Protocol Notes

- Stdio transport uses newline-delimited JSON-RPC.
- The server supports MCP protocol versions `2025-11-25`, `2025-06-18`, and `2025-03-26`.
- Tool results include both `structuredContent` and a JSON text block.
- Ingest tools emit progress notifications when the client supplies a progress token.
- Session changes emit `notifications/resources/list_changed`.

## Layout

```text
MCP client
  -> Node stdio server
  -> JSON store
  -> Hopper live exporter
  -> Hopper
```

Main files:

- `src/mcp-server.js`
- `src/hopper-live.js`
- `src/knowledge-store.js`
- `src/transaction-manager.js`
- `docs/adapter-protocol.md`
- `docs/official-hopper-mcp-notes.md`
