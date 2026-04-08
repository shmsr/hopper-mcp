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
npm run start
```

Quick checks:

```bash
npm run test:protocol
npm run smoke
npm run test:real
```

Live Hopper check:

```bash
LIVE_HOPPER_PARSE_OBJC=0 LIVE_HOPPER_PARSE_SWIFT=0 LIVE_HOPPER_TIMEOUT_MS=90000 LIVE_HOPPER_MAX_FUNCTIONS=20 LIVE_HOPPER_MAX_STRINGS=50 npm run test:live
```

Full tool check:

```bash
LIVE_HOPPER_PARSE_OBJC=0 LIVE_HOPPER_PARSE_SWIFT=0 LIVE_HOPPER_ANALYSIS=0 LIVE_HOPPER_TIMEOUT_MS=90000 LIVE_HOPPER_MAX_FUNCTIONS=20 LIVE_HOPPER_MAX_STRINGS=50 npm run test:tools
```

Official Hopper MCP backend check:

```bash
npm run test:official
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

Pseudocode export can be slow, so it is off by default. Without it, `procedure_pseudo_code` returns a clear “not captured” result.

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

Official-style Hopper snapshot tools:

- `list_documents`, `current_document`
- `list_segments`
- `list_procedures`, `list_procedure_size`, `list_procedure_info`, `search_procedures`
- `procedure_info`, `procedure_address`, `procedure_assembly`, `procedure_pseudo_code`
- `procedure_callers`, `procedure_callees`, `xrefs`
- `current_address`, `current_procedure`
- `list_strings`, `list_names`, `search_name`, `address_name`, `list_bookmarks`

These tools mirror Hopper concepts using the last ingested snapshot. They do not query the frontmost Hopper UI live after export; that still needs the future persistent Hopper-side adapter.
The mirror follows the official server's observed shapes where possible: procedure/string/name lists are address-keyed objects, search tools accept `pattern` and optional `case_sensitive`, and procedure assembly/pseudocode/current address/name calls return strings. The extended `search_strings` path still accepts `regex` plus `semantic: true` for richer local-store results.

To query Hopper's installed official MCP server through this server, pass:

```json
{
  "backend": "official"
}
```

on supported mirror tools such as `list_documents`, `procedure_info`, `procedure_assembly`, `xrefs`, and `list_names`. This gives live active-document behavior while keeping the rest of this server available for resources, caching, local Mach-O import, and transaction preview.

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

as `ingest_official_hopper` or `refresh_snapshot`. This gives our resource/cache layer a current official-Hopper snapshot without relying on private Hopper APIs. Keep `include_assembly`, `include_pseudocode`, and `include_call_graph` off unless needed; they require per-procedure official backend calls and can be slow on large documents.

To commit a reviewed local transaction through the official backend:

```json
{
  "transaction_id": "txn-id",
  "backend": "official",
  "confirm_live_write": true
}
```

The server must also be started with `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1`. Unsupported operations, such as `queue_type_patch`, are rejected rather than silently applied only to the local cache.

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

Resources:

- `hopper://session/current`
- `hopper://binary/metadata`
- `hopper://binary/imports`
- `hopper://binary/exports`
- `hopper://binary/strings`
- `hopper://names`
- `hopper://bookmarks`
- `hopper://comments`
- `hopper://inline-comments`
- `hopper://cursor`
- `hopper://functions`
- `hopper://function/{addr}`
- `hopper://function/{addr}/summary`
- `hopper://function/{addr}/evidence`
- `hopper://graph/callers/{addr}`
- `hopper://graph/callees/{addr}`
- `hopper://objc/classes`
- `hopper://swift/symbols`
- `hopper://transactions/pending`

Resource templates:

- `hopper://function/{addr}`
- `hopper://function/{addr}/summary`
- `hopper://function/{addr}/evidence`
- `hopper://graph/callers/{addr}?radius={radius}`
- `hopper://graph/callees/{addr}?radius={radius}`

Tools:

- `capabilities`
- `official_hopper_call`
- `official_hopper_tools`
- `ingest_official_hopper`
- `refresh_snapshot`
- `open_session`
- `ingest_sample`
- `ingest_live_hopper`
- `import_macho`
- `disassemble_range`
- `find_xrefs`
- `find_functions`
- `resolve`
- `analyze_function_deep`
- `get_graph_slice`
- `search_strings`
- `list_documents`
- `current_document`
- `list_segments`
- `list_procedures`
- `list_procedure_size`
- `list_procedure_info`
- `list_strings`
- `search_procedures`
- `procedure_info`
- `procedure_address`
- `procedure_assembly`
- `procedure_pseudo_code`
- `procedure_callers`
- `procedure_callees`
- `xrefs`
- `current_address`
- `current_procedure`
- `list_names`
- `search_name`
- `address_name`
- `list_bookmarks`
- `begin_transaction`
- `queue_rename`
- `queue_comment`
- `queue_inline_comment`
- `queue_type_patch`
- `preview_transaction`
- `commit_transaction`
- `rollback_transaction`

Internal test helpers such as `debug_echo` are hidden unless
`HOPPER_MCP_ENABLE_DEBUG_TOOLS=1` is set.

Prompts:

- `function_triage`
- `hypothesis_workspace`

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
