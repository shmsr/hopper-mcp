# Hopper MCP

MCP server for Hopper. It opens binaries in Hopper, exports indexed state through Hopper's Python scripting API, and exposes that state through MCP resources and tools.

Current write behavior is local-only: transaction commits update the JSON store and return `appliedToHopper: false`. Writing comments/renames back into an already-open Hopper window still needs the persistent Hopper-side adapter.

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

Full tool check against a live Hopper-ingested binary:

```bash
LIVE_HOPPER_PARSE_OBJC=0 LIVE_HOPPER_PARSE_SWIFT=0 LIVE_HOPPER_TIMEOUT_MS=120000 LIVE_HOPPER_MAX_FUNCTIONS=80 LIVE_HOPPER_MAX_STRINGS=200 npm run test:tools
```

If macOS blocks Automation, allow the launcher app to control Hopper in `System Settings > Privacy & Security > Automation`.

For large binaries, start with the faster local importer:

```json
{
  "executable_path": "/path/to/binary",
  "arch": "arm64",
  "max_strings": 10000
}
```

Call that as `import_macho`. Use `ingest_live_hopper` when you need Hopper's current document state.

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
- `open_session`
- `ingest_sample`
- `ingest_live_hopper`
- `import_macho`
- `resolve`
- `analyze_function_deep`
- `get_graph_slice`
- `search_strings`
- `begin_transaction`
- `queue_rename`
- `queue_comment`
- `queue_inline_comment`
- `queue_type_patch`
- `preview_transaction`
- `commit_transaction`
- `rollback_transaction`

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
