# Hopper MCP

An MCP server that gives an LLM client structured, transaction-safe access to a [Hopper](https://www.hopperapp.com) reverse-engineering session — without putting the disassembler in the model's context window.

Two ways to load a binary:

- **Local Mach-O** (fast, no Hopper required) — `import_macho` parses the binary with `otool` / native macOS tools.
- **Live Hopper** (slower, full analysis) — `ingest_live_hopper` opens the binary in Hopper, runs an in-app Python exporter, and ingests the analyzed document.

Reads (`resolve`, `procedure`, `search`, `analyze_binary`, …) hit a local indexed snapshot so they're cheap to call repeatedly. Writes (renames, comments, tags, hypotheses) go through a `begin_transaction → queue → preview → commit` pipeline. By default commits land in the local store only; flipping `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` plus `confirm_live_write: true` routes them through Hopper's official MCP server too.

## Requirements

- macOS
- Node.js 20+
- Hopper.app installed (only required for `ingest_live_hopper` / `ingest_official_hopper` / official-backend writes; the local importer works without it)
- Automation permission for the launcher app, granted via *System Settings → Privacy & Security → Automation*

## Install

```bash
git clone <this repo> hopper-mcp
cd hopper-mcp
npm install
npm test            # 119 offline tests, ~12s
npm run test:live   # adds the live-Hopper suite (HOPPER_MCP_LIVE=1)
```

## Add to a client

Replace `/abs/path/to/hopper-mcp` with the absolute path to your clone.

**Claude Code**

```bash
claude mcp add -s user hopper -- node /abs/path/to/hopper-mcp/src/mcp-server.js
```

**Codex CLI**

```bash
codex mcp add hopper -- node /abs/path/to/hopper-mcp/src/mcp-server.js
```

**Cursor / Claude Desktop / generic MCP** — add to the client's `mcpServers` JSON:

```json
{
  "mcpServers": {
    "hopper": {
      "command": "node",
      "args": ["/abs/path/to/hopper-mcp/src/mcp-server.js"],
      "env": {}
    }
  }
}
```

**MCP Inspector** (for poking at the server interactively):

```bash
npx @modelcontextprotocol/inspector node /abs/path/to/hopper-mcp/src/mcp-server.js
```

If you previously installed any other Hopper-related MCP entry, remove it first — running both at once will confuse the client's tool registry.

## Workflows

### Quick local triage (no Hopper needed)

```jsonc
// import_macho
{ "executable_path": "/path/to/binary", "max_strings": 10000 }
```

The local importer auto-selects the architecture (`arm64e` → `arm64` → `x86_64`). Pass `arch` only when you need a specific slice. For a deeper local analysis that scans ARM64 disassembly, finds frame-prologue functions, builds call edges from `bl`, and links ADRP+ADD/LDR string refs:

```jsonc
// import_macho
{ "executable_path": "/path/to/binary", "deep": true, "max_functions": 5000 }
```

### Full Hopper analysis

```jsonc
// ingest_live_hopper
{
  "executable_path": "/path/to/binary",
  "wait_for_analysis": true,
  "full_export": true
}
```

`full_export: true` removes the function/string/basic-block caps and records `capabilities.liveExport` totals so the client can tell if anything was truncated. Pseudocode is opt-in (`include_pseudocode: true`) because it's expensive.

### Refresh from Hopper's official live backend

If Hopper is open with the document already analyzed, `ingest_official_hopper` pulls a snapshot through Hopper's installed MCP server:

```jsonc
{ "max_procedures": 500, "include_procedure_info": true }
```

Keep `include_assembly` / `include_pseudocode` / `include_call_graph` off unless you need them — each adds a per-procedure round-trip.

### Annotation lifecycle

```text
begin_transaction              → returns transactionId
queue(kind: rename | comment | inline_comment | type_patch | tag | untag | rename_batch)
hypothesis(action: create | link | status)
preview_transaction            → review what's about to land
commit_transaction             → applies to local store; optionally to Hopper
rollback_transaction           → discards
```

Local-only commits return `appliedToHopper: false`. To write back through Hopper:

```jsonc
// commit_transaction
{ "transaction_id": "txn-…", "backend": "official", "confirm_live_write": true }
```

Both `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` (server env) AND `confirm_live_write: true` (call arg) are required. Operations with no official-backend equivalent (e.g. `type_patch`) fail rather than silently apply only to the local cache.

### Direct passthrough

`official_hopper_call` calls any tool exposed by Hopper's installed MCP server. Large text results are capped by default; pass `max_result_chars` to widen the preview or `include_full_result: true` to receive the untruncated payload in `structuredContent`.

## Tool surface (30 tools)

Every tool is one of: a snapshot reader, the live passthrough `official_hopper_call`, or a mutator. Live access is only via `official_hopper_call`; live writes are only via `commit_transaction(backend: "official")`.

| Group | Tools |
|---|---|
| **Meta** | `capabilities`, `official_hopper_call` |
| **Lifecycle / ingest** | `import_macho`, `ingest_live_hopper`, `ingest_official_hopper`, `open_session`, `close_session`, `set_current_session` |
| **Local binary helpers** | `disassemble_range`, `find_xrefs`, `find_functions` |
| **Snapshot reads** | `procedure`, `search`, `list`, `xrefs`, `containing_function`, `resolve`, `query`, `analyze_function_deep`, `get_graph_slice` |
| **Transactions** | `begin_transaction`, `queue`, `hypothesis`, `preview_transaction`, `commit_transaction`, `rollback_transaction` |
| **Forensics** | `analyze_binary`, `compute_fingerprints`, `find_similar_functions`, `diff_sessions` |

Discriminator-style tools (`procedure`, `search`, `list`, `queue`, `hypothesis`, `analyze_binary`) take a `kind:` (or `action:` / `field:`) argument that selects the variant.

**Resources** — 30 `hopper://` URIs (binary metadata, strings, functions, graph slices, transactions, …); see `src/server-resources.js`.

**Prompts** — `function_triage`, `hypothesis_workspace`.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `HOPPER_MCP_STORE` | `<repo>/data/knowledge-store.json` | Path to the JSON store. Use a per-project path to keep sessions separate. |
| `HOPPER_MCP_SESSION_CAP` | `16` | Max sessions kept on disk (oldest evicted by `updatedAt`; current session is pinned). |
| `HOPPER_MCP_ENABLE_OFFICIAL_WRITES` | unset | Set to `1` to allow live writes through Hopper's official MCP server. Each call must also pass `confirm_live_write: true`. |
| `HOPPER_MCP_SOCKET` | unset | Reserved for the future in-process Hopper adapter. |
| `HOPPER_LAUNCHER` | unset | Override the path used to launch Hopper for live ingest. |
| `HOPPER_MCP_DEBUG` | unset (file logging on) | `0` disables debug logging entirely. `1` or `stderr` additionally mirrors records to stderr. |
| `HOPPER_MCP_DEBUG_LOG` | `<repo>/data/debug.log` | Override the structured NDJSON log path. |
| `HOPPER_MCP_LIVE` | unset | Test-only — `1` opts into the live test suite. |

## Debugging

The server writes a structured NDJSON log to `data/debug.log` by default — one record per line, including matched `tool_start` / `tool_end` pairs, lifecycle events (`boot`, `store_loaded`, `transport_connected`, `shutdown`), and crash sentinels (`uncaughtException`, `unhandledRejection`, EPIPE) with a snapshot of currently in-flight tool calls.

```bash
tail -f data/debug.log | jq .
```

Useful queries:

```bash
# Was the last shutdown clean?
grep -E '"kind":"(shutdown|uncaught|unhandled)"' data/debug.log | tail

# Slowest tool calls in the most recent run
grep '"kind":"tool_end"' data/debug.log | jq -r '[.ms,.name] | @tsv' | sort -nr | head

# Disable file logging entirely (e.g. for short-lived test harnesses)
HOPPER_MCP_DEBUG=0 node src/mcp-server.js
```

Shutdown is gated by an internal dirty bit: read-only tool batches exit in ~10ms (no full-store rewrite); only batches that mutated state pay the JSON serialization cost on the way out.

## Protocol notes

- Stdio transport, newline-delimited JSON-RPC.
- Supported MCP protocol versions: `2025-11-25`, `2025-06-18`, `2025-03-26`.
- Tool results carry both a JSON text block and `structuredContent`.
- Ingest tools emit `notifications/progress` when the client supplies a progress token.
- Session changes emit `notifications/resources/list_changed`.

## Layout

```text
MCP client
  → stdio JSON-RPC
  → src/mcp-server.js          process entry
    ├─ src/server-tools.js     30 tools
    ├─ src/server-resources.js hopper:// resource handlers
    ├─ src/server-prompts.js   prompts
    ├─ src/knowledge-store.js  durable JSON snapshot
    ├─ src/transaction-manager.js  begin / queue / preview / commit / rollback
    ├─ src/macho-importer.js   local Mach-O importer (otool-based)
    ├─ src/hopper-live.js      Hopper Python exporter driver
    ├─ src/official-hopper-backend.js  bridge to Hopper's installed MCP server
    └─ src/debug-log.js        structured NDJSON debug logger
  → data/knowledge-store.json  per-session indexed state
  → data/debug.log             diagnostic log
```

Further reading:

- `docs/adapter-protocol.md` — internal adapter wire format
- `docs/official-hopper-mcp-notes.md` — notes on Hopper's official MCP server
- `CONTRIBUTING.md` — dev setup and PR conventions

## License

MIT — see `LICENSE`.
