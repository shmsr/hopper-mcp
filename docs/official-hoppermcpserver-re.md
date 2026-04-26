# Official HopperMCPServer Reverse-Engineering Notes

These notes summarize interoperability-relevant findings from inspecting and
disassembling Hopper 6.2.6's bundled `HopperMCPServer` binary. They avoid
copying proprietary implementation code; the goal is to understand the protocol
boundary and design a more reliable MCP around Hopper.

## Binary Shape

- Path: `/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer`
- Format: universal Mach-O, `x86_64` and `arm64`
- Main frameworks: Foundation, AppKit, CoreFoundation, libobjc, libc++
- Code-signing identifier: `HopperMCPServer`
- Server identity reported over MCP: `HopperMCPServer` `1.0.0`
- MCP protocol version: `2025-03-26`
- Transport: newline-delimited JSON-RPC over stdin/stdout

The binary is not a disassembler. It is a small stdio MCP shim plus an
Objective-C XPC client into the Hopper app.

## Process Architecture

Observed flow:

1. Initialize logging.
2. Disable sudden and automatic termination while the XPC connection is active.
3. Create `NSXPCConnection` with service name `com.cryptic-apps.ExternalAPI`.
4. Set the remote interface to `@protocol(ExternalAPIProtocol)`.
5. Install invalidation/interruption/error handlers that log and terminate.
6. Resume the XPC connection.
7. Build the MCP tool registry.
8. Run a background stdio JSON-RPC loop while the main run loop stays alive.

Relevant strings and symbols:

- Hopper app bundle id: `com.cryptic-apps.hopper-web-4`
- XPC service name: `com.cryptic-apps.ExternalAPI`
- Log subsystem/category strings: `com.cryptic-apps.hopper.mcpserver`,
  `com.cryptic-apps.hopper`, `mcp-server`
- Objective-C protocol: `ExternalAPIProtocol`
- Launcher method: `+[HopperLauncher ensureHopperIsRunning]`

## Hopper Launch Behavior

`+[HopperLauncher ensureHopperIsRunning]` checks whether Hopper is already
running by bundle id. If not, it resolves the Hopper app URL through
`NSWorkspace`, launches it with an `NSWorkspaceOpenConfiguration`, and polls
until the app is running/finished launching.

Important detail: this launch path only ensures the app process exists. It does
not open/import an executable and does not control loader options. File opening
is outside the official MCP server's tool surface.

For our MCP, deterministic opening still needs the Hopper CLI, AppleScript, or a
Hopper-side Python bridge.

## Stdio JSON-RPC Loop

The server loop:

- Sets stdin non-blocking with `fcntl`.
- Uses `select()` on fd `0`.
- Reads from stdin with `read()`.
- Buffers until newline.
- Parses JSON.
- Dispatches on `method`.
- Writes JSON-RPC responses to stdout with `write()`.

Recognized JSON-RPC methods:

- `initialize`
- `tools/list`
- `tools/call`
- `notifications/initialized`

The method dispatch compares some short method names inline rather than via
normal string references, which is why string xrefs for `initialize`,
`tools/list`, and `tools/call` are sparse.

## Tool Dispatch Model

At startup the server builds a static MCP tool table from embedded strings. Each
tool has a JSON schema, description, and a handler that forwards to the Hopper
XPC proxy. The official server does not persist any document identity of its
own; most calls operate on Hopper's current document.

Tool-to-XPC selector mapping:

| MCP tool | XPC selector |
| --- | --- |
| `list_documents` | `documentListWithReply:` |
| `current_document` | `currentDocumentWithReply:` |
| `set_current_document` | `setCurrentDocument:withReply:` |
| `list_segments` | `segmentListWithReply:` |
| `list_procedures` | `procedureListWithReply:` |
| `list_procedure_size` | `procedureSizeListWithReply:` |
| `list_procedure_info` | `procedureInfoListWithReply:` |
| `list_strings` | `stringListWithReply:` |
| `search_strings` | `searchStringUsingPattern:caseSensitive:withReply:` |
| `search_procedures` | `searchProcedureUsingPattern:caseSensitive:withReply:` |
| `procedure_info` | `infoOfProcedure:withReply:` |
| `procedure_address` | `addressOfProcedure:withReply:` |
| `current_address` | `currentAddressWithReply:` |
| `current_procedure` | `currentProcedureWithReply:` |
| `goto_address` | `gotoAddress:withReply:` |
| `procedure_assembly` | `asmOfProcedure:withReply:` |
| `procedure_pseudo_code` | `pseudoCodeOfProcedure:withReply:` |
| `procedure_callers` | `callersOfProcedure:withReply:` |
| `procedure_callees` | `calleesOfProcedure:withReply:` |
| `xrefs` | `referencesToAddress:withReply:` |
| `comment` | `commentAtAddress:withReply:` |
| `inline_comment` | `inlineCommentAtAddress:withReply:` |
| `set_comment` | `setComment:atAddress:withReply:` |
| `set_inline_comment` | `setInlineComment:atAddress:withReply:` |
| `next_address` | `nextAddress:withReply:` |
| `prev_address` | `prevAddress:withReply:` |
| `list_names` | `nameListWithReply:` |
| `search_name` | `searchNameUsingPattern:caseSensitive:withReply:` |
| `address_name` | `nameOfAddress:withReply:` |
| `set_address_name` | `setNameOfAddress:to:withReply:` |
| `set_addresses_names` | `setNamesOfAddresses:withReply:` |
| `list_bookmarks` | `bookmarkListWithReply:` |
| `set_bookmark` | `setBookmarkAtAddress:withName:withReply:` |
| `unset_bookmark` | `unsetBookmarkAtAddress:withReply:` |

The protocol also contains `registerAppEndpoint:withReply:`. The server uses it
as part of wiring the app endpoint, not as an exposed MCP tool.

## What The Official Server Does Not Do

The official server does not expose:

- Open/import executable.
- Open database.
- Close document.
- Wait for analysis.
- Stop background analysis.
- Save database.
- Run Python script/command.
- Address a document by executable path or stable document id.
- Query or set loader options.

Those omissions are why wrapping the official server alone cannot become a
production-grade Hopper lifecycle backend.

## Concurrency Implications

The official MCP server is active-document oriented. `set_current_document`
changes Hopper global UI/app state, and later reads/writes follow whichever
document Hopper considers current.

Production rules for our MCP:

- Use one shared official backend process, not multiple competing official MCP
  subprocesses.
- Serialize all calls that can change current document or cursor:
  `set_current_document`, `goto_address`, writes, open/import, close.
- For a document-scoped operation, acquire a Hopper mutex, select the document,
  verify `current_document`, perform the call, and verify again when practical.
- Prefer cached/local snapshot reads when exact live state is not required.
- Do not rely on display name as a stable identity. Use executable path,
  database path, arch/options, and our session id.

## Relation To The Loader Dialog

The official MCP server does not open files, so it cannot control the loader
dialog shown during imports. That dialog comes from Hopper's open/import path.
Different checkbox defaults can come from Hopper UI state, loader plugin
defaults, and incomplete open parameters.

For deterministic imports, use one of:

- Hopper CLI helper with explicit flags, e.g. `-e`, `-a/-A`, `-o/-O`, `-f/-F`,
  `-z/-Z`, plus loader selection/options where available.
- AppleScript `open executable ... with options ...`.
- Best long-term: a Hopper-side Python bridge launched at open time, which
  exports from the exact `Document` object and can close that object.

## Recommended Production Design

Use the official MCP only as a live active-document adapter. Build robust
lifecycle and document identity outside it:

1. Local Mach-O analyzer/cache for parallel-safe metadata and fallback.
2. Official MCP adapter for live read/write parity with Hopper UI.
3. Hopper Python bridge for exact-document operations: open result export,
   wait/stop analysis, close, save, document path matching, comments, names,
   tags, xrefs, and decompilation.

The Python bridge is the path that fixes the hard lifecycle bugs: exact close,
exact document matching, analysis waiting, and import/export without depending
on whichever document is currently selected.

## Evidence Anchors

- `EntryPoint` at `0x1000011dc`: creates the XPC connection, remote interface,
  error handlers, dispatch worker, and main run loop.
- `+[HopperLauncher ensureHopperIsRunning]` at `0x1000010ac`: launch/readiness
  helper for the Hopper app.
- Large tool-table builder/block at `0x1000016b8`: embeds tool names,
  descriptions, schemas, and per-tool handlers.
- Stdio server loop around `0x10000d65c`: `fcntl`, `select`, `read`, line
  buffering, and server start/end logging.
- JSON-RPC dispatcher around `0x10000dbdc`: extracts `id`, `method`, and
  `params`, handles parse/method errors, and dispatches `initialize`,
  `tools/list`, and `tools/call`.
