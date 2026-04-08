# Official Hopper MCP Notes

These notes are from clean-room behavioral testing of Hopper's installed MCP server over stdio JSON-RPC.
They do not depend on decompiling or copying the proprietary server implementation.

## Binary

- Path: `/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer`
- Server info: `HopperMCPServer` version `1.0.0`
- MCP protocol: negotiates to `2025-03-26`
- Capabilities: `tools` only
- Transport: stdio

The bundled Hopper help page documents configuring this binary directly as an MCP stdio server.

## Tool Surface

The official server exposes these tools:

```text
list_documents
current_document
set_current_document
list_segments
list_procedures
list_procedure_size
list_procedure_info
list_strings
search_strings
search_procedures
procedure_info
procedure_address
current_address
current_procedure
goto_address
procedure_assembly
procedure_pseudo_code
procedure_callers
procedure_callees
xrefs
comment
inline_comment
set_comment
set_inline_comment
next_address
prev_address
list_names
search_name
address_name
set_address_name
set_addresses_names
list_bookmarks
set_bookmark
unset_bookmark
```

## Observed Shapes

- `list_documents` returns an array of document names.
- `current_document` returns the active document name as a string.
- `list_segments` returns an array of segment objects with `name`, `start`, `end`, `writable`, `executable`, and `sections`.
- `list_procedures` returns an object keyed by procedure address with procedure names as values.
- `list_procedure_size` returns an object keyed by procedure address with `{ name, basicblock_count, size }`.
- `list_procedure_info` and `procedure_info` return objects with `entrypoint`, `name`, `basicblock_count`, `basicblocks`, `length`, `signature`, and `locals`.
- `list_strings`, `search_strings`, `list_names`, and `search_name` return objects keyed by address.
- `search_strings`, `search_procedures`, and `search_name` take `pattern` and optional `case_sensitive`.
- `current_address`, `current_procedure`, `procedure_address`, `procedure_assembly`, `procedure_pseudo_code`, `comment`, `inline_comment`, and `address_name` return strings.
- `procedure_callers`, `procedure_callees`, `xrefs`, and `list_bookmarks` return arrays.

## Behavioral Boundary

The official server is live-Hopper oriented: it queries and edits the active Hopper documents directly.
This project mirrors the read tools against the last ingested snapshot and keeps writes behind local transaction preview.
That means our mirror can provide MCP resources, caching, and large-binary fallbacks, but it does not replace a persistent in-process Hopper adapter for live UI/database parity.

## Combined Backend

This project can also call the official server as a subprocess. Supported mirror tools accept
`backend: "official"` to route the call to Hopper's official active-document server instead of the local
snapshot. The `official_hopper_call` tool can call non-mirrored official tools directly.

Official write/navigation tools are blocked unless `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` is present in the
server environment and the call passes `confirm_live_write: true`.
