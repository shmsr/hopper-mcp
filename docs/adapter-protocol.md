# Hopper Adapter Protocol

The MCP server is split into a stateful façade, a knowledge store, and a Hopper
adapter. The adapter currently has two modes: a local Mach-O importer (no
Hopper required) and a live ingest that opens the binary in Hopper, runs an
in-app Python exporter, and ingests the resulting normalized session JSON.

## Live Ingest Flow

`ingest_live_hopper` is read-first:

1. MCP client calls `ingest_live_hopper`.
2. The Node MCP server creates a temporary Python exporter script.
3. The server runs AppleScript: `open executable ... execute Python script ...`.
4. Hopper opens the target, performs analysis, and executes the Python exporter in-process.
5. The exporter writes a normalized session JSON file.
6. The Node server ingests that session into the local knowledge store.

By default this returns a capped snapshot. Callers that need a completed
analysis pass should set `wait_for_analysis: true`; callers that need a strict
export should set `full_export: true`. Full export forces `wait_for_analysis`,
removes export caps unless explicit caps are supplied, and reports
`capabilities.liveExport` metadata with totals, exported counts, and truncation
flags. If explicit caps truncate a full export, the exporter fails unless
`fail_on_truncation: false` is set.

The exporter mirrors most of Hopper's public Python API into the snapshot:

- procedure metadata, signatures, locals, callers, callees, call refs, basic blocks, successors, and sampled assembly
- optional pseudocode with `include_pseudocode: true`
- segments, strings, names, bookmarks, prefix comments, inline comments, and captured cursor state

This avoids private interfaces and SIP-disabling injection. It does require
macOS Automation permission for the terminal host, which may appear as
`Ghostty` (or your terminal of choice) in System Settings.

## Session Document Shape

The exporter and `import_macho` both produce documents in this shape, which is
the contract the knowledge store ingests:

```json
{
  "sessionId": "hopper-session-id",
  "binaryId": "stable-binary-id",
  "binary": {
    "name": "Example",
    "path": "/path/to/Example",
    "format": "Mach-O",
    "arch": "arm64",
    "baseAddress": "0x100000000"
  },
  "capabilities": {
    "officialApi": true,
    "privateApi": false
  },
  "functions": [
    {
      "addr": "0x100003f50",
      "name": "sub_100003f50",
      "summary": "Optional adapter-provided summary",
      "callers": ["0x100004120"],
      "callees": ["0x100004010"],
      "strings": ["license_key"],
      "imports": ["_SecItemCopyMatching"],
      "pseudocode": "optional",
      "assembly": "optional sampled assembly",
      "signature": "int sub_100003f50(void)",
      "locals": [],
      "callerRefs": [],
      "calleeRefs": [],
      "basicBlocks": [
        { "addr": "0x100003f50", "end": "0x100003f90", "successors": [], "instructions": [] }
      ]
    }
  ],
  "strings": [{ "addr": "0x100008000", "value": "license_key" }],
  "names": [{ "addr": "0x100003f50", "name": "sub_100003f50" }],
  "bookmarks": [],
  "comments": [],
  "inlineComments": [],
  "cursor": { "address": "0x100003f50", "procedure": "0x100003f50", "selection": [] },
  "imports": ["_SecItemCopyMatching"],
  "exports": ["_main"],
  "objcClasses": [],
  "swiftSymbols": []
}
```
