# Hopper Adapter Protocol

This project is intentionally split into a stateful MCP façade, a knowledge store, and a Hopper adapter.
The current live adapter can open an executable in Hopper, run an official in-Hopper Python exporter, and
ingest the resulting live document. A future persistent in-process adapter should apply transaction commits
back into already-open Hopper documents.

## Current Live Ingest

The current bridge is read-first:

1. MCP client calls `ingest_live_hopper`.
2. The Node MCP server creates a temporary Python exporter script.
3. The server runs AppleScript: `open executable ... execute Python script ...`.
4. Hopper opens the target, performs analysis, and executes the Python exporter in-process.
5. The exporter writes a normalized session JSON file.
6. The Node server ingests that session into the local knowledge store.

This avoids private interfaces and SIP-disabling injection. It does require macOS Automation permission for
the terminal host, which may appear as `Ghostty` in System Settings.

## Target Persistent Shape

The next Hopper-side adapter should run persistently in-process and talk to the daemon over a Unix domain socket or XPC.
It should prefer official Hopper SDK/Python APIs and expose any private-interface usage only behind
an explicit capability flag.

The daemon should receive normalized session documents:

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
    "privateApi": false,
    "dynamicDebugger": false
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
      "basicBlocks": [
        { "addr": "0x100003f50", "summary": "optional block note" }
      ]
    }
  ],
  "strings": [{ "addr": "0x100008000", "value": "license_key" }],
  "imports": ["_SecItemCopyMatching"],
  "exports": ["_main"],
  "objcClasses": [],
  "swiftSymbols": []
}
```

## Transaction Application

MCP write tools only queue and preview operations. On commit, the daemon sends the adapter:

```json
{
  "type": "apply_transaction",
  "sessionId": "hopper-session-id",
  "transaction": {
    "id": "txn-...",
    "operations": [
      {
        "kind": "rename",
        "addr": "0x100003f50",
        "oldValue": "sub_100003f50",
        "newValue": "validate_license_key",
        "rationale": "Evidence references keychain lookup and SHA256 digest comparison."
      }
    ]
  }
}
```

The adapter should return per-operation status and never silently coerce an address or symbol name.

## Next Bridge Milestones

1. Export current document metadata, functions, strings, imports, exports, comments, and xrefs.
2. Add pseudocode and basic block slices where the official API exposes them.
3. Add Objective-C selector/class extraction and Swift demangling metadata.
4. Add optional debugger state: selected thread, PC, registers, backtrace, memory reads, breakpoints.
5. Add private API capability reporting only if the user explicitly opts in.
