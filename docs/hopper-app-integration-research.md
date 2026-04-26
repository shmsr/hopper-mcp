# Hopper App Integration Research

Clean-room notes from inspecting Hopper 6.2.6's installed app bundle, bundled
AppleScript dictionary, bundled Python API documentation, official MCP tool
schemas, and small behavioral probes. This deliberately avoids decompiling or
copying proprietary implementation code.

## Installed Surfaces

Hopper ships these integration surfaces:

- App bundle: `/Applications/Hopper Disassembler.app`
- GUI executable: `Contents/MacOS/Hopper Disassembler`
- CLI launcher helper: `Contents/MacOS/hopper`
- Official MCP server: `Contents/MacOS/HopperMCPServer`
- AppleScript dictionary: `Contents/Resources/Hopper.sdef`
- Python scripting API reference: `Contents/Resources/hopper_api.py`

`Info.plist` reports `NSAppleScriptEnabled=true` and `OSAScriptingDefinition=Hopper.sdef`.

## Opening And Importing

There are two reliable open paths.

### AppleScript

`Hopper.sdef` exposes `open executable` and `open database`.

Important `open executable` parameters:

- `analysis`: start background analysis after load.
- `parse objectivec`: parse Objective-C metadata.
- `parse swift`: parse Swift metadata.
- `parse exceptions`: parse exception metadata.
- `only procedures`: treat code section as procedures only.
- `branch stops procedures`: branch instructions always stop procedures.
- `jump to address`: set cursor after load.
- `base address`: rebase non-raw loads.
- `execute Python script`: run a Python script after initial analysis.
- `execute Python command`: run a Python command after initial analysis.
- `with options`: loader option records, including loader name, CPU plugin,
  CPU family/subfamily, string/address/checkbox/combobox options.

This is the most controllable route when we need to run an exporter script at
load time. It requires macOS Automation permission for the launching process.

### CLI Launcher

`Contents/MacOS/hopper` is a dedicated launcher, not the GUI binary. Its usage
surface maps closely to the AppleScript command:

- `-e` / `--executable`: open executable.
- `-d` / `--database`: open `.hop`.
- `-Y` / `--python`: execute Python script after initial analysis.
- `-y` / `--python-command`: execute Python command after initial analysis.
- `-a` / `-A`: enable/disable analysis.
- `-o` / `-O`: enable/disable Objective-C metadata.
- `-f` / `-F`: enable/disable Swift metadata.
- `-z` / `-Z`: enable/disable exception metadata.
- `-j`, `-r`: jump/rebase.
- `-l` plus loader-specific options: loader chain selection.

Behavioral probe result: opening `/bin/echo` with the CLI created an in-memory
document named `echo.hop`, with executable path `/bin/echo`, no database path,
4 segments, 11 procedures, and `backgroundProcessActive=false` when the post-load
Python script ran.

Production implication: document matching must accept both `basename` and
`basename.hop`, because AppleScript and CLI paths can expose different display
names.

## Python API Capabilities

The bundled Python API is the richest public interface. Key classes:

- `Document`: document lifecycle, cursor, segments, tags/colors, names, bytes,
  save/load, background analysis.
- `Segment`: sections, byte reads/writes, types, comments, labels, references,
  procedures, strings.
- `Procedure`: entrypoint, basic blocks, callers/callees, locals, signature,
  decompile, local labels, tags.
- `BasicBlock`, `Instruction`, `Section`, `Tag`, `CallReference`.

Lifecycle methods worth designing around:

- `Document.getCurrentDocument()`
- `Document.getAllDocuments()`
- `doc.closeDocument()`
- `doc.getDocumentName()`
- `doc.getExecutableFilePath()`
- `doc.getDatabaseFilePath()`
- `doc.backgroundProcessActive()`
- `doc.requestBackgroundProcessStop()`
- `doc.waitForBackgroundProcessToEnd()`

Read/write methods worth exposing through a production bridge:

- `doc.setNameAtAddress`, `doc.getNameAtAddress`, `doc.getAddressForName`
- `seg.setCommentAtAddress`, `seg.setInlineCommentAtAddress`
- `seg.getReferencesOfAddress`, `seg.getReferencesFromAddress`
- `proc.getAllCallers`, `proc.getAllCallees`
- `proc.getAllCallerProcedures`, `proc.getAllCalleeProcedures`
- `proc.signatureString`, `proc.decompile`
- `doc.addTagAtAddress`, `doc.setColorAtAddress`
- `seg.markAsProcedure`, `seg.markAsCode`, `seg.setTypeAtAddress`

Production implication: the best long-term MCP backend is a persistent
Hopper-side Python bridge or plugin that can address a specific `Document`
object, not only the global active document.

## Official MCP Behavior

The official MCP server is useful but active-document oriented:

- It exposes document selection, procedure info, strings, names, comments,
  bookmarks, xrefs, navigation, and write tools.
- It does not open/import files.
- It does not close documents.
- It operates on Hopper's current selected document unless `set_current_document`
  is called first.
- `set_addresses_names` is the efficient bulk rename path.
- Pseudocode generation can be slow; the official description recommends using
  it on procedures with fewer than roughly 50 basic blocks.

Production implication: every official-MCP call must be treated as global-state
access. A robust wrapper should select the document, verify the current document,
perform the operation, and avoid interleaving another operation that changes the
current document.

## Closing Documents

Observed close paths:

- In Python, `doc.closeDocument()` closes the exact document object.
- AppleScript standard document closing by document specifier/name is not
  reliable in this Hopper build. A probe of
  `close (every document whose name is "...") saving no` returned Apple event
  error `-1708`.
- The official MCP server has no close-document tool.

Behavioral probe result: a post-load Python script calling `doc.closeDocument()`
closed the probe document. After closing, `list_documents` returned no probe
document.

Production recommendation:

- For documents opened solely for a one-shot import, prefer a post-load Python
  script that exports then closes its own `doc` object.
- For already-open user documents, avoid auto-closing unless the user requested
  it.
- If only AppleScript/official MCP is available, return a structured
  unsupported/best-effort result. Do not claim the live document was closed.
- A persistent Python bridge should close by executable path or internal
  document object, not by display name.

## Concurrency Model

Hopper is document-based but has global current-document state.

Behavioral concurrent probe:

- Two CLI imports can be launched near the same time.
- Each post-load Python script saw its own `Document.getCurrentDocument()` when
  it began, but document lists showed transient states such as `Untitled`.
- The official MCP server always targets whichever document Hopper considers
  current at call time.

Current repo behavior already has the right high-level safety rule:

- `liveIngestQueue` serializes live imports.
- `liveIngestInFlight` deduplicates concurrent imports of the same executable.
- The singleton `OfficialHopperBackend` should be reused instead of spawning
  multiple official MCP subprocesses racing against the same Hopper UI.

Production rules:

- Serialize all operations that can change Hopper's current document:
  open/import, `set_current_document`, navigation, official writes, close.
- Allow concurrent local-store reads and local Mach-O imports.
- Allow concurrent official reads only when they are scoped through a
  document-operation mutex that selects/verifies the document first.
- Avoid making a document current just to answer from a cached snapshot.
- Treat document display names as unstable identifiers; prefer executable path,
  database path, and a generated session id.

## Recommended Production Architecture

Use three layers:

1. Local analyzer/cache
   - Mach-O importer, otool/nm/strings/codesign/objc extraction.
   - Safe for parallel use.
   - Good fallback when Hopper is unavailable or busy.

2. Official MCP adapter
   - Live active-document reads and simple writes.
   - Guard all writes behind preview + explicit confirmation.
   - Use a per-Hopper mutex and `set_current_document` verification.
   - Use `set_addresses_names` for batch renames.

3. Hopper Python bridge
   - Target state for production.
   - Runs inside Hopper and talks to this MCP server over a local socket or
     one-shot JSON files.
   - Maintains a document registry keyed by executable path/database path/name.
   - Exposes exact-document operations: export, wait/stop analysis, close,
     rename, comments, tags, xrefs, cursor, decompile.

## Open/Import Algorithm

For a production `open_or_import` tool:

1. Normalize executable path and desired loader/analysis options.
2. Check local session cache by executable path + mtime + arch/options.
3. Acquire Hopper lifecycle mutex.
4. Query open documents.
5. Reuse an open document only if:
   - name matches `basename` or `basename.hop`, and
   - the document has procedures/segments, and
   - if Python bridge is available, executable path matches exactly.
6. Otherwise open with CLI or AppleScript.
7. Wait for either:
   - Python exporter result file, or
   - official MCP procedure index becoming non-empty.
8. Export snapshot.
9. Apply explicit caps and truncation metadata.
10. Optionally close one-shot documents if requested.

## Close Algorithm

For `close_document`:

1. If Python bridge is available, find matching `Document` by executable path,
   database path, or session id and call `doc.closeDocument()`.
2. Else if AppleScript is available, close by display name with `saving no`.
3. Treat AppleScript error `-1708` as unsupported for this Hopper version.
4. Else return a structured unsupported result.
5. Update the local session store independently of live close success.

## Failure Modes To Surface

- Automation permission denied.
- Hopper accepted open request but loader is waiting for UI input.
- Background analysis still running after timeout.
- Official MCP current document changed during an operation.
- Duplicate document names.
- Document has no content or zero procedures.
- Pseudocode skipped because procedure is too complex.
- Partial export due caps.

## Immediate Repo Implications

Implemented/fixed while preparing this note:

- The CLI helper path should be `Contents/MacOS/hopper`.
- CLI launch arguments should use `-e`, `-a/-A`, `-o/-O`, and `-f/-F`.
- Live document matching should accept both `basename` and `basename.hop`.
- Existing `close_session close_in_hopper` can fail gracefully today, but exact
  live close needs the planned Python bridge or one-shot export-and-close flow.
- `ingest_live_hopper` now defaults to a one-shot Hopper-side Python exporter
  launched with the Hopper CLI `-Y` path. It captures the exact `Document`
  object, records `liveExport.backend = "hopper-python-bridge"`, supports
  `parse_exceptions`, and can close that exact document with
  `close_after_export=true`.
- Calls routed through the official MCP backend are serialized in-process to
  avoid interleaving current-document operations from this server.

Next high-value implementation steps:

- Add a `document_lock` helper around official backend calls that select or
  depend on current document.
- Add a first-class `close_document` tool separate from local `close_session`.
- Add an `open_or_reuse_hopper_document` helper with explicit document match
  diagnostics.
- Add a one-shot Python lifecycle exporter that can close its own document after
  export for non-user-owned imports.
- Prototype a persistent Python bridge with exact-document addressing.
