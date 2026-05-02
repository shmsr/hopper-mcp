# Ground-Up Hopper MCP Design

Date: 2026-04-30

## Goal

Build a production Hopper MCP that is faster and more capable than Hopper's official MCP server while staying correct, testable, and explicit about trust boundaries.

The production path should not be JavaScript. JavaScript remains useful only as a compatibility prototype and migration reference.

## Non-Goals

- Do not expose `otool`, `nm`, `strings`, or `codesign` as public fallback analysis tools.
- Do not fabricate facts that Hopper did not analyze or export.
- Do not make private API injection invisible. Private capability must be opt-in, version-gated, and observable.
- Do not require the private backend for basic snapshot querying.

## Architecture

The rewrite is split into three production components:

1. `hopper-mcpd`: Rust MCP daemon.
2. `hopper-agent`: native Hopper-side private backend, written in Objective-C++ first, with Swift only where it improves installer/UI work.
3. `hopper-wire`: versioned local protocol shared by daemon and agent.

Rust owns all client-facing MCP behavior. The native agent owns direct Hopper integration only. This avoids putting MCP protocol logic inside an injected process and keeps private API failures contained.

```text
MCP client
  -> hopper-mcpd (Rust, stdio MCP)
    -> snapshot/index/query/transactions
    -> hopper-wire local transport
      -> hopper-agent (native, inside or beside Hopper)
        -> Hopper public/private APIs
```

## Language Decision

Rust is the daemon language because it gives a single distributable binary, strict data modeling, strong testability, low memory overhead, fast indexing, and safe concurrency. It is the right place for MCP protocol handling, JSON/schema validation, snapshot persistence, graph traversal, fingerprints, diffing, search, and transaction planning.

Objective-C++ is the first private backend language because Hopper is a macOS Objective-C application and private API work depends on Objective-C runtime inspection, selectors, AppKit behavior, method signatures, dynamic dispatch, and, if needed, injection/plugin lifecycle hooks. Swift can be used for installer-facing code, but it should not be the first choice for reverse-engineered private runtime work.

JavaScript is not a production target. The existing Node implementation should be treated as a behavior oracle and migration harness until Rust reaches feature parity.

## Backend Modes

### Safe Backends

Safe backends require no SIP changes:

- `official`: calls Hopper's installed MCP server.
- `python`: launches Hopper and runs a Python exporter.
- `snapshot`: opens a previously exported normalized session.

These backends remain valuable for compatibility, CI smoke tests, and users who do not want private API installation.

### Private Backend

The private backend is opt-in and capability-gated:

- `backend: "private"` explicitly requests it.
- `backend: "auto"` may choose it only if installed, healthy, and compatible with the current Hopper build.
- The daemon reports private backend state in `capabilities`: installed, connected, Hopper version/build, agent version, selector table version, supported tools, and unsupported reasons.

Private backend failures must fail closed. If selector resolution fails or Hopper's private ABI changes, the daemon returns a precise unsupported/error state instead of falling back to guessed data.

## Private Backend Capability Targets

The private backend should eventually support:

- Current document discovery and stable document IDs.
- Procedure enumeration without waiting for full Python export.
- Assembly, pseudocode, CFG, callers, callees, xrefs, strings, names, comments, inline comments, bookmarks, imports, exports, segments.
- Address navigation and selected-range reads.
- Safe write operations: rename, comment, inline comment, tags/bookmarks where Hopper supports them.
- Batch reads to reduce round-trips.
- Versioned capability probing so tools can degrade explicitly.

## Transport

Use Unix domain sockets first. XPC can be added later if the installer/helper needs macOS service semantics.

The wire protocol should be small and versioned:

- Handshake: daemon version, agent version, wire version, Hopper version/build, capability bitmap.
- Requests: JSON initially for debuggability; MessagePack can be added after protocol stability if profiling proves JSON overhead matters.
- Responses: normalized records with provenance and truncation metadata.
- Errors: typed, structured, and user-actionable.

The daemon remains the only MCP server. The agent never speaks MCP directly.

## Installation Model

Provide a separate installer/check tool rather than hiding private setup in normal MCP startup:

- `hopper-install check`: reports SIP/TCC/Hopper compatibility and whether the private backend can be installed.
- `hopper-install install-private`: installs the agent/plugin/helper.
- `hopper-install uninstall-private`: removes it.
- `hopper-install doctor`: validates Hopper launch, agent connection, version match, socket permissions, and a minimal document read.

If SIP disabling or special permissions are required, the tool reports exact steps but does not pretend it can bypass macOS security prompts.

## Data Model

All backends normalize into one Rust-owned session model:

- `Session`: document identity, binary metadata, capabilities, provenance.
- `Function`: address, name, size/range, assembly, pseudocode, CFG, xrefs, callers/callees, locals, strings, imports, comments.
- `Graph`: caller/callee and CFG slices.
- `Transaction`: queued edits with preview and apply status.

Every field that came from Hopper includes provenance:

- backend name.
- Hopper version/build if live.
- export timestamp.
- truncation/cap status.
- confidence where applicable.

## Tool Surface

The Rust daemon should expose stable high-level tools, not backend internals:

- Ingest/session: `open_session`, `ingest_current_hopper`, `ingest_live_hopper`, `set_current_session`, `close_session`.
- Reads: `list`, `search`, `resolve`, `procedure`, `xrefs`, `containing_function`, `get_graph_slice`, `analyze_function_deep`, `query`.
- Forensics/index: `compute_fingerprints`, `find_similar_functions`, `diff_sessions`, `analyze_binary`.
- Transactions: `begin_transaction`, `queue`, `preview_transaction`, `commit_transaction`, `rollback_transaction`, `hypothesis`.
- Backend operations: `capabilities`, `backend_status`, `backend_diagnostics`.

Backend selection is an argument on relevant tools, not a separate duplicate tool namespace.

## Correctness Rules

- No silent backend fallback when it changes evidence quality.
- No private writes without preview and explicit confirmation.
- No destructive Hopper document operations without a clear flag.
- No unbounded reads by default. All high-cardinality outputs need caps and truncation metadata.
- No regex or query path that can cause ReDoS or huge unbounded responses.
- No stale session ambiguity: tools must state which session/document they read.

## Testing Strategy

### Rust Daemon Tests

- Unit tests for store normalization, address parsing, query parser, graph traversal, fingerprints, diffs, transactions, and schema validation.
- Stdio MCP contract tests for initialize, tools/list, tools/call, resources/list, resources/read, and error envelopes.
- Golden cassette tests for MCP protocol compatibility.
- Fuzz/property tests for query parsing, address normalization, and snapshot deserialization.

### Wire Protocol Tests

- Agent mock tests for every request/response type.
- Version negotiation tests.
- Timeout, disconnect, malformed response, and capability mismatch tests.

### Native Agent Tests

- Pure Objective-C++ tests for selector resolution and serialization where possible.
- Hopper live smoke tests gated behind an explicit env flag.
- Matrix over small system binaries, large Swift apps, Objective-C apps, Electron apps, and malformed/unsupported binaries.
- Failure-mode tests for unsupported Hopper versions and missing permissions.

### End-to-End Tests

- Snapshot-only offline suite must pass on CI without Hopper.
- Safe live suite runs with Hopper installed.
- Private live suite runs only on a dedicated macOS machine configured for the private backend.

## Migration Plan

Phase 1: Rust daemon parity for snapshot reads and transactions.

Phase 2: Rust daemon owns persistence, resources, prompts, query engine, fingerprints, diffs, and protocol tests.

Phase 3: Introduce `hopper-wire` and a mock agent; implement daemon backend abstraction.

Phase 4: Build native private agent with read-only capabilities first.

Phase 5: Add private write capabilities behind transaction preview and explicit confirmation.

Phase 6: Mark Node as legacy and remove it from the production path after Rust/private backend reaches parity.

## Open Risks

- Hopper private APIs may change without notice. Mitigation: version-gated selector tables and fail-closed capability probing.
- SIP-off/injection reduces system security. Mitigation: separate opt-in installer, clear diagnostics, and safe backend fallback.
- Running logic inside Hopper can crash Hopper. Mitigation: keep the agent thin, put indexing in Rust, and batch small read operations.
- GUI state can block automation. Mitigation: prefer direct agent reads over GUI/AppleScript paths.
- Private API licensing/support risk. Mitigation: keep official/Python backends available and label private mode explicitly.

## Approval Criteria

This design is approved when we agree that:

- Rust is the production MCP daemon.
- Objective-C++ is the private Hopper backend language.
- JavaScript is migration/prototype only.
- Private API support is allowed but capability-gated and fail-closed.
- The next step is an implementation plan for Phase 1 through Phase 3 before private injection work begins.
