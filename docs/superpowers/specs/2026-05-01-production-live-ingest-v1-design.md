# Production Live Ingest v1 Design

Date: 2026-05-01

## Goal

Make the Hopper MCP production-grade by moving live Hopper ingest onto the Rust production path with deterministic lifecycle handling, explicit diagnostics, and repeatable tests.

## Production-Grade Definition

For this milestone, "production-grade" means:

- The MCP client talks to `hopper-mcpd` as the primary server.
- Live ingest is exposed by the Rust daemon, not only by the JavaScript migration server.
- Hopper launch arguments are deterministic for FAT and non-FAT Mach-O inputs.
- The daemon returns clear backend status, timeout, cleanup, and failure diagnostics.
- No public tool fabricates local analysis with `otool`, `nm`, `strings`, or `codesign`.
- All new behavior has contract tests and a gated live test path.
- The release gate is documented and executable.

This milestone does not require private API injection, SIP-off installation, or write-back into Hopper. Those belong to later phases after the safe live ingest path is stable.

## Current Gap

The repository already declares Rust as the production path, but current live extraction still lives in `src/hopper-live.js` and the Rust daemon only supports `ingest_current_hopper` against a mock backend. This split means users can run the Rust MCP for snapshot/query workflows, but must rely on the JavaScript migration path for actual live Hopper export.

## Architecture

Add a safe live-ingest backend boundary to `hopper-mcpd` before introducing private injection:

```text
MCP client
  -> hopper-mcpd (Rust)
    -> live_ingest tool contract
    -> LiveIngestBackend trait
      -> Node migration bridge adapter for v1
      -> future native/private adapter
    -> normalized Rust SnapshotStore
```

The v1 implementation may delegate the actual Hopper Python exporter to the existing Node bridge as a subprocess, but Rust owns the MCP tool, schema, persistence, diagnostics, and session ingestion. This gives users one production MCP endpoint while allowing incremental replacement of the bridge.

## Tool Contract

Add `ingest_live_hopper` to the Rust daemon with a strict schema matching the stable subset of the Node tool:

- `executable_path` string, required.
- `timeout_ms` integer, optional.
- `max_functions` integer, optional.
- `max_strings` integer, optional.
- `analysis` boolean, optional.
- `loader` string, optional.
- `only_procedures` boolean, optional.
- `parse_objective_c` boolean, optional.
- `parse_swift` boolean, optional.
- `parse_exceptions` boolean, optional.
- `close_after_export` boolean, optional.
- `wait_for_analysis` boolean, optional.
- `full_export` boolean, optional.
- `include_pseudocode` boolean, optional.
- `max_pseudocode_functions` integer, optional.
- `overwrite` boolean, optional.

The returned structured content includes:

- `session`: normalized session descriptor from the Rust store.
- `launch`: launcher command/mode/arguments when safe to expose.
- `diagnostics`: backend name, elapsed milliseconds, timeout, and cleanup status.

## Lifecycle Rules

- Default `close_after_export` is `false` to avoid discarding a useful Hopper analysis window.
- Tests and throwaway agent runs should pass `close_after_export: true`.
- Timeouts must include the launcher mode and a user-actionable hint.
- If the bridge exits before producing JSON, the daemon returns a typed MCP error rather than ingesting partial data.
- Rust persists the store only after a successful session ingest.
- Rust must not silently fall back to local binary analysis.

## Testing

Required tests for this milestone:

- Rust tools list includes `ingest_live_hopper` as a strict read-write tool.
- Rust schema rejects unknown arguments.
- Rust bridge adapter ingests a fixture session from a fake bridge command.
- Rust bridge adapter reports malformed JSON as a structured error.
- Rust bridge adapter reports non-zero bridge exit as a structured error.
- Rust persistence test proves successful live ingest writes the store and failed ingest does not.
- Existing Node live test remains as a migration-reference gate.
- Gated live test exercises `/bin/echo` with `close_after_export: true`.

## Release Gate

The milestone is not complete unless these commands pass:

```bash
npm test
cargo fmt --check
cargo test --workspace
npm run test:live
```

`npm run test:live` requires Hopper and may remain opt-in for CI, but it must pass on the development machine before claiming production readiness for live ingest.

## Future Work

- Replace the Node bridge adapter with a native safe backend.
- Add Objective-C++ private agent for lower-latency direct reads.
- Add installer/doctor commands.
- Add macOS CI or a dedicated live-test runner.
- Add large real-app corpus tests.
