# Hopper MCP

An MCP server that gives an LLM client structured, transaction-safe access to Hopper-derived reverse-engineering snapshots without putting the disassembler in the model's context window.

The production rewrite is `crates/hopper-mcpd`. It owns MCP stdio, snapshot indexing, query, resources, prompts, local transactions, persistence, Rust-side live ingest orchestration, and the versioned `hopper-wire` backend boundary. The JavaScript server is retained as a migration reference and live-export bridge until the native/private backend fully replaces it.

The public analysis surface is Hopper-native. It does not expose local `otool`, `nm`, `strings`, or `codesign` fallback tools; if Hopper has not analyzed or exported evidence, the server reports that gap instead of fabricating local heuristics.

## Current Rust Scope

- `open_session` loads a Hopper-derived JSON snapshot into the indexed Rust store.
- `ingest_current_hopper` exercises the backend boundary with either the mock backend or a configured private `hopper-wire` Unix-socket agent.
- `ingest_live_hopper` is exposed by the Rust daemon and delegates safe Hopper Python export to the Node live bridge.
- Snapshot read tools cover list/search/resolve/procedure/xrefs/containing function queries.
- Analysis tools cover graph slices, deep function summaries, fingerprints, similarity, diffs, and query DSL.
- Resources and prompts are exposed through MCP `resources/*` and `prompts/*`.
- Local transactions support rename, comment, and inline comment changes with preview/commit/rollback.
- `hopper-wire` pins the daemon-to-agent JSON contract with versioned request/response types.
- `agents/hopper-agent` builds an Objective-C++ Unix-socket agent artifact that speaks the `hopper-wire` handshake, current-document, and procedure-list protocol.
- `agents/hopper-tool-plugin` builds a signed Hopper Tool Plugin bundle that can expose the same `hopper-wire` protocol from inside Hopper using the official Hopper SDK.

Private Hopper live extraction is implemented on the daemon side as a fail-closed `hopper-wire` Unix-socket client and on the native side as packaged Objective-C++ agents. Today, non-fixture `hopper-agent` mode bridges real Hopper evidence through Hopper's bundled MCP subprocess and returns structured errors when Hopper has no current document. `HopperMCPAgent.hopperTool` is the direct in-Hopper plugin path and is built from the official SDK. The plugin now publishes a Foundation bridge service keyed off the configured plugin socket path, and `hopper-agent --plugin-service auto` can expose that service through the existing `hopper-wire` Unix socket contract. Hopper will only live-load that plugin when it is signed with a real Apple codesigning identity; ad-hoc signatures are sufficient for packaging smoke but are not sufficient evidence of live plugin acceptance. `hopper-agent --fixture` is only for tests/package smoke, so fixture data cannot be mistaken for live Hopper evidence.

## Requirements

- macOS
- Rust toolchain
- Node.js 20+ for npm wrappers, migration-reference tests, and the v1 live-export bridge
- Hopper.app installed for live ingest tests and workflows

## Install

```bash
git clone <this repo> hopper-mcp
cd hopper-mcp
npm install
npm run build:rust
npm run doctor
npm run test:rust
npm test
```

## Add To A Client

Replace `/abs/path/to/hopper-mcp` with the absolute path to your clone.

**Claude Code**

```bash
claude mcp add -s user hopper -- cargo run --manifest-path /abs/path/to/hopper-mcp/Cargo.toml -p hopper-mcpd --
```

**Codex CLI**

```bash
codex mcp add hopper -- cargo run --manifest-path /abs/path/to/hopper-mcp/Cargo.toml -p hopper-mcpd --
```

**Cursor / Claude Desktop / generic MCP**

```json
{
  "mcpServers": {
    "hopper": {
      "command": "cargo",
      "args": ["run", "--manifest-path", "/abs/path/to/hopper-mcp/Cargo.toml", "-p", "hopper-mcpd", "--"],
      "env": {}
    }
  }
}
```

**MCP Inspector**

```bash
npx @modelcontextprotocol/inspector cargo run --manifest-path /abs/path/to/hopper-mcp/Cargo.toml -p hopper-mcpd --
```

## Workflows

### Load A Hopper Snapshot

```jsonc
// open_session
{
  "session": {
    "sessionId": "calculator",
    "binary": {
      "name": "Calculator",
      "format": "hopper-snapshot",
      "arch": "arm64"
    },
    "functions": {
      "0x100003f50": {
        "name": "_main",
        "size": 96,
        "callees": ["0x100004010"]
      }
    }
  }
}
```

The Rust daemon normalizes addresses and indexes functions, resources, names, strings, comments, call edges, and transaction state from the snapshot.

### Exercise The Backend Boundary

```jsonc
// ingest_current_hopper
{ "backend": "mock" }
```

The mock backend returns a minimal `live-{documentId}` session and proves the daemon-to-agent seam. To require a configured native/private agent, set `HOPPER_MCP_PRIVATE_AGENT_SOCKET` and call:

```jsonc
// ingest_current_hopper
{ "backend": "private" }
```

The private path connects to the Unix socket, performs a `hopper-wire` versioned handshake, requests the current document and procedure list, and fails closed if the socket is missing, the wire version is rejected, Hopper reports no current document, or the configured backend is not private. `backend: "auto"` uses whichever backend the daemon was configured with; it does not silently switch evidence quality. By default, `hopper-agent` uses Hopper's bundled `HopperMCPServer` as its real evidence source; pass `--official-mcp-command PATH` to test against an alternate command.

### SIP-Off Private Backend Power Mode

This is a separate lane from the signed public Hopper Tool Plugin path. Select
it explicitly with:

```jsonc
// ingest_current_hopper
{ "backend": "private" }
```

Diagnose the configured private lane before ingesting with `backend_status` or
`backend_diagnostics`. A healthy private backend reports `backend: "private"`,
`backendMode: "injected_private"`, and `readiness: "ready"`.

For host preflight, run:

```bash
cargo run -p hopper-mcpd -- doctor --require-private-host
```

That check is intended only for a designated SIP-disabled host. In code it
passes when `csrutil status` reports SIP disabled, or when
`HOPPER_MCP_ASSUME_SIP_DISABLED=1` is set for controlled runners where host
detection is unavailable. Override the probe command with
`--csrutil-command PATH` or `HOPPER_MCP_CSRUTIL=PATH` in controlled
environments.

Validate the full private lane only on a designated SIP-disabled Hopper host:

```bash
npm run --silent release:check:private-backend
```

The private-backend gate runs `doctor --require-private-host`, builds
`hopper-agent` plus the Foundation-only Hopper Tool Plugin, installs the plugin
bundle, opens a real target through the proven live-export Hopper path, then
verifies private socket handshake, current document, and procedure list via
`scripts/private-backend-runtime.mjs`. The default probe uses a temporary
`HOPPER_MCP_PRIVATE_AGENT_SOCKET` and lets the Hopper Tool Plugin host the
private socket server directly inside Hopper; the custom launcher path remains
only for synthetic test fixtures. Success in this lane does not prove the
signed public Hopper Tool Plugin path. The self-hosted live CI workflow stores
the resulting JSON as `reports/release-check-private-backend.json` and uploads
it as part of the `hopper-release-gate-reports` artifact bundle.

The abandoned `DYLD_INSERT_LIBRARIES` injection experiment is not part of the
supported production path and is not shipped as a public build target.

### Ingest A Live Hopper Export

```jsonc
// ingest_live_hopper
{
  "executable_path": "/bin/echo",
  "timeout_ms": 90000,
  "max_functions": 20,
  "max_strings": 50,
  "close_after_export": true
}
```

The Rust daemon invokes the live bridge, ingests the normalized Hopper session into the Rust store, and returns `session`, `launch`, and `diagnostics`. Universal Mach-O inputs are launched with Hopper's `FAT` loader chain to avoid the manual architecture picker. `close_after_export` defaults to `false`; set it to `true` for throwaway agent/test runs where the Hopper document should be cleaned up after export.

Live ingest is intentionally capped so one MCP call cannot monopolize the
daemon indefinitely: `timeout_ms <= 600000`, `max_functions <= 50000`,
`max_strings <= 250000`, and `max_pseudocode_functions <= 1000`. For
`full_export: true`, omitted function/string limits are filled with those hard
caps instead of becoming unbounded.

### Annotation Lifecycle

```text
begin_transaction              -> returns transactionId
queue(kind: rename | comment | inline_comment)
preview_transaction            -> review queued operations
commit_transaction             -> applies atomically to the local Rust store
rollback_transaction           -> discards queued operations
```

## Tool Surface

The Rust daemon exposes strict schemas for every tool. Unknown arguments are rejected at runtime.

| Group | Tools |
|---|---|
| Meta / backend | `capabilities`, `backend_status`, `backend_diagnostics` |
| Lifecycle / ingest | `open_session`, `ingest_current_hopper`, `ingest_live_hopper` |
| Snapshot reads | `procedure`, `search`, `list`, `xrefs`, `containing_function`, `resolve`, `query`, `analyze_function_deep`, `get_graph_slice` |
| Transactions | `begin_transaction`, `queue`, `preview_transaction`, `commit_transaction`, `rollback_transaction` |
| Analysis | `compute_fingerprints`, `find_similar_functions`, `diff_sessions` |

Discriminator-style tools (`procedure`, `search`, `list`, `queue`) take a `kind:` or `field:` argument that selects the variant.

**Resources** - `hopper://session/current`, `hopper://binary/metadata`, `hopper://functions`, `hopper://strings`, `hopper://names`, and `hopper://transactions/pending`.

**Prompts** - `function_triage`, `hypothesis_workspace`.

## Rust Commands

```bash
npm run start:rust
npm run doctor
npm run doctor:json
npm run package:release
npm run package:release:ad-hoc
npm run package:release:check
npm run package:verify -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
npm run package:smoke -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
npm run package:notarize -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
npm run fetch:hopper-sdk
npm run build:agent
npm run build:hopper-plugin
npm run hopper-plugin:service-name -- --socket /tmp/hopper-plugin.sock
npm run hopper-plugin:identities
npm run hopper-plugin:install
npm run hopper-plugin:probe
npm run cleanup:hopper-state
npm run test:agent
npm run build:rust
npm run check:rust
npm run fmt:rust
npm run clippy:rust
npm run test:rust
npm run test:live
npm run test:live:corpus:dry-run
npm run test:live:corpus
npm run test:live:corpus:large-apps
npm run release:check
npm run release:check:live
npm run release:check:private-backend
npm run release:check:internal
npm run release:check:internal-soak
npm run release:check:plugin-live
npm run release:check:distribution
npm run release:check:public-release
npm run release:check:public
```

Production readiness in this repo is split into two explicit profiles:

- `internal`: non-live verification, live Hopper verification, and the SIP-off
  private-backend lane on a designated Hopper runner
- `internal-soak`: the full internal profile plus the optional large-app live
  corpus soak
- `public`: signed plugin acceptance, signed distribution packaging, and
  notarized public release

Use the profile wrappers below when your claim is about one complete release
profile rather than a single gate.

Non-live CI release gate:

```bash
npm run release:check
```

The non-live gate now emits structured JSON with a `phase` field and runs JS
syntax/tests, Rust formatting, `cargo clippy` with warnings denied, Rust tests,
doctor checks, and package release verification. For machine parsing, prefer
`npm run --silent release:check`. The GitHub-hosted CI job stores the
resulting JSON as `reports/release-check.json` and uploads it as the
`hopper-nonlive-release-gate-report` artifact.

Full local release gate on a macOS machine with Hopper installed and Automation permission:

```bash
npm run release:check:live
```

The live gate now starts with a `doctor` preflight that hard-requires Hopper on
the current machine, then opens throwaway Hopper documents, ingests them,
verifies the official write-back path with
`HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` plus `confirm_live_write=true`, closes
the documents without saving, and runs the default live corpus with its
content/performance budgets. Before `test:live` and before the live corpus run,
the wrapper clears any existing GUI Hopper process and unsets
`HOPPER_MCP_PLUGIN_SOCKET` so stale interactive Hopper state cannot poison the
release gate. Cleanup failures are fatal on otherwise-successful runs, so the
gate will not return green if Hopper still persists after a phase completes.
The gate emits structured JSON with a `phase` field so
Hopper-readiness failures are distinguishable from failures in the non-live
gate, live suite, or live corpus. For machine parsing, prefer
`npm run --silent release:check:live`. The self-hosted live CI workflow stores
the resulting JSON as `reports/release-check-live.json` and uploads it as part
of the `hopper-release-gate-reports` artifact bundle. That workflow now also
runs `npm run --silent cleanup:hopper-state` as a final `if: always()` step,
stores `reports/cleanup-hopper-state.json`, and clears any leftover Hopper GUI
processes plus `HOPPER_MCP_PLUGIN_SOCKET` from the runner before the job ends.

Internal/private production profile on the designated Hopper runner:

```bash
npm run release:check:internal
```

This wrapper runs `release:check`, `release:check:live`, and
`release:check:private-backend` in order and returns structured JSON with
`profile: "internal"`. A green result here means the repo is production-ready
for internal/private Hopper use on the designated runner. It does not satisfy
the signed public-release requirements below.

Extended internal/private soak profile on a designated heavy-app workstation:

```bash
npm run release:check:internal-soak
```

This wrapper runs `release:check:internal` and then the optional heavyweight
live corpus manifest from `corpus/live-large-apps.json`. That manifest records
the large-app stability lane used during hardening and keeps each target
`optional`, so machines without Capture One, Chrome, VS Code, Safari, Resolve,
Photoshop, or a usable Xcode bundle will skip those entries instead of failing
the soak run.

Signed in-Hopper plugin gate on a macOS machine with Hopper installed and a
real Apple developer signing identity:

```bash
npm run release:check:plugin-live
```

This gate fails fast on missing codesigning identities, then runs the
end-to-end plugin probe so the signed `HopperMCPAgent.hopperTool` path is
validated as a first-class release step rather than an ad hoc manual command.
Before probing, the wrapper clears any existing Hopper GUI process and unsets
`HOPPER_MCP_PLUGIN_SOCKET` so stale interactive state cannot poison the signed
plugin acceptance run. Cleanup failures are fatal on otherwise-successful runs,
so the gate will not return green if Hopper still persists afterward. The gate
now emits structured JSON with a `phase` field so CI and release operators can
distinguish a signing-readiness failure from a probe failure. For machine
parsing, prefer `npm run --silent release:check:plugin-live`. The self-hosted
live CI workflow stores the resulting JSON as
`reports/release-check-plugin-live.json` and uploads it as part of the
`hopper-release-gate-reports` artifact bundle.

If you only need the signing preflight without touching Hopper, run:

```bash
npm run doctor:plugin-live
```

Signed distribution gate on a macOS machine with a real signing identity:

```bash
npm run release:check:distribution
```

This runs the non-live release gate and then requires a real signed
distribution artifact build via `npm run package:release`. The gate emits
structured JSON with a `phase` field so failures in the non-live gate are
distinguishable from signed packaging failures. It now starts with a `doctor`
preflight that hard-requires a `Developer ID Application` distribution identity
and a clean git worktree so misconfigured release hosts fail before spending
time in the non-live gate.
For machine parsing, prefer `npm run --silent release:check:distribution`. The
self-hosted live CI workflow stores the resulting JSON as
`reports/release-check-distribution.json` and uploads it as part of the
`hopper-release-gate-reports` artifact bundle.

If you only need the signed-distribution host preflight without building, run:

```bash
npm run doctor:distribution
```

Public release gate on a macOS machine with a real signing identity and Apple
notary credentials:

```bash
npm run release:check:public-release
```

This runs the signed distribution gate and then notarizes the resulting
artifact through `package:notarize`. It now starts with a `doctor` preflight
that hard-requires both a `Developer ID Application` distribution identity and
Apple notarization credentials, plus a clean git worktree, so misconfigured
release hosts fail before doing build work. For machine parsing, prefer
`npm run --silent release:check:public-release`. The self-hosted live CI
workflow stores the resulting JSON as `reports/release-check-public-release.json`
and uploads it as part of the `hopper-release-gate-reports` artifact bundle.

Public signed-release production profile on a prepared macOS release host:

```bash
npm run release:check:public
```

This wrapper runs `release:check:plugin-live`,
`release:check:distribution`, and `release:check:public-release` in order and
returns structured JSON with `profile: "public"`. A green result here means
the signed Hopper plugin, packaged distribution artifact, and notarized public
release paths are all production-ready.

If you only need the public-release host preflight without building or
notarizing, run:

```bash
npm run doctor:public-release
```

`npm run doctor` validates the store path, Node live bridge command, bridge script,
Hopper installation, local Apple codesigning identity availability, public
distribution identity readiness, Apple notarization credential readiness, and
private-agent socket readiness when configured. Missing Hopper, missing signing
identities, missing public-release prerequisites, and an unset private socket
are warnings by default so non-live CI can run on clean machines; use
`cargo run -p hopper-mcpd -- doctor --require-hopper` for live release runners.
The structured JSON report now includes an optional per-check `remediation`
field, and text output renders those hints as `next:` lines, so release hosts
can see the exact follow-up command or environment variable to fix.
Use `cargo run -p hopper-mcpd -- doctor --require-plugin-identity` when you
need a hard failure on machines that cannot live-load the Hopper Tool Plugin.
Use `cargo run -p hopper-mcpd -- doctor --require-distribution-identity` when
you need a hard failure on machines that cannot produce a signed public
distribution artifact. Use
`cargo run -p hopper-mcpd -- doctor --require-clean-git-tree` when you need a
hard failure unless the release host is building from a committed checkout, and
`cargo run -p hopper-mcpd -- doctor --require-notary-credentials` when you need
a hard failure on machines that cannot submit to Apple notarization. Use
`--private-agent-socket PATH` or
`HOPPER_MCP_PRIVATE_AGENT_SOCKET=PATH` to make doctor probe the native/private
backend handshake, and `--security-command PATH` or `HOPPER_MCP_SECURITY=PATH`
to inject a specific `security` binary in controlled environments.
Use `cargo run -p hopper-mcpd -- doctor --require-private-host` only on a
designated SIP-disabled private-backend host. That preflight proves the host is
eligible for the private lane, and in code it detects SIP state via
`csrutil status` unless `HOPPER_MCP_ASSUME_SIP_DISABLED=1` is set explicitly.
Socket-level private readiness is then proven by `backend_diagnostics`,
private ingest, and `release:check:private-backend`. Use
`--csrutil-command PATH` or `HOPPER_MCP_CSRUTIL=PATH` to inject a specific
probe binary in controlled environments.

`npm run fetch:hopper-sdk` downloads the current public Hopper SDK metadata from
Hopper's official files API, verifies the SDK zip SHA-1 published by that API,
and unpacks it under `.cache/hopper-sdk/<version>`. The SDK is not vendored into
this repository.

`npm run build:hopper-plugin` compiles
`target/release/HopperMCPAgent.hopperTool` from `agents/hopper-tool-plugin`
against that SDK. The plugin uses Hopper's public SDK interfaces for
`currentDocument`, procedure addresses, procedure names, basic-block-derived
sizes, and a Foundation distributed-object bridge that is keyed off the configured
plugin socket path. By default that socket path is
`~/Library/Application Support/hopper-mcp/hopper-plugin.sock`; set
`HOPPER_MCP_PLUGIN_SOCKET` before launching Hopper to override it. The external
native helper can derive the matching bridge service name with:

```bash
npm run hopper-plugin:service-name -- --socket /tmp/hopper-plugin.sock
```

Install and sign the plugin bundle into Hopper's official user plugin
directory with:

```bash
npm run hopper-plugin:install
```

That command copies the built bundle into
`~/Library/Application Support/Hopper/PlugIns/v4/Tools/HopperMCPAgent.hopperTool`
and signs it with `HOPPER_MCP_CODESIGN_IDENTITY` when set. If no identity is
configured, the command now fails fast instead of silently producing an ad-hoc
signed bundle that Hopper will usually refuse to load. Check local signing
identities with:

```bash
npm run hopper-plugin:identities
```

Hopper's SDK documentation states that macOS 11+ plugins must be signed with an
Apple developer certificate to load. On machines where `hopper-plugin:identities`
reports no valid identities, Hopper may reject even minimal tool plugins with a
generic "external function(s)" loader error; treat that as an environment
blocker, not as evidence that the plugin protocol is wrong.

If you intentionally need an ad-hoc-signed bundle for fixture or harness work,
make that choice explicit:

```bash
npm run hopper-plugin:install -- --ad-hoc
```

Ad-hoc signing is not valid evidence that Hopper will accept the plugin on a
real macOS 11+ host.

To validate the whole in-Hopper bridge path with one command, use:

```bash
npm run hopper-plugin:probe
```

The probe installs the plugin, requires a real Apple codesigning identity by
default, seeds `HOPPER_MCP_PLUGIN_SOCKET` into the GUI launch domain with
`launchctl setenv`, launches Hopper on `/bin/echo`, starts
`hopper-agent --plugin-service auto`, verifies the `hopper-wire` handshake plus
current-document/procedure responses, and then terminates the probe-launched
agent and Hopper processes before unsetting the GUI-domain socket variable
again. Both `hopper-plugin:install` and `hopper-plugin:probe` now fail fast if
the plugin bundle links `AppKit` or `Cocoa`; the in-Hopper Tool Plugin path is
expected to stay Foundation-only. Use `-- --skip-sign` only for fixture-only
development or injected test harnesses; it is not evidence that Hopper will
accept the plugin on a real macOS 11+ host.

`npm run package:release` builds `target/release/hopper-mcpd` and writes a
versioned tarball plus `.sha256` checksum under `dist/`. On macOS the release
build now requires a real signing identity through
`HOPPER_MCP_CODESIGN_IDENTITY`; for public distribution that identity must be a
`Developer ID Application` identity. Signed distribution builds also require a
clean git worktree so the packaged provenance matches a committed source state.
The build no longer silently falls back to ad-hoc signing for distribution
artifacts. For local fixture or smoke packaging where distribution-grade
signing is not the claim, use:

```bash
npm run package:release:ad-hoc
```

The release build compiles and signs
`target/release/hopper-agent` and
`target/release/HopperMCPAgent.hopperTool`. The tarball includes
`release-manifest.json` with per-file byte counts, SHA-256 hashes, and git
source provenance (`commit` plus clean/dirty tree state), plus build/signing
provenance (`nodeVersion`, `cargoVersion`, and ad-hoc vs Developer ID signing
mode) for the bundled runtime files. The archive path is now deterministic for
identical staged inputs: staged mtimes are normalized, tar ownership metadata is
fixed, and gzip runs with `-n` so the compressed artifact does not carry a
per-run timestamp. The bundle keeps `bin/hopper-mcp`,
`target/release/hopper-mcpd`, `target/release/hopper-agent`,
`target/release/HopperMCPAgent.hopperTool`, and `src/live-bridge-cli.js` under
the same root so the Rust daemon can find the live bridge and private agent
artifacts after extraction.
`npm run package:release:check` builds the same layout in a temporary
directory, verifies the checksum, extracts it, validates `release-manifest.json`,
rejects unsafe or unexpected archive members, executes the packaged live bridge
against a controlled malformed request, verifies the packaged daemon signature
against a controlled malformed request, executes a packaged `hopper-agent`
fixture and real-bridge `hopper-wire` handshake/current-document/procedure
smoke, verifies packaged daemon/agent/plugin signatures with `codesign`,
verifies that the packaged Hopper Tool Plugin does not link AppKit/Cocoa, runs
packaged `doctor`, and performs an MCP initialize handshake. This verification
path uses an explicit ad-hoc packaging mode internally so local release checks
still run on machines without a distribution identity. Verify and
smoke-test an artifact before distributing it:

```bash
npm run package:verify -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
npm run package:smoke -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
```

For Apple notarization, first build and smoke the tarball, then run:

```bash
HOPPER_MCP_NOTARY_PROFILE=profile-name npm run package:notarize -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
```

`package:notarize` re-runs package smoke verification, wraps the extracted
tarball contents in a temporary ZIP submission payload, verifies that the
packaged daemon is signed with a `Developer ID Application` identity, and calls
`xcrun notarytool submit --wait --output-format json`. Use
`HOPPER_MCP_CODESIGN_IDENTITY` when building the tarball, and use
`HOPPER_MCP_NOTARY_PROFILE` for a stored notarytool keychain profile, or set
`APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_PASSWORD` for direct credentials.

`npm run test:live:corpus` runs `corpus/live-smoke.json` through live Hopper
ingest and emits a JSON report with per-target timing/counts/assertions. The
default manifest covers several stable macOS system binaries and keeps Finder
as a resolved-but-disabled app-bundle target for heavier local runs. Use
`npm run test:live:corpus:dry-run` to validate target resolution without
opening Hopper. Pass `-- --report path/to/report.json` to persist the report;
manifest targets can enforce `min_functions`, `min_strings`, and
`max_elapsed_ms` budgets.

`npm run test:live:corpus:large-apps` runs the optional
`corpus/live-large-apps.json` manifest. It is intended for local research
workstations and records the heavier real-app soak lane with optional targets
for Capture One, Chrome, VS Code, Safari, Resolve, Photoshop, and Xcode.

## Protocol Notes

- Stdio transport, newline-delimited JSON-RPC.
- Supported MCP protocol version: `2025-11-25`.
- Tool results carry both a JSON text block and `structuredContent`.
- Requests with explicit `id: null` are rejected instead of treated as notifications.

## Layout

```text
MCP client
  -> stdio JSON-RPC
  -> crates/hopper-mcpd/src/main.rs      Rust process entry
    |- protocol.rs                      MCP/JSON-RPC response types
    |- model.rs                         normalized Hopper snapshot types
    |- store.rs                         indexed snapshot store and resources
    |- tools.rs                         strict tool registry and handlers
    |- transactions.rs                  local transaction lifecycle
    |- persistence.rs                   atomic JSON persistence
    |- live.rs                          subprocess live-export bridge
    `- backend.rs                       versioned backend boundary
```

```text
JavaScript migration reference only
  -> src/mcp-server.js
    |- src/server-tools.js
    |- src/server-resources.js
    |- src/server-prompts.js
    |- src/knowledge-store.js
    |- src/live-bridge-cli.js
    |- src/hopper-live.js
    `- src/official-hopper-backend.js
```

```text
Native private backend artifact
  -> agents/hopper-agent
    |- Makefile
    `- src/main.mm                      Objective-C++ hopper-wire socket agent

Native Hopper Tool Plugin artifact
  -> agents/hopper-tool-plugin
    |- Makefile
    |- Info.plist
    `- src/HopperMCPAgent.m             in-Hopper hopper-wire socket agent
```

Further reading:

- `docs/adapter-protocol.md` - internal adapter wire format
- `docs/official-hopper-mcp-notes.md` - notes on Hopper's official MCP server
- `CONTRIBUTING.md` - dev setup and PR conventions

## License

MIT - see `LICENSE`.
