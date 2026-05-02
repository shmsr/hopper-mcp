# Private Backend Power Mode Design

Date: 2026-05-01

> Revision note: the shipped v1 private backend kept the explicit SIP-off power
> mode and `hopper-wire` boundary from this design, but replaced the original
> `DYLD_INSERT_LIBRARIES` injection/helper runtime with a Hopper Tool Plugin
> that hosts the private socket server directly inside Hopper. Hopper proved
> unstable under the launch-time injection experiment, so treat the injection
> architecture below as superseded history unless a later design explicitly
> revives it.

## Goal

Add a production-quality SIP-disabled Hopper backend that is more capable than
the official/public Hopper path while preserving the Rust daemon as the only
MCP server and keeping the current signed/public release lane stable.

## Scope

This design adds a second production backend lane:

- the existing official/public lane remains the default production path
- a new SIP-off private lane is added as an explicit power mode

The private lane must be isolated, observable, capability-gated, and
fail-closed. It must not silently replace the public backend or weaken the
current release gates.

## Non-Goals

- Do not make private injection the default backend for all users.
- Do not mix Hopper private API logic into the Rust MCP daemon.
- Do not expose MCP directly from injected Hopper-side code.
- Do not add private write operations in the first slice.
- Do not treat the private lane as evidence that the signed public release lane
  is complete.

## Production-Grade Definition

For this milestone, the SIP-off lane is production-grade only when:

- `hopper-mcpd` remains the sole MCP entrypoint.
- the injected Hopper path is isolated behind `hopper-wire`
- backend selection is explicit and visible in diagnostics
- the private lane can fail cleanly without degrading into heuristic output
- the first private lane supports real read-only evidence, not fixtures
- the private lane has its own targeted release gate on SIP-disabled machines
- the existing official/public gates remain intact and green

This milestone does not require private pseudocode export, private write-back,
or automatic private-backend selection.

## Current Repo Seam

The current repository already has the correct integration seam:

- `crates/hopper-mcpd` is the production MCP daemon
- `hopper-wire` is the versioned local daemon/backend contract
- `ingest_current_hopper` is the correct Rust tool boundary for a native Hopper
  backend
- `ingest_live_hopper` remains the official/public live-export lane

This means the private SIP-off backend should plug into `ingest_current_hopper`
through `hopper-wire` rather than extending the Node migration bridge or
inventing a second MCP server.

## Architecture

The private lane is split into four components:

1. `hopper-mcpd`
   - owns MCP stdio, tool schemas, persistence, diagnostics, and backend
     selection
2. `injector/helper`
   - watches for Hopper launch or attaches to a running Hopper instance
   - injects the payload into Hopper on SIP-disabled systems
   - manages reconnect and teardown
3. `injected payload`
   - runs inside Hopper
   - resolves and calls private Hopper Objective-C APIs
   - tracks load/readiness state and builds minimal caches
4. `private agent bridge`
   - translates payload data into the existing `hopper-wire` request/response
     protocol
   - keeps Hopper-private details out of Rust and out of MCP clients

```text
MCP client
  -> hopper-mcpd (Rust)
    -> ingest_current_hopper / backend diagnostics
    -> hopper-wire
      -> private agent bridge
        -> injector/helper
          -> injected payload inside Hopper
            -> Hopper private Objective-C APIs
```

## Backend Selection

The private lane is an explicit power mode:

- `backend: "private"` requests the injected backend
- `backend: "auto"` may continue to mean "configured production choice", but it
  must not silently upgrade a user from the official/public lane into injected
  mode without an explicit machine-level opt-in
- `backend: "mock"` remains test-only

The daemon must report the active backend and capability level through:

- `backend_status`
- `backend_diagnostics`
- session provenance/capabilities

At minimum, diagnostics must identify:

- backend kind: mock / official live export / private injected
- readiness state
- Hopper version/build if available
- wire protocol version
- installed capability set
- unsupported reasons when a private feature is unavailable

## Wire Contract

The private lane must extend `hopper-wire`, not bypass it.

### Required core calls

The first private slice must support:

- handshake/version negotiation
- current document
- procedure list

These are enough to prove that Rust is consuming real injected evidence through
the native boundary rather than through fixtures or the official MCP
subprocess.

### Optional capability-gated calls

Once the first slice is stable, `hopper-wire` may add optional requests for:

- document inventory
- focus/set-current-document
- richer procedure metadata
- disassembly fetch
- pseudocode fetch
- symbol/name lookup
- comment lookup
- xref lookup
- analysis readiness / load-state

All new calls must be versioned and capability-advertised. If the payload
cannot resolve required selectors for a feature, the backend must report that
explicitly instead of returning partial or guessed data.

## State And Readiness Model

The injected backend must expose state instead of forcing the daemon to guess.

Minimum states:

- `unavailable`
- `injecting`
- `ready`
- `analyzing`
- `no_document`
- `unsupported`
- `failed`

The daemon should treat these as first-class diagnostics. A private lane that
is still analyzing, attached to an empty Hopper window, or broken by private
API drift must return a structured backend error rather than falling back to
local heuristics or stale cached data.

## Safety Rules

- Private injection must stay opt-in.
- Private API calls must be version-gated and capability-advertised.
- The injected payload must stay thin; indexing, schema handling, and MCP
  behavior belong in Rust.
- No silent fallback when evidence quality changes.
- No private write operations without preview, explicit confirmation, and a
  dedicated follow-up design slice.
- Failures in injection, selector resolution, protocol negotiation, or Hopper
  document state must return structured errors.

## Testing Strategy

The private lane needs its own release evidence and must not dilute the current
official/public gates.

### Existing gates that remain unchanged

- `npm run --silent release:check`
- `npm run --silent release:check:live`
- `npm run --silent release:check:plugin-live`
- `npm run --silent release:check:distribution`
- `npm run --silent release:check:public-release`

### New private-lane gate

Add a separate gate for SIP-disabled hosts that proves:

- injector/helper starts
- payload loads into Hopper
- `hopper-wire` handshake succeeds
- current document comes from the injected path
- procedure inventory comes from the injected path
- at least one richer read-only private capability works once implemented

This gate must run only on explicitly configured SIP-off machines. It is not a
substitute for the signed public/plugin/distribution gates.

### Test phases

1. unit and contract tests for the extended `hopper-wire` protocol
2. integration test with a fake or harnessed private bridge
3. gated live test on a SIP-disabled Hopper host

## Doctor And Operator UX

The current `doctor` flow should grow a separate private-lane readiness view.

Future checks should include:

- SIP state
- Hopper presence/version
- injector/helper availability
- socket/service readiness
- compatibility of the current Hopper build with the private selector table

These checks belong in diagnostics and release gates, not in ad hoc shell notes.

## First Implementation Slice

The first slice should be intentionally narrow:

- do not start with pseudocode
- do not start with writes
- do not replace the current official path

Instead, prove the lane end to end:

1. explicit private backend selection
2. injector/helper lifecycle
3. injected payload bootstrap
4. `hopper-wire` handshake
5. current document read
6. procedure list read
7. structured diagnostics and fail-closed behavior

That gives the repo a real production private backbone without coupling early
success to the hardest private features.

## Risks

- Hopper private APIs may drift between releases.
  Mitigation: version-gated selector tables and capability probing.
- Injection bugs can destabilize Hopper.
  Mitigation: keep payload thin and keep MCP/index logic out of process.
- SIP-off requirements reduce security and portability.
  Mitigation: keep the lane explicit, isolated, and separately gated.
- Users may confuse private-lane success with public-release readiness.
  Mitigation: keep release gates separate and diagnostics explicit.

## Approval Criteria

This design is approved when we agree that:

- the SIP-off injected backend is a separate power lane, not a silent default
- Rust remains the only MCP server
- `hopper-wire` remains the only daemon/backend contract
- the first implementation slice is read-only and narrow
- the private lane gets its own dedicated release gate
- existing official/public production gates remain authoritative for signed and
  public release claims
