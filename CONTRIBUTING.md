# Contributing

This project should stay boring in the places that matter: clear commits,
small changes, explicit safety gates, and tests that exercise real MCP calls.

## Commit Messages

Use the Go project commit message style:

```text
area: lowercase action phrase
```

Examples:

```text
mcp: add protocol negotiation test
hopper: fix live exporter timeout handling
macho: preserve function discovery caps
docs: document client setup
```

Rules:

- Put the affected area before the colon, such as `mcp`, `hopper`, `macho`,
  `docs`, `test`, or `repo`.
- Use a lowercase verb after the colon.
- Write the subject so it completes: "this change modifies the project to ...".
- Keep the subject short, ideally under 72 characters.
- Do not add a trailing period to the subject.
- If a body is needed, wrap it around 72 columns.
- Do not use Markdown in commit message bodies.
- Do not add `Signed-off-by` lines.

Reference: https://go.dev/wiki/CommitMessage

## Code Quality

- Prefer small, reviewable changes over broad rewrites.
- Keep the Rust daemon as the production MCP entrypoint. JavaScript may remain
  as a migration-reference bridge, but new client-facing behavior should be
  routed through `hopper-mcpd`.
- Keep JavaScript bridge code production-grade: clear module boundaries,
  explicit errors, bounded output, and tests for new MCP behavior.
- Keep generated Python exporter code deterministic and easy to inspect.
- Keep private Hopper integration opt-in, version-gated, and fail-closed.
  Private API work belongs behind `hopper-wire`; do not put MCP protocol logic
  into injected or Hopper-side code, and do not copy proprietary implementation
  details.
- Keep `agents/hopper-agent` buildable with `npm run build:agent`; release
  packaging must include and smoke-test the compiled native agent.
- Keep `agents/hopper-tool-plugin` buildable with `npm run build:hopper-plugin`.
  It must use the official Hopper SDK fetched by `npm run fetch:hopper-sdk`;
  do not vendor the SDK zip or generated cache contents.
- Keep `scripts/hopper-plugin-runtime.mjs` aligned with the native plugin/helper
  rendezvous rules. Its service-name derivation must stay consistent with both
  `agents/hopper-agent` and `agents/hopper-tool-plugin`.
- `hopper-agent --fixture` is only for tests and package smoke. Do not make
  fixture data the default private backend behavior. Non-fixture mode must
  return real Hopper evidence through its configured backend or a structured
  error; it must never synthesize replacement data.
- Use Hopper's official MCP server only as a subprocess interface or behavior
  reference.
- Keep live writes guarded. Hopper write-back must require an explicit preview,
  an opt-in environment variable, and a per-call confirmation.

## Tests

Run the non-live release gate before opening a PR:

```bash
npm run release:check
```

The non-live release gate runs JS checks/tests, Rust formatting, `cargo clippy`
with warnings denied, Rust tests, doctor checks, and
`npm run package:release:check`, which builds a temporary release tarball,
verifies its `.sha256`, extracts it, validates the internal
`release-manifest.json`, rejects unsafe or unexpected archive members, executes
the packaged live bridge against a controlled malformed request, executes the
packaged Objective-C++ `hopper-agent` protocol smoke, verifies packaged binary
and Hopper Tool Plugin protocol smoke, verifies packaged binary and plugin
signatures with `codesign`, verifies that the packaged Hopper Tool Plugin does
not link AppKit/Cocoa, runs packaged `doctor`, and performs an MCP
initialize handshake from the extracted bundle. The check path uses an explicit
ad-hoc packaging mode internally so it can run on clean macOS machines.
Distribution builds should use a real signing identity through
`HOPPER_MCP_CODESIGN_IDENTITY`, and that identity should be a `Developer ID Application`
identity for public distribution; if you intentionally need a local ad-hoc archive
outside the check flow, use `npm run package:release:ad-hoc`. Signed
distribution packaging must come from a clean git worktree so the embedded
release provenance matches committed source. The gate now
returns structured JSON with a `phase` field; use
`npm run --silent release:check` when a machine consumer needs stdout to remain
pure JSON. The GitHub-hosted CI job captures that JSON to
`reports/release-check.json` and uploads it as the
`hopper-nonlive-release-gate-report` artifact.

Production readiness is split into two explicit profiles:

- `internal`: non-live gate + live Hopper gate + SIP-off private-backend gate
- `public`: signed plugin gate + signed distribution gate + notarized public release gate

Use the profile wrappers below when your claim is about one complete release
profile rather than a single gate.

Run the full release gate before claiming live Hopper production readiness:

```bash
npm run release:check:live
```

This now starts with `doctor --json --require-hopper`, then runs the non-live
release gate, live ingest/write-back tests, and the default live corpus budget
run. Before `test:live` and before the corpus run, the wrapper clears any
existing GUI Hopper process and unsets `HOPPER_MCP_PLUGIN_SOCKET` so stale
interactive Hopper state does not bleed into the release gate. Cleanup
failures are fatal on otherwise-successful runs, so the gate will not return
green if Hopper still persists after a phase completes. The gate returns
structured JSON with a `phase` field so missing-Hopper failures are
distinguishable from failures in the non-live gate, the live suite, or the
corpus run. Use `npm run --silent release:check:live` when a machine consumer
needs stdout to remain pure JSON. The self-hosted live CI job captures that
JSON to `reports/release-check-live.json` and uploads it in the
`hopper-release-gate-reports` artifact bundle. It also runs
`npm run --silent cleanup:hopper-state` in a final `if: always()` step, stores
`reports/cleanup-hopper-state.json`, and clears any leftover Hopper GUI
processes plus `HOPPER_MCP_PLUGIN_SOCKET` from the runner before the job ends.

Run the full internal/private production profile on the designated Hopper
runner when that is the release claim:

```bash
npm run release:check:internal
```

This wrapper runs `release:check`, `release:check:live`, and
`release:check:private-backend` in order and returns structured JSON with
`profile: "internal"`. A green result here proves internal/private
production readiness only; it does not satisfy the signed public path.

Run the extended internal soak lane when you need reproducible evidence across
the heavier app corpus used during stability hardening:

```bash
npm run release:check:internal-soak
```

This wrapper runs `release:check:internal` and then
`test:live:corpus:large-apps`. The large-app manifest lives in
`corpus/live-large-apps.json`. Its targets are marked `optional`, so hosts that
do not have Capture One, Chrome, VS Code, Safari, Resolve, Photoshop, or a
usable Xcode bundle will skip those entries rather than failing the soak lane.

Run the signed plugin gate before claiming the in-Hopper Tool Plugin path is
production ready:

```bash
npm run release:check:plugin-live
```

This gate requires a real Apple codesigning identity and then runs the plugin
probe end to end. The probe seeds `HOPPER_MCP_PLUGIN_SOCKET` into the GUI
launch domain with `launchctl setenv` before starting Hopper, because the GUI
process does not reliably inherit that socket override from the CLI launcher
alone. Before probing, the wrapper clears any existing Hopper GUI process and
unsets `HOPPER_MCP_PLUGIN_SOCKET` so stale interactive state cannot poison the
acceptance run. Cleanup failures are now fatal on otherwise-successful runs, so
the gate will not return green if Hopper still persists afterward. Use
`npm run --silent release:check:plugin-live` when a machine consumer needs
stdout to remain pure JSON. The self-hosted live CI job captures that JSON to
`reports/release-check-plugin-live.json` and uploads it in the
`hopper-release-gate-reports` artifact bundle.

For signing-only preflight without touching Hopper, run:

```bash
npm run doctor:plugin-live
```

Run the private-backend power-mode gate only on designated SIP-disabled Hopper
runners:

```bash
npm run --silent release:check:private-backend
```

This gate first runs `doctor --json --require-private-host`, then a real MCP
private-backend probe via `scripts/private-backend-runtime.mjs`. The wrapper
builds `hopper-agent` and the Hopper Tool Plugin, installs the Foundation-only
plugin bundle, opens a real target through the proven live-export Hopper path,
and verifies private handshake/current-document/procedure responses over a
temporary `HOPPER_MCP_PRIVATE_AGENT_SOCKET`. It detects SIP state with
`csrutil status` unless `HOPPER_MCP_ASSUME_SIP_DISABLED=1` is set explicitly
for controlled runners. Use `--csrutil-command PATH` or
`HOPPER_MCP_CSRUTIL=PATH` to inject a specific probe binary in controlled
environments. Success in this lane does not satisfy
`release:check:plugin-live`, `release:check:distribution`, or
`release:check:public-release`. The self-hosted live CI workflow captures that
JSON as `reports/release-check-private-backend.json` and uploads it in the
`hopper-release-gate-reports` artifact bundle.

The older `DYLD_INSERT_LIBRARIES` injection experiment is not a supported
production path and should not be reintroduced as a public build target.

Run the signed distribution gate before claiming the packaged public artifact
path is production ready:

```bash
npm run release:check:distribution
```

This gate runs the non-live release checks and then requires a real signed
distribution archive build. Use `npm run --silent release:check:distribution`
when a machine consumer needs stdout to remain pure JSON. The self-hosted live
CI job captures that JSON to `reports/release-check-distribution.json` and
uploads it in the `hopper-release-gate-reports` artifact bundle.

For signed-distribution host preflight without building, run:

```bash
npm run doctor:distribution
```

Run the public release gate before claiming notarized public macOS release
readiness:

```bash
npm run release:check:public-release
```

This gate runs the signed distribution gate and then notarizes the built
archive. Use `npm run --silent release:check:public-release` when a machine
consumer needs stdout to remain pure JSON. The self-hosted live CI job captures
that JSON to `reports/release-check-public-release.json` and uploads it in the
`hopper-release-gate-reports` artifact bundle.

Run the full signed public production profile on a prepared macOS release host
when that is the release claim:

```bash
npm run release:check:public
```

This wrapper runs `release:check:plugin-live`,
`release:check:distribution`, and `release:check:public-release` in order and
returns structured JSON with `profile: "public"`.

For public-release host preflight without building or notarizing, run:

```bash
npm run doctor:public-release
```

Run targeted live checks before changing Hopper integration:

```bash
npm run test:live
npm run test:live:corpus:dry-run
```

`npm run test:live` includes a guarded official write-back test against an
unsaved throwaway Hopper document. The test enables
`HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` only for its spawned server and still
requires `confirm_live_write=true`.

If a live Hopper test cannot run because macOS Automation is blocked, say that
explicitly in the PR or change notes.

Run `npm run test:live:corpus` before release candidates when you need evidence
across multiple binaries/app bundles. The default manifest is
`corpus/live-smoke.json` and includes several enabled macOS system binaries
plus a disabled Finder app-bundle target for heavier local runs. Pass
`-- --manifest path/to/manifest.json` to test a larger local corpus, and
`-- --report reports/live-corpus.json` to persist the JSON evidence. Corpus
targets can enforce `min_functions`, `min_strings`, and `max_elapsed_ms`;
failed assertions fail the corpus run.

Use `npm run test:live:corpus:large-apps` for the optional heavyweight local
manifest in `corpus/live-large-apps.json`. That manifest keeps its entries
optional so it remains portable across hosts while still recording the big-app
stability lane on a fully provisioned workstation.

Use `npm run doctor` when debugging local setup. Use
`cargo run -p hopper-mcpd -- doctor --require-hopper` on live runners where
Hopper is mandatory. If testing the native/private backend, set
`HOPPER_MCP_PRIVATE_AGENT_SOCKET` or pass `--private-agent-socket PATH`; doctor
will fail if the configured socket cannot complete a `hopper-wire` handshake.
Use `cargo run -p hopper-mcpd -- doctor --require-private-host` only on the
designated SIP-disabled private-backend runners; that stricter preflight
proves the host is eligible for the private lane, and in code it detects SIP
state via `csrutil status` unless `HOPPER_MCP_ASSUME_SIP_DISABLED=1` is set
explicitly. Socket-level private readiness is then proven by
`backend_diagnostics`, private ingest, and `release:check:private-backend`.
Use `--csrutil-command PATH` or `HOPPER_MCP_CSRUTIL=PATH` to inject a specific
probe binary in controlled environments.
The JSON doctor report now includes an optional `remediation` field for
actionable follow-up, and text output renders those hints as `next:` lines.
Use `cargo run -p hopper-mcpd -- doctor --require-plugin-identity` when the
Hopper Tool Plugin path is in scope and you want CI or a release host to fail
fast if no Apple codesigning identities are available. Use
`cargo run -p hopper-mcpd -- doctor --require-distribution-identity` when the
public distribution path is in scope and you need a hard failure unless a
`Developer ID Application` identity is available through
`HOPPER_MCP_CODESIGN_IDENTITY`. Use
`cargo run -p hopper-mcpd -- doctor --require-clean-git-tree` when the release
host must prove it is building from a committed checkout. Use
`cargo run -p hopper-mcpd -- doctor --require-notary-credentials` when the
release host must prove it can authenticate to Apple notarization.
`npm run release:check:private-backend`, `npm run release:check:plugin-live`,
`npm run release:check:distribution`, and
`npm run release:check:public-release` all return structured JSON with a
`phase` field so gate failures are attributable without scraping shell output.
`npm run release:check:distribution` now starts with
`doctor --json --require-distribution-identity --require-clean-git-tree`
before it runs the non-live gate, so machines with no `Developer ID
Application` identity or a dirty release checkout fail fast instead of burning
time before `package:release`.
Run `npm run hopper-plugin:identities` before treating Hopper Tool Plugin load
failures as code regressions. Hopper's SDK docs require a real Apple developer
certificate for macOS 11+ plugin loading, and machines with no valid signing
identities can reject even minimal tool plugins with Hopper's generic loader
error.
Run `npm run hopper-plugin:probe` when you need one command that installs the
plugin, launches Hopper with the plugin socket configured, verifies the
`hopper-agent --plugin-service auto` bridge, and then cleans up the probe
processes. Both `hopper-plugin:install` and `hopper-plugin:probe` now fail fast
if the plugin bundle links `AppKit` or `Cocoa`; the in-Hopper Tool Plugin path
is expected to stay Foundation-only. `-- --skip-sign` is only for fixture or
harness testing and does not prove Hopper will accept the plugin.
Do not silently rely on ad-hoc signing for live plugin installs. Use a real
identity by default; `npm run hopper-plugin:install -- --ad-hoc` is only for
fixture or harness scenarios where Hopper live-loading is not the claim being
tested.

Release artifacts must include a `.sha256` next to the tarball, an internal
`release-manifest.json` with per-file hashes plus source/build/signing
provenance, and a verifiable signature on the packaged daemon. The packaging
path should stay deterministic for identical staged inputs. Verify and
smoke-test the extracted bundle before uploading or sharing:

```bash
npm run package:verify -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
npm run package:smoke -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz
```

For Apple notarization, `npm run package:notarize -- dist/hopper-mcp-0.1.0-darwin-arm64.tar.gz`
first re-runs package smoke verification, then wraps the extracted tarball
contents in a temporary ZIP because Apple's notary service accepts ZIP, DMG, or
flat PKG submissions. The archive must have been built with a `Developer ID
Application` identity via `HOPPER_MCP_CODESIGN_IDENTITY`; ad-hoc signed
archives are refused before `notarytool` is called. Use
`HOPPER_MCP_NOTARY_PROFILE` for a stored notarytool keychain profile, or
`APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_PASSWORD` for direct credentials. Do
not claim notarization unless this command returns `ok: true` from Apple
notarytool.

`npm run release:check:public-release` now starts with a `doctor` preflight
that hard-requires `--require-distribution-identity`,
`--require-clean-git-tree`, and `--require-notary-credentials` before it
attempts the signed distribution build or `package:notarize`.
