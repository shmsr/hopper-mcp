# Hopper MCP Overhaul — Design

- **Status:** approved (brainstorming)
- **Date:** 2026-04-26
- **Owner:** subham sarkar
- **Branch target:** `main` (breaking changes accepted)

## Summary

Cut Hopper MCP from 63 tools to 56 (deleting 7), enforce a single architectural
invariant ("snapshot reader, live passthrough, or mutator — never a mix"),
delete every per-tool `backend:` flag, and consolidate the test suite from 16
files to 9 across four explicit tiers. The Mach-O importer, forensics tools,
and transaction layer are preserved as-is in scope; only their surface and
dead duplication go away.

The headline reduction is not in tool count — it is in *flag-routing*
complexity. We collapse 17 per-tool `backend:` branches to 1, eliminate three
parallel ways to reach the same operation, and shrink `server-tools.js` by
~45%.

## Goals

1. One canonical way to do every operation. Eliminate three-way duplication
   (snapshot tool / discriminator / live-routed).
2. Strict superset of `HopperMCPServer`'s 32 tool names: any official-MCP
   client can point at us and snapshot-read everything.
3. Single live access point: `official_hopper_call`. Per-tool live routing is
   removed from reads; lives only on `commit_transaction` (the single mutator
   that crosses the local/live boundary).
4. Smaller, more readable codebase. `src/server-tools.js` from 1972 lines to
   ~1100. Test surface from ~5000 lines across 16 files to ~9 focused files.
5. Crisp test tiers (T0 static, T1 unit, T2 integration, T3 live) so PR CI is
   fast and Hopper-required runs are gated.

## Non-goals

- No new disassembler functionality. Mach-O importer, forensics, and live
  exporter capabilities stay as they are today.
- No persistent in-process Hopper adapter (still future work; tracked in
  `docs/adapter-protocol.md`).
- No new resource templates beyond `hopper://transactions/{id}`.
- No reformatting of snapshot reader output shapes — we preserve byte-for-byte
  compatibility with the official server's address-keyed objects, etc.
- No re-architecture of the JSON store or transaction manager.

## The architectural invariant

Every tool obeys exactly one of three roles. There is no fourth mode and no
per-tool `backend` flag.

| Role | Source of truth | Side effects | Examples |
|------|-----------------|--------------|----------|
| Snapshot reader | Local JSON store (last ingested session) | None | `procedure_info`, `list_strings`, `xrefs`, `resolve`, `query` |
| Live passthrough | Hopper UI via XPC (through `HopperMCPServer`) | Whatever the official tool does | `official_hopper_call`, `official_hopper_tools` |
| Mutator | Local JSON store + (on commit) optional live write-through | Writes JSON; optionally writes Hopper | `begin_transaction`, `queue`, `hypothesis`, `commit_transaction`, `import_macho`, `ingest_*` |

Consequences:

- Every snapshot tool is deterministic and offline-capable.
- "I want live document state" → exactly one answer: `official_hopper_call`.
- Mutators are explicit about scope (local vs live) via `confirm_live_write`
  on `commit_transaction`, not via flags on every read.
- `compare_with_hopper` / `hopper_decompile` / `hopper_assembly` /
  `hopper_callees` — which currently mix snapshot and live in one call — are
  deleted. If a client wants a snapshot/live diff, it can drive both paths.

## Final tool surface (56)

### Meta + capabilities (3)

- `capabilities` — server/adapter/backend capabilities + session list
- `official_hopper_call` — the single live passthrough; all live reads route here
- `official_hopper_tools` — list official tools

Removed: `debug_echo`.

### Lifecycle / ingest (5)

- `open_session` — load a pre-indexed JSON payload
- `close_session` — drop a session from the store
- `set_current_session` — pick the active session for unscoped tool calls
- `ingest_sample` — built-in tiny sample for smoke tests
- `ingest_live_hopper` — open a binary in Hopper, run the Python exporter,
  ingest the resulting normalized session
- `ingest_official_hopper` — refresh local snapshot from the official MCP
  backend (the prior `refresh_snapshot` alias is removed; one name only)

### Local Mach-O + address helpers (5)

- `import_macho` — local-only Mach-O import (otool/codesign/objc/strings)
- `disassemble_range`
- `find_xrefs`
- `find_functions`
- `containing_function` — address-in-range lookup; reads the local snapshot
  (no live Hopper call), grouped here because it complements the binary-scan
  helpers

### Snapshot mirror — official names, 1:1 (24)

All read from local JSON. No `backend:` flag.

`list_documents`, `current_document`, `list_segments`, `list_procedures`,
`list_procedure_size`, `list_procedure_info`, `list_strings`, `search_strings`,
`search_procedures`, `procedure_info`, `procedure_address`, `current_address`,
`current_procedure`, `procedure_assembly`, `procedure_pseudo_code`,
`procedure_callers`, `procedure_callees`, `xrefs`, `comment`, `inline_comment`,
`list_names`, `search_name`, `address_name`, `list_bookmarks`.

Not mirrored (use `official_hopper_call` for live, transactions for persisted
state): `set_current_document`, `goto_address`, `next_address`, `prev_address`,
`set_comment`, `set_inline_comment`, `set_address_name`, `set_addresses_names`,
`set_bookmark`, `unset_bookmark`.

### Snapshot-only enrichments (4)

- `resolve` — fuzzy address/name/string lookup
- `query` — structured DSL (name/calls/imports/string/tag/capability/anti)
- `analyze_function_deep`
- `get_graph_slice`

Removed: `procedure` and `search` discriminator helpers — redundant with the
official-named tools above.

### Transactions (6)

- `begin_transaction`
- `queue` — keeps `kind` discriminator (rename / comment / inline_comment /
  type_patch / tag / untag / rename_batch)
- `hypothesis` — separate write-tool for hypothesis lifecycle
  (create / link / status); grouped with transactions because it is a
  store-mutating queue helper, not a snapshot read
- `preview_transaction`
- `commit_transaction` — the *only* tool with backend routing; supports
  `backend: "official"` + `confirm_live_write: true` (gated by
  `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1`)
- `rollback_transaction`

### Forensics / research (8)

`classify_capabilities`, `detect_anti_analysis`, `compute_section_entropy`,
`extract_code_signing`, `extract_objc_runtime`, `compute_fingerprints`,
`find_similar_functions`, `diff_sessions`.

## Resources (22)

Existing 21 entries kept verbatim. **One addition:**
`hopper://transactions/{id}` — read a specific transaction by id (currently
only the `pending` collection is exposed).

## Prompts (2)

`function_triage` and `hypothesis_workspace` — unchanged.

## Net change

| | Before | After | Δ |
|---|---|---|---|
| Tools | 63 (+1 hidden) | 56 | −7 |
| `backend:` flag sites | 17 | 1 (`commit_transaction`) | −16 |
| Discriminator helpers (`procedure`, `search`) | 2 | 0 | −2 |
| Mixed snapshot/live tools | 4 (`compare_with_hopper`, `hopper_*`) | 0 | −4 |
| `server-tools.js` lines | 1972 | ~1100 (target) | −44% |
| Test files | 16 | 9 | −7 |
| Test lines | ~5000 | ~3000 (target) | −40% |

Tool count drops modestly; *cognitive surface* drops sharply. Every snapshot
read is now reachable by exactly one official-style name, every live read by
exactly one passthrough, and there is no third way.

## Removals (concrete)

### Tools deleted (7)

| Tool | Replacement |
|---|---|
| `debug_echo` (hidden) | none — test helper, not a real surface |
| `compare_with_hopper` | drive both paths from the client if needed |
| `hopper_decompile` | `official_hopper_call({name:"procedure_pseudo_code"})` |
| `hopper_assembly` | `official_hopper_call({name:"procedure_assembly"})` |
| `hopper_callees` | `official_hopper_call({name:"procedure_callees"})` |
| `procedure` (discriminator) | `procedure_info` / `procedure_assembly` / `procedure_pseudo_code` / `procedure_callers` / `procedure_callees` |
| `search` (discriminator) | `search_strings` / `search_procedures` / `search_name` |

Plus removal of the per-tool `backend:` flag from 16 snapshot readers, and
consolidation of `refresh_snapshot` and `ingest_official_hopper` to a single
canonical name (`ingest_official_hopper`). If `refresh_snapshot` is currently
only an alias mapping, this is a config-side rename; if it is a separate
registration, that registration is removed (verify during implementation).

### File-level changes

- `src/server-tools.js` (1972 → ~1100): delete `officialRead` helper; delete
  every `backend === "official"` branch in snapshot tools; delete the four
  `hopper_*` comparison tools; delete `procedure`/`search` discriminator
  handlers; delete `debug_echo` and the `enableDebugTools` branch; collapse
  `refresh_snapshot` to `ingest_official_hopper`-only.
- `src/official-hopper-backend.js` (359): no public-API change; remains the
  live gateway for `official_hopper_call` and `commit_transaction(backend:"official")`.
- `src/server-helpers.js` (201): drop helpers used only by deleted comparison
  tools; audit unused exports.
- `src/hopper-bridge.js` (648): verify still needed. If only used by per-tool
  live routing (which is being removed), shrinks or disappears. Live routing
  goes only through `official-hopper-backend.js`. Likely outcome: bridge stays
  for `ingest_live_hopper` Python exporter glue but loses any "fan-out to
  mirror tools" code.
- `src/server-resources.js`: add `hopper://transactions/{id}` template.
- `src/server-prompts.js`: unchanged.
- `src/sample-session.js`: unchanged (used by `ingest_sample`).
- `src/research-tools.js` (1079): unchanged surface.
- `src/macho-importer.js` (1325): unchanged surface.
- `src/knowledge-store.js` (580): add `getTransactionById` for the new
  resource; audit for methods only used by deleted helpers.
- `src/transaction-manager.js` (241): unchanged.
- `src/hopper-adapter.js` (45): if unused after cuts, delete; otherwise document.
- `package.json`: prune the file-by-file `scripts.check`; replace with a glob
  (`node --check src/*.js test/*.mjs`) so it stays correct.

### Untracked stragglers

- `data/knowledge-store.json.*.tmp` (two leftover atomic-write tempfiles).
  Delete; verify atomic write actually unlinks them on success — if it
  doesn't, that is a bug to fix during this overhaul.

### README

The "MCP Surface" section becomes the new 56-tool list, organized by the role
groups above. The `backend: official`
routing examples are removed; replaced with one short paragraph saying
"live access goes through `official_hopper_call`."

### Behavior preserved across the cuts

- All snapshot read shapes stay byte-identical to today's outputs (the
  official-style address-keyed objects, etc.).
- All transaction semantics unchanged.
- All resources still return what they return now.
- Lifecycle tools unchanged.

## Test plan

### Tiers

| Tier | When | Requires | Scripts |
|---|---|---|---|
| T0 — static | every save | none | `npm run check` |
| T1 — unit/protocol | every PR | none | `npm run smoke`, `npm run test:protocol`, `npm run test:store` |
| T2 — integration | every PR | sample binaries on disk | `npm run test:macho`, `npm run test:research`, `npm run test:lifecycle`, `npm run test:transactions`, `npm run test:snapshot` |
| T3 — live | nightly/manual | macOS, Hopper installed, Automation permission | `npm run test:live` |

### Test files (9 total)

| File | Covers | Tier |
|---|---|---|
| `test/protocol.mjs` | JSON-RPC framing; three protocol versions; capabilities; init handshake | T1 |
| `test/smoke.mjs` | boot server, `ingest_sample`, read every resource | T1 |
| `test/store.mjs` | knowledge-store unit tests: sessions, atomic writes, crash recovery, alias-fold, current-session | T1 |
| `test/lifecycle.mjs` | `open_session` / `close_session` / `set_current_session` / `ingest_*` orchestration; tempfile cleanup; concurrent ingest queueing | T2 |
| `test/macho.mjs` | `import_macho`, `disassemble_range`, `find_xrefs`, `find_functions`, `containing_function`; multi-arch slice selection; deep mode | T2 |
| `test/snapshot-mirror.mjs` | all 24 official-named snapshot readers + `resolve` + `query` + `analyze_function_deep` + `get_graph_slice` against fixed sample sessions | T2 |
| `test/transactions.mjs` | `begin → queue (every kind) → preview → commit/rollback`; `hypothesis` lifecycle; local-only path; live-write rejection without env+confirm flags | T2 |
| `test/research.mjs` | all 8 forensics tools against real binaries (ObjC, code-sign, entropy, fingerprints, similarity, anti-analysis, capability classify, diff_sessions) | T2 |
| `test/live.mjs` | `ingest_live_hopper` happy path + `full_export` + `include_pseudocode`; `official_hopper_call` to several official tools; `commit_transaction(backend:"official")` end-to-end with `confirm_live_write` | T3 |

Deleted: `all-tools-real.mjs`, `binary-zoo.mjs`, `deep-coverage.mjs`,
`hopper-real-app.mjs`, `live-hopper-aggressive.mjs`, `multi-binary.mjs`,
`procedure-resolution.mjs`, `real-app.mjs`, `research-integration.mjs`,
`session-lifecycle.mjs`. Their unique cases get folded into the 9 files above.

### Coverage matrix (must-pass before merge)

For each of the 56 tools:

1. Happy path — given a known sample, expected output shape.
2. Wrong session/address — clean error, no crash.
3. Argument validation — Zod schema rejects bad inputs with rpc-error -32602.
4. Output shape — matches the official server's shape where applicable.
5. Idempotency where relevant (calling `ingest_*` twice doesn't corrupt store;
   calling `rollback` twice errors cleanly).

For the 22 resources/templates: each has a smoke read against `ingest_sample`
output, plus one negative case (unknown address → JSON-RPC error).

### Cross-cutting tests

- **Atomic write / crash recovery:** kill the server mid-`commit_transaction`,
  restart, verify no `.tmp` litter and the JSON store is in either pre- or
  post-state, never half. (The current `data/knowledge-store.json.*.tmp`
  stragglers suggest this is broken and should be fixed during the overhaul.)
- **Concurrent ingests:** two `ingest_live_hopper` for same path → one runs,
  one dedupes. Two for different paths → serialized.
- **Backend disabled:** with `HOPPER_MCP_ENABLE_OFFICIAL_WRITES` unset, every
  official-write attempt rejects before touching anything.
- **Large output truncation:** `official_hopper_call` to `procedure_pseudo_code`
  of a big function caps at `max_result_chars` and surfaces the full result via
  `structuredContent` only when `include_full_result: true`.
- **Snapshot/live equivalence:** when both available, snapshot's
  `procedure_info("0x...")` and `official_hopper_call("procedure_info", {...})`
  return the same fields for the same function. (Sanity check; not strict
  equality — live can have edits not in snapshot.)

### Single-command runners

- `npm test` → T0 + T1 + T2 (no Hopper required, ~30 s).
- `npm run test:live` → T3 (requires Hopper; 2–5 min).
- `npm run test:all` → everything.

### Fixture strategy

Fetch from `/usr/bin/*` at test start; snapshot once. We already require macOS,
so this introduces no new constraint and avoids vendoring binaries. Targets:

- A trivial CLI (e.g. `/bin/echo`) for smoke.
- An ObjC-heavy binary (small AppKit utility) for ObjC/Swift extraction.
- A binary with anti-analysis indicators (`ptrace`, syscalls) for forensics.

If a fixture must be vendored (e.g. for reproducibility of fingerprint hashes),
keep it tiny and obviously non-malicious; document its provenance under
`test/fixtures/README.md`.

## Migration / breaking changes

This release is **not** backward-compatible by design.

- Clients calling `compare_with_hopper`, `hopper_decompile`, `hopper_assembly`,
  `hopper_callees`, `procedure`, `search`, `refresh_snapshot`, or `debug_echo`
  must update.
- Clients passing `backend: "official"` to any read tool must switch to
  `official_hopper_call`. The `backend:` flag survives only on
  `commit_transaction`.
- Server-side env: `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` and
  `HOPPER_MCP_ENABLE_DEBUG_TOOLS` semantics unchanged for the former; the
  latter is removed (debug tools no longer exist).

## Open questions

None blocking. To resolve during implementation:

- Whether `src/hopper-adapter.js` (45 lines) survives or is deleted.
- Whether `src/hopper-bridge.js` collapses meaningfully after per-tool live
  routing is removed.
- The precise atomic-write fix that makes `.tmp` stragglers impossible.

## Related docs

- `docs/official-hopper-mcp-notes.md` — clean-room behavioral notes.
- `docs/official-hoppermcpserver-re.md` — disassembly-derived interop notes.
- `docs/hopper-app-integration-research.md` — Hopper app surfaces, lifecycle.
- `docs/adapter-protocol.md` — long-term persistent adapter shape.
