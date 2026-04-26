# Hopper MCP Overhaul — Design

- **Status:** approved (brainstorming)
- **Date:** 2026-04-26
- **Owner:** subham sarkar
- **Branch target:** `main` (breaking changes accepted)
- **Audience:** LLM agents (this MCP is consumed by language models, not humans
  reading tool names off a help page)

## Summary

Cut Hopper MCP from 63 tools to ~30 by consolidating around discriminator
verbs that are easier for LLMs to use correctly and that cost less prompt
context. Enforce a single architectural invariant ("snapshot reader, live
passthrough, or mutator — never a mix"). Kill every per-tool `backend:` flag.
Consolidate the test suite from 16 files to 9 across four explicit tiers.

The Mach-O importer, transaction layer, and forensics capabilities are
preserved in scope; their *surface* shrinks because LLMs do better with fewer,
broader tools picking enum kinds than with 24 nearly-identical 1:1 official
mirror tools.

## Why LLM-first changes the answer

The earlier draft of this spec kept all 24 official-named snapshot mirror
tools to be a drop-in superset of `HopperMCPServer`. With LLMs as the only
consumer, every reason for that disappears:

- LLMs don't have a cursor. `current_address`, `current_procedure`,
  `current_document`, `next_address`, `prev_address` are useless.
- LLMs don't need name parity with another server's prompts.
- The full tool list lives in *every* prompt this MCP participates in.
  Every redundant tool definition is a tax on every call, forever.
- LLMs handle discriminator tools (`procedure(field: ...)`) better than
  five almost-identical procedure tools — fewer choices, smaller schema
  surface, less risk of picking the wrong one.

## Goals

1. Make every tool *unambiguously useful* to an LLM agent doing reverse
   engineering. If a human-only convenience is removed, that's success, not
   regret.
2. Enforce: every tool is a snapshot reader, a live passthrough, or a mutator
   — never a mix. No per-tool `backend:` flag.
3. Single live access point: `official_hopper_call`. The only place the
   `backend:` flag survives is `commit_transaction` (the one mutator that
   crosses local/live).
4. Reduce `server-tools.js` from 1972 lines to ~800 (target).
5. Crisp test tiers (T0 static, T1 unit, T2 integration, T3 live).

## Non-goals

- No new disassembler functionality.
- No persistent in-process Hopper adapter (still future work; tracked in
  `docs/adapter-protocol.md`).
- No new resource templates beyond `hopper://transactions/{id}`.
- No re-architecture of the JSON store or transaction manager.

## The architectural invariant

Every tool obeys exactly one of three roles. There is no fourth mode and no
per-tool `backend` flag.

| Role | Source of truth | Side effects | Examples |
|------|-----------------|--------------|----------|
| Snapshot reader | Local JSON store (last ingested session) | None | `procedure`, `search`, `list`, `xrefs`, `resolve`, `query` |
| Live passthrough | Hopper UI via XPC (through `HopperMCPServer`) | Whatever the official tool does | `official_hopper_call` |
| Mutator | Local JSON store + (on commit) optional live write-through | Writes JSON; optionally writes Hopper | `begin_transaction`, `queue`, `hypothesis`, `commit_transaction`, `import_macho`, `ingest_*` |

Consequences:

- Snapshot tools are deterministic and offline-capable. The model can use them
  without Hopper running.
- "I want live document state" → exactly one tool: `official_hopper_call`.
- Mutators are explicit about scope (local vs live) only at
  `commit_transaction` — not at every read site.

## Final tool surface (30)

### Meta (2)

- `capabilities` — server/adapter/backend capabilities, session list, active
  session id, list of feature flags. The LLM's first call after init.
- `official_hopper_call` — escape hatch for any live operation we don't expose
  directly (e.g. `set_addresses_names` to a live document, navigation,
  bookmarks). Rare, but the alternative is hard-coding ad-hoc passthroughs.

Removed: `official_hopper_tools` (LLMs don't need self-discovery; humans read
the README), `debug_echo`.

### Lifecycle (6)

- `import_macho` — local-only Mach-O import (no Hopper required).
- `ingest_live_hopper` — open executable in Hopper, run Python exporter,
  ingest the resulting normalized session.
- `ingest_official_hopper` — refresh local snapshot from Hopper's official
  MCP backend (the prior `refresh_snapshot` alias is removed).
- `open_session` — load a pre-indexed JSON payload (replay/testing).
- `close_session` — drop a session from the store.
- `set_current_session` — pick the active session for unscoped tool calls.

Removed: `ingest_sample` (test fixture, not a real surface — moves to test
helpers).

### Snapshot reads (9)

These read only the local JSON store. They are deterministic and require no
Hopper.

- `procedure` — `field`: `info` | `assembly` | `pseudo_code` | `callers` |
  `callees` | `comments`. Accepts addr or name; defaults to the active
  session's cursor procedure when omitted. **Replaces** `procedure_info`,
  `procedure_assembly`, `procedure_pseudo_code`, `procedure_callers`,
  `procedure_callees`, `comment`, `inline_comment`.
- `search` — `kind`: `strings` | `procedures` | `names`. `pattern` (regex
  unless `case_sensitive`), optional `semantic` for strings. **Replaces**
  `search_strings`, `search_procedures`, `search_name`.
- `list` — `kind`: `procedures` | `strings` | `names` | `segments` |
  `bookmarks` | `imports` | `exports`. Optional `detail` for procedures
  (`brief` | `size` | `info`). **Replaces** `list_procedures`,
  `list_procedure_size`, `list_procedure_info`, `list_strings`, `list_names`,
  `list_segments`, `list_bookmarks`.
- `xrefs` — references to/from an address (snapshot).
- `containing_function` — address-in-range lookup; "what function is this PC
  in?"
- `resolve` — fuzzy address/name/string → results. **Replaces**
  `procedure_address`, `address_name` (both are special cases of resolve).
- `query` — structured DSL (`name=`, `calls=`, `callers=`, `callees=`,
  `imports=`, `string=`, `tag=`, `capability=`, `anti=`, `addr=`,
  `pseudocode=`, `size=`; AND/OR/NOT/parens).
- `analyze_function_deep` — comprehensive single-function bundle: purpose,
  pseudocode, graph context, evidence anchors, provenance.
- `get_graph_slice` — caller/callee neighborhood with radius.

Deleted as snapshot reads (covered by the above or LLM-irrelevant):
`list_documents`, `current_document`, `current_address`, `current_procedure`,
`procedure_info`, `procedure_assembly`, `procedure_pseudo_code`,
`procedure_callers`, `procedure_callees`, `procedure_address`,
`address_name`, `list_segments`, `list_procedures`, `list_procedure_size`,
`list_procedure_info`, `list_strings`, `list_names`, `list_bookmarks`,
`search_strings`, `search_procedures`, `search_name`, `comment`,
`inline_comment`. **23 deletions.**

### Local binary helpers (3)

These need the executable on disk; they don't read the JSON snapshot, they
*scan*. Distinct enough to stay separate.

- `disassemble_range` — otool slice for a VM address range.
- `find_xrefs` — scan ARM64 disassembly for branches and ADRP+ADD/LDR refs.
- `find_functions` — frame-prologue function discovery.

### Transactions (6)

- `begin_transaction`
- `queue` — `kind`: `rename` | `comment` | `inline_comment` | `type_patch` |
  `tag` | `untag` | `rename_batch`.
- `hypothesis` — `action`: `create` | `link` | `status`. Kept separate from
  `queue` because the data shape (hypothesis ID space) is distinct enough
  that a fused schema would confuse the model.
- `preview_transaction`
- `commit_transaction` — the *only* tool with backend routing.
  `backend: "official"` + `confirm_live_write: true`, gated by
  `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1`.
- `rollback_transaction`

### Forensics (4)

- `analyze_binary` — `kind`: `capabilities` | `anti_analysis` | `entropy` |
  `code_signing` | `objc`. **Replaces** `classify_capabilities`,
  `detect_anti_analysis`, `compute_section_entropy`, `extract_code_signing`,
  `extract_objc_runtime` (5→1; all take just `session_id`).
- `compute_fingerprints` — per-function fingerprints (distinct args; not
  folded).
- `find_similar_functions` — cross-session similarity (distinct args).
- `diff_sessions` — two-session diff (distinct args).

## Resources (22)

Existing 21 entries kept verbatim. **One addition:**
`hopper://transactions/{id}` — read a specific transaction by id (currently
only the `pending` collection is exposed).

## Prompts (2)

`function_triage` and `hypothesis_workspace` — unchanged.

## Net change

Counts are exact. 63 = registered tools today including the env-gated
`debug_echo`.

| | Before | After | Δ |
|---|---|---|---|
| Total tools | 63 | 30 | −33 |
| Snapshot read tools | 31 | 9 | −22 |
| Forensics tools | 8 | 4 | −4 |
| `backend:` flag sites | 17 | 1 (`commit_transaction`) | −16 |
| Discriminator tools | 2 (`procedure`, `search`) | 4 (+`list`, `analyze_binary`) | +2 |
| `server-tools.js` lines | 1972 | ~800 (target) | −60% |
| Test files | 16 | 9 | −7 |
| Test lines | ~5000 | ~3000 (target) | −40% |

Tool deletions = 35 (see below); additions = 2 (`list`, `analyze_binary`);
net = −33.

The headline: **−52% of tools, −94% of `backend:` flag sites, −60% of
`server-tools.js`.** Every snapshot read goes through one of 9 tools. The
LLM never has to choose between five near-identical procedure tools.

## Removals (concrete)

### Tools deleted (35)

Snapshot mirror (23): `list_documents`, `current_document`, `current_address`,
`current_procedure`, `procedure_info`, `procedure_assembly`,
`procedure_pseudo_code`, `procedure_callers`, `procedure_callees`,
`procedure_address`, `address_name`, `list_segments`, `list_procedures`,
`list_procedure_size`, `list_procedure_info`, `list_strings`, `list_names`,
`list_bookmarks`, `search_strings`, `search_procedures`, `search_name`,
`comment`, `inline_comment`.

Forensics consolidations (5): `classify_capabilities`, `detect_anti_analysis`,
`compute_section_entropy`, `extract_code_signing`, `extract_objc_runtime`
(all folded into `analyze_binary`).

Mixed-mode comparators (4): `compare_with_hopper`, `hopper_decompile`,
`hopper_assembly`, `hopper_callees`.

Test-only / discovery (3): `debug_echo`, `ingest_sample`,
`official_hopper_tools`.

Plus removal of the per-tool `backend:` flag from 16 snapshot readers, and
consolidation of `refresh_snapshot` and `ingest_official_hopper` to the
single canonical name `ingest_official_hopper`. (`refresh_snapshot` may not
be a separate registration today — verify during implementation.)

### File-level changes

- `src/server-tools.js` (1972 → ~800): delete the 23 mirror tools, 5 forensics
  consolidations, 4 mixed-mode comparators, 3 test-only registrations; add
  `list` and `analyze_binary` discriminator handlers; rewrite `procedure`
  and `search` discriminators to subsume the deleted singletons; delete
  `officialRead` helper and every `backend === "official"` branch.
- `src/official-hopper-backend.js` (359): no public-API change; remains the
  live gateway for `official_hopper_call` and
  `commit_transaction(backend:"official")`.
- `src/server-helpers.js` (201): drop helpers used only by deleted comparison
  and mirror tools; audit unused exports.
- `src/hopper-bridge.js` (648): verify still needed. With per-tool live
  routing gone, it likely shrinks to just the `ingest_live_hopper` Python
  exporter glue. Likely outcome: file shrinks ~50% or merges into
  `hopper-live.js`.
- `src/server-resources.js`: add `hopper://transactions/{id}` template.
- `src/server-prompts.js`: unchanged.
- `src/sample-session.js`: keep — moves under `test/fixtures/` since it's
  test-only after `ingest_sample` is removed.
- `src/research-tools.js` (1079): unchanged internally; the 5 folded entry
  points become one dispatcher in `server-tools.js`.
- `src/macho-importer.js` (1325): unchanged.
- `src/knowledge-store.js` (580): add `getTransactionById` for the new
  resource; expose unified `list({kind})` and `procedure({field})` accessors
  to make the discriminator handlers thin.
- `src/transaction-manager.js` (241): unchanged.
- `src/hopper-adapter.js` (45): if unused after cuts, delete.
- `package.json`: prune the file-by-file `scripts.check`; replace with a
  glob (`node --check src/*.js test/*.mjs`).

### Untracked stragglers

- `data/knowledge-store.json.*.tmp` (two leftover atomic-write tempfiles).
  Delete; verify the atomic write actually unlinks them on success — if it
  doesn't, fix during the overhaul.

### README

The "MCP Surface" section becomes the new 30-tool list, organized by role.
The `backend: official` routing examples are removed; replaced with one
short paragraph explaining the snapshot/passthrough/mutator invariant.

### Behavior preserved across the cuts

- All snapshot read *outputs* stay shape-compatible with the official server's
  conventions (address-keyed objects, etc.) — they're just reached through a
  smaller tool surface.
- All transaction semantics unchanged.
- All resources still return what they return now.
- Lifecycle tools unchanged in semantics.

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
| `test/smoke.mjs` | boot server; load test fixture session; read every resource | T1 |
| `test/store.mjs` | knowledge-store unit tests: sessions, atomic writes, crash recovery, alias-fold, current-session, getTransactionById | T1 |
| `test/lifecycle.mjs` | `open_session` / `close_session` / `set_current_session` / `ingest_*` orchestration; tempfile cleanup; concurrent ingest queueing | T2 |
| `test/macho.mjs` | `import_macho`, `disassemble_range`, `find_xrefs`, `find_functions`; multi-arch slice selection; deep mode | T2 |
| `test/snapshot.mjs` | every kind of `procedure` / `search` / `list` / `analyze_binary`; `xrefs`, `containing_function`, `resolve`, `query`, `analyze_function_deep`, `get_graph_slice` against fixed sample sessions | T2 |
| `test/transactions.mjs` | `begin → queue (every kind) → preview → commit/rollback`; `hypothesis` lifecycle (create/link/status); local-only path; live-write rejection without env+confirm flags | T2 |
| `test/research.mjs` | `compute_fingerprints`, `find_similar_functions`, `diff_sessions`; the `analyze_binary` kinds against real binaries (capabilities, anti-analysis, entropy, code-signing, objc) | T2 |
| `test/live.mjs` | `ingest_live_hopper` happy path + `full_export` + `include_pseudocode`; `official_hopper_call` to several official tools; `commit_transaction(backend:"official")` end-to-end with `confirm_live_write` | T3 |

Deleted: `all-tools-real.mjs`, `binary-zoo.mjs`, `deep-coverage.mjs`,
`hopper-real-app.mjs`, `live-hopper-aggressive.mjs`, `multi-binary.mjs`,
`procedure-resolution.mjs`, `real-app.mjs`, `research-integration.mjs`,
`session-lifecycle.mjs`. Their unique cases get folded into the 9 files above.

### Coverage matrix (must-pass before merge)

For each of the 30 tools:

1. Happy path — given a known sample, expected output shape.
2. Wrong session/address — clean error, no crash.
3. Argument validation — Zod schema rejects bad inputs with rpc-error -32602.
4. Per-discriminator coverage: every `kind`/`field`/`action` enum value
   exercised at least once. (This is the new must-have given that 4 tools
   carry significant `kind` surface.)
5. Idempotency where relevant.

For the 22 resources/templates: each has a smoke read against a fixture
session, plus one negative case (unknown address → JSON-RPC error).

### Cross-cutting tests

- **Atomic write / crash recovery:** kill the server mid-`commit_transaction`,
  restart, verify no `.tmp` litter and the JSON store is in either pre- or
  post-state, never half. (The current `data/knowledge-store.json.*.tmp`
  stragglers indicate this is broken; fix during the overhaul.)
- **Concurrent ingests:** two `ingest_live_hopper` for same path → one runs,
  one dedupes. Two for different paths → serialized.
- **Backend disabled:** with `HOPPER_MCP_ENABLE_OFFICIAL_WRITES` unset, every
  official-write attempt rejects before touching anything.
- **Large output truncation:** `official_hopper_call` to `procedure_pseudo_code`
  of a big function caps at `max_result_chars`; full result via
  `structuredContent` only when `include_full_result: true`.
- **Discriminator equivalence:** the new `procedure(field:"info")` matches
  whatever `procedure_info` returns today (snapshot output preserved).
- **Snapshot/live correspondence:** when both available,
  `procedure({field:"info", procedure:"0x..."})` and
  `official_hopper_call("procedure_info", {procedure:"0x..."})` describe the
  same function (sanity, not strict equality — live can have edits).

### Single-command runners

- `npm test` → T0 + T1 + T2 (no Hopper required, ~30 s).
- `npm run test:live` → T3 (requires Hopper; 2–5 min).
- `npm run test:all` → everything.

### Fixture strategy

Fetch from `/usr/bin/*` at test start; snapshot once. We already require
macOS, so this introduces no new constraint and avoids vendoring binaries.
Targets:

- A trivial CLI (e.g. `/bin/echo`) for smoke.
- An ObjC-heavy binary (small AppKit utility) for ObjC/Swift extraction.
- A binary with anti-analysis indicators (`ptrace`, syscalls) for forensics.

If a fixture must be vendored (for reproducible fingerprint hashes), keep it
tiny and obviously non-malicious; document provenance under
`test/fixtures/README.md`.

## Migration / breaking changes

This release is **not** backward-compatible.

- Every `procedure_*`, `search_*`, `list_*`, `address_name`, `procedure_address`,
  `comment`, `inline_comment`, `current_*`, `next_address`, `prev_address`,
  `compare_with_hopper`, `hopper_*` tool name is gone. Clients route through
  `procedure(field:)`, `search(kind:)`, `list(kind:)`, `resolve`, or
  `official_hopper_call` for live UI ops.
- `classify_capabilities`, `detect_anti_analysis`, `compute_section_entropy`,
  `extract_code_signing`, `extract_objc_runtime` → `analyze_binary(kind:)`.
- `ingest_sample` → moved to test fixtures only.
- `official_hopper_tools` → removed; humans read README; LLMs don't need it.
- `debug_echo` → removed; never user-facing.
- `backend:` flag is removed from every read tool. Lives only on
  `commit_transaction`.
- `HOPPER_MCP_ENABLE_DEBUG_TOOLS` env var → no-op (debug tools no longer
  exist). `HOPPER_MCP_ENABLE_OFFICIAL_WRITES` semantics unchanged.

## Open questions

To resolve during implementation:

- Whether `src/hopper-adapter.js` (45 lines) survives or is deleted.
- Whether `src/hopper-bridge.js` shrinks ~50% or merges into `hopper-live.js`.
- The precise atomic-write fix that makes `.tmp` stragglers impossible.
- Final shape of `list({kind: "procedures", detail: "info"})` — verify the
  output object matches today's `list_procedure_info` byte-for-byte where the
  intent is parity, and is intentionally different where the consolidation
  improves the data shape.

## Related docs

- `docs/official-hopper-mcp-notes.md` — clean-room behavioral notes.
- `docs/official-hoppermcpserver-re.md` — disassembly-derived interop notes.
- `docs/hopper-app-integration-research.md` — Hopper app surfaces, lifecycle.
- `docs/adapter-protocol.md` — long-term persistent adapter shape.
