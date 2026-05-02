import test from "node:test";
import assert from "node:assert/strict";
import { startServer, startWithSample, sampleSession, decodeToolResult } from "./fixtures/index.mjs";

test("list({kind:'procedures'}) returns address-keyed object", async () => {
  const h = await startWithSample();
  try {
    const result = await h.call("list", { kind: "procedures" });
    const out = decodeToolResult(result);
    assert.equal(typeof out, "object");
    assert.ok(Object.keys(out).length > 0, "expected at least one procedure");
    for (const [addr, name] of Object.entries(out)) {
      assert.match(addr, /^0x[0-9a-f]+$/i);
      assert.equal(typeof name, "string");
    }
  } finally { await h.close(); }
});

test("list({kind:'procedures', detail:'size'}) returns objects with size + bb count", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "procedures", detail: "size" }));
    const first = Object.values(out)[0];
    assert.ok("size" in first && "basicblock_count" in first && "name" in first);
  } finally { await h.close(); }
});

test("list({kind:'strings'}) returns address-keyed object with values", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "strings" }));
    assert.ok(Object.values(out).every((s) => typeof s.value === "string"));
  } finally { await h.close(); }
});

test("list rejects unknown kind", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(() => h.call("list", { kind: "nonsense" }), /kind/i);
  } finally { await h.close(); }
});

test("list({kind:'segments'}) returns non-empty array of segments", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "segments" }));
    assert.ok(Array.isArray(out), "segments should be an array");
    assert.ok(out.length > 0, "expected at least one segment in sample session");
    // Each entry should have at least a name and start.
    for (const seg of out) {
      assert.equal(typeof seg, "object");
    }
  } finally { await h.close(); }
});

test("list({kind:'names'}) returns {name, demangled} entries and includes function renames", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "names" }));
    assert.equal(typeof out, "object");
    for (const [addr, entry] of Object.entries(out)) {
      assert.match(addr, /^0x[0-9a-f]+$/i);
      assert.equal(typeof entry, "object");
      assert.equal(typeof entry.name, "string");
      assert.ok("demangled" in entry);
    }
  } finally { await h.close(); }
});

test("list({kind:'bookmarks'}) returns array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "bookmarks" }));
    assert.ok(Array.isArray(out));
  } finally { await h.close(); }
});

test("list({kind:'imports'}) returns array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "imports" }));
    assert.ok(Array.isArray(out));
  } finally { await h.close(); }
});

test("list({kind:'exports'}) returns array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "exports" }));
    assert.ok(Array.isArray(out));
  } finally { await h.close(); }
});

test("analyze_binary({kind:'capabilities'}) returns counts + capped samples", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("analyze_binary", { kind: "capabilities" }));
    assert.equal(typeof out, "object");
    assert.equal(typeof out.totalImports, "number", "totalImports number");
    assert.ok(out.counts && typeof out.counts === "object", "counts object");
    assert.ok(out.samples && typeof out.samples === "object", "samples object");
    assert.ok(Array.isArray(out.truncated), "truncated array");
    // Every counts key must have a matching samples key (and vice versa).
    assert.deepEqual(Object.keys(out.counts).sort(), Object.keys(out.samples).sort());
    // max_per_bucket=2 must be honored.
    const capped = decodeToolResult(await h.call("analyze_binary", {
      kind: "capabilities", max_per_bucket: 2,
    }));
    for (const [bucket, sample] of Object.entries(capped.samples)) {
      assert.ok(sample.length <= 2, `samples[${bucket}] capped to 2: got ${sample.length}`);
    }
  } finally { await h.close(); }
});

// Snapshot-only analysis must not shell out against the fixture's synthetic
// binary path. Modes Hopper does not expose return unsupported payloads.
for (const kind of ["anti_analysis", "code_signing"]) {
  test(`analyze_binary({kind:'${kind}'}) returns a non-error result`, async () => {
    const h = await startWithSample();
    try {
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.notEqual(out, null);
    } finally { await h.close(); }
  });
}

// entropy used to shell out against the binary path. It now resolves from the
// Hopper snapshot only and reports unsupported when no exported raw bytes exist.
for (const kind of ["entropy"]) {
  test(`analyze_binary({kind:'${kind}'}) does not use local binary fallback`, async () => {
    const h = await startWithSample();
    try {
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.equal(out.supported, false);
      assert.equal(out.source, "hopper-snapshot");
    } finally { await h.close(); }
  });
}

test("analyze_binary({kind:'objc'}) uses exported snapshot metadata", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("analyze_binary", { kind: "objc" }));
    assert.equal(out.source, "hopper-snapshot");
    assert.equal(typeof out.supported, "boolean");
    assert.equal(out.supported, out.count > 0);
    assert.ok(Array.isArray(out.classes));
  } finally { await h.close(); }
});

test("analyze_binary rejects unknown kind", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(() => h.call("analyze_binary", { kind: "nope" }));
  } finally { await h.close(); }
});

test("hopper://transactions/{id} returns the matching transaction", async () => {
  const h = await startWithSample();
  try {
    const beginRes = await h.call("begin_transaction", { name: "test-txn" });
    const begin = decodeToolResult(beginRes);
    const id = begin.transactionId ?? begin.id;
    const read = await h.readResource(`hopper://transactions/${id}`);
    assert.ok(Array.isArray(read.contents) && read.contents.length > 0, "contents should be non-empty");
    const body = JSON.parse(read.contents[0].text);
    // Pin to the canonical field. transaction-manager stores .id on the
    // record; .transactionId is only used by the begin/preview return shape.
    assert.equal(body.id, id);
  } finally { await h.close(); }
});

test("hopper://transactions/{id} returns 404-equivalent for unknown id", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.readResource("hopper://transactions/unknown-xxx"),
      /No transaction 'unknown-xxx'/,
    );
  } finally { await h.close(); }
});

// ── procedure field coverage ──────────────────────────────────────────────

// procedure({field:"info"}) returns an officialProcedureInfo object with entrypoint + name.
test("procedure({field:'info'}) returns entrypoint-keyed info object", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "info", procedure: "0x100003f50" }),
    );
    assert.equal(typeof out, "object");
    assert.equal(out.name, "sub_100003f50");
    assert.equal(out.entrypoint, "0x100003f50");
  } finally { await h.close(); }
});

// procedure({field:"assembly"}) returns a string (may be empty for a fixture without raw bytes).
test("procedure({field:'assembly'}) returns a string", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "assembly", procedure: "0x100003f50" }),
    );
    assert.equal(typeof out, "string");
  } finally { await h.close(); }
});

// procedure({field:"pseudo_code"}) returns the pseudocode string for a fixture that has it.
test("procedure({field:'pseudo_code'}) returns pseudocode string containing 'sha256' or 'candidate'", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "pseudo_code", procedure: "0x100003f50" }),
    );
    assert.equal(typeof out, "string");
    assert.ok(
      /sha256|candidate/i.test(out),
      `expected pseudocode to mention sha256 or candidate; got: ${out}`,
    );
  } finally { await h.close(); }
});

// procedure({field:"callers"}) returns array — sub_100003f50 is called by _main.
test("procedure({field:'callers'}) returns array containing _main", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "callers", procedure: "0x100003f50" }),
    );
    assert.ok(Array.isArray(out), "callers should be an array");
    assert.ok(out.includes("_main"), `expected _main in callers; got ${JSON.stringify(out)}`);
  } finally { await h.close(); }
});

// procedure({field:"callees"}) returns array — sub_100003f50 calls sub_100004010.
test("procedure({field:'callees'}) returns array containing sub_100004010", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "callees", procedure: "0x100003f50" }),
    );
    assert.ok(Array.isArray(out), "callees should be an array");
    assert.ok(
      out.includes("sub_100004010"),
      `expected sub_100004010 in callees; got ${JSON.stringify(out)}`,
    );
  } finally { await h.close(); }
});

// Pre-fix: max_lines was honored for assembly but silently ignored on
// callers/callees and pseudo_code, so a hub function with thousands of
// callees would dump the whole list and blow the host's token budget.
// Honor max_lines on every text/list field, with a tail marker that says
// how many entries were dropped so callers know to widen.
test("procedure({field:'callees', max_lines:N}) caps the list and appends a truncation marker", async () => {
  const h = await startWithSample();
  try {
    const full = decodeToolResult(
      await h.call("procedure", { field: "callees", procedure: "0x100003f50" }),
    );
    assert.ok(Array.isArray(full) && full.length >= 2,
      `need a function with >=2 callees for the truncation test; got ${JSON.stringify(full)}`);
    const truncated = decodeToolResult(
      await h.call("procedure", { field: "callees", procedure: "0x100003f50", max_lines: 1 }),
    );
    assert.equal(truncated.length, 2,
      `expected 1 entry + 1 marker; got ${JSON.stringify(truncated)}`);
    assert.match(truncated[1], /\.\.\. \d+ more.*max_lines=0/i,
      `expected a tail marker telling the caller how to widen; got ${truncated[1]}`);
  } finally { await h.close(); }
});

// max_lines:0 (or omitted) means "no cap" — match the assembly convention.
test("procedure({field:'callees', max_lines:0}) returns the full list with no marker", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "callees", procedure: "0x100003f50", max_lines: 0 }),
    );
    assert.ok(Array.isArray(out));
    // No tail marker — every entry is a real callee name/addr.
    for (const entry of out) {
      assert.ok(!/\.\.\. \d+ more/.test(entry),
        `unexpected truncation marker in uncapped list: ${entry}`);
    }
  } finally { await h.close(); }
});

// callers shares the same code path as callees.
test("procedure({field:'callers', max_lines:N}) caps the list when there are more entries", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("procedure", { field: "callers", procedure: "0x100003f50", max_lines: 1 }),
    );
    assert.ok(Array.isArray(out) && out.length >= 1, `expected at least one caller; got ${JSON.stringify(out)}`);
    // Either the function has 1 caller (no marker) or N≥2 callers (marker on the second slot).
    if (out.length === 2) {
      assert.match(out[1], /\.\.\. \d+ more.*max_lines=0/i);
    }
  } finally { await h.close(); }
});

// pseudo_code with max_lines should slice and append a truncation marker.
test("procedure({field:'pseudo_code', max_lines:N}) caps the text and appends a truncation marker", async () => {
  const h = await startWithSample();
  try {
    const full = decodeToolResult(
      await h.call("procedure", { field: "pseudo_code", procedure: "0x100003f50" }),
    );
    const fullLines = full.split("\n");
    if (fullLines.length < 3) return; // fixture pseudocode is too short to truncate; skip silently.
    const truncated = decodeToolResult(
      await h.call("procedure", { field: "pseudo_code", procedure: "0x100003f50", max_lines: 2 }),
    );
    assert.ok(typeof truncated === "string");
    const lines = truncated.split("\n");
    assert.equal(lines.length, 3, `expected 2 head lines + 1 marker; got ${lines.length}`);
    assert.match(lines[2], /\.\.\. \d+ more pseudocode lines.*max_lines=0/i,
      `expected truncation marker; got ${lines[2]}`);
  } finally { await h.close(); }
});

// procedure with an unknown address should reject with an error.
test("procedure({field:'info'}) rejects unknown address", async () => {
  const h = await startWithSample();
  try {
    // resolveProcedure throws "Address 0x... is not the entrypoint of any
    // known function and is not contained in any known function body."
    await assert.rejects(
      () => h.call("procedure", { field: "info", procedure: "0xdeadbeef" }),
      /not the entrypoint|not contained|unknown procedure/i,
    );
  } finally { await h.close(); }
});

// Bare "Unknown procedure: foo" gave the user no next step. The hint now
// points at resolve() (substring + name index) and search({kind:'names'|...})
// (regex), mirroring the address-branch helpfulness so name misses are also
// actionable.
test("procedure({field:'info'}) on unknown name surfaces resolve/search hint", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("procedure", { field: "info", procedure: "totally_does_not_exist_xyz" }),
      /resolve.*search|search.*resolve/i,
    );
  } finally { await h.close(); }
});

// ── search coverage ───────────────────────────────────────────────────────

// search({kind:"strings"}) — "license" matches "license_key" in the fixture.
test("search({kind:'strings', pattern:'license'}) returns non-empty address-keyed object", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("search", { kind: "strings", pattern: "license" }),
    );
    assert.equal(typeof out, "object");
    assert.ok(Object.keys(out).length > 0, "expected at least one matching string");
  } finally { await h.close(); }
});

// search({kind:"procedures"}) — "main" matches "_main".
test("search({kind:'procedures', pattern:'main'}) returns non-empty address-keyed object", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("search", { kind: "procedures", pattern: "main" }),
    );
    assert.equal(typeof out, "object");
    assert.ok(Object.keys(out).length > 0, "expected at least one procedure matching 'main'");
  } finally { await h.close(); }
});

// search({kind:"names"}) — "sub_" matches sample function names.
test("search({kind:'names', pattern:'sub_'}) returns non-empty address-keyed object", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("search", { kind: "names", pattern: "sub_" }),
    );
    assert.equal(typeof out, "object");
    assert.ok(Object.keys(out).length > 0, "expected at least one name matching 'sub_'");
  } finally { await h.close(); }
});

// ── regression: search() applies a default cap of 500 ──────────────────────
// Pre-fix, search(kind:'procedures', pattern:'.*') against a 30k-procedure
// session emitted a 130KB+ payload that overflowed the MCP per-tool token
// budget. Mirror list()'s contract: undefined → cap at 500, explicit 0 →
// uncapped.
test("search({kind:'procedures', pattern:'.*'}) caps to 500 by default", async () => {
  const h = await startServer();
  try {
    // Build a session with 600 functions so the default 500 cap is observable.
    const session = sampleSession();
    for (let i = 0; i < 600; i++) {
      const addr = `0x100200000`.replace(/0$/, "") + (0x10 * i + 0x10).toString(16);
      session.functions.push({
        addr, name: `bulk_${i}`, size: 16,
        callers: [], callees: [], strings: [], imports: [],
        basicBlocks: [{ addr, summary: "trivial" }],
      });
    }
    await h.call("open_session", { session });
    const out = decodeToolResult(
      await h.call("search", { kind: "procedures", pattern: ".*" }),
    );
    assert.equal(typeof out, "object");
    assert.equal(Object.keys(out).length, 500,
      `expected 500 results at default cap; got ${Object.keys(out).length}`);
  } finally { await h.close(); }
});

test("search({kind:'procedures', pattern:'.*', max_results:0}) returns uncapped", async () => {
  const h = await startServer();
  try {
    const session = sampleSession();
    // Total functions: 3 from sample + 600 = 603.
    for (let i = 0; i < 600; i++) {
      const addr = `0x100200000`.replace(/0$/, "") + (0x10 * i + 0x10).toString(16);
      session.functions.push({
        addr, name: `bulk_${i}`, size: 16,
        callers: [], callees: [], strings: [], imports: [],
        basicBlocks: [{ addr, summary: "trivial" }],
      });
    }
    await h.call("open_session", { session });
    const out = decodeToolResult(
      await h.call("search", { kind: "procedures", pattern: ".*", max_results: 0 }),
    );
    assert.ok(Object.keys(out).length >= 600,
      `expected >=600 results when uncapped; got ${Object.keys(out).length}`);
  } finally { await h.close(); }
});

// Pre-fix: a search pattern like '(a+)+$' burns 60+ seconds in V8's
// backtracker on a 30-char string — the JSON-RPC loop freezes for the
// entire MCP host. Detect the canonical nested-quantifier shape statically
// and reject before compile so a typo or copy-pasted pattern can't DoS
// the server.
test("search rejects patterns with nested unbounded quantifiers (ReDoS)", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("search", { kind: "names", pattern: "(a+)+$" }),
      /nested unbounded quantifiers|catastrophic backtracking/i,
    );
    await assert.rejects(
      () => h.call("search", { kind: "names", pattern: "(.*)+" }),
      /nested unbounded quantifiers|catastrophic backtracking/i,
    );
    await assert.rejects(
      () => h.call("search", { kind: "names", pattern: "(.+){5,}" }),
      /nested unbounded quantifiers|catastrophic backtracking/i,
    );
  } finally { await h.close(); }
});

// Permissive case: ordinary patterns shouldn't trip the detector.
// '(?:foo)+' is a non-capturing group with a single quantifier — fine.
test("search accepts non-pathological patterns with grouping/quantifiers", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("search", { kind: "names", pattern: "(?:sub|main)" }),
    );
    assert.equal(typeof out, "object");
  } finally { await h.close(); }
});

// query DSL sees regex literals via /pattern/flags. The same fence applies.
test("query DSL rejects /regex/ predicate with nested unbounded quantifiers", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "name:/(a+)+/" }),
      /nested unbounded quantifiers|catastrophic backtracking/i,
    );
  } finally { await h.close(); }
});

// search with an invalid kind should reject.
test("search({kind:'wrong'}) rejects with schema validation error", async () => {
  const h = await startWithSample();
  try {
    // Zod surfaces the bad enum as an "invalid"/"expected" message naming `kind`.
    await assert.rejects(
      () => h.call("search", { kind: "wrong", pattern: "x" }),
      /kind/i,
    );
  } finally { await h.close(); }
});

// ── xrefs ─────────────────────────────────────────────────────────────────

// xrefs({address:"0x100003f50"}) — called by _main (0x100004120); callee edge should appear.
test("xrefs({address:'0x100003f50'}) returns array containing caller 0x100004120", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("xrefs", { address: "0x100003f50" }),
    );
    // snapshotXrefs returns an array of addresses that reference the target.
    assert.ok(Array.isArray(out), `expected array; got ${JSON.stringify(out)}`);
    assert.ok(
      out.includes("0x100004120"),
      `expected 0x100004120 in xrefs; got ${JSON.stringify(out)}`,
    );
  } finally { await h.close(); }
});

// ── containing_function ───────────────────────────────────────────────────

// An exact entrypoint address returns match="entrypoint".
test("containing_function({address:'0x100003f50'}) returns match='entrypoint'", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("containing_function", { address: "0x100003f50" }),
    );
    assert.equal(out.match, "entrypoint");
    assert.equal(out.offset, 0);
  } finally { await h.close(); }
});

// An address inside sub_100003f50's body (size=192) returns match="containment".
test("containing_function({address:'0x100003fa8'}) returns match='containment' with offset>0", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("containing_function", { address: "0x100003fa8" }),
    );
    assert.equal(out.match, "containment");
    assert.ok(out.offset > 0, `expected offset > 0; got ${out.offset}`);
  } finally { await h.close(); }
});

// An address that falls outside all known function ranges returns match="none".
test("containing_function({address:'0xdeadbeef'}) returns match='none'", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("containing_function", { address: "0xdeadbeef" }),
    );
    assert.equal(out.match, "none");
  } finally { await h.close(); }
});

// ── resolve ───────────────────────────────────────────────────────────────

// resolve by address — 0x100003f50 maps to sub_100003f50.
test("resolve({query:'0x100003f50'}) returns non-empty result array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("resolve", { query: "0x100003f50" }),
    );
    assert.ok(Array.isArray(out) && out.length > 0, "expected at least one result");
    assert.equal(out[0].kind, "function");
  } finally { await h.close(); }
});

// resolve by name — "_main" resolves to the entrypoint function.
test("resolve({query:'_main'}) returns non-empty result array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("resolve", { query: "_main" }),
    );
    assert.ok(Array.isArray(out) && out.length > 0, "expected at least one result for _main");
  } finally { await h.close(); }
});

// resolve by string value — "license_key" appears in both function strings and the strings table.
test("resolve({query:'license_key'}) returns non-empty result array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("resolve", { query: "license_key" }),
    );
    assert.ok(Array.isArray(out) && out.length > 0, "expected at least one result for license_key");
  } finally { await h.close(); }
});

// resolve("") used to return 20 random fingerprint dumps because
// `haystack.includes("")` is true for every haystack — the indexer accepted
// the empty query as "match anything" and ranked unrelated functions at
// 0.65. Reject it explicitly so the caller knows what shape resolve takes.
test("resolve({query:''}) rejects with a hint pointing at supported query shapes", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("resolve", { query: "" }),
      /non-empty query|address.*name.*string|list.*procedures/i,
    );
    // Same rejection on whitespace-only — the trim() is what keys the check.
    await assert.rejects(
      () => h.call("resolve", { query: "   " }),
      /non-empty query|address.*name.*string|list.*procedures/i,
    );
  } finally { await h.close(); }
});

// ── regression: resolve hints when the indexed snapshot misses ─────────────
// On Raycast probe: a hex addr that isn't a function entrypoint (e.g. __stubs)
// or a regex-style query both returned bare []. Now both surface a typed
// stub with a `hint` so the caller knows the next step (containing_function
// for addrs, search() for regex). Without the hint they look identical to a
// "no such address" miss and waste a round trip.
//
// This also guards that resolve() does not try to scan the local binary.
test("resolve({query:'0xdeadbeef0001'}) returns unresolved_address stub with hint", async () => {
  const h = await startServer();
  try {
    await h.call("open_session", {
      session: {
        sessionId: "no-path",
        binary: { name: "noPathBin", arch: "arm64" },
        functions: [{
          addr: "0x100001000", name: "only_fn", size: 32,
          callers: [], callees: [], strings: [], imports: [],
          basicBlocks: [{ addr: "0x100001000", summary: "trivial" }],
        }],
      },
    });
    const out = decodeToolResult(
      await h.call("resolve", { query: "0xdeadbeef0001" }),
    );
    assert.ok(Array.isArray(out) && out.length === 1,
      `expected single hint stub; got ${JSON.stringify(out)}`);
    assert.equal(out[0].kind, "unresolved_address");
    assert.equal(out[0].addr, "0xdeadbeef0001");
    assert.match(out[0].hint, /containing_function/i,
      `hint should point at containing_function; got: ${out[0].hint}`);
  } finally { await h.close(); }
});

test("resolve({query:'/^totally_no_match/i'}) returns regex_unsupported stub with hint", async () => {
  const h = await startServer();
  try {
    await h.call("open_session", {
      session: {
        sessionId: "no-path-rx",
        binary: { name: "noPathBin", arch: "arm64" },
        functions: [{
          addr: "0x100001000", name: "only_fn", size: 32,
          callers: [], callees: [], strings: [], imports: [],
          basicBlocks: [{ addr: "0x100001000", summary: "trivial" }],
        }],
      },
    });
    const q = "/^totally_no_match/i";
    const out = decodeToolResult(await h.call("resolve", { query: q }));
    assert.ok(Array.isArray(out) && out.length === 1,
      `expected single hint stub; got ${JSON.stringify(out)}`);
    assert.equal(out[0].kind, "regex_unsupported");
    assert.equal(out[0].query, q);
    assert.match(out[0].hint, /search\(/i,
      `hint should point at search(); got: ${out[0].hint}`);
  } finally { await h.close(); }
});

// Real names still pass through and aren't mistaken for regex-style queries.
test("resolve({query:'_main'}) is not mis-classified as regex_unsupported", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("resolve", { query: "_main" }));
    assert.ok(Array.isArray(out) && out.length > 0);
    assert.notEqual(out[0].kind, "regex_unsupported",
      `_main should resolve normally, not hit regex hint: ${JSON.stringify(out[0])}`);
  } finally { await h.close(); }
});

// ── query ─────────────────────────────────────────────────────────────────

// query with name: predicate matching a known function name (DSL uses colon separator).
test("query({expression:'name:sub_100003f50'}) returns count>=1 and matches array", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("query", { expression: "name:sub_100003f50" }),
    );
    assert.equal(typeof out, "object");
    assert.ok(out.count >= 1, `expected count >= 1; got ${out.count}`);
    assert.ok(Array.isArray(out.matches), "matches should be an array");
  } finally { await h.close(); }
});

// query with imports: predicate — _ptrace is imported by _main (DSL uses colon separator).
test("query({expression:'imports:_ptrace'}) returns count>=1", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("query", { expression: "imports:_ptrace" }),
    );
    assert.ok(out.count >= 1, `expected count >= 1; got ${out.count}`);
    assert.ok(Array.isArray(out.matches));
  } finally { await h.close(); }
});

// ── query DSL: malformed input rejects loudly instead of returning count:0 ─

// Empty expression used to fall through parseAtom's `{kind:"true"}` branch
// and silently match every function in the session (capped to maxResults).
test("query({expression:''}) rejects empty expression with a parse error", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "" }),
      /empty/i,
    );
  } finally { await h.close(); }
});

// Unknown predicates used to silently return count:0, indistinguishable from
// "valid predicate, no matches". Reject at parse time with a useful list.
test("query({expression:'bogus_predicate:foo'}) rejects with supported-predicate list", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "bogus_predicate:foo" }),
      /Unknown query predicate.*bogus_predicate/i,
    );
  } finally { await h.close(); }
});

// An unclosed quote used to make tokeniseQuery eat the rest of the input
// into a single predicate value, producing a degenerate AST that matched
// nothing without ever signalling the parse failure.
test("query({expression:'name:\"unclosed'}) rejects unclosed quote", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: 'name:"unclosed' }),
      /unclosed quote/i,
    );
  } finally { await h.close(); }
});

// `name:` with empty value used to match every function — regexOrEqual("")
// returns a matcher whose .test() is always true (String.includes("")). On
// real binaries that quietly returned the entire procedure table capped at
// max_results=50. Reject at parse time and point the caller at the
// `name:.*` regex form for "match everything".
test("query({expression:'name:'}) rejects empty predicate value with a hint", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "name:" }),
      /empty value|name:.*regex|substring/i,
    );
  } finally { await h.close(); }
});

// `size:abc` used to silently return count:0 because evalNumeric returned
// `false` for any expr that didn't match its strict numeric regex. Reject
// at parse time so a typo doesn't masquerade as "no matching functions".
test("query({expression:'size:abc'}) rejects malformed numeric predicate", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "size:abc" }),
      /size:abc.*malformed|size.*expected/i,
    );
  } finally { await h.close(); }
});

// `size > 100` (with spaces) used to tokenize as three bare-name searches
// AND'd together: name:size AND name:> AND name:100. Every WhatsApp-sized
// session would confidently report count:0 because no function is named
// "size" — masking the colon-omission as "no results". Throw with a hint.
// Surfaced live on WhatsApp at the round-11 probe.
test("query({expression:'size > 100'}) rejects with a hint about the colon syntax", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "size > 100" }),
      /bare.*size.*predicate|size:VALUE|size:>100/i,
    );
  } finally { await h.close(); }
});

// Same trap, just the bare keyword on its own.
test("query({expression:'addr'}) rejects bare predicate keyword without colon", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("query", { expression: "addr" }),
      /bare.*addr.*predicate|addr:VALUE/i,
    );
  } finally { await h.close(); }
});

// Don't break the explicit form. `name:size` is a real, valid name search
// (looking for a function literally named "size") and must not collide
// with the bare-keyword detector.
test("query({expression:'name:size'}) is accepted (explicit predicate, not bare)", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("query", { expression: "name:size" }));
    assert.equal(typeof out.count, "number",
      "name:size should parse and execute, even if it returns 0 matches");
  } finally { await h.close(); }
});

// ── analyze_function_deep ─────────────────────────────────────────────────

// analyze_function_deep returns a rich object with at minimum a function + pseudocode field.
test("analyze_function_deep({addr:'0x100003f50'}) returns object with pseudocode and evidenceAnchors", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("analyze_function_deep", { addr: "0x100003f50" }),
    );
    assert.equal(typeof out, "object");
    // The store returns: function, inferredPurpose, confidence, callers, callees,
    // stringsTouched, importsTouched, selectorsTouched, evidenceAnchors, pseudocode,
    // assemblySlices, provenance.
    assert.ok("function" in out, "expected 'function' key");
    assert.ok("pseudocode" in out, "expected 'pseudocode' key");
    assert.ok("evidenceAnchors" in out, "expected 'evidenceAnchors' key");
  } finally { await h.close(); }
});

// analyze_function_deep with an unknown address should reject — getFunction
// throws "Unknown function address: 0x...".
test("analyze_function_deep({addr:'0xdeadbeef'}) rejects with unknown-function error", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("analyze_function_deep", { addr: "0xdeadbeef" }),
      /Unknown function address/i,
    );
  } finally { await h.close(); }
});

// ── get_graph_slice ───────────────────────────────────────────────────────

// get_graph_slice with kind="calls" returns a graph object with nodes and edges.
test("get_graph_slice radius=1 kind='calls' returns a graph object", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("get_graph_slice", { seed: "0x100003f50", radius: 1, kind: "calls" }),
    );
    // getGraphSlice always returns { root, nodes, edges } regardless of kind;
    // pin to nodes (the same shape callers/callees tests below assert) so a
    // regression that drops nodes for kind="calls" can't slip through.
    assert.ok(Array.isArray(out.nodes), `expected nodes array; got ${JSON.stringify(out)}`);
    assert.ok(out.nodes.length > 0, "calls graph from a connected seed should be non-empty");
  } finally { await h.close(); }
});

// get_graph_slice with kind="callers" — sub_100003f50 is called by _main.
test("get_graph_slice kind='callers' returns graph with _main in nodes", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("get_graph_slice", { seed: "0x100003f50", radius: 1, kind: "callers" }),
    );
    assert.ok(Array.isArray(out.nodes), "nodes should be an array");
    const names = out.nodes.map((n) => n.name);
    assert.ok(names.includes("_main"), `expected _main in callers graph nodes; got ${JSON.stringify(names)}`);
  } finally { await h.close(); }
});

// get_graph_slice with kind="callees" — sub_100003f50 calls sub_100004010.
test("get_graph_slice kind='callees' returns graph with sub_100004010 in nodes", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("get_graph_slice", { seed: "0x100003f50", radius: 1, kind: "callees" }),
    );
    assert.ok(Array.isArray(out.nodes), "nodes should be an array");
    const names = out.nodes.map((n) => n.name);
    assert.ok(
      names.includes("sub_100004010"),
      `expected sub_100004010 in callees graph nodes; got ${JSON.stringify(names)}`,
    );
  } finally { await h.close(); }
});

// ── regression: get_graph_slice routes seed through resolveProcedure ───────
// Pre-fix it called store.getFunction directly, so a function name (e.g.
// "_main") or a mid-function addr returned bare "Unknown function address"
// even though the same input worked fine in `procedure` and
// `find_similar_functions`. Now seed accepts the same shapes those tools do.
test("get_graph_slice({seed:'_main'}) accepts a function name", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("get_graph_slice", { seed: "_main", radius: 1, kind: "callees" }),
    );
    assert.ok(Array.isArray(out.nodes) && out.nodes.length >= 1,
      `expected at least one node; got ${JSON.stringify(out)}`);
    const addrs = out.nodes.map((n) => n.addr);
    assert.ok(addrs.includes("0x100004120"),
      `expected _main entrypoint 0x100004120 in nodes; got ${JSON.stringify(addrs)}`);
  } finally { await h.close(); }
});

test("get_graph_slice({seed:'0x100003fa8'}) accepts a mid-function addr via containment", async () => {
  // 0x100003fa8 is inside sub_100003f50's body (entrypoint 0x100003f50, size 192).
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("get_graph_slice", { seed: "0x100003fa8", radius: 1, kind: "callees" }),
    );
    const addrs = out.nodes.map((n) => n.addr);
    assert.ok(addrs.includes("0x100003f50"),
      `expected containment to resolve to entrypoint 0x100003f50; got ${JSON.stringify(addrs)}`);
  } finally { await h.close(); }
});

// Hub functions can balloon a graph slice — every known node ships its full
// fingerprint (simhash + minhash + stringBag), so a high-fanout root at
// radius 3+ can serialize past the host budget. max_nodes caps BFS at the
// frontier and signals truncation so callers can paginate down.
test("get_graph_slice({max_nodes:1}) signals truncation when frontier exceeds cap", async () => {
  const h = await startWithSample();
  try {
    // Sample _main calls 0x100003f50 which calls 0x100004010 — so kind=calls
    // at radius 2 explores 3 nodes. max_nodes=1 forces the cap to bite.
    const out = decodeToolResult(
      await h.call("get_graph_slice", {
        seed: "_main", radius: 2, kind: "calls", max_nodes: 1,
      }),
    );
    assert.equal(out.truncated, true, `expected truncated:true; got ${JSON.stringify(out)}`);
    assert.equal(out.maxNodes, 1, "echoes cap back");
    assert.equal(out.nodes.length, 1, "only the root inside the cap");
  } finally { await h.close(); }
});

// Default (max_nodes=200) leaves typical neighborhoods intact — the cap must
// not silently truncate a small graph. Guards against off-by-one in the cap
// check (e.g. seen.size > maxNodes vs >=).
test("get_graph_slice without max_nodes returns truncated:false on small graphs", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("get_graph_slice", { seed: "_main", radius: 2, kind: "calls" }),
    );
    assert.equal(out.truncated, false, `expected truncated:false; got ${JSON.stringify(out)}`);
  } finally { await h.close(); }
});

// ── negative cases ────────────────────────────────────────────────────────

// xrefs for an unknown address returns an empty array (no cross-references exist).
test("xrefs({address:'0xdeadbeef'}) returns empty array for unknown address", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("xrefs", { address: "0xdeadbeef" }),
    );
    assert.ok(Array.isArray(out), `expected array; got ${JSON.stringify(out)}`);
    assert.equal(out.length, 0, `expected empty array; got ${JSON.stringify(out)}`);
  } finally { await h.close(); }
});

// resolve is snapshot-only. A plain substring miss returns an empty result;
// typed hint stubs are reserved for address and regex-shaped queries.
test("resolve({query:'this_will_not_match_anything_xyz'}) returns [] for no-match query", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("resolve", { query: "this_will_not_match_anything_xyz" }));
    assert.deepEqual(out, []);
  } finally { await h.close(); }
});

// query with a name predicate that matches nothing returns count=0 and empty matches.
test("query({expression:'name:does_not_exist_xyz'}) returns count=0 and empty matches", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(
      await h.call("query", { expression: "name:does_not_exist_xyz" }),
    );
    assert.equal(out.count, 0, `expected count 0; got ${out.count}`);
    assert.ok(Array.isArray(out.matches) && out.matches.length === 0, "expected empty matches array");
  } finally { await h.close(); }
});

// get_graph_slice with an unknown seed surfaces the helpful resolveProcedure
// hint pointing at containing_function. Pre-fix it threw bare 'Unknown
// function address: 0xdeadbeef' from store.getFunction with no next step.
test("get_graph_slice({seed:'0xdeadbeef'}) rejects with containing_function hint", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("get_graph_slice", { seed: "0xdeadbeef", radius: 1, kind: "calls" }),
      /containing_function|not the entrypoint/i,
    );
  } finally { await h.close(); }
});

// ── procedure({field:'comments'}) ────────────────────────────────────────

test("procedure({field:'comments'}) returns prefix + inline comments map", async () => {
  const h = await startWithSample();
  try {
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const out = decodeToolResult(await h.call("procedure", { field: "comments", procedure: addr }));
    assert.ok("prefix" in out && "inline" in out);
    assert.equal(typeof out.prefix, "object");
    assert.equal(typeof out.inline, "object");
    // Fixture has a prefix comment at the entrypoint and an inline comment at
    // an instruction within the function range. Asserting that real strings
    // come through guards against future regressions to the wrong field name
    // (which would silently produce undefined values).
    assert.equal(typeof out.prefix[addr], "string");
    assert.ok(out.prefix[addr].length > 0);
    const inlineValues = Object.values(out.inline);
    assert.ok(inlineValues.length > 0 && inlineValues.every((v) => typeof v === "string" && v.length > 0));
  } finally { await h.close(); }
});

// ── regression: resolve honors max_results on the primary path ─────────────
// Before this fix, max_results only capped the old fallback path; the primary
// store.resolve() path returned every fuzzy hit. resolve("main") against
// Raycast returned 20 fingerprint-heavy hits regardless of the cap.
test("resolve({query, max_results:N}) caps the primary path output", async () => {
  const h = await startServer();
  try {
    // Build a session with several similarly-named functions so the fuzzy
    // resolver can return more than two hits. NOTE: sampleSession().functions
    // is an Array, so push() — `session.functions[addr] = ...` would set a
    // named property the array branch of normalizeSession skips entirely.
    const session = sampleSession();
    for (const [addr, name] of [
      ["0x100100000", "main_a"],
      ["0x100100020", "main_b"],
      ["0x100100040", "main_c"],
      ["0x100100060", "main_d"],
    ]) {
      session.functions.push({
        addr, name, size: 32, basicBlocks: [], callers: [], callees: [],
      });
    }
    await h.call("open_session", { session });
    // Without the cap, the resolver returns >=5 main_* matches plus _main.
    const uncapped = decodeToolResult(await h.call("resolve", { query: "main" }));
    assert.ok(uncapped.length >= 5,
      `expected uncapped resolve('main') to return >=5 hits; got ${uncapped.length}`);
    const out = decodeToolResult(await h.call("resolve", { query: "main", max_results: 2 }));
    assert.ok(Array.isArray(out), "result is array");
    assert.equal(out.length, 2, `expected exactly 2 results; got ${out.length}`);
  } finally { await h.close(); }
});

// ── regression: snapshotXrefs includes target.callers directly ─────────────
// Importer asymmetry: target.callers stores canonical entrypoints, but
// caller.callees stores raw edge.to addresses that may not match. The scan
// missed callers that lived in target.callers without a reciprocal entry in
// caller.callees. Fix: pull target.callers directly.
test("xrefs includes entries in target.callers even when caller.callees lacks the reverse edge", async () => {
  const h = await startServer();
  try {
    const session = sampleSession();
    // Construct the asymmetric case explicitly: F2 lists F1 as a caller, but
    // F1's callees list does NOT include F2 (the deep-importer scenario where
    // raw call-target addr lands inside F2 but at a non-entrypoint offset).
    // NOTE: sampleSession().functions is an Array, push() to add entries.
    session.functions.push({
      addr: "0x200000000", name: "F1", size: 64,
      basicBlocks: [], callers: [], callees: [], // intentionally empty
    });
    session.functions.push({
      addr: "0x200001000", name: "F2", size: 64,
      basicBlocks: [], callers: ["0x200000000"], callees: [], // canonical caller only
    });
    await h.call("open_session", { session });
    const out = decodeToolResult(await h.call("xrefs", { address: "0x200001000" }));
    assert.ok(Array.isArray(out), "xrefs returned array");
    assert.ok(out.includes("0x200000000"),
      `expected F1 (0x200000000) in xrefs; got ${JSON.stringify(out)}`);
  } finally { await h.close(); }
});

// ── regression: procedure(assembly) emits "not captured" hint when empty ───
// Used to silently return "" when the deep MachO importer didn't populate
// basic-block instructions. The new message mirrors pseudo_code's hint so
// callers know how to upgrade (re-ingest with use_hopper=true).
test("procedure({field:'assembly'}) returns helpful hint when basicBlocks lack instructions", async () => {
  const h = await startServer();
  try {
    const session = sampleSession();
    // sampleSession().functions is an Array; push() instead of named-key set.
    session.functions.push({
      addr: "0x300000000", name: "no_asm", size: 64,
      basicBlocks: [{ addr: "0x300000000", summary: "no instructions" }],
      callers: [], callees: [],
    });
    await h.call("open_session", { session });
    const out = decodeToolResult(
      await h.call("procedure", { field: "assembly", procedure: "0x300000000" }),
    );
    assert.equal(typeof out, "string");
    assert.match(out, /not captured/i,
      `expected 'not captured' hint; got: ${out}`);
  } finally { await h.close(); }
});
