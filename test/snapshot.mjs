import test from "node:test";
import assert from "node:assert/strict";
import { startWithSample, decodeToolResult } from "./fixtures/index.mjs";

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

test("analyze_binary({kind:'capabilities'}) returns capability buckets", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("analyze_binary", { kind: "capabilities" }));
    assert.equal(typeof out, "object");
    // Expect at least the buckets that are non-empty; structure: {bucket: [imports]}.
    for (const [bucket, list] of Object.entries(out)) {
      assert.ok(Array.isArray(list));
      assert.ok(typeof bucket === "string");
    }
  } finally { await h.close(); }
});

// anti_analysis is pure in-memory and never shells out.
// code_signing shells out to codesign, but extractCodeSigning catches its own
// subprocess errors and returns them as result.error rather than throwing.
// Both therefore resolve OK even when the fixture's binary path is synthetic.
for (const kind of ["anti_analysis", "code_signing"]) {
  test(`analyze_binary({kind:'${kind}'}) returns a non-error result`, async () => {
    const h = await startWithSample();
    try {
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.notEqual(out, null);
    } finally { await h.close(); }
  });
}

// entropy + objc shell out to otool against the binary path. Against the
// fixture's synthetic /tmp/SampleMachO path otool fails — assert that the
// error propagates (matches legacy compute_section_entropy / extract_objc_runtime).
for (const kind of ["entropy", "objc"]) {
  test(`analyze_binary({kind:'${kind}'}) propagates errors when binary path is invalid`, async () => {
    const h = await startWithSample();
    try {
      await assert.rejects(() => h.call("analyze_binary", { kind }));
    } finally { await h.close(); }
  });
}

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

// procedure with an unknown address should reject with an error.
test("procedure({field:'info'}) rejects unknown address", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("procedure", { field: "info", procedure: "0xdeadbeef" }),
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

// search with an invalid kind should reject.
test("search({kind:'wrong'}) rejects with schema validation error", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(() => h.call("search", { kind: "wrong", pattern: "x" }));
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

// analyze_function_deep with an unknown address should reject.
test("analyze_function_deep({addr:'0xdeadbeef'}) rejects with unknown-function error", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("analyze_function_deep", { addr: "0xdeadbeef" }),
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
    assert.ok(out && typeof out === "object");
    assert.ok("nodes" in out || "callers" in out || "callees" in out, "graph slice should expose nodes or call lists");
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
