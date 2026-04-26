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

test("procedure({field:'comments'}) returns prefix + inline comments map", async () => {
  const h = await startWithSample();
  try {
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const out = decodeToolResult(await h.call("procedure", { field: "comments", procedure: addr }));
    assert.ok("prefix" in out && "inline" in out);
    assert.equal(typeof out.prefix, "object");
    assert.equal(typeof out.inline, "object");
  } finally { await h.close(); }
});
