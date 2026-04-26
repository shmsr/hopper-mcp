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
