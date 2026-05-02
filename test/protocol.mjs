import test from "node:test";
import assert from "node:assert/strict";
import { startServer } from "./fixtures/index.mjs";

// Indirect coverage of the initialize handshake: startServer() throws if
// the server doesn't successfully negotiate, so a green tools/list call
// proves the lifecycle (initialize → notifications/initialized → tools/list)
// completes end-to-end.
test("server completes initialize handshake and exposes tools", async () => {
  const h = await startServer();
  try {
    const tools = await h.listTools();
    assert.ok(Array.isArray(tools.tools));
    assert.ok(tools.tools.length > 0);
  } finally { await h.close(); }
});

test("tools/list returns required tool fields", async () => {
  const h = await startServer();
  try {
    const { tools } = await h.listTools();
    for (const tool of tools) {
      assert.ok(typeof tool.name === "string" && tool.name.length > 0);
      assert.ok(tool.inputSchema, `tool ${tool.name} missing inputSchema`);
    }
  } finally { await h.close(); }
});

test("ingest_live_hopper exposes loader checkbox overrides in its schema", async () => {
  const h = await startServer();
  try {
    const { tools } = await h.listTools();
    const ingest = tools.find((tool) => tool.name === "ingest_live_hopper");
    assert.ok(ingest);
    assert.deepEqual(ingest.inputSchema.properties.loader_checkboxes, {
      type: "array",
      items: {
        type: "string",
      },
    });
  } finally { await h.close(); }
});

test("tools/list does not expose local Mach-O fallback tools", async () => {
  const h = await startServer();
  try {
    const { tools } = await h.listTools();
    const names = new Set(tools.map((tool) => tool.name));
    for (const removed of ["import_macho", "disassemble_range", "find_xrefs", "find_functions"]) {
      assert.equal(names.has(removed), false, `${removed} must not be exposed`);
    }
  } finally { await h.close(); }
});

test("calling unknown tool returns clean error", async () => {
  const h = await startServer();
  try {
    await assert.rejects(() => h.call("nonexistent_tool_xxx", {}));
  } finally { await h.close(); }
});

test("malformed tool input is rejected with a descriptive error", async () => {
  const h = await startServer();
  try {
    // `list.kind` is a Zod enum. The SDK surfaces schema-validation
    // failures inside a tools/call response as `isError: true` content
    // (which our harness reflects as a rejected promise carrying the
    // text). Both halves of the conjunction must match so neither side
    // can silently drift.
    await assert.rejects(
      () => h.call("list", { kind: 42 }),
      (err) => /kind/i.test(err.message) && /(invalid|expected)/i.test(err.message),
    );
  } finally { await h.close(); }
});

// Pre-fix the SDK's Zod schemas ran in `.strip()` mode, which silently
// dropped unknown keys. A caller calling `compute_fingerprints({addrs:
// [...]})` (a param the tool doesn't accept) saw a happy "updated: 30005"
// result — the entire session got recomputed even though the caller
// thought they'd scoped it. Replace raw-shape inputSchema with a strict
// Zod object at the registerTool wrapper level so the SDK's Zod
// validator now reports "Unrecognized key" instead of silently dropping.
test("unknown argument keys are rejected by strict-mode Zod", async () => {
  const h = await startServer();
  try {
    await assert.rejects(
      // `addrs` was the original culprit on compute_fingerprints; pick a
      // tool that takes only optional args so the unknown key is the only
      // possible source of error.
      () => h.call("compute_fingerprints", { addrs: ["0xdeadbeef"], session_id: "current" }),
      (err) => /unrecognized key/i.test(err.message) && /addrs/.test(err.message),
    );
  } finally { await h.close(); }
});

// A typo in a known arg is the realistic shape of this bug — `sesion_id`
// would silently become a no-op pre-fix. Strict mode flags it.
test("typo'd argument keys surface a clear message instead of silent no-op", async () => {
  const h = await startServer();
  try {
    await assert.rejects(
      () => h.call("compute_fingerprints", { sesion_id: "current" }),
      (err) => /unrecognized key/i.test(err.message) && /sesion_id/.test(err.message),
    );
  } finally { await h.close(); }
});
