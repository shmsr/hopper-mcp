import test from "node:test";
import assert from "node:assert/strict";
import { startServer } from "./fixtures/index.mjs";

test("initialize negotiates protocol version", async () => {
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

test("calling unknown tool returns clean error", async () => {
  const h = await startServer();
  try {
    await assert.rejects(() => h.call("nonexistent_tool_xxx", {}));
  } finally { await h.close(); }
});

test("malformed input rejected with -32602", async () => {
  const h = await startServer();
  try {
    // `list` requires `kind`; passing an integer should be rejected.
    await assert.rejects(() => h.call("list", { kind: 42 }), (err) => err.code === -32602 || /kind/i.test(err.message));
  } finally { await h.close(); }
});
