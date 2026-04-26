import test from "node:test";
import assert from "node:assert/strict";
import { startServer, decodeToolResult } from "./fixtures/index.mjs";

const SKIP = process.env.HOPPER_MCP_LIVE !== "1";
const TARGET = process.env.HOPPER_MCP_LIVE_TARGET ?? "/bin/echo";

test("ingest_live_hopper opens, exports, ingests", { skip: SKIP }, async () => {
  const h = await startServer({ env: { LIVE_HOPPER_MAX_FUNCTIONS: "20", LIVE_HOPPER_MAX_STRINGS: "50" } });
  try {
    const out = decodeToolResult(await h.call("ingest_live_hopper", {
      executable_path: TARGET,
      timeout_ms: 90_000,
      max_functions: 20,
      max_strings: 50,
    }));
    assert.ok(out.sessionId);
  } finally { await h.close(); }
});

test("official_hopper_call list_documents returns the live document set", { skip: SKIP }, async () => {
  const h = await startServer();
  try {
    const out = decodeToolResult(await h.call("official_hopper_call", {
      name: "list_documents", arguments: {},
    }));
    assert.ok(Array.isArray(out) || typeof out === "object");
  } finally { await h.close(); }
});

test("commit_transaction(backend:official) end-to-end", { skip: SKIP || !process.env.HOPPER_MCP_LIVE_RENAME }, async () => {
  // Requires HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 and HOPPER_MCP_LIVE_RENAME=1.
  const h = await startServer({ env: { HOPPER_MCP_ENABLE_OFFICIAL_WRITES: "1" } });
  try {
    await h.call("ingest_live_hopper", { executable_path: TARGET, timeout_ms: 90_000, max_functions: 5 });
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const txn = decodeToolResult(await h.call("begin_transaction", {}));
    await h.call("queue", { kind: "rename", addr, value: `live_test_${Date.now()}`, transaction_id: txn.transactionId });
    const out = decodeToolResult(await h.call("commit_transaction", {
      transaction_id: txn.transactionId, backend: "official", confirm_live_write: true,
    }));
    assert.ok(out.applied || out.appliedToHopper);
  } finally { await h.close(); }
});
