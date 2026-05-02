import test from "node:test";
import assert from "node:assert/strict";
import { startServer, sampleSession, decodeToolResult } from "./fixtures/index.mjs";

test("open_session + close_session round-trip", async () => {
  const h = await startServer();
  try {
    const opened = decodeToolResult(await h.call("open_session", { session: sampleSession() }));
    assert.ok(opened.sessionId);

    const caps = decodeToolResult(await h.call("capabilities", {}));
    assert.ok(caps.sessions.find((s) => s.sessionId === opened.sessionId));

    await h.call("close_session", { session_id: opened.sessionId });
    const caps2 = decodeToolResult(await h.call("capabilities", {}));
    assert.ok(!caps2.sessions.find((s) => s.sessionId === opened.sessionId));
  } finally { await h.close(); }
});

test("set_current_session targets the right session for unscoped reads", async () => {
  const h = await startServer();
  try {
    const a = decodeToolResult(await h.call("open_session", { session: { ...sampleSession(), sessionId: "A" } }));
    const b = decodeToolResult(await h.call("open_session", { session: { ...sampleSession(), sessionId: "B" } }));
    await h.call("set_current_session", { session_id: b.sessionId });
    const caps = decodeToolResult(await h.call("capabilities", {}));
    assert.equal(caps.currentSessionId, b.sessionId);
  } finally { await h.close(); }
});

test("open_session(overwrite:false) on existing id is rejected", async () => {
  const h = await startServer();
  try {
    await h.call("open_session", { session: { ...sampleSession(), sessionId: "dup" } });
    await assert.rejects(
      () => h.call("open_session", { session: { ...sampleSession(), sessionId: "dup" }, overwrite: false }),
      /already exists/i,
    );
  } finally { await h.close(); }
});
