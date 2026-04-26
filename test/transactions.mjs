import test from "node:test";
import assert from "node:assert/strict";
import { startWithSample, decodeToolResult } from "./fixtures/index.mjs";

// Helper: begin a transaction and return { h, txnId }.
// Caller is responsible for h.close() in finally.
async function beginTxn(h, opts = {}) {
  const res = decodeToolResult(await h.call("begin_transaction", opts));
  return res.transactionId;
}

// Helper: queue an op and decode the result.
async function queue(h, args) {
  return decodeToolResult(await h.call("queue", args));
}

// ── begin_transaction ─────────────────────────────────────────────────────────

// begin_transaction returns a transactionId; the txn appears in pending resource.
test("begin_transaction returns transactionId and appears in hopper://transactions/pending", async () => {
  const h = await startWithSample();
  try {
    const res = decodeToolResult(await h.call("begin_transaction", { name: "test-begin" }));
    assert.ok(typeof res.transactionId === "string" && res.transactionId.startsWith("txn-"),
      `expected transactionId starting with 'txn-'; got ${res.transactionId}`);
    assert.equal(res.status, "open");
    // Verify it appears in the pending resource list.
    const resource = await h.readResource("hopper://transactions/pending");
    assert.ok(Array.isArray(resource.contents) && resource.contents.length > 0);
    const pending = JSON.parse(resource.contents[0].text);
    assert.ok(Array.isArray(pending), "pending should be an array");
    const found = pending.find((t) => t.id === res.transactionId);
    assert.ok(found, `expected to find txn ${res.transactionId} in pending list`);
  } finally { await h.close(); }
});

// ── queue kinds ───────────────────────────────────────────────────────────────

// queue rename → preview shows rename op with kind, addr, newValue.
test("queue rename → preview_transaction shows the rename operation", async () => {
  const h = await startWithSample();
  try {
    const txnId = await beginTxn(h);
    const preview = await queue(h, { kind: "rename", addr: "0x100003f50", value: "validateLicense" });
    assert.equal(preview.transactionId, txnId);
    const op = preview.operations.find((o) => o.kind === "rename");
    assert.ok(op, "expected rename op in operations");
    assert.equal(op.addr, "0x100003f50");
    assert.equal(op.newValue, "validateLicense");
  } finally { await h.close(); }
});

// queue comment → preview shows comment op.
test("queue comment → preview_transaction shows the comment operation", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = await queue(h, { kind: "comment", addr: "0x100003f50", value: "license check routine" });
    const op = preview.operations.find((o) => o.kind === "comment");
    assert.ok(op, "expected comment op in operations");
    assert.equal(op.addr, "0x100003f50");
    assert.equal(op.newValue, "license check routine");
  } finally { await h.close(); }
});

// queue inline_comment → preview shows inline_comment op.
test("queue inline_comment → preview_transaction shows the inline_comment operation", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = await queue(h, { kind: "inline_comment", addr: "0x100003fa8", value: "sha256 call site" });
    const op = preview.operations.find((o) => o.kind === "inline_comment");
    assert.ok(op, "expected inline_comment op in operations");
    assert.equal(op.addr, "0x100003fa8");
    assert.equal(op.newValue, "sha256 call site");
  } finally { await h.close(); }
});

// queue type_patch → preview shows type_patch op.
test("queue type_patch → preview_transaction shows the type_patch operation", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = await queue(h, { kind: "type_patch", addr: "0x100003f50", value: "int (const char *)" });
    const op = preview.operations.find((o) => o.kind === "type_patch");
    assert.ok(op, "expected type_patch op in operations");
    assert.equal(op.addr, "0x100003f50");
    assert.equal(op.newValue, "int (const char *)");
  } finally { await h.close(); }
});

// queue tag → preview shows tag op with tags array.
test("queue tag → preview_transaction shows the tag operation with tags", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = await queue(h, { kind: "tag", addr: "0x100003f50", tag: "crypto" });
    const op = preview.operations.find((o) => o.kind === "tag");
    assert.ok(op, "expected tag op in operations");
    assert.equal(op.addr, "0x100003f50");
    assert.ok(Array.isArray(op.tags) && op.tags.includes("crypto"),
      `expected tags to include 'crypto'; got ${JSON.stringify(op.tags)}`);
  } finally { await h.close(); }
});

// queue untag → preview shows untag op.
test("queue untag → preview_transaction shows the untag operation", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    // First tag so there's something to untag.
    await queue(h, { kind: "tag", addr: "0x100003f50", tag: "crypto" });
    const preview = await queue(h, { kind: "untag", addr: "0x100003f50", tag: "crypto" });
    const op = preview.operations.find((o) => o.kind === "untag");
    assert.ok(op, "expected untag op in operations");
    assert.equal(op.addr, "0x100003f50");
    assert.ok(Array.isArray(op.tags) && op.tags.includes("crypto"),
      `expected tags to include 'crypto'; got ${JSON.stringify(op.tags)}`);
  } finally { await h.close(); }
});

// queue rename_batch → preview shows rename_batch op with mapping.
test("queue rename_batch → preview_transaction shows the rename_batch operation", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const mapping = { "0x100003f50": "fnA", "0x100004010": "fnB" };
    const preview = await queue(h, { kind: "rename_batch", mapping });
    const op = preview.operations.find((o) => o.kind === "rename_batch");
    assert.ok(op, "expected rename_batch op in operations");
    assert.ok(op.mapping, "expected mapping field on op");
    assert.equal(op.mapping["0x100003f50"], "fnA");
    assert.equal(op.mapping["0x100004010"], "fnB");
  } finally { await h.close(); }
});

// ── preview_transaction ───────────────────────────────────────────────────────

// preview_transaction called explicitly returns the same shape as queue's return.
test("preview_transaction returns transactionId and operations array", async () => {
  const h = await startWithSample();
  try {
    const txnId = await beginTxn(h);
    await queue(h, { kind: "rename", addr: "0x100003f50", value: "renamed" });
    const preview = decodeToolResult(await h.call("preview_transaction", {}));
    assert.equal(preview.transactionId, txnId);
    assert.ok(Array.isArray(preview.operations) && preview.operations.length >= 1,
      "expected at least one queued op in preview");
    const op = preview.operations.find((o) => o.kind === "rename");
    assert.ok(op, "expected rename op in explicit preview");
    // oldValue should be the name that existed before the rename.
    assert.equal(op.oldValue, "sub_100003f50");
    assert.equal(op.newValue, "renamed");
  } finally { await h.close(); }
});

// ── commit_transaction (local) ────────────────────────────────────────────────

// commit_transaction (no backend) applies the rename; subsequent procedure info reflects it.
test("commit_transaction (local) applies rename to knowledge store", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await queue(h, { kind: "rename", addr: "0x100003f50", value: "licenseCheck" });
    const committed = decodeToolResult(await h.call("commit_transaction", {}));
    assert.equal(committed.status, "committed");
    // Subsequent procedure lookup should reflect the new name.
    const info = decodeToolResult(
      await h.call("procedure", { field: "info", procedure: "0x100003f50" }),
    );
    assert.equal(info.name, "licenseCheck",
      `expected renamed function; got ${info.name}`);
  } finally { await h.close(); }
});

// ── rollback_transaction ──────────────────────────────────────────────────────

// rollback_transaction discards queued ops; a second preview shows empty operations.
test("rollback_transaction discards queued ops", async () => {
  const h = await startWithSample();
  try {
    const txnId = await beginTxn(h);
    await queue(h, { kind: "rename", addr: "0x100003f50", value: "shouldNotApply" });
    const rollback = decodeToolResult(await h.call("rollback_transaction", {}));
    assert.equal(rollback.transactionId, txnId);
    assert.ok(
      rollback.status === "rolled_back" || rollback.status === "rolled-back",
      `expected rolled_back status; got ${rollback.status}`,
    );
    // Name should NOT have changed since we rolled back.
    const info = decodeToolResult(
      await h.call("procedure", { field: "info", procedure: "0x100003f50" }),
    );
    assert.equal(info.name, "sub_100003f50",
      `expected original name after rollback; got ${info.name}`);
  } finally { await h.close(); }
});

// rollback twice on the same txn — second call rejects with "not open" / "rolled_back".
test("rollback_transaction twice on same txn rejects with 'not open' error", async () => {
  const h = await startWithSample();
  try {
    const txnId = await beginTxn(h);
    await h.call("rollback_transaction", { transaction_id: txnId });
    // Second rollback must reject — the txn is no longer open.
    await assert.rejects(
      () => h.call("rollback_transaction", { transaction_id: txnId }),
      /not open|rolled.back/i,
    );
  } finally { await h.close(); }
});

// ── commit_transaction (official backend, no env var) ─────────────────────────

// commit_transaction({backend:"official", confirm_live_write:true}) without
// HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 rejects, refusing to send anything to Hopper.
test("commit_transaction official backend without HOPPER_MCP_ENABLE_OFFICIAL_WRITES rejects", async () => {
  // The harness spawns the server without the env var; backend check fires before
  // any attempt to spawn HopperMCPServer, so this is safe in CI.
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await queue(h, { kind: "rename", addr: "0x100003f50", value: "officalTest" });
    await assert.rejects(
      () => h.call("commit_transaction", { backend: "official", confirm_live_write: true }),
      /HOPPER_MCP_ENABLE_OFFICIAL_WRITES|enable.*writes/i,
    );
  } finally { await h.close(); }
});

// ── hypothesis lifecycle ──────────────────────────────────────────────────────

// hypothesis({action:"create"}) queues a hypothesis_create op; the op carries a hypothesisId.
test("hypothesis create queues hypothesis_create op with hypothesisId matching /^hyp-/", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const created = decodeToolResult(
      await h.call("hypothesis", { action: "create", topic: "license-check", claim: "Function validates license keys." }),
    );
    assert.ok(Array.isArray(created.operations), "expected operations array");
    const op = created.operations.find((o) => o.kind === "hypothesis_create");
    assert.ok(op, "expected hypothesis_create op");
    assert.match(op.hypothesisId, /^hyp-/, `expected hypothesisId matching /^hyp-/; got ${op.hypothesisId}`);
    assert.equal(op.topic, "license-check");
  } finally { await h.close(); }
});

// hypothesis({action:"link"}) links evidence to an existing hypothesis.
test("hypothesis link queues hypothesis_link op with the right hypothesisId", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    // Create first to obtain the hypothesisId.
    const created = decodeToolResult(
      await h.call("hypothesis", { action: "create", topic: "anti-debug", claim: "Uses ptrace to detect debuggers." }),
    );
    const hypId = created.operations.find((o) => o.kind === "hypothesis_create").hypothesisId;
    // Link evidence (an address pointing into _main).
    const linked = decodeToolResult(
      await h.call("hypothesis", { action: "link", hypothesis_id: hypId, addr: "0x100004120", evidence: "ptrace call in _main" }),
    );
    const linkOp = linked.operations.find((o) => o.kind === "hypothesis_link");
    assert.ok(linkOp, "expected hypothesis_link op");
    assert.equal(linkOp.hypothesisId, hypId);
  } finally { await h.close(); }
});

// hypothesis({action:"status"}) queues a hypothesis_status op.
test("hypothesis status queues hypothesis_status op with the supplied status", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const created = decodeToolResult(
      await h.call("hypothesis", { action: "create", topic: "license-check", claim: "Validates keys via SHA-256." }),
    );
    const hypId = created.operations.find((o) => o.kind === "hypothesis_create").hypothesisId;
    const updated = decodeToolResult(
      await h.call("hypothesis", { action: "status", hypothesis_id: hypId, status: "supported" }),
    );
    const statusOp = updated.operations.find((o) => o.kind === "hypothesis_status");
    assert.ok(statusOp, "expected hypothesis_status op");
    assert.equal(statusOp.hypothesisId, hypId);
    assert.equal(statusOp.status, "supported");
  } finally { await h.close(); }
});

// ── negative / edge cases ─────────────────────────────────────────────────────

// queue without a prior begin_transaction rejects — no open transaction.
test("queue without begin_transaction rejects with 'No open transaction' error", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "shouldFail" }),
      /No open transaction/i,
    );
  } finally { await h.close(); }
});

// queue with an unknown kind is rejected by Zod schema validation.
test("queue with unknown kind rejects with validation error", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "invalid_kind", addr: "0x100003f50", value: "x" }),
      /invalid_kind|Invalid enum|kind/i,
    );
  } finally { await h.close(); }
});

// hypothesis action=create without topic rejects.
test("hypothesis create without topic rejects with validation error", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("hypothesis", { action: "create" }),
      /topic/i,
    );
  } finally { await h.close(); }
});
