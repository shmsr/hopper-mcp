import test from "node:test";
import assert from "node:assert/strict";
import { startServer, startWithSample, decodeToolResult } from "./fixtures/index.mjs";

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

// begin_transaction's `name` and `rationale` flowed straight from MCP tool
// args into the persisted txn record — no NUL byte rejection, no length cap,
// no type check. Every other prose path (queue.rationale, comments,
// hypotheses) routes through validateProseValue. begin was the lone gap. A
// 5MB name pollutes hopper://transactions/pending on every read and bloats
// every JSON.stringify on save (Round 18's coalesce only helps repeat saves
// of the same state — a real mutation still pays full stringify cost).
test("begin_transaction rejects pathologically long name (Round 21)", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("begin_transaction", { name: "x".repeat(5000) }),
      /cap is 4096/i,
    );
  } finally { await h.close(); }
});

test("begin_transaction rejects pathologically long rationale (Round 21)", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("begin_transaction", { rationale: "y".repeat(5000) }),
      /cap is 4096/i,
    );
  } finally { await h.close(); }
});

// NUL bytes break log pipelines, JSON streaming consumers, every editor's
// display, and `cat` of the on-disk store. Other prose validators reject
// them; begin must do the same so a single bad client can't poison the
// pending-transaction resource for everyone reading it.
test("begin_transaction rejects NUL byte in name (Round 21)", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("begin_transaction", { name: "ok\x00bad" }),
      /control character|NUL/i,
    );
  } finally { await h.close(); }
});

test("begin_transaction rejects NUL byte in rationale (Round 21)", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(
      () => h.call("begin_transaction", { rationale: "ok\x00bad" }),
      /control character|NUL/i,
    );
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
    // Non-empty preview must NOT carry the empty-tx warning.
    assert.equal(preview.warning, undefined,
      "non-empty preview should not include warning field");
  } finally { await h.close(); }
});

// Regression: empty preview surfaces a warning instead of looking like a
// normal transaction. Pre-fix an analyst could call preview on an open tx
// with zero queued ops, see the bare envelope, and commit a no-op without
// realising they'd forgotten to queue anything.
test("preview_transaction on empty transaction includes a warning", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = decodeToolResult(await h.call("preview_transaction", {}));
    assert.ok(Array.isArray(preview.operations) && preview.operations.length === 0,
      "expected empty operations array");
    assert.ok(typeof preview.warning === "string" && preview.warning.length > 0,
      `expected warning field on empty preview; got ${JSON.stringify(preview)}`);
    assert.match(preview.warning, /no.*operations|no-op|empty/i);
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

// rollback_transaction discards queued ops: the rename never lands and a
// follow-up procedure({field:"info"}) shows the original name.
test("rollback_transaction discards queued ops", async () => {
  const h = await startWithSample();
  try {
    const txnId = await beginTxn(h);
    await queue(h, { kind: "rename", addr: "0x100003f50", value: "shouldNotApply" });
    const rollback = decodeToolResult(await h.call("rollback_transaction", {}));
    assert.equal(rollback.transactionId, txnId);
    assert.equal(rollback.status, "rolled_back");
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
    await queue(h, { kind: "rename", addr: "0x100003f50", value: "officialTest" });
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

// Pre-fix `queue({kind:'rename', value:''})` was silently accepted, queueing
// a destructive overwrite to "" — typos quietly corrupted the symbol table
// at commit. Reject empty/whitespace newValue at queue time.
test("queue rename with empty value rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "" }),
      /rename requires a non-empty value/i,
    );
    // Whitespace-only is the same class of mistake.
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "   " }),
      /rename requires a non-empty value/i,
    );
  } finally { await h.close(); }
});

// Pre-fix: a 1KB+ rename value (someone accidentally pastes a stack trace,
// log line, or selection of pseudocode into a rename arg) was silently
// accepted and committed to the symbol table. Cap at 1024 chars with an
// actionable hint that this looks like an accidental paste.
test("queue rename rejects pathologically long value", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const huge = "x".repeat(2000);
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: huge }),
      /cap is 1024/i,
    );
  } finally { await h.close(); }
});

// Whitespace and control characters in symbol names corrupt logs and any
// downstream tool that splits on space/tab/newline. Tabs and newlines in
// particular are silent: a JSON arg like `"foo\nbar"` parses fine but the
// committed name then breaks every consumer that emits one symbol per line.
test("queue rename rejects names with embedded whitespace or control chars", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "name with spaces" }),
      /whitespace or a control character/i,
    );
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "name\twith\ttabs" }),
      /whitespace or a control character/i,
    );
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "name\nwith\nnewlines" }),
      /whitespace or a control character/i,
    );
    // Leading/trailing whitespace is the typo signal — the name itself is
    // fine, the surrounding spaces aren't. Different message.
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "  trim_me  " }),
      /leading\/trailing whitespace/i,
    );
  } finally { await h.close(); }
});

// rename_batch entries used to skip the per-value validation entirely
// (the gate keyed off `kind === "rename"`, but rename_batch is its own
// kind). A single bad name in a 100-entry batch quietly corrupted the
// symbol table on commit, and the round-7 fix only covered single
// renames. Surfaced live on WhatsApp at the round-12 probe.
test("queue rename_batch rejects entries with embedded whitespace", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename_batch",
        mapping: { "0x100003f50": "good_name", "0x100004000": "bad name with space" },
      }),
      /whitespace or a control character/i,
    );
  } finally { await h.close(); }
});

test("queue rename_batch rejects entries with empty/whitespace-only values", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename_batch",
        mapping: { "0x100003f50": "good_name", "0x100004000": "" },
      }),
      /requires a non-empty value/i,
    );
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename_batch",
        mapping: { "0x100003f50": "good_name", "0x100004000": "   " },
      }),
      /requires a non-empty value/i,
    );
  } finally { await h.close(); }
});

test("queue rename_batch rejects entries with control characters", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename_batch",
        mapping: { "0x100003f50": "tabbed\tname" },
      }),
      /whitespace or a control character/i,
    );
    // C0 control char that isn't \s — must still be rejected.
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename_batch",
        mapping: { "0x100003f50": "name\x07with_BEL" },
      }),
      /whitespace or a control character/i,
    );
  } finally { await h.close(); }
});

// Empty mapping is itself a queue mistake; flag it instead of recording
// a no-op operation that just clutters the transaction preview.
test("queue rename_batch with empty mapping is rejected", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "rename_batch", mapping: {} }),
      /mapping is empty|at least one/i,
    );
  } finally { await h.close(); }
});

// Single-rename regression: confirm the regex still rejects raw C0
// controls (non-whitespace ones like BEL, 0x07). Pre-fix the regex was
// stored with literal control bytes which was correct semantically but
// made the file binary-ish; round-12 normalized to escapes — verify
// behavior didn't change.
test("queue rename rejects values with non-whitespace C0 control bytes (BEL)", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "rename", addr: "0x100003f50", value: "name\x07bel" }),
      /whitespace or a control character/i,
    );
  } finally { await h.close(); }
});

// Pre-fix: tag/untag normalisation was just `tags.map(String)` with zero
// validation. Embedded whitespace, tabs, newlines, NULs, and even empty
// strings flowed straight into session.tags[addr]. Same shape as the
// rename_batch round-12 bug — a single bad value persists into the tag set
// at commit and breaks every consumer that splits on whitespace. Validate
// each entry with the same rules used for rename labels.
test("queue tag rejects values with embedded whitespace", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: "has whitespace" }),
      /whitespace or a control character/i,
    );
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: "with\ttab" }),
      /whitespace or a control character/i,
    );
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: "with\nnewline" }),
      /whitespace or a control character/i,
    );
  } finally { await h.close(); }
});

test("queue tag rejects empty/whitespace-only values", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: "" }),
      /requires tag or tags/i,
    );
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: "   " }),
      /requires a non-empty tag/i,
    );
    // Single bad entry in a multi-entry array must still be rejected — the
    // round-12 lesson was that batch validation gates have to run per-entry.
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tags: ["good", ""] }),
      /requires a non-empty tag/i,
    );
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tags: ["good", "   "] }),
      /requires a non-empty tag/i,
    );
  } finally { await h.close(); }
});

test("queue tag rejects leading/trailing whitespace", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: "  surrounded  " }),
      /leading\/trailing whitespace/i,
    );
  } finally { await h.close(); }
});

test("queue tag rejects pathologically long values", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const huge = "x".repeat(500);
    await assert.rejects(
      () => h.call("queue", { kind: "tag", addr: "0x100003f50", tag: huge }),
      /cap is 256/i,
    );
  } finally { await h.close(); }
});

// untag follows the same code path as tag — make sure the validation gate
// fires for it too. A typo'd untag value silently no-ops at commit (the
// untag set never matches any real tag), but the normalisation should still
// surface the problem at queue time.
test("queue untag rejects values with embedded whitespace", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", { kind: "untag", addr: "0x100003f50", tag: "with\nnewline" }),
      /whitespace or a control character/i,
    );
  } finally { await h.close(); }
});

// Sanity: a clean tag value still queues. Regression guard against
// over-tightening the validator (which would block legitimate tags like
// `crypto`, `auth-flow`, `parser_v2`).
test("queue tag accepts clean alphanumeric/underscore/hyphen values", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = await queue(h, {
      kind: "tag",
      addr: "0x100003f50",
      tags: ["crypto", "auth-flow", "parser_v2", "step.1"],
    });
    const op = preview.operations.find((o) => o.kind === "tag");
    assert.ok(op, "expected tag op in operations");
    assert.deepEqual(op.tags, ["crypto", "auth-flow", "parser_v2", "step.1"]);
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

// Pre-fix `if (!operation.topic)` only caught undefined/null/empty, so
// "   " (whitespace-only) was truthy and committed verbatim — leaving
// silent ghost hypotheses with blank topics in the UI.
test("hypothesis create with whitespace-only topic rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("hypothesis", { action: "create", topic: "   " }),
      /requires a non-empty topic/i,
    );
    await assert.rejects(
      () => h.call("hypothesis", { action: "create", topic: "\t\n " }),
      /requires a non-empty topic/i,
    );
  } finally { await h.close(); }
});

// A multi-MB topic string was passed straight through. Long pastes
// (logs, pseudocode dumps) would silently bloat the knowledge store.
test("hypothesis create with pathologically long topic rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const huge = "x".repeat(2000);
    await assert.rejects(
      () => h.call("hypothesis", { action: "create", topic: huge }),
      /cap is 1024/i,
    );
  } finally { await h.close(); }
});

// NUL/DEL/BEL etc. corrupt log pipelines and JSON streaming. Topics, claims,
// and evidence are prose and may legitimately contain \n or \t, but the
// non-whitespace C0 controls have no business in human-readable text.
test("hypothesis create with NUL byte in topic rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("hypothesis", { action: "create", topic: "topic\x00with-NUL" }),
      /non-whitespace control character/i,
    );
  } finally { await h.close(); }
});

// hypothesis_create.claim is optional, but if provided it gets the same
// length cap and control-byte ban. A 50KB pseudocode paste in claim should
// fail at queue time.
test("hypothesis create with oversized claim rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const huge = "x".repeat(5000);
    await assert.rejects(
      () => h.call("hypothesis", { action: "create", topic: "valid", claim: huge }),
      /cap is 4096/i,
    );
  } finally { await h.close(); }
});

// hypothesis_link.evidence shares the prose-validation contract.
test("hypothesis link with NUL byte in evidence rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const create = await h.call("hypothesis", { action: "create", topic: "valid" });
    const created = JSON.parse(create.content[0].text);
    const hypId = created.operations.at(-1).hypothesisId;
    await assert.rejects(
      () => h.call("hypothesis", {
        action: "link",
        hypothesis_id: hypId,
        evidence: "evidence\x00with-NUL",
      }),
      /non-whitespace control character/i,
    );
  } finally { await h.close(); }
});

// Multi-line prose IS allowed for topics/claims/evidence — they're prose,
// not symbol names. Regression guard against over-tightening the validator.
test("hypothesis create with multi-line claim is accepted", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const result = await h.call("hypothesis", {
      action: "create",
      topic: "API session lifecycle",
      claim: "Sessions transition open → suspended → closed.\n\nClose drops the channel.",
    });
    const decoded = JSON.parse(result.content[0].text);
    const op = decoded.operations.at(-1);
    assert.match(op.claim, /open → suspended → closed/);
    assert.match(op.claim, /Close drops the channel/);
  } finally { await h.close(); }
});

// comment/inline_comment/type_patch share the prose path with looser
// "empty allowed" semantics (clearing a comment is legitimate). They still
// get the size cap and NUL/DEL ban, since pasting a 50KB stack trace into
// a comment field used to silently persist a giant blob.
test("queue comment with NUL byte rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    await assert.rejects(
      () => h.call("queue", {
        kind: "comment",
        addr: "0x100003f50",
        value: "comment\x00with-NUL",
      }),
      /non-whitespace control character/i,
    );
  } finally { await h.close(); }
});

test("queue comment with pathologically long value rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const huge = "x".repeat(20000);
    await assert.rejects(
      () => h.call("queue", { kind: "comment", addr: "0x100003f50", value: huge }),
      /cap is 16384/i,
    );
  } finally { await h.close(); }
});

// Empty comment value remains accepted — clearing a comment is a legitimate
// operation. Regression guard against accidentally tightening this.
test("queue comment with empty value is accepted (clear-op)", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const preview = await queue(h, { kind: "comment", addr: "0x100003f50", value: "" });
    const op = preview.operations.find((o) => o.kind === "comment");
    assert.ok(op, "expected comment op in operations");
    assert.equal(op.newValue, "");
  } finally { await h.close(); }
});

// rationale on any op kind also gets validated — pre-fix it was raw
// passthrough, so a multi-MB rationale string would commit straight into
// the journal.
test("queue rename with oversized rationale rejects", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h);
    const huge = "x".repeat(5000);
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename",
        addr: "0x100003f50",
        value: "good_name",
        rationale: huge,
      }),
      /cap is 4096/i,
    );
  } finally { await h.close(); }
});

// Pre-fix the no-tx error said only "Call begin_transaction first" even when
// the caller passed an explicit (typo'd) transaction_id — leaving them to
// guess whether the id was wrong or the workflow was. Distinguish the two so
// the failing knob is obvious.
test("queue with unknown transaction_id reports 'not found' instead of 'no open transaction'", async () => {
  const h = await startWithSample();
  try {
    await beginTxn(h); // open a real one so "no open" is a wrong answer
    await assert.rejects(
      () => h.call("queue", {
        kind: "rename",
        addr: "0x100003f50",
        value: "shouldFail",
        transaction_id: "txn-bogus-id-does-not-exist",
      }),
      /Transaction.*txn-bogus-id-does-not-exist.*not found/i,
    );
  } finally { await h.close(); }
});

// hypothesis docs now mention the transaction requirement explicitly so
// callers don't get a bare "No open transaction" with no context on which
// path to take. This guards the description text from silent regression.
test("hypothesis tool description mentions begin_transaction", async () => {
  const h = await startServer();
  try {
    const tools = await h.listTools();
    const hyp = tools.tools.find((t) => t.name === "hypothesis");
    assert.ok(hyp, "hypothesis tool registered");
    assert.match(hyp.description, /begin_transaction|transaction/i,
      `expected description to mention transaction, got: ${hyp.description}`);
  } finally { await h.close(); }
});
