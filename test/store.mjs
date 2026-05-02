import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KnowledgeStore, parseAddress, formatAddress } from "../src/knowledge-store.js";
import { TransactionManager } from "../src/transaction-manager.js";

// ── parseAddress / formatAddress invariants ───────────────────────────────

// Real Mach-O addresses round-trip cleanly.
test("parseAddress + formatAddress round-trip on real Mach-O addrs", () => {
  for (const addr of ["0x100003f50", "0x1025b0b0c", "0x100008000", "0x0", "0x100"]) {
    assert.equal(formatAddress(addr), addr, `expected ${addr} to round-trip`);
  }
});

// Throws on hex addrs beyond Number.MAX_SAFE_INTEGER (2^53 - 1) instead of
// silently rounding via JS Number — pre-fix 0xdeadbeefdeadbeef became
// 0xdeadbeefdeadc000 by the time it round-tripped, corrupting any addr the
// caller queued or stored.
test("parseAddress throws on addrs beyond Number.MAX_SAFE_INTEGER", () => {
  for (const addr of ["0xdeadbeefdeadbeef", "0xffffffffffffffff", "0x20000000000001"]) {
    assert.throws(() => parseAddress(addr), /MAX_SAFE_INTEGER|precision loss/i,
      `expected ${addr} to throw`);
  }
});

// Edge: 0x1fffffffffffff is the largest safe integer — must still parse.
test("parseAddress accepts the largest safe integer (2^53 - 1)", () => {
  assert.equal(parseAddress("0x1fffffffffffff"), Number.MAX_SAFE_INTEGER);
});

// Non-numeric input still returns null (not throws) — preserves the existing
// contract for parseAddress callers that fall through to name matching.
test("parseAddress returns null for non-numeric input", () => {
  assert.equal(parseAddress("not_an_addr"), null);
  assert.equal(parseAddress(""), null);
  assert.equal(parseAddress(null), null);
});

test("load() sweeps orphan tmpfiles", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const storePath = join(dir, "store.json");
  await writeFile(`${storePath}.42.123.tmp`, "{}");
  await writeFile(`${storePath}.43.456.tmp`, "{}");

  const store = new KnowledgeStore(storePath);
  await store.load();

  const entries = await readdir(dir);
  assert.deepEqual(entries.filter((n) => n.endsWith(".tmp")), [], "orphan tmps should be gone");
  await rm(dir, { recursive: true, force: true });
});

test("write failure cleans up its tmpfile", async () => {
  // Force a real rename failure from the production _writeStateToDisk by
  // pre-creating a non-empty directory at the store path: rename(tmp, path)
  // then fails with EISDIR/ENOTEMPTY without any stubbing.
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const storePath = join(dir, "store.json");
  await mkdir(storePath, { recursive: true });
  await writeFile(join(storePath, "blocker"), "x");

  const store = new KnowledgeStore(storePath);
  store.state = { schemaVersion: 1, sessions: {} };
  await assert.rejects(() => store.save());

  const entries = await readdir(dir);
  assert.deepEqual(entries.filter((n) => n.endsWith(".tmp")), []);
  await rm(dir, { recursive: true, force: true });
});

test("upsertSession with overwrite:false rejects duplicate sessionId", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: [], strings: [] });
    await assert.rejects(
      () => store.upsertSession({ sessionId: "a", binary: { name: "A2" }, functions: [], strings: [] }, { overwrite: false }),
      /already exists/i,
    );
  } finally {
    await store.save(); // drain scheduleSave() before rm to avoid ENOTEMPTY race
    await rm(dir, { recursive: true, force: true });
  }
});

test("setCurrentSession rejects unknown id and accepts known id", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: [], strings: [] });
    await store.upsertSession({ sessionId: "b", binary: { name: "B" }, functions: [], strings: [] });
    assert.throws(() => store.setCurrentSession("nope"), /No Hopper session/i);
    store.setCurrentSession("a");
    assert.equal(store.state.currentSessionId, "a");
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

test("listSessions returns every loaded session", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: [], strings: [] });
    await store.upsertSession({ sessionId: "b", binary: { name: "B" }, functions: [], strings: [] });
    const list = store.listSessions();
    assert.equal(list.length, 2);
    assert.deepEqual(list.map((s) => s.sessionId).sort(), ["a", "b"]);
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

test('getResource("hopper://transactions/pending") returns an array', async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: [], strings: [] });
    store.setCurrentSession("a");
    const out = store.getResource("hopper://transactions/pending");
    assert.ok(Array.isArray(out));
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

test('getResource("hopper://function/{addr}") returns the function record', async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "a",
      binary: { name: "A" },
      functions: [{ addr: "0x1000", name: "fnA", size: 8 }],
      strings: [],
    });
    store.setCurrentSession("a");
    const out = store.getResource("hopper://function/0x1000");
    assert.ok(out);
    assert.equal(out.addr, "0x1000");
    assert.equal(out.name, "fnA");
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

test("getResource with ?session_id reads from a non-current session", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "a",
      binary: { name: "A" },
      functions: [{ addr: "0x1000", name: "fnA", size: 4 }],
      strings: [],
    });
    await store.upsertSession({
      sessionId: "b",
      binary: { name: "B" },
      functions: [{ addr: "0x2000", name: "fnB", size: 4 }],
      strings: [],
    });
    store.setCurrentSession("a");
    const out = store.getResource("hopper://function/0x2000?session_id=b");
    assert.equal(out?.name, "fnB");
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

test("session cap evicts oldest non-current sessions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"), { sessionCap: 3 });
  await store.load();
  try {
    for (const id of ["s0", "s1", "s2", "s3", "s4"]) {
      await store.upsertSession({ sessionId: id, binary: { name: id }, functions: [], strings: [] });
      // The pruner sorts by updatedAt; sleep a tick so siblings differ.
      await new Promise((r) => setTimeout(r, 5));
    }
    const ids = Object.keys(store.state.sessions).sort();
    assert.deepEqual(ids, ["s2", "s3", "s4"]);
    assert.equal(store.state.currentSessionId, "s4");
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

test("session cap pins currentSessionId even when oldest", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"), { sessionCap: 100 });
  await store.load();
  try {
    for (const id of ["old", "newer", "newest"]) {
      await store.upsertSession({ sessionId: id, binary: { name: id }, functions: [], strings: [] });
      await new Promise((r) => setTimeout(r, 5));
    }
    store.state.currentSessionId = "old";
    const evicted = store.pruneStaleSessions(1);
    assert.deepEqual(Object.keys(store.state.sessions), ["old"]);
    assert.deepEqual(evicted.sort(), ["newer", "newest"]);
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// Round 17: WhatsApp's live ingest pulled 756,174 entries from list_names
// straight into the session. The on-disk store ballooned to 222 MB and every
// save did a synchronous JSON.stringify on the whole blob — a ~1.5 s event-loop
// stall that very plausibly tipped the MCP host into "tool unavailable" on the
// next call. Cap the names array at upsert time so a pathological binary can't
// silently inflate the store.
test("upsertSession caps oversized names array (Round 17)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    const big = Array.from({ length: 250_000 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x100000000).toString(16)}`,
      name: `loc_${i}`,
    }));
    const session = await store.upsertSession({
      sessionId: "huge",
      binary: { name: "huge" },
      functions: [],
      strings: [],
      names: big,
    });
    assert.equal(session.names.length, 100_000, "names should be capped to default");
    assert.equal(session.truncation?.names?.kept, 100_000);
    assert.equal(session.truncation?.names?.dropped, 150_000);
    assert.equal(session.truncation?.names?.cap, 100_000);
    assert.equal(session.truncation?.names?.original, 250_000);
    // describeSession must surface the truncation so callers see the cut.
    const description = store.describeSession(session);
    assert.equal(description.counts.names, 100_000);
    assert.equal(description.truncation?.names?.dropped, 150_000);
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// Below the cap → no truncation field, names returned verbatim.
test("upsertSession leaves small names arrays untouched (Round 17)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    const small = Array.from({ length: 50 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x100000000).toString(16)}`,
      name: `loc_${i}`,
    }));
    const session = await store.upsertSession({
      sessionId: "small",
      binary: { name: "small" },
      functions: [],
      strings: [],
      names: small,
    });
    assert.equal(session.names.length, 50);
    assert.equal(session.truncation, undefined, "no truncation for small inputs");
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// HOPPER_MCP_MAX_NAMES env override lets ops tune the cap per-deployment;
// useful when the operator knows they're working with massive symbol tables
// and wants to give back some headroom.
test("HOPPER_MCP_MAX_NAMES env override (Round 17)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const prior = process.env.HOPPER_MCP_MAX_NAMES;
  process.env.HOPPER_MCP_MAX_NAMES = "500";
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    const big = Array.from({ length: 1500 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x100000000).toString(16)}`,
      name: `loc_${i}`,
    }));
    const session = await store.upsertSession({
      sessionId: "tuned",
      binary: { name: "tuned" },
      functions: [],
      strings: [],
      names: big,
    });
    assert.equal(session.names.length, 500);
    assert.equal(session.truncation?.names?.cap, 500);
    assert.equal(session.truncation?.names?.dropped, 1000);
  } finally {
    if (prior === undefined) delete process.env.HOPPER_MCP_MAX_NAMES;
    else process.env.HOPPER_MCP_MAX_NAMES = prior;
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// Round 18: scheduleSave/save chain a fresh _writeStateToDisk for every
// concurrent caller, even when the in-memory state has not changed since the
// first queued write. On a 150 MB store that means N concurrent annotation
// saves serialize the same blob N times — N × ~700 ms of pointless event-loop
// stall. Coalesce: if the in-flight save already captured the latest state,
// the queued one should skip.
test("scheduleSave coalesces redundant writes (Round 18)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: [], strings: [] });
    await store.flushDurable();

    let writes = 0;
    const original = store._writeStateToDisk.bind(store);
    store._writeStateToDisk = async function () {
      writes += 1;
      return original();
    };

    // 5 concurrent saves with no mutation between them: the first should land,
    // the rest should coalesce because state is already up-to-date on disk.
    await Promise.all([
      store.save(),
      store.save(),
      store.save(),
      store.save(),
      store.save(),
    ]);

    assert.equal(writes, 1, `expected 1 write, got ${writes}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Coalesce must not swallow real mutations. Mutate between two saves and
// ensure both writes land — otherwise we'd lose data.
test("scheduleSave still writes when state mutates between saves (Round 18)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: [], strings: [] });
    await store.flushDurable();

    let writes = 0;
    const original = store._writeStateToDisk.bind(store);
    store._writeStateToDisk = async function () {
      writes += 1;
      return original();
    };

    await store.save();
    // Real mutation followed by another save — must produce a second write.
    store.state.sessions.a.binary.name = "A2";
    await store.save();

    assert.equal(writes, 2, `expected 2 writes (one per change), got ${writes}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Round 17b: load() must retroactively trim oversized sessions. The Round 17a
// upsert-time cap stops the bleeding for fresh ingests, but does nothing for
// the 222 MB store already on disk — that store still does a 1.5s sync stringify
// every save. Trim on load so the next process start shrinks the store
// permanently and follow-up saves are cheap.
test("load() retroactively trims sessions over names cap (Round 17b)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const storePath = join(dir, "s.json");
  const prior = process.env.HOPPER_MCP_MAX_NAMES;
  process.env.HOPPER_MCP_MAX_NAMES = "100";
  try {
    const oversized = Array.from({ length: 500 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x100000000).toString(16)}`,
      name: `loc_${i}`,
    }));
    const undersized = Array.from({ length: 50 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x200000000).toString(16)}`,
      name: `keep_${i}`,
    }));
    // Hand-build the on-disk store directly so we exercise the load path,
    // not upsertSession (which already enforces the cap).
    await writeFile(
      storePath,
      JSON.stringify({
        schemaVersion: 1,
        currentSessionId: "huge",
        sessions: {
          huge: {
            sessionId: "huge",
            binaryId: "huge",
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
            binary: { name: "huge" },
            capabilities: {},
            functions: {},
            strings: [],
            names: oversized,
            bookmarks: [],
            comments: [],
            inlineComments: [],
            cursor: {},
            imports: [],
            exports: [],
            objcClasses: [],
            swiftSymbols: [],
            tags: {},
            hypotheses: [],
            antiAnalysisFindings: [],
            transactions: { pending: [] },
          },
          tiny: {
            sessionId: "tiny",
            binaryId: "tiny",
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
            binary: { name: "tiny" },
            capabilities: {},
            functions: {},
            strings: [],
            names: undersized,
            bookmarks: [],
            comments: [],
            inlineComments: [],
            cursor: {},
            imports: [],
            exports: [],
            objcClasses: [],
            swiftSymbols: [],
            tags: {},
            hypotheses: [],
            antiAnalysisFindings: [],
            transactions: { pending: [] },
          },
        },
      }),
    );

    const store = new KnowledgeStore(storePath);
    await store.load();

    // Oversized session was trimmed in place to the env cap.
    assert.equal(store.state.sessions.huge.names.length, 100);
    assert.equal(store.state.sessions.huge.truncation?.names?.cap, 100);
    assert.equal(store.state.sessions.huge.truncation?.names?.dropped, 400);
    assert.equal(store.state.sessions.huge.truncation?.names?.original, 500);
    // Undersized session is untouched.
    assert.equal(store.state.sessions.tiny.names.length, 50);
    assert.equal(store.state.sessions.tiny.truncation, undefined);

    // Drain any save scheduled by the trim before the test ends, so the
    // shrunken state actually lands on disk for the next process start.
    await store.flushDurable();
    const reloaded = JSON.parse(await (await import("node:fs/promises")).readFile(storePath, "utf8"));
    assert.equal(reloaded.sessions.huge.names.length, 100,
      "trimmed names must persist to disk");
  } finally {
    if (prior === undefined) delete process.env.HOPPER_MCP_MAX_NAMES;
    else process.env.HOPPER_MCP_MAX_NAMES = prior;
    await rm(dir, { recursive: true, force: true });
  }
});

// Re-upsert merges existing.names into the new session via mergeUserAnnotations.
// Without a post-merge cap, two 80k-names imports of the same id would compose
// to 160k — defeating the whole point of the cap. Verify the cap is enforced
// after merge, not just at first ingest.
test("upsertSession re-merge does not bypass names cap (Round 17)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const prior = process.env.HOPPER_MCP_MAX_NAMES;
  process.env.HOPPER_MCP_MAX_NAMES = "1000";
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    const first = Array.from({ length: 800 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x100000000).toString(16)}`,
      name: `first_${i}`,
    }));
    await store.upsertSession({
      sessionId: "merge",
      binary: { name: "merge" },
      functions: [],
      strings: [],
      names: first,
    });
    // Different addresses so merge doesn't dedup them away.
    const second = Array.from({ length: 800 }, (_, i) => ({
      addr: `0x${(i * 4 + 0x200000000).toString(16)}`,
      name: `second_${i}`,
    }));
    const session = await store.upsertSession({
      sessionId: "merge",
      binary: { name: "merge" },
      functions: [],
      strings: [],
      names: second,
    });
    assert.ok(session.names.length <= 1000, `merged names exceeded cap: ${session.names.length}`);
    assert.equal(session.truncation?.names?.cap, 1000);
  } finally {
    if (prior === undefined) delete process.env.HOPPER_MCP_MAX_NAMES;
    else process.env.HOPPER_MCP_MAX_NAMES = prior;
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// searchStrings used to feed args.pattern straight into `new RegExp(pattern, "i")`
// with no length cap or catastrophic-shape check. A user calling search()
// kind=strings,semantic=true with `(a+)+b` against a session whose strings are
// just ~30 chars of letters burns >60s of CPU in the JSON-RPC loop, freezing
// the entire MCP session. compileUserRegex already guards every other public
// regex entry point — searchStrings was the lone holdout.
test("searchStrings rejects catastrophic regex patterns (Round 19)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "redos",
      binary: { name: "redos" },
      functions: [],
      strings: [{ addr: "0x100008000", value: "license_key" }],
      names: [],
    });
    assert.throws(
      () => store.searchStrings("(a+)+b", { sessionId: "redos" }),
      /catastrophic backtracking|nested unbounded quantifiers/i,
      "expected catastrophic-regex guard to reject (a+)+b",
    );
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// 257-char patterns are well past any realistic search and almost always
// indicate an accidental paste (a stack trace, a log line). Reject before we
// hand it to V8 — same 256-char cap the other regex entry points use.
test("searchStrings rejects oversized patterns (Round 19)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "big",
      binary: { name: "big" },
      functions: [],
      strings: [{ addr: "0x100008000", value: "x" }],
      names: [],
    });
    assert.throws(
      () => store.searchStrings("a".repeat(257), { sessionId: "big" }),
      /cap is 256|too long/i,
      "expected length cap to reject 257-char patterns",
    );
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// Syntactically invalid patterns must surface as a typed JSON-RPC error
// (-32602 InvalidParams) — not as the raw 'Invalid regular expression: …'
// SyntaxError that V8 emits, which escapes as a server bug to the host.
test("searchStrings rejects invalid regex syntax (Round 19)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "bad",
      binary: { name: "bad" },
      functions: [],
      strings: [{ addr: "0x100008000", value: "x" }],
      names: [],
    });
    assert.throws(
      () => store.searchStrings("[unterminated", { sessionId: "bad" }),
      /invalid regular expression/i,
      "expected guarded compile to reject unterminated character class",
    );
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// Sessions are evicted by `session.updatedAt` order when sessionCap is hit
// (pruneStaleSessions, knowledge-store.js:307). upsertSession sets updatedAt
// to ingest time, but applyToKnowledgeStore never bumped it on subsequent
// transaction commits — so a session the user has been heavily annotating for
// hours still looks "stale" (by initial-ingest time) the next time eviction
// runs. The 17th ingest can wipe a session full of annotations even though
// the user's been working in it. Bump session.updatedAt on commit so LRU
// reflects actual user activity.
test("commitTransaction bumps session.updatedAt (Round 20)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "edited",
      binary: { name: "edited" },
      functions: [{ addr: "0x100003f50", name: "sub_100003f50", size: 16, summary: "" }],
      strings: [],
      names: [],
    });
    const ingestUpdatedAt = store.state.sessions.edited.updatedAt;
    // Ingest sets updatedAt to "now" — wait one ms so the post-commit value
    // is unambiguously greater (ISO 8601 string compare is char-by-char).
    await new Promise((resolve) => setTimeout(resolve, 5));

    const txns = new TransactionManager(store);
    const begun = await txns.begin({ sessionId: "edited", name: "annotate" });
    await txns.queue(
      { transactionId: begun.transactionId, kind: "rename", addr: "0x100003f50", value: "validated" },
      { sessionId: "edited" },
    );
    await txns.commit({ transactionId: begun.transactionId, sessionId: "edited" });

    const after = store.state.sessions.edited.updatedAt;
    assert.ok(
      after > ingestUpdatedAt,
      `expected session.updatedAt to advance past ${ingestUpdatedAt}; got ${after}`,
    );
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});

// Hard end-to-end check on the eviction consequence: heavily-annotated A is
// no longer current, B is current, A was committed-to most recently — when
// we ingest C past the cap, B (older actual-activity) should be evicted, not
// A. Pre-fix, A's stale ingest-time updatedAt loses to B's later ingest
// timestamp and A is wiped despite the recent annotations.
test("pruneStaleSessions preserves recently-annotated non-current session (Round 20)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const store = new KnowledgeStore(join(dir, "s.json"));
  store.sessionCap = 2;
  await store.load();
  try {
    await store.upsertSession({
      sessionId: "A",
      binary: { name: "A" },
      functions: [{ addr: "0x100003f50", name: "sub_A", size: 16, summary: "" }],
      strings: [],
      names: [],
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await store.upsertSession({
      sessionId: "B",
      binary: { name: "B" },
      functions: [],
      strings: [],
      names: [],
    });
    // B is now current. Annotate A heavily after B's ingest.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const txns = new TransactionManager(store);
    const begun = await txns.begin({ sessionId: "A", name: "annotate" });
    await txns.queue(
      { transactionId: begun.transactionId, kind: "rename", addr: "0x100003f50", value: "renamed" },
      { sessionId: "A" },
    );
    await txns.commit({ transactionId: begun.transactionId, sessionId: "A" });

    // Now ingest C: cap=2, so one of {A, B} must be evicted. B is current
    // and pinned, but pruneStaleSessions also pins by currentSessionId at
    // call time — and currentSessionId becomes C after the upsert. So
    // evictable = {A, B}, sorted by updatedAt asc: A's last commit must
    // beat B's ingest, so B (older) is evicted, A preserved.
    await store.upsertSession({
      sessionId: "C",
      binary: { name: "C" },
      functions: [],
      strings: [],
      names: [],
    });

    assert.ok(store.state.sessions.A, "A (recently annotated) must survive eviction");
    assert.equal(store.state.sessions.A.functions["0x100003f50"].name, "renamed",
      "A's annotations must be preserved");
    assert.ok(!store.state.sessions.B, "B (older by activity) should have been evicted");
    assert.ok(store.state.sessions.C, "C (current) is pinned");
  } finally {
    await store.save();
    await rm(dir, { recursive: true, force: true });
  }
});
