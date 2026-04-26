import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KnowledgeStore } from "../src/knowledge-store.js";

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
