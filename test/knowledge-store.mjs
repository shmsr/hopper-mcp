import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { KnowledgeStore } from "../src/knowledge-store.js";

async function freshStore({ sessionCap } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ks-test-"));
  const path = join(dir, "store.json");
  const store = new KnowledgeStore(path, { sessionCap });
  await store.load();
  return { store, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

async function ingest(store, id) {
  await store.upsertSession({ sessionId: id, binary: { name: id }, functions: [], strings: [] });
  // The pruner sorts by updatedAt; sleep a tick so siblings differ.
  await new Promise((resolve) => setTimeout(resolve, 5));
}

test("pruneStaleSessions evicts oldest by updatedAt and pins current", async () => {
  const { store, cleanup } = await freshStore({ sessionCap: 3 });
  try {
    for (const id of ["s0", "s1", "s2", "s3", "s4"]) await ingest(store, id);
    const ids = Object.keys(store.state.sessions).sort();
    assert.deepEqual(ids, ["s2", "s3", "s4"]);
    assert.equal(store.state.currentSessionId, "s4");
  } finally {
    await cleanup();
  }
});

test("pruneStaleSessions never evicts the current session even if it is oldest", async () => {
  // High cap so the per-upsert prune does not interfere; we exercise the
  // explicit-cap path below.
  const { store, cleanup } = await freshStore({ sessionCap: 100 });
  try {
    await ingest(store, "old");
    await ingest(store, "newer");
    await ingest(store, "newest");
    // Pin the oldest session as current, then prune to a single slot.
    store.state.currentSessionId = "old";
    const evicted = store.pruneStaleSessions(1);
    const ids = Object.keys(store.state.sessions);
    assert.deepEqual(ids, ["old"], `current session was evicted; remaining=${ids.join(",")}`);
    assert.deepEqual(evicted.sort(), ["newer", "newest"]);
  } finally {
    await cleanup();
  }
});

test("constructor falls back to default cap on bad input", async () => {
  const cases = [{ sessionCap: 0 }, { sessionCap: -3 }, { sessionCap: "not a number" }, {}];
  for (const opts of cases) {
    const { store, cleanup } = await freshStore(opts);
    try {
      assert.ok(store.sessionCap > 0, `bad cap ${JSON.stringify(opts)} produced ${store.sessionCap}`);
    } finally {
      await cleanup();
    }
  }
});

test("empty store: pruneStaleSessions is a no-op", async () => {
  const { store, cleanup } = await freshStore({ sessionCap: 1 });
  try {
    assert.deepEqual(store.pruneStaleSessions(), []);
  } finally {
    await cleanup();
  }
});
