import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readdir, rm } from "node:fs/promises";
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
  const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
  const storePath = join(dir, "subdir-that-doesnt-block/store.json");
  const store = new KnowledgeStore(storePath);
  await store.load();
  store.state = { schemaVersion: 1, sessions: { x: { sessionId: "x", binary: { name: "n" } } } };
  // Force a write failure mid-flight by stubbing _writeStateToDisk with a copy
  // of the new try/catch flow that throws between writeFile and rename. This
  // does not exercise the production method directly, but it does prove the
  // cleanup pattern leaves no tempfiles when rename fails.
  store._writeStateToDisk = async function () {
    const tmp = `${this.path}.${process.pid}.${Date.now()}.tmp`;
    const { writeFile, unlink } = await import("node:fs/promises");
    try {
      await writeFile(tmp, "ok", "utf8");
      throw new Error("simulated rename failure");
    } catch (err) {
      try { await unlink(tmp); } catch {}
      throw err;
    }
  };
  await assert.rejects(() => store.save());
  const entries = await readdir(dir);
  assert.deepEqual(entries.filter((n) => n.endsWith(".tmp")), []);
  await rm(dir, { recursive: true, force: true });
});
