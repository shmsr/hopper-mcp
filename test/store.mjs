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
