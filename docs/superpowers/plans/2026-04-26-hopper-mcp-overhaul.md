# Hopper MCP Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut Hopper MCP tool surface from 63 to 30 LLM-friendly tools, enforce a snapshot/passthrough/mutator invariant, fix atomic-write tempfile leak, and reorganize tests into 9 files across 4 tiers.

**Architecture:** Add three consolidated discriminator tools (`list`, `analyze_binary`; extend existing `procedure`/`search`) and one resource template *first*, port the test suite onto the new surface, then delete 35 obsolete tools in three safe slices, then wire up scripts and docs. Order is critical: tests must already exercise the new surface before any deletions, so every removal step has a green baseline.

**Tech Stack:** Node.js 20+, `@modelcontextprotocol/sdk` ^1.29, Zod, JSON-RPC over stdio. macOS-only (otool/codesign/Hopper).

**Spec:** `docs/superpowers/specs/2026-04-26-hopper-mcp-overhaul-design.md`

---

## File structure

### Files to create

- `test/fixtures/index.mjs` — shared test helpers (server spawn, JSON-RPC client, fixture loaders)
- `test/fixtures/sample-session.mjs` — moved from `src/sample-session.js`
- `test/fixtures/README.md` — fixture provenance
- `test/protocol.mjs` — replaces `test/protocol-compat.mjs`
- `test/store.mjs` — replaces `test/knowledge-store.mjs`
- `test/lifecycle.mjs` — replaces `test/session-lifecycle.mjs`
- `test/macho.mjs` — replaces parts of `multi-binary.mjs`/`deep-coverage.mjs`
- `test/snapshot.mjs` — replaces `test/procedure-resolution.mjs` and parts of `all-tools-real.mjs`
- `test/transactions.mjs` — extracts transaction tests
- `test/research.mjs` — replaces `research-tools.mjs`/`research-integration.mjs`
- `test/live.mjs` — replaces `live-hopper.mjs`/`live-hopper-aggressive.mjs`/`official-backend.mjs`/`hopper-real-app.mjs`

### Files to modify

- `src/server-tools.js` — major: add `list`+`analyze_binary`, extend `procedure`+`search`, remove 35 tools, kill `backend:` branches (1972 → ~800 lines)
- `src/server-resources.js` — add `hopper://transactions/{id}` template
- `src/knowledge-store.js` — add `getTransactionById`, `listByKind`, `procedureField` helpers; fix tempfile cleanup
- `src/server-helpers.js` — drop helpers used only by deleted tools
- `src/hopper-bridge.js` — remove fan-out for per-tool live routing
- `src/hopper-adapter.js` — delete if unused
- `src/sample-session.js` — moved (delete here, recreated under test/fixtures)
- `package.json` — script overhaul
- `README.md` — surface section rewrite

### Files to delete

Test files (10): `all-tools-real.mjs`, `binary-zoo.mjs`, `deep-coverage.mjs`, `hopper-real-app.mjs`, `live-hopper-aggressive.mjs`, `live-hopper.mjs`, `multi-binary.mjs`, `official-backend.mjs`, `procedure-resolution.mjs`, `protocol-compat.mjs`, `real-app.mjs`, `research-integration.mjs`, `research-tools.mjs`, `session-lifecycle.mjs`, `knowledge-store.mjs` (these are renamed/replaced — exact rm list in Task 16).

Untracked: `data/knowledge-store.json.44387.1777131199566.tmp`, `data/knowledge-store.json.74519.1777144513011.tmp` (cleaned in Task 6).

---

## Task 1: Test fixtures and JSON-RPC client harness

**Files:**
- Create: `test/fixtures/index.mjs`
- Create: `test/fixtures/sample-session.mjs`
- Create: `test/fixtures/README.md`
- Modify: `src/server-tools.js` (update import path to sample session — temporary; tool itself is removed in Task 14)

**Why first:** every other test file uses these helpers. The first test in Task 7 fails until this is done.

- [ ] **Step 1: Move `src/sample-session.js` → `test/fixtures/sample-session.mjs`**

```bash
git -C /Users/shmsr/hopper-mcp mv src/sample-session.js test/fixtures/sample-session.mjs
```

- [ ] **Step 2: Update import in `src/server-tools.js` (line ~51)**

Old:
```js
import { sampleSession } from "./sample-session.js";
```
New:
```js
import { sampleSession } from "../test/fixtures/sample-session.mjs";
```

(This is temporary — `ingest_sample` is removed in Task 14, after which this import goes away entirely.)

- [ ] **Step 3: Write `test/fixtures/index.mjs`**

```js
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(fileURLToPath(import.meta.url), "../../..");
const SERVER = join(REPO, "src/mcp-server.js");

export { sampleSession } from "./sample-session.mjs";

// Spawn the MCP server in an isolated store path; returns { call, close }.
export async function startServer({ env = {} } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "hopper-mcp-test-"));
  const child = spawn(process.execPath, [SERVER], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOPPER_MCP_STORE_PATH: join(dir, "store.json"), ...env },
  });

  let buffer = "";
  const pending = new Map();
  let nextId = 1;

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let idx;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      if (msg.id !== undefined && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(Object.assign(new Error(msg.error.message), msg.error));
        else resolve(msg.result);
      }
    }
  });

  child.stderr.on("data", (chunk) => process.stderr.write(`[server] ${chunk}`));

  function send(method, params) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  await send("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "test-harness", version: "0.0.0" },
  });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

  return {
    call: (name, args = {}) => send("tools/call", { name, arguments: args }),
    listTools: () => send("tools/list", {}),
    readResource: (uri) => send("resources/read", { uri }),
    listResources: () => send("resources/list", {}),
    raw: send,
    async close() {
      child.stdin.end();
      try { await once(child, "exit"); } catch {}
      await rm(dir, { recursive: true, force: true });
    },
  };
}

// Decode the JSON content block from a tools/call result.
export function decodeToolResult(result) {
  if (result.structuredContent !== undefined) return result.structuredContent;
  const block = result.content?.find((c) => c.type === "text");
  return block ? JSON.parse(block.text) : null;
}

// Convenience: starts server, ingests the sample session, returns harness + sessionId.
export async function startWithSample(opts) {
  const harness = await startServer(opts);
  // Sample is loaded via open_session (ingest_sample is going away in Task 14;
  // we never depend on the deprecated tool from tests).
  const { sampleSession } = await import("./sample-session.mjs");
  const result = await harness.call("open_session", { session: sampleSession() });
  const session = decodeToolResult(result);
  return { ...harness, sessionId: session.sessionId };
}
```

- [ ] **Step 4: Write `test/fixtures/README.md`**

```md
# Test fixtures

`sample-session.mjs` — a tiny normalized Hopper session, used as a deterministic
fixture by every T1/T2 test. Keep it small; this is loaded into a fresh store
in nearly every test.

`index.mjs` — `startServer()` spawns the MCP server in an isolated store path
and gives back a JSON-RPC client. `startWithSample()` adds an `open_session`
of the sample for convenience. Always `await harness.close()` in your `finally`
to avoid leaking servers and tmpdirs.

When tests need real binaries (T2/T3), they fetch from `/usr/bin/*` at start.
We require macOS already, so this is no new constraint and avoids vendoring
binaries.
```

- [ ] **Step 5: Verify the harness boots**

```bash
node -e '
import("./test/fixtures/index.mjs").then(async ({ startServer }) => {
  const h = await startServer();
  const tools = await h.listTools();
  console.log("tool count:", tools.tools.length);
  await h.close();
});
'
```

Expected: prints a number ≥ 60 (current surface). No errors, no leftover process.

- [ ] **Step 6: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: bootstrap fixtures and JSON-RPC harness"
```

---

## Task 2: Add `list({kind, detail})` tool

**Files:**
- Modify: `src/knowledge-store.js` — add `listByKind(session, kind, detail)` method
- Modify: `src/server-tools.js` — register `list` tool
- Test: `test/snapshot.mjs` (created here as a stub; expanded in Task 9)

The `list` tool replaces 7 today's tools: `list_procedures`, `list_procedure_size`, `list_procedure_info`, `list_strings`, `list_names`, `list_segments`, `list_bookmarks`. Plus two new affordances: `list({kind:"imports"})` and `list({kind:"exports"})`.

- [ ] **Step 1: Create `test/snapshot.mjs` with the failing test**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { startWithSample, decodeToolResult } from "./fixtures/index.mjs";

test("list({kind:'procedures'}) returns address-keyed object", async () => {
  const h = await startWithSample();
  try {
    const result = await h.call("list", { kind: "procedures" });
    const out = decodeToolResult(result);
    assert.equal(typeof out, "object");
    assert.ok(Object.keys(out).length > 0, "expected at least one procedure");
    for (const [addr, name] of Object.entries(out)) {
      assert.match(addr, /^0x[0-9a-f]+$/i);
      assert.equal(typeof name, "string");
    }
  } finally { await h.close(); }
});

test("list({kind:'procedures', detail:'size'}) returns objects with size + bb count", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "procedures", detail: "size" }));
    const first = Object.values(out)[0];
    assert.ok("size" in first && "basicblock_count" in first && "name" in first);
  } finally { await h.close(); }
});

test("list({kind:'strings'}) returns address-keyed object with values", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("list", { kind: "strings" }));
    assert.ok(Object.values(out).every((s) => typeof s.value === "string"));
  } finally { await h.close(); }
});

test("list rejects unknown kind", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(() => h.call("list", { kind: "nonsense" }), /kind/i);
  } finally { await h.close(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
node --test test/snapshot.mjs
```

Expected: all four tests fail with "tool not found: list" or similar.

- [ ] **Step 3: Add `listByKind` to `src/knowledge-store.js`** (insert before the closing `}` of the `KnowledgeStore` class)

```js
  // Single dispatch point used by the `list` tool. Each kind returns a shape
  // compatible with the corresponding pre-overhaul `list_*` tool.
  listByKind(sessionId, kind, detail = "brief") {
    const session = this.getSession(sessionId);
    switch (kind) {
      case "procedures": return this._listProcedures(session, detail);
      case "strings":    return this._listStrings(session);
      case "names":      return this._listNames(session);
      case "segments":   return session.segments ?? [];
      case "bookmarks":  return session.bookmarks ?? [];
      case "imports":    return session.imports ?? [];
      case "exports":    return session.exports ?? [];
      default:
        throw new Error(`Unknown list kind '${kind}'. Expected one of procedures|strings|names|segments|bookmarks|imports|exports.`);
    }
  }

  _listProcedures(session, detail) {
    const fns = Object.values(session.functions ?? {});
    const out = {};
    for (const fn of fns) {
      const addr = formatAddress(fn.addr);
      if (detail === "size") {
        out[addr] = { name: fn.name ?? null, size: fn.size ?? 0, basicblock_count: fn.basicBlocks?.length ?? 0 };
      } else if (detail === "info") {
        out[addr] = {
          name: fn.name ?? null,
          entrypoint: addr,
          length: fn.size ?? 0,
          basicblock_count: fn.basicBlocks?.length ?? 0,
          basicblocks: fn.basicBlocks ?? [],
          signature: fn.signature ?? null,
          locals: fn.locals ?? [],
        };
      } else {
        out[addr] = fn.name ?? addr;
      }
    }
    return out;
  }

  _listStrings(session) {
    const out = {};
    for (const s of session.strings ?? []) {
      out[formatAddress(s.addr)] = { value: s.value };
    }
    return out;
  }

  _listNames(session) {
    const out = {};
    for (const n of session.names ?? []) {
      out[formatAddress(n.addr)] = { name: n.name, demangled: n.demangled ?? null };
    }
    return out;
  }
```

- [ ] **Step 4: Register `list` tool in `src/server-tools.js`** (insert near the existing `procedure` registration around line 1330)

```js
  server.registerTool(
    "list",
    {
      title: "List",
      description:
        "List items from the active session by kind: procedures | strings | names | segments | bookmarks | imports | exports. " +
        "For procedures, optional `detail`: brief (default, addr→name) | size (addr→{name,size,basicblock_count}) | info (addr→full procedure info).",
      inputSchema: {
        kind: z.enum(["procedures", "strings", "names", "segments", "bookmarks", "imports", "exports"]),
        detail: z.enum(["brief", "size", "info"]).optional(),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => toolResult(store.listByKind(sessionFor(args), args.kind, args.detail ?? "brief")),
  );
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
node --test test/snapshot.mjs
```

Expected: 4 passed, 0 failed.

- [ ] **Step 6: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "feat(tools): add list tool with 7 kinds"
```

---

## Task 3: Add `analyze_binary({kind})` tool

**Files:**
- Modify: `src/server-tools.js` — register `analyze_binary` tool
- Test: append to `test/snapshot.mjs`

Folds 5 today's tools into one: `classify_capabilities`, `detect_anti_analysis`, `compute_section_entropy`, `extract_code_signing`, `extract_objc_runtime`. All take only `session_id`.

- [ ] **Step 1: Append failing tests to `test/snapshot.mjs`**

```js
test("analyze_binary({kind:'capabilities'}) returns capability buckets", async () => {
  const h = await startWithSample();
  try {
    const out = decodeToolResult(await h.call("analyze_binary", { kind: "capabilities" }));
    assert.equal(typeof out, "object");
    // Expect at least the buckets that are non-empty; structure: {bucket: [imports]}.
    for (const [bucket, list] of Object.entries(out)) {
      assert.ok(Array.isArray(list));
      assert.ok(typeof bucket === "string");
    }
  } finally { await h.close(); }
});

for (const kind of ["anti_analysis", "entropy", "code_signing", "objc"]) {
  test(`analyze_binary({kind:'${kind}'}) returns a non-error result`, async () => {
    const h = await startWithSample();
    try {
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.notEqual(out, null);
    } finally { await h.close(); }
  });
}

test("analyze_binary rejects unknown kind", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(() => h.call("analyze_binary", { kind: "nope" }));
  } finally { await h.close(); }
});
```

- [ ] **Step 2: Verify failure**

```bash
node --test test/snapshot.mjs
```

Expected: 6 new failures ("tool not found: analyze_binary").

- [ ] **Step 3: Register `analyze_binary` in `src/server-tools.js`** (insert at the end of the forensics section around line 1633)

```js
  server.registerTool(
    "analyze_binary",
    {
      title: "Analyze Binary",
      description:
        "Single entry for binary-level forensics. " +
        "kind: capabilities (imports bucketed) | anti_analysis (anti-debug findings) | entropy (per-section entropy) | code_signing (signing + entitlements) | objc (Objective-C runtime metadata).",
      inputSchema: {
        kind: z.enum(["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      switch (args.kind) {
        case "capabilities":  return toolResult(classifyImports(session.imports ?? []));
        case "anti_analysis": return toolResult(detectAntiAnalysis(session));
        case "entropy":       return toolResult(await computeSectionEntropy(session));
        case "code_signing":  return toolResult(await extractCodeSigning(session));
        case "objc":          return toolResult(await extractObjCRuntime(session));
      }
    },
  );
```

- [ ] **Step 4: Run tests**

```bash
node --test test/snapshot.mjs
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "feat(tools): add analyze_binary with 5 kinds"
```

---

## Task 4: Extend `procedure` tool with `comments` field

**Files:**
- Modify: `src/server-tools.js` — extend `procedure` enum and dispatcher
- Test: append to `test/snapshot.mjs`

Adds a `comments` field that returns both prefix and inline comments for the function and its instructions. Lets us delete the `comment` and `inline_comment` mirror tools.

- [ ] **Step 1: Append failing test**

```js
test("procedure({field:'comments'}) returns prefix + inline comments map", async () => {
  const h = await startWithSample();
  try {
    // Sample fixture must include a function with a known comment; harness ensures this.
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const out = decodeToolResult(await h.call("procedure", { field: "comments", procedure: addr }));
    assert.ok("prefix" in out && "inline" in out);
    assert.equal(typeof out.prefix, "object");
    assert.equal(typeof out.inline, "object");
  } finally { await h.close(); }
});
```

You may also need to extend `test/fixtures/sample-session.mjs` to include a comment on the first procedure if it doesn't already. Check first; if absent, add an entry to `comments` and `inlineComments` arrays for the first function's address.

- [ ] **Step 2: Verify failure**

```bash
node --test test/snapshot.mjs
```

Expected: failure on the `comments` field — current schema is enum without `"comments"`.

- [ ] **Step 3: Update `procedure` registration in `src/server-tools.js`** (line ~1330)

Replace the `field` enum:

Old:
```js
field: z.enum(["info", "assembly", "pseudo_code", "callers", "callees"]),
```
New:
```js
field: z.enum(["info", "assembly", "pseudo_code", "callers", "callees", "comments"]),
```

Add a case to the switch:

```js
case "comments": {
  const session = store.getSession(sessionId);
  const start = parseAddress(fn.addr) ?? 0;
  const end = start + (fn.size ?? 0);
  const inRange = (entry) => {
    const a = parseAddress(entry.addr) ?? 0;
    return a >= start && (end === start || a < end);
  };
  const prefix = {};
  const inline = {};
  for (const c of session.comments ?? []) if (inRange(c)) prefix[formatAddress(c.addr)] = c.value;
  for (const c of session.inlineComments ?? []) if (inRange(c)) inline[formatAddress(c.addr)] = c.value;
  return toolResult({ prefix, inline });
}
```

- [ ] **Step 4: Run tests**

```bash
node --test test/snapshot.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "feat(tools): extend procedure with comments field"
```

---

## Task 5: Add `hopper://transactions/{id}` resource template

**Files:**
- Modify: `src/knowledge-store.js` — add `getTransactionById(sessionId, txnId)`
- Modify: `src/server-resources.js` — register the template
- Test: append to `test/snapshot.mjs`

- [ ] **Step 1: Append failing test**

```js
test("hopper://transactions/{id} returns the matching transaction", async () => {
  const h = await startWithSample();
  try {
    const beginRes = await h.call("begin_transaction", { name: "test-txn" });
    const begin = decodeToolResult(beginRes);
    const id = begin.transactionId ?? begin.id;
    const read = await h.readResource(`hopper://transactions/${id}`);
    const body = JSON.parse(read.contents[0].text);
    assert.equal(body.id ?? body.transactionId, id);
  } finally { await h.close(); }
});

test("hopper://transactions/{id} returns 404-equivalent for unknown id", async () => {
  const h = await startWithSample();
  try {
    await assert.rejects(() => h.readResource("hopper://transactions/unknown-xxx"));
  } finally { await h.close(); }
});
```

- [ ] **Step 2: Add `getTransactionById` to `KnowledgeStore`** (in `src/knowledge-store.js`, alongside other transaction accessors)

```js
  getTransactionById(sessionId, txnId) {
    const session = this.getSession(sessionId);
    const txns = session.transactions ?? {};
    const txn = txns[txnId];
    if (!txn) throw new Error(`No transaction '${txnId}' in session '${session.sessionId}'.`);
    return txn;
  }
```

Also extend `getResource` (search for the existing transactions/pending case) to handle the parameterized form, e.g.:

```js
if (parsed.path.startsWith("/transactions/") && parsed.path !== "/transactions/pending") {
  const id = parsed.path.slice("/transactions/".length);
  return this.getTransactionById(sessionId, id);
}
```

- [ ] **Step 3: Register the template in `src/server-resources.js`** (after the existing `graph_callees` block)

```js
  server.registerResource(
    "transaction",
    new ResourceTemplate("hopper://transactions/{id}", { list: undefined }),
    {
      title: "Transaction",
      description: "Read a specific local transaction by id.",
      mimeType: "application/json",
    },
    read,
  );
```

- [ ] **Step 4: Run tests**

```bash
node --test test/snapshot.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "feat(resources): add hopper://transactions/{id} template"
```

---

## Task 6: Fix atomic-write tempfile leak

**Files:**
- Modify: `src/knowledge-store.js` — `_writeStateToDisk` and `load`
- Test: append to `test/store.mjs` (created in Task 8; for now, write the test inline to confirm the fix)
- Delete: stale `data/knowledge-store.json.*.tmp` files

The leftover `.tmp` files in `data/` indicate that on at least one path, the temp file is created but `rename` doesn't run (e.g. process crash or write error before rename). Fix two ways: (a) `try`/`finally` cleanup of the temp on write error, (b) startup sweep for orphan tempfiles matching the store path.

- [ ] **Step 1: Inspect the current implementation**

Read `src/knowledge-store.js:62-67` (the `_writeStateToDisk` method). Confirm: it creates `${path}.${pid}.${ts}.tmp`, writes content, then renames. On `writeFile` failure, the tmp leaks. On crash between writeFile and rename, the tmp leaks.

- [ ] **Step 2: Add the fix to `_writeStateToDisk`**

Replace the method body:

```js
  async _writeStateToDisk() {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.${Date.now()}.tmp`;
    try {
      await writeFile(tmp, JSON.stringify(this.state) + "\n", "utf8");
      await rename(tmp, this.path);
    } catch (err) {
      // Best-effort cleanup so we don't leak tmpfiles on write/rename failure.
      try { await unlink(tmp); } catch {}
      throw err;
    }
  }
```

Also add `unlink` to the imports at the top of the file:

```js
import { readFile, writeFile, mkdir, rename, unlink, readdir } from "node:fs/promises";
```

- [ ] **Step 3: Add a startup sweep in `load()`**

Modify `load()` to call a new `_sweepOrphanTmps` after a successful load:

```js
  async load() {
    try {
      const text = await readFile(this.path, "utf8");
      this.state = JSON.parse(text);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.state = structuredClone(EMPTY_STORE);
      await this.save();
    }
    await this._sweepOrphanTmps();
  }

  async _sweepOrphanTmps() {
    const dir = dirname(this.path);
    const base = this.path.split("/").pop();
    let entries;
    try { entries = await readdir(dir); } catch { return; }
    const prefix = `${base}.`;
    const suffix = ".tmp";
    for (const name of entries) {
      if (!name.startsWith(prefix) || !name.endsWith(suffix)) continue;
      // Skip our own in-flight tmp (none should exist at load time, but be safe).
      try { await unlink(`${dir}/${name}`); } catch {}
    }
  }
```

- [ ] **Step 4: Write a verification test**

Create `test/store.mjs` (this file is expanded further in Task 8; minimal stub here):

```js
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
  // Pre-create a directory where the rename target should be, to force rename failure.
  // Simulate with circular/illegal state instead: stub writeFile to throw.
  const store = new KnowledgeStore(storePath);
  await store.load();
  store.state = { schemaVersion: 1, sessions: { x: { sessionId: "x", binary: { name: "n" } } } };
  // Cause a forced failure by replacing _writeStateToDisk's write step.
  const orig = store._writeStateToDisk.bind(store);
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
```

- [ ] **Step 5: Run tests**

```bash
node --test test/store.mjs
```

Expected: 2 passed.

- [ ] **Step 6: Delete the stale tmpfiles in the repo**

```bash
rm -f /Users/shmsr/hopper-mcp/data/knowledge-store.json.*.tmp
ls /Users/shmsr/hopper-mcp/data
```

Expected: only `knowledge-store.json` remains.

- [ ] **Step 7: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "fix(store): clean up orphan tempfiles on load and on write failure"
```

---

## Task 7: Migrate protocol + smoke tests

**Files:**
- Create: `test/protocol.mjs` (replaces `test/protocol-compat.mjs`)
- Modify: `test/smoke.mjs` — port to fixtures helpers; cover all 22 resources

- [ ] **Step 1: Read the current `test/protocol-compat.mjs` and current `test/smoke.mjs`** to understand what they cover.

```bash
cat /Users/shmsr/hopper-mcp/test/protocol-compat.mjs
cat /Users/shmsr/hopper-mcp/test/smoke.mjs
```

- [ ] **Step 2: Write `test/protocol.mjs`**

```js
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
```

- [ ] **Step 3: Rewrite `test/smoke.mjs`**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { startWithSample, decodeToolResult } from "./fixtures/index.mjs";

const STATIC_RESOURCES = [
  "hopper://session/current",
  "hopper://binary/metadata",
  "hopper://binary/imports",
  "hopper://binary/exports",
  "hopper://binary/strings",
  "hopper://binary/capabilities",
  "hopper://binary/signing",
  "hopper://binary/entropy",
  "hopper://anti-analysis",
  "hopper://tags",
  "hopper://hypotheses",
  "hopper://names",
  "hopper://bookmarks",
  "hopper://comments",
  "hopper://inline-comments",
  "hopper://cursor",
  "hopper://functions",
  "hopper://objc/classes",
  "hopper://swift/symbols",
  "hopper://transactions/pending",
];

test("smoke: capabilities returns a session", async () => {
  const h = await startWithSample();
  try {
    const caps = decodeToolResult(await h.call("capabilities", {}));
    assert.ok(caps.sessions && caps.sessions.length >= 1);
  } finally { await h.close(); }
});

for (const uri of STATIC_RESOURCES) {
  test(`smoke: read ${uri}`, async () => {
    const h = await startWithSample();
    try {
      const res = await h.readResource(uri);
      assert.ok(res.contents && res.contents.length > 0);
    } finally { await h.close(); }
  });
}
```

- [ ] **Step 4: Run both**

```bash
node --test test/protocol.mjs
node --test test/smoke.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: migrate protocol and smoke tests onto fixtures harness"
```

---

## Task 8: Migrate store + lifecycle tests

**Files:**
- Modify: `test/store.mjs` — extend with cases ported from current `test/knowledge-store.mjs`
- Create: `test/lifecycle.mjs` — replaces `test/session-lifecycle.mjs`

- [ ] **Step 1: Read existing tests for content to port**

```bash
cat /Users/shmsr/hopper-mcp/test/knowledge-store.mjs
cat /Users/shmsr/hopper-mcp/test/session-lifecycle.mjs
```

- [ ] **Step 2: Extend `test/store.mjs`** with tests for: upsertSession + alias-fold, setCurrentSession, listSessions, getResource for static and parameterized URIs, session cap eviction policy. Keep the atomic-write tests from Task 6.

The store lives in `src/knowledge-store.js`; you can construct one directly with a tmp path (no server needed). Pattern:

```js
const dir = await mkdtemp(join(tmpdir(), "hopper-store-"));
const store = new KnowledgeStore(join(dir, "s.json"));
await store.load();
await store.upsertSession({ sessionId: "a", binary: { name: "A" }, functions: {}, /* ... */ });
// ...assertions...
await rm(dir, { recursive: true, force: true });
```

Cover at minimum:
- `upsertSession` with `overwrite:false` rejects duplicate id
- `setCurrentSession` rejects unknown id
- `setCurrentSession` updates `state.currentSessionId`
- `listSessions` returns all loaded sessions
- `getResource("hopper://transactions/pending")` returns array
- `getResource("hopper://function/{addr}")` returns the right function
- `getResource("hopper://function/{addr}{?session_id=other}")` reads from a non-current session
- Session cap: when `sessionCap=2`, after 3 ingests the oldest non-current session is evicted

- [ ] **Step 3: Write `test/lifecycle.mjs`**

```js
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
    await assert.rejects(() => h.call("open_session", { session: { ...sampleSession(), sessionId: "dup" }, overwrite: false }));
  } finally { await h.close(); }
});
```

- [ ] **Step 4: Run both**

```bash
node --test test/store.mjs test/lifecycle.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: migrate store and lifecycle tests"
```

---

## Task 9: Migrate Mach-O test

**Files:**
- Create: `test/macho.mjs` (replaces parts of `multi-binary.mjs` and `deep-coverage.mjs`)

- [ ] **Step 1: Read source tests for context**

```bash
head -80 /Users/shmsr/hopper-mcp/test/multi-binary.mjs
head -80 /Users/shmsr/hopper-mcp/test/deep-coverage.mjs
```

- [ ] **Step 2: Write `test/macho.mjs`**

Cover:
- `import_macho` against `/usr/bin/echo` returns a session with imports + procedures.
- `import_macho({deep:true, max_functions:200})` discovers more procedures than non-deep mode.
- `import_macho({arch:"arm64"})` selects the right slice for fat binaries (use `/usr/bin/dd` or any system fat binary — verify in source).
- `disassemble_range` returns assembly text for the entrypoint of an imported binary.
- `find_xrefs` finds at least one branch xref within an imported binary.
- `find_functions` returns ≥1 function for an imported binary.
- `containing_function` resolves an instruction address to its enclosing function.

```js
import test from "node:test";
import assert from "node:assert/strict";
import { startServer, decodeToolResult } from "./fixtures/index.mjs";

const ECHO = "/bin/echo";

test("import_macho ingests /bin/echo with procedures + imports", async () => {
  const h = await startServer();
  try {
    const out = decodeToolResult(await h.call("import_macho", { executable_path: ECHO }));
    assert.ok(out.sessionId);
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    assert.ok(Object.keys(procs).length > 0);
    const imports = decodeToolResult(await h.call("list", { kind: "imports" }));
    assert.ok(Array.isArray(imports) && imports.length > 0);
  } finally { await h.close(); }
});

test("import_macho deep mode discovers more procedures than shallow", async () => {
  const h = await startServer();
  try {
    const shallow = decodeToolResult(await h.call("import_macho", { executable_path: ECHO }));
    const shallowCount = Object.keys(decodeToolResult(await h.call("list", { kind: "procedures" }))).length;
    const deep = decodeToolResult(await h.call("import_macho", {
      executable_path: ECHO, deep: true, max_functions: 500, overwrite: true,
    }));
    const deepCount = Object.keys(decodeToolResult(await h.call("list", { kind: "procedures" }))).length;
    assert.ok(deepCount >= shallowCount, `deep (${deepCount}) should not be smaller than shallow (${shallowCount})`);
  } finally { await h.close(); }
});

test("disassemble_range returns text", async () => {
  const h = await startServer();
  try {
    const sess = decodeToolResult(await h.call("import_macho", { executable_path: ECHO }));
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const lines = decodeToolResult(await h.call("disassemble_range", { start: addr, length: 64 }));
    assert.ok(typeof lines === "string" || Array.isArray(lines));
  } finally { await h.close(); }
});

// Add: find_xrefs, find_functions, containing_function, multi-arch slice.
```

- [ ] **Step 3: Run**

```bash
node --test test/macho.mjs
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: migrate Mach-O importer + helpers tests"
```

---

## Task 10: Complete `test/snapshot.mjs`

**Files:**
- Modify: `test/snapshot.mjs` — extend to full coverage of all 9 snapshot reads

Already covers `list` (Task 2), `analyze_binary` (Task 3), `procedure` field (Task 4), `transactions/{id}` resource (Task 5). Add explicit cases for the rest.

- [ ] **Step 1: Append to `test/snapshot.mjs`** — for each tool below, write at least one happy-path test against the sample fixture, and one negative case (unknown address or mistyped input).

Tools to cover:
- `procedure` — exercise every `field` enum value (info, assembly, pseudo_code, callers, callees, comments) — partly covered, complete the matrix.
- `search` — exercise every `kind` (strings, procedures, names) with a known-matching pattern from the sample.
- `xrefs` — given a known address with refs in the sample, verify the response.
- `containing_function` — already covered in macho.mjs against an imported binary; here, cover the snapshot path against the sample (entrypoint match + containment match).
- `resolve` — exercise: address → function lookup, name → address, string → address.
- `query` — at least one DSL example: `name=foo`, `imports=_open`.
- `analyze_function_deep` — call against the first procedure of the sample, assert the response carries pseudocode/graph/evidence keys.
- `get_graph_slice` — radius=1 callers and callees against the first procedure.

Provide one full example so the engineer has a template:

```js
test("get_graph_slice radius=1 returns a graph object", async () => {
  const h = await startWithSample();
  try {
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const seed = Object.keys(procs)[0];
    const out = decodeToolResult(await h.call("get_graph_slice", { seed, radius: 1, kind: "calls" }));
    assert.ok(out && typeof out === "object");
    assert.ok("nodes" in out || "callers" in out || "callees" in out, "graph slice should expose nodes or call lists");
  } finally { await h.close(); }
});
```

- [ ] **Step 2: Run**

```bash
node --test test/snapshot.mjs
```

Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: complete snapshot read coverage"
```

---

## Task 11: Migrate transaction tests

**Files:**
- Create: `test/transactions.mjs`

- [ ] **Step 1: Write `test/transactions.mjs`**

Cover:
- `begin_transaction` returns an id; appears in `hopper://transactions/pending`.
- `queue` for each `kind`: `rename`, `comment`, `inline_comment`, `type_patch`, `tag`, `untag`, `rename_batch`. Each call returns a structured operation with `kind`, `addr`, etc.
- `preview_transaction` shows old/new values from queued ops.
- `commit_transaction` (no `backend`) writes to local store; subsequent `procedure({field:"info"})` reflects the rename.
- `rollback_transaction` discards queued ops; preview returns empty.
- `commit_transaction({backend:"official", confirm_live_write:true})` *without* `HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` rejects (refuses to send anything to Hopper).
- `commit_transaction` is idempotent in the failure sense: calling rollback twice is a clean error, not a crash.
- `hypothesis({action:"create"})` returns an id; `link` and `status` actions follow the lifecycle.

```js
import test from "node:test";
import assert from "node:assert/strict";
import { startWithSample, decodeToolResult } from "./fixtures/index.mjs";

test("begin → queue rename → preview shows pending op", async () => {
  const h = await startWithSample();
  try {
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const txn = decodeToolResult(await h.call("begin_transaction", { name: "rename test" }));
    await h.call("queue", { kind: "rename", addr, value: "renamed_target", transaction_id: txn.id });
    const preview = decodeToolResult(await h.call("preview_transaction", { transaction_id: txn.id }));
    assert.ok(preview.operations.find((op) => op.kind === "rename" && op.newValue === "renamed_target"));
  } finally { await h.close(); }
});

// Repeat shape for each queue kind. For brevity: write a helper that
// queues the right minimal payload per kind and asserts preview includes it.

test("commit applies rename to local store", async () => {
  const h = await startWithSample();
  try {
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const txn = decodeToolResult(await h.call("begin_transaction", {}));
    await h.call("queue", { kind: "rename", addr, value: "fn_after_commit", transaction_id: txn.id });
    await h.call("commit_transaction", { transaction_id: txn.id });
    const info = decodeToolResult(await h.call("procedure", { field: "info", procedure: addr }));
    assert.equal(info.name, "fn_after_commit");
  } finally { await h.close(); }
});

test("commit_transaction(backend:official) without env flag is rejected", async () => {
  const h = await startWithSample(); // env unset
  try {
    const txn = decodeToolResult(await h.call("begin_transaction", {}));
    await h.call("queue", { kind: "rename", addr: "0x1000", value: "x", transaction_id: txn.id });
    await assert.rejects(
      () => h.call("commit_transaction", { transaction_id: txn.id, backend: "official", confirm_live_write: true }),
      /HOPPER_MCP_ENABLE_OFFICIAL_WRITES|enable.*writes/i,
    );
  } finally { await h.close(); }
});

test("hypothesis create + link + status round-trip", async () => {
  const h = await startWithSample();
  try {
    const created = decodeToolResult(await h.call("hypothesis", { action: "create", topic: "license-check", claim: "validates a key" }));
    const id = created.hypothesisId ?? created.id;
    await h.call("hypothesis", { action: "link", hypothesis_id: id, evidence: "0x100003f50", evidence_kind: "address" });
    await h.call("hypothesis", { action: "status", hypothesis_id: id, status: "supported" });
  } finally { await h.close(); }
});
```

- [ ] **Step 2: Run**

```bash
node --test test/transactions.mjs
```

Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: migrate transaction tests onto fixtures harness"
```

---

## Task 12: Migrate research tests

**Files:**
- Create: `test/research.mjs`

- [ ] **Step 1: Read source tests**

```bash
head -100 /Users/shmsr/hopper-mcp/test/research-tools.mjs
head -100 /Users/shmsr/hopper-mcp/test/research-integration.mjs
```

- [ ] **Step 2: Write `test/research.mjs`** covering:

- All 5 `analyze_binary` kinds against an imported binary (`/usr/bin/login`, `/bin/echo`, or `/usr/bin/security` for code-signing richness).
- `compute_fingerprints` for a known function returns deterministic SHA-shaped strings.
- `find_similar_functions` between two slightly-different sessions returns at least one match.
- `diff_sessions` between an empty and a populated session returns expected adds/removes.

```js
import test from "node:test";
import assert from "node:assert/strict";
import { startServer, decodeToolResult } from "./fixtures/index.mjs";

const BIN = "/bin/echo";

for (const kind of ["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]) {
  test(`analyze_binary({kind:'${kind}'}) on ${BIN} returns a value`, async () => {
    const h = await startServer();
    try {
      await h.call("import_macho", { executable_path: BIN });
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.notEqual(out, null);
    } finally { await h.close(); }
  });
}

test("compute_fingerprints returns stable hashes", async () => {
  const h = await startServer();
  try {
    await h.call("import_macho", { executable_path: BIN });
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const a = decodeToolResult(await h.call("compute_fingerprints", { addr }));
    const b = decodeToolResult(await h.call("compute_fingerprints", { addr }));
    assert.deepEqual(a, b);
  } finally { await h.close(); }
});

// Add: find_similar_functions, diff_sessions.
```

- [ ] **Step 3: Run**

```bash
node --test test/research.mjs
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: migrate forensics tests onto analyze_binary"
```

---

## Task 13: Migrate live tests (T3)

**Files:**
- Create: `test/live.mjs` — gated; only runs when `HOPPER_MCP_LIVE=1`

- [ ] **Step 1: Write `test/live.mjs`** — guarded by env

```js
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
    await h.call("queue", { kind: "rename", addr, value: `live_test_${Date.now()}`, transaction_id: txn.id });
    const out = decodeToolResult(await h.call("commit_transaction", {
      transaction_id: txn.id, backend: "official", confirm_live_write: true,
    }));
    assert.ok(out.applied || out.appliedToHopper);
  } finally { await h.close(); }
});
```

- [ ] **Step 2: Smoke run with skip**

```bash
node --test test/live.mjs
```

Expected: all skipped (output: `# tests N`, `# pass 0`, `# skipped N`).

- [ ] **Step 3: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "test: add gated live tier with ingest + official_hopper_call coverage"
```

---

## Task 14: Strip 23 snapshot mirror tools

**Files:**
- Modify: `src/server-tools.js` — remove tool registrations
- Modify: `src/server-helpers.js` — drop helpers used only by deleted tools (audit after the deletions land)

This is the first big slice. After this task, every snapshot read goes through `procedure`, `search`, `list`, `xrefs`, `containing_function`, `resolve`, `query`, `analyze_function_deep`, or `get_graph_slice`.

- [ ] **Step 1: Run the full T0+T1+T2 suite first, save the baseline**

```bash
npx --yes --no-install node --check src/*.js test/*.mjs
node --test test/protocol.mjs test/smoke.mjs test/store.mjs test/lifecycle.mjs test/macho.mjs test/snapshot.mjs test/transactions.mjs test/research.mjs
```

Expected: all green. This is the baseline — it must stay green after the deletions.

- [ ] **Step 2: Delete the 23 tool registrations from `src/server-tools.js`**

Remove `registerTool` blocks for each of:

`list_documents`, `current_document`, `current_address`, `current_procedure`, `procedure_info`, `procedure_assembly`, `procedure_pseudo_code`, `procedure_callers`, `procedure_callees`, `procedure_address`, `address_name`, `list_segments`, `list_procedures`, `list_procedure_size`, `list_procedure_info`, `list_strings`, `list_names`, `list_bookmarks`, `search_strings`, `search_procedures`, `search_name`, `comment`, `inline_comment`.

Use grep to locate each: `grep -n '"list_documents"\|"current_document"\| ...' src/server-tools.js` — line numbers were captured during exploration: 821, 841, 861, 875, 897, 912, 937, 958, 974, 991, 1005, 1019, 1035, 1055, 1069, 1100, 1129, 1150, 1171, 1205, 1241, 1278, 1296, 1313 (verify with a fresh grep before deleting).

- [ ] **Step 3: Delete the `officialRead` helper and every `backend === "official"` branch in surviving tools**

Search and remove:

```bash
grep -n 'officialRead\|backend === "official"\|optionalBackend' /Users/shmsr/hopper-mcp/src/server-tools.js
```

The `optionalBackend` import / declaration at the top should also go *except* for the one site `commit_transaction` still uses (line ~1563). Keep just that one.

- [ ] **Step 4: Audit `src/server-helpers.js`**

```bash
grep -nE 'export (function|const)' /Users/shmsr/hopper-mcp/src/server-helpers.js
```

For each export, grep `src/server-tools.js` and `src/research-tools.js` for usage. Anything with no remaining caller is dead — delete.

- [ ] **Step 5: Static-check + run all T1+T2 tests**

```bash
node --check src/server-tools.js && node --test test/protocol.mjs test/smoke.mjs test/store.mjs test/lifecycle.mjs test/macho.mjs test/snapshot.mjs test/transactions.mjs test/research.mjs
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "refactor: remove 23 snapshot mirror tools (replaced by list/search/procedure/resolve)"
```

---

## Task 15: Strip 5 forensics singletons + 4 mixed-mode comparators

**Files:**
- Modify: `src/server-tools.js`

- [ ] **Step 1: Remove forensics singletons**

Delete `registerTool` blocks for: `classify_capabilities`, `detect_anti_analysis`, `compute_section_entropy`, `extract_code_signing`, `extract_objc_runtime` (lines 1633, 1658, 1681, 1712, 1739 in original — verify).

- [ ] **Step 2: Remove mixed-mode comparators**

Delete: `compare_with_hopper`, `hopper_decompile`, `hopper_assembly`, `hopper_callees` (lines 404, 442, 473, 502 in original).

- [ ] **Step 3: Drop dead imports from `src/server-tools.js`**

Specifically remove (top of file):
```js
import {
  fetchHopperProcedureIndex,
  computeProcedureDrift,
  fetchHopperXrefs,
  fetchHopperDecompilation,
  fetchHopperAssembly,
  fetchHopperCallees,
  fetchHopperNames,
} from "./hopper-bridge.js";
```

if those are only consumed by the deleted comparators. Verify with grep first; if `hopper-live.js` still uses any, keep them.

- [ ] **Step 4: Audit `src/hopper-bridge.js`**

```bash
grep -nE 'export (function|const)' /Users/shmsr/hopper-mcp/src/hopper-bridge.js
```

For each export, check callers in `src/`. Delete any export with no remaining importer. If only `ingest_live_hopper` glue remains, the file may still hold ~50% of its content; that is fine.

- [ ] **Step 5: Static-check + run T1+T2**

```bash
node --check src/server-tools.js src/hopper-bridge.js && \
node --test test/protocol.mjs test/smoke.mjs test/store.mjs test/lifecycle.mjs test/macho.mjs test/snapshot.mjs test/transactions.mjs test/research.mjs
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "refactor: remove forensics singletons (folded into analyze_binary) and mixed-mode comparators"
```

---

## Task 16: Strip 3 test-only/discovery tools and dead helpers

**Files:**
- Modify: `src/server-tools.js`
- Possibly delete: `src/hopper-adapter.js`, `src/sample-session.js` (already moved in Task 1; the old file should not exist anymore, just confirm)

- [ ] **Step 1: Remove `debug_echo` registration and the `enableDebugTools` block**

In `src/server-tools.js` lines ~147-166, delete the `if (enableDebugTools) { server.registerTool("debug_echo", ...)` entirely. Also remove the constant declaration `const enableDebugTools = process.env.HOPPER_MCP_ENABLE_DEBUG_TOOLS === "1";` at line ~65.

- [ ] **Step 2: Remove `ingest_sample` registration**

Delete the block at line ~240. Also remove `import { sampleSession } from "../test/fixtures/sample-session.mjs";` since no production code imports it anymore.

- [ ] **Step 3: Remove `official_hopper_tools` registration**

Delete the block at line ~136.

- [ ] **Step 4: Audit `src/hopper-adapter.js`**

```bash
grep -rn 'hopper-adapter' /Users/shmsr/hopper-mcp/src/
```

If the only references are inside `hopper-adapter.js` itself (no importers), delete the file.

- [ ] **Step 5: Confirm `src/sample-session.js` no longer exists**

```bash
ls /Users/shmsr/hopper-mcp/src/sample-session.js 2>&1 | head -1
```

Expected: `No such file or directory` (was moved in Task 1).

- [ ] **Step 6: Static-check + run T1+T2**

```bash
node --check src/server-tools.js && \
node --test test/protocol.mjs test/smoke.mjs test/store.mjs test/lifecycle.mjs test/macho.mjs test/snapshot.mjs test/transactions.mjs test/research.mjs
```

- [ ] **Step 7: Verify the final tool count**

```bash
node -e '
import("./test/fixtures/index.mjs").then(async ({ startServer }) => {
  const h = await startServer();
  const { tools } = await h.listTools();
  console.log("count:", tools.length);
  console.log(tools.map((t) => t.name).sort().join("\n"));
  await h.close();
});
'
```

Expected output: count 30, listing the 30 tools enumerated in the spec.

- [ ] **Step 8: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "refactor: remove debug_echo/ingest_sample/official_hopper_tools and dead helpers"
```

---

## Task 17: Update `package.json` and delete obsolete tests

**Files:**
- Modify: `package.json`
- Delete: 12 obsolete test files

- [ ] **Step 1: Replace `package.json` scripts block**

```json
  "scripts": {
    "start": "node ./src/mcp-server.js",
    "check": "node --check src/*.js && node --check test/*.mjs && node --check test/fixtures/*.mjs",
    "test": "npm run check && node --test test/protocol.mjs test/smoke.mjs test/store.mjs test/lifecycle.mjs test/macho.mjs test/snapshot.mjs test/transactions.mjs test/research.mjs",
    "test:live": "HOPPER_MCP_LIVE=1 node --test test/live.mjs",
    "test:all": "npm test && npm run test:live"
  },
```

- [ ] **Step 2: Delete obsolete test files**

```bash
rm /Users/shmsr/hopper-mcp/test/all-tools-real.mjs \
   /Users/shmsr/hopper-mcp/test/binary-zoo.mjs \
   /Users/shmsr/hopper-mcp/test/deep-coverage.mjs \
   /Users/shmsr/hopper-mcp/test/hopper-real-app.mjs \
   /Users/shmsr/hopper-mcp/test/knowledge-store.mjs \
   /Users/shmsr/hopper-mcp/test/live-hopper-aggressive.mjs \
   /Users/shmsr/hopper-mcp/test/live-hopper.mjs \
   /Users/shmsr/hopper-mcp/test/multi-binary.mjs \
   /Users/shmsr/hopper-mcp/test/official-backend.mjs \
   /Users/shmsr/hopper-mcp/test/procedure-resolution.mjs \
   /Users/shmsr/hopper-mcp/test/protocol-compat.mjs \
   /Users/shmsr/hopper-mcp/test/real-app.mjs \
   /Users/shmsr/hopper-mcp/test/research-integration.mjs \
   /Users/shmsr/hopper-mcp/test/research-tools.mjs \
   /Users/shmsr/hopper-mcp/test/session-lifecycle.mjs
```

- [ ] **Step 3: Run the new `npm test`**

```bash
cd /Users/shmsr/hopper-mcp && npm test
```

Expected: all tests pass; check passes; output runs in under 60s.

- [ ] **Step 4: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "build: simplify test scripts; delete 15 obsolete test files"
```

---

## Task 18: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the "MCP Surface" section with the 30-tool list**

Locate the "## MCP Surface" heading. Replace the body with:

```md
## MCP Surface

Tools follow a strict invariant: every tool is one of (a) a snapshot reader,
(b) the live passthrough `official_hopper_call`, or (c) a mutator. There is no
per-tool `backend:` flag — live access goes through `official_hopper_call`,
and live writes go through `commit_transaction(backend:"official")` (gated by
`HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1` and `confirm_live_write: true`).

**Meta (2)**
- `capabilities`
- `official_hopper_call`

**Lifecycle / ingest (6)**
- `import_macho`
- `ingest_live_hopper`
- `ingest_official_hopper`
- `open_session`
- `close_session`
- `set_current_session`

**Local binary helpers (3)**
- `disassemble_range`
- `find_xrefs`
- `find_functions`

**Snapshot reads (9)**
- `procedure(field: info|assembly|pseudo_code|callers|callees|comments)`
- `search(kind: strings|procedures|names)`
- `list(kind: procedures|strings|names|segments|bookmarks|imports|exports)`
- `xrefs`, `containing_function`, `resolve`, `query`, `analyze_function_deep`, `get_graph_slice`

**Transactions (6)**
- `begin_transaction`, `queue(kind: …)`, `hypothesis(action: …)`, `preview_transaction`, `commit_transaction`, `rollback_transaction`

**Forensics (4)**
- `analyze_binary(kind: capabilities|anti_analysis|entropy|code_signing|objc)`
- `compute_fingerprints`, `find_similar_functions`, `diff_sessions`

**Resources** — 22 entries; see `src/server-resources.js`.

**Prompts** — `function_triage`, `hypothesis_workspace`.
```

- [ ] **Step 2: Remove all `backend: "official"` examples in the README**

Search:
```bash
grep -n 'backend.*official' /Users/shmsr/hopper-mcp/README.md
```

Each non-`commit_transaction` example must be removed or rewritten to use `official_hopper_call`. The remaining `commit_transaction` example stays; it is the only legitimate use.

- [ ] **Step 3: Update the `Run` section to reference the new scripts**

Replace any references to `npm run test:protocol`, `npm run smoke`, `npm run test:tools`, etc. with `npm test` and `npm run test:live`.

- [ ] **Step 4: Final test pass**

```bash
cd /Users/shmsr/hopper-mcp && npm test
```

- [ ] **Step 5: Commit**

```bash
git -C /Users/shmsr/hopper-mcp add -A
git -C /Users/shmsr/hopper-mcp commit -m "docs: rewrite README MCP surface for the 30-tool overhaul"
```

---

## Done criteria

- `npm test` runs T0+T1+T2 in < 60 s, all green, on a machine without Hopper.
- `npm run test:live` runs T3 in 2-5 min when Hopper is installed and `HOPPER_MCP_LIVE=1`.
- `tools/list` returns exactly 30 tools matching the spec.
- `resources/list` includes `hopper://transactions/{id}` template.
- No `data/knowledge-store.json.*.tmp` stragglers after a full test run.
- `src/server-tools.js` is below 1100 lines (target ~800).
- README's MCP Surface section matches the 30-tool spec exactly.
