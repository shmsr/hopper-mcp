// Deep coverage regression: exercises code paths that multi-binary.mjs doesn't cover.
//   A. Deep-mode otool function discovery (ARM64)
//   B. x86_64 slice import (universal binary, alternate arch)
//   C. disassemble_range on a real entry, validates streaming output
//   D. find_xrefs against a real branch target
//   E. Knowledge-store persistence across MCP server restarts
//   F. Snapshot reads via hopper:// resources + unified search/resolve
//   G. preview_transaction surfaces queued operations before commit
//   H. Query DSL: combined predicates, NOT, regex literals, parens
//   I. Error paths: invalid address, malformed query
//   J. Code-signing entitlements parsed from sandboxed binary
//   K. ObjC parser depth: class+method addresses captured

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rmSync, existsSync, statSync } from "node:fs";
import assert from "node:assert/strict";
import {
  importMachO,
  disassembleRange,
  findXrefs,
  discoverFunctionsFromDisassembly,
} from "../src/macho-importer.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const storePath = join(root, "data", "deep-coverage-store.json");
try { rmSync(storePath, { force: true }); } catch {}

const LS = "/bin/ls";
const CALC = "/System/Applications/Calculator.app/Contents/MacOS/Calculator";

function fail(label, got) {
  throw new Error(`${label} (got ${JSON.stringify(got)?.slice(0, 200)})`);
}

// ─── Phase A: Deep-mode discovery ────────────────────────────────────────
console.log("[A] deep-mode otool function discovery (arm64e)…");
{
  const t0 = Date.now();
  const session = await importMachO(LS, { arch: "arm64e", deep: true, maxFunctions: 5000 });
  const ms = Date.now() - t0;
  const otoolFns = session.functions.filter((f) => f.source === "otool-discovery" || f.source === "nm+otool");
  if (otoolFns.length < 10) fail("deep mode found <10 otool functions", otoolFns.length);
  const withCallees = otoolFns.filter((f) => f.callees?.length);
  if (withCallees.length < 5) fail("expected ≥5 functions with callees", withCallees.length);
  // every discovered function has a fingerprint
  const noFp = otoolFns.filter((f) => !f.fingerprint);
  if (noFp.length) fail("some otool functions missing fingerprint", noFp.length);
  // edge sanity: target of a callee should look like an address
  const sampleEdge = withCallees[0].callees[0];
  if (!/^0x[0-9a-fA-F]+$/.test(sampleEdge)) fail("callee target malformed", sampleEdge);
  console.log(`  ✓ ${ms}ms total=${session.functions.length} otool=${otoolFns.length} withCallees=${withCallees.length}`);
}

// Direct discovery API (used by find_xrefs / range tools)
console.log("[A2] discoverFunctionsFromDisassembly direct…");
{
  const out = await discoverFunctionsFromDisassembly(LS, { arch: "arm64e", maxFunctions: 100 });
  if (out.functions.length < 10) fail("direct discovery <10 fns", out.functions.length);
  if (out.callEdges.length < 5) fail("direct discovery <5 call edges", out.callEdges.length);
  // adrpRefs should resolve to *some* targets (not necessarily strings on /bin/ls)
  if (!Array.isArray(out.adrpRefs)) fail("adrpRefs not array", out.adrpRefs);
  console.log(`  ✓ fns=${out.functions.length} edges=${out.callEdges.length} adrpRefs=${out.adrpRefs.length}`);
}

// ─── Phase B: x86_64 slice import ────────────────────────────────────────
console.log("[B] x86_64 slice import (universal /bin/ls)…");
{
  const session = await importMachO(LS, { arch: "x86_64", maxStrings: 200 });
  if (session.binary.arch !== "x86_64") fail("arch mismatch", session.binary.arch);
  if (!session.imports.length) fail("x86 imports empty", session.imports.length);
  const text = session.binary.sectionEntropy.find((s) => s.sectname === "__text");
  if (!text) fail("x86 missing __text entropy", session.binary.sectionEntropy.map((s) => s.sectname));
  if (text.entropy < 4 || text.entropy > 8) fail("x86 __text entropy out of band", text.entropy);
  if (!session.binary.signing?.signed) fail("x86 not signed", session.binary.signing);
  if (!session.binary.imphash) fail("x86 missing imphash", session.binary.imphash);
  // arm64e and x86_64 imphashes must differ (different syscall ABIs surface different stubs)
  const arm = await importMachO(LS, { arch: "arm64e", maxStrings: 50 });
  if (session.binary.imphash === arm.binary.imphash) fail("imphash collision arm vs x86", { x86: session.binary.imphash, arm: arm.binary.imphash });
  // segments populated for both arches
  if (!session.binary.segments?.length) fail("x86 segments empty", session.binary.segments);
  if (!arm.binary.segments?.length) fail("arm segments empty", arm.binary.segments);
  console.log(`  ✓ x86 entropy=${text.entropy.toFixed(2)} segs=${session.binary.segments.length} imphash=${session.binary.imphash.slice(0, 8)}…`);
}

// ─── Phase C: disassemble_range ──────────────────────────────────────────
console.log("[C] disassembleRange on /bin/ls…");
{
  // Use real text-section addresses (from /bin/ls __text)
  const out = await disassembleRange(LS, { arch: "arm64e", startAddr: "0x100002a00", endAddr: "0x100002a40" });
  if (!out.lineCount) fail("disasm zero lines", out);
  if (out.lines.length !== out.lineCount) fail("lineCount/lines mismatch", { count: out.lineCount, len: out.lines.length });
  const first = out.lines[0];
  if (!first.addr || !first.mnemonic) fail("first line missing fields", first);
  // Each line addr must be within range
  for (const line of out.lines) {
    const addr = parseInt(line.addr, 16);
    if (addr < 0x100002a00 || addr > 0x100002a40) fail("disasm line out of range", line);
  }
  console.log(`  ✓ ${out.lineCount} instructions, first=${first.mnemonic} ${first.operands}`);
}

// ─── Phase D: find_xrefs ─────────────────────────────────────────────────
console.log("[D] findXrefs…");
{
  // Pick a target that has callers. Discover first, then xref the most-called fn.
  const disc = await discoverFunctionsFromDisassembly(LS, { arch: "arm64e", maxFunctions: 200 });
  const callTo = new Map();
  for (const e of disc.callEdges) callTo.set(e.to, (callTo.get(e.to) ?? 0) + 1);
  const [target] = [...callTo.entries()].sort((a, b) => b[1] - a[1]);
  if (!target) fail("no call edges discovered", disc.callEdges.length);
  const [targetAddr, expectedCount] = target;
  const xrefs = await findXrefs(LS, { arch: "arm64e", targetAddr, maxResults: 50 });
  if (!xrefs.length) fail(`xrefs empty for popular target ${targetAddr}`, xrefs);
  if (xrefs.length < Math.min(expectedCount, 5)) fail(`xrefs count too low (expected near ${expectedCount})`, xrefs.length);
  // every xref must be a call/branch/adrp_*
  for (const r of xrefs) {
    if (!/^(call|branch|adrp_(add|ldr))$/.test(r.type)) fail("unexpected xref type", r);
    if (!/^0x[0-9a-fA-F]+$/.test(r.addr)) fail("malformed xref addr", r);
  }
  console.log(`  ✓ target=${targetAddr} found=${xrefs.length} (expected ≥${Math.min(expectedCount, 5)})`);
}

// ─── Phase E: store persistence across MCP restarts ──────────────────────
console.log("[E] knowledge-store persistence across restarts…");
const lsSession = await importMachO(LS, { arch: "arm64e", maxStrings: 100 });
lsSession.sessionId = "deep-ls";
{
  // Round 1: open session, queue+commit a tag, then kill server
  const round1 = await spawnServer(storePath);
  await round1.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "deep", version: "0" } });
  await round1.callTool("open_session", { session: lsSession });
  const txn = await round1.callTool("begin_transaction", { session_id: lsSession.sessionId, name: "persist tag" });
  // Tag at first real function addr.
  const fnAddr = lsSession.functions[0].addr;
  await round1.callTool("queue", {
    kind: "tag",
    session_id: lsSession.sessionId,
    transaction_id: txn.transactionId,
    addr: fnAddr,
    tags: ["persisted", "round1"],
  });
  await round1.callTool("commit_transaction", { session_id: lsSession.sessionId, transaction_id: txn.transactionId });
  await round1.shutdown();

  // The store file should exist and be non-trivially sized.
  if (!existsSync(storePath)) fail("store file missing after commit", storePath);
  const size = statSync(storePath).size;
  if (size < 1024) fail("store file too small", size);

  // Round 2: fresh server, no open_session — tags should still be there.
  const round2 = await spawnServer(storePath);
  await round2.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "deep", version: "0" } });
  const tagsRes = await round2.rpc("resources/read", { uri: `hopper://tags?session_id=${lsSession.sessionId}` });
  const tags = JSON.parse(tagsRes.contents[0].text);
  if (!tags[fnAddr]) fail("persisted tag missing after restart", tags);
  if (!tags[fnAddr].includes("persisted") || !tags[fnAddr].includes("round1")) fail("tag content lost", tags[fnAddr]);
  // capabilities.sessions should still see the session.
  const caps = await round2.callTool("capabilities", {});
  if (!Array.isArray(caps?.sessions) || !caps.sessions.length) fail("capabilities.sessions empty after restart", caps);
  await round2.shutdown();
  console.log(`  ✓ store=${size}b tags persisted across restart`);
}

// ─── Phase F-K: single long-running server ───────────────────────────────
console.log("[F-K] mirror tools / preview / DSL / errors / entitlements / objc…");
const server = await spawnServer(storePath);
await server.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "deep", version: "0" } });

try {
  // Re-open ls (round 2 retained data, but re-upload to ensure session.binary is fresh)
  await server.callTool("open_session", { session: lsSession });

  // Calc session for ObjC + entitlements coverage
  const calcSession = await importMachO(CALC, { arch: "arm64e", maxStrings: 1500 });
  calcSession.sessionId = "deep-calc";
  await server.callTool("open_session", { session: calcSession });

  // ─── F: snapshot reads via resources + unified search/procedure ────────
  console.log("  [F] snapshot reads via resources…");
  const sessionInfo = await server.rpc("resources/read", { uri: `hopper://session/current?session_id=${calcSession.sessionId}` });
  const sessionJson = JSON.parse(sessionInfo.contents[0].text);
  const curDoc = sessionJson?.binary?.name;
  if (!curDoc || typeof curDoc !== "string" || !/calculator/i.test(curDoc)) fail("hopper://session/current binary.name wrong", curDoc);

  const cursorRes = await server.rpc("resources/read", { uri: `hopper://cursor?session_id=${calcSession.sessionId}` });
  const cursor = JSON.parse(cursorRes.contents[0].text);
  // cursor.{address,procedure} may legitimately be null on imported sessions
  if (cursor && cursor.address && typeof cursor.address !== "string") fail("cursor.address shape", cursor.address);
  if (cursor && cursor.procedure && typeof cursor.procedure !== "string") fail("cursor.procedure shape", cursor.procedure);

  // hopper://binary/strings — calc has 1500 strings; resource returns an array
  const stringsRes = await server.rpc("resources/read", { uri: `hopper://binary/strings?session_id=${calcSession.sessionId}` });
  const strs = JSON.parse(stringsRes.contents[0].text);
  if (!Array.isArray(strs) || strs.length === 0) fail("hopper://binary/strings empty", strs);

  // hopper://names — addr/name array
  const namesRes = await server.rpc("resources/read", { uri: `hopper://names?session_id=${calcSession.sessionId}` });
  const names = JSON.parse(namesRes.contents[0].text);
  if (!Array.isArray(names)) fail("hopper://names shape", names);

  // hopper://bookmarks — should at least return an array (likely empty for imports)
  const bookmarksRes = await server.rpc("resources/read", { uri: `hopper://bookmarks?session_id=${calcSession.sessionId}` });
  const bookmarks = JSON.parse(bookmarksRes.contents[0].text);
  if (!Array.isArray(bookmarks)) fail("hopper://bookmarks shape", bookmarks);

  // search kind=procedures — find calc procedures by regex
  const sproc = await server.callTool("search", { kind: "procedures", session_id: calcSession.sessionId, pattern: ".*", max_results: 3 });
  if (!sproc) fail("search kind=procedures null", sproc);

  // search kind=names — search the names index
  const sname = await server.callTool("search", { kind: "names", session_id: calcSession.sessionId, pattern: ".*", max_results: 3 });
  if (sname === null || sname === undefined) fail("search kind=names null", sname);

  // resolve(addr) — for a real function entry, returns matches with .item.name
  const calcFn = calcSession.functions[0];
  const resolved = await server.callTool("resolve", { session_id: calcSession.sessionId, query: calcFn.addr });
  if (!Array.isArray(resolved)) fail("resolve shape", resolved);
  console.log(`    ✓ doc="${curDoc}" strings=${strs.length} names=${names.length} resolved=${resolved.length}`);

  // ─── G: preview_transaction ────────────────────────────────────────────
  console.log("  [G] preview_transaction…");
  const txnPreview = await server.callTool("begin_transaction", { session_id: calcSession.sessionId, name: "preview test" });
  await server.callTool("queue", {
    kind: "comment",
    session_id: calcSession.sessionId,
    transaction_id: txnPreview.transactionId,
    addr: calcFn.addr,
    value: "preview-only annotation",
  });
  await server.callTool("queue", {
    kind: "rename",
    session_id: calcSession.sessionId,
    transaction_id: txnPreview.transactionId,
    addr: calcFn.addr,
    value: "preview_renamed_fn",
  });
  const preview = await server.callTool("preview_transaction", {
    session_id: calcSession.sessionId,
    transaction_id: txnPreview.transactionId,
  });
  if (!preview || !Array.isArray(preview.operations)) fail("preview missing operations[]", preview);
  if (preview.operations.length !== 2) fail("preview should show 2 queued ops", preview.operations.length);
  // Preview must NOT mutate underlying state — name should still be the original.
  const infoBefore = await server.callTool("procedure", { field: "info", session_id: calcSession.sessionId, procedure: calcFn.addr });
  if (infoBefore.name === "preview_renamed_fn") fail("preview leaked into state", infoBefore.name);
  // Roll back to clean up
  await server.callTool("rollback_transaction", { session_id: calcSession.sessionId, transaction_id: txnPreview.transactionId });
  console.log(`    ✓ ops=${preview.operations.length} state untouched (still '${infoBefore.name}')`);

  // ─── H: Query DSL composites ───────────────────────────────────────────
  console.log("  [H] query DSL composites…");
  // First make sure capabilities are computed for ls
  await server.callTool("classify_capabilities", { session_id: lsSession.sessionId });
  // Tag a function so we can compose tag + capability queries
  const lsFn = lsSession.functions[0];
  const tagTxn = await server.callTool("begin_transaction", { session_id: lsSession.sessionId, name: "compose tag" });
  await server.callTool("queue", {
    kind: "tag",
    session_id: lsSession.sessionId,
    transaction_id: tagTxn.transactionId,
    addr: lsFn.addr,
    tags: ["composite-test"],
  });
  await server.callTool("commit_transaction", { session_id: lsSession.sessionId, transaction_id: tagTxn.transactionId });

  // Implicit AND: name predicate + tag predicate
  const composite = await server.callTool("query", {
    session_id: lsSession.sessionId,
    expression: `tag:composite-test AND name:${lsFn.name}`,
  });
  if (composite.count !== 1) fail("composite AND should match exactly 1", composite);

  // NOT predicate
  const notQuery = await server.callTool("query", {
    session_id: lsSession.sessionId,
    expression: "NOT tag:composite-test",
  });
  if (notQuery.count !== lsSession.functions.length - 1) fail("NOT count wrong", { got: notQuery.count, expected: lsSession.functions.length - 1 });

  // Parens override precedence: (a OR b) AND c
  const parenQuery = await server.callTool("query", {
    session_id: lsSession.sessionId,
    expression: `(tag:composite-test OR tag:nonexistent) AND name:${lsFn.name}`,
  });
  if (parenQuery.count !== 1) fail("paren composite wrong", parenQuery);

  // Regex literal — match function names matching /sub_/
  const regexQuery = await server.callTool("query", {
    session_id: lsSession.sessionId,
    expression: "/sub_/",
  });
  if (typeof regexQuery.count !== "number") fail("regex query missing count", regexQuery);
  console.log(`    ✓ composite=1 not=${notQuery.count} paren=1 regex=${regexQuery.count}`);

  // ─── I: error paths ────────────────────────────────────────────────────
  console.log("  [I] error paths…");
  // Invalid procedure address
  let threw = false;
  try {
    await server.callTool("procedure", { field: "info", session_id: calcSession.sessionId, procedure: "0xdeadbeefcafe" });
  } catch (e) {
    threw = true;
    if (!/not found|unknown|no procedure|resolve/i.test(e.message)) fail("unexpected procedure error", e.message);
  }
  if (!threw) fail("procedure field=info should throw on bogus addr", "no throw");

  // Empty/whitespace-only query — should either throw or return zero matches, not crash
  const emptyResult = await server.callTool("query", { session_id: lsSession.sessionId, expression: "   " }).catch((e) => ({ thrown: e.message }));
  if (emptyResult && typeof emptyResult.count !== "number" && !emptyResult.thrown) fail("empty query produced unexpected result", emptyResult);

  // Commit non-existent transaction
  let badTxnThrew = false;
  try {
    await server.callTool("commit_transaction", { session_id: lsSession.sessionId, transaction_id: "txn-does-not-exist" });
  } catch (e) {
    badTxnThrew = true;
  }
  if (!badTxnThrew) fail("commit of bogus txn should throw", "no throw");
  console.log(`    ✓ procedure field=info throws on bogus addr, bogus commit throws, empty query handled`);

  // ─── J: entitlements ───────────────────────────────────────────────────
  console.log("  [J] entitlements (Calculator is sandboxed)…");
  const sig = await server.callTool("extract_code_signing", { session_id: calcSession.sessionId, executable_path: CALC });
  if (!sig.entitlements || typeof sig.entitlements !== "object") fail("entitlements missing", sig);
  if (sig.entitlements["com.apple.security.app-sandbox"] !== true) fail("sandbox entitlement missing", sig.entitlements);
  if (!sig.entitlements["com.apple.security.exception.shared-preference.read-only"]) fail("expected shared-preference exception", sig.entitlements);
  console.log(`    ✓ entitlements keys=${Object.keys(sig.entitlements).length} (sandboxed=true)`);

  // ─── K: ObjC parser depth ──────────────────────────────────────────────
  console.log("  [K] ObjC class+method depth…");
  const objc = await server.callTool("extract_objc_runtime", {
    session_id: calcSession.sessionId,
    executable_path: CALC,
    arch: "arm64e",
  });
  if (objc.count < 5) fail("calc objc count low", objc.count);
  // class names must be populated for nearly all classes
  const namedClasses = objc.classes.filter((c) => c.name && c.name.length > 0);
  if (namedClasses.length < 0.8 * objc.count) fail("too many anonymous classes", { named: namedClasses.length, total: objc.count });
  // class names should contain Apple-style mangled or ObjC names
  if (!objc.classes.some((c) => /Calculator|TtC/.test(c.name))) fail("expected Calculator/Swift class names", objc.classes.slice(0, 5).map((c) => c.name));
  // at least one class should have method records (addr+kind populated even if name is null)
  const withMethods = objc.classes.filter((c) => c.methods?.length > 0);
  if (!withMethods.length) fail("no class has methods", objc.classes.length);
  for (const m of withMethods[0].methods) {
    if (!m.kind) fail("method missing kind", m);
    if (m.addr && !/^0x[0-9a-fA-F]+$/.test(m.addr)) fail("method addr malformed", m);
  }
  console.log(`    ✓ classes=${objc.count} named=${namedClasses.length} withMethods=${withMethods.length} sample="${withMethods[0].name?.slice(0, 50)}"`);

  console.log("deep coverage ok");
} finally {
  await server.shutdown();
}

// ─── Helpers ─────────────────────────────────────────────────────────────

async function spawnServer(storePathArg) {
  const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
    stdio: ["pipe", "pipe", "inherit"],
    env: { ...process.env, HOPPER_MCP_STORE: storePathArg },
  });
  const rl = createInterface({ input: child.stdout });
  const responses = new Map();
  rl.on("line", (line) => {
    try {
      const m = JSON.parse(line);
      if (m.id != null) responses.set(m.id, m);
    } catch {}
  });

  let nextId = 0;
  const rpc = async (method, params = {}) => {
    const id = ++nextId;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    for (;;) {
      if (responses.has(id)) {
        const r = responses.get(id);
        responses.delete(id);
        if (r.error) throw new Error(`${method}: ${r.error.message}`);
        return r.result;
      }
      await new Promise((res) => setTimeout(res, 5));
    }
  };

  const callTool = async (name, args = {}) => {
    const out = await rpc("tools/call", { name, arguments: args });
    if (out.isError) throw new Error(`${name}: ${out.content?.[0]?.text ?? "tool error"}`);
    return JSON.parse(out.content[0].text);
  };

  const shutdown = async () => {
    child.stdin.end();
    child.kill();
    await new Promise((r) => child.on("close", r));
  };

  return { child, rpc, callTool, shutdown };
}
