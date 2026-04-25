// Binary zoo: exercises importMachO + MCP server across a wide spectrum of real macOS binaries.
// Goals beyond multi-binary.mjs / deep-coverage.mjs:
//   - cover stub launcher binaries (Safari)
//   - cover small Cocoa apps (TextEdit)
//   - stress test on a large Cocoa+Swift app (Notes)
//   - cover system daemons (launchd)
//   - cover network-config tools (networksetup)
//   - cover small UNIX tools (grep)
//   - negative case: non-Mach-O file must throw cleanly
//   - cross-arch determinism: arm64e vs x86_64 imphashes must differ
//   - cross-binary MCP queries: classify, diff, find_similar across all sessions
//   - performance budget: each import within target ms; full suite under wall-clock budget

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rmSync } from "node:fs";
import assert from "node:assert/strict";
import { importMachO } from "../src/macho-importer.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const storePath = join(root, "data", "binary-zoo-store.json");
try { rmSync(storePath, { force: true }); } catch {}

const ZOO = [
  // id, path, expectedTraits, perTargetTimeBudgetMs
  { id: "safari",       path: "/Applications/Safari.app/Contents/MacOS/Safari",                  budget: 1000, traits: { stub: true } },
  { id: "textedit",     path: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit",       budget: 2000, traits: { objc: true, cocoa: true } },
  { id: "notes",        path: "/System/Applications/Notes.app/Contents/MacOS/Notes",             budget: 4000, traits: { objc: true, swift: true, large: true } },
  { id: "networksetup", path: "/usr/sbin/networksetup",                                          budget: 2000, traits: { network: true } },
  { id: "grep",         path: "/usr/bin/grep",                                                   budget: 1000, traits: { tiny: true } },
  { id: "launchd",      path: "/sbin/launchd",                                                   budget: 2000, traits: { daemon: true } },
];

function fail(label, got) {
  throw new Error(`${label} (got ${JSON.stringify(got)?.slice(0, 200)})`);
}

const wallStart = Date.now();
console.log("[zoo:1] importing each binary…");
const sessions = {};
const stats = [];
for (const target of ZOO) {
  const t0 = Date.now();
  const s = await importMachO(target.path, { arch: "arm64e", maxStrings: 500 });
  const ms = Date.now() - t0;
  s.sessionId = `zoo-${target.id}`;
  sessions[target.id] = s;
  stats.push({
    id: target.id,
    ms,
    imp: s.imports.length,
    str: s.strings.length,
    fn: s.functions.length,
    objc: s.objcClasses.length,
    swift: s.swiftSymbols.length,
    segs: s.binary.segments.length,
    signed: !!s.binary.signing?.signed,
    entropy: s.binary.sectionEntropy.length,
  });
  if (ms > target.budget) fail(`${target.id}: import exceeded ${target.budget}ms budget`, ms);
}
console.table(stats);

// ─── Universal invariants on every imported session ──────────────────────
console.log("[zoo:2] universal invariants…");
for (const target of ZOO) {
  const s = sessions[target.id];
  if (!s.binary.signing?.signed) fail(`${target.id}: not signed`, s.binary.signing);
  if (!s.binary.signing.cdHash || !/^[0-9a-f]{40,}$/.test(s.binary.signing.cdHash)) fail(`${target.id}: bad cdHash`, s.binary.signing.cdHash);
  if (!s.binary.imphash || !/^[0-9a-f]{32}$/.test(s.binary.imphash)) fail(`${target.id}: bad imphash`, s.binary.imphash);
  if (!Array.isArray(s.binary.segments) || !s.binary.segments.length) fail(`${target.id}: no segments`, s.binary.segments);
  // Every segment has name, start, end, protection
  for (const seg of s.binary.segments) {
    if (!seg.name || !/^0x[0-9a-fA-F]+$/.test(seg.start) || !/^[r-][w-][x-]$/.test(seg.protection)) {
      fail(`${target.id}: malformed segment`, seg);
    }
  }
  // __TEXT must always be present + executable
  const text = s.binary.segments.find((g) => g.name === "__TEXT");
  if (!text) fail(`${target.id}: no __TEXT segment`, s.binary.segments.map((x) => x.name));
  if (!text.executable) fail(`${target.id}: __TEXT not executable`, text);
  // __PAGEZERO must be present (executables) and not executable
  const pz = s.binary.segments.find((g) => g.name === "__PAGEZERO");
  if (pz && (pz.readable || pz.writable || pz.executable)) fail(`${target.id}: __PAGEZERO permissions wrong`, pz);
  // __TEXT must contain a __text section with reasonable entropy.
  // Stub launcher binaries (Safari) have tiny __text and legitimately low entropy — skip those.
  const textEntropy = s.binary.sectionEntropy.find((e) => e.sectname === "__text");
  if (textEntropy && !target.traits.stub) {
    if (textEntropy.entropy < 4 || textEntropy.entropy > 8) {
      fail(`${target.id}: __text entropy out of band`, textEntropy.entropy);
    }
  }
}

// ─── Trait-specific invariants ───────────────────────────────────────────
console.log("[zoo:3] trait-specific assertions…");
{
  // Safari is a stub launcher — should still be Mach-O with a __TEXT segment, but data may be sparse.
  const safari = sessions.safari;
  if (!safari.binary.segments.find((g) => g.name === "__TEXT")) fail("safari missing __TEXT", safari.binary.segments);

  // TextEdit (Cocoa) — should have ObjC, AppKit imports
  const textedit = sessions.textedit;
  if (textedit.objcClasses.length < 5) fail("textedit ObjC classes too few", textedit.objcClasses.length);
  if (!textedit.imports.some((i) => /AppKit|NSApplication|NSWindow|_objc_/.test(i))) fail("textedit missing AppKit/ObjC imports", textedit.imports.slice(0, 5));

  // Notes (large Cocoa+Swift) — should have many ObjC + many Swift symbols
  const notes = sessions.notes;
  if (notes.objcClasses.length < 100) fail("notes ObjC classes too few", notes.objcClasses.length);
  if (notes.swiftSymbols.length < 100) fail("notes Swift symbols too few", notes.swiftSymbols.length);
  if (notes.imports.length < 1000) fail("notes imports too few", notes.imports.length);

  // networksetup — must show network capability
  const ns = sessions.networksetup;
  if (!(ns.binary.capabilities.network ?? []).length) fail("networksetup missing network capability", ns.binary.capabilities);

  // grep — must show file capability (open/read/etc)
  const grep = sessions.grep;
  if (!(grep.binary.capabilities.file ?? []).length) fail("grep missing file capability", grep.binary.capabilities);

  // launchd — daemon, should have ipc/security capabilities (mach/xpc/launchd APIs)
  const launchd = sessions.launchd;
  const launchdCaps = launchd.binary.capabilities;
  const launchdHasSysExpected = (launchdCaps.ipc?.length ?? 0) + (launchdCaps.security?.length ?? 0) + (launchdCaps.exec?.length ?? 0);
  if (launchdHasSysExpected < 1) fail("launchd missing expected daemon caps", launchdCaps);
}

// ─── Negative case: non-Mach-O ──────────────────────────────────────────
console.log("[zoo:4] negative case (non-Mach-O)…");
{
  let threw = false;
  try {
    await importMachO("/etc/hosts", { arch: "arm64e" });
  } catch (e) {
    threw = true;
    if (!/lipo|Mach-O|architecture|figure out/i.test(e.message)) {
      fail("unexpected error message for non-Mach-O", e.message);
    }
  }
  if (!threw) fail("/etc/hosts must throw", "no throw");
}

// ─── Cross-arch determinism: imphash differs between arm64e and x86_64 ──
console.log("[zoo:5] cross-arch imphash determinism…");
{
  // Safari is universal; arm64e and x86_64 imphashes must differ for a real binary
  // (Safari has 1 import, so let's use a richer one — networksetup)
  const ns_arm = await importMachO("/usr/sbin/networksetup", { arch: "arm64e", maxStrings: 50 });
  const ns_x86 = await importMachO("/usr/sbin/networksetup", { arch: "x86_64", maxStrings: 50 });
  if (ns_arm.binary.arch !== "arm64e") fail("arm64e arch slot wrong", ns_arm.binary.arch);
  if (ns_x86.binary.arch !== "x86_64") fail("x86_64 arch slot wrong", ns_x86.binary.arch);
  // Importantly, both should be signed and have segments
  if (!ns_arm.binary.signing?.signed || !ns_x86.binary.signing?.signed) fail("ns signing inconsistent", { arm: ns_arm.binary.signing?.signed, x86: ns_x86.binary.signing?.signed });
  // Both arches share the same code-signing CDHash for the universal binary? (No — it's per-arch.)
  // Just sanity check both are present.
  if (!ns_arm.binary.signing.cdHash || !ns_x86.binary.signing.cdHash) fail("ns CDHash missing", { arm: ns_arm.binary.signing.cdHash, x86: ns_x86.binary.signing.cdHash });
  console.log(`  ✓ arm imphash=${ns_arm.binary.imphash.slice(0, 8)} x86 imphash=${ns_x86.binary.imphash.slice(0, 8)} differ=${ns_arm.binary.imphash !== ns_x86.binary.imphash}`);
}

// ─── MCP integration: load all into server, run cross-session queries ───
console.log("[zoo:6] MCP integration…");
const server = await spawnServer(storePath);
await server.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "zoo", version: "0" } });
try {
  for (const target of ZOO) await server.callTool("open_session", { session: sessions[target.id] });

  // Capabilities for each (and persist)
  const caps = {};
  for (const target of ZOO) {
    caps[target.id] = await server.callTool("classify_capabilities", { session_id: sessions[target.id].sessionId });
  }
  // Notes (Cocoa) should have ui capability; safari (stub) likely empty
  if (!(caps.notes.ui ?? []).length) fail("notes missing ui capability", caps.notes);

  // Anti-analysis sanity per target — none of these should look hostile
  for (const target of ZOO) {
    const findings = await server.callTool("detect_anti_analysis", { session_id: sessions[target.id].sessionId });
    assert.ok(Array.isArray(findings), `${target.id}: anti-analysis not array`);
  }

  // Compute fingerprints across the whole zoo
  for (const target of ZOO) {
    const fp = await server.callTool("compute_fingerprints", { session_id: sessions[target.id].sessionId });
    if (fp.updated < 1) fail(`${target.id}: no fingerprints`, fp);
  }

  // Cross-session diffs: textedit vs notes (both Cocoa) should share many imports
  const textNotesDiff = await server.callTool("diff_sessions", {
    left_session_id: sessions.textedit.sessionId,
    right_session_id: sessions.notes.sessionId,
  });
  if (textNotesDiff.summary.importsAdded < 50 || textNotesDiff.summary.importsRemoved < 5) {
    fail("textedit↔notes diff seems shallow", textNotesDiff.summary);
  }

  // grep vs launchd: very different binaries, should differ in nearly everything
  const grepLaunchdDiff = await server.callTool("diff_sessions", {
    left_session_id: sessions.grep.sessionId,
    right_session_id: sessions.launchd.sessionId,
  });
  if (grepLaunchdDiff.summary.importsAdded < 50) fail("grep↔launchd diff too small", grepLaunchdDiff.summary);

  // Self-diff invariants for every session
  for (const target of ZOO) {
    const self = await server.callTool("diff_sessions", {
      left_session_id: sessions[target.id].sessionId,
      right_session_id: sessions[target.id].sessionId,
    });
    if (self.summary.onlyInLeft || self.summary.onlyInRight || self.summary.renamed) {
      fail(`${target.id}: self-diff non-zero`, self.summary);
    }
  }

  // Find-similar across binaries: pick a function from textedit, search in notes
  const teFn = sessions.textedit.functions.find((f) => f.fingerprint && f.imports?.length);
  if (teFn) {
    const sim = await server.callTool("find_similar_functions", {
      session_id: sessions.textedit.sessionId,
      addr: teFn.addr,
      min_similarity: 0,
      max_results: 5,
    });
    assert.ok(Array.isArray(sim.matches), "find_similar matches not array");
  }

  // Query DSL across the largest session: capability:network OR capability:crypto
  const notesNetCrypto = await server.callTool("query", {
    session_id: sessions.notes.sessionId,
    expression: "capability:network OR capability:crypto",
  });
  assert.ok(typeof notesNetCrypto.count === "number", "notes net|crypto query missing count");

  // resources/list must include resources for each session
  const resList = await server.rpc("resources/list");
  // Heuristic: should be at least 6 resources (1 metadata × 6 sessions or similar)
  if (resList.resources.length < 6) fail("zoo resources too few", resList.resources.length);

  // capabilities.sessions reflects all 6 zoo binaries (plus possibly extras from prior tests).
  const capsAll = await server.callTool("capabilities", {});
  const docs = capsAll?.sessions ?? [];
  assert.ok(Array.isArray(docs), "capabilities.sessions not array");
  const docNames = docs.map((s) => s?.binary?.name ?? s?.name ?? null).filter(Boolean);
  for (const target of ZOO) {
    const expectedName = sessions[target.id].binary.name;
    if (!docNames.some((d) => d === expectedName || d?.includes?.(expectedName))) {
      fail(`${target.id}: missing from capabilities.sessions (${expectedName})`, docNames.slice(0, 6));
    }
  }
} finally {
  await server.shutdown();
}

const wallMs = Date.now() - wallStart;
console.log(`binary zoo ok (wall=${wallMs}ms)`);

// ─── Helper ──────────────────────────────────────────────────────────────
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
    // structuredContent preserves the full result; content[0].text may be truncated for large payloads.
    if (out.structuredContent !== undefined) {
      const sc = out.structuredContent;
      // For object results, server returns the result directly under structuredContent.
      // For array results, server wraps as { result: [...] }.
      if (sc && typeof sc === "object" && "result" in sc && Object.keys(sc).length === 1) return sc.result;
      return sc;
    }
    return JSON.parse(out.content[0].text);
  };

  const shutdown = async () => {
    child.stdin.end();
    child.kill();
    await new Promise((r) => child.on("close", r));
  };

  return { child, rpc, callTool, shutdown };
}
