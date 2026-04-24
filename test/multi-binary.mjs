// Multi-binary regression: exercises every existing + new tool against three real Mach-O targets.
// Targets:
//   - /bin/ls                                  (small universal)
//   - /usr/bin/codesign                        (crypto/security/network-heavy universal)
//   - /System/Applications/Calculator.app/...  (Cocoa + ObjC + Swift)

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rmSync } from "node:fs";
import assert from "node:assert/strict";
import { importMachO } from "../src/macho-importer.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const storePath = join(root, "data", "multi-binary-store.json");
try { rmSync(storePath, { force: true }); } catch {}

const TARGETS = [
  { id: "ls",       path: "/bin/ls",                                                            arch: "arm64e" },
  { id: "codesign", path: "/usr/bin/codesign",                                                  arch: "arm64e" },
  { id: "calc",     path: "/System/Applications/Calculator.app/Contents/MacOS/Calculator",      arch: "arm64e" },
];

function fail(label, got) {
  throw new Error(`${label} (got ${JSON.stringify(got)?.slice(0, 200)})`);
}

// ─── Phase 1: importMachO smoke against three real binaries ───────────────
console.log("[phase 1] importing real binaries…");
const sessions = {};
for (const target of TARGETS) {
  const t0 = Date.now();
  const session = await importMachO(target.path, { arch: target.arch, maxStrings: 1500 });
  session.sessionId = `multi-${target.id}`;
  sessions[target.id] = session;
  console.log(`  ${target.id} (${target.arch}): ${Date.now() - t0}ms`,
    `imports=${session.imports.length}`,
    `strings=${session.strings.length}`,
    `fns=${session.functions.length}`,
    `objc=${session.objcClasses.length}`,
    `signed=${!!session.binary.signing?.signed}`,
    `entropySections=${session.binary.sectionEntropy.length}`,
    `imphash=${session.binary.imphash?.slice(0, 8)}…`);
}

// All three should import non-empty data
for (const target of TARGETS) {
  const s = sessions[target.id];
  if (!s.imports.length) fail(`${target.id}: no imports`, s.imports.length);
  if (!s.strings.length) fail(`${target.id}: no strings`, s.strings.length);
  if (!Array.isArray(s.binary.sectionEntropy) || !s.binary.sectionEntropy.length) fail(`${target.id}: no entropy`, s.binary.sectionEntropy);
  if (!s.binary.signing) fail(`${target.id}: no signing block`, s.binary.signing);
  if (!s.binary.imphash || !/^[0-9a-f]{32}$/.test(s.binary.imphash)) fail(`${target.id}: bad imphash`, s.binary.imphash);
}

// codesign should expose crypto + security + network capabilities (it talks to TLS, hashes, keychain)
if (!(sessions.codesign.binary.capabilities.crypto ?? []).length) fail("codesign missing crypto capability", sessions.codesign.binary.capabilities);
if (!(sessions.codesign.binary.capabilities.security ?? []).length) fail("codesign missing security capability", sessions.codesign.binary.capabilities);
if (!(sessions.codesign.binary.capabilities.network ?? []).length) fail("codesign missing network capability", sessions.codesign.binary.capabilities);

// Calculator should expose ui + objc capabilities and at least 5 ObjC classes
if (!(sessions.calc.binary.capabilities.ui ?? []).length) fail("calc missing ui capability", sessions.calc.binary.capabilities);
if (!(sessions.calc.binary.capabilities.objc ?? []).length) fail("calc missing objc capability", sessions.calc.binary.capabilities);
if (sessions.calc.objcClasses.length < 5) fail("calc has too few ObjC classes", sessions.calc.objcClasses.length);

// All three binaries are Apple-signed
for (const target of TARGETS) {
  const sig = sessions[target.id].binary.signing;
  if (!sig.signed) fail(`${target.id}: signing.signed=false`, sig);
  if (!sig.signer || !/Apple|Software Signing/i.test(sig.signer)) fail(`${target.id}: unexpected signer`, sig.signer);
}

// Each should have a __TEXT,__text section in entropy with reasonable entropy (4.5–7.5 for compiled code)
for (const target of TARGETS) {
  const text = sessions[target.id].binary.sectionEntropy.find((s) => s.sectname === "__text");
  if (!text) fail(`${target.id}: no __text section in entropy`, sessions[target.id].binary.sectionEntropy.map((s) => s.sectname));
  if (text.entropy < 4 || text.entropy > 8) fail(`${target.id}: __text entropy out of range`, text.entropy);
}

// ─── Phase 2: bring up MCP server ────────────────────────────────────────
console.log("[phase 2] launching MCP server…");
const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: storePath },
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
async function rpc(method, params = {}) {
  const id = ++nextId;
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  for (;;) {
    if (responses.has(id)) {
      const r = responses.get(id);
      responses.delete(id);
      if (r.error) throw new Error(`${method}: ${r.error.message}`);
      return r.result;
    }
    await new Promise((r) => setTimeout(r, 5));
  }
}

const callTool = async (name, args = {}) => {
  const out = await rpc("tools/call", { name, arguments: args });
  return JSON.parse(out.content[0].text);
};

try {
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "multi-binary", version: "0.1.0" } });

  // Open all three sessions (server keeps last as 'current')
  for (const target of TARGETS) {
    await callTool("open_session", { session: sessions[target.id] });
  }

  // ─── Phase 3: existing tools regression on each binary ─────────────────
  console.log("[phase 3] existing tools regression…");
  for (const target of TARGETS) {
    const sid = sessions[target.id].sessionId;

    // Re-open to make this session current (resources/read uses current).
    await callTool("open_session", { session: sessions[target.id] });

    const meta = await rpc("resources/read", { uri: "hopper://binary/metadata" });
    if (!meta.contents[0].text.includes(target.path) && !meta.contents[0].text.includes(sessions[target.id].binary.name)) {
      fail(`${target.id}: metadata missing binary identity`, meta.contents[0].text.slice(0, 500));
    }

    const list = await rpc("resources/list");
    if (!list.resources.some((r) => r.uri.includes("binary/metadata"))) fail("missing metadata resource", list.resources.length);
    if (!list.resources.some((r) => r.uri.includes("binary/capabilities"))) fail("missing capabilities resource", list.resources.length);

    const segs = await callTool("list_segments", { session_id: sid });
    if (!Array.isArray(segs) || !segs.length) fail(`${target.id}: list_segments empty`, segs);

    const procs = await callTool("list_procedures", { session_id: sid, max_results: 5 });
    assert.ok(procs && typeof procs === "object", `${target.id}: list_procedures must return object`);
    assert.ok(Object.keys(procs).length >= 1, `${target.id}: list_procedures returned no entries`);

    // Use a target-specific narrow regex so the result fits within toolResult's text cap.
    const stringsProbe = target.id === "codesign" ? "Apple"
      : target.id === "calc" ? "scientific"
      : "usage";
    const stringsHit = await callTool("search_strings", { session_id: sid, regex: stringsProbe, max_results: 3 });
    assert.ok(Array.isArray(stringsHit), `${target.id}: search_strings must return array (got ${typeof stringsHit})`);
    if (!stringsHit.length) fail(`${target.id}: search_strings(${stringsProbe}) returned no hits`, stringsHit);

    // resolve a known-good import per target
    const probe = target.id === "codesign" ? "_Sec"
      : target.id === "calc" ? "NSWindow"
      : "_open";
    const resolved = await callTool("resolve", { session_id: sid, query: probe });
    assert.ok(resolved, `${target.id}: resolve returned nothing`);

    // analyze_function_deep on the first function
    const fn = sessions[target.id].functions[0];
    if (fn) {
      const deep = await callTool("analyze_function_deep", { session_id: sid, addr: fn.addr });
      assert.ok(deep.evidenceAnchors || deep.evidence_anchors || JSON.stringify(deep).includes("evidence"),
        `${target.id}: analyze_function_deep missing evidence`);
    }
  }

  // ─── Phase 4: classify_capabilities — runtime, not just import ─────────
  console.log("[phase 4] classify_capabilities…");
  const lsCaps = await callTool("classify_capabilities", { session_id: sessions.ls.sessionId });
  if (!(lsCaps.file ?? []).length) fail("ls missing file capability", lsCaps);

  const codesignCaps = await callTool("classify_capabilities", { session_id: sessions.codesign.sessionId });
  if (!(codesignCaps.network ?? []).length) fail("codesign missing network capability", codesignCaps);
  if (!(codesignCaps.crypto ?? []).length) fail("codesign missing crypto capability", codesignCaps);
  if (!(codesignCaps.security ?? []).length) fail("codesign missing security capability", codesignCaps);

  const calcCaps = await callTool("classify_capabilities", { session_id: sessions.calc.sessionId });
  if (!(calcCaps.ui ?? []).length) fail("calc missing ui capability", calcCaps);

  // ─── Phase 5: detect_anti_analysis ─────────────────────────────────────
  console.log("[phase 5] detect_anti_analysis…");
  for (const target of TARGETS) {
    const findings = await callTool("detect_anti_analysis", { session_id: sessions[target.id].sessionId });
    assert.ok(Array.isArray(findings), `${target.id}: anti-analysis findings not array`);
    // codesign uses _isatty → exit_on_isatty finding; ls/calc usually clean. Just assert array shape.
  }

  // ─── Phase 6: extract_code_signing (live invocation, not cached) ───────
  console.log("[phase 6] extract_code_signing…");
  for (const target of TARGETS) {
    const sig = await callTool("extract_code_signing", { session_id: sessions[target.id].sessionId, executable_path: target.path });
    if (!sig.signed) fail(`${target.id}: live signing.signed=false`, sig);
    if (!sig.signer || !/Apple|Software Signing/i.test(sig.signer)) fail(`${target.id}: live unexpected signer`, sig.signer);
  }

  // ─── Phase 7: compute_section_entropy (live) ───────────────────────────
  console.log("[phase 7] compute_section_entropy…");
  const lsEntropy = await callTool("compute_section_entropy", {
    session_id: sessions.ls.sessionId,
    executable_path: "/bin/ls",
    arch: "arm64e",
  });
  if (!lsEntropy.length) fail("ls entropy empty", lsEntropy);
  const lsText = lsEntropy.find((s) => s.sectname === "__text");
  if (!lsText) fail("ls missing __text in entropy", lsEntropy.map((s) => s.sectname));
  if (lsText.entropy < 4 || lsText.entropy > 8) fail("ls __text entropy out of band", lsText.entropy);

  // ─── Phase 8: extract_objc_runtime (live) ──────────────────────────────
  console.log("[phase 8] extract_objc_runtime…");
  const calcObjC = await callTool("extract_objc_runtime", {
    session_id: sessions.calc.sessionId,
    executable_path: TARGETS[2].path,
    arch: "arm64e",
  });
  if (calcObjC.count < 5) fail("calc ObjC class count low", calcObjC.count);
  if (!calcObjC.classes.some((c) => c.name && c.name.length > 0)) fail("calc ObjC classes missing names", calcObjC.classes.slice(0, 3));
  console.log(`  calc ObjC classes via tool: ${calcObjC.count}`);

  // ─── Phase 9: compute_fingerprints + find_similar_functions ────────────
  console.log("[phase 9] fingerprints + similarity…");
  for (const target of TARGETS) {
    const fp = await callTool("compute_fingerprints", { session_id: sessions[target.id].sessionId });
    assert.ok(fp.updated >= 1, `${target.id}: compute_fingerprints didn't update any`);
  }
  // Pick a function from codesign, find similar across all sessions
  const codesignFn = sessions.codesign.functions[0];
  if (!codesignFn) throw new Error("codesign session has no functions");
  const sim = await callTool("find_similar_functions", {
    session_id: sessions.codesign.sessionId,
    addr: codesignFn.addr,
    min_similarity: 0,
    max_results: 5,
  });
  assert.ok(sim.target?.fingerprint, "find_similar_functions missing target fingerprint");
  assert.ok(Array.isArray(sim.matches), "find_similar_functions matches not array");

  // ─── Phase 10: diff_sessions across two real binaries ──────────────────
  console.log("[phase 10] diff_sessions…");
  const diff = await callTool("diff_sessions", {
    left_session_id: sessions.ls.sessionId,
    right_session_id: sessions.codesign.sessionId,
  });
  assert.ok(diff.summary.importsAdded > 10 || diff.summary.importsRemoved > 10,
    `diff_sessions ls↔codesign should show import differences (${JSON.stringify(diff.summary)})`);

  // diff a session against itself = no changes
  const diffSelf = await callTool("diff_sessions", {
    left_session_id: sessions.codesign.sessionId,
    right_session_id: sessions.codesign.sessionId,
  });
  assert.equal(diffSelf.summary.onlyInLeft, 0, "self-diff onlyInLeft != 0");
  assert.equal(diffSelf.summary.onlyInRight, 0, "self-diff onlyInRight != 0");

  // ─── Phase 11: query DSL on real data ──────────────────────────────────
  console.log("[phase 11] query DSL…");
  const cryptoQuery = await callTool("query", {
    session_id: sessions.codesign.sessionId,
    expression: "imports:_CC_",
  });
  // codesign uses CommonCrypto (CC_*) — ensure query DSL evaluates without error
  assert.ok(typeof cryptoQuery.count === "number", "codesign crypto query missing count");

  const capQuery = await callTool("query", {
    session_id: sessions.codesign.sessionId,
    expression: "capability:network",
  });
  assert.ok(typeof capQuery.count === "number", "codesign capability query missing count");

  const orQuery = await callTool("query", {
    session_id: sessions.codesign.sessionId,
    expression: "capability:network OR capability:crypto",
  });
  assert.ok(orQuery.count >= capQuery.count, "OR query should be a superset");

  // ─── Phase 12: tagging through transactions ────────────────────────────
  console.log("[phase 12] tags via transactions…");
  const txnTags = await callTool("begin_transaction", {
    session_id: sessions.codesign.sessionId,
    name: "tag networking funcs",
    rationale: "Validate tagging end-to-end.",
  });
  await callTool("queue_tag", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnTags.transactionId,
    addr: codesignFn.addr,
    tags: ["network", "investigate"],
  });
  const tagCommit = await callTool("commit_transaction", { session_id: sessions.codesign.sessionId, transaction_id: txnTags.transactionId });
  assert.equal(tagCommit.status, "committed");
  const tags = await callTool("list_tags", { session_id: sessions.codesign.sessionId });
  assert.deepEqual(tags[codesignFn.addr]?.sort(), ["investigate", "network"]);

  // Untag one tag
  const txnUntag = await callTool("begin_transaction", { session_id: sessions.codesign.sessionId, name: "remove investigate tag" });
  await callTool("queue_untag", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnUntag.transactionId,
    addr: codesignFn.addr,
    tags: ["investigate"],
  });
  await callTool("commit_transaction", { session_id: sessions.codesign.sessionId, transaction_id: txnUntag.transactionId });
  const tags2 = await callTool("list_tags", { session_id: sessions.codesign.sessionId });
  assert.deepEqual(tags2[codesignFn.addr], ["network"]);

  // ─── Phase 13: hypothesis lifecycle ────────────────────────────────────
  console.log("[phase 13] hypotheses…");
  const txnHyp = await callTool("begin_transaction", { session_id: sessions.codesign.sessionId, name: "tls hypothesis" });
  const hypResult = await callTool("create_hypothesis", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnHyp.transactionId,
    topic: "TLS path",
    claim: "codesign uses CommonCrypto for hashing + Security framework for keychain.",
  });
  const hypothesisId = hypResult.operations.find((op) => op.kind === "hypothesis_create").hypothesisId;
  await callTool("link_evidence", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnHyp.transactionId,
    hypothesis_id: hypothesisId,
    addr: codesignFn.addr,
    evidence: "_CC_SHA256 import found",
  });
  await callTool("set_hypothesis_status", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnHyp.transactionId,
    hypothesis_id: hypothesisId,
    status: "supported",
  });
  await callTool("commit_transaction", { session_id: sessions.codesign.sessionId, transaction_id: txnHyp.transactionId });
  const hyps = await callTool("list_hypotheses", { session_id: sessions.codesign.sessionId });
  assert.equal(hyps.length, 1, "expected 1 hypothesis");
  assert.equal(hyps[0].status, "supported");
  assert.equal(hyps[0].evidence.length, 1);

  // Filter by status
  const supported = await callTool("list_hypotheses", { session_id: sessions.codesign.sessionId, status: "supported" });
  assert.equal(supported.length, 1);
  const refuted = await callTool("list_hypotheses", { session_id: sessions.codesign.sessionId, status: "refuted" });
  assert.equal(refuted.length, 0);

  // ─── Phase 14: queue_rename_batch + rollback ───────────────────────────
  console.log("[phase 14] rename_batch + rollback…");
  const calcFns = sessions.calc.functions.slice(0, 2);
  if (calcFns.length >= 2) {
    const txnRen = await callTool("begin_transaction", { session_id: sessions.calc.sessionId, name: "batch rename" });
    await callTool("queue_rename_batch", {
      session_id: sessions.calc.sessionId,
      transaction_id: txnRen.transactionId,
      mapping: {
        [calcFns[0].addr]: "calc_entry_a",
        [calcFns[1].addr]: "calc_entry_b",
      },
      rationale: "Probe batch rename.",
    });
    const commit = await callTool("commit_transaction", { session_id: sessions.calc.sessionId, transaction_id: txnRen.transactionId });
    assert.equal(commit.status, "committed");
    // Verify via procedure_info (accepts session_id).
    const infoA = await callTool("procedure_info", { session_id: sessions.calc.sessionId, procedure: calcFns[0].addr });
    assert.equal(infoA.name, "calc_entry_a", `batch rename A not applied (got ${infoA.name})`);
    const infoB = await callTool("procedure_info", { session_id: sessions.calc.sessionId, procedure: calcFns[1].addr });
    assert.equal(infoB.name, "calc_entry_b", `batch rename B not applied (got ${infoB.name})`);

    // Re-upload the same session — merge logic must preserve user renames.
    await callTool("open_session", { session: sessions.calc });
    const reInfoA = await callTool("procedure_info", { session_id: sessions.calc.sessionId, procedure: calcFns[0].addr });
    assert.equal(reInfoA.name, "calc_entry_a", `rename clobbered on re-upload (got ${reInfoA.name})`);
  }

  // Rollback path
  const txnRoll = await callTool("begin_transaction", { session_id: sessions.codesign.sessionId, name: "rollback test" });
  await callTool("queue_comment", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnRoll.transactionId,
    addr: codesignFn.addr,
    comment: "should be rolled back",
  });
  const rb = await callTool("rollback_transaction", { session_id: sessions.codesign.sessionId, transaction_id: txnRoll.transactionId });
  assert.equal(rb.status, "rolled_back");

  // ─── Phase 15: comment + inline_comment + type_patch ───────────────────
  console.log("[phase 15] comment / inline_comment / type_patch…");
  const txnAll = await callTool("begin_transaction", { session_id: sessions.codesign.sessionId, name: "annotation suite" });
  await callTool("queue_comment", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnAll.transactionId,
    addr: codesignFn.addr,
    comment: "function-level annotation",
  });
  await callTool("queue_inline_comment", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnAll.transactionId,
    addr: codesignFn.addr,
    comment: "inline annotation",
  });
  await callTool("queue_type_patch", {
    session_id: sessions.codesign.sessionId,
    transaction_id: txnAll.transactionId,
    addr: codesignFn.addr,
    type: "int (*)(const char *)",
  });
  const commitAll = await callTool("commit_transaction", { session_id: sessions.codesign.sessionId, transaction_id: txnAll.transactionId });
  assert.equal(commitAll.status, "committed");
  assert.equal(commitAll.operations.length, 3);

  console.log("multi-binary regression ok");
} finally {
  child.stdin.end();
  child.kill();
}
