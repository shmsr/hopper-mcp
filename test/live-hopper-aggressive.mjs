// Aggressive live-Hopper integration test.
//
// Exercises the live ingest path against multiple real binaries — opens
// each one inside Hopper.app, then drives the official mirror tools
// against the freshly analyzed document. Designed to surface bugs that
// only appear when Hopper actually re-analyzes a target, switches
// documents, or fields concurrent queries.
//
// Skip with HOPPER_LIVE_SKIP=1 if Hopper is unavailable.
// Override the binary set with HOPPER_LIVE_TARGETS="/path/a:/path/b".

import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, basename, join } from "node:path";
import { rm } from "node:fs/promises";
import assert from "node:assert/strict";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

if (process.env.HOPPER_LIVE_SKIP === "1") {
  console.log("aggressive live-hopper test skipped (HOPPER_LIVE_SKIP=1)");
  process.exit(0);
}

const targets = (process.env.HOPPER_LIVE_TARGETS
  ? process.env.HOPPER_LIVE_TARGETS.split(":").filter(Boolean)
  : ["/bin/ls", "/usr/bin/file", "/usr/bin/grep"]);

if (targets.length < 2) {
  throw new Error("aggressive live-hopper test requires at least two binaries");
}

const ingestTimeoutMs = Number(process.env.HOPPER_LIVE_AGGR_INGEST_TIMEOUT_MS ?? 180000);
const callTimeoutMs = Number(process.env.HOPPER_LIVE_AGGR_CALL_TIMEOUT_MS ?? 60000);
const storePath = join(root, "data", "live-aggressive-store.json");
await rm(storePath, { force: true });

const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: storePath },
});

const responses = new Map();
const rl = createInterface({ input: child.stdout });
rl.on("line", (line) => {
  if (!line.trim()) return;
  try {
    const message = JSON.parse(line);
    if (Object.hasOwn(message, "id")) responses.set(message.id, message);
  } catch {
    // server may emit log lines on stdout in unusual modes — ignore
  }
});

let nextId = 0;
async function rpc(method, params = {}, { timeoutMs = callTimeoutMs } = {}) {
  const id = ++nextId;
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (responses.has(id)) {
      const response = responses.get(id);
      responses.delete(id);
      if (response.error) throw new Error(response.error.message);
      return response.result ?? {};
    }
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${method} (id=${id}) after ${timeoutMs}ms.`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

function payload(result, { allowError = false } = {}) {
  if (result.isError) {
    if (allowError) return result.content?.[0]?.text ?? null;
    throw new Error(result.content?.[0]?.text ?? "tool call failed");
  }
  if (result.structuredContent !== undefined) {
    const sc = result.structuredContent;
    if (sc && typeof sc === "object" && "result" in sc && Object.keys(sc).length === 1) return sc.result;
    return sc;
  }
  if (!result.content?.length) return null;
  const text = result.content[0].text;
  try { return JSON.parse(text); }
  catch { return text; }
}

async function callTool(name, args = {}, opts = {}) {
  return payload(await rpc("tools/call", { name, arguments: args }, opts), opts);
}

function normalizeAddr(value) {
  if (value == null) return null;
  if (typeof value === "number" && Number.isFinite(value)) return `0x${value.toString(16)}`;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^0x[0-9a-f]+$/i.test(trimmed)) return trimmed.toLowerCase();
    if (/^[0-9]+$/.test(trimmed)) return `0x${Number(trimmed).toString(16)}`;
    if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length >= 4) return `0x${trimmed.toLowerCase()}`;
  }
  return null;
}

function summarizeProcedures(index) {
  if (!index || typeof index !== "object") return [];
  if (Array.isArray(index)) {
    return index.map((entry) => {
      if (typeof entry === "string") return { name: entry, addr: normalizeAddr(entry) };
      if (entry && typeof entry === "object") return { name: entry.name ?? entry.label ?? null, addr: normalizeAddr(entry.addr ?? entry.address ?? entry.entry_point) };
      return { name: null, addr: null };
    }).filter((e) => e.addr);
  }
  return Object.entries(index).map(([key, value]) => {
    if (typeof value === "string" || typeof value === "number") {
      const asAddr = normalizeAddr(value);
      if (asAddr) return { name: key, addr: asAddr };
      const keyAddr = normalizeAddr(key);
      if (keyAddr) return { name: typeof value === "string" ? value : key, addr: keyAddr };
      return { name: key, addr: null };
    }
    if (value && typeof value === "object") {
      return { name: value.name ?? key, addr: normalizeAddr(value.addr ?? value.address ?? value.entry_point ?? key) };
    }
    return { name: key, addr: normalizeAddr(key) };
  }).filter((e) => e.addr);
}

function pickProcedureSamples(procs, count) {
  return procs.slice(0, count);
}

const launches = [];
const sessionsByTarget = new Map();

try {
  console.log(`[init] launching MCP server, store=${storePath}`);
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "live-aggr", version: "0.1.0" } });

  console.log("[A] capability + official tool list…");
  const caps = await callTool("capabilities", {});
  assert.equal(caps.adapter.liveIngest, true, "capabilities should report liveIngest");
  const officialTools = await callTool("official_hopper_tools", {});
  assert.ok(Array.isArray(officialTools) && officialTools.length >= 5, `expected >=5 official tools, got ${officialTools?.length}`);
  const officialToolNames = new Set(officialTools.map((t) => t.name));
  for (const required of ["current_document", "list_documents", "list_procedures", "list_segments"]) {
    assert.ok(officialToolNames.has(required), `official backend missing ${required}`);
  }
  console.log(`  ✓ ${officialTools.length} official tools, including ${[...officialToolNames].slice(0, 6).join(", ")}…`);

  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const tag = basename(target);
    console.log(`[B${i + 1}] ingest_live_hopper ${tag} (open in Hopper)…`);
    const t0 = Date.now();
    const ingested = await callTool("ingest_live_hopper", {
      executable_path: target,
      timeout_ms: ingestTimeoutMs,
      analysis: true,
      parse_objective_c: false,
      parse_swift: false,
      max_functions: 60,
      max_strings: 200,
    }, { timeoutMs: ingestTimeoutMs + 30000 });
    const elapsed = Date.now() - t0;
    assert.ok(ingested.session?.sessionId, `${tag}: ingest missing sessionId`);
    assert.ok(ingested.session.counts?.functions > 0, `${tag}: zero functions`);
    assert.ok(ingested.session.capabilities?.liveExport, `${tag}: missing liveExport metadata`);
    sessionsByTarget.set(target, ingested.session);
    launches.push({ target, mode: ingested.launch?.mode, skipped: Boolean(ingested.launch?.skipped), elapsed });
    console.log(`  ✓ ${tag} session=${ingested.session.sessionId.slice(0, 24)} fns=${ingested.session.counts.functions} strings=${ingested.session.counts.strings} elapsed=${elapsed}ms launch=${ingested.launch?.mode ?? "?"} skipped=${Boolean(ingested.launch?.skipped)}`);

    console.log(`  [B${i + 1}.tools] live mirror queries on ${tag}…`);
    const docName = await callTool("current_document", {});
    assert.equal(typeof docName, "string", `${tag}: current_document not a string`);
    assert.equal(docName, tag, `${tag}: current_document=${docName} did not switch to active target`);

    const segments = await callTool("list_segments", {});
    assert.ok(segments && (Array.isArray(segments) || typeof segments === "object"), `${tag}: list_segments shape wrong`);

    const procIndex = await callTool("list_procedures", { max_results: 20 });
    const procs = summarizeProcedures(procIndex);
    if (!procs.length) {
      const sample = JSON.stringify(procIndex).slice(0, 400);
      throw new Error(`${tag}: list_procedures returned 0 usable entries; raw sample=${sample}`);
    }
    console.log(`    list_procedures=${procs.length} list_segments=${Array.isArray(segments) ? segments.length : Object.keys(segments).length}`);

    const samples = pickProcedureSamples(procs, 4);
    assert.ok(samples.length >= 1, `${tag}: no usable procedure samples`);

    console.log(`    drilling ${samples.length} procedures (info/assembly/callers/callees)…`);
    for (const sample of samples) {
      const info = await callTool("procedure_info", { procedure: sample.addr });
      assert.ok(info && typeof info === "object", `${tag}: procedure_info empty for ${sample.addr}`);
      const asm = await callTool("procedure_assembly", { procedure: sample.addr });
      assert.ok(asm, `${tag}: procedure_assembly empty for ${sample.addr}`);
      const callers = await callTool("procedure_callers", { procedure: sample.addr });
      const callees = await callTool("procedure_callees", { procedure: sample.addr });
      assert.ok(callers !== undefined && callees !== undefined, `${tag}: callers/callees undefined for ${sample.addr}`);
    }

    console.log(`    parallel procedure_info×${samples.length}…`);
    const parallel = await Promise.all(samples.map((s) => callTool("procedure_info", { procedure: s.addr })));
    assert.equal(parallel.length, samples.length, `${tag}: parallel info length mismatch`);
    parallel.forEach((p, idx) => assert.ok(p, `${tag}: parallel info index ${idx} empty`));

    console.log(`    list_strings + list_names + list_bookmarks…`);
    const strings = await callTool("list_strings", { max_results: 25 });
    const names = await callTool("list_names", { max_results: 25 });
    const bookmarks = await callTool("list_bookmarks", {});
    assert.ok(strings, `${tag}: list_strings null`);
    assert.ok(names, `${tag}: list_names null`);
    assert.ok(bookmarks !== undefined, `${tag}: list_bookmarks undefined`);

    console.log(`    address_name + procedure_address round-trip…`);
    const firstSample = samples[0];
    const nameAtAddr = await callTool("address_name", { address: firstSample.addr });
    assert.equal(typeof nameAtAddr, "string", `${tag}: address_name not a string`);
    if (firstSample.name && !/^sub_/.test(firstSample.name)) {
      const reverseAddr = await callTool("procedure_address", { procedure: firstSample.name }, { allowError: true });
      assert.ok(reverseAddr !== null, `${tag}: procedure_address(name=${firstSample.name}) returned null`);
    }
  }

  console.log("[C] re-ingest first target (must reuse current_document if active)…");
  const firstTarget = targets[0];
  const firstTag = basename(firstTarget);
  const docNameBefore = await callTool("current_document", {});
  const reingest1 = await callTool("ingest_live_hopper", {
    executable_path: firstTarget,
    timeout_ms: ingestTimeoutMs,
    analysis: true,
    parse_objective_c: false,
    parse_swift: false,
    max_functions: 60,
    max_strings: 200,
  }, { timeoutMs: ingestTimeoutMs + 30000 });
  if (docNameBefore === firstTag) {
    assert.equal(reingest1.launch?.skipped, true, `re-ingesting active document should skip launch (was ${reingest1.launch?.mode})`);
    console.log(`  ✓ reuse skipped=true (active doc was ${docNameBefore})`);
  } else {
    assert.equal(reingest1.launch?.skipped, false, `re-ingesting non-active doc should re-launch (was ${reingest1.launch?.mode})`);
    console.log(`  ✓ relaunched mode=${reingest1.launch?.mode} (active doc was ${docNameBefore} != ${firstTag})`);
  }

  console.log("[D] write guard via official_hopper_call…");
  const blocked = await callTool("official_hopper_call", {
    name: "set_comment",
    arguments: { address: "0x0", comment: "blocked write" },
  }, { allowError: true });
  assert.ok(typeof blocked === "string" && blocked.includes("HOPPER_MCP_ENABLE_OFFICIAL_WRITES"), `write guard did not block: ${JSON.stringify(blocked)}`);
  console.log(`  ✓ blocked: ${String(blocked).slice(0, 80)}…`);

  console.log("[E] commit_transaction backend=official without write env var (should fail gracefully)…");
  const session = sessionsByTarget.get(firstTarget);
  const someProc = summarizeProcedures(await callTool("list_procedures", { session_id: session.sessionId, max_results: 5 }))[0];
  if (someProc?.addr) {
    const txn = await callTool("begin_transaction", { session_id: session.sessionId, name: "live commit attempt" });
    await callTool("queue_comment", {
      session_id: session.sessionId,
      transaction_id: txn.transactionId,
      addr: someProc.addr,
      comment: "live test attempted comment",
    });
    const commitErr = await callTool("commit_transaction", {
      session_id: session.sessionId,
      transaction_id: txn.transactionId,
      backend: "official",
    }, { allowError: true });
    assert.ok(typeof commitErr === "string" && commitErr.includes("HOPPER_MCP_ENABLE_OFFICIAL_WRITES"), `live commit guard did not block: ${JSON.stringify(commitErr)}`);
    console.log(`  ✓ live commit blocked`);
  }

  console.log("[F] refresh_snapshot (official snapshot rebuild against live Hopper)…");
  const snapshot = await callTool("refresh_snapshot", { max_procedures: 5, include_procedure_info: true }, { timeoutMs: ingestTimeoutMs });
  assert.ok(snapshot.session?.sessionId, "refresh_snapshot did not return a session");
  assert.equal(snapshot.source, "official-hopper-mcp", `refresh_snapshot source=${snapshot.source}`);
  assert.ok(snapshot.session.counts.functions <= 5, `refresh_snapshot honoured max_procedures (got ${snapshot.session.counts.functions})`);
  console.log(`  ✓ snapshot session=${snapshot.session.sessionId.slice(0, 24)} fns=${snapshot.session.counts.functions}`);

  console.log("[G] cross-session diff (imphash + segments + counts)…");
  const sessionList = await rpc("resources/list");
  const sessionResources = sessionList.resources.filter((r) => r.uri.startsWith("hopper://session"));
  assert.ok(sessionResources.length >= 1, "expected at least one session resource");

  const sessionIds = [...sessionsByTarget.values()].map((s) => s.sessionId);
  console.log(`  recorded sessions: ${sessionIds.length} (${sessionIds.map((id) => id.slice(0, 16)).join(", ")})`);

  const allSessions = await callTool("list_documents", {});
  console.log(`  list_documents → ${Array.isArray(allSessions) ? allSessions.length : "?"} entries: ${JSON.stringify(allSessions).slice(0, 200)}`);

  if (sessionIds.length >= 2) {
    const diff = await callTool("diff_sessions", {
      session_a: sessionIds[0],
      session_b: sessionIds[1],
    });
    assert.ok(diff && typeof diff === "object", "diff_sessions returned no object");
    console.log(`  ✓ diff between first two sessions: keys=${Object.keys(diff).join(",").slice(0, 100)}`);
  }

  console.log("\n=== Live Hopper aggressive summary ===");
  console.table(launches);
  console.log(`launches: ${launches.length} (skipped=${launches.filter((l) => l.skipped).length}, opened=${launches.filter((l) => !l.skipped).length})`);
  console.log("aggressive live-hopper test ok");
} catch (error) {
  const message = String(error?.message ?? error);
  if (message.includes("Not authorized to send Apple events") || message.includes("Operation not permitted")) {
    console.error([
      "Aggressive live-Hopper test could not run: macOS Automation perms blocked control of Hopper.",
      "System Settings > Privacy & Security > Automation, allow your terminal to control Hopper Disassembler, then re-run.",
      "",
      message,
    ].join("\n"));
    process.exitCode = 78;
  } else {
    console.error("aggressive live-hopper test failed:");
    console.error(message);
    process.exitCode = 1;
  }
} finally {
  child.stdin.end();
  child.kill();
  await once(child, "exit").catch(() => {});
}
