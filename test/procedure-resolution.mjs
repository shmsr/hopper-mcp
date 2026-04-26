// Procedure/address-resolution audit. Verifies:
//  • `procedure(addr)` refuses silently-wrong substring fallbacks for numeric
//    queries.
//  • `containing_function` returns the function whose body covers an
//    instruction address (via deep-mode size data).
//  • The macho-importer matches nm-defined symbols to discovered function
//    ranges so off-by-N entrypoints get proper names instead of `sub_<addr>`.
//
// Uses /bin/ls (small, ARM64, has unstripped Apple symbols) so we don't need
// a live Hopper. Intel-only hosts will skip the deep-mode portion.

import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { mergeFunctionSets } from "../src/macho-importer.js";
import {
  computeProcedureDrift,
  fetchHopperProcedureIndex,
  fetchHopperXrefs,
  fetchHopperCallees,
  fetchHopperDecompilation,
  fetchHopperAssembly,
  fetchHopperNames,
  clearHopperCaches,
} from "../src/hopper-bridge.js";
import { OfficialHopperBackend, normalizeOfficialResult } from "../src/official-hopper-backend.js";

const execFileAsync = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const serverScript = join(root, "src", "mcp-server.js");

const passed = [];
function pass(name) {
  passed.push(name);
  process.stderr.write(`  ✓ ${name}\n`);
}

function assert(cond, message) {
  if (!cond) throw new Error(`assertion failed: ${message}`);
}

function spawnServer(storePath) {
  const child = spawn(process.execPath, [serverScript], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOPPER_MCP_STORE: storePath },
  });
  const responses = new Map();
  const stderrChunks = [];
  child.stderr.on("data", (chunk) => stderrChunks.push(chunk.toString()));

  const rl = createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let message;
    try { message = JSON.parse(line); } catch { return; }
    if (message.id !== undefined) responses.set(message.id, message);
  });

  let id = 0;
  const rpc = async (method, params = {}, { timeoutMs = 120000 } = {}) => {
    const requestId = ++id;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
    const deadline = Date.now() + timeoutMs;
    while (!responses.has(requestId)) {
      if (Date.now() > deadline) throw new Error(`rpc ${method} timed out`);
      await new Promise((r) => setTimeout(r, 5));
    }
    const response = responses.get(requestId);
    responses.delete(requestId);
    if (response.error) {
      const err = new Error(response.error.message);
      err.code = response.error.code;
      throw err;
    }
    return response.result;
  };

  const callTool = async (name, args, opts) => {
    const result = await rpc("tools/call", { name, arguments: args }, opts);
    if (result.isError) {
      const text = result.content?.[0]?.text ?? "tool call failed";
      const err = new Error(text);
      err.toolError = true;
      throw err;
    }
    return JSON.parse(result.content[0].text);
  };

  return {
    child,
    rpc,
    callTool,
    stderr: () => stderrChunks.join(""),
    async close() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.stdin.end();
      child.kill();
      await once(child, "exit").catch(() => {});
    },
  };
}

async function initialize(server) {
  await server.rpc("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "procedure-resolution-test", version: "0.1.0" },
  });
}

// ── unit: mergeFunctionSets — nm symbols are authoritative entrypoints ──
{
  // Two nm symbols and two discovery starts. The discovery start at
  // 0x10007981c sits 0x14 bytes after the nm symbol at 0x100079808 — that's
  // the classic Rust off-by-prologue case (x29,x30 saved last). The nm
  // entrypoint must win and the discovery start must be folded in. The
  // second nm/discovery pair matches exactly. Final size for vars_os is the
  // gap to the next entrypoint.
  const existing = [
    { addr: "0x100079808", name: "__ZN3std3env7vars_os17hABCDE", size: null, source: "nm", confidence: 0.55 },
    { addr: "0x100079900", name: "_main", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = {
    functions: [
      { addr: "0x10007981c", size: 0x100 },
      { addr: "0x100079900", size: 0x40 },
    ],
    callEdges: [],
    adrpRefs: [],
  };
  const merged = mergeFunctionSets(existing, discovery, []);
  const byAddr = Object.fromEntries(merged.map((fn) => [fn.addr, fn]));
  assert(byAddr["0x100079808"]?.name === "__ZN3std3env7vars_os17hABCDE", "nm symbol kept as the entrypoint");
  assert(!byAddr["0x10007981c"], "discovery start within prologue tolerance is dropped (nm wins)");
  assert(byAddr["0x100079808"]?.size === 0x100079900 - 0x100079808, "size derived from gap to next entrypoint");
  assert(byAddr["0x100079900"]?.name === "_main", "exact-address nm symbol survives merge");
  pass("mergeFunctionSets treats nm symbols as authoritative entrypoints");
}

{
  // nm symbol slightly AFTER a discovery start (0x100079808 is 8 bytes after
  // 0x100079800). They're the same function — nm wins, discovery dropped.
  const existing = [
    { addr: "0x100079808", name: "__ZN3std3env7vars_os17hABCDE", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = {
    functions: [
      { addr: "0x100079800", size: 0x100 },
    ],
    callEdges: [],
    adrpRefs: [],
  };
  const merged = mergeFunctionSets(existing, discovery, [], { textEnd: 0x100079900 });
  const byAddr = Object.fromEntries(merged.map((fn) => [fn.addr, fn]));
  assert(!byAddr["0x100079800"], "discovery start within tolerance of nm is dropped");
  assert(byAddr["0x100079808"]?.name === "__ZN3std3env7vars_os17hABCDE", "nm symbol is the entrypoint");
  assert(byAddr["0x100079808"]?.size === 0x100079900 - 0x100079808, "size derived from textEnd cap");
  assert(byAddr["0x100079808"]?.source === "nm+otool", "source reflects discovery confirmation");
  pass("mergeFunctionSets drops discovery starts that match an nm symbol within tolerance");
}

{
  // nm symbol with no discovery anchor anywhere nearby — pure nm record,
  // size derived from gap to the next entrypoint.
  const existing = [
    { addr: "0x100000000", name: "_alpha", size: null, source: "nm", confidence: 0.55 },
    { addr: "0x100000200", name: "_beta", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = {
    functions: [
      { addr: "0x100000400", size: 0x10 }, // Far from both nm symbols — kept as sub_*.
    ],
    callEdges: [],
    adrpRefs: [],
  };
  const merged = mergeFunctionSets(existing, discovery, [], { textEnd: 0x100000500 });
  const byAddr = Object.fromEntries(merged.map((fn) => [fn.addr, fn]));
  assert(byAddr["0x100000000"]?.size === 0x200, "alpha sized by gap to beta");
  assert(byAddr["0x100000200"]?.size === 0x200, "beta sized by gap to discovery start");
  assert(byAddr["0x100000400"]?.name === "sub_100000400", "discovery in gap kept as sub_");
  assert(byAddr["0x100000400"]?.size === 0x100, "trailing entry capped at textEnd");
  pass("mergeFunctionSets sizes via gaps, fills sub_ entries in gaps");
}

{
  // Re-merging an already-merged set must be idempotent: the names and
  // entrypoints from the first pass should survive a second call.
  const existing = [
    { addr: "0x100079808", name: "_dl_hook", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = {
    functions: [{ addr: "0x100079800", size: 0x100 }],
    callEdges: [],
    adrpRefs: [],
  };
  const merged = mergeFunctionSets(existing, discovery, [], { textEnd: 0x100079900 });
  const second = mergeFunctionSets(merged, discovery, [], { textEnd: 0x100079900 });
  const byAddr = Object.fromEntries(second.map((fn) => [fn.addr, fn]));
  assert(byAddr["0x100079808"]?.name === "_dl_hook", "existing name preserved across re-merge");
  assert(!byAddr["0x100079800"], "no orphaned discovery start after re-merge");
  pass("mergeFunctionSets is idempotent across repeated calls");
}

{
  // Re-attribution: a single discovery range that spans two real functions
  // should split correctly when nm symbols mark the second function. Call
  // edges anchored on instruction addresses get attributed to the right
  // sub-function — not smeared onto the discovery start.
  const existing = [
    { addr: "0x100079808", name: "_apply_sandbox", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = {
    functions: [
      // Discovery thinks one big range covers both functions.
      { addr: "0x100079700", size: 0x200 }, // [0x100079700, 0x100079900)
    ],
    callEdges: [
      { from: "0x100079700", fromInstr: "0x100079720", to: "0xdeadbeef" }, // inside sub_100079700
      { from: "0x100079700", fromInstr: "0x10007982c", to: "0xcafef00d" }, // inside _apply_sandbox
    ],
    adrpRefs: [],
  };
  const merged = mergeFunctionSets(existing, discovery, [], { textEnd: 0x100079900 });
  const byAddr = Object.fromEntries(merged.map((fn) => [fn.addr, fn]));
  assert(byAddr["0x100079700"], "leading discovery range becomes its own sub_");
  assert(byAddr["0x100079700"].callees.includes("0xdeadbeef"), "edge before nm boundary attributed to sub_");
  assert(byAddr["0x100079808"].callees.includes("0xcafef00d"), "edge after nm boundary attributed to nm function");
  assert(!byAddr["0x100079700"].callees.includes("0xcafef00d"), "edge does not bleed into wrong function");
  pass("mergeFunctionSets re-attributes call edges by instruction address");
}

{
  // Hopper fusion: when a Hopper procedure index is supplied, Hopper's
  // entrypoints are treated as authoritative alongside nm. A Hopper-only
  // entrypoint that sits inside an nm function's gap becomes its own record;
  // an exact-addr Hopper match enriches the nm record with size/signature/
  // basicblocks; a discovery start within tolerance of either source is
  // dropped.
  const existing = [
    { addr: "0x100000000", name: "_alpha", size: null, source: "nm", confidence: 0.55 },
    { addr: "0x100000400", name: "_gamma", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = {
    functions: [
      { addr: "0x100000208", size: 0x40 }, // within tolerance of Hopper's 0x100000200 → dropped
      { addr: "0x100000300", size: 0x40 }, // gap entry, kept as sub_
    ],
    callEdges: [],
    adrpRefs: [],
  };
  const hopperIndex = new Map([
    [0x100000000, {
      addr: "0x100000000", name: "alpha_pretty", size: 0x100,
      signature: "void alpha(int)", basicBlockCount: 3,
      basicBlocks: [{ from: "0x100000000", to: "0x100000040" }],
    }],
    // Hopper-only entrypoint: nm doesn't know about this.
    [0x100000200, { addr: "0x100000200", name: "_beta_hopper", size: 0xc0 }],
  ]);

  const merged = mergeFunctionSets(existing, discovery, [], { textEnd: 0x100000600, hopperIndex });
  const byAddr = Object.fromEntries(merged.map((fn) => [fn.addr, fn]));

  assert(byAddr["0x100000000"]?.name === "_alpha", "nm name kept when both have non-placeholder names");
  assert(byAddr["0x100000000"]?.hopperName === "alpha_pretty", "Hopper name attached as alternative");
  assert(byAddr["0x100000000"]?.size === 0x100, "Hopper explicit size wins over gap-based size");
  assert(byAddr["0x100000000"]?.signature === "void alpha(int)", "Hopper signature is attached");
  assert(byAddr["0x100000000"]?.source === "nm+hopper", "source upgraded to nm+hopper");
  assert(byAddr["0x100000200"], "Hopper-only entrypoint becomes its own record");
  assert(byAddr["0x100000200"]?.name === "_beta_hopper", "Hopper-only record uses Hopper's name");
  assert(byAddr["0x100000200"]?.source === "hopper", "Hopper-only record sourced 'hopper'");
  assert(byAddr["0x100000200"]?.size === 0xc0, "Hopper-only record uses Hopper's explicit size");
  assert(!byAddr["0x100000208"], "discovery start within tolerance of Hopper entry is dropped");
  assert(byAddr["0x100000300"], "discovery start outside tolerance of any authoritative entry survives");
  assert(byAddr["0x100000400"]?.name === "_gamma", "untouched nm entries pass through");
  pass("mergeFunctionSets fuses a Hopper procedure index alongside nm");
}

{
  // Hopper override on a sub_ placeholder: when nm only has a sub_ stub at
  // an address Hopper named, the Hopper name wins. (Realistic case: nm
  // produced a sub_ because the symbol was stripped, but Hopper's analysis
  // recovered the demangled name.)
  const existing = [
    { addr: "0x100079808", name: "sub_100079808", size: null, source: "nm", confidence: 0.55 },
  ];
  const discovery = { functions: [], callEdges: [], adrpRefs: [] };
  const hopperIndex = new Map([
    [0x100079808, { addr: "0x100079808", name: "apply_sandbox_and_exec", size: 0x200 }],
  ]);
  const merged = mergeFunctionSets(existing, discovery, [], { textEnd: 0x100079a08, hopperIndex });
  const fn = merged.find((f) => f.addr === "0x100079808");
  assert(fn?.name === "apply_sandbox_and_exec", "Hopper name overrides nm's sub_ placeholder");
  assert(!fn?.hopperName, "no hopperName alternative when nm name was a placeholder");
  pass("mergeFunctionSets uses Hopper name when nm has only a sub_ placeholder");
}

{
  // computeProcedureDrift: structured drift report between local + Hopper.
  const local = {
    functions: [
      { addr: "0x100000000", name: "_alpha", size: 0x100, source: "nm" },
      { addr: "0x100000200", name: "sub_100000200", size: 0x80, source: "otool-discovery" },
      { addr: "0x100000400", name: "_only_local", size: 0x40, source: "nm" },
      { addr: "0xfff00000", name: "synthetic_cluster", source: "semantic-import-cluster" },
    ],
  };
  const hopperResult = {
    documentName: "binary",
    procedures: {
      map: new Map([
        [0x100000000, { addr: "0x100000000", name: "_alpha", size: 0x100 }],
        [0x100000200, { addr: "0x100000200", name: "_beta", size: 0xc0 }],   // size + name drift
        [0x100000800, { addr: "0x100000800", name: "_only_hopper", size: 0x40 }], // hopper-only
      ]),
    },
  };
  const report = computeProcedureDrift(local, hopperResult, { maxPerCategory: 50 });
  assert(report.ok, "report is ok when both sides present");
  assert(report.summary.local.count === 3, "synthetic cluster excluded from local count");
  assert(report.summary.hopper.count === 3, "hopper count matches map size");
  assert(report.summary.matched === 2, "matched = exact-addr intersection");
  assert(report.summary.localOnly === 1, "_only_local detected");
  assert(report.summary.hopperOnly === 1, "_only_hopper detected");
  assert(report.summary.sizeDrift === 1, "size mismatch on 0x100000200");
  assert(report.summary.nameDrift === 1, "name mismatch on 0x100000200");
  assert(report.drift.sizeDrift[0].delta === 0xc0 - 0x80, "delta computed as hopper - local");
  assert(report.drift.localOnly[0].addr === "0x100000400", "localOnly lists the right entry");
  assert(report.drift.hopperOnly[0].addr === "0x100000800", "hopperOnly lists the right entry");
  pass("computeProcedureDrift summarizes drift between local + Hopper");
}

{
  // computeProcedureDrift gracefully reports when Hopper isn't reachable.
  const local = { functions: [{ addr: "0x100000000", name: "_alpha", size: 0x100, source: "nm" }] };
  const hopperResult = { reachable: false, reason: "no document loaded" };
  const report = computeProcedureDrift(local, hopperResult);
  assert(!report.ok, "ok=false when Hopper is not reachable");
  assert(/no document loaded/.test(report.reason ?? ""), "reason surfaced from upstream");
  assert(report.summary.local.count === 1, "still report local count");
  pass("computeProcedureDrift handles unreachable Hopper without crashing");
}

{
  // applyTransaction batches consecutive renames into one set_addresses_names
  // call, preserves order, and falls back to one-at-a-time for non-rename
  // ops. Uses a mocked OfficialHopperBackend that records every callTool
  // invocation.
  const calls = [];
  const backend = new OfficialHopperBackend();
  backend.enableWrites = true;
  backend.callTool = async (name, args) => {
    calls.push({ name, args });
    return { content: [{ type: "text", text: JSON.stringify({ ok: true }) }] };
  };

  const tx = {
    id: "tx-1",
    operations: [
      { operationId: "r1", kind: "rename", addr: "0x100", newValue: "alpha" },
      { operationId: "r2", kind: "rename", addr: "0x200", newValue: "beta" },
      { operationId: "c1", kind: "comment", addr: "0x300", newValue: "note" },
      { operationId: "r3", kind: "rename", addr: "0x400", newValue: "gamma" },
    ],
  };
  const result = await backend.applyTransaction(null, tx, { confirmLiveWrite: true });

  assert(calls.length === 3, `expected 3 backend calls (1 batch + 1 comment + 1 batch), got ${calls.length}`);
  assert(calls[0].name === "set_addresses_names", "first call is the batched rename");
  assert(calls[0].args.names["0x100"] === "alpha" && calls[0].args.names["0x200"] === "beta", "batch contains both renames");
  assert(calls[1].name === "set_comment", "second call is the lone comment");
  assert(calls[2].name === "set_addresses_names", "third call batches the trailing rename");
  assert(calls[2].args.names["0x400"] === "gamma", "trailing rename is in its own batch");
  assert(result.operations.length === 4, "every op gets an entry in the response");
  assert(result.operations[0].batched === 2, "first batch records its size");
  assert(result.operations[2].batched === undefined, "single-rename batch is not annotated");
  pass("applyTransaction batches consecutive renames via set_addresses_names");
}

{
  // Bulk fetchHopperProcedureIndex prefers list_procedure_info when available.
  let calls = 0;
  const backend = {
    callTool: async (name) => {
      calls++;
      if (name === "current_document") return reply("test_doc");
      if (name === "list_procedures") return reply({ "0x100": "_alpha", "0x200": "_beta" });
      if (name === "list_procedure_size") return reply({});
      if (name === "list_procedure_info") {
        return reply({
          "0x100": { name: "_alpha", length: 0x40, basicblock_count: 2, signature: "void alpha()", basicblocks: [{ from: "0x100", to: "0x140" }], locals: [] },
          "0x200": { name: "_beta", length: 0x80, basicblock_count: 3, signature: "int beta(int)", basicblocks: [], locals: [{ name: "x" }] },
        });
      }
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperProcedureIndex(backend, { expectedDocument: "test_doc", fetchProcedureInfo: true });
  assert(r.reachable && r.documentName === "test_doc", "doc match accepted");
  assert(r.procedures.map.size === 2, "two procedures indexed");
  const a = r.procedures.map.get(0x100);
  assert(a?.size === 0x40 && a.signature === "void alpha()", "alpha enriched from bulk info");
  assert(a.basicBlockCount === 2, "alpha basicBlockCount populated");
  // 4 expected calls: current_document, list_procedures, list_procedure_size, list_procedure_info
  assert(calls === 4, `expected 4 backend calls, got ${calls}`);
  pass("fetchHopperProcedureIndex uses bulk list_procedure_info (one round-trip)");
}

{
  // Bulk fetch falls back to per-procedure procedure_info when list_procedure_info errors.
  let bulkCalls = 0, perCalls = 0;
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("doc");
      if (name === "list_procedures") return reply({ "0x100": "_a", "0x200": "_b" });
      if (name === "list_procedure_size") return reply({});
      if (name === "list_procedure_info") { bulkCalls++; throw new Error("not supported in this Hopper version"); }
      if (name === "procedure_info") { perCalls++; return reply({ name: args?.procedure === "0x100" ? "alpha" : "beta", length: 0x10, signature: "x" }); }
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperProcedureIndex(backend, { expectedDocument: "doc", fetchProcedureInfo: true });
  assert(bulkCalls === 1 && perCalls === 2, `expected bulk attempt then 2 per-procedure calls, got bulk=${bulkCalls} per=${perCalls}`);
  assert(r.procedures.map.get(0x200)?.signature === "x", "fallback path still enriches records");
  pass("fetchHopperProcedureIndex falls back to per-procedure info when bulk fails");
}

{
  // fetchHopperXrefs returns analyzed xrefs with caller resolution via both
  // procedure_callers (function-granularity) and procedure_address (instr-granularity).
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("bin");
      if (name === "xrefs" && args?.address === "0x1000") return reply(["0x2004", "0x3010"]);
      if (name === "procedure_callers" && args?.procedure === "0x1000") return reply(["caller_a", "caller_b"]);
      if (name === "list_procedures") return reply({ "0x2000": "caller_a", "0x3000": "caller_b" });
      if (name === "procedure_address" && args?.procedure === "0x2004") return reply("0x2000");
      if (name === "procedure_address" && args?.procedure === "0x3010") return reply("0x3000");
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperXrefs(backend, "0x1000", { expectedDocument: "bin", resolveCallers: true });
  assert(r.reachable && Array.isArray(r.xrefs), "xrefs returned an array");
  assert(r.xrefs.length === 2, "both xrefs preserved");
  assert(r.xrefs[0].addr === "0x2004" && r.xrefs[0].function === "0x2000", "per-instr resolved to entrypoint");
  assert(Array.isArray(r.callerProcedures) && r.callerProcedures.length === 2, "callerProcedures populated");
  assert(r.callerProcedures[0].name === "caller_a" && r.callerProcedures[0].addr === "0x2000", "caller name resolved to addr via list_procedures");
  pass("fetchHopperXrefs returns analyzed xrefs with caller resolution");
}

{
  // fetchHopperXrefs gracefully handles Hopper procedure_callers + procedure_address
  // failures (real /bin/ls case): xrefs returned, no per-instr resolution, no
  // procedure_callers.
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("bin");
      if (name === "xrefs") return reply(["0xabcd"]);
      if (name === "procedure_callers") throw new Error("no callers tracked");
      if (name === "procedure_address") throw new Error("Cannot find procedure named 0xabcd");
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperXrefs(backend, "0x1000", { expectedDocument: "bin", resolveCallers: true });
  assert(r.xrefs.length === 1 && r.xrefs[0].addr === "0xabcd", "xref still surfaced");
  assert(r.xrefs[0].function === undefined, "function field absent when procedure_address fails");
  assert(r.callerProcedures === null, "callerProcedures null when procedure_callers fails");
  pass("fetchHopperXrefs tolerates procedure_callers + procedure_address failures");
}

{
  // computeProcedureDrift recognizes local entries that fall inside Hopper
  // procedures (the /bin/ls case: prologue scanner over-discovers).
  const local = {
    functions: [
      { addr: "0x100000960", name: "EntryPoint", size: 0x100, source: "nm" },        // exact match
      { addr: "0x100000978", name: "sub_100000978", source: "otool-discovery" },     // inside EntryPoint
      { addr: "0x100001000", name: "sub_100001000", source: "otool-discovery" },     // genuinely local-only
    ],
  };
  const hopperResult = {
    documentName: "bin",
    procedures: {
      map: new Map([
        [0x100000960, { addrNum: 0x100000960, addr: "0x100000960", name: "EntryPoint", size: 0x100 }],
        [0x100000a80, { addrNum: 0x100000a80, addr: "0x100000a80", name: "_helper", size: 0x40 }],
      ]),
    },
  };
  const r = computeProcedureDrift(local, hopperResult);
  assert(r.summary.matched === 1, "EntryPoint matches exactly");
  assert(r.summary.insideHopperProc === 1, "sub_100000978 falls inside EntryPoint");
  assert(r.summary.localOnly === 1, "sub_100001000 stays in localOnly");
  assert(r.drift.insideHopperProc[0].hopperProc === "EntryPoint", "containing proc identified by name");
  assert(r.drift.insideHopperProc[0].offsetIntoHopperProc === 0x18, "offset into containing proc reported");
  pass("computeProcedureDrift flags local entries that land inside Hopper procs");
}

{
  // fetchHopperXrefs surfaces document mismatch.
  const backend = {
    callTool: async (name) => {
      if (name === "current_document") return reply("other");
      throw new Error("should not call xrefs on mismatch");
    },
  };
  const r = await fetchHopperXrefs(backend, "0x1000", { expectedDocument: "/path/expected", documentMustMatch: true });
  assert(r.reachable, "still reachable even on mismatch");
  assert(r.documentMismatch?.expected === "expected" && r.documentMismatch?.got === "other", "mismatch fields populated");
  assert(r.xrefs === null, "no xrefs on mismatch");
  pass("fetchHopperXrefs surfaces document mismatch and skips the xrefs call");
}

function reply(payload) {
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

{
  // fetchHopperCallees resolves callee names back to addresses via list_procedures.
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("bin");
      if (name === "procedure_callees" && args?.procedure === "0x1000") return reply(["_strdup", "_free", "_strdup"]);
      if (name === "list_procedures") return reply({ "0x2000": "_strdup", "0x3000": "_free" });
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperCallees(backend, "0x1000", { expectedDocument: "bin" });
  assert(r.reachable && Array.isArray(r.callees), "callees array returned");
  assert(r.callees.length === 2, "duplicate callee deduped");
  assert(r.callees[0].name === "_strdup" && r.callees[0].addr === "0x2000", "callee resolved to addr");
  pass("fetchHopperCallees resolves callee names to addresses and dedupes");
}

{
  // fetchHopperCallees handles non-array procedure_callees response gracefully.
  const backend = {
    callTool: async (name) => {
      if (name === "current_document") return reply("bin");
      if (name === "procedure_callees") return reply(null);
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperCallees(backend, "0x1000", { expectedDocument: "bin" });
  assert(r.reachable && r.callees === null, "callees null on missing data");
  assert(typeof r.reason === "string", "reason field present");
  pass("fetchHopperCallees tolerates non-array procedure_callees");
}

{
  // fetchHopperDecompilation bails on procedures with too many basic blocks
  // (the EntryPoint case: 153 blocks → 5s pseudo_code call).
  clearHopperCaches();
  let pseudoCalled = false;
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("bin");
      if (name === "list_procedure_size") return reply({ "0x1000": { name: "Big", size: 0x1000 } });
      if (name === "procedure_info" && args?.procedure === "0x1000") {
        return reply({ name: "Big", basicblock_count: 500, signature: "void Big()" });
      }
      if (name === "procedure_pseudo_code") { pseudoCalled = true; return reply("..."); }
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperDecompilation(backend, "0x1000", { expectedDocument: "bin", maxBasicBlocks: 250 });
  assert(r.reachable && r.decompilation === null, "decompilation skipped");
  assert(r.basicBlockCount === 500, "basic block count surfaced");
  assert(/too slow/.test(r.reason ?? ""), "reason explains the bail");
  assert(!pseudoCalled, "pseudo_code never called when block count exceeds max");
  pass("fetchHopperDecompilation refuses procs above maxBasicBlocks");
}

{
  // fetchHopperDecompilation caches results keyed by document fingerprint+addr.
  clearHopperCaches();
  let pseudoCalls = 0;
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("bin");
      if (name === "list_procedure_size") return reply({ "0x1000": { name: "Small", size: 0x40 } });
      if (name === "procedure_info" && args?.procedure === "0x1000") {
        return reply({ name: "Small", basicblock_count: 4 });
      }
      if (name === "procedure_pseudo_code") { pseudoCalls++; return reply("int Small() { return 0; }"); }
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r1 = await fetchHopperDecompilation(backend, "0x1000", { expectedDocument: "bin" });
  const r2 = await fetchHopperDecompilation(backend, "0x1000", { expectedDocument: "bin" });
  assert(pseudoCalls === 1, `pseudo_code called once (got ${pseudoCalls})`);
  assert(r1.cached === undefined && r2.cached === true, "second call flagged cached");
  assert(r1.decompilation === r2.decompilation, "cached payload identical");
  pass("fetchHopperDecompilation caches by (document fingerprint, addr)");
}

{
  // fetchHopperDecompilation invalidates cache when fingerprint changes
  // (simulates user re-analyzing the binary in Hopper).
  clearHopperCaches();
  let pseudoCalls = 0;
  let sizes = { "0x1000": { name: "S", size: 0x40 } };
  const backend = {
    callTool: async (name, args) => {
      if (name === "current_document") return reply("bin");
      if (name === "list_procedure_size") return reply(sizes);
      if (name === "procedure_info") return reply({ name: "S", basicblock_count: 4 });
      if (name === "procedure_pseudo_code") { pseudoCalls++; return reply("v1"); }
      throw new Error(`unexpected call ${name}`);
    },
  };
  await fetchHopperDecompilation(backend, "0x1000", { expectedDocument: "bin" });
  // Re-analyze: same address but a renamed procedure — fingerprint must drift.
  sizes = { "0x1000": { name: "S_renamed", size: 0x40 } };
  await fetchHopperDecompilation(backend, "0x1000", { expectedDocument: "bin" });
  assert(pseudoCalls === 2, `expected 2 pseudo_code calls after fingerprint drift, got ${pseudoCalls}`);
  pass("fetchHopperDecompilation re-fetches when document fingerprint changes");
}

{
  // fetchHopperAssembly returns annotated assembly and skips the basic-block guard.
  clearHopperCaches();
  let asmCalls = 0;
  const backend = {
    callTool: async (name) => {
      if (name === "current_document") return reply("bin");
      if (name === "list_procedure_size") return reply({ "0x1000": { name: "Big", size: 0x800 } });
      if (name === "procedure_info") return reply({ name: "Big", basicblock_count: 500, length: 0x800 });
      if (name === "procedure_assembly") { asmCalls++; return reply("0x1000: stp x29, x30..."); }
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperAssembly(backend, "0x1000", { expectedDocument: "bin" });
  assert(r.reachable && typeof r.assembly === "string", "assembly text returned");
  assert(asmCalls === 1, "procedure_assembly fired even with high BB count (no slow guard)");
  // Cache hit on second call.
  await fetchHopperAssembly(backend, "0x1000", { expectedDocument: "bin" });
  assert(asmCalls === 1, "second call hit cache");
  pass("fetchHopperAssembly returns assembly without BB guard and caches");
}

{
  // fetchHopperNames maps list_names into a normalized Map<addrNum, name>.
  const backend = {
    callTool: async (name) => {
      if (name === "current_document") return reply("bin");
      if (name === "list_names") {
        return reply({
          "0x100000960": "EntryPoint",
          "0x100001234": "_helper",
          "0x100002000": "cstring_hello",
          "0xnotanaddr": "garbage",
          "0x100003000": "",
        });
      }
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperNames(backend, { expectedDocument: "bin" });
  assert(r.reachable && r.names instanceof Map, "names returned as Map");
  assert(r.names.size === 3, `expected 3 valid names, got ${r.names.size}`);
  assert(r.names.get(0x100000960) === "EntryPoint", "EntryPoint resolved");
  assert(r.names.get(0x100002000) === "cstring_hello", "string label resolved");
  pass("fetchHopperNames normalizes list_names into Map<addrNum, name>");
}

{
  // fetchHopperNames returns null when list_names returns non-object.
  const backend = {
    callTool: async (name) => {
      if (name === "current_document") return reply("bin");
      if (name === "list_names") return reply(null);
      throw new Error(`unexpected call ${name}`);
    },
  };
  const r = await fetchHopperNames(backend, { expectedDocument: "bin" });
  assert(r.reachable && r.names === null, "names null on missing data");
  pass("fetchHopperNames tolerates null list_names response");
}

{
  // normalizeOfficialResult turns search_* null payloads into {} so callers
  // can iterate without special-casing.
  const original = { content: [{ type: "text", text: "null" }] };
  const out = normalizeOfficialResult("search_strings", original);
  assert(out.content[0].text === "{}", "null → {} for search_strings");
  const passthrough = normalizeOfficialResult("search_strings", { content: [{ type: "text", text: '{"x":1}' }] });
  assert(passthrough.content[0].text === '{"x":1}', "non-null search_* payload passes through");
  const xrefsNull = normalizeOfficialResult("xrefs", original);
  assert(xrefsNull.content[0].text === "null", "non-search tools are not normalized");
  pass("normalizeOfficialResult rewrites search_* null payloads to {}");
}

{
  // Schema validation rejects unknown args (the foot-gun this catches: passing
  // `regex` to search_strings, which actually wants `pattern`).
  const backend = new OfficialHopperBackend({});
  // Bypass start() — inject a fake tool catalog directly so we can exercise
  // #validateArgs without spawning the official server.
  backend.tools = [
    { name: "search_strings", inputSchema: { type: "object", properties: { pattern: { type: "string" } }, required: ["pattern"] } },
    { name: "set_comment", inputSchema: { type: "object", properties: { address: { type: "string" }, comment: { type: "string" } }, required: ["address", "comment"] } },
  ];
  backend.initialized = true;
  backend.child = { killed: false, kill() {} };
  // Override request so we never touch the network — tests should fail before reaching it.
  backend.request = async () => { throw new Error("request must not be reached for validation tests"); };
  let threw = null;
  try {
    await backend.callTool("search_strings", { regex: "hello" });
  } catch (err) { threw = err; }
  assert(threw && /unknown argument/.test(threw.message), `expected unknown-arg error, got: ${threw?.message}`);
  assert(/Allowed: pattern/.test(threw.message), "error lists the actual allowed args");

  // Missing required arg also caught.
  threw = null;
  try {
    await backend.callTool("search_strings", {});
  } catch (err) { threw = err; }
  assert(threw && /missing required/.test(threw.message), "missing required arg caught");

  // Unknown tool name caught.
  threw = null;
  try {
    await backend.callTool("totally_made_up_tool", {});
  } catch (err) { threw = err; }
  assert(threw && /Unknown official Hopper tool/.test(threw.message), "unknown tool caught");

  pass("OfficialHopperBackend validates args against published tool schemas");
}

// ── server-side: numeric procedure refuses substring fallback ─────────────
const workdir = await mkdtemp(join(tmpdir(), "hopper-mcp-resolution-"));
const storePath = join(workdir, "store.json");

let archs = [];
try {
  const result = await execFileAsync("lipo", ["-archs", "/bin/ls"]);
  archs = result.stdout.trim().split(/\s+/);
} catch {}
const hasArm64 = archs.some((a) => /^arm64/.test(a));

try {
  const server = spawnServer(storePath);
  try {
    await initialize(server);
    const importResult = await server.callTool("import_macho", {
      executable_path: "/bin/ls",
      max_strings: 50,
      deep: true,
    });
    const sessionId = importResult.session.sessionId;
    const sessionInfo = await server.callTool("capabilities", {});
    assert(sessionInfo.currentSessionId === sessionId, "capabilities reports current session");

    const session = await server.rpc("resources/read", { uri: `hopper://session/current?session_id=${sessionId}` });
    const counts = JSON.parse(session.contents[0].text).counts;
    assert(counts.functions > 0, "deep import populated functions");

    // Pick a function that has a known size (deep mode populates these).
    // Read /functions resource to get full records with size; list_procedures
    // collapses to addr→name pairs.
    const fnResource = await server.rpc("resources/read", { uri: `hopper://functions?session_id=${sessionId}` });
    const allFns = JSON.parse(fnResource.contents[0].text);
    const sizedFn = allFns.find((fn) => fn.size && Number(fn.size) > 8);
    assert(sizedFn, "deep mode produced at least one sized function");

    // 1. procedure() with the exact entrypoint works.
    const info = await server.callTool("procedure", { field: "info", procedure: sizedFn.addr });
    assert(info.entrypoint === sizedFn.addr, "procedure(entrypoint) returns the exact function");
    pass("procedure(entrypoint) returns the exact function");

    // 2. An address inside the function body resolves via range lookup.
    const startAddr = parseInt(sizedFn.addr.replace(/^0x/, ""), 16);
    const innerAddr = `0x${(startAddr + 4).toString(16)}`;
    const innerInfo = await server.callTool("procedure", { field: "info", procedure: innerAddr });
    assert(innerInfo.entrypoint === sizedFn.addr, "procedure(addr+4) finds the containing function");
    pass("procedure(inner address) resolves via range lookup");

    // 3. An obviously-not-mapped address must throw, NOT return some other function.
    const badAddr = "0xdeadbeef";
    let threw = false;
    let errorMessage = null;
    try {
      await server.callTool("procedure", { field: "info", procedure: badAddr });
    } catch (err) {
      threw = true;
      errorMessage = err.message;
    }
    assert(threw, `procedure(${badAddr}) must throw, not silently return`);
    assert(/not the entrypoint|not contained/.test(errorMessage ?? ""), `error message should explain refusal: ${errorMessage}`);
    pass("procedure(bogus address) refuses silent fallback");

    // 4. containing_function returns entrypoint match for the entrypoint.
    const cfEntry = await server.callTool("containing_function", { address: sizedFn.addr });
    assert(cfEntry.match === "entrypoint", "containing_function returns entrypoint match");
    pass("containing_function reports entrypoint match");

    // 5. containing_function returns containment for an interior address.
    const cfInside = await server.callTool("containing_function", { address: innerAddr });
    assert(cfInside.match === "containment", "containing_function recognizes interior address");
    assert(cfInside.offset === 4, `expected offset=4, got ${cfInside.offset}`);
    pass("containing_function reports containment with correct offset");

    // 6. containing_function returns 'none' (with a hint) for unmapped addr.
    const cfNone = await server.callTool("containing_function", { address: badAddr });
    assert(cfNone.match === "none", "containing_function reports none for unmapped addr");
    assert(typeof cfNone.hint === "string" && cfNone.hint.length > 0, "containing_function provides a hint");
    pass("containing_function returns 'none' with a helpful hint");

    if (hasArm64) {
      pass("(deep import ran on ARM64; xref/symbol tests covered above)");
    } else {
      process.stderr.write("  ⊘ skipping ARM64-only assertions (no arm64 slice)\n");
    }
  } finally {
    await server.close();
  }
} finally {
  await rm(workdir, { recursive: true, force: true });
}

process.stderr.write(`\n${passed.length} procedure-resolution test(s) passed.\n`);
