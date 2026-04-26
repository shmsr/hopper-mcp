// Real-application dogfood for the three Hopper optimizations.
//
//   (1) bulk list_procedure_info vs per-procedure procedure_info
//   (2) batched set_addresses_names vs single set_address_name
//   (3) Hopper-analyzed xrefs vs otool-scanned xrefs
//
// Prerequisites:
//   - Hopper Disassembler is running with a real Mach-O loaded (not "Untitled").
//   - The same binary is readable on disk so we can run our local importer.
//
// Usage:
//   HOPPER_REAL_BINARY=/path/to/binary node test/hopper-real-app.mjs
//
// Or omit HOPPER_REAL_BINARY to auto-resolve from Hopper's current_document
// against a search list of common system binaries.

import { OfficialHopperBackend, officialToolPayload } from "../src/official-hopper-backend.js";
import {
  fetchHopperProcedureIndex,
  fetchHopperXrefs,
  computeProcedureDrift,
  fetchHopperDecompilation,
  fetchHopperAssembly,
  fetchHopperCallees,
  fetchHopperNames,
  clearHopperCaches,
} from "../src/hopper-bridge.js";
import { importMachO } from "../src/macho-importer.js";
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { performance } from "node:perf_hooks";

const SEARCH_PATHS = [
  process.env.HOPPER_REAL_BINARY,
  "/bin/ls", "/bin/cat", "/bin/echo", "/usr/bin/grep", "/usr/bin/file",
  "/usr/bin/otool", "/usr/bin/nm",
].filter(Boolean);

function fmt(n) {
  return typeof n === "number" ? n.toLocaleString() : String(n);
}

async function main() {
  const backend = new OfficialHopperBackend({ timeoutMs: 60_000 });
  try {
    const docName = officialToolPayload(await backend.callTool("current_document"));
    if (!docName || docName === "Untitled") {
      console.log("[skip] Hopper has no real document loaded (current_document =", JSON.stringify(docName), ")");
      console.log("       Load a Mach-O binary in the Hopper GUI and re-run.");
      return;
    }
    console.log(`# Hopper has '${docName}' loaded.`);

    let binaryPath = process.env.HOPPER_REAL_BINARY ?? null;
    if (!binaryPath) {
      for (const p of SEARCH_PATHS) {
        if (basename(p) === docName && existsSync(p)) { binaryPath = p; break; }
      }
    }
    if (!binaryPath || !existsSync(binaryPath)) {
      console.log(`[skip] Cannot find on-disk match for '${docName}'.`);
      console.log("       Set HOPPER_REAL_BINARY=/abs/path and re-run.");
      return;
    }
    console.log(`# Resolved on-disk binary: ${binaryPath}\n`);

    // ── (1) Bulk list_procedure_info vs per-procedure round-trips ─────────
    console.log("## (1) Bulk list_procedure_info vs per-procedure procedure_info");
    const t0 = performance.now();
    const idxBulk = await fetchHopperProcedureIndex(backend, {
      expectedDocument: binaryPath,
      fetchProcedureInfo: true,
    });
    const tBulk = performance.now() - t0;
    if (!idxBulk.procedures || idxBulk.procedures.error) {
      console.log("  [error]", idxBulk.reason ?? idxBulk.procedures?.error);
      return;
    }
    const map = idxBulk.procedures.map;
    const enriched = [...map.values()].filter((p) => p.basicBlocks || p.locals || p.signature);
    console.log(`  bulk path: ${fmt(map.size)} procedures, ${fmt(enriched.length)} enriched in ${tBulk.toFixed(0)}ms`);

    // Cap a per-procedure comparison to a small sample so we don't pay N
    // round-trips against a multi-thousand-procedure binary.
    const sampleAddrs = [...map.keys()].sort((a, b) => a - b).slice(0, 25);
    const t1 = performance.now();
    let perProcEnriched = 0;
    for (const addrNum of sampleAddrs) {
      const proc = map.get(addrNum);
      const info = officialToolPayload(await backend.callTool("procedure_info", { procedure: proc.addr }));
      if (info && (info.basicblocks || info.locals || info.signature)) perProcEnriched++;
    }
    const tPer = performance.now() - t1;
    console.log(`  per-proc sample: ${fmt(perProcEnriched)}/${sampleAddrs.length} enriched in ${tPer.toFixed(0)}ms (${(tPer / sampleAddrs.length).toFixed(1)}ms/call)`);
    const projectedFull = (tPer / sampleAddrs.length) * map.size;
    console.log(`  → projected full per-proc walk: ${(projectedFull / 1000).toFixed(1)}s, bulk wins by ${(projectedFull / tBulk).toFixed(1)}×\n`);

    // ── Local importer + drift report ──────────────────────────────────────
    console.log("## Local importer + drift");
    const localSession = await importMachO(binaryPath, { deep: true });
    console.log(`  local: ${fmt(localSession.functions.length)} functions`);
    const drift = computeProcedureDrift(localSession, idxBulk, { maxPerCategory: 5 });
    if (!drift.ok) {
      console.log("  [error]", drift.reason);
    } else {
      console.log("  drift summary:", JSON.stringify(drift.summary));
      if (drift.drift.insideHopperProc?.length) {
        console.log("  insideHopperProc (first 3):", drift.drift.insideHopperProc.slice(0, 3));
      }
      if (drift.drift.sizeDrift.length) {
        console.log("  sample sizeDrift:", drift.drift.sizeDrift.slice(0, 3));
      }
      if (drift.drift.nameDrift.length) {
        console.log("  sample nameDrift:", drift.drift.nameDrift.slice(0, 3));
      }
    }
    console.log("");

    // ── (2) Batched set_addresses_names vs single set_address_name ────────
    console.log("## (2) Batched rename via set_addresses_names");
    const candidates = [...map.values()].filter((p) => p.name && /^sub_/.test(p.name)).slice(0, 5);
    if (!candidates.length) {
      console.log("  [skip] no sub_* placeholders to rename in this binary.");
    } else if (process.env.HOPPER_MCP_ENABLE_OFFICIAL_WRITES !== "1") {
      console.log(`  [skip] set HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 to actually rename ${candidates.length} placeholders.`);
      console.log(`  (would batch: ${candidates.map((c) => c.addr).join(", ")})`);
    } else {
      // Re-instantiate backend with writes enabled.
      const writer = new OfficialHopperBackend({ timeoutMs: 60_000, enableWrites: true });
      try {
        const originals = candidates.map((c) => ({ addr: c.addr, name: c.name }));
        const transaction = {
          id: "real-app-batch-rename",
          operations: candidates.map((c, i) => ({
            operationId: `op-${i}`, kind: "rename", addr: c.addr,
            previousValue: c.name, newValue: `${c.name}_dogfood`,
          })),
        };
        const tBatch0 = performance.now();
        const batchResult = await writer.applyTransaction(null, transaction, { confirmLiveWrite: true });
        const tBatch = performance.now() - tBatch0;
        const distinctTools = new Set(batchResult.operations.map((op) => op.tool));
        console.log(`  batched ${candidates.length} renames in ${tBatch.toFixed(0)}ms via ${[...distinctTools].join(",")}`);
        console.log(`  operations[0]:`, JSON.stringify({ ...batchResult.operations[0], result: undefined }));

        // Restore originals — best effort.
        const restoreTx = {
          id: "real-app-batch-rename-restore",
          operations: originals.map((o, i) => ({
            operationId: `restore-${i}`, kind: "rename", addr: o.addr,
            previousValue: `${o.name}_dogfood`, newValue: o.name,
          })),
        };
        await writer.applyTransaction(null, restoreTx, { confirmLiveWrite: true });
        console.log("  restored original names.");
      } finally {
        writer.close();
      }
    }
    console.log("");

    // ── (3) Hopper-analyzed xrefs vs otool ────────────────────────────────
    console.log("## (3) Hopper xrefs (analyzed) vs otool fallback");
    // Probe several candidates — entrypoints typically have 0 internal xrefs
    // (called by kernel/dyld), so we want a hot helper instead.
    const candidatesXref = [...map.values()]
      .filter((p) => p.name && !/^EntryPoint/i.test(p.name) && p.size && p.size > 32)
      .slice(0, 20);
    let bestXrefs = null;
    for (const cand of candidatesXref) {
      const r = await fetchHopperXrefs(backend, cand.addr, {
        expectedDocument: binaryPath, resolveCallers: false, maxResults: 50,
      });
      if (r.xrefs && r.xrefs.length && (!bestXrefs || r.xrefs.length > bestXrefs.count)) {
        bestXrefs = { target: cand, count: r.xrefs.length };
        if (r.xrefs.length >= 5) break;
      }
    }
    if (!bestXrefs) {
      console.log("  [skip] no procedure with internal xrefs found in first 20 candidates.");
    } else {
      const t = bestXrefs.target;
      console.log(`  target: ${t.name} @ ${t.addr} (size=${t.size}, ${bestXrefs.count} xrefs from probe)`);
      const tx0 = performance.now();
      const hopperX = await fetchHopperXrefs(backend, t.addr, {
        expectedDocument: binaryPath, resolveCallers: true, maxResults: 50,
      });
      const tx1 = performance.now() - tx0;
      const callers = hopperX.xrefs.filter((x) => x.function).length;
      console.log(`  hopper-analyzed: ${hopperX.xrefs.length} xrefs (${callers} per-instr resolved) in ${tx1.toFixed(0)}ms`);
      console.log("  sample xrefs:", hopperX.xrefs.slice(0, 3));
      if (hopperX.callerProcedures?.length) {
        console.log(`  callerProcedures: ${hopperX.callerProcedures.length} procs`);
        console.log("  sample callerProcedures:", hopperX.callerProcedures.slice(0, 3));
      } else {
        console.log("  callerProcedures: (none reported by Hopper procedure_callers)");
      }
    }
    // ── (4) hopper_decompile + cache ──────────────────────────────────────
    console.log("\n## (4) hopper_decompile (procedure_pseudo_code + cache)");
    // Pick a small procedure (≤50 BB) so pseudo_code is fast.
    const small = [...map.values()]
      .filter((p) => p.basicBlockCount && p.basicBlockCount <= 50 && p.size && p.size > 16)
      .sort((a, b) => a.basicBlockCount - b.basicBlockCount)[0];
    if (!small) {
      console.log("  [skip] no procedure with basicBlockCount ≤ 50 found.");
    } else {
      clearHopperCaches();
      const td0 = performance.now();
      const dec1 = await fetchHopperDecompilation(backend, small.addr, {
        expectedDocument: binaryPath,
      });
      const td1 = performance.now() - td0;
      const td2 = performance.now();
      const dec2 = await fetchHopperDecompilation(backend, small.addr, {
        expectedDocument: binaryPath,
      });
      const td3 = performance.now() - td2;
      console.log(`  target: ${small.name} @ ${small.addr} (${small.basicBlockCount} BBs)`);
      console.log(`  cold:   ${dec1.decompilation ? `${dec1.decompilation.length} chars` : "no result"} in ${td1.toFixed(0)}ms`);
      console.log(`  warm:   cached=${dec2.cached === true} in ${td3.toFixed(0)}ms`);
      if (dec1.decompilation) {
        const head = dec1.decompilation.split("\n").slice(0, 4).join(" | ");
        console.log(`  preview: ${head.slice(0, 140)}${head.length > 140 ? "…" : ""}`);
      }
    }

    // ── BB guard against EntryPoint or another oversize proc ──────────────
    const big = [...map.values()].find((p) => p.basicBlockCount && p.basicBlockCount > 100);
    if (big) {
      const guarded = await fetchHopperDecompilation(backend, big.addr, {
        expectedDocument: binaryPath,
        maxBasicBlocks: 50,
      });
      console.log(`  BB guard: ${big.name} (${big.basicBlockCount} BBs) → decompilation=${guarded.decompilation === null ? "null" : "computed"}, reason="${guarded.reason ?? "n/a"}"`);
    }
    console.log("");

    // ── (5) hopper_assembly + cache ───────────────────────────────────────
    console.log("## (5) hopper_assembly (procedure_assembly + cache)");
    const asmTarget = small ?? [...map.values()].find((p) => p.size && p.size > 16);
    if (!asmTarget) {
      console.log("  [skip] no procedure available for assembly.");
    } else {
      clearHopperCaches();
      const ta0 = performance.now();
      const asm1 = await fetchHopperAssembly(backend, asmTarget.addr, { expectedDocument: binaryPath });
      const ta1 = performance.now() - ta0;
      const ta2 = performance.now();
      const asm2 = await fetchHopperAssembly(backend, asmTarget.addr, { expectedDocument: binaryPath });
      const ta3 = performance.now() - ta2;
      console.log(`  target: ${asmTarget.name} @ ${asmTarget.addr}`);
      console.log(`  cold:   ${asm1.assembly ? `${asm1.assembly.length} chars` : "no result"} in ${ta1.toFixed(0)}ms`);
      console.log(`  warm:   cached=${asm2.cached === true} in ${ta3.toFixed(0)}ms`);
    }
    console.log("");

    // ── (6) hopper_callees ────────────────────────────────────────────────
    console.log("## (6) hopper_callees (forward call-graph slice)");
    let calleeProbe = null;
    for (const cand of [...map.values()].filter((p) => p.name && p.size && p.size > 32).slice(0, 20)) {
      const r = await fetchHopperCallees(backend, cand.addr, { expectedDocument: binaryPath });
      if (r.callees && r.callees.length) { calleeProbe = { target: cand, result: r }; break; }
    }
    if (!calleeProbe) {
      console.log("  [skip] no procedure with detectable callees in first 20 candidates.");
    } else {
      const { target: t, result: r } = calleeProbe;
      console.log(`  target: ${t.name} @ ${t.addr}`);
      console.log(`  callees: ${r.callees.length} unique`);
      console.log("  sample:", r.callees.slice(0, 5));
    }
    console.log("");

    // ── (7) find_xrefs include_callees integration ────────────────────────
    console.log("## (7) find_xrefs include_callees");
    if (calleeProbe && bestXrefs) {
      const t = calleeProbe.target;
      const xRes = await fetchHopperXrefs(backend, t.addr, {
        expectedDocument: binaryPath,
        resolveCallers: true,
        includeCallees: true,
        maxResults: 25,
      });
      console.log(`  ${t.name}: callerProcedures=${xRes.callerProcedures?.length ?? 0}, calleeProcedures=${xRes.calleeProcedures?.length ?? 0}`);
    } else {
      console.log("  [skip] no good combined target.");
    }
    console.log("");

    // ── (8) hopper_include_names ingestion via importMachO ────────────────
    console.log("## (8) list_names ingestion (Hopper labels for strings + procs)");
    const namesResult = await fetchHopperNames(backend, { expectedDocument: binaryPath });
    if (!namesResult.names) {
      console.log("  [skip] list_names not available:", namesResult.reason);
    } else {
      console.log(`  Hopper exports ${namesResult.names.size} named addresses.`);
      const tn0 = performance.now();
      const labelledSession = await importMachO(binaryPath, {
        deep: true,
        hopperIndex: idxBulk.procedures.map,
        hopperLabels: namesResult.names,
        maxStrings: 200,
      });
      const tn1 = performance.now() - tn0;
      const labelledStrings = labelledSession.strings.filter((s) => s.hopperLabel);
      console.log(`  importMachO with hopperLabels: ${tn1.toFixed(0)}ms`);
      console.log(`  strings annotated with hopperLabel: ${labelledStrings.length}/${labelledSession.strings.length}`);
      if (labelledStrings.length) {
        console.log("  sample labelled strings:", labelledStrings.slice(0, 3).map((s) => ({ addr: s.addr, label: s.hopperLabel, value: (s.value ?? "").slice(0, 30) })));
      }
      console.log(`  serialized session.hopperLabels: ${labelledSession.hopperLabels ? Object.keys(labelledSession.hopperLabels).length + " entries" : "null"}`);
    }

    console.log("\n# Real-app dogfood complete.");
  } finally {
    backend.close();
  }
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
