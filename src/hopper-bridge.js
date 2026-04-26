// Bridge to Hopper's official MCP server: fetches an authoritative
// procedure index (entrypoint addr → name/size/[basicblocks/signature/locals])
// that can be fused into our local nm-driven analysis.
//
// importMachO deep mode (when a Hopper backend is wired in) calls this — the
// index is folded into mergeFunctionSets so Hopper's split decisions and
// basicblock counts override our prologue-derived ranges.
//
// We intentionally keep the "lite" fetch path (list_procedures +
// list_procedure_size) as the default — those are O(1) round-trips and
// suffice for the index. procedure_info is one call per procedure, so it's
// gated behind fetchProcedureInfo + maxProcedureInfo to avoid a 5000-call
// stampede on a large binary.

import { basename } from "node:path";
import { officialToolPayload } from "./official-hopper-backend.js";
import { parseAddress, formatAddress } from "./knowledge-store.js";

export async function fetchHopperProcedureIndex(backend, {
  expectedDocument = null,
  documentMustMatch = true,
  fetchProcedureInfo = false,
  maxProcedureInfo = 200,
} = {}) {
  if (!backend) return { reachable: false, reason: "no official backend" };

  let documentName;
  try {
    documentName = await callPayload(backend, "current_document");
  } catch (err) {
    return { reachable: false, reason: `current_document failed: ${truncErr(err)}` };
  }
  if (typeof documentName !== "string" || !documentName) {
    return { reachable: true, documentName: null, procedures: null, reason: "Hopper has no open document" };
  }

  if (expectedDocument) {
    const expectedBase = basename(String(expectedDocument));
    const matches = documentName === expectedBase || documentName === expectedDocument;
    if (!matches && documentMustMatch) {
      return {
        reachable: true,
        documentName,
        procedures: null,
        documentMismatch: { expected: expectedBase, got: documentName },
      };
    }
    if (!matches) {
      // Caller asked us to proceed anyway, but record the mismatch.
      return {
        reachable: true,
        documentName,
        procedures: await loadProcedures(backend, { fetchProcedureInfo, maxProcedureInfo }),
        documentMismatch: { expected: expectedBase, got: documentName },
      };
    }
  }

  return {
    reachable: true,
    documentName,
    procedures: await loadProcedures(backend, { fetchProcedureInfo, maxProcedureInfo }),
  };
}

async function loadProcedures(backend, { fetchProcedureInfo, maxProcedureInfo }) {
  let names;
  try {
    names = await callPayload(backend, "list_procedures");
  } catch (err) {
    return { error: `list_procedures failed: ${truncErr(err)}`, map: new Map() };
  }
  if (!names || typeof names !== "object" || Array.isArray(names)) {
    return { error: "list_procedures returned non-object", map: new Map() };
  }

  let sizes = {};
  try {
    const raw = await callPayload(backend, "list_procedure_size");
    if (raw && typeof raw === "object" && !Array.isArray(raw)) sizes = raw;
  } catch {
    // Tolerate Hopper builds that don't expose list_procedure_size — we'll
    // still return entrypoints+names, just without sizes.
  }

  const map = new Map();
  for (const [addr, name] of Object.entries(names)) {
    const addrNum = parseAddress(addr);
    if (addrNum === null) continue;
    const sizeInfo = sizes?.[addr] ?? sizes?.[formatAddress(addr)] ?? {};
    map.set(addrNum, {
      addrNum,
      addr: formatAddress(addr),
      name: typeof name === "string" ? name : null,
      size: parseSize(sizeInfo?.size),
      basicBlockCount: parseSize(sizeInfo?.basicblock_count),
    });
  }

  if (fetchProcedureInfo) {
    // Hopper's `list_procedure_info` returns full info (signature, locals,
    // basicblocks, length, name) for ALL procedures in a single round-trip.
    // That replaces N round-trips of `procedure_info`, so we always prefer
    // it. The per-procedure fallback below only fires if the bulk call
    // failed — older Hopper builds shipped without `list_procedure_info`.
    const bulk = await tryCall(backend, "list_procedure_info");
    if (bulk && typeof bulk === "object" && !Array.isArray(bulk)) {
      mergeBulkInfo(map, bulk);
    } else if (maxProcedureInfo > 0) {
      const sortedKeys = [...map.keys()].sort((a, b) => a - b).slice(0, maxProcedureInfo);
      for (const key of sortedKeys) {
        const proc = map.get(key);
        const info = await tryCall(backend, "procedure_info", { procedure: proc.addr });
        if (info && typeof info === "object") mergeProcInfo(proc, info);
      }
    }
  }

  return { error: null, map };
}

function mergeBulkInfo(map, bulk) {
  for (const [addr, info] of Object.entries(bulk)) {
    const addrNum = parseAddress(addr);
    if (addrNum === null) continue;
    const proc = map.get(addrNum) ?? {
      addrNum,
      addr: formatAddress(addr),
      name: null,
      size: null,
      basicBlockCount: null,
    };
    mergeProcInfo(proc, info);
    map.set(addrNum, proc);
  }
}

function mergeProcInfo(proc, info) {
  if (!info || typeof info !== "object") return;
  if (typeof info.name === "string" && info.name) proc.name = info.name;
  const length = parseSize(info.length);
  if (length !== null) proc.size = length;
  const bbCount = parseSize(info.basicblock_count);
  if (bbCount !== null) proc.basicBlockCount = bbCount;
  if (info.signature) proc.signature = info.signature;
  if (Array.isArray(info.locals) && info.locals.length) proc.locals = info.locals;
  if (Array.isArray(info.basicblocks)) proc.basicBlocks = info.basicblocks.map(normalizeBlock);
}

async function tryCall(backend, name, args = {}) {
  try {
    return await callPayload(backend, name, args);
  } catch {
    return null;
  }
}

async function callPayload(backend, name, args = {}) {
  return officialToolPayload(await backend.callTool(name, args));
}

function parseSize(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function normalizeBlock(block) {
  if (!block || typeof block !== "object") return block;
  const out = { ...block };
  if (block.from !== undefined) out.from = formatAddress(block.from);
  if (block.to !== undefined) out.to = formatAddress(block.to);
  if (block.addr !== undefined) out.addr = formatAddress(block.addr);
  return out;
}

function truncErr(err) {
  return String(err?.message ?? err).slice(0, 200);
}

// Fetch xrefs for a target address from Hopper's analyzed document. Hopper's
// `xrefs` tool returns instruction-addresses that reference the target —
// strictly more authoritative than otool-scan because Hopper resolves
// indirect-jump tables and runtime-dispatch heuristics that pure
// disassembly can't see.
//
// Returns:
//   { reachable, documentName, documentMismatch?, xrefs: [{addr, function?}],
//     reason? }
// The `function` field is filled when we can resolve the calling procedure
// via Hopper's `procedure_address` (one round-trip per xref). It's gated
// behind resolveCallers so callers can keep the latency bounded.
export async function fetchHopperXrefs(backend, targetAddr, {
  expectedDocument = null,
  documentMustMatch = true,
  resolveCallers = true,
  includeCallees = false,
  maxResults = 100,
} = {}) {
  if (!backend) return { reachable: false, reason: "no official backend" };
  if (!targetAddr) return { reachable: false, reason: "missing target_addr" };

  let documentName;
  try {
    documentName = await callPayload(backend, "current_document");
  } catch (err) {
    return { reachable: false, reason: `current_document failed: ${truncErr(err)}` };
  }
  if (typeof documentName !== "string" || !documentName) {
    return { reachable: true, documentName: null, xrefs: null, reason: "Hopper has no open document" };
  }
  if (documentMustMatch && expectedDocument) {
    const expectedBase = basename(String(expectedDocument));
    if (documentName !== expectedBase && documentName !== expectedDocument) {
      return {
        reachable: true,
        documentName,
        xrefs: null,
        documentMismatch: { expected: expectedBase, got: documentName },
      };
    }
  }

  const target = formatAddress(targetAddr);
  let raw;
  try {
    raw = await callPayload(backend, "xrefs", { address: target });
  } catch (err) {
    return { reachable: true, documentName, xrefs: null, reason: `xrefs failed: ${truncErr(err)}` };
  }

  // Hopper returns either an array of addrs or null/empty when nothing.
  const list = Array.isArray(raw) ? raw : [];
  const out = [];
  const seen = new Set();
  for (const ref of list) {
    const addr = formatAddress(ref);
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    out.push({ addr });
    if (out.length >= maxResults) break;
  }

  let callerProcedures = null;
  if (resolveCallers) {
    // Hopper's `procedure_callers` is the documented tool for "what procedures
    // call X" — strictly better than calling `procedure_address` per xref,
    // which fails when an instruction address falls outside any tracked
    // procedure (real /bin/ls case: xrefs returned 6 instr addrs, none of
    // which resolved via procedure_address). procedure_callers returns names;
    // we resolve names→addresses by looking them up in list_procedures.
    const callers = await tryCall(backend, "procedure_callers", { procedure: target });
    if (Array.isArray(callers) && callers.length) {
      const procs = await tryCall(backend, "list_procedures") ?? {};
      const nameToAddr = new Map();
      for (const [addr, name] of Object.entries(procs)) {
        if (typeof name === "string") nameToAddr.set(name, formatAddress(addr));
      }
      callerProcedures = callers.map((name) => ({
        name,
        addr: nameToAddr.get(name) ?? null,
      })).filter((c) => c.addr || c.name);
    }
    // Best-effort per-xref attribution as a secondary pass — only fires for
    // xrefs whose instruction address actually maps to a tracked procedure.
    for (const x of out) {
      const fn = await tryCall(backend, "procedure_address", { procedure: x.addr });
      if (fn) {
        const resolved = formatAddress(fn);
        if (resolved && resolved !== "null") x.function = resolved;
      }
    }
  }

  let calleeProcedures = null;
  if (includeCallees) {
    // Forward direction: what does THIS procedure call? Useful when the
    // caller wants the local call-graph slice in a single round-trip.
    const callees = await tryCall(backend, "procedure_callees", { procedure: target });
    if (Array.isArray(callees) && callees.length) {
      const procs = await tryCall(backend, "list_procedures") ?? {};
      const nameToAddr = new Map();
      for (const [addr, name] of Object.entries(procs)) {
        if (typeof name === "string") nameToAddr.set(name, formatAddress(addr));
      }
      calleeProcedures = callees.map((name) => ({
        name,
        addr: nameToAddr.get(name) ?? null,
      })).filter((c) => c.addr || c.name);
    } else if (Array.isArray(callees)) {
      calleeProcedures = [];
    }
  }

  return { reachable: true, documentName, xrefs: out, callerProcedures, calleeProcedures };
}

// Fetch Hopper's full named-address dictionary (labels for procs, vars,
// string-pool entries, sections, etc.). On /bin/ls this returns 486 entries
// in ~3ms — strictly more than what we get from nm because Hopper's analyzer
// labels post-discovery targets too. Returns Map<addrNum, name>.
export async function fetchHopperNames(backend, {
  expectedDocument = null,
  documentMustMatch = true,
} = {}) {
  if (!backend) return { reachable: false, reason: "no official backend" };
  const docCheck = await ensureDocument(backend, { expectedDocument, documentMustMatch });
  if (!docCheck.ok) return docCheck.result;
  const raw = await tryCall(backend, "list_names");
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { reachable: true, documentName: docCheck.documentName, names: null, reason: "list_names returned non-object" };
  }
  const map = new Map();
  for (const [addr, name] of Object.entries(raw)) {
    if (typeof name !== "string" || !name) continue;
    const addrNum = parseAddress(addr);
    if (addrNum === null) continue;
    map.set(addrNum, name);
  }
  return { reachable: true, documentName: docCheck.documentName, names: map };
}

// Internal helper: shared document-check logic for the new fetchers, so each
// returns {ok, result, documentName} consistently. Keeping it here avoids
// repeating six lines across four functions.
async function ensureDocument(backend, { expectedDocument, documentMustMatch }) {
  let documentName;
  try {
    documentName = await callPayload(backend, "current_document");
  } catch (err) {
    return { ok: false, result: { reachable: false, reason: `current_document failed: ${truncErr(err)}` } };
  }
  if (typeof documentName !== "string" || !documentName) {
    return { ok: false, result: { reachable: true, documentName: null, reason: "Hopper has no open document" } };
  }
  if (documentMustMatch && expectedDocument) {
    const expectedBase = basename(String(expectedDocument));
    if (documentName !== expectedBase && documentName !== expectedDocument) {
      return {
        ok: false,
        result: {
          reachable: true,
          documentName,
          documentMismatch: { expected: expectedBase, got: documentName },
        },
      };
    }
  }
  return { ok: true, documentName };
}
