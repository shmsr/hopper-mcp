// Bridge to Hopper's official MCP server: fetches an authoritative
// procedure index (entrypoint addr → name/size/[basicblocks/signature/locals])
// that can be fused into our local nm-driven analysis.
//
// Two callers use this:
//   1. importMachO deep mode (when a Hopper backend is wired in) — the index
//      is folded into mergeFunctionSets so Hopper's split decisions and
//      basicblock counts override our prologue-derived ranges.
//   2. compare_with_hopper diagnostic — runs the local pipeline and the
//      Hopper index side-by-side and reports the drift.
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

// Compute drift between a local importMachO session and a Hopper index. Used
// by the compare_with_hopper diagnostic tool. Returns a structured report
// with totals and capped per-category drift lists.
export function computeProcedureDrift(localSession, hopperResult, { maxPerCategory = 100 } = {}) {
  const localByAddr = new Map();
  for (const fn of localSession.functions ?? []) {
    if (!fn?.addr) continue;
    if (/^0xfff[0-9a-f]+$/.test(fn.addr)) continue;
    if (fn.source === "semantic-import-cluster") continue;
    const addrNum = parseAddress(fn.addr);
    if (addrNum === null) continue;
    localByAddr.set(addrNum, fn);
  }

  const hopperMap = hopperResult?.procedures?.map ?? null;
  if (!hopperMap) {
    return {
      ok: false,
      reason: hopperResult?.reason
        ?? hopperResult?.procedures?.error
        ?? "no Hopper procedures available",
      documentName: hopperResult?.documentName ?? null,
      summary: { local: { count: localByAddr.size }, hopper: null },
    };
  }

  const localOnly = [];
  const hopperOnly = [];
  const sizeDrift = [];
  const nameDrift = [];
  let matched = 0;

  for (const [addrNum, hop] of hopperMap) {
    const lf = localByAddr.get(addrNum);
    if (!lf) {
      hopperOnly.push({ addr: formatAddress(addrNum), name: hop.name, size: hop.size });
      continue;
    }
    matched++;
    const lfSize = Number(lf.size);
    if (hop.size && Number.isFinite(lfSize) && lfSize > 0 && hop.size !== lfSize) {
      sizeDrift.push({
        addr: formatAddress(addrNum),
        local: lfSize,
        hopper: hop.size,
        delta: hop.size - lfSize,
      });
    }
    if (hop.name && lf.name && hop.name !== lf.name) {
      nameDrift.push({ addr: formatAddress(addrNum), local: lf.name, hopper: hop.name });
    }
  }

  // Pre-sort Hopper entries by addr so we can binary-search "what proc
  // contains this local entry?" — important for /bin/ls-style binaries
  // where our prologue scanner finds entries inside Hopper procedures
  // (false splits). Without this, the entire drift looks like 'localOnly'
  // and the user can't tell systematic over-discovery from genuine misses.
  const hopperSorted = [...hopperMap.values()].sort((a, b) => a.addrNum - b.addrNum);
  const insideHopperProc = [];

  for (const [addrNum, lf] of localByAddr) {
    if (hopperMap.has(addrNum)) continue;
    const containing = findContainingProc(hopperSorted, addrNum);
    if (containing) {
      insideHopperProc.push({
        addr: formatAddress(addrNum),
        localName: lf.name,
        hopperProc: containing.name ?? formatAddress(containing.addrNum),
        hopperProcAddr: formatAddress(containing.addrNum),
        offsetIntoHopperProc: addrNum - containing.addrNum,
      });
    } else {
      localOnly.push({
        addr: formatAddress(addrNum),
        name: lf.name,
        size: lf.size ?? null,
        source: lf.source ?? null,
      });
    }
  }

  return {
    ok: true,
    documentName: hopperResult?.documentName ?? null,
    documentMismatch: hopperResult?.documentMismatch ?? null,
    summary: {
      local: { count: localByAddr.size },
      hopper: { count: hopperMap.size },
      matched,
      localOnly: localOnly.length,
      insideHopperProc: insideHopperProc.length,
      hopperOnly: hopperOnly.length,
      sizeDrift: sizeDrift.length,
      nameDrift: nameDrift.length,
    },
    drift: {
      localOnly: cap(localOnly, maxPerCategory),
      insideHopperProc: cap(insideHopperProc, maxPerCategory),
      hopperOnly: cap(hopperOnly, maxPerCategory),
      sizeDrift: cap(sizeDrift, maxPerCategory),
      nameDrift: cap(nameDrift, maxPerCategory),
    },
  };
}

function findContainingProc(sorted, addrNum) {
  // Binary search for greatest entry whose addrNum <= target. Then check that
  // target falls inside its [addrNum, addrNum + size) range when size is known.
  let lo = 0;
  let hi = sorted.length - 1;
  let candidate = null;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (sorted[mid].addrNum <= addrNum) {
      candidate = sorted[mid];
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  if (!candidate || candidate.addrNum === addrNum) return null;
  if (candidate.size && addrNum < candidate.addrNum + candidate.size) return candidate;
  // Fallback when Hopper didn't supply a size: cap by next proc's addr.
  if (!candidate.size) {
    const idx = sorted.indexOf(candidate);
    const next = sorted[idx + 1];
    if (next && addrNum < next.addrNum) return candidate;
  }
  return null;
}

function cap(list, n) {
  if (!Number.isFinite(n) || n <= 0) return list;
  return list.length <= n ? list : list.slice(0, n);
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

// Fetch the procedures called BY a given target (forward call graph).
// `procedure_callees` returns an array of names; we resolve to entrypoint
// addresses via list_procedures so callers can navigate. Returns null when
// Hopper isn't reachable / doc mismatched / target isn't a procedure.
export async function fetchHopperCallees(backend, targetAddr, {
  expectedDocument = null,
  documentMustMatch = true,
  maxResults = 200,
} = {}) {
  if (!backend) return { reachable: false, reason: "no official backend" };
  const docCheck = await ensureDocument(backend, { expectedDocument, documentMustMatch });
  if (!docCheck.ok) return docCheck.result;

  const target = formatAddress(targetAddr);
  const callees = await tryCall(backend, "procedure_callees", { procedure: target });
  if (!Array.isArray(callees)) {
    return { reachable: true, documentName: docCheck.documentName, callees: null, reason: "procedure_callees returned non-array" };
  }
  const procs = await tryCall(backend, "list_procedures") ?? {};
  const nameToAddr = new Map();
  for (const [addr, name] of Object.entries(procs)) {
    if (typeof name === "string") nameToAddr.set(name, formatAddress(addr));
  }
  const out = [];
  const seen = new Set();
  for (const name of callees) {
    if (typeof name !== "string" || seen.has(name)) continue;
    seen.add(name);
    out.push({ name, addr: nameToAddr.get(name) ?? null });
    if (out.length >= maxResults) break;
  }
  return { reachable: true, documentName: docCheck.documentName, callees: out };
}

// Caches for procedure_pseudo_code and procedure_assembly. Both are
// deterministic per (docName, procAddr) within a single Hopper session — but
// can be invalidated when the user re-analyzes. We key by docName+addr and
// stamp with a fingerprint of `list_procedure_size` so that a rename or
// re-analysis at the user's end forces a refetch on the next call.
const decompileCache = new Map();
const assemblyCache = new Map();

async function fingerprintDoc(backend, documentName) {
  // list_procedure_size is the cheapest "did anything in the procedure space
  // change?" probe — 2ms on /bin/ls. Hash its size+name dictionary into a
  // short fingerprint string. We don't include data sections because they
  // don't affect decompilation/assembly.
  const sizes = await tryCall(backend, "list_procedure_size") ?? {};
  let acc = 0;
  for (const [addr, info] of Object.entries(sizes)) {
    const n = info?.name ?? "";
    const s = info?.size ?? 0;
    // Cheap polynomial hash; collisions only matter if the user RE-analyzes
    // and Hopper happens to land on identical sizes+names — which is a fine
    // tradeoff for a cache invalidator.
    for (const ch of `${addr}|${n}|${s};`) acc = (acc * 31 + ch.charCodeAt(0)) | 0;
  }
  return `${documentName}#${(acc >>> 0).toString(16)}`;
}

export async function fetchHopperDecompilation(backend, procedureAddr, {
  expectedDocument = null,
  documentMustMatch = true,
  useCache = true,
  maxBasicBlocks = 250,
} = {}) {
  if (!backend) return { reachable: false, reason: "no official backend" };
  const docCheck = await ensureDocument(backend, { expectedDocument, documentMustMatch });
  if (!docCheck.ok) return docCheck.result;

  const proc = formatAddress(procedureAddr);
  const fingerprint = useCache ? await fingerprintDoc(backend, docCheck.documentName) : null;
  const key = `${fingerprint}::${proc}`;
  if (useCache && decompileCache.has(key)) {
    return { ...decompileCache.get(key), cached: true };
  }

  // Guard: pseudo_code is the slowest tool by far (5s on EntryPoint with 153
  // basic blocks). Hopper's docs explicitly recommend <50 basic blocks.
  // Probe procedure_info first and bail if too complex.
  const info = await tryCall(backend, "procedure_info", { procedure: proc });
  if (!info || typeof info !== "object") {
    return { reachable: true, documentName: docCheck.documentName, decompilation: null, reason: `no procedure at ${proc}` };
  }
  if (info.basicblock_count && info.basicblock_count > maxBasicBlocks) {
    return {
      reachable: true,
      documentName: docCheck.documentName,
      decompilation: null,
      reason: `procedure has ${info.basicblock_count} basic blocks (> ${maxBasicBlocks}); pseudo-code generation is too slow. Increase max_basic_blocks to override.`,
      basicBlockCount: info.basicblock_count,
    };
  }

  let pseudo;
  try {
    pseudo = await callPayload(backend, "procedure_pseudo_code", { procedure: proc });
  } catch (err) {
    return { reachable: true, documentName: docCheck.documentName, decompilation: null, reason: `procedure_pseudo_code failed: ${truncErr(err)}` };
  }
  const result = {
    reachable: true,
    documentName: docCheck.documentName,
    procedure: proc,
    name: info.name ?? null,
    signature: info.signature ?? null,
    basicBlockCount: info.basicblock_count ?? null,
    decompilation: typeof pseudo === "string" ? pseudo : String(pseudo ?? ""),
  };
  if (useCache) decompileCache.set(key, result);
  return result;
}

export async function fetchHopperAssembly(backend, procedureAddr, {
  expectedDocument = null,
  documentMustMatch = true,
  useCache = true,
} = {}) {
  if (!backend) return { reachable: false, reason: "no official backend" };
  const docCheck = await ensureDocument(backend, { expectedDocument, documentMustMatch });
  if (!docCheck.ok) return docCheck.result;

  const proc = formatAddress(procedureAddr);
  const fingerprint = useCache ? await fingerprintDoc(backend, docCheck.documentName) : null;
  const key = `${fingerprint}::${proc}`;
  if (useCache && assemblyCache.has(key)) {
    return { ...assemblyCache.get(key), cached: true };
  }

  const info = await tryCall(backend, "procedure_info", { procedure: proc });
  if (!info || typeof info !== "object") {
    return { reachable: true, documentName: docCheck.documentName, assembly: null, reason: `no procedure at ${proc}` };
  }

  let asm;
  try {
    asm = await callPayload(backend, "procedure_assembly", { procedure: proc });
  } catch (err) {
    return { reachable: true, documentName: docCheck.documentName, assembly: null, reason: `procedure_assembly failed: ${truncErr(err)}` };
  }
  const result = {
    reachable: true,
    documentName: docCheck.documentName,
    procedure: proc,
    name: info.name ?? null,
    length: info.length ?? null,
    basicBlockCount: info.basicblock_count ?? null,
    assembly: typeof asm === "string" ? asm : String(asm ?? ""),
  };
  if (useCache) assemblyCache.set(key, result);
  return result;
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

// Clear the in-memory caches; mainly for tests + a future "reload" tool.
export function clearHopperCaches() {
  decompileCache.clear();
  assemblyCache.clear();
}
