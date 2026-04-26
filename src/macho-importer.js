import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { basename } from "node:path";
import { promisify } from "node:util";
import {
  classifyImports,
  detectAntiAnalysis,
  computeSectionEntropy,
  extractCodeSigning,
  extractObjCRuntime,
  computeImphash,
  buildFunctionFingerprint,
  discoverX86Functions,
} from "./research-tools.js";

const execFileAsync = promisify(execFile);
const PREFERRED_ARCHS = ["arm64e", "arm64", "x86_64"];

export async function importMachO(path, {
  arch = "auto",
  maxStrings = 5000,
  deep = false,
  maxFunctions = 30000,
  includeSigning = true,
  includeEntropy = true,
  includeObjC = true,
  hopperIndex = null,
  hopperLabels = null,
} = {}) {
  if (!path || typeof path !== "string") {
    throw new Error("import_macho requires executable_path (string).");
  }
  const archSelection = await resolveMachOArch(path, arch);
  const selectedArch = archSelection.arch;
  const [fileInfo, libraries, symbols, stringRows, loadCommands] = await Promise.all([
    run("file", [path]),
    run("otool", ["-arch", selectedArch, "-L", path]),
    run("nm", ["-arch", selectedArch, "-m", path], { maxBuffer: 64 * 1024 * 1024 }),
    run("strings", ["-a", "-t", "x", "-n", "8", path], { maxBuffer: 128 * 1024 * 1024 }),
    run("otool", ["-arch", selectedArch, "-l", path], { maxBuffer: 64 * 1024 * 1024 }),
  ]);

  const parsedSymbols = parseNm(symbols.stdout);
  const imports = parsedSymbols.imports;
  // Cap was historically 1000 (small Apple binaries), but stripped-but-still-
  // mangled Rust/Swift binaries routinely have tens of thousands of local
  // text symbols. Slicing too low means real function names like
  // __ZN13cursorsandbox5macos22apply_sandbox_and_exec... never enter the
  // session and the user gets `sub_<addr>` placeholders. Mirror maxFunctions.
  const exportedFunctions = parsedSymbols.defined.slice(0, Math.max(1000, maxFunctions));
  const loadCommandData = parseLoadCommands(loadCommands.stdout);
  const strings = parseStringsWithOffsets(stringRows.stdout, maxStrings, loadCommandData.offsetMaps);
  const dylibs = parseDylibs(libraries.stdout);
  const binaryId = createHash("sha256").update(`${path}:${selectedArch}:${fileInfo.stdout}`).digest("hex").slice(0, 16);

  let functions = buildFunctions({ exportedFunctions, imports, strings, dylibs });

  if (deep) {
    const isIntel = /^(?:x86_64|x86_64h|i386)$/.test(selectedArch);
    const discovery = isIntel
      ? await discoverX86Functions(path, { arch: selectedArch, maxFunctions })
      : await discoverFunctionsFromDisassembly(path, { arch: selectedArch, maxFunctions });
    // Use the __TEXT,__text section end to cap the last function's size when
    // there's no successor entry to compute a gap against.
    const textSection = (loadCommandData.segments ?? [])
      .flatMap((seg) => (seg.sections ?? []).map((sec) => ({ ...sec, segname: seg.name })))
      .find((sec) => sec.segname === "__TEXT" && (sec.name === "__text" || sec.name === "text"));
    const textEnd = textSection ? hexToInt(textSection.end) : null;
    functions = mergeFunctionSets(functions, discovery, strings, { textEnd, hopperIndex });
  }

  const capabilities = classifyImports(imports);
  const sessionImports = imports;
  for (const fn of functions) {
    fn.fingerprint = buildFunctionFingerprint(fn, sessionImports);
    if (fn.imports?.length) {
      fn.capabilityTags = capabilityTagsFor(fn.imports, capabilities);
    }
  }

  const objcClasses = includeObjC
    ? await safe(() => extractObjCRuntime(path, selectedArch, { maxClasses: 1000 }), inferObjCClasses(strings))
    : inferObjCClasses(strings);

  const signing = includeSigning ? await safe(() => extractCodeSigning(path), null) : null;
  const sectionEntropy = includeEntropy ? await safe(() => computeSectionEntropy(path, selectedArch), []) : [];

  const sessionStub = { imports, strings };
  const antiAnalysisFindings = detectAntiAnalysis(sessionStub);
  const imphash = computeImphash(imports);

  // Annotate strings with Hopper labels when present. Hopper assigns
  // synthetic labels like `aUsrlibdyld` to string-pool entries that nm
  // doesn't know about — exposing them lets users search by Hopper label.
  if (hopperLabels instanceof Map && hopperLabels.size && Array.isArray(strings)) {
    for (const s of strings) {
      const addrNum = hexToInt(s.addr ?? s.address);
      if (addrNum === null) continue;
      const label = hopperLabels.get(addrNum);
      if (label) s.hopperLabel = label;
    }
  }

  return {
    sessionId: `real-${binaryId}`,
    binaryId,
    binary: {
      name: basename(path),
      path,
      format: "Mach-O",
      arch: selectedArch,
      requestedArch: archSelection.requestedArch,
      availableArchs: archSelection.availableArchs,
      fileInfo: fileInfo.stdout.trim(),
      libraries: dylibs,
      capabilities,
      signing,
      sectionEntropy,
      imphash,
      segments: loadCommandData.segments,
    },
    capabilities: {
      officialApi: false,
      privateApi: false,
      dynamicDebugger: false,
      source: deep ? "local-macho-deep" : "local-macho-importer",
    },
    imports,
    exports: exportedFunctions.map((symbol) => symbol.name),
    strings,
    objcClasses,
    swiftSymbols: imports.filter((name) => name.startsWith("_$s")).slice(0, 500),
    functions,
    antiAnalysisFindings,
    // Expose Hopper's full named-address dictionary as a serializable object
    // so downstream tools (queries, snapshots) can resolve any addr → label.
    // This is strictly larger than the function-only set in `functions`.
    hopperLabels: hopperLabels instanceof Map
      ? Object.fromEntries([...hopperLabels].map(([addr, name]) => [`0x${addr.toString(16)}`, name]))
      : null,
  };
}

function capabilityTagsFor(funcImports, buckets) {
  const tags = new Set();
  for (const sym of funcImports) {
    for (const [bucket, list] of Object.entries(buckets)) {
      if (list.includes(sym)) tags.add(bucket);
    }
  }
  return [...tags].sort();
}

async function safe(fn, fallback) {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

export async function searchMachOStrings(path, pattern, { maxMatches = 50, minLength = 8 } = {}) {
  const regex = new RegExp(pattern, "i");
  const child = spawn("strings", ["-a", "-n", String(minLength), path], { stdio: ["ignore", "pipe", "pipe"] });
  const matches = [];
  let buffer = "";
  let stderr = "";
  let lineNumber = 0;

  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      lineNumber += 1;
      const value = line.trim();
      if (value.length < minLength || looksLikeInstructionNoise(value)) continue;
      if (!regex.test(value)) continue;
      matches.push({ addr: `strscan:${lineNumber.toString(16)}`, value, source: "local-strings-scan" });
      if (matches.length >= maxMatches) child.kill();
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (buffer && matches.length < maxMatches) {
        lineNumber += 1;
        const value = buffer.trim();
        if (value.length >= minLength && !looksLikeInstructionNoise(value) && regex.test(value)) {
          matches.push({ addr: `strscan:${lineNumber.toString(16)}`, value, source: "local-strings-scan" });
        }
      }
      if (code && signal !== "SIGTERM") {
        reject(new Error(`strings exited with code ${code}: ${stderr.slice(-1000)}`));
        return;
      }
      resolve();
    });
  });

  return matches;
}

// ─── otool-based function discovery (streaming) ───────────────────────────

export async function discoverFunctionsFromDisassembly(path, { arch = "auto", maxFunctions = 30000, startAddr = null, endAddr = null } = {}) {
  if (maxFunctions <= 0) return { functions: [], callEdges: [], adrpRefs: [] };
  const archSelection = await resolveMachOArch(path, arch);
  const selectedArch = archSelection.arch;

  const functions = [];          // { addr, size }
  const callEdges = [];          // { from, to }
  const adrpState = {};          // register -> { page, instrAddr }
  const adrpRefs = [];           // { instrAddr, targetAddr, functionAddr }
  let currentFunc = null;
  let prevAddr = null;
  let stopped = false;

  const child = spawn("otool", ["-arch", selectedArch, "-tv", path], { stdio: ["ignore", "pipe", "pipe"] });
  let buffer = "";
  let stderr = "";

  const stop = () => {
    stopped = true;
    child.kill();
  };

  const clearAdrpState = () => {
    for (const key of Object.keys(adrpState)) delete adrpState[key];
  };

  const finalizeCurrent = () => {
    if (!currentFunc || prevAddr === null) {
      currentFunc = null;
      return;
    }
    if (functions.length < maxFunctions) {
      currentFunc.size = prevAddr - currentFunc.addrNum + 4;
      functions.push(currentFunc);
    }
    currentFunc = null;
    if (functions.length >= maxFunctions) stop();
  };

  const processLine = (line) => {
    if (stopped) return;
    const addrMatch = line.match(/^([0-9a-fA-F]{8,16})\s+(.+)/);
    if (!addrMatch) return;

    const addr = parseInt(addrMatch[1], 16);
    const instr = addrMatch[2].trim();

    if (startAddr !== null && addr < startAddr) return;
    if (endAddr !== null && addr > endAddr) {
      finalizeCurrent();
      stop();
      return;
    }

    // Function prologue detection: stp x29, x30 (with or without tab)
    if (isFramePrologue(instr)) {
      finalizeCurrent();
      if (stopped) return;
      currentFunc = { addr: fmtAddr(addr), addrNum: addr, size: null };
      clearAdrpState();
    }

    // Call edge: bl 0x<target>
    // Track both the discovery-anchored function (`from`) and the actual call
    // instruction address (`fromInstr`). When mergeFunctionSets later switches
    // the function partition (e.g. nm symbols are authoritative and a single
    // discovery range gets split into multiple real functions), `fromInstr`
    // lets us re-attribute the edge to the correct sub-function instead of
    // smearing all calls onto the discovery anchor.
    const blMatch = instr.match(/^bl\s+0x([0-9a-fA-F]+)/);
    if (blMatch && currentFunc) {
      callEdges.push({
        from: currentFunc.addr,
        fromInstr: fmtAddr(addr),
        to: fmtAddr(parseInt(blMatch[1], 16)),
      });
    }

    // ADRP tracking: adrp x<reg>, <page> ; 0x<addr>
    const adrpMatch = instr.match(/^adrp\s+x(\d+),\s*\d+\s*;\s*0x([0-9a-fA-F]+)/);
    if (adrpMatch) {
      adrpState[adrpMatch[1]] = { page: parseInt(adrpMatch[2], 16), instrAddr: addr };
    }

    // ADD pairing: add x<reg>, x<reg>, #0x<offset>
    const addMatch = instr.match(/^add\s+x(\d+),\s*x\1,\s*#0x([0-9a-fA-F]+)/);
    if (addMatch && adrpState[addMatch[1]]) {
      const resolved = adrpState[addMatch[1]].page + parseInt(addMatch[2], 16);
      if (currentFunc) {
        adrpRefs.push({ instrAddr: fmtAddr(addr), targetAddr: fmtAddr(resolved), functionAddr: currentFunc.addr });
      }
      delete adrpState[addMatch[1]];
    }

    // LDR from literal pool: ldr x<reg>, [x<reg>, #0x<off>] ; literal pool...
    const ldrMatch = instr.match(/^ldr\s+x(\d+),\s*\[x\1,\s*#0x([0-9a-fA-F]+)\]/);
    if (ldrMatch && adrpState[ldrMatch[1]]) {
      const resolved = adrpState[ldrMatch[1]].page + parseInt(ldrMatch[2], 16);
      if (currentFunc) {
        adrpRefs.push({ instrAddr: fmtAddr(addr), targetAddr: fmtAddr(resolved), functionAddr: currentFunc.addr });
      }
      delete adrpState[ldrMatch[1]];
    }

    prevAddr = addr;
  };

  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      processLine(line);
      if (stopped) return;
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (!stopped && buffer) processLine(buffer);
      if (!stopped) finalizeCurrent();
      if (code && signal !== "SIGTERM") {
        reject(new Error(`otool exited with code ${code}: ${stderr.slice(-1000)}`));
        return;
      }
      resolve();
    });
  });

  return { functions, callEdges, adrpRefs };
}

// Tolerance window for reconciling a discovery prologue start against an
// nm-defined symbol. Apple/C convention saves x29,x30 first, so discovery
// often agrees with nm exactly. Rust saves x29,x30 LAST, so the prologue
// heuristic anchors up to ~5 instructions (≤ 0x14 bytes) after the real
// entrypoint. 0x40 also covers Swift-style longer prologues with extra
// callee-saved register pairs.
const PROLOGUE_TOLERANCE = 0x40;

// Build the deep-import function set with nm-defined symbols treated as
// authoritative entrypoints. The previous implementation used prologue-
// detected ranges as the spine and tried to retro-fit nm names in by
// "covering range" lookup, but discovery routinely overshoots the next real
// entrypoint (Rust prologues are tail-loaded), so a single discovery range
// could span multiple real functions and silently absorb the wrong nm name.
// The fix: use nm symbols as the authoritative function boundary list, fold
// in discovery starts only where they sit in gaps with no nm coverage, and
// compute sizes from address gaps rather than from where the next prologue
// happened to land.
//
// When a Hopper procedure index is supplied (opts.hopperIndex), Hopper's
// entrypoints are treated as equally authoritative as nm — they go into the
// same dedup pass, their sizes win when explicit, and discovery starts that
// match either source are still dropped. This is how the importer fuses
// Hopper's analysis (which knows about indirect-jump tables, hand-written
// asm, and Hopper-renamed symbols) with nm/discovery without losing either
// side's evidence.
//
// Inputs:
//   existing: records produced by buildFunctions() (includes nm-defined
//     symbols with source="nm" plus synthetic cluster nodes at 0xfff*).
//   discovery: { functions, callEdges, adrpRefs } from
//     discoverFunctionsFromDisassembly.
//   strings: parsed string table; used to attach string evidence to
//     functions whose ADRP+ADD/LDR pairs target known strings.
//   opts.textEnd: end VA of the __TEXT,__text section, used to cap the
//     final function's size when there is no successor entry.
//   opts.hopperIndex: optional Map<addrNum, {addr,name,size,signature,locals,
//     basicBlocks,basicBlockCount}> from fetchHopperProcedureIndex().
export function mergeFunctionSets(existing, discovery, strings, opts = {}) {
  const { textEnd = null, hopperIndex = null } = opts;

  // Partition the input. Cluster/synthetic nodes (0xfff*) pass through
  // untouched — they're not real functions, just tag groupings. Anything
  // else with source="nm" is a real, named entrypoint we trust.
  const clusterNodes = [];
  const nmEntries = [];
  for (const fn of existing) {
    if (/^0xfff[0-9a-f]+$/.test(fn.addr) || fn.source === "semantic-import-cluster") {
      clusterNodes.push(fn);
      continue;
    }
    if (fn.source === "nm" || fn.source === "nm+otool" || fn.source === "nm+otool+hopper" || fn.source === "nm+hopper") {
      const start = hexToInt(fn.addr);
      if (start === null) continue;
      nmEntries.push({
        addrNum: start,
        record: {
          ...fn,
          callers: Array.isArray(fn.callers) ? [...fn.callers] : [],
          callees: Array.isArray(fn.callees) ? [...fn.callees] : [],
          strings: Array.isArray(fn.strings) ? [...fn.strings] : [],
          imports: Array.isArray(fn.imports) ? [...fn.imports] : [],
        },
      });
    }
    // Anything else (e.g. stale otool-discovery records from a previous
    // merge call, as in the unit tests) is intentionally rebuilt from
    // discovery below — no point preserving partition state we're about
    // to recompute.
  }
  nmEntries.sort((a, b) => a.addrNum - b.addrNum);
  const nmAddrSet = new Set(nmEntries.map((e) => e.addrNum));
  const nmAddrSorted = nmEntries.map((e) => e.addrNum);

  // Hopper entries — folded in the same way nm is. We keep the Hopper info
  // alongside so we can enrich an nm match (signature/basicblocks) or
  // synthesize a fresh record for Hopper-only entrypoints below.
  const hopperByAddr = new Map();
  if (hopperIndex && typeof hopperIndex.entries === "function") {
    for (const [addrNum, info] of hopperIndex) {
      if (typeof addrNum !== "number" || !Number.isFinite(addrNum)) continue;
      hopperByAddr.set(addrNum, info);
    }
  }
  const hopperAddrSorted = [...hopperByAddr.keys()].sort((a, b) => a - b);
  const authoritativeAddrSorted = hopperAddrSorted.length
    ? [...new Set([...nmAddrSorted, ...hopperAddrSorted])].sort((a, b) => a - b)
    : nmAddrSorted;

  // Discovery starts: keep only those that don't sit within ±tolerance of
  // any authoritative entry (nm or Hopper). An adjacent discovery start is
  // the same function — the authoritative source wins.
  const discoveryEntries = [];
  for (const fn of discovery.functions) {
    const addrNum = hexToInt(fn.addr);
    if (addrNum === null) continue;
    if (closestWithin(authoritativeAddrSorted, addrNum, PROLOGUE_TOLERANCE) !== null) continue;
    discoveryEntries.push({
      addrNum,
      record: {
        addr: fn.addr,
        name: `sub_${fn.addr.replace("0x", "")}`,
        size: fn.size,
        summary: null,
        confidence: 0.65,
        callers: [],
        callees: [],
        strings: [],
        imports: [],
        source: "otool-discovery",
        fingerprint: {
          cfgShape: "discovered",
          importSignature: [],
          stringBag: [],
        },
      },
    });
  }

  // Combined entrypoint list — nm first (so it wins ties), then Hopper-only
  // (we synthesize records for entries Hopper has but nm doesn't), then
  // discovery (already filtered against both). The dedup below collapses
  // any same-addr pairs.
  const hopperOnlyEntries = [];
  for (const [addrNum, hop] of hopperByAddr) {
    if (nmAddrSet.has(addrNum)) continue;
    hopperOnlyEntries.push({
      addrNum,
      record: synthesizeHopperRecord(addrNum, hop),
    });
  }
  const entries = [...nmEntries, ...hopperOnlyEntries, ...discoveryEntries]
    .sort((a, b) => a.addrNum - b.addrNum);
  const dedup = [];
  for (const e of entries) {
    if (dedup.length && dedup[dedup.length - 1].addrNum === e.addrNum) continue;
    dedup.push(e);
  }

  // Enrich nm records that have a Hopper match at the exact same address.
  // We keep the nm-attached imports/strings (built from the symbol table)
  // and overlay Hopper's signature/locals/basicBlocks. Hopper's name only
  // overrides when nm has nothing useful (placeholder sub_, empty).
  for (const e of dedup) {
    const hop = hopperByAddr.get(e.addrNum);
    if (!hop) continue;
    enrichWithHopper(e.record, hop);
  }

  // Compute size from gap to the next entrypoint. For the last entry, fall
  // back to the __TEXT,__text end if known, otherwise leave the existing
  // size (which may be discovery's prologue-derived size, or null for a
  // bare nm record). Hopper's explicit size wins when present — it knows
  // about non-contiguous procedure layouts that gap-based sizing can't see.
  for (let i = 0; i < dedup.length; i++) {
    const cur = dedup[i];
    const next = dedup[i + 1];
    const hopperSize = Number(cur.record.hopperSize ?? NaN);
    let size = null;
    if (Number.isFinite(hopperSize) && hopperSize > 0) {
      size = hopperSize;
    } else if (next) {
      size = next.addrNum - cur.addrNum;
    } else if (textEnd) {
      size = textEnd - cur.addrNum;
    }
    if (size !== null && size > 0) cur.record.size = size;
  }

  // Mark which nm entries had a near-by discovery anchor (informational);
  // also flag exact prologue mismatches so callers can spot Rust-style
  // shifted prologues. When Hopper agreed at the same addr we already set
  // source=nm+hopper in enrichWithHopper, so we just upgrade further to
  // nm+otool+hopper here.
  const discoveryAddrSorted = discovery.functions
    .map((fn) => hexToInt(fn.addr))
    .filter((n) => n !== null)
    .sort((a, b) => a - b);
  for (const e of dedup) {
    if (!nmAddrSet.has(e.addrNum)) continue;
    const nearby = closestWithin(discoveryAddrSorted, e.addrNum, PROLOGUE_TOLERANCE);
    if (nearby !== null) {
      e.record.source = combineSource(e.record.source, "otool");
      if (nearby !== e.addrNum) e.record.symbolEntrypoint = e.record.addr;
    }
    // else: nm-only (no discovery anchor in tolerance window)
  }

  // Re-attribute call edges and ADRP refs by instruction address. This is
  // the key correctness step: a single discovery range may span multiple
  // real functions, so attributing edges to discovery's anchor would
  // smear them across several callers. Using fromInstr / instrAddr places
  // each edge in the function whose [start, end) contains the instruction.
  const ranges = dedup.map((e) => {
    const size = Number(e.record.size ?? 0);
    return {
      start: e.addrNum,
      end: size > 0 ? e.addrNum + size : e.addrNum + 4,
      record: e.record,
    };
  });
  // ranges already sorted by start ascending
  const containingRange = (addrNum) => {
    if (addrNum === null) return null;
    // Linear scan — N is bounded by maxFunctions (≤30k) and this runs once
    // per import, so binary search is not worth the complexity yet.
    for (const r of ranges) {
      if (addrNum < r.start) return null;
      if (addrNum < r.end) return r;
    }
    return null;
  };

  for (const edge of discovery.callEdges) {
    const instrAddrNum = hexToInt(edge.fromInstr ?? edge.from);
    const fromRange = containingRange(instrAddrNum);
    if (!fromRange) continue;
    fromRange.record.callees.push(edge.to);
    const targetRange = containingRange(hexToInt(edge.to));
    if (targetRange) targetRange.record.callers.push(fromRange.record.addr);
  }

  const stringByAddr = new Map();
  for (const s of strings) stringByAddr.set(s.addr, s.value);
  for (const ref of discovery.adrpRefs) {
    const strVal = stringByAddr.get(ref.targetAddr);
    if (!strVal) continue;
    const r = containingRange(hexToInt(ref.instrAddr));
    if (!r) continue;
    r.record.strings.push(strVal);
  }

  // Dedup the per-function lists.
  for (const r of ranges) {
    r.record.callees = [...new Set(r.record.callees)];
    r.record.callers = [...new Set(r.record.callers)];
    r.record.strings = [...new Set(r.record.strings)];
    if (r.record.fingerprint && Array.isArray(r.record.strings)) {
      r.record.fingerprint = {
        ...r.record.fingerprint,
        stringBag: r.record.strings.slice(0, 10),
      };
    }
  }

  return [...dedup.map((e) => e.record), ...clusterNodes];
}

// Synthesize a function record for a Hopper procedure that nm didn't see.
// Hopper has the entrypoint, name, size, and (optionally) basicblocks/
// signature/locals — but not the per-instruction call/string evidence,
// which the edge re-attribution step downstream will fill in.
function synthesizeHopperRecord(addrNum, hop) {
  const addr = fmtAddr(addrNum);
  const size = Number(hop?.size ?? NaN);
  const record = {
    addr,
    name: typeof hop?.name === "string" && hop.name ? hop.name : `sub_${addr.replace("0x", "")}`,
    size: Number.isFinite(size) && size > 0 ? size : null,
    summary: null,
    confidence: 0.85,
    callers: [],
    callees: [],
    strings: [],
    imports: [],
    source: "hopper",
    hopperSize: Number.isFinite(size) && size > 0 ? size : null,
    fingerprint: {
      cfgShape: "hopper",
      importSignature: [],
      stringBag: [],
    },
  };
  if (hop?.signature) record.signature = hop.signature;
  if (Array.isArray(hop?.locals) && hop.locals.length) record.locals = hop.locals;
  if (Array.isArray(hop?.basicBlocks) && hop.basicBlocks.length) record.basicBlocks = hop.basicBlocks;
  if (Number.isFinite(Number(hop?.basicBlockCount)) && Number(hop.basicBlockCount) > 0) {
    record.basicBlockCount = Number(hop.basicBlockCount);
  }
  return record;
}

// Overlay Hopper data onto an existing nm record. nm contributes the symbol
// table evidence (mangled name, imports list, real callers/callees from
// otool); Hopper contributes the signature/locals/basicblocks we can't
// reconstruct from heuristics. Names: nm wins unless nm only has a sub_/
// empty placeholder.
function enrichWithHopper(record, hop) {
  if (typeof hop?.name === "string" && hop.name && hop.name !== record.name) {
    if (!record.name || /^sub_[0-9a-f]+$/.test(record.name)) {
      record.name = hop.name;
    } else {
      record.hopperName = hop.name;
    }
  }
  const size = Number(hop?.size ?? NaN);
  if (Number.isFinite(size) && size > 0) record.hopperSize = size;
  if (hop?.signature) record.signature = hop.signature;
  if (Array.isArray(hop?.locals) && hop.locals.length && !record.locals?.length) {
    record.locals = hop.locals;
  }
  if (Array.isArray(hop?.basicBlocks) && hop.basicBlocks.length && !record.basicBlocks?.length) {
    record.basicBlocks = hop.basicBlocks;
  }
  if (
    Number.isFinite(Number(hop?.basicBlockCount))
    && Number(hop.basicBlockCount) > 0
    && !Number.isFinite(Number(record.basicBlockCount))
  ) {
    record.basicBlockCount = Number(hop.basicBlockCount);
  }
  record.source = combineSource(record.source, "hopper");
}

// Combine source tags. "nm" + "otool" → "nm+otool"; adding "hopper" yields
// "nm+otool+hopper". Token order is stable: nm, otool, hopper.
function combineSource(...sources) {
  const seen = new Set();
  for (const s of sources) {
    if (!s) continue;
    for (const t of String(s).split("+")) {
      if (t) seen.add(t);
    }
  }
  const order = ["nm", "otool", "hopper"];
  const ordered = [];
  for (const tok of order) if (seen.has(tok)) { ordered.push(tok); seen.delete(tok); }
  for (const tok of seen) ordered.push(tok);
  return ordered.join("+");
}

// Returns the closest value in `sorted` to `target` whose absolute distance
// is ≤ `tolerance`, or null if none qualify. `sorted` must be ascending.
function closestWithin(sorted, target, tolerance) {
  if (sorted.length === 0) return null;
  // Linear scan with early bailout. Inputs are in the tens-of-thousands range
  // and this is called per discovery start; if it shows up in profiles we
  // can swap to a binary search.
  let best = null;
  let bestDist = Infinity;
  for (const v of sorted) {
    const dist = Math.abs(v - target);
    if (dist < bestDist) {
      best = v;
      bestDist = dist;
    }
    if (v - target > tolerance) break;
  }
  return bestDist <= tolerance ? best : null;
}

function hexToInt(addr) {
  if (typeof addr !== "string") return null;
  const m = addr.match(/^0x([0-9a-fA-F]+)$/);
  if (!m) return null;
  return parseInt(m[1], 16);
}

// ─── Targeted disassembly ─────────────────────────────────────────────────

export async function disassembleRange(path, { arch = "auto", startAddr, endAddr, maxLines = 500 } = {}) {
  const start = typeof startAddr === "string" ? parseInt(startAddr, 16) : startAddr;
  const end = typeof endAddr === "string" ? parseInt(endAddr, 16) : endAddr;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
    throw new Error("disassemble_range requires valid start_addr and end_addr.");
  }
  const archSelection = await resolveMachOArch(path, arch);
  const selectedArch = archSelection.arch;
  const lines = [];

  const child = spawn("otool", ["-arch", selectedArch, "-tV", path], { stdio: ["ignore", "pipe", "pipe"] });
  let buffer = "";
  let collecting = false;
  let stopped = false;
  let stderr = "";

  const processLine = (line) => {
    if (stopped) return;
    const m = line.match(/^([0-9a-fA-F]{8,16})\s+(.*)/);
    if (!m) return;
    const addr = parseInt(m[1], 16);
    if (addr >= start) collecting = true;
    if (addr > end || lines.length >= maxLines) {
      stopped = true;
      child.kill();
      return;
    }
    if (collecting) {
      const parts = m[2].trim().split(/\s+/);
      lines.push({ addr: fmtAddr(addr), mnemonic: parts[0] || "", operands: parts.slice(1).join(" "), raw: m[2].trim() });
    }
  };

  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    const parts = buffer.split("\n");
    buffer = parts.pop() ?? "";
    for (const line of parts) {
      processLine(line);
      if (stopped) return;
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (!stopped && buffer) processLine(buffer);
      if (code && signal !== "SIGTERM") {
        reject(new Error(`otool exited with code ${code}: ${stderr.slice(-1000)}`));
        return;
      }
      resolve();
    });
  });

  return { lines, startAddr: fmtAddr(start), endAddr: fmtAddr(end), lineCount: lines.length, arch: selectedArch, requestedArch: archSelection.requestedArch };
}

// ─── Cross-reference finder ───────────────────────────────────────────────

export async function findXrefs(path, { arch = "auto", targetAddr, maxResults = 50 } = {}) {
  const target = typeof targetAddr === "string" ? parseInt(targetAddr, 16) : targetAddr;
  if (!Number.isFinite(target)) throw new Error("find_xrefs requires a valid target_addr.");
  const archSelection = await resolveMachOArch(path, arch);
  const selectedArch = archSelection.arch;
  const results = [];
  const adrpState = {};
  let currentFunc = null;

  // otool -tv resolves bl/b targets to symbol names when the symbol table
  // names the target — e.g. `bl __ZN3std3env7vars_os17h...` instead of
  // `bl 0x1001ad674`. Without translating those symbolic operands we'd
  // miss every xref to a named function. Build name→address from nm and
  // accept either form.
  const nameToAddr = await safe(() => buildSymbolAddressMap(path, selectedArch), new Map());
  const targetNames = new Set();
  for (const [name, addr] of nameToAddr.entries()) {
    if (addr === target) targetNames.add(name);
  }

  // Sorted unique nm addresses, used to drive currentFunc as we scan
  // disassembly. nm symbols are authoritative function boundaries; the
  // prologue heuristic is only a fallback for regions with no nm coverage.
  // Without this, currentFunc would anchor on `stp x29,x30` lines, which
  // for Rust prologues sits ~0x14 bytes after the real entrypoint and
  // would report xrefs as belonging to addresses that no longer exist as
  // function entries in the merged session.
  const nmAddrsSorted = [
    ...new Set([...nameToAddr.values()].filter((v) => Number.isFinite(v))),
  ].sort((a, b) => a - b);
  let nmCursor = 0;

  const child = spawn("otool", ["-arch", selectedArch, "-tv", path], { stdio: ["ignore", "pipe", "pipe"] });
  let buffer = "";
  let stopped = false;
  let stderr = "";

  const pushResult = (result) => {
    if (results.length >= maxResults) return;
    results.push(result);
    if (results.length >= maxResults) {
      stopped = true;
      child.kill();
    }
  };

  const processLine = (line) => {
    if (stopped) return;
    const m = line.match(/^([0-9a-fA-F]{8,16})\s+(.+)/);
    if (!m) return;
    const addr = parseInt(m[1], 16);
    const instr = m[2].trim();

    // Track function boundaries — nm symbols first (authoritative),
    // prologue heuristic as a fallback for unnamed regions.
    while (nmCursor < nmAddrsSorted.length && nmAddrsSorted[nmCursor] <= addr) {
      currentFunc = fmtAddr(nmAddrsSorted[nmCursor]);
      nmCursor++;
      for (const k of Object.keys(adrpState)) delete adrpState[k];
    }
    if (isFramePrologue(instr)) {
      const lastNm = currentFunc ? parseInt(currentFunc.slice(2), 16) : null;
      // Only let the prologue advance currentFunc when it's beyond any
      // nearby nm symbol (i.e. we're in an unnamed gap). Within ~0x40 of
      // an nm symbol the prologue is the SAME function — Rust saves x29
      // last so the prologue line follows the entrypoint.
      if (lastNm === null || addr - lastNm > 0x40) {
        currentFunc = fmtAddr(addr);
        for (const k of Object.keys(adrpState)) delete adrpState[k];
      }
    }

    const branchHexMatch = instr.match(/^(bl|b)\s+0x([0-9a-fA-F]+)/);
    if (branchHexMatch && parseInt(branchHexMatch[2], 16) === target) {
      pushResult({ addr: fmtAddr(addr), type: branchHexMatch[1] === "bl" ? "call" : "branch", function: currentFunc });
      if (stopped) return;
    } else if (targetNames.size) {
      // Symbolic form: `bl __ZN3std...` (no 0x). We trim trailing comments
      // (otool sometimes appends `; <symbol>` annotations).
      const branchSymMatch = instr.match(/^(bl|b)\s+([A-Za-z_$][\w.$]*)/);
      if (branchSymMatch && targetNames.has(branchSymMatch[2])) {
        pushResult({
          addr: fmtAddr(addr),
          type: branchSymMatch[1] === "bl" ? "call" : "branch",
          function: currentFunc,
          via: branchSymMatch[2],
        });
        if (stopped) return;
      }
    }

    // ADRP+ADD/LDR resolution
    const adrpMatch = instr.match(/^adrp\s+x(\d+),\s*\d+\s*;\s*0x([0-9a-fA-F]+)/);
    if (adrpMatch) adrpState[adrpMatch[1]] = { page: parseInt(adrpMatch[2], 16) };

    const addMatch = instr.match(/^add\s+x(\d+),\s*x\1,\s*#0x([0-9a-fA-F]+)/);
    if (addMatch && adrpState[addMatch[1]]) {
      const resolved = adrpState[addMatch[1]].page + parseInt(addMatch[2], 16);
      if (resolved === target) {
        pushResult({ addr: fmtAddr(addr), type: "adrp_add", function: currentFunc });
      }
      delete adrpState[addMatch[1]];
      if (stopped) return;
    }

    const ldrMatch = instr.match(/^ldr\s+x(\d+),\s*\[x\1,\s*#0x([0-9a-fA-F]+)\]/);
    if (ldrMatch && adrpState[ldrMatch[1]]) {
      const resolved = adrpState[ldrMatch[1]].page + parseInt(ldrMatch[2], 16);
      if (resolved === target) {
        pushResult({ addr: fmtAddr(addr), type: "adrp_ldr", function: currentFunc });
      }
      delete adrpState[ldrMatch[1]];
    }
  };

  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      processLine(line);
      if (stopped) return;
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (!stopped && buffer) processLine(buffer);
      if (code && signal !== "SIGTERM") {
        reject(new Error(`otool exited with code ${code}: ${stderr.slice(-1000)}`));
        return;
      }
      resolve();
    });
  });

  return results;
}

// ─── Helper ───────────────────────────────────────────────────────────────

// Build a name → vmaddress map from nm output. Used by findXrefs to translate
// otool-resolved symbolic branches (`bl __ZN…`) back into address comparisons.
async function buildSymbolAddressMap(path, arch) {
  const result = await execFileAsync("nm", ["-arch", arch, "-n", path], { maxBuffer: 64 * 1024 * 1024 }).catch((err) => {
    if (err.stdout || err.stderr) return { stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
    throw err;
  });
  const map = new Map();
  for (const line of result.stdout.split("\n")) {
    const m = line.match(/^([0-9a-fA-F]+)\s+[A-Za-z]\s+(\S+)/);
    if (!m) continue;
    const addr = parseInt(m[1], 16);
    if (!Number.isFinite(addr)) continue;
    const name = m[2];
    if (!map.has(name)) map.set(name, addr);
  }
  return map;
}

function fmtAddr(n) {
  return `0x${n.toString(16)}`;
}

function isFramePrologue(instr) {
  return /stp\s+x29,\s*x30/.test(instr) || /stp\tx29, x30/.test(instr);
}

async function resolveMachOArch(path, requestedArch = "auto") {
  const requested = requestedArch ?? "auto";
  const availableArchs = await listMachOArchitectures(path);
  if (!availableArchs.length) {
    if (requested === "auto") throw new Error(`Could not determine Mach-O architecture for ${path}.`);
    return { arch: requested, requestedArch: requested, availableArchs };
  }

  if (requested !== "auto") {
    if (availableArchs.includes(requested)) return { arch: requested, requestedArch: requested, availableArchs };
    if (requested === "arm64" && availableArchs.includes("arm64e")) {
      return { arch: "arm64e", requestedArch: requested, availableArchs };
    }
    throw new Error(`Mach-O file ${path} does not contain architecture '${requested}'. Available architectures: ${availableArchs.join(", ")}.`);
  }

  const preferred = PREFERRED_ARCHS.find((candidate) => availableArchs.includes(candidate));
  return {
    arch: preferred ?? availableArchs[0],
    requestedArch: requested,
    availableArchs,
  };
}

async function listMachOArchitectures(path) {
  if (!path || typeof path !== "string") {
    throw new Error("listMachOArchitectures requires a non-empty path string.");
  }
  try {
    const result = await execFileAsync("lipo", ["-archs", path], { maxBuffer: 1024 * 1024 });
    return result.stdout.trim().split(/\s+/).filter(Boolean);
  } catch (error) {
    const output = `${error.stdout ?? ""}\n${error.stderr ?? ""}`;
    const match = output.match(/Non-fat file: .+ is architecture: (\S+)/);
    if (match) return [match[1]];
    throw error;
  }
}

// ─── Original functions ───────────────────────────────────────────────────

function buildFunctions({ exportedFunctions, imports, strings, dylibs }) {
  const functions = exportedFunctions.map((symbol) => ({
    addr: symbol.addr,
    name: symbol.name,
    size: null,
    summary: "Named symbol imported from Mach-O symbol table.",
    confidence: 0.55,
    callers: [],
    callees: [],
    strings: [],
    imports: [],
    source: "nm",
    fingerprint: {
      cfgShape: "unknown",
      importSignature: [],
      stringBag: [],
    },
  }));

  const clusters = [
    ["security_api_cluster", "Security.framework and keychain/code-signing related imports.", /(_Sec|Security|CodeSign|Requirement)/i],
    ["xpc_api_cluster", "XPC/service-management related imports.", /(_xpc_|ServiceManagement|SMAppService|Launchd)/i],
    ["objc_runtime_cluster", "Objective-C runtime and dynamic dispatch imports.", /(_objc_|_class_|_sel_|_method_|ObjectiveC)/i],
    ["swift_runtime_cluster", "Swift runtime and Swift standard-library imports.", /(_swift_|^\_$s|libswift)/i],
    ["networking_cluster", "URL, WebKit, or networking-adjacent imports/strings.", /(URL|WebKit|NSURL|Network|http)/i],
  ];

  clusters.forEach(([name, summary, pattern], index) => {
    const clusterImports = imports.filter((item) => pattern.test(item)).slice(0, 80);
    const clusterStrings = strings.filter((item) => pattern.test(item.value)).slice(0, 40).map((item) => item.value);
    const clusterLibs = dylibs.filter((item) => pattern.test(item)).slice(0, 20);
    if (!clusterImports.length && !clusterStrings.length && !clusterLibs.length) return;

    functions.push({
      addr: `0xfff${index.toString(16).padStart(5, "0")}`,
      name,
      size: null,
      summary,
      confidence: 0.5,
      callers: [],
      callees: [],
      strings: clusterStrings,
      imports: [...clusterImports, ...clusterLibs],
      source: "semantic-import-cluster",
      fingerprint: {
        cfgShape: "synthetic-cluster",
        importSignature: clusterImports.slice(0, 20),
        stringBag: clusterStrings.slice(0, 20),
      },
      basicBlocks: [
        {
          addr: `0xfff${index.toString(16).padStart(5, "0")}`,
          summary: "Synthetic evidence node generated from real Mach-O imports/libraries/strings.",
        },
      ],
    });
  });

  if (!functions.length) {
    functions.push({
      addr: "0xfff00000",
      name: "binary_overview",
      size: null,
      summary: "Synthetic overview node generated because no defined function symbols were available.",
      confidence: 0.35,
      callers: [],
      callees: [],
      strings: strings.slice(0, 20).map((item) => item.value),
      imports: imports.slice(0, 40),
      source: "semantic-import-cluster",
      basicBlocks: [{ addr: "0xfff00000", summary: "Overview of top strings and imports." }],
    });
  }

  return functions;
}

function parseNm(output) {
  const imports = [];
  const defined = [];

  for (const line of output.split("\n")) {
    const undefinedMatch = line.match(/\(undefined\)\s+(?:weak\s+)?external\s+(\S+)/);
    if (undefinedMatch) {
      imports.push(undefinedMatch[1]);
      continue;
    }

    // Accept both `external` (capital-T text symbols) and `non-external`
    // (lowercase-t local text symbols). Rust/Swift binaries strip externs
    // but keep mangled local names — those are exactly the function names
    // the user wants surfaced. Filter to __TEXT,__text so we don't pull in
    // data symbols.
    const definedMatch = line.match(/^\s*([0-9a-fA-F]+)\s+\(([^)]+)\)\s+(?:non-)?external\s+(\S+)/);
    if (definedMatch && /^__TEXT,/.test(definedMatch[2])) {
      defined.push({
        addr: `0x${definedMatch[1].replace(/^0+/, "") || "0"}`,
        name: definedMatch[3],
        section: definedMatch[2],
      });
    }
  }

  return {
    imports: [...new Set(imports)].sort(),
    defined: dedupeByAddress(defined),
  };
}

function parseDylibs(output) {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("/") || line.startsWith("@"))
    .map((line) => line.replace(/\s+\(.+$/, ""))
    .filter(Boolean);
}

function parseStringsWithOffsets(output, maxStrings, offsetMaps = []) {
  const strings = [];
  const seen = new Map();

  for (const line of output.split("\n")) {
    // strings -t x format: "   47f0 some string value"
    const match = line.match(/^\s*([0-9a-fA-F]+)\s+(.+)/);
    if (!match) continue;
    const offset = match[1];
    const fileOffset = parseInt(offset, 16);
    const value = match[2].trim();
    if (value.length < 8 || looksLikeInstructionNoise(value)) continue;
    const mapped = offsetToVmAddress(fileOffset, offsetMaps);
    if (offsetMaps.length && mapped === null) continue;
    const item = {
      addr: fmtAddr(mapped?.vmAddress ?? fileOffset),
      fileOffset: fmtAddr(fileOffset),
      value,
    };
    const priority = mapped?.priority ?? 100;
    const previous = seen.get(value);
    if (previous) {
      if (priority >= previous.priority) continue;
      strings[previous.index] = item;
      previous.priority = priority;
      continue;
    }
    seen.set(value, { index: strings.length, priority });
    strings.push(item);
    if (!offsetMaps.length && strings.length >= maxStrings) break;
  }

  return strings.slice(0, maxStrings);
}

function parseStrings(output, maxStrings) {
  const seen = new Set();
  const strings = [];

  for (const value of output.split("\n")) {
    const trimmed = value.trim();
    if (trimmed.length < 8 || seen.has(trimmed) || looksLikeInstructionNoise(trimmed)) continue;
    seen.add(trimmed);
    strings.push({
      addr: `str:${strings.length.toString(16)}`,
      value: trimmed,
    });
    if (strings.length >= maxStrings) break;
  }

  return strings;
}

function inferObjCClasses(strings) {
  const classNames = new Set();
  for (const item of strings) {
    const match = item.value.match(/\bSo([A-Z][A-Za-z0-9_]{3,})C\b/);
    if (match) classNames.add(match[1]);
  }
  return [...classNames].slice(0, 200).map((name) => ({ name, methods: [] }));
}

function dedupeByAddress(symbols) {
  const seen = new Set();
  return symbols.filter((symbol) => {
    if (seen.has(symbol.addr)) return false;
    seen.add(symbol.addr);
    return true;
  });
}

function looksLikeInstructionNoise(value) {
  return /^(AWAV|[A-Z]\[A\\A|[a-z]{2,8}\.[a-z0-9]+$)/.test(value);
}

function parseLoadCommands(output) {
  const segments = [];
  const allSectionMaps = [];
  const stringSectionMaps = [];
  let currentSegment = null;
  let currentSection = null;

  const finalizeSection = () => {
    if (
      currentSegment &&
      currentSection &&
      Number.isFinite(currentSection.fileStart) &&
      Number.isFinite(currentSection.vmStart) &&
      Number.isFinite(currentSection.size)
    ) {
      const sectionRecord = {
        name: currentSection.sectname ?? null,
        segname: currentSection.segname ?? currentSegment.segname ?? null,
        start: fmtAddr(currentSection.vmStart),
        end: fmtAddr(currentSection.vmStart + currentSection.size),
        length: currentSection.size,
        fileStart: currentSection.fileStart,
        fileEnd: currentSection.fileStart + currentSection.size,
      };
      currentSegment.sections.push(sectionRecord);

      if (currentSection.size > 0) {
        const mapping = {
          fileStart: currentSection.fileStart,
          fileEnd: currentSection.fileStart + currentSection.size,
          vmStart: currentSection.vmStart,
          priority: stringSectionPriority(currentSection),
        };
        allSectionMaps.push(mapping);
        if (mapping.priority !== null) stringSectionMaps.push(mapping);
      }
    }
    currentSection = null;
  };

  const finalizeSegment = () => {
    finalizeSection();
    if (
      currentSegment &&
      Number.isFinite(currentSegment.fileStart) &&
      Number.isFinite(currentSegment.vmStart) &&
      Number.isFinite(currentSegment.size)
    ) {
      const initprot = Number.isFinite(currentSegment.initprot) ? currentSegment.initprot : 0;
      segments.push({
        name: currentSegment.segname ?? null,
        start: fmtAddr(currentSegment.vmStart),
        end: fmtAddr(currentSegment.vmStart + (currentSegment.vmSize ?? currentSegment.size)),
        length: currentSegment.vmSize ?? currentSegment.size,
        fileStart: currentSegment.fileStart,
        fileEnd: currentSegment.fileStart + currentSegment.size,
        protection: protString(initprot),
        readable: Boolean(initprot & 0x1),
        writable: Boolean(initprot & 0x2),
        executable: Boolean(initprot & 0x4),
        sections: currentSegment.sections,
      });
    }
    currentSegment = null;
  };

  for (const rawLine of output.split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("Load command ")) {
      finalizeSegment();
      continue;
    }
    if (line === "cmd LC_SEGMENT_64" || line === "cmd LC_SEGMENT") {
      currentSegment = { sections: [] };
      continue;
    }
    if (line === "Section") {
      finalizeSection();
      currentSection = {};
      continue;
    }
    const [key, value] = line.split(/\s+/, 2);
    if (!value) continue;
    if (currentSection) {
      if (key === "sectname") currentSection.sectname = value;
      if (key === "segname") currentSection.segname = value;
      if (key === "addr") currentSection.vmStart = parseInt(value, 16);
      if (key === "size") currentSection.size = parseInt(value, 16);
      if (key === "offset") currentSection.fileStart = parseInt(value, 10);
      continue;
    }
    if (currentSegment) {
      if (key === "segname") currentSegment.segname = value;
      if (key === "vmaddr") currentSegment.vmStart = parseInt(value, 16);
      if (key === "vmsize") currentSegment.vmSize = parseInt(value, 16);
      if (key === "filesize") currentSegment.size = parseInt(value, 16);
      if (key === "fileoff") currentSegment.fileStart = parseInt(value, 10);
      if (key === "initprot") currentSegment.initprot = parseInt(value, 16);
      if (key === "maxprot") currentSegment.maxprot = parseInt(value, 16);
    }
  }
  finalizeSegment();

  let offsetMaps;
  if (stringSectionMaps.length) offsetMaps = stringSectionMaps;
  else if (allSectionMaps.length) offsetMaps = allSectionMaps;
  else {
    offsetMaps = segments
      .filter((seg) => seg.fileEnd > seg.fileStart)
      .map((seg) => ({
        fileStart: seg.fileStart,
        fileEnd: seg.fileEnd,
        vmStart: parseInt(seg.start.replace("0x", ""), 16),
        priority: 100,
      }));
  }

  return { offsetMaps, segments };
}

function protString(prot) {
  return `${prot & 0x1 ? "r" : "-"}${prot & 0x2 ? "w" : "-"}${prot & 0x4 ? "x" : "-"}`;
}

function offsetToVmAddress(offset, maps) {
  const mapping = maps.find((candidate) => offset >= candidate.fileStart && offset < candidate.fileEnd);
  if (!mapping) return null;
  return {
    vmAddress: mapping.vmStart + (offset - mapping.fileStart),
    priority: mapping.priority ?? 100,
  };
}

function stringSectionPriority(section) {
  const name = `${section.sectname ?? ""}:${section.segname ?? ""}`;
  if (/__cstring/.test(name)) return 0;
  if (/__objc_(methname|classname|methtype)/.test(name)) return 1;
  if (/__ustring|__cfstring/.test(name)) return 2;
  if (/__swift/.test(name)) return 3;
  if (/__const/.test(name)) return 10;
  return null;
}

async function run(command, args, options = {}) {
  try {
    return await execFileAsync(command, args, { maxBuffer: options.maxBuffer ?? 8 * 1024 * 1024 });
  } catch (error) {
    if (error.stdout || error.stderr) return { stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
    throw error;
  }
}
