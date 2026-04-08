import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { basename } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const PREFERRED_ARCHS = ["arm64e", "arm64", "x86_64"];

export async function importMachO(path, { arch = "auto", maxStrings = 5000, deep = false, maxFunctions = 30000 } = {}) {
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
  const exportedFunctions = parsedSymbols.defined.slice(0, 1000);
  const strings = parseStringsWithOffsets(stringRows.stdout, maxStrings, parseOffsetMaps(loadCommands.stdout));
  const dylibs = parseDylibs(libraries.stdout);
  const binaryId = createHash("sha256").update(`${path}:${selectedArch}:${fileInfo.stdout}`).digest("hex").slice(0, 16);

  let functions = buildFunctions({ exportedFunctions, imports, strings, dylibs });

  if (deep) {
    const discovery = await discoverFunctionsFromDisassembly(path, { arch: selectedArch, maxFunctions });
    functions = mergeFunctionSets(functions, discovery, strings);
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
    objcClasses: inferObjCClasses(strings),
    swiftSymbols: imports.filter((name) => name.startsWith("_$s")).slice(0, 500),
    functions,
  };
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
    const blMatch = instr.match(/^bl\s+0x([0-9a-fA-F]+)/);
    if (blMatch && currentFunc) {
      callEdges.push({ from: currentFunc.addr, to: fmtAddr(parseInt(blMatch[1], 16)) });
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

export function mergeFunctionSets(existing, discovery, strings) {
  const byAddr = new Map();
  for (const fn of existing) byAddr.set(fn.addr, fn);

  // Build string address lookup
  const stringByAddr = new Map();
  for (const s of strings) stringByAddr.set(s.addr, s.value);

  // Build callee/caller maps from edges
  const calleeMap = new Map();  // from -> [to]
  const callerMap = new Map();  // to -> [from]
  for (const edge of discovery.callEdges) {
    if (!calleeMap.has(edge.from)) calleeMap.set(edge.from, []);
    calleeMap.get(edge.from).push(edge.to);
    if (!callerMap.has(edge.to)) callerMap.set(edge.to, []);
    callerMap.get(edge.to).push(edge.from);
  }

  // Build function string refs from adrpRefs
  const funcStrings = new Map();  // funcAddr -> [string values]
  for (const ref of discovery.adrpRefs) {
    const strVal = stringByAddr.get(ref.targetAddr);
    if (strVal) {
      if (!funcStrings.has(ref.functionAddr)) funcStrings.set(ref.functionAddr, []);
      funcStrings.get(ref.functionAddr).push(strVal);
    }
  }

  for (const fn of discovery.functions) {
    if (byAddr.has(fn.addr)) {
      // Enrich existing
      const existing = byAddr.get(fn.addr);
      existing.size = existing.size ?? fn.size;
      existing.callees = [...new Set([...(existing.callees || []), ...(calleeMap.get(fn.addr) || [])])];
      existing.callers = [...new Set([...(existing.callers || []), ...(callerMap.get(fn.addr) || [])])];
      existing.strings = [...new Set([...(existing.strings || []), ...(funcStrings.get(fn.addr) || [])])];
      existing.source = "nm+otool";
    } else {
      byAddr.set(fn.addr, {
        addr: fn.addr,
        name: `sub_${fn.addr.replace("0x", "")}`,
        size: fn.size,
        summary: null,
        confidence: 0.65,
        callers: [...new Set(callerMap.get(fn.addr) || [])],
        callees: [...new Set(calleeMap.get(fn.addr) || [])],
        strings: [...new Set(funcStrings.get(fn.addr) || [])],
        imports: [],
        source: "otool-discovery",
        fingerprint: {
          cfgShape: "discovered",
          importSignature: [],
          stringBag: (funcStrings.get(fn.addr) || []).slice(0, 10),
        },
      });
    }
  }

  return [...byAddr.values()];
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

    // Track function boundaries
    if (isFramePrologue(instr)) {
      currentFunc = fmtAddr(addr);
      for (const k of Object.keys(adrpState)) delete adrpState[k];
    }

    const branchMatch = instr.match(/^(bl|b)\s+0x([0-9a-fA-F]+)/);
    if (branchMatch && parseInt(branchMatch[2], 16) === target) {
      pushResult({ addr: fmtAddr(addr), type: branchMatch[1] === "bl" ? "call" : "branch", function: currentFunc });
      if (stopped) return;
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

    const definedMatch = line.match(/^\s*([0-9a-fA-F]+)\s+.*\sexternal\s+(\S+)/);
    if (definedMatch) {
      defined.push({
        addr: `0x${definedMatch[1].replace(/^0+/, "") || "0"}`,
        name: definedMatch[2],
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

function parseOffsetMaps(output) {
  const allSections = [];
  const stringSections = [];
  const segments = [];
  let currentSegment = null;
  let currentSection = null;

  const finalizeSection = () => {
    if (
      currentSection &&
      Number.isFinite(currentSection.fileStart) &&
      Number.isFinite(currentSection.vmStart) &&
      Number.isFinite(currentSection.size) &&
      currentSection.size > 0
    ) {
      const mapping = {
        fileStart: currentSection.fileStart,
        fileEnd: currentSection.fileStart + currentSection.size,
        vmStart: currentSection.vmStart,
        priority: stringSectionPriority(currentSection),
      };
      allSections.push(mapping);
      if (mapping.priority !== null) stringSections.push(mapping);
    }
    currentSection = null;
  };

  const finalizeSegment = () => {
    finalizeSection();
    if (
      currentSegment &&
      Number.isFinite(currentSegment.fileStart) &&
      Number.isFinite(currentSegment.vmStart) &&
      Number.isFinite(currentSegment.size) &&
      currentSegment.size > 0
    ) {
      segments.push({
        fileStart: currentSegment.fileStart,
        fileEnd: currentSegment.fileStart + currentSegment.size,
        vmStart: currentSegment.vmStart,
        priority: 100,
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
    if (line === "cmd LC_SEGMENT_64") {
      currentSegment = {};
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
      if (key === "vmaddr") currentSegment.vmStart = parseInt(value, 16);
      if (key === "filesize") currentSegment.size = parseInt(value, 16);
      if (key === "fileoff") currentSegment.fileStart = parseInt(value, 10);
    }
  }
  finalizeSegment();

  if (stringSections.length) return stringSections;
  if (allSections.length) return allSections;
  return segments;
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
