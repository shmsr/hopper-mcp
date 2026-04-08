import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { basename } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function importMachO(path, { arch = "arm64", maxStrings = 2000 } = {}) {
  const [fileInfo, libraries, symbols, stringRows] = await Promise.all([
    run("file", [path]),
    run("otool", ["-arch", arch, "-L", path]),
    run("nm", ["-arch", arch, "-m", path], { maxBuffer: 64 * 1024 * 1024 }),
    run("strings", ["-a", "-n", "8", path], { maxBuffer: 64 * 1024 * 1024 }),
  ]);

  const parsedSymbols = parseNm(symbols.stdout);
  const imports = parsedSymbols.imports;
  const exportedFunctions = parsedSymbols.defined.slice(0, 1000);
  const strings = parseStrings(stringRows.stdout, maxStrings);
  const dylibs = parseDylibs(libraries.stdout);
  const binaryId = createHash("sha256").update(`${path}:${arch}:${fileInfo.stdout}`).digest("hex").slice(0, 16);

  return {
    sessionId: `real-${binaryId}`,
    binaryId,
    binary: {
      name: basename(path),
      path,
      format: "Mach-O",
      arch,
      fileInfo: fileInfo.stdout.trim(),
      libraries: dylibs,
    },
    capabilities: {
      officialApi: false,
      privateApi: false,
      dynamicDebugger: false,
      source: "local-macho-importer",
    },
    imports,
    exports: exportedFunctions.map((symbol) => symbol.name),
    strings,
    objcClasses: inferObjCClasses(strings),
    swiftSymbols: imports.filter((name) => name.startsWith("_$s")).slice(0, 500),
    functions: buildFunctions({ exportedFunctions, imports, strings, dylibs }),
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

async function run(command, args, options = {}) {
  try {
    return await execFileAsync(command, args, { maxBuffer: options.maxBuffer ?? 8 * 1024 * 1024 });
  } catch (error) {
    if (error.stdout || error.stderr) return { stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
    throw error;
  }
}
