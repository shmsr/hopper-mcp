import { execFile, spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { normalizeSession } from "./knowledge-store.js";
import { OfficialHopperBackend, officialToolPayload } from "./official-hopper-backend.js";
import { buildOfficialSnapshot } from "./official-snapshot.js";

const DEFAULT_OSASCRIPT = "/usr/bin/osascript";
const DEFAULT_HOPPER_CLI = "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler";
const execFileAsync = promisify(execFile);
const PREFERRED_ARCHS = ["arm64e", "arm64", "x86_64"];
const liveIngestInFlight = new Map();
let liveIngestQueue = Promise.resolve();

export async function ingestWithLiveHopper({
  executablePath,
  hopperLauncher = DEFAULT_OSASCRIPT,
  analysis = true,
  parseObjectiveC = true,
  parseSwift = true,
  timeoutMs = 600000,
  maxFunctions,
  maxStrings,
  maxBlocksPerFunction,
  maxInstructionsPerBlock,
  includePseudocode = false,
  maxPseudocodeFunctions,
  waitForAnalysis = false,
  fullExport = false,
  failOnTruncation = fullExport,
} = {}) {
  if (!executablePath) throw new Error("ingest_live_hopper requires executable_path.");
  const executableKey = normalizeExecutableKey(executablePath);
  const existing = liveIngestInFlight.get(executableKey);
  if (existing) return await existing;

  const task = enqueueLiveIngest(() => ingestWithLiveHopperUnlocked({
    executablePath,
    hopperLauncher,
    analysis,
    parseObjectiveC,
    parseSwift,
    timeoutMs,
    maxFunctions,
    maxStrings,
    maxBlocksPerFunction,
    maxInstructionsPerBlock,
    includePseudocode,
    maxPseudocodeFunctions,
    waitForAnalysis,
    fullExport,
    failOnTruncation,
  }));
  liveIngestInFlight.set(executableKey, task);
  try {
    return await task;
  } finally {
    if (liveIngestInFlight.get(executableKey) === task) liveIngestInFlight.delete(executableKey);
  }
}

async function ingestWithLiveHopperUnlocked({
  executablePath,
  hopperLauncher = DEFAULT_OSASCRIPT,
  analysis = true,
  parseObjectiveC = true,
  parseSwift = true,
  timeoutMs = 600000,
  maxFunctions,
  maxStrings,
  maxBlocksPerFunction,
  maxInstructionsPerBlock,
  includePseudocode = false,
  maxPseudocodeFunctions,
  waitForAnalysis = false,
  fullExport = false,
  failOnTruncation = fullExport,
} = {}) {
  if (!executablePath) throw new Error("ingest_live_hopper requires executable_path.");

  const effectiveWaitForAnalysis = fullExport ? true : waitForAnalysis;
  const effectiveMaxFunctions = fullExport ? (maxFunctions ?? null) : (maxFunctions ?? 5000);
  const effectiveMaxStrings = fullExport ? (maxStrings ?? null) : (maxStrings ?? 10000);
  const effectiveMaxBlocksPerFunction = fullExport ? (maxBlocksPerFunction ?? null) : (maxBlocksPerFunction ?? 64);
  const effectiveMaxInstructionsPerBlock = fullExport ? (maxInstructionsPerBlock ?? null) : (maxInstructionsPerBlock ?? 24);
  const effectiveMaxPseudocodeFunctions = includePseudocode ? (maxPseudocodeFunctions ?? 25) : 0;
  const officialBackend = new OfficialHopperBackend({
    timeoutMs: Math.min(Math.max(10000, Math.floor(timeoutMs / 4)), 30000),
  });

  try {
    const baselineCurrentDocument = await safeCurrentDocument(officialBackend);
    const reusableCurrentDocument = await shouldReuseCurrentDocument({
      officialBackend,
      executablePath,
      currentDocument: baselineCurrentDocument,
    });
    const launch = await launchExecutableInHopper({
      executablePath,
      hopperLauncher,
      analysis,
      parseObjectiveC,
      parseSwift,
      skipLaunch: reusableCurrentDocument,
    });
    const snapshot = await waitForOfficialSnapshot({
      officialBackend,
      executablePath,
      baselineCurrentDocument,
      timeoutMs,
      maxFunctions: effectiveMaxFunctions,
      includePseudocode,
      failOnTruncation,
    });
    snapshot.sessionId = `live-${snapshot.sessionId ?? safeId(basename(executablePath))}`;
    snapshot.binaryId = `live-${snapshot.binaryId ?? safeId(basename(executablePath))}`;
    applyLiveExportLimits(snapshot, {
      maxStrings: effectiveMaxStrings,
      maxPseudocodeFunctions: effectiveMaxPseudocodeFunctions,
      fullExport,
      waitForAnalysis: effectiveWaitForAnalysis,
      failOnTruncation,
      maxFunctions: effectiveMaxFunctions,
      maxBlocksPerFunction: effectiveMaxBlocksPerFunction,
      maxInstructionsPerBlock: effectiveMaxInstructionsPerBlock,
    });
    await enrichSnapshotBinary(snapshot, executablePath);
    return {
      session: normalizeSession(snapshot),
      launch,
    };
  } finally {
    officialBackend.close();
  }
}

function enqueueLiveIngest(work) {
  const task = liveIngestQueue
    .catch(() => {})
    .then(work);
  liveIngestQueue = task.catch(() => {});
  return task;
}

async function launchExecutableInHopper({
  executablePath,
  hopperLauncher,
  analysis,
  parseObjectiveC,
  parseSwift,
  skipLaunch = false,
}) {
  if (skipLaunch) {
    return {
      hopperLauncher: null,
      args: [],
      mode: "reuse_current_document",
      appleScript: null,
      stdout: "",
      stderr: "",
      skipped: true,
    };
  }

  const launch = buildLaunchSpec({
    executablePath,
    analysis,
    parseObjectiveC,
    parseSwift,
    hopperLauncher,
  });

  if (launch.mode === "cli") {
    const child = spawn(launch.command, launch.args, {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    return {
      hopperLauncher: launch.command,
      args: launch.args,
      mode: launch.mode,
      appleScript: null,
      stdout: "",
      stderr: "",
      skipped: false,
    };
  }

  const launched = await execFileAsync(launch.command, launch.args, {
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });
  return {
    hopperLauncher: launch.command,
    args: launch.args,
    mode: launch.mode,
    appleScript: launch.appleScript ?? null,
    stdout: launched.stdout ?? "",
    stderr: launched.stderr ?? "",
    skipped: false,
  };
}

async function shouldReuseCurrentDocument({
  officialBackend,
  executablePath,
  currentDocument,
}) {
  if (currentDocument !== basename(executablePath)) return false;
  try {
    const procedures = await officialBackend.callTool("list_procedures", {});
    const procedureIndex = officialToolPayload(procedures);
    if (procedureIndex && typeof procedureIndex === "object" && Object.keys(procedureIndex).length > 0) return true;
  } catch {
    return true;
  }
  return true;
}

async function waitForOfficialSnapshot({
  officialBackend,
  executablePath,
  baselineCurrentDocument,
  timeoutMs,
  maxFunctions,
  includePseudocode,
  failOnTruncation,
}) {
  const deadline = Date.now() + timeoutMs;
  const expectedName = basename(executablePath);
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const currentDocument = await safeCurrentDocument(officialBackend);
      const documents = await safeDocumentList(officialBackend);
      const shouldProbe =
        currentDocument === expectedName ||
        (currentDocument && currentDocument !== baselineCurrentDocument) ||
        documents.includes(expectedName);

      if (shouldProbe) {
        const procedures = await officialBackend.callTool("list_procedures", {});
        const procedureIndex = officialToolPayload(procedures);
        if (procedureIndex && typeof procedureIndex === "object" && Object.keys(procedureIndex).length > 0) {
          return await buildOfficialSnapshot(officialBackend, {
            maxProcedures: maxFunctions,
            includeProcedureInfo: true,
            includeAssembly: true,
            includePseudocode,
            includeCallGraph: true,
            failOnTruncation,
          });
        }
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error(`Timed out waiting for Hopper to analyze '${expectedName}' through the official backend.${lastError ? ` Last error: ${String(lastError.message ?? lastError)}` : ""}`);
}

async function safeCurrentDocument(officialBackend) {
  try {
    const result = await officialBackend.callTool("current_document", {});
    return officialToolPayload(result);
  } catch {
    return null;
  }
}

async function safeDocumentList(officialBackend) {
  try {
    const result = await officialBackend.callTool("list_documents", {});
    const payload = officialToolPayload(result);
    return Array.isArray(payload) ? payload : [];
  } catch {
    return [];
  }
}

function applyLiveExportLimits(snapshot, {
  maxStrings,
  maxPseudocodeFunctions,
  fullExport,
  waitForAnalysis,
  failOnTruncation,
  maxFunctions,
  maxBlocksPerFunction,
  maxInstructionsPerBlock,
}) {
  const stringLimit = normalizeLimit(maxStrings);
  const pseudocodeLimit = normalizeLimit(maxPseudocodeFunctions);
  const originalStringCount = snapshot.strings?.length ?? 0;
  let stringsTruncated = false;

  if (stringLimit !== null && originalStringCount > stringLimit) {
    snapshot.strings = snapshot.strings.slice(0, stringLimit);
    stringsTruncated = true;
  }

  if (pseudocodeLimit !== null && pseudocodeLimit >= 0) {
    let exportedPseudocode = 0;
    for (const fn of snapshot.functions ?? []) {
      if (!fn.pseudocode) continue;
      if (exportedPseudocode >= pseudocodeLimit) {
        fn.pseudocode = null;
      } else {
        exportedPseudocode += 1;
      }
    }
  }

  const totals = snapshot.capabilities?.officialSnapshot?.totals ?? {};
  const exported = snapshot.capabilities?.officialSnapshot?.exported ?? {};
  const truncated = snapshot.capabilities?.officialSnapshot?.truncated ?? {};
  snapshot.capabilities = {
    ...(snapshot.capabilities ?? {}),
    liveExport: {
      backend: "official-hopper-mcp",
      fullExport,
      waitForAnalysis,
      failOnTruncation,
      limits: {
        functions: maxFunctions ?? null,
        strings: maxStrings ?? null,
        blocksPerFunction: maxBlocksPerFunction ?? null,
        instructionsPerBlock: maxInstructionsPerBlock ?? null,
        pseudocodeFunctions: maxPseudocodeFunctions ?? null,
      },
      totals: {
        functions: totals.procedures ?? snapshot.functions?.length ?? 0,
        strings: totals.strings ?? originalStringCount,
        pseudocode: (snapshot.functions ?? []).filter((fn) => Boolean(fn.pseudocode)).length,
      },
      exported: {
        functions: exported.procedures ?? snapshot.functions?.length ?? 0,
        strings: snapshot.strings?.length ?? 0,
        pseudocode: (snapshot.functions ?? []).filter((fn) => Boolean(fn.pseudocode)).length,
      },
      truncated: {
        functions: Boolean(truncated.procedures),
        strings: stringsTruncated,
      },
    },
  };
}

async function enrichSnapshotBinary(snapshot, executablePath) {
  const metadata = await readMachOBinaryMetadata(executablePath);
  snapshot.binary = {
    ...(snapshot.binary ?? {}),
    name: snapshot.binary?.name ?? basename(executablePath),
    path: executablePath,
    arch: metadata.arch,
    requestedArch: metadata.requestedArch,
    availableArchs: metadata.availableArchs,
    fileInfo: metadata.fileInfo,
    libraries: metadata.libraries,
    entryPoint: metadata.entryPoint,
  };
}

async function readMachOBinaryMetadata(executablePath) {
  const archSelection = await resolveMachOArch(executablePath);
  const selectedArch = archSelection.arch;
  const [fileInfo, libraries, loadCommands] = await Promise.all([
    execFileAsync("file", [executablePath], { maxBuffer: 1024 * 1024 }),
    execFileAsync("otool", ["-arch", selectedArch, "-L", executablePath], { maxBuffer: 8 * 1024 * 1024 }),
    execFileAsync("otool", ["-arch", selectedArch, "-l", executablePath], { maxBuffer: 16 * 1024 * 1024 }),
  ]);

  return {
    arch: selectedArch,
    requestedArch: archSelection.requestedArch,
    availableArchs: archSelection.availableArchs,
    fileInfo: fileInfo.stdout.trim(),
    libraries: parseDylibs(libraries.stdout),
    entryPoint: parseEntryPoint(loadCommands.stdout),
  };
}

function parseEntryPoint(loadCommandsOutput) {
  const entryoffMatch = loadCommandsOutput.match(/cmd LC_MAIN[\s\S]*?entryoff\s+(\d+)/);
  if (!entryoffMatch) return null;
  const entryoff = Number(entryoffMatch[1]);
  if (!Number.isFinite(entryoff)) return null;

  const textMatch = loadCommandsOutput.match(/segname __TEXT[\s\S]*?vmaddr\s+0x([0-9a-fA-F]+)[\s\S]*?fileoff\s+(\d+)/);
  if (!textMatch) return null;
  const vmaddr = parseInt(textMatch[1], 16);
  const fileoff = Number(textMatch[2]);
  if (!Number.isFinite(vmaddr) || !Number.isFinite(fileoff)) return null;
  return `0x${(vmaddr + entryoff - fileoff).toString(16)}`;
}

async function resolveMachOArch(executablePath, requestedArch = "auto") {
  const requested = requestedArch ?? "auto";
  const availableArchs = await listMachOArchitectures(executablePath);
  if (!availableArchs.length) {
    if (requested === "auto") throw new Error(`Could not determine Mach-O architecture for ${executablePath}.`);
    return { arch: requested, requestedArch: requested, availableArchs };
  }
  if (requested !== "auto") {
    if (availableArchs.includes(requested)) return { arch: requested, requestedArch: requested, availableArchs };
    if (requested === "arm64" && availableArchs.includes("arm64e")) {
      return { arch: "arm64e", requestedArch: requested, availableArchs };
    }
    throw new Error(`Mach-O file ${executablePath} does not contain architecture '${requested}'. Available architectures: ${availableArchs.join(", ")}.`);
  }
  const preferred = PREFERRED_ARCHS.find((candidate) => availableArchs.includes(candidate));
  return {
    arch: preferred ?? availableArchs[0],
    requestedArch: requested,
    availableArchs,
  };
}

async function listMachOArchitectures(executablePath) {
  try {
    const result = await execFileAsync("lipo", ["-archs", executablePath], { maxBuffer: 1024 * 1024 });
    return result.stdout.trim().split(/\s+/).filter(Boolean);
  } catch (error) {
    const output = `${error.stdout ?? ""}\n${error.stderr ?? ""}`;
    const match = output.match(/Non-fat file: .+ is architecture: (\S+)/);
    if (match) return [match[1]];
    throw error;
  }
}

function normalizeLimit(value) {
  if (value === null || value === undefined) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Math.floor(parsed);
}

function safeId(value) {
  return String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "document";
}

function normalizeExecutableKey(executablePath) {
  return resolve(String(executablePath));
}

function parseDylibs(output) {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("/") || line.startsWith("@"))
    .map((line) => line.replace(/\s+\(.+$/, ""))
    .filter(Boolean);
}

async function runHopperExporter({
  hopperLauncher,
  timeoutMs,
  maxFunctions,
  maxStrings,
  maxBlocksPerFunction,
  maxInstructionsPerBlock,
  includePseudocode,
  maxPseudocodeFunctions,
  waitForAnalysis,
  fullExport,
  failOnTruncation,
  buildLaunchSpec,
  diagnostics,
}) {
  const workdir = await mkdtemp(join(tmpdir(), "hopper-live-"));
  const outputPath = join(workdir, "session.json");
  const scriptPath = join(workdir, "export_live_session.py");
  await writeFile(scriptPath, buildExportScript({ outputPath, maxFunctions, maxStrings, maxBlocksPerFunction, maxInstructionsPerBlock, includePseudocode, maxPseudocodeFunctions, waitForAnalysis, fullExport, failOnTruncation }), "utf8");

  const launch = buildLaunchSpec(scriptPath);
  const { command, args, mode } = launch;

  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let childExit = null;
  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  child.on("exit", (code, signal) => {
    childExit = { code, signal };
  });

  try {
    const session = await waitForJson(outputPath, timeoutMs, () => ({
      stdout,
      stderr,
      childExit,
      hopperLauncher: command,
      args,
      mode,
      ...diagnostics,
      outputPath,
    }));
    return {
      session: normalizeSession(session),
      launch: {
        hopperLauncher: command,
        args,
        mode,
        appleScript: launch.appleScript ?? null,
        stdout: stdout.slice(-4000),
        stderr: stderr.slice(-4000),
        outputPath,
      },
    };
  } finally {
    child.kill();
    if (process.env.HOPPER_LIVE_KEEP_TEMP !== "1") {
      await rm(workdir, { recursive: true, force: true });
    }
  }
}

async function waitForJson(path, timeoutMs, diagnostics) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    const details = diagnostics();
    if (details.childExit && details.childExit.code !== 0) {
      throw new Error(`Hopper launcher exited before writing a session file.${launcherFailureHint(details)} Diagnostics: ${JSON.stringify({
        childExit: details.childExit,
        hopperLauncher: details.hopperLauncher,
        args: details.args,
        outputPath: details.outputPath,
        stdoutTail: details.stdout.slice(-1000),
        stderrTail: details.stderr.slice(-1000),
      })}`);
    }
    try {
      const text = await readFile(path, "utf8");
      if (text.trim()) {
        const parsed = JSON.parse(text);
        if (parsed.error) throw new Error(`Hopper live exporter failed: ${parsed.error}\n${parsed.traceback ?? ""}`);
        return parsed;
      }
    } catch (error) {
      if (error.code === "ENOENT") {
        // Hopper has not created the export file yet.
      } else if (error instanceof SyntaxError) {
        // The exporter may still be writing JSON. Keep polling until the file is complete.
        lastError = error;
      } else {
        throw error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  const details = diagnostics();
  throw new Error(`Timed out waiting for Hopper live export after ${timeoutMs}ms.${lastError ? ` Last error: ${lastError.message}` : ""} ${timeoutHint(details)} Diagnostics: ${JSON.stringify({
    childExit: details.childExit,
    hopperLauncher: details.hopperLauncher,
    args: details.args,
    outputPath: details.outputPath,
    stdoutTail: details.stdout.slice(-1000),
    stderrTail: details.stderr.slice(-1000),
  })}`);
}

function timeoutHint(details) {
  if (details.mode === "cli") {
    return "Hopper launched through its CLI, but the exporter did not write a session file before the timeout.";
  }
  if (details.childExit?.code === 0) {
    return "Hopper accepted the AppleScript request, but the exporter did not write a session file before the timeout. If this is a large binary, retry with import_macho or smaller max_functions/max_strings.";
  }
  if (details.parseObjectiveC || details.parseSwift) {
    return "For large Mach-O files, retry with parse_objective_c=false and parse_swift=false first.";
  }
  return "Hopper may still be analyzing the target or waiting for UI input.";
}

function launcherFailureHint(details) {
  const tail = [details.stderr, details.stdout].filter(Boolean).join("\n");
  if (/Not authorized to send Apple events/i.test(tail)) {
    return " macOS blocked Automation access.";
  }
  if (details.mode === "osascript") {
    return " AppleScript failed before Hopper started the exporter.";
  }
  return " Hopper CLI failed before the exporter script ran.";
}

function buildExportScript({ outputPath, maxFunctions, maxStrings, maxBlocksPerFunction, maxInstructionsPerBlock, includePseudocode, maxPseudocodeFunctions, waitForAnalysis, fullExport, failOnTruncation }) {
  return String.raw`
import hashlib
import json
import traceback

OUTPUT_PATH = ${JSON.stringify(outputPath)}
MAX_FUNCTIONS = ${pythonLiteral(maxFunctions)}
MAX_STRINGS = ${pythonLiteral(maxStrings)}
MAX_BLOCKS_PER_FUNCTION = ${pythonLiteral(maxBlocksPerFunction)}
MAX_INSTRUCTIONS_PER_BLOCK = ${pythonLiteral(maxInstructionsPerBlock)}
INCLUDE_PSEUDOCODE = ${pythonBool(includePseudocode)}
MAX_PSEUDOCODE_FUNCTIONS = ${pythonLiteral(maxPseudocodeFunctions)}
WAIT_FOR_ANALYSIS = ${pythonBool(waitForAnalysis)}
FULL_EXPORT = ${pythonBool(fullExport)}
FAIL_ON_TRUNCATION = ${pythonBool(failOnTruncation)}

def hx(value):
    try:
        if value is None or value < 0:
            return None
        return hex(value)
    except Exception:
        return None

def safe_string(value):
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return repr(value)

def safe_call(default, func, *args):
    try:
        value = func(*args)
        if value is None:
            return default
        return value
    except Exception:
        return default

def stable_id(prefix, *parts):
    h = hashlib.sha256()
    for part in parts:
        h.update((safe_string(part) or "<none>").encode("utf-8", "replace"))
        h.update(b"\x00")
    return "%s-%s" % (prefix, h.hexdigest()[:16])

def limit_count(total, limit):
    if limit is None:
        return total
    try:
        if limit < 0:
            return total
    except Exception:
        return total
    return min(total, limit)

def is_truncated(total, limit):
    if limit is None:
        return False
    try:
        if limit < 0:
            return False
    except Exception:
        return False
    return total > limit

def export_limit(limit):
    return None if limit is None or limit < 0 else limit

def procedure_addr(proc):
    return safe_call(None, proc.getEntryPoint)

def procedure_name(doc, proc):
    addr = procedure_addr(proc)
    name = safe_call(None, doc.getNameAtAddress, addr)
    if name:
        return safe_string(name)
    if addr is None:
        return "unknown_procedure"
    return "sub_%x" % addr

def procedure_refs(procs):
    refs = []
    for proc in procs or []:
        addr = procedure_addr(proc)
        if addr is not None:
            refs.append(hx(addr))
    return refs

def call_ref(ref):
    return {
        "from": hx(safe_call(None, ref.fromAddress)),
        "to": hx(safe_call(None, ref.toAddress)),
        "type": safe_call(None, ref.type)
    }

def collect_call_refs(refs):
    items = []
    for ref in refs or []:
        items.append(call_ref(ref))
    return items

def collect_basic_blocks(seg, proc):
    blocks = []
    comment_addresses = set()
    block_count = safe_call(0, proc.getBasicBlockCount)
    block_limit = limit_count(block_count, MAX_BLOCKS_PER_FUNCTION)
    for block_index in range(block_limit):
        block = safe_call(None, proc.getBasicBlock, block_index)
        if block is None:
            continue
        start = safe_call(None, block.getStartingAddress)
        end = safe_call(None, block.getEndingAddress)
        if start is not None:
            comment_addresses.add(start)
        if end is not None:
            comment_addresses.add(end)
        successors = []
        for successor_index in range(safe_call(0, block.getSuccessorCount)):
            successors.append(hx(safe_call(None, block.getSuccessorAddressAtIndex, successor_index)))
        instructions = []
        cursor = start
        count = 0
        instruction_limit = export_limit(MAX_INSTRUCTIONS_PER_BLOCK)
        while cursor is not None and end is not None and cursor <= end and (instruction_limit is None or count < instruction_limit):
            instr = safe_call(None, seg.getInstructionAtAddress, cursor)
            if instr is None:
                break
            comment_addresses.add(cursor)
            text = safe_call("", instr.getInstructionString)
            args = []
            for arg_index in range(safe_call(0, instr.getArgumentCount)):
                args.append(safe_string(safe_call("", instr.getFormattedArgument, arg_index)))
            instructions.append({
                "addr": hx(cursor),
                "text": safe_string(text),
                "args": args,
                "refsFrom": [hx(value) for value in safe_call([], seg.getReferencesFromAddress, cursor)],
            })
            length = safe_call(1, instr.getInstructionLength)
            if length <= 0:
                length = 1
            cursor = cursor + length
            count = count + 1
        blocks.append({
            "addr": hx(start),
            "from": hx(start),
            "end": hx(end),
            "to": hx(end),
            "successors": successors,
            "summary": "Live Hopper basic block with %d sampled instruction(s)." % len(instructions),
            "instructions": instructions,
        })
    return {"blocks": blocks, "commentAddresses": list(comment_addresses)}

def collect_strings(doc):
    strings = []
    total = 0
    for seg in safe_call([], doc.getSegmentsList):
        for value, addr in safe_call([], seg.getStringsList):
            total = total + 1
            if MAX_STRINGS is None or MAX_STRINGS < 0 or len(strings) < MAX_STRINGS:
                strings.append({"addr": hx(addr), "value": safe_string(value)})
    return {
        "items": strings,
        "total": total,
        "truncated": is_truncated(total, MAX_STRINGS)
    }

def collect_segments(doc):
    segments = []
    for seg in safe_call([], doc.getSegmentsList):
        sections = []
        for section in safe_call([], seg.getSectionsList):
            sections.append({
                "name": safe_string(safe_call("", section.getName)),
                "start": hx(safe_call(None, section.getStartingAddress)),
                "length": safe_call(0, section.getLength),
                "flags": safe_call(0, section.getFlags),
            })
        segments.append({
            "name": safe_string(safe_call("", seg.getName)),
            "start": hx(safe_call(None, seg.getStartingAddress)),
            "length": safe_call(0, seg.getLength),
            "fileOffset": safe_call(0, seg.getFileOffset),
            "sections": sections,
        })
    return segments

def collect_names(doc):
    names = []
    for seg in safe_call([], doc.getSegmentsList):
        labels = safe_call([], seg.getLabelsList)
        addresses = safe_call([], seg.getNamedAddresses)
        for index, addr in enumerate(addresses):
            label = labels[index] if index < len(labels) else safe_call(None, seg.getNameAtAddress, addr)
            names.append({
                "addr": hx(addr),
                "name": safe_string(label),
                "demangled": safe_string(safe_call(None, seg.getDemangledNameAtAddress, addr)),
                "segment": safe_string(safe_call("", seg.getName)),
            })
    return names

def collect_bookmarks(doc):
    bookmarks = []
    for addr in safe_call([], doc.getBookmarks):
        bookmarks.append({
            "addr": hx(addr),
            "name": safe_string(safe_call(None, doc.getBookmarkName, addr)),
        })
    return bookmarks

def collect_comments(doc, addresses):
    comments = []
    inline_comments = []
    for addr in sorted(addresses):
        seg = safe_call(None, doc.getSegmentAtAddress, addr)
        if seg is None:
            continue
        comment = safe_string(safe_call(None, seg.getCommentAtAddress, addr))
        inline = safe_string(safe_call(None, seg.getInlineCommentAtAddress, addr))
        if comment:
            comments.append({"addr": hx(addr), "comment": comment})
        if inline:
            inline_comments.append({"addr": hx(addr), "comment": inline})
    return {"comments": comments, "inlineComments": inline_comments}

def collect_current(doc):
    current_addr = safe_call(None, doc.getCurrentAddress)
    current_proc = safe_call(None, doc.getCurrentProcedure)
    selection = safe_call([], doc.getSelectionAddressRange)
    return {
        "address": hx(current_addr),
        "procedure": hx(procedure_addr(current_proc)) if current_proc is not None else None,
        "selection": [hx(value) for value in selection] if selection else []
    }

def collect_functions(doc):
    functions = []
    comment_addresses = set()
    pseudocode_count = 0
    total = 0
    for seg in safe_call([], doc.getSegmentsList):
        count = safe_call(0, seg.getProcedureCount)
        total = total + count
        for index in range(count):
            if MAX_FUNCTIONS is not None and MAX_FUNCTIONS >= 0 and len(functions) >= MAX_FUNCTIONS:
                continue
            proc = safe_call(None, seg.getProcedureAtIndex, index)
            if proc is None:
                continue
            addr = procedure_addr(proc)
            if addr is None:
                continue
            comment_addresses.add(addr)
            callers = procedure_refs(safe_call([], proc.getAllCallerProcedures))
            callees = procedure_refs(safe_call([], proc.getAllCalleeProcedures))
            caller_refs = collect_call_refs(safe_call([], proc.getAllCallers))
            callee_refs = collect_call_refs(safe_call([], proc.getAllCallees))
            signature = safe_call(None, proc.signatureString)
            block_export = collect_basic_blocks(seg, proc)
            for comment_addr in block_export["commentAddresses"]:
                comment_addresses.add(comment_addr)
            pseudocode = None
            if INCLUDE_PSEUDOCODE and (MAX_PSEUDOCODE_FUNCTIONS is None or pseudocode_count < MAX_PSEUDOCODE_FUNCTIONS):
                pseudocode = safe_string(safe_call(None, proc.decompile))
                pseudocode_count = pseudocode_count + 1
            local_vars = []
            for local in safe_call([], proc.getLocalVariableList):
                local_vars.append({
                    "name": safe_string(safe_call("", local.name)),
                    "displacement": safe_call(0, local.displacement),
                })
            functions.append({
                "addr": hx(addr),
                "name": procedure_name(doc, proc),
                "size": safe_call(None, proc.getHeapSize),
                "basicBlockCount": safe_call(0, proc.getBasicBlockCount),
                "summary": "Live Hopper procedure exported via official Python API.",
                "confidence": 0.8,
                "callers": callers,
                "callees": callees,
                "callerRefs": caller_refs,
                "calleeRefs": callee_refs,
                "xrefsFrom": callee_refs,
                "xrefsTo": caller_refs,
                "strings": [],
                "imports": [],
                "signature": safe_string(signature),
                "locals": local_vars,
                "pseudocode": pseudocode,
                "source": "hopper-python-live",
                "basicBlocks": block_export["blocks"],
                "assembly": "\n".join([
                    "%s: %s" % (instr.get("addr"), instr.get("text"))
                    for block in block_export["blocks"]
                    for instr in block.get("instructions", [])
                ]),
                "fingerprint": {
                    "cfgShape": "blocks:%d" % safe_call(0, proc.getBasicBlockCount),
                    "importSignature": [],
                    "stringBag": []
                }
            })
    return {
        "items": functions,
        "total": total,
        "truncated": is_truncated(total, MAX_FUNCTIONS),
        "commentAddresses": list(comment_addresses),
        "pseudocodeExported": pseudocode_count
    }

try:
    doc = Document.getCurrentDocument()
    if WAIT_FOR_ANALYSIS:
        doc.waitForBackgroundProcessToEnd()
    executable_path = safe_call(None, doc.getExecutableFilePath)
    database_path = safe_call(None, doc.getDatabaseFilePath)
    document_name = safe_call("Hopper Document", doc.getDocumentName)
    function_export = collect_functions(doc)
    string_export = collect_strings(doc)
    names = collect_names(doc)
    bookmarks = collect_bookmarks(doc)
    comment_addresses = set(function_export["commentAddresses"])
    for item in string_export["items"]:
        parsed = int(item["addr"], 16) if item.get("addr") else None
        if parsed is not None:
            comment_addresses.add(parsed)
    for item in names:
        parsed = int(item["addr"], 16) if item.get("addr") else None
        if parsed is not None:
            comment_addresses.add(parsed)
    for item in bookmarks:
        parsed = int(item["addr"], 16) if item.get("addr") else None
        if parsed is not None:
            comment_addresses.add(parsed)
    comments = collect_comments(doc, comment_addresses)
    truncated = {
        "functions": function_export["truncated"],
        "strings": string_export["truncated"],
    }
    if FAIL_ON_TRUNCATION and (truncated["functions"] or truncated["strings"]):
        raise Exception("Hopper live export was truncated: %s" % json.dumps(truncated, sort_keys=True))
    session = {
        "sessionId": stable_id("hopper-live", document_name, executable_path, database_path),
        "binaryId": stable_id("hopper-live", executable_path, document_name),
        "binary": {
            "name": safe_string(document_name),
            "path": safe_string(executable_path),
            "databasePath": safe_string(database_path),
            "format": "Hopper live document",
            "arch": "64-bit" if safe_call(False, doc.is64Bits) else "32-bit",
            "entryPoint": hx(safe_call(None, doc.getEntryPoint)),
            "segments": collect_segments(doc)
        },
        "capabilities": {
            "officialApi": True,
            "privateApi": False,
            "dynamicDebugger": False,
            "source": "hopper-python-live",
            "writesRequirePreview": True,
            "liveExport": {
                "fullExport": FULL_EXPORT,
                "waitForAnalysis": WAIT_FOR_ANALYSIS,
                "failOnTruncation": FAIL_ON_TRUNCATION,
                "limits": {
                    "functions": MAX_FUNCTIONS,
                    "strings": MAX_STRINGS,
                    "blocksPerFunction": MAX_BLOCKS_PER_FUNCTION,
                    "instructionsPerBlock": MAX_INSTRUCTIONS_PER_BLOCK,
                    "pseudocodeFunctions": MAX_PSEUDOCODE_FUNCTIONS
                },
                "totals": {
                    "functions": function_export["total"],
                    "strings": string_export["total"],
                    "pseudocode": function_export["pseudocodeExported"]
                },
                "exported": {
                    "functions": len(function_export["items"]),
                    "strings": len(string_export["items"]),
                    "pseudocode": function_export["pseudocodeExported"]
                },
                "truncated": truncated
            }
        },
        "functions": function_export["items"],
        "strings": string_export["items"],
        "names": names,
        "bookmarks": bookmarks,
        "comments": comments["comments"],
        "inlineComments": comments["inlineComments"],
        "cursor": collect_current(doc),
        "imports": [],
        "exports": [],
        "objcClasses": [],
        "swiftSymbols": [],
        "transactions": {"pending": []}
    }
    with open(OUTPUT_PATH, "w") as out:
        json.dump(session, out, ensure_ascii=True)
except Exception as error:
    with open(OUTPUT_PATH, "w") as out:
        json.dump({"error": str(error), "traceback": traceback.format_exc()}, out)
`;
}

function buildOpenExecutableAppleScript({ executablePath, analysis, parseObjectiveC, parseSwift }) {
  return [
    'tell application "Hopper Disassembler" to open executable POSIX file ',
    quoteAppleScriptString(executablePath),
    " analysis ",
    analysis ? "true" : "false",
    " parse objectivec ",
    parseObjectiveC ? "true" : "false",
    " parse swift ",
    parseSwift ? "true" : "false",
  ].join("");
}

function buildLaunchSpec({ executablePath, analysis, parseObjectiveC, parseSwift, hopperLauncher }) {
  const launcher = hopperLauncher ?? DEFAULT_HOPPER_CLI;
  if (isOsaScriptLauncher(launcher)) {
    const appleScript = buildOpenExecutableAppleScript({ executablePath, analysis, parseObjectiveC, parseSwift });
    return {
      command: launcher,
      args: ["-e", appleScript],
      mode: "osascript",
      appleScript,
    };
  }
  return {
    command: launcher,
    args: [
      "-executable",
      executablePath,
    ],
    mode: "cli",
  };
}

function isOsaScriptLauncher(value) {
  return /(?:^|\/)osascript$/i.test(String(value ?? ""));
}

function pythonBool(value) {
  return value ? "True" : "False";
}

function pythonLiteral(value) {
  if (value === null || value === undefined) return "None";
  return JSON.stringify(value);
}

function quoteAppleScriptString(value) {
  return `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}
