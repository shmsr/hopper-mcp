import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { normalizeSession } from "./knowledge-store.js";

const DEFAULT_OSASCRIPT = "/usr/bin/osascript";

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

  return runHopperExporter({
    hopperLauncher,
    timeoutMs,
    maxFunctions: effectiveMaxFunctions,
    maxStrings: effectiveMaxStrings,
    maxBlocksPerFunction: effectiveMaxBlocksPerFunction,
    maxInstructionsPerBlock: effectiveMaxInstructionsPerBlock,
    waitForAnalysis: effectiveWaitForAnalysis,
    fullExport,
    failOnTruncation,
    buildAppleScript: (scriptPath) => buildOpenExecutableAppleScript({
      executablePath,
      scriptPath,
      analysis,
      parseObjectiveC,
      parseSwift,
    }),
    diagnostics: {
      mode: "open_executable",
      parseObjectiveC,
      parseSwift,
      analysis,
      executablePath,
      fullExport,
      waitForAnalysis: effectiveWaitForAnalysis,
    },
  });
}

async function runHopperExporter({
  hopperLauncher,
  timeoutMs,
  maxFunctions,
  maxStrings,
  maxBlocksPerFunction,
  maxInstructionsPerBlock,
  waitForAnalysis,
  fullExport,
  failOnTruncation,
  buildAppleScript,
  diagnostics,
}) {
  const workdir = await mkdtemp(join(tmpdir(), "hopper-live-"));
  const outputPath = join(workdir, "session.json");
  const scriptPath = join(workdir, "export_live_session.py");
  await writeFile(scriptPath, buildExportScript({ outputPath, maxFunctions, maxStrings, maxBlocksPerFunction, maxInstructionsPerBlock, waitForAnalysis, fullExport, failOnTruncation }), "utf8");

  const appleScript = buildAppleScript(scriptPath);
  const args = ["-e", appleScript];

  const child = spawn(hopperLauncher, args, { stdio: ["ignore", "pipe", "pipe"] });
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
      hopperLauncher,
      args,
      ...diagnostics,
      outputPath,
    }));
    return {
      session: normalizeSession(session),
      launch: {
        hopperLauncher,
        args,
        appleScript,
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
  if (details.childExit?.code === 0) {
    return "Hopper accepted the AppleScript request, but the exporter did not write a session file before the timeout. If this is a large binary, retry with import_macho or smaller max_functions/max_strings.";
  }
  if (details.parseObjectiveC || details.parseSwift) {
    return "For large Mach-O files, retry with parse_objective_c=false and parse_swift=false first.";
  }
  return "Hopper may still be analyzing the target or waiting for UI input.";
}

function buildExportScript({ outputPath, maxFunctions, maxStrings, maxBlocksPerFunction, maxInstructionsPerBlock, waitForAnalysis, fullExport, failOnTruncation }) {
  return String.raw`
import hashlib
import json
import traceback

OUTPUT_PATH = ${JSON.stringify(outputPath)}
MAX_FUNCTIONS = ${pythonLiteral(maxFunctions)}
MAX_STRINGS = ${pythonLiteral(maxStrings)}
MAX_BLOCKS_PER_FUNCTION = ${pythonLiteral(maxBlocksPerFunction)}
MAX_INSTRUCTIONS_PER_BLOCK = ${pythonLiteral(maxInstructionsPerBlock)}
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

def collect_basic_blocks(seg, proc):
    blocks = []
    block_count = safe_call(0, proc.getBasicBlockCount)
    block_limit = limit_count(block_count, MAX_BLOCKS_PER_FUNCTION)
    for block_index in range(block_limit):
        block = safe_call(None, proc.getBasicBlock, block_index)
        if block is None:
            continue
        start = safe_call(None, block.getStartingAddress)
        end = safe_call(None, block.getEndingAddress)
        instructions = []
        cursor = start
        count = 0
        instruction_limit = export_limit(MAX_INSTRUCTIONS_PER_BLOCK)
        while cursor is not None and end is not None and cursor <= end and (instruction_limit is None or count < instruction_limit):
            instr = safe_call(None, seg.getInstructionAtAddress, cursor)
            if instr is None:
                break
            text = safe_call("", instr.getInstructionString)
            args = []
            for arg_index in range(safe_call(0, instr.getArgumentCount)):
                args.append(safe_string(safe_call("", instr.getFormattedArgument, arg_index)))
            instructions.append({
                "addr": hx(cursor),
                "text": safe_string(text),
                "args": args,
            })
            length = safe_call(1, instr.getInstructionLength)
            if length <= 0:
                length = 1
            cursor = cursor + length
            count = count + 1
        blocks.append({
            "addr": hx(start),
            "end": hx(end),
            "summary": "Live Hopper basic block with %d sampled instruction(s)." % len(instructions),
            "instructions": instructions,
        })
    return blocks

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

def collect_functions(doc):
    functions = []
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
            callers = procedure_refs(safe_call([], proc.getAllCallerProcedures))
            callees = procedure_refs(safe_call([], proc.getAllCalleeProcedures))
            signature = safe_call(None, proc.signatureString)
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
                "summary": "Live Hopper procedure exported via official Python API.",
                "confidence": 0.8,
                "callers": callers,
                "callees": callees,
                "strings": [],
                "imports": [],
                "signature": safe_string(signature),
                "locals": local_vars,
                "source": "hopper-python-live",
                "basicBlocks": collect_basic_blocks(seg, proc),
                "fingerprint": {
                    "cfgShape": "blocks:%d" % safe_call(0, proc.getBasicBlockCount),
                    "importSignature": [],
                    "stringBag": []
                }
            })
    return {
        "items": functions,
        "total": total,
        "truncated": is_truncated(total, MAX_FUNCTIONS)
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
                    "instructionsPerBlock": MAX_INSTRUCTIONS_PER_BLOCK
                },
                "totals": {
                    "functions": function_export["total"],
                    "strings": string_export["total"]
                },
                "exported": {
                    "functions": len(function_export["items"]),
                    "strings": len(string_export["items"])
                },
                "truncated": truncated
            }
        },
        "functions": function_export["items"],
        "strings": string_export["items"],
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

function buildOpenExecutableAppleScript({ executablePath, scriptPath, analysis, parseObjectiveC, parseSwift }) {
  return [
    'tell application "Hopper Disassembler" to open executable POSIX file ',
    quoteAppleScriptString(executablePath),
    " analysis ",
    analysis ? "true" : "false",
    " parse objectivec ",
    parseObjectiveC ? "true" : "false",
    " parse swift ",
    parseSwift ? "true" : "false",
    " execute Python script POSIX file ",
    quoteAppleScriptString(scriptPath),
  ].join("");
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
