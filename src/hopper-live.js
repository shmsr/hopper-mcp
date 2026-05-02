import { execFile, spawn } from "node:child_process";
import { access, mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { normalizeSession } from "./knowledge-store.js";
import { OfficialHopperBackend, officialToolPayload } from "./official-hopper-backend.js";
import { buildOfficialSnapshot } from "./official-snapshot.js";
import { cleanupCommandsFromEnv, cleanupHopperState, cleanupTimingFromEnv } from "./hopper-cleanup.js";

const DEFAULT_OSASCRIPT = "/usr/bin/osascript";
const DEFAULT_OPEN = "/usr/bin/open";
const DEFAULT_HOPPER_CLI = "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper";
const DEFAULT_HOPPER_LOADER = process.env.HOPPER_DEFAULT_LOADER ?? "Mach-O";
const HOPPER_FAT_LOADER = "FAT";
const HOPPER_MACHO_LOADER = "Mach-O";
const execFileAsync = promisify(execFile);
const liveIngestInFlight = new Map();
let liveIngestQueue = Promise.resolve();

export async function ingestWithLiveHopper({
  executablePath,
  hopperLauncher = DEFAULT_HOPPER_CLI,
  analysis = true,
  loader = DEFAULT_HOPPER_LOADER,
  loaderCheckboxes,
  onlyProcedures,
  parseObjectiveC = true,
  parseSwift = true,
  parseExceptions = true,
  closeAfterExport = false,
  liveBackend = process.env.HOPPER_LIVE_BACKEND ?? "python",
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
  officialBackend = null,
} = {}) {
  if (!executablePath) throw new Error("ingest_live_hopper requires executable_path.");
  const executableKey = normalizeExecutableKey(executablePath);
  const existing = liveIngestInFlight.get(executableKey);
  if (existing) return await existing;

  const task = enqueueLiveIngest(() => ingestWithLiveHopperUnlocked({
    executablePath,
    hopperLauncher,
    analysis,
    loader,
    loaderCheckboxes,
    onlyProcedures,
    parseObjectiveC,
    parseSwift,
    parseExceptions,
    closeAfterExport,
    liveBackend,
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
    officialBackend,
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
  hopperLauncher = DEFAULT_HOPPER_CLI,
  analysis = true,
  loader = DEFAULT_HOPPER_LOADER,
  loaderCheckboxes,
  onlyProcedures,
  parseObjectiveC = true,
  parseSwift = true,
  parseExceptions = true,
  closeAfterExport = false,
  liveBackend = process.env.HOPPER_LIVE_BACKEND ?? "python",
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
  officialBackend = null,
} = {}) {
  if (!executablePath) throw new Error("ingest_live_hopper requires executable_path.");
  const baselineWindowNames = closeAfterExport && isOsaScriptLauncher(DEFAULT_OSASCRIPT)
    ? await listHopperWindowNames({ hopperLauncher: DEFAULT_OSASCRIPT })
    : [];

  const effectiveWaitForAnalysis = fullExport ? true : waitForAnalysis;
  const effectiveLaunchAnalysis = effectivePythonLaunchAnalysis({
    analysis,
    waitForAnalysis: effectiveWaitForAnalysis,
    fullExport,
  });
  const effectiveOnlyProcedures = onlyProcedures ?? Boolean(loader && !effectiveLaunchAnalysis);
  const effectiveMaxFunctions = fullExport ? (maxFunctions ?? null) : (maxFunctions ?? 5000);
  const effectiveMaxStrings = fullExport ? (maxStrings ?? null) : (maxStrings ?? 10000);
  const defaultMaxBlocksPerFunction = effectiveOnlyProcedures && !effectiveLaunchAnalysis ? 4 : 64;
  const defaultMaxInstructionsPerBlock = effectiveOnlyProcedures && !effectiveLaunchAnalysis ? 8 : 24;
  const effectiveMaxBlocksPerFunction = fullExport ? (maxBlocksPerFunction ?? null) : (maxBlocksPerFunction ?? defaultMaxBlocksPerFunction);
  const effectiveMaxInstructionsPerBlock = fullExport ? (maxInstructionsPerBlock ?? null) : (maxInstructionsPerBlock ?? defaultMaxInstructionsPerBlock);
  const effectiveMaxPseudocodeFunctions = includePseudocode ? (maxPseudocodeFunctions ?? 25) : 0;
  const fastFunctionSummaries = effectiveOnlyProcedures && !effectiveLaunchAnalysis && !includePseudocode;
  const fatArch = await detectHopperFatArch({ executablePath, loader });

  await ensureHopperAppReady({
    hopperLauncher,
    officialBackend,
    timeoutMs,
  });

  if (liveBackend !== "official") {
    try {
      const exported = await runHopperExporter({
        hopperLauncher,
        timeoutMs,
        requestedExecutablePath: executablePath,
        maxFunctions: effectiveMaxFunctions,
        maxStrings: effectiveMaxStrings,
        maxBlocksPerFunction: effectiveMaxBlocksPerFunction,
        maxInstructionsPerBlock: effectiveMaxInstructionsPerBlock,
        includePseudocode,
        maxPseudocodeFunctions: effectiveMaxPseudocodeFunctions,
        fastFunctionSummaries,
        waitForAnalysis: effectiveWaitForAnalysis,
        fullExport,
        failOnTruncation,
        closeAfterExport,
        buildLaunchSpec: (scriptPath) => buildLiveExportLaunchSpec({
          executablePath,
          scriptPath,
          analysis: effectiveLaunchAnalysis,
          loader,
          loaderCheckboxes,
          fatArch,
          onlyProcedures: effectiveOnlyProcedures,
          parseObjectiveC,
          parseSwift,
          parseExceptions,
          hopperLauncher,
        }),
        diagnostics: {
          executablePath,
          requestedAnalysis: analysis,
          launchAnalysis: effectiveLaunchAnalysis,
          loader,
          loaderCheckboxes: loaderCheckboxes ?? null,
          fatArch,
          onlyProcedures: effectiveOnlyProcedures,
          fastFunctionSummaries,
          waitForAnalysis: effectiveWaitForAnalysis,
          fullExport,
          parseObjectiveC,
          parseSwift,
          parseExceptions,
          closeAfterExport,
          liveBackend: "python",
        },
      });
      if (shouldFallbackToOfficialLiveExportResult(exported.session)) {
        const fallback = await ingestWithOfficialBackend({
          executablePath,
          hopperLauncher,
          analysis: true,
          loader,
          loaderCheckboxes,
          fatArch,
          onlyProcedures,
          parseObjectiveC,
          parseSwift,
          parseExceptions,
          timeoutMs,
          maxFunctions: effectiveMaxFunctions,
          maxStrings: effectiveMaxStrings,
          maxBlocksPerFunction: effectiveMaxBlocksPerFunction,
          maxInstructionsPerBlock: effectiveMaxInstructionsPerBlock,
          includePseudocode,
          maxPseudocodeFunctions: effectiveMaxPseudocodeFunctions,
          waitForAnalysis: true,
          fullExport,
          failOnTruncation,
          closeAfterExport,
          baselineWindowNames,
          minimumProcedureCount: 10,
          officialBackend,
        });
        const fallbackReason = "Hopper live export produced an empty session; falling back to official Hopper snapshot.";
        fallback.launch = {
          ...(fallback.launch ?? {}),
          fallbackFrom: "hopper-python-bridge",
          fallbackReason,
        };
        fallback.session.capabilities = {
          ...(fallback.session.capabilities ?? {}),
          liveExport: {
            ...(fallback.session.capabilities?.liveExport ?? {}),
            backend: "hopper-official-fallback",
            fallbackFrom: "hopper-python-bridge",
            fallbackReason,
          },
        };
        return fallback;
      }
      if (closeAfterExport) {
        await closeHopperLaunchArtifacts({
          executablePath,
          hopperLauncher: DEFAULT_OSASCRIPT,
          baselineWindowNames,
        });
      } else {
        await focusExecutableDocument({
          officialBackend,
          executablePath,
        });
      }
      await enrichSnapshotBinary(exported.session, executablePath);
      exported.session.capabilities = {
        ...(exported.session.capabilities ?? {}),
        liveExport: {
          ...(exported.session.capabilities?.liveExport ?? {}),
          backend: "hopper-python-bridge",
          launchAnalysis: effectiveLaunchAnalysis,
          loader: loader ?? null,
          loaderCheckboxes: loaderCheckboxes ?? null,
          fatArch: fatArch ?? null,
          onlyProcedures: effectiveOnlyProcedures,
          fastFunctionSummaries,
        },
      };
      exported.session = normalizeSession(exported.session);
      return exported;
    } catch (error) {
      if (!shouldFallbackToOfficialLiveExport(error)) throw error;
      const fallback = await ingestWithOfficialBackend({
        executablePath,
        hopperLauncher,
        analysis,
        loader,
        loaderCheckboxes,
        fatArch,
        onlyProcedures,
        parseObjectiveC,
        parseSwift,
        parseExceptions,
        timeoutMs,
        maxFunctions: effectiveMaxFunctions,
        maxStrings: effectiveMaxStrings,
        maxBlocksPerFunction: effectiveMaxBlocksPerFunction,
        maxInstructionsPerBlock: effectiveMaxInstructionsPerBlock,
        includePseudocode,
        maxPseudocodeFunctions: effectiveMaxPseudocodeFunctions,
        waitForAnalysis: effectiveWaitForAnalysis,
        fullExport,
        failOnTruncation,
        closeAfterExport,
        baselineWindowNames,
        officialBackend,
      });
      fallback.launch = {
        ...(fallback.launch ?? {}),
        fallbackFrom: "hopper-python-bridge",
        fallbackReason: String(error?.message ?? error),
      };
      fallback.session.capabilities = {
        ...(fallback.session.capabilities ?? {}),
        liveExport: {
          ...(fallback.session.capabilities?.liveExport ?? {}),
          backend: "hopper-official-fallback",
          fallbackFrom: "hopper-python-bridge",
          fallbackReason: String(error?.message ?? error),
        },
      };
      return fallback;
    }
  }

  return await ingestWithOfficialBackend({
    executablePath,
    hopperLauncher,
    analysis,
    loader,
    loaderCheckboxes,
    fatArch,
    onlyProcedures,
    parseObjectiveC,
    parseSwift,
    parseExceptions,
    timeoutMs,
    maxFunctions: effectiveMaxFunctions,
    maxStrings: effectiveMaxStrings,
    maxBlocksPerFunction: effectiveMaxBlocksPerFunction,
    maxInstructionsPerBlock: effectiveMaxInstructionsPerBlock,
    includePseudocode,
    maxPseudocodeFunctions: effectiveMaxPseudocodeFunctions,
    waitForAnalysis: effectiveWaitForAnalysis,
    fullExport,
    failOnTruncation,
    closeAfterExport,
    baselineWindowNames,
    officialBackend,
  });
}

// Best-effort: ask Hopper to close a document by name. Used by close_session
// when the caller asked us to also evict the live document. Failures are
// swallowed by callers — the user may have closed the document already, or
// may be running without Automation permission.
export async function closeHopperDocument(documentName, { hopperLauncher = DEFAULT_OSASCRIPT } = {}) {
  if (!documentName) throw new Error("closeHopperDocument requires a document name.");
  if (!isOsaScriptLauncher(hopperLauncher)) {
    throw new Error("closeHopperDocument needs an osascript launcher to drive Hopper.");
  }
  const appleScript = [
    'tell application "Hopper Disassembler" to ',
    "close (every document whose name is ",
    quoteAppleScriptString(documentName),
    ") saving no",
  ].join("");
  try {
    await execFileAsync(hopperLauncher, ["-e", appleScript], {
      timeout: 15000,
      maxBuffer: 1024 * 1024,
    });
  } catch (err) {
    const output = `${err?.stdout ?? ""}\n${err?.stderr ?? ""}\n${err?.message ?? ""}`;
    if (/-1708/.test(output) || /doesn.t understand the .close. message/i.test(output)) {
      return await closeHopperDocumentWithSystemEvents(documentName, { hopperLauncher });
    }
    throw err;
  }
  return { documentName, appleScript };
}

async function closeHopperDocumentsForExecutable(executablePath) {
  const candidates = documentNameCandidates(executablePath);
  const results = [];
  for (const candidate of candidates) {
    try {
      results.push(await closeHopperDocument(candidate));
    } catch {
      // Best-effort cleanup only. The live ingest result has already been
      // captured, and a cleanup failure should not discard that evidence.
    }
  }
  return results;
}

async function closeHopperLaunchArtifacts({
  executablePath,
  hopperLauncher = DEFAULT_OSASCRIPT,
  baselineWindowNames = [],
}) {
  if (baselineWindowNames.length === 0) {
    const commands = cleanupCommandsFromEnv();
    const timing = cleanupTimingFromEnv();
    await cleanupHopperState({
      ...commands,
      ...timing,
    });
    return;
  }
  await closeHopperDocumentsForExecutable(executablePath);
  const openWindowNames = await listHopperWindowNames({ hopperLauncher });
  const untitledNames = [...new Set(openWindowNames.filter(isUntitledHopperWindowName))];
  for (const documentName of untitledNames) {
    try {
      await closeHopperDocument(documentName, { hopperLauncher });
    } catch {
      // Best-effort cleanup only.
    }
  }
}

async function listHopperWindowNames({ hopperLauncher = DEFAULT_OSASCRIPT } = {}) {
  if (!isOsaScriptLauncher(hopperLauncher)) return [];
  const appleScript = [
    'tell application "System Events"',
    '\n  if exists process "Hopper Disassembler" then',
    '\n    tell process "Hopper Disassembler" to get name of every window',
    "\n  end if",
    "\n  return {}",
    "\nend tell",
  ].join("");
  const result = await execFileAsync(hopperLauncher, ["-e", appleScript], {
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  return parseAppleScriptList(result.stdout ?? "");
}

async function closeHopperDocumentWithSystemEvents(documentName, { hopperLauncher = DEFAULT_OSASCRIPT } = {}) {
  if (!isOsaScriptLauncher(hopperLauncher)) {
    throw new Error("System Events Hopper close fallback needs osascript.");
  }
  const appleScript = [
    'tell application "System Events"',
    '\n  if exists process "Hopper Disassembler" then',
    '\n    tell process "Hopper Disassembler"',
    "\n      repeat with i from (count windows) to 1 by -1",
    "\n        set w to window i",
    "\n        if name of w is ",
    quoteAppleScriptString(documentName),
    " then",
    "\n          click button 1 of w",
    "\n          delay 0.2",
    "\n          if (count windows) >= i and (count sheets of window i) > 0 then",
    '\n            click button "Delete" of splitter group 1 of sheet 1 of window i',
    "\n            delay 0.2",
    "\n          end if",
    "\n        end if",
    "\n      end repeat",
    "\n    end tell",
    "\n  end if",
    "\nend tell",
  ].join("");
  await execFileAsync(hopperLauncher, ["-e", appleScript], {
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  return { documentName, appleScript, fallback: "system-events" };
}

async function ingestWithOfficialBackend({
  executablePath,
  hopperLauncher,
  analysis,
  loader,
  loaderCheckboxes,
  fatArch,
  onlyProcedures,
  parseObjectiveC,
  parseSwift,
  parseExceptions,
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
  closeAfterExport = false,
  baselineWindowNames = [],
  forceFreshLaunch = false,
  minimumProcedureCount = 1,
  officialBackend = null,
}) {
  const ownsBackend = !officialBackend;
  if (!officialBackend) {
    officialBackend = new OfficialHopperBackend({
      timeoutMs: Math.min(Math.max(10000, Math.floor(timeoutMs / 4)), 30000),
    });
  }

  try {
    const baselineCurrentDocument = await safeCurrentDocument(officialBackend);
    const reusableCurrentDocument = !forceFreshLaunch && await shouldReuseCurrentDocument({
      officialBackend,
      executablePath,
      currentDocument: baselineCurrentDocument,
      minimumProcedureCount,
    });
    if (!reusableCurrentDocument && isOsaScriptLauncher(hopperLauncher)) {
      try {
        await closeHopperDocumentsForExecutable(executablePath);
      } catch {
        // Best-effort only.
      }
    }
    const launch = await launchExecutableInHopper({
      executablePath,
      hopperLauncher,
      analysis,
      loader,
      loaderCheckboxes,
      fatArch,
      onlyProcedures,
      parseObjectiveC,
      parseSwift,
      parseExceptions,
      skipLaunch: reusableCurrentDocument,
    });
    const snapshot = await waitForOfficialSnapshot({
      officialBackend,
      executablePath,
      baselineCurrentDocument,
      timeoutMs,
      maxFunctions,
      includePseudocode,
      failOnTruncation,
    });
    snapshot.sessionId = `live-${snapshot.sessionId ?? safeId(basename(executablePath))}`;
    snapshot.binaryId = `live-${snapshot.binaryId ?? safeId(basename(executablePath))}`;
    applyLiveExportLimits(snapshot, {
      maxStrings,
      maxPseudocodeFunctions,
      fullExport,
      waitForAnalysis,
      failOnTruncation,
      maxFunctions,
      maxBlocksPerFunction,
      maxInstructionsPerBlock,
    });
    await enrichSnapshotBinary(snapshot, executablePath);
    if (closeAfterExport) {
      await closeHopperLaunchArtifacts({
        executablePath,
        hopperLauncher: DEFAULT_OSASCRIPT,
        baselineWindowNames,
      });
    } else {
      await focusExecutableDocument({
        officialBackend,
        executablePath,
      });
    }
    return {
      session: normalizeSession(snapshot),
      launch,
    };
  } finally {
    if (ownsBackend) officialBackend.close();
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
  loader,
  loaderCheckboxes,
  fatArch,
  onlyProcedures,
  parseObjectiveC,
  parseSwift,
  parseExceptions,
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
    loader,
    loaderCheckboxes,
    fatArch,
    onlyProcedures,
    parseObjectiveC,
    parseSwift,
    parseExceptions,
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

export async function shouldReuseCurrentDocument({
  officialBackend,
  executablePath,
  currentDocument,
  documents = null,
  minimumProcedureCount = 1,
}) {
  const minimumCount = Math.max(1, Number(minimumProcedureCount) || 1);
  const listed = Array.isArray(documents) ? documents : await safeDocumentList(officialBackend);
  const candidates = [];
  if (documentMatchesExecutableName(currentDocument, executablePath)) {
    candidates.push(currentDocument);
  }
  for (const name of listed) {
    if (!documentMatchesExecutableName(name, executablePath)) continue;
    if (candidates.includes(name)) continue;
    candidates.push(name);
  }

  for (const candidate of candidates) {
    try {
      if (candidate !== currentDocument) {
        await officialBackend.callInternalTool("set_current_document", { document: candidate });
        currentDocument = await safeCurrentDocument(officialBackend);
      }
      if (!documentMatchesExecutableName(currentDocument, executablePath)) continue;
      // Only reuse when the selected document already has a non-empty
      // procedure index. A stale 'ls' document with zero procedures (or one
      // whose backend errors with "The document has no content") would
      // otherwise trick us into skipping the launch and then time out polling
      // forever.
      const procedures = await officialBackend.callTool("list_procedures", {});
      const procedureIndex = officialToolPayload(procedures);
      if (
        procedureIndex &&
        typeof procedureIndex === "object" &&
        Object.keys(procedureIndex).length >= minimumCount
      ) return true;
    } catch {
      continue;
    }
  }
  return false;
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
  const expectedNames = documentNameCandidates(executablePath);
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const currentDocument = await safeCurrentDocument(officialBackend);
      const documents = await safeDocumentList(officialBackend);
      const selectedDocument = await focusExecutableDocument({
        officialBackend,
        executablePath,
        currentDocument,
        documents,
      });
      const shouldProbe =
        expectedNames.has(selectedDocument ?? currentDocument) ||
        ((selectedDocument ?? currentDocument) && (selectedDocument ?? currentDocument) !== baselineCurrentDocument) ||
        documents.some((name) => expectedNames.has(name));

      if (shouldProbe) {
        const procedures = await officialBackend.callTool("list_procedures", {});
        const procedureIndex = officialToolPayload(procedures);
        if (procedureIndex && typeof procedureIndex === "object" && Object.keys(procedureIndex).length > 0) {
          return await buildOfficialSnapshot(officialBackend, {
            documentName: typeof selectedDocument === "string" ? selectedDocument : currentDocument,
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

  throw new Error(`Timed out waiting for Hopper to analyze one of '${[...expectedNames].join("', '")}' through the official backend.${lastError ? ` Last error: ${String(lastError.message ?? lastError)}` : ""}`);
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

export async function ensureHopperAppReady({
  hopperLauncher = DEFAULT_HOPPER_CLI,
  officialBackend = null,
  timeoutMs = 30000,
  settleDelayMs = Number(process.env.HOPPER_LIVE_PREWARM_SETTLE_MS ?? 5000),
  prewarmRetryCount = Number(process.env.HOPPER_LIVE_PREWARM_RETRY_COUNT ?? 3),
  prewarmRetryDelayMs = Number(process.env.HOPPER_LIVE_PREWARM_RETRY_DELAY_MS ?? 1000),
  openCommand = DEFAULT_OPEN,
  launchApp = defaultLaunchHopperApp,
  waitUntilReady = defaultWaitForHopperReady,
  settleAfterReady = defaultSettleAfterReady,
} = {}) {
  if (!isHopperCliHelper(hopperLauncher)) return { prewarmed: false };
  await launchHopperAppWithRetry({
    hopperLauncher,
    openCommand,
    launchApp,
    prewarmRetryCount,
    prewarmRetryDelayMs,
  });
  if (officialBackend) {
    await waitUntilReady({ officialBackend, timeoutMs });
  }
  await settleAfterReady({ delayMs: settleDelayMs });
  return { prewarmed: true };
}

async function launchHopperAppWithRetry({
  hopperLauncher,
  openCommand,
  launchApp,
  prewarmRetryCount = 3,
  prewarmRetryDelayMs = 1000,
}) {
  const maxAttempts = Math.max(1, Number(prewarmRetryCount) || 1);
  let lastError = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await launchApp({ hopperLauncher, openCommand });
      return;
    } catch (error) {
      lastError = error;
      if (!isTransientHopperLaunchError(error) || attempt >= maxAttempts) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, Number(prewarmRetryDelayMs) || 0)));
    }
  }
  throw lastError;
}

export async function focusExecutableDocument({
  officialBackend = null,
  executablePath,
  currentDocument = null,
  documents = null,
} = {}) {
  if (!officialBackend || !executablePath) return currentDocument;
  const current = currentDocument ?? await safeCurrentDocument(officialBackend);
  if (documentMatchesExecutableName(current, executablePath)) return current;
  const listed = Array.isArray(documents) ? documents : await safeDocumentList(officialBackend);
  const match = listed.find((name) => documentMatchesExecutableName(name, executablePath));
  if (!match) return current;
  try {
    await officialBackend.callInternalTool("set_current_document", { document: match });
  } catch {
    return current;
  }
  return await safeCurrentDocument(officialBackend);
}

async function defaultLaunchHopperApp({ hopperLauncher, openCommand }) {
  const appBundlePath = hopperAppBundlePath(hopperLauncher);
  if (!appBundlePath) return;
  await execFileAsync(openCommand, ["-a", appBundlePath], {
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });
}

async function defaultWaitForHopperReady({ officialBackend = null, timeoutMs = 30000 }) {
  const deadline = Date.now() + timeoutMs;
  const ownsBackend = !officialBackend;
  const backend = officialBackend ?? new OfficialHopperBackend({
    timeoutMs: Math.min(Math.max(1000, Math.floor(timeoutMs / 4)), 5000),
  });
  try {
    while (Date.now() < deadline) {
      try {
        await backend.listTools();
        await safeDocumentList(backend);
        return;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    throw new Error(`Timed out waiting for Hopper to become ready after ${timeoutMs}ms.`);
  } finally {
    if (ownsBackend) backend.close();
  }
}

async function defaultSettleAfterReady({ delayMs = 0 } = {}) {
  if (!Number.isFinite(delayMs) || delayMs <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

function isTransientHopperLaunchError(error) {
  const message = String(error?.message ?? error ?? "");
  return /_LSOpenURLsWithCompletionHandler\(\) failed/i.test(message) && /error -(600|609)\b/i.test(message);
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
  snapshot.binary = {
    ...(snapshot.binary ?? {}),
    name: snapshot.binary?.name ?? basename(executablePath),
    path: executablePath,
    arch: snapshot.binary?.arch ?? null,
    requestedArch: snapshot.binary?.requestedArch ?? null,
    availableArchs: snapshot.binary?.availableArchs ?? [],
    fileInfo: snapshot.binary?.fileInfo ?? null,
    libraries: snapshot.binary?.libraries ?? [],
    entryPoint: snapshot.binary?.entryPoint ?? null,
  };
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

async function runHopperExporter({
  hopperLauncher,
  timeoutMs,
  requestedExecutablePath,
  maxFunctions,
  maxStrings,
  maxBlocksPerFunction,
  maxInstructionsPerBlock,
  includePseudocode,
  maxPseudocodeFunctions,
  fastFunctionSummaries,
  waitForAnalysis,
  fullExport,
  failOnTruncation,
  closeAfterExport,
  buildLaunchSpec,
  diagnostics,
}) {
  const workdir = await mkdtemp(join(tmpdir(), "hopper-live-"));
  const outputPath = join(workdir, "session.json");
  const progressPath = join(workdir, "progress.json");
  const scriptPath = join(workdir, "export_live_session.py");
  // mkdtemp already creates the directory at 0o700, but the umask of the
  // server process can leave the script readable to other local users.
  // Pass `mode` explicitly so the exporter source is owner-only — this is
  // a generated Python file that osascript will execute, so any local
  // tampering before Hopper opens it would run inside the Hopper process.
  await writeFile(
    scriptPath,
    buildExportScript({ outputPath, progressPath, requestedExecutablePath, maxFunctions, maxStrings, maxBlocksPerFunction, maxInstructionsPerBlock, includePseudocode, maxPseudocodeFunctions, fastFunctionSummaries, waitForAnalysis, fullExport, failOnTruncation, closeAfterExport }),
    { encoding: "utf8", mode: 0o600 },
  );

  const launch = buildLaunchSpec(scriptPath);
  const { command, args, mode } = launch;

  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let childExit = null;
  // The exporter can run for `timeoutMs` (default 600s); a chatty Hopper
  // session writes hundreds of MB to stdout/stderr in that window, which we
  // would silently retain in process RSS forever. Cap each side to ~512 KB
  // tail — that's well above the slice-(-4000) we surface to the user, and
  // the file-based session JSON is the actual data channel.
  const STREAM_TAIL_BYTES = 512 * 1024;
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
    if (stdout.length > STREAM_TAIL_BYTES) stdout = stdout.slice(-STREAM_TAIL_BYTES);
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
    if (stderr.length > STREAM_TAIL_BYTES) stderr = stderr.slice(-STREAM_TAIL_BYTES);
  });
  child.on("exit", (code, signal) => {
    childExit = { code, signal };
  });

  let lastAssistAt = 0;
  const onPoll = async () => {
    if (mode === "cli-python-export" && childExit === null) {
      return;
    }
    const now = Date.now();
    if (now - lastAssistAt < 1000) return;
    lastAssistAt = now;
    try {
      await dismissHopperLoaderDialog();
    } catch {
      // Best-effort only. If UI scripting is unavailable, keep polling for
      // exporter output and surface the original timeout/error.
    }
  };

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
      progressPath,
    }), {
      onPoll: mode === "cli-python-export" || mode === "osascript" ? onPoll : null,
    });
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
    await terminateChild(child, { alreadyExited: childExit !== null });
    if (process.env.HOPPER_LIVE_KEEP_TEMP !== "1") {
      await rm(workdir, { recursive: true, force: true });
    }
  }
}

export async function terminateChild(child, {
  alreadyExited = false,
  termGraceMs = 2000,
  killGraceMs = 2000,
} = {}) {
  if (!child || alreadyExited) {
    return { exited: true, escalated: false, code: null, signal: null };
  }

  const termWait = waitForChildClose(child, termGraceMs);
  child.kill("SIGTERM");
  const termResult = await termWait;
  if (termResult) return { ...termResult, escalated: false };

  const killWait = waitForChildClose(child, killGraceMs);
  child.kill("SIGKILL");
  const killResult = await killWait;
  return {
    ...(killResult ?? { exited: false, code: null, signal: null }),
    escalated: true,
  };
}

function waitForChildClose(child, timeoutMs) {
  return new Promise((resolve) => {
    const onClose = (code, signal) => {
      clearTimeout(timeout);
      resolve({ exited: true, code, signal });
    };
    const timeout = setTimeout(() => {
      child.off?.("close", onClose);
      resolve(null);
    }, timeoutMs);
    child.once("close", onClose);
  });
}

export async function waitForJson(path, timeoutMs, diagnostics, { onPoll = null, pollIntervalMs = 500 } = {}) {
  const deadline = Date.now() + timeoutMs;
  const startupDeadline = Date.now() + Number(process.env.HOPPER_LIVE_EXPORT_STARTUP_TIMEOUT_MS ?? 15000);
  let lastError = null;
  let sawProgress = false;

  while (Date.now() < deadline) {
    const details = diagnostics();
    if (!sawProgress && details.progressPath) {
      sawProgress = await existsPath(details.progressPath);
    }
    if (details.childExit && details.childExit.code !== 0) {
      throw new Error(`Hopper launcher exited before writing a session file.${launcherFailureHint(details)} Diagnostics: ${JSON.stringify({
        childExit: details.childExit,
        hopperLauncher: details.hopperLauncher,
        args: details.args,
        launchAnalysis: details.launchAnalysis,
        waitForAnalysis: details.waitForAnalysis,
        fullExport: details.fullExport,
        outputPath: details.outputPath,
        stdoutTail: details.stdout.slice(-1000),
        stderrTail: details.stderr.slice(-1000),
      })}`);
    }
    if (details.childExit && details.childExit.code === 0 && !sawProgress) {
      throw new Error(`Hopper launcher exited before writing a session file.${launcherFailureHint(details)} Diagnostics: ${JSON.stringify({
        childExit: details.childExit,
        hopperLauncher: details.hopperLauncher,
        args: details.args,
        launchAnalysis: details.launchAnalysis,
        waitForAnalysis: details.waitForAnalysis,
        fullExport: details.fullExport,
        outputPath: details.outputPath,
        progressPath: details.progressPath ?? null,
        stdoutTail: details.stdout.slice(-1000),
        stderrTail: details.stderr.slice(-1000),
      })}`);
    }
    if (!sawProgress && Date.now() >= startupDeadline && !details.childExit) {
      throw new Error(`Hopper exporter script did not write progress before the startup timeout.${launcherFailureHint(details)} Diagnostics: ${JSON.stringify({
        hopperLauncher: details.hopperLauncher,
        args: details.args,
        launchAnalysis: details.launchAnalysis,
        waitForAnalysis: details.waitForAnalysis,
        fullExport: details.fullExport,
        outputPath: details.outputPath,
        progressPath: details.progressPath ?? null,
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
    if (onPoll) {
      await onPoll();
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  const details = diagnostics();
  throw new Error(`Timed out waiting for Hopper live export after ${timeoutMs}ms.${lastError ? ` Last error: ${lastError.message}` : ""} ${timeoutHint(details)} Diagnostics: ${JSON.stringify({
    childExit: details.childExit,
    hopperLauncher: details.hopperLauncher,
    args: details.args,
    launchAnalysis: details.launchAnalysis,
    waitForAnalysis: details.waitForAnalysis,
    fullExport: details.fullExport,
    outputPath: details.outputPath,
    stdoutTail: details.stdout.slice(-1000),
    stderrTail: details.stderr.slice(-1000),
  })}`);
}

export function buildDismissLoaderDialogAppleScript() {
  return [
    'tell application "System Events"',
    '  if not (exists process "Hopper Disassembler") then return "idle"',
    '  keystroke return',
    '  tell process "Hopper Disassembler"',
    '    repeat with w in windows',
    '      set loaderWindow to false',
    '      try',
    '        if exists (static text "Loader:" of w) then set loaderWindow to true',
    '      end try',
    '      if not loaderWindow then',
    '        try',
    '          if exists (pop up button 1 of w) then set loaderWindow to true',
    '        end try',
    '      end if',
    '      if loaderWindow then',
    '        try',
    '          click button "OK" of w',
    '          return "clicked"',
    '        end try',
    '      end if',
    '    end repeat',
    '  end tell',
    'end tell',
    'return "idle"',
  ].join("\n");
}

export async function dismissHopperLoaderDialog({
  hopperLauncher = DEFAULT_OSASCRIPT,
  execFileImpl = execFileAsync,
} = {}) {
  if (!isOsaScriptLauncher(hopperLauncher)) {
    throw new Error("dismissHopperLoaderDialog requires an osascript launcher.");
  }
  const appleScript = buildDismissLoaderDialogAppleScript();
  await execFileImpl(hopperLauncher, ["-e", appleScript], {
    timeout: 2000,
    maxBuffer: 64 * 1024,
  });
}

function timeoutHint(details) {
  if (details.mode === "cli-python-export" && details.launchAnalysis) {
    return "Hopper CLI scripts run only after initial analysis ends; retry with wait_for_analysis=false/full_export=false for a quick snapshot, or raise timeout_ms for a full analysis.";
  }
  if (details.mode === "cli-python-export") {
    return "Hopper launched through its CLI without background analysis, but the exporter did not write a session file before the timeout. Hopper may be blocked on a loader/license UI prompt or a stale GUI document.";
  }
  if (details.mode === "cli") {
    return "Hopper launched through its CLI, but the requested document state was not observable before the timeout.";
  }
  if (details.childExit?.code === 0) {
    return "Hopper accepted the AppleScript request, but the exporter did not write a session file before the timeout. If this is a large binary, retry with smaller max_functions/max_strings or wait_for_analysis=false.";
  }
  if (details.parseObjectiveC || details.parseSwift) {
    return "For large Mach-O files, retry with parse_objective_c=false and parse_swift=false first.";
  }
  return "Hopper may still be analyzing the target or waiting for UI input.";
}

export function effectivePythonLaunchAnalysis({ analysis = true, waitForAnalysis = false, fullExport = false } = {}) {
  return Boolean(analysis && (fullExport || waitForAnalysis));
}

export function shouldFallbackToOfficialLiveExport(error) {
  const message = String(error?.message ?? error ?? "");
  return (
    /Hopper launcher exited before writing a session file/i.test(message) ||
    /Hopper exporter script did not write progress before the startup timeout/i.test(message) ||
    /Timed out waiting for Hopper live export/i.test(message)
  );
}

export function shouldFallbackToOfficialLiveExportResult(session) {
  const functions = countExportItems(session?.functions);
  const strings = countExportItems(session?.strings);
  return functions === 0 && strings === 0;
}

function countExportItems(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === "object") return Object.keys(value).length;
  return 0;
}

async function existsPath(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
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

export function buildExportScript({ outputPath, progressPath, requestedExecutablePath, maxFunctions, maxStrings, maxBlocksPerFunction, maxInstructionsPerBlock, includePseudocode, maxPseudocodeFunctions, fastFunctionSummaries, waitForAnalysis, fullExport, failOnTruncation, closeAfterExport }) {
  return String.raw`
import hashlib
import json
import traceback
import os

OUTPUT_PATH = ${JSON.stringify(outputPath)}
PROGRESS_PATH = ${JSON.stringify(progressPath ?? null)}
REQUESTED_EXECUTABLE_PATH = ${JSON.stringify(requestedExecutablePath ?? null)}
MAX_FUNCTIONS = ${pythonLiteral(maxFunctions)}
MAX_STRINGS = ${pythonLiteral(maxStrings)}
MAX_BLOCKS_PER_FUNCTION = ${pythonLiteral(maxBlocksPerFunction)}
MAX_INSTRUCTIONS_PER_BLOCK = ${pythonLiteral(maxInstructionsPerBlock)}
INCLUDE_PSEUDOCODE = ${pythonBool(includePseudocode)}
MAX_PSEUDOCODE_FUNCTIONS = ${pythonLiteral(maxPseudocodeFunctions)}
FAST_FUNCTION_SUMMARIES = ${pythonBool(fastFunctionSummaries)}
WAIT_FOR_ANALYSIS = ${pythonBool(waitForAnalysis)}
FULL_EXPORT = ${pythonBool(fullExport)}
FAIL_ON_TRUNCATION = ${pythonBool(failOnTruncation)}
CLOSE_AFTER_EXPORT = ${pythonBool(closeAfterExport)}

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

def normalized_path(value):
    raw = safe_string(value)
    if raw is None:
        return None
    try:
        return os.path.realpath(raw)
    except Exception:
        return raw

def write_progress(stage, extra=None):
    if PROGRESS_PATH is None:
        return
    payload = {"stage": safe_string(stage)}
    if extra is not None:
        payload["extra"] = extra
    try:
        with open(PROGRESS_PATH, "w") as fh:
            json.dump(payload, fh)
    except Exception:
        pass

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
            if FAST_FUNCTION_SUMMARIES:
                name = "sub_%x" % addr
                size = None
                basic_block_count = 0
                callers = []
                callees = []
                caller_refs = []
                callee_refs = []
                signature = None
                block_export = {"blocks": [], "commentAddresses": []}
                local_vars = []
            else:
                name = procedure_name(doc, proc)
                size = safe_call(None, proc.getHeapSize)
                basic_block_count = safe_call(0, proc.getBasicBlockCount)
                callers = procedure_refs(safe_call([], proc.getAllCallerProcedures))
                callees = procedure_refs(safe_call([], proc.getAllCalleeProcedures))
                caller_refs = collect_call_refs(safe_call([], proc.getAllCallers))
                callee_refs = collect_call_refs(safe_call([], proc.getAllCallees))
                signature = safe_call(None, proc.signatureString)
                block_export = collect_basic_blocks(seg, proc)
                for comment_addr in block_export["commentAddresses"]:
                    comment_addresses.add(comment_addr)
                local_vars = []
                for local in safe_call([], proc.getLocalVariableList):
                    local_vars.append({
                        "name": safe_string(safe_call("", local.name)),
                        "displacement": safe_call(0, local.displacement),
                    })
            pseudocode = None
            if INCLUDE_PSEUDOCODE and (MAX_PSEUDOCODE_FUNCTIONS is None or pseudocode_count < MAX_PSEUDOCODE_FUNCTIONS):
                pseudocode = safe_string(safe_call(None, proc.decompile))
                pseudocode_count = pseudocode_count + 1
            functions.append({
                "addr": hx(addr),
                "name": name,
                "size": size,
                "basicBlockCount": basic_block_count,
                "summary": "Live Hopper procedure summary exported via official Python API." if FAST_FUNCTION_SUMMARIES else "Live Hopper procedure exported via official Python API.",
                "confidence": 0.65 if FAST_FUNCTION_SUMMARIES else 0.8,
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
                    "cfgShape": "blocks:%d" % basic_block_count,
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

def document_score(doc):
    if doc is None:
        return -1
    score = 0
    executable_path = normalized_path(safe_call(None, doc.getExecutableFilePath))
    requested_path = normalized_path(REQUESTED_EXECUTABLE_PATH)
    if requested_path is not None and executable_path == requested_path:
        score = score + 1000000
    for seg in safe_call([], doc.getSegmentsList):
        score = score + safe_call(0, seg.getProcedureCount)
    return score

def select_best_document():
    current_doc = Document.getCurrentDocument()
    all_docs = safe_call([], Document.getAllDocuments)
    doc_candidates = [current_doc] + all_docs
    best_doc = current_doc
    best_score = -1
    seen = set()
    for doc in doc_candidates:
        if doc is None:
            continue
        identifier = id(doc)
        if identifier in seen:
            continue
        seen.add(identifier)
        score = document_score(doc)
        if score > best_score:
            best_doc = doc
            best_score = score
    return best_doc

try:
    write_progress("started")
    doc = select_best_document()
    if WAIT_FOR_ANALYSIS:
        doc.waitForBackgroundProcessToEnd()
    write_progress("document_opened", {"name": safe_call(None, doc.getDocumentName)})
    executable_path = safe_call(None, doc.getExecutableFilePath)
    database_path = safe_call(None, doc.getDatabaseFilePath)
    document_name = safe_call("Hopper Document", doc.getDocumentName)
    function_export = collect_functions(doc)
    if FAST_FUNCTION_SUMMARIES:
        string_export = {"items": [], "total": 0, "truncated": False}
        names = []
        bookmarks = []
        comments = {"comments": [], "inlineComments": []}
    else:
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
    write_progress("collected", {"functions": len(function_export["items"]), "strings": len(string_export["items"])})
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
                "fastFunctionSummaries": FAST_FUNCTION_SUMMARIES,
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
    if CLOSE_AFTER_EXPORT:
        doc.closeDocument()
    with open(OUTPUT_PATH, "w") as out:
        json.dump(session, out, ensure_ascii=True)
    write_progress("wrote_session", {"functions": len(function_export["items"]), "strings": len(string_export["items"])})
except Exception as error:
    write_progress("error", {"message": str(error)})
    with open(OUTPUT_PATH, "w") as out:
        json.dump({"error": str(error), "traceback": traceback.format_exc()}, out)
`;
}

function buildOpenExecutableAppleScript({ executablePath, analysis, onlyProcedures = false, parseObjectiveC, parseSwift, parseExceptions = true, scriptPath = null }) {
  const parts = [
    'tell application "Hopper Disassembler" to open executable POSIX file ',
    quoteAppleScriptString(executablePath),
    " analysis ",
    analysis ? "true" : "false",
    " only procedures ",
    onlyProcedures ? "true" : "false",
    " parse objectivec ",
    parseObjectiveC ? "true" : "false",
    " parse swift ",
    parseSwift ? "true" : "false",
    " parse exceptions ",
    parseExceptions ? "true" : "false",
  ];
  if (scriptPath) {
    parts.push(" execute Python script POSIX file ", quoteAppleScriptString(scriptPath));
  }
  return parts.join("");
}

function buildLaunchSpec({ executablePath, analysis, loader, loaderCheckboxes, fatArch, onlyProcedures = false, parseObjectiveC, parseSwift, parseExceptions = true, hopperLauncher }) {
  const launcher = hopperLauncher ?? DEFAULT_HOPPER_CLI;
  if (isOsaScriptLauncher(launcher)) {
    rejectOsaScriptLoaderSelection(loader, fatArch);
    const appleScript = buildOpenExecutableAppleScript({ executablePath, analysis, onlyProcedures, parseObjectiveC, parseSwift, parseExceptions });
    return {
      command: launcher,
      args: ["-e", appleScript],
      mode: "osascript",
      appleScript,
    };
  }
  if (isHopperCliHelper(launcher)) {
    return {
      command: launcher,
      args: hopperCliOpenArgs({ executablePath, analysis, loader, loaderCheckboxes, fatArch, onlyProcedures, parseObjectiveC, parseSwift, parseExceptions }),
      mode: "cli",
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

export function buildLiveExportLaunchSpec({ executablePath, scriptPath, analysis, loader, loaderCheckboxes, fatArch, onlyProcedures = false, parseObjectiveC, parseSwift, parseExceptions = true, hopperLauncher }) {
  const launcher = hopperLauncher ?? DEFAULT_HOPPER_CLI;
  if (isOsaScriptLauncher(launcher)) {
    rejectOsaScriptLoaderSelection(loader, fatArch);
    const appleScript = buildOpenExecutableAppleScript({
      executablePath,
      analysis,
      onlyProcedures,
      parseObjectiveC,
      parseSwift,
      parseExceptions,
      scriptPath,
    });
    return {
      command: launcher,
      args: ["-e", appleScript],
      mode: "osascript",
      appleScript,
    };
  }
  if (isHopperCliHelper(launcher)) {
    return {
      command: launcher,
      args: [
        ...hopperCliOpenArgs({ executablePath, analysis, loader, loaderCheckboxes, fatArch, onlyProcedures, parseObjectiveC, parseSwift, parseExceptions }),
        "-Y",
        scriptPath,
      ],
      mode: "cli-python-export",
    };
  }
  return {
    command: launcher,
    args: [
      "-executable",
      executablePath,
      "-python",
      scriptPath,
    ],
    mode: "cli-python-export",
  };
}

function rejectOsaScriptLoaderSelection(loader, fatArch) {
  if (loader || fatArch) {
    throw new Error("The osascript Hopper launcher does not support loader or FAT architecture selection; use Hopper's CLI launcher for universal binaries.");
  }
}

export function hopperCliOpenArgs({ executablePath, analysis, loader, loaderCheckboxes, fatArch, onlyProcedures = false, parseObjectiveC, parseSwift, parseExceptions = true }) {
  const args = [];
  if (loader) {
    const loaderId = sanitizedLoader(loader);
    if (fatArch && loaderId === HOPPER_MACHO_LOADER) {
      args.push("-l", HOPPER_FAT_LOADER, hopperCpuFlagForArch(fatArch), "-l", loaderId);
    } else {
      args.push("-l", loaderId);
    }
  }
  for (const checkbox of sanitizedLoaderCheckboxes(loaderCheckboxes)) {
    args.push("-C", checkbox);
  }
  args.push(
    "-e",
    executablePath,
    analysis ? "-a" : "-A",
    parseObjectiveC ? "-o" : "-O",
    parseSwift ? "-f" : "-F",
    parseExceptions ? "-z" : "-Z",
  );
  if (onlyProcedures) args.push("-W");
  return args;
}

async function detectHopperFatArch({ executablePath, loader }) {
  if (!executablePath || !loader || sanitizedLoader(loader) !== HOPPER_MACHO_LOADER) return null;
  try {
    const result = await execFileAsync("/usr/bin/lipo", ["-info", executablePath], {
      timeout: 3000,
      maxBuffer: 64 * 1024,
    });
    return preferredHopperFatArch(parseLipoFatArchs(result.stdout));
  } catch (error) {
    const output = `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
    return preferredHopperFatArch(parseLipoFatArchs(output));
  }
}

function parseLipoFatArchs(output) {
  const match = String(output ?? "").match(/Architectures in the fat file: .+ are:\s*(.+)$/m);
  if (!match) return [];
  return match[1].trim().split(/\s+/).filter(Boolean);
}

function preferredHopperFatArch(archs) {
  if (!Array.isArray(archs) || archs.length < 2) return null;
  const hostPreferred = process.arch === "arm64"
    ? ["arm64e", "arm64", "x86_64", "i386"]
    : ["x86_64", "i386", "arm64e", "arm64"];
  return hostPreferred.find((arch) => archs.includes(arch)) ?? null;
}

function hopperCpuFlagForArch(arch) {
  switch (String(arch).toLowerCase()) {
    case "arm64":
    case "arm64e":
    case "aarch64":
      return "--aarch64";
    case "x86_64":
    case "amd64":
    case "x64":
      return "--intel-64";
    case "i386":
    case "i686":
    case "x86":
      return "--intel-32";
    default:
      throw new Error(`Unsupported Hopper FAT architecture '${arch}'.`);
  }
}

function isOsaScriptLauncher(value) {
  return /(?:^|\/)osascript$/i.test(String(value ?? ""));
}

function isHopperCliHelper(value) {
  return /(?:^|\/)hopper$/i.test(String(value ?? ""));
}

function hopperAppBundlePath(hopperLauncher) {
  const launcher = String(hopperLauncher ?? "");
  const marker = "/Contents/MacOS/";
  const idx = launcher.indexOf(marker);
  if (idx === -1) return null;
  return launcher.slice(0, idx);
}

function documentNameCandidates(executablePath) {
  const base = basename(String(executablePath ?? ""));
  return new Set([base, `${base}.hop`].filter(Boolean));
}

function documentMatchesExecutableName(documentName, executablePath) {
  if (!documentName) return false;
  return documentNameCandidates(executablePath).has(String(documentName));
}

function isUntitledHopperWindowName(value) {
  return /^Untitled(?: \d+)?$/.test(String(value ?? ""));
}

function pythonBool(value) {
  return value ? "True" : "False";
}

function pythonLiteral(value) {
  if (value === null || value === undefined) return "None";
  return JSON.stringify(value);
}

function sanitizedLoader(value) {
  const text = String(value);
  if (!/^[A-Za-z0-9_.-]+$/.test(text)) {
    throw new Error("Hopper loader id must contain only letters, numbers, underscore, dot, or hyphen.");
  }
  return text;
}

function sanitizedLoaderCheckboxes(values) {
  if (values === undefined || values === null) return [];
  if (!Array.isArray(values)) {
    throw new Error("Hopper loader checkboxes must be an array of strings.");
  }
  return values.map((value) => {
    const text = String(value);
    if (!/^[A-Za-z0-9_. -]+(?:=(?:true|false))?$/.test(text)) {
      throw new Error("Hopper loader checkbox names may contain letters, numbers, spaces, underscore, dot, or hyphen, optionally followed by =true or =false.");
    }
    return text;
  });
}

// AppleScript string literals only allow `\\`, `\"`, `\n`, `\r`, `\t` as
// escapes. Any raw newline or control char in `value` would otherwise close
// the literal early or terminate the surrounding command, allowing whoever
// controls e.g. an `executable_path` or document name to inject AppleScript.
// Encode the dangerous characters as their AppleScript escapes; reject any
// remaining control chars (NUL through 0x1f minus the three we just handled,
// plus DEL) so we never silently strip them.
function quoteAppleScriptString(value) {
  const text = String(value);
  let out = '"';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code === 0x7f) {
      throw new Error(
        `Refusing to embed control character U+${code.toString(16).padStart(4, "0")} in AppleScript literal.`,
      );
    } else {
      out += ch;
    }
  }
  return `${out}"`;
}

function parseAppleScriptList(stdout) {
  const text = String(stdout ?? "").trim();
  if (!text || text === "{}") return [];
  return text
    .split(/\s*,\s*/)
    .map((value) => value.trim())
    .filter(Boolean);
}
