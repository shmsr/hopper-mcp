#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const options = parseArgs(process.argv.slice(2));

let report;
if (options.validateReport) {
  report = validateReport(JSON.parse(await readFile(resolve(repoRoot, options.validateReport), "utf8")));
} else {
  const manifestPath = resolve(repoRoot, options.manifest);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const defaults = manifest.defaults ?? {};
  const resolvedTargets = await resolveTargets(manifest.targets ?? []);
  if (options.dryRun) {
    report = buildDryRunReport(resolvedTargets, manifestPath);
  } else {
    report = await runLiveCorpus(resolvedTargets, defaults, manifestPath);
  }
}

const reportJson = `${JSON.stringify(report, null, 2)}\n`;
if (options.report) {
  const reportPath = resolve(repoRoot, options.report);
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, reportJson);
}
process.stdout.write(reportJson);
process.exitCode = report.ok ? 0 : 1;

async function resolveTargets(targets) {
  const resolved = [];
  for (const target of targets) {
    if (!target || typeof target !== "object" || Array.isArray(target)) {
      resolved.push({
        id: "invalid-target",
        status: "failed",
        error: "target must be an object",
      });
      continue;
    }

    const id = target.id ?? target.path ?? target.app_bundle ?? "unnamed-target";
    try {
      const executablePath = await resolveExecutablePath(target);
      if (!(await exists(executablePath))) {
        resolved.push(missingTarget(target, id, executablePath));
        continue;
      }
      resolved.push({
        ...target,
        id,
        executablePath,
        status: "ready",
      });
    } catch (error) {
      resolved.push({
        ...target,
        id,
        status: target.optional ? "skipped" : "failed",
        error: String(error?.message ?? error),
      });
    }
  }
  return resolved;
}

async function resolveExecutablePath(target) {
  if (target.path) {
    return target.path;
  }
  if (target.app_bundle) {
    const appBundle = target.app_bundle;
    if (target.executable) {
      return join(appBundle, "Contents", "MacOS", target.executable);
    }
    return await resolveBundleExecutablePath(appBundle);
  }
  throw new Error("target requires path or app_bundle");
}

async function resolveBundleExecutablePath(appBundle) {
  const topLevel = await readBundleExecutablePath(appBundle);
  if (topLevel) return topLevel;

  const nested = await findNestedBundleExecutablePath(appBundle);
  if (nested) return nested;

  throw new Error(`failed to locate a runnable bundle executable inside ${appBundle}`);
}

async function readBundleExecutablePath(appBundle) {
  const infoPlist = join(appBundle, "Contents", "Info.plist");
  const { code, stdout, stderr } = await runProcess("/usr/libexec/PlistBuddy", [
    "-c",
    "Print:CFBundleExecutable",
    infoPlist,
  ]);
  if (code !== 0) {
    return null;
  }
  const executablePath = join(appBundle, "Contents", "MacOS", stdout.trim());
  return await exists(executablePath) ? executablePath : null;
}

async function findNestedBundleExecutablePath(appBundle) {
  const { code, stdout } = await runProcess("/usr/bin/find", [
    appBundle,
    "-maxdepth",
    "8",
    "-path",
    "*/Contents/Info.plist",
  ]);
  if (code !== 0) {
    return null;
  }

  const candidates = stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .sort();

  for (const infoPlist of candidates) {
    const nestedBundle = dirname(dirname(infoPlist));
    if (nestedBundle === appBundle) continue;
    const executablePath = await readBundleExecutablePath(nestedBundle);
    if (executablePath) return executablePath;
  }

  return null;
}

function missingTarget(target, id, executablePath) {
  return {
    ...target,
    id,
    executablePath,
    status: target.optional ? "skipped" : "failed",
    error: `target executable not found: ${executablePath}`,
  };
}

function buildDryRunReport(targets, manifestPath) {
  return {
    ok: targets.every((target) => target.status !== "failed"),
    dryRun: true,
    manifest: manifestPath,
    summary: summarize(targets),
    targets,
  };
}

async function runLiveCorpus(targets, defaults, manifestPath) {
  const results = [];
  for (const target of targets) {
    if (target.status !== "ready" || target.live === false) {
      results.push(target.live === false && target.status === "ready"
        ? {
            ...target,
            status: "skipped",
            error: "target is disabled for live corpus runs",
          }
        : target);
      continue;
    }
    const started = Date.now();
    try {
      const output = await ingestTarget(target, defaults);
      results.push(validateTargetResult({
        ...target,
        status: "passed",
        elapsedMs: Date.now() - started,
        sessionId: output.session?.sessionId,
        functionCount: reportedCount(output.session, "functions"),
        stringCount: reportedCount(output.session, "strings"),
      }));
    } catch (error) {
      results.push({
        ...target,
        status: "failed",
        elapsedMs: Date.now() - started,
        error: String(error?.message ?? error),
      });
    }
  }
  return validateReport({
    dryRun: false,
    manifest: manifestPath,
    targets: results,
  });
}

async function ingestTarget(target, defaults) {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-corpus-"));
  const child = spawn("bin/hopper-mcp", [], {
    cwd: repoRoot,
    env: {
      ...process.env,
      HOPPER_MCP_STORE: join(tempDir, "store.json"),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });

  try {
    const responsePromise = readJsonRpcResponse(child, target.timeout_ms ?? defaults.timeout_ms ?? 120_000);
    child.stdin.end(`${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "ingest_live_hopper",
        arguments: {
          executable_path: target.executablePath,
          timeout_ms: target.timeout_ms ?? defaults.timeout_ms ?? 120_000,
          max_functions: target.max_functions ?? defaults.max_functions ?? 30,
          max_strings: target.max_strings ?? defaults.max_strings ?? 80,
          analysis: target.analysis ?? defaults.analysis,
          wait_for_analysis: target.wait_for_analysis ?? defaults.wait_for_analysis,
          full_export: target.full_export ?? defaults.full_export,
          include_pseudocode: target.include_pseudocode ?? defaults.include_pseudocode,
          max_pseudocode_functions: target.max_pseudocode_functions ?? defaults.max_pseudocode_functions,
          close_after_export: target.close_after_export ?? defaults.close_after_export ?? true,
        },
      },
    })}\n`);
    const response = await responsePromise;
    if (response.error) {
      throw new Error(JSON.stringify(response.error));
    }
    const toolResult = response.result ?? {};
    if (toolResult.isError) {
      throw new Error(extractToolErrorMessage(toolResult));
    }
    if (toolResult.structuredContent !== undefined) {
      return toolResult.structuredContent;
    }
    const text = firstTextContent(toolResult.content);
    if (!text) {
      return {};
    }
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new Error(`MCP tool returned non-JSON text without structuredContent: ${text}`);
    }
  } finally {
    await terminateChild(child);
    await rm(tempDir, { recursive: true, force: true });
  }
}

function extractToolErrorMessage(result) {
  const text = firstTextContent(result.content);
  if (text) return text;
  if (result.structuredContent !== undefined) {
    return JSON.stringify(result.structuredContent);
  }
  return "MCP tool failed without an error message";
}

function firstTextContent(content) {
  if (!Array.isArray(content)) return null;
  for (const item of content) {
    if (item?.type === "text" && typeof item.text === "string" && item.text.trim()) {
      return item.text;
    }
  }
  return null;
}

function readJsonRpcResponse(child, timeoutMs) {
  return new Promise((resolvePromise, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      void terminateChild(child);
      reject(new Error(`timed out waiting for MCP response\nstderr:\n${stderr}`));
    }, timeoutMs + 10_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      const lineEnd = stdout.indexOf("\n");
      if (lineEnd !== -1) {
        clearTimeout(timeout);
        try {
          resolvePromise(JSON.parse(stdout.slice(0, lineEnd)));
        } catch (error) {
          reject(error);
        }
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (code) => {
      if (!stdout.includes("\n")) {
        clearTimeout(timeout);
        reject(new Error(`MCP process exited before response: ${code}\nstderr:\n${stderr}`));
      }
    });
  });
}

async function terminateChild(child, { termGraceMs = 2000, killGraceMs = 2000 } = {}) {
  const termWait = waitForClose(child, termGraceMs);
  child.kill("SIGTERM");
  if (await termWait) return;

  const killWait = waitForClose(child, killGraceMs);
  child.kill("SIGKILL");
  await killWait;
}

function waitForClose(child, timeoutMs) {
  return new Promise((resolve) => {
    const onClose = () => {
      clearTimeout(timeout);
      resolve(true);
    };
    const timeout = setTimeout(() => {
      child.off("close", onClose);
      resolve(false);
    }, timeoutMs);
    child.once("close", onClose);
  });
}

function summarize(targets) {
  return {
    total: targets.length,
    ready: targets.filter((target) => target.status === "ready").length,
    passed: targets.filter((target) => target.status === "passed").length,
    skipped: targets.filter((target) => target.status === "skipped").length,
    failed: targets.filter((target) => target.status === "failed").length,
  };
}

function validateReport(report) {
  const targets = (report.targets ?? []).map(validateTargetResult);
  return {
    ...report,
    ok: targets.every((target) => target.status !== "failed"),
    summary: summarize(targets),
    targets,
  };
}

function validateTargetResult(target) {
  if (target.status !== "passed") return target;
  const assertions = [];
  const minFunctions = numericBudget(target.min_functions);
  const minStrings = numericBudget(target.min_strings);
  const maxElapsedMs = numericBudget(target.max_elapsed_ms);
  if (minFunctions !== null && (target.functionCount ?? 0) < minFunctions) {
    assertions.push(`expected at least ${minFunctions} function(s), got ${target.functionCount ?? 0}`);
  }
  if (minStrings !== null && (target.stringCount ?? 0) < minStrings) {
    assertions.push(`expected at least ${minStrings} string(s), got ${target.stringCount ?? 0}`);
  }
  if (maxElapsedMs !== null && (target.elapsedMs ?? Number.POSITIVE_INFINITY) > maxElapsedMs) {
    assertions.push(`elapsedMs ${target.elapsedMs ?? "unknown"} exceeded max_elapsed_ms ${maxElapsedMs}`);
  }
  if (!assertions.length) {
    return target.assertions ? { ...target, assertions: [] } : target;
  }
  return {
    ...target,
    status: "failed",
    assertions,
    error: assertions.join("; "),
  };
}

function numericBudget(value) {
  return Number.isFinite(value) ? value : null;
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function countCollection(value) {
  if (Array.isArray(value)) return value.length;
  if (!value || typeof value !== "object") return 0;
  return Object.keys(value).length;
}

function reportedCount(session, field) {
  if (typeof session?.counts?.[field] === "number") {
    return session.counts[field];
  }
  const liveExport = session?.capabilities?.liveExport;
  return liveExport?.exported?.[field] ?? liveExport?.totals?.[field] ?? countCollection(session?.[field]);
}

function parseArgs(args) {
  const options = {
    dryRun: false,
    manifest: "corpus/live-smoke.json",
    validateReport: null,
    report: null,
  };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--manifest") {
      const value = args[i + 1];
      if (!value) throw new Error("--manifest requires a path");
      options.manifest = value;
      i += 1;
    } else if (arg === "--validate-report") {
      const value = args[i + 1];
      if (!value) throw new Error("--validate-report requires a path");
      options.validateReport = value;
      i += 1;
    } else if (arg === "--report") {
      const value = args[i + 1];
      if (!value) throw new Error("--report requires a path");
      options.report = value;
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write("Usage: node scripts/live-corpus.mjs [--dry-run] [--manifest PATH] [--validate-report PATH] [--report PATH]\n");
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return options;
}

function runProcess(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ code, stdout, stderr }));
  });
}
