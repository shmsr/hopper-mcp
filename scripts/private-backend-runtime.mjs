#!/usr/bin/env node
import net from "node:net";
import { spawn } from "node:child_process";
import { cp, mkdir, readdir, rm, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { ingestWithLiveHopper, hopperCliOpenArgs, terminateChild } from "../src/hopper-live.js";
import {
  DEFAULT_HOPPER_APP_COMMAND,
  shouldUseLiveExportWarmup,
  runPrivateLiveExportWarmup,
} from "../src/private-backend-runtime.js";

const command = process.argv[2];
const args = process.argv.slice(3);
const DEFAULT_PLUGIN_SOURCE = resolve("target", "release", "HopperMCPAgent.hopperTool");
const DEFAULT_PROBE_TIMEOUT_MS = 30_000;

if (command === "probe") {
  const options = parseArgs(args, {
    "--plugin": "plugin",
    "--dest-root": "destRoot",
    "--otool-command": "otoolCommand",
    "--socket": "socket",
    "--agent-command": "agentCommand",
    "--hopper-command": "hopperCommand",
    "--injection-library": "injectionLibrary",
    "--target": "target",
    "--timeout-ms": "timeoutMs",
    "--loader": "loader",
    "--fat-arch": "fatArch",
  });
  const report = await probePrivateBackend(options);
  printJson(report);
  process.exit(report.ok ? 0 : 1);
}

printUsage();
process.exit(2);

function parseArgs(argv, spec) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const key = spec[arg];
    if (!key) throw new Error(`unknown argument: ${arg}`);
    const value = argv[i + 1];
    if (!value) throw new Error(`${arg} requires a value`);
    options[key] = value;
    i += 1;
  }
  return options;
}

function defaultPluginInstallRoot() {
  return join(homedir(), "Library", "Application Support", "Hopper", "PlugIns", "v4", "Tools");
}

function defaultProbeSocketPath() {
  return join("/tmp", `hopper-private-probe-${process.pid}-${Date.now()}.sock`);
}

function pluginServiceNameForSocketPath(socketPath) {
  let sanitized = "";
  for (const ch of String(socketPath)) {
    sanitized += /[A-Za-z0-9]/.test(ch) ? ch : "-";
  }
  sanitized = sanitized.replace(/-+$/g, "");
  if (!sanitized) sanitized = "default";
  if (sanitized.length > 80) sanitized = sanitized.slice(0, 80);
  return `dev.hopper-mcp.plugin.${sanitized}`;
}

async function probePrivateBackend(options) {
  const socket = options.socket || defaultProbeSocketPath();
  const serviceName = pluginServiceNameForSocketPath(socket);
  const timeoutMs = parseIntegerOption(options.timeoutMs, "--timeout-ms", DEFAULT_PROBE_TIMEOUT_MS);
  const agentCommand = options.agentCommand ? resolve(options.agentCommand) : null;
  const hopperCommand = options.hopperCommand || DEFAULT_HOPPER_APP_COMMAND;
  const target = resolve(options.target || "/bin/echo");
  const plugin = resolve(options.plugin || DEFAULT_PLUGIN_SOURCE);
  const destRoot = resolve(options.destRoot || defaultPluginInstallRoot());
  const loader = options.loader || "Mach-O";
  const fatArch = options.fatArch || null;
  const otoolCommand = options.otoolCommand || "otool";

  try {
    const linkage = await verifyPluginLinkage({ pluginBundle: plugin, otoolCommand });
    if (!linkage.ok) {
      return {
        ok: false,
        phase: "pluginLinkage",
        socket,
        serviceName,
        message: linkage.message,
      };
    }

    const install = await installPlugin({ plugin, destRoot });
    if (!install.ok) {
      return {
        ok: false,
        phase: "install",
        socket,
        serviceName,
        ...install,
      };
    }

    const useLiveExportWarmup = shouldUseLiveExportWarmup({ hopperCommand, agentCommand });
    if (agentCommand) {
      await rm(socket, { force: true }).catch(() => {});
    }
    let liveWarmup = null;
    if (useLiveExportWarmup) {
      liveWarmup = await runPrivateLiveExportWarmup({
        socket,
        target,
        timeoutMs,
        loader,
        ingest: ingestWithLiveHopper,
        runCapture,
      });
    }
    const agent = agentCommand ? spawn(agentCommand, [
      "--socket",
      socket,
      "--plugin-service",
      "auto",
    ], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    }) : null;
    const agentLogs = captureTail(agent);
    let hopper = null;
    let hopperArgs = [];
    let liveLaunch = null;
    let hopperLogs = { stdout: "", stderr: "" };
    try {
      if (useLiveExportWarmup) {
        liveLaunch = liveWarmup?.liveLaunch ?? null;
      } else {
        hopperArgs = hopperCliOpenArgs({
          executablePath: target,
          analysis: false,
          loader,
          fatArch,
          onlyProcedures: true,
          parseObjectiveC: true,
          parseSwift: true,
          parseExceptions: true,
        });
        hopper = spawn(hopperCommand, hopperArgs, {
          cwd: process.cwd(),
          env: {
            ...process.env,
            HOPPER_MCP_PRIVATE_TARGET: target,
            ...(agentCommand
              ? { HOPPER_MCP_PLUGIN_SOCKET: socket }
              : { HOPPER_MCP_PRIVATE_AGENT_SOCKET: socket }),
          },
          stdio: ["ignore", "pipe", "pipe"],
        });
        hopperLogs = captureTail(hopper);
      }

      let handshake = null;
      let currentDocument = null;
      let procedures = null;
      let phase = "handshake";
      let failure = null;
      const startedAt = Date.now();

      try {
        const client = await waitForProbeReady({
          socket,
          timeoutMs,
          agent,
          hopper,
          agentLogs,
          hopperLogs,
        });
        try {
          handshake = await verifyHandshake(client);
          phase = "currentDocument";
          currentDocument = await waitForProbeResponse({
            client,
            timeoutMs: Math.max(1_000, timeoutMs - (Date.now() - startedAt)),
            request: { type: "current_document" },
            validate: (response) => response?.type === "current_document",
            retryable: (response) => isRetryableProbeResponse(response),
          });
          phase = "procedures";
          procedures = await waitForProbeResponse({
            client,
            timeoutMs: Math.max(1_000, timeoutMs - (Date.now() - startedAt)),
            request: { type: "list_procedures", maxResults: 10 },
            validate: (response) => response?.type === "procedures" && Array.isArray(response.procedures),
            retryable: (response) => isRetryableProbeResponse(response),
          });
        } finally {
          client.destroy();
        }
      } catch (error) {
        failure = {
          ok: false,
          phase,
          socket,
          serviceName,
          install,
          launch: {
            hopperCommand,
            hopperArgs,
            agentCommand,
            target,
            liveLaunch,
          },
          message: error.message,
          agentStderr: agentLogs.stderr,
          hopperStderr: hopperLogs.stderr,
        };
      } finally {
        const cleanup = await cleanupProbeChildren({ agent, hopper });
        await rm(socket, { force: true }).catch(() => {});
        await liveWarmup?.cleanupEnv?.();
        if (failure) {
          return {
            ...failure,
            cleanup,
          };
        }
        return {
          ok: true,
          socket,
          serviceName,
          install,
          launch: {
            hopperCommand,
            hopperArgs,
            agentCommand,
            target,
            liveLaunch,
          },
          handshake,
          currentDocument,
          procedures,
          cleanup,
          readyAfterMs: Date.now() - startedAt,
        };
      }
    } catch (error) {
      await liveWarmup?.cleanupEnv?.();
      throw error;
    }
  } catch (error) {
    return {
      ok: false,
      phase: "probe",
      socket,
      serviceName,
      message: error.message,
    };
  }
}

async function installPlugin({ plugin, destRoot }) {
  const source = plugin;
  const destination = join(destRoot, "HopperMCPAgent.hopperTool");
  if (!(await fileExists(source))) {
    return {
      ok: false,
      source,
      destination,
      message: `plugin bundle not found: ${source}`,
    };
  }
  await mkdir(destRoot, { recursive: true });
  await rm(destination, { recursive: true, force: true });
  await cp(source, destination, { recursive: true });
  return {
    ok: true,
    source,
    destination,
    signed: false,
    serviceName: pluginServiceNameForSocketPath(defaultProbeSocketPath()),
  };
}

async function verifyPluginLinkage({ pluginBundle, otoolCommand }) {
  if (process.platform !== "darwin") {
    return {
      ok: true,
      message: "plugin linkage verification skipped on non-darwin platform",
    };
  }
  const executable = await resolvePluginExecutable(pluginBundle);
  if (!executable) {
    return {
      ok: false,
      message: `plugin bundle has no executable under ${join(pluginBundle, "Contents", "MacOS")}`,
    };
  }
  const result = await runCapture(otoolCommand, ["-L", executable]);
  if (result.code !== 0) {
    return {
      ok: false,
      message: `${otoolCommand} -L ${executable} failed with code ${result.code}: ${result.stderr || result.stdout}`,
    };
  }
  const details = `${result.stdout}\n${result.stderr}`;
  if (/AppKit\.framework|Cocoa\.framework/i.test(details)) {
    return {
      ok: false,
      message: "plugin bundle links AppKit/Cocoa; Hopper Tool plugins should stay Foundation-only",
    };
  }
  return {
    ok: true,
    message: "plugin bundle uses Foundation-only linkage",
  };
}

async function resolvePluginExecutable(pluginBundle) {
  const macosDir = join(pluginBundle, "Contents", "MacOS");
  let entries;
  try {
    entries = await readdir(macosDir, { withFileTypes: true });
  } catch {
    return null;
  }
  const executable = entries.find((entry) => entry.isFile());
  return executable ? join(macosDir, executable.name) : null;
}

function printUsage() {
  process.stderr.write(
    "Usage: node scripts/private-backend-runtime.mjs probe [options]\n",
  );
}

function printJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

function parseIntegerOption(value, flag, fallback) {
  if (value == null) return fallback;
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return parsed;
}

async function fileExists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function runCapture(command, commandArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, {
      cwd: process.cwd(),
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
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function captureTail(child, maxBytes = 4096) {
  const logs = { stdout: "", stderr: "" };
  if (!child) return logs;
  child.stdout?.on("data", (chunk) => {
    logs.stdout = `${logs.stdout}${chunk.toString()}`.slice(-maxBytes);
  });
  child.stderr?.on("data", (chunk) => {
    logs.stderr = `${logs.stderr}${chunk.toString()}`.slice(-maxBytes);
  });
  return logs;
}

async function waitForProbeReady({ socket, timeoutMs, agent, hopper, agentLogs, hopperLogs }) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    if (agent && agent.exitCode !== null) {
      throw new Error(`hopper-agent exited early with code ${agent.exitCode}: ${agentLogs.stderr}`);
    }
    if (hopper && hopper.exitCode !== null && hopper.exitCode !== 0) {
      throw new Error(`Hopper launcher exited early with code ${hopper.exitCode}: ${hopperLogs.stderr}`);
    }
    try {
      return await connect(socket);
    } catch (error) {
      lastError = error;
      await sleep(100);
    }
  }
  throw new Error(`timed out waiting for hopper-agent socket ${socket}: ${lastError?.message ?? "not ready"}`);
}

async function verifyHandshake(client) {
  client.write(`${JSON.stringify({
    type: "handshake",
    wireVersion: 1,
    daemonVersion: "private-backend-probe",
  })}\n`);
  const handshake = await readJsonLine(client, 5_000);
  if (handshake?.type !== "handshake" || handshake.accepted !== true) {
    throw new Error(`unexpected handshake response: ${JSON.stringify(handshake)}`);
  }
  return handshake;
}

async function waitForProbeResponse({ client, timeoutMs, request, validate, retryable }) {
  const deadline = Date.now() + timeoutMs;
  let lastResponse = null;
  while (Date.now() < deadline) {
    client.write(`${JSON.stringify(request)}\n`);
    const response = await readJsonLine(client, Math.min(5_000, Math.max(500, deadline - Date.now())));
    if (validate(response)) return response;
    lastResponse = response;
    if (!retryable(response)) {
      throw new Error(`probe request ${request.type} returned ${JSON.stringify(response)}`);
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${request.type}: ${JSON.stringify(lastResponse)}`);
}

function isRetryableProbeResponse(response) {
  return response?.type === "error"
    && ["plugin_service_failed", "no_document", "no_disassembled_file"].includes(response.code);
}

async function cleanupProbeChildren({ agent, hopper }) {
  const agentResult = agent ? await terminateChild(agent, {
    alreadyExited: agent.exitCode !== null || agent.signalCode !== null,
    termGraceMs: 1_000,
    killGraceMs: 1_000,
  }) : { exited: true, signal: null };
  const hopperResult = hopper ? await terminateChild(hopper, {
    alreadyExited: hopper.exitCode !== null || hopper.signalCode !== null,
    termGraceMs: 1_000,
    killGraceMs: 2_000,
  }) : { exited: true, signal: null };
  return {
    agentTerminated: agentResult.exited === true,
    hopperTerminated: hopperResult.exited === true,
    agentSignal: agentResult.signal,
    hopperSignal: hopperResult.signal,
  };
}

function connect(socket) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socket);
    client.once("connect", () => resolve(client));
    client.once("error", (error) => {
      client.destroy();
      reject(error);
    });
  });
}

function readJsonLine(client, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for JSON line; buffered=${JSON.stringify(buffer)}`));
    }, timeoutMs);
    const onData = (chunk) => {
      buffer += chunk.toString();
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      cleanup();
      resolve(JSON.parse(buffer.slice(0, newline)));
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error(`stream closed before JSON line; buffered=${JSON.stringify(buffer)}`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      client.off("data", onData);
      client.off("error", onError);
      client.off("close", onClose);
    };
    client.on("data", onData);
    client.once("error", onError);
    client.once("close", onClose);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
