#!/usr/bin/env node
import net from "node:net";
import { spawn } from "node:child_process";
import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { hopperCliOpenArgs, terminateChild } from "../src/hopper-live.js";

const command = process.argv[2];
const args = process.argv.slice(3);
const DEFAULT_HOPPER_COMMAND = "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper";
const DEFAULT_AGENT_COMMAND = resolve("target", "release", "hopper-agent");
const DEFAULT_PROBE_TIMEOUT_MS = 30_000;

if (command === "service-name") {
  const options = parseArgs(args, {
    "--socket": "socket",
  });
  requiredOption(options, "socket", "--socket is required for service-name");
  printJson({
    ok: true,
    socket: options.socket,
    serviceName: pluginServiceNameForSocketPath(options.socket),
  });
  process.exit(0);
}

if (command === "identities") {
  const options = parseArgs(args, {
    "--security-command": "securityCommand",
  });
  const securityCommand = options.securityCommand || "security";
  const report = await codesigningIdentityReport({ securityCommand });
  printJson({
    ok: report.ok,
    securityCommand,
    identities: report.identities,
    message: report.message,
  });
  process.exit(report.commandFailed ? 1 : 0);
}

if (command === "install") {
  const options = parseArgs(args, {
    "--plugin": "plugin",
    "--dest-root": "destRoot",
    "--codesign-command": "codesignCommand",
    "--otool-command": "otoolCommand",
    "--identity": "identity",
    "--ad-hoc": "adHoc",
    "--skip-sign": "skipSign",
  });
  const report = await installPlugin(options);
  printJson(report);
  process.exit(report.ok ? 0 : 1);
}

if (command === "probe") {
  const options = parseArgs(args, {
    "--plugin": "plugin",
    "--dest-root": "destRoot",
    "--codesign-command": "codesignCommand",
    "--otool-command": "otoolCommand",
    "--launchctl-command": "launchctlCommand",
    "--identity": "identity",
    "--ad-hoc": "adHoc",
    "--skip-sign": "skipSign",
    "--security-command": "securityCommand",
    "--socket": "socket",
    "--agent-command": "agentCommand",
    "--hopper-command": "hopperCommand",
    "--target": "target",
    "--timeout-ms": "timeoutMs",
    "--loader": "loader",
    "--fat-arch": "fatArch",
  });
  const report = await probePlugin(options);
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
    if (arg === "--skip-sign" || arg === "--ad-hoc") {
      options[key] = true;
      continue;
    }
    const value = argv[i + 1];
    if (!value) throw new Error(`${arg} requires a value`);
    options[key] = value;
    i += 1;
  }
  return options;
}

function requiredOption(options, key, message) {
  if (!options[key]) throw new Error(message);
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

function parseIdentities(output) {
  return String(output)
    .split("\n")
    .map((line) => line.match(/^\s*\d+\)\s+([0-9A-F]+)\s+\"([^\"]+)\"/i))
    .filter(Boolean)
    .map((match) => ({
      hash: match[1],
      name: match[2],
    }));
}

function defaultPluginInstallRoot() {
  return join(homedir(), "Library", "Application Support", "Hopper", "PlugIns", "v4", "Tools");
}

function defaultPluginSocketPath() {
  return join(homedir(), "Library", "Application Support", "hopper-mcp", "hopper-plugin.sock");
}

function printUsage() {
  process.stderr.write(
    "Usage: node scripts/hopper-plugin-runtime.mjs <service-name|identities|install|probe> [options]\n",
  );
}

function printJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
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

async function installPlugin(options) {
  const source = resolve(options.plugin || join("target", "release", "HopperMCPAgent.hopperTool"));
  const destRoot = resolve(options.destRoot || defaultPluginInstallRoot());
  const destination = join(destRoot, "HopperMCPAgent.hopperTool");
  const codesignCommand = options.codesignCommand || "codesign";
  const otoolCommand = options.otoolCommand || "otool";
  const requestedIdentity = options.identity || process.env.HOPPER_MCP_CODESIGN_IDENTITY || null;
  const sign = !options.skipSign;
  const adHoc = options.adHoc === true;

  if (sign && !requestedIdentity && !adHoc) {
    return {
      ok: false,
      destination,
      source,
      message: "plugin install requires an explicit signing identity or --ad-hoc; implicit ad-hoc signing is not allowed",
    };
  }

  if (!sign && adHoc) {
    return {
      ok: false,
      destination,
      source,
      message: "--ad-hoc cannot be combined with --skip-sign",
    };
  }

  const identity = sign ? (requestedIdentity || "-") : null;
  const linkage = await verifyPluginLinkage({ pluginBundle: source, otoolCommand });
  if (!linkage.ok) {
    return {
      ok: false,
      phase: "pluginLinkage",
      source,
      destination,
      message: linkage.message,
    };
  }

  await mkdir(destRoot, { recursive: true });
  await rm(destination, { recursive: true, force: true });
  await cp(source, destination, { recursive: true });

  if (sign) {
    const signed = await runCapture(codesignCommand, ["--force", "--sign", identity, destination]);
    if (signed.code !== 0) {
      return {
        ok: false,
        destination,
        source,
        phase: "codesign",
        message: `codesign failed with code ${signed.code}: ${signed.stderr || signed.stdout}`,
      };
    }
  }

  return {
    ok: true,
    source,
    destination,
    signed: sign,
    identity: sign ? identity : null,
    serviceName: pluginServiceNameForSocketPath(defaultPluginSocketPath()),
  };
}

async function probePlugin(options) {
  const socket = options.socket || defaultProbeSocketPath();
  const serviceName = pluginServiceNameForSocketPath(socket);
  const timeoutMs = parseIntegerOption(options.timeoutMs, "--timeout-ms", DEFAULT_PROBE_TIMEOUT_MS);
  const agentCommand = resolve(options.agentCommand || DEFAULT_AGENT_COMMAND);
  const hopperCommand = options.hopperCommand || DEFAULT_HOPPER_COMMAND;
  const target = resolve(options.target || "/bin/echo");
  const loader = options.loader || "Mach-O";
  const fatArch = options.fatArch || null;
  const securityCommand = options.securityCommand || "security";
  const launchctlCommand = options.launchctlCommand || "launchctl";
  let identity = options.identity || process.env.HOPPER_MCP_CODESIGN_IDENTITY || null;

  try {
    if (!options.skipSign) {
      const identityReport = await codesigningIdentityReport({ securityCommand });
      if (identityReport.commandFailed) {
        return {
          ok: false,
          phase: "codesignIdentity",
          socket,
          serviceName,
          identities: identityReport.identities,
          message: identityReport.message,
        };
      }
      if (!identity) identity = selectPreferredIdentity(identityReport.identities);
      if (!identity) {
        return {
          ok: false,
          phase: "codesignIdentity",
          socket,
          serviceName,
          identities: identityReport.identities,
          message: "no valid codesigning identities found; install an Apple developer certificate or rerun with --skip-sign for fixture-only testing",
        };
      }
      options.identity = identity;
    }

    const install = await installPlugin(options);
    if (!install.ok) {
      return {
        ok: false,
        phase: install.phase ?? "install",
        socket,
        serviceName,
        ...install,
      };
    }

    await rm(socket, { force: true }).catch(() => {});
    const launchctlSetenv = await runLaunchctl(
      launchctlCommand,
      ["setenv", "HOPPER_MCP_PLUGIN_SOCKET", socket],
    );
    if (!launchctlSetenv.ok) {
      return {
        ok: false,
        phase: "launchctlSetenv",
        socket,
        serviceName,
        install,
        launchctlCommand,
        message: launchctlSetenv.message,
      };
    }

    const agent = spawn(agentCommand, [
      "--socket",
      socket,
      "--plugin-service",
      "auto",
    ], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const agentLogs = captureTail(agent);

    const hopperArgs = hopperCliOpenArgs({
      executablePath: target,
      analysis: false,
      loader,
      fatArch,
      onlyProcedures: true,
      parseObjectiveC: true,
      parseSwift: true,
      parseExceptions: true,
    });
    const hopper = spawn(hopperCommand, hopperArgs, {
      cwd: process.cwd(),
      env: {
        ...process.env,
        HOPPER_MCP_PLUGIN_SOCKET: socket,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const hopperLogs = captureTail(hopper);

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
        },
        message: error.message,
        agentStderr: agentLogs.stderr,
        hopperStderr: hopperLogs.stderr,
      };
    } finally {
      const cleanup = await cleanupProbeChildren({ agent, hopper });
      const launchctlUnsetenv = await runLaunchctl(
        launchctlCommand,
        ["unsetenv", "HOPPER_MCP_PLUGIN_SOCKET"],
      );
      await rm(socket, { force: true }).catch(() => {});
      cleanup.launchctlUnsetenv = launchctlUnsetenv.ok;
      if (!launchctlUnsetenv.ok) {
        cleanup.launchctlUnsetenvMessage = launchctlUnsetenv.message;
      }
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
        },
        handshake,
        currentDocument,
        procedures,
        cleanup,
        readyAfterMs: Date.now() - startedAt,
      };
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

function defaultProbeSocketPath() {
  return join("/tmp", `hopper-plugin-probe-${process.pid}-${Date.now()}.sock`);
}

async function codesigningIdentityReport({ securityCommand }) {
  const result = await runCapture(securityCommand, ["find-identity", "-p", "codesigning", "-v"]);
  const identities = result.code === 0 ? parseIdentities(result.stdout) : [];
  return {
    ok: result.code === 0 && identities.length > 0,
    commandFailed: result.code !== 0,
    identities,
    message: result.code !== 0
      ? `security command failed with code ${result.code}: ${result.stderr || result.stdout}`
      : identities.length > 0
        ? `found ${identities.length} codesigning identit${identities.length === 1 ? "y" : "ies"}`
        : "no valid codesigning identities found",
  };
}

function selectPreferredIdentity(identities) {
  if (!Array.isArray(identities) || identities.length === 0) return null;
  return (
    identities.find((identity) => /Developer ID Application:/i.test(identity.name))?.name
    || identities.find((identity) => /Apple Development:/i.test(identity.name))?.name
    || identities[0]?.name
    || null
  );
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

async function runLaunchctl(command, commandArgs) {
  try {
    const result = await runCapture(command, commandArgs);
    if (result.code === 0) {
      return { ok: true };
    }
    return {
      ok: false,
      message: `${command} ${commandArgs.join(" ")} failed with code ${result.code}: ${result.stderr || result.stdout}`,
    };
  } catch (error) {
    return {
      ok: false,
      message: `${command} ${commandArgs.join(" ")} could not start: ${error.message}`,
    };
  }
}

function parseIntegerOption(value, flag, fallback) {
  if (value == null) return fallback;
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return parsed;
}

function captureTail(child, maxBytes = 4096) {
  const logs = { stdout: "", stderr: "" };
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
    if (agent.exitCode !== null) {
      throw new Error(`hopper-agent exited early with code ${agent.exitCode}: ${agentLogs.stderr}`);
    }
    if (hopper.exitCode !== null && hopper.exitCode !== 0) {
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
    daemonVersion: "hopper-plugin-probe",
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
    && ["plugin_service_failed", "no_document"].includes(response.code);
}

async function cleanupProbeChildren({ agent, hopper }) {
  const agentResult = await terminateChild(agent, {
    alreadyExited: agent.exitCode !== null || agent.signalCode !== null,
    termGraceMs: 1_000,
    killGraceMs: 1_000,
  });
  const hopperResult = await terminateChild(hopper, {
    alreadyExited: hopper.exitCode !== null || hopper.signalCode !== null,
    termGraceMs: 1_000,
    killGraceMs: 2_000,
  });
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
