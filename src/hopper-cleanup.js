import { spawn } from "node:child_process";

const HOPPER_KILL_PATTERNS = [
  ["-x", "Hopper Disassembler"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/XPCServices/ExternalAPI.xpc/Contents/MacOS/ExternalAPI"],
];

const HOPPER_PGREP_PATTERNS = [
  ["-x", "Hopper Disassembler"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer"],
  ["-f", "/Applications/Hopper Disassembler.app/Contents/XPCServices/ExternalAPI.xpc/Contents/MacOS/ExternalAPI"],
];

export function cleanupCommandsFromEnv({
  pkillVar = "HOPPER_MCP_CLEANUP_PKILL",
  pgrepVar = "HOPPER_MCP_CLEANUP_PGREP",
  launchctlVar = "HOPPER_MCP_CLEANUP_LAUNCHCTL",
} = {}) {
  return {
    pkillCommand: process.env[pkillVar] || "pkill",
    pgrepCommand: process.env[pgrepVar] || "pgrep",
    launchctlCommand: process.env[launchctlVar] || "launchctl",
  };
}

export function cleanupTimingFromEnv({
  timeoutVar = "HOPPER_MCP_CLEANUP_TIMEOUT_MS",
  pollVar = "HOPPER_MCP_CLEANUP_POLL_MS",
  defaultTimeoutMs = 15_000,
  defaultPollMs = 250,
} = {}) {
  return {
    timeoutMs: parsePositiveInt(process.env[timeoutVar], defaultTimeoutMs),
    pollMs: parsePositiveInt(process.env[pollVar], defaultPollMs),
  };
}

export async function cleanupHopperState({
  pkillCommand = "pkill",
  pgrepCommand = "pgrep",
  launchctlCommand = "launchctl",
  extraLaunchctlEnvVars = [],
  cwd = process.cwd(),
  env = process.env,
  stderr = process.stderr,
  timeoutMs = 15_000,
  pollMs = 250,
} = {}) {
  await runKillPass(pkillCommand, HOPPER_KILL_PATTERNS, { cwd, env, stderr });
  await runBestEffort(launchctlCommand, ["unsetenv", "HOPPER_MCP_PLUGIN_SOCKET"], { cwd, env, stderr });
  for (const envVar of extraLaunchctlEnvVars) {
    if (typeof envVar !== "string" || envVar.length === 0) continue;
    await runBestEffort(launchctlCommand, ["unsetenv", envVar], { cwd, env, stderr });
  }
  if (await waitForNoHopper({ pgrepCommand, cwd, env, stderr, timeoutMs, pollMs })) return;
  await runKillPass(pkillCommand, HOPPER_KILL_PATTERNS, {
    cwd,
    env,
    stderr,
    signal: "-9",
  });
  if (await waitForNoHopper({
    pgrepCommand,
    cwd,
    env,
    stderr,
    timeoutMs: Math.max(pollMs * 4, 50),
    pollMs,
  })) return;
  throw new Error(`timed out waiting for Hopper to exit after ${timeoutMs}ms`);
}

async function runBestEffort(command, args, { cwd, env, stderr }) {
  await new Promise((resolvePromise) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.on("data", (chunk) => {
      stderr.write(chunk.toString());
    });
    child.stderr.on("data", (chunk) => {
      stderr.write(chunk.toString());
    });
    child.on("error", () => resolvePromise());
    child.on("close", () => resolvePromise());
  });
}

async function runKillPass(command, patternArgsList, { cwd, env, stderr, signal = null }) {
  for (const args of patternArgsList) {
    const fullArgs = signal ? [signal, ...args] : args;
    await runBestEffort(command, fullArgs, { cwd, env, stderr });
  }
}

async function waitForNoHopper({ pgrepCommand, cwd, env, stderr, timeoutMs, pollMs }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const active = await isHopperRunning({ pgrepCommand, cwd, env, stderr });
    if (!active) return true;
    await sleep(pollMs);
  }
  return false;
}

async function isHopperRunning({ pgrepCommand, cwd, env, stderr }) {
  for (const args of HOPPER_PGREP_PATTERNS) {
    if (await runPgrep(pgrepCommand, args, { cwd, env, stderr })) return true;
  }
  return false;
}

async function runPgrep(command, args, { cwd, env, stderr }) {
  return await new Promise((resolvePromise) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.on("data", (chunk) => {
      stderr.write(chunk.toString());
    });
    child.stderr.on("data", (chunk) => {
      stderr.write(chunk.toString());
    });
    child.on("error", () => resolvePromise(false));
    child.on("close", (code) => resolvePromise(code === 0));
  });
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function expectedCleanupCalls({ extraLaunchctlEnvVars = [], signal = null } = {}) {
  return [
    ...expectedKillCalls({ signal }),
    "launchctl:unsetenv HOPPER_MCP_PLUGIN_SOCKET",
    ...extraLaunchctlEnvVars.map((envVar) => `launchctl:unsetenv ${envVar}`),
  ];
}

export function expectedPgrepCalls() {
  return HOPPER_PGREP_PATTERNS.map((args) => `pgrep:${args.join(" ")}`);
}

export function expectedKillCalls({ signal = null } = {}) {
  return HOPPER_KILL_PATTERNS.map((args) =>
    `pkill:${signal ? [signal, ...args].join(" ") : args.join(" ")}`);
}
