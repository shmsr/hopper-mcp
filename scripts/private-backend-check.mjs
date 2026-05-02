#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  cleanupCommandsFromEnv,
  cleanupHopperState as cleanupHopperStateShared,
  cleanupTimingFromEnv,
} from "../src/hopper-cleanup.js";

const cargoCommand = process.env.HOPPER_MCP_PRIVATE_BACKEND_CARGO || "cargo";
const npmCommand = process.env.HOPPER_MCP_PRIVATE_BACKEND_NPM || "npm";
const nodeCommand = process.env.HOPPER_MCP_PRIVATE_BACKEND_NODE || "node";
const cleanupCommands = cleanupCommandsFromEnv({
  pkillVar: "HOPPER_MCP_PRIVATE_BACKEND_PKILL",
  pgrepVar: "HOPPER_MCP_PRIVATE_BACKEND_PGREP",
  launchctlVar: "HOPPER_MCP_PRIVATE_BACKEND_LAUNCHCTL",
});
const cleanupTiming = cleanupTimingFromEnv();

const result = await main();
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = result.ok ? 0 : 1;

async function main() {
  let shouldCleanupAtExit = false;
  let result = null;
  let failure = null;
  try {
    await run("doctor", cargoCommand, [
      "run",
      "-p",
      "hopper-mcpd",
      "--",
      "doctor",
      "--json",
      "--require-hopper",
      "--require-private-host",
    ]);
    await run("buildAgent", npmCommand, ["run", "build:agent"]);
    await run("buildPlugin", npmCommand, ["run", "build:hopper-plugin"]);
    shouldCleanupAtExit = true;
    await cleanupRunnerState();
    await run("runtimeProbe", nodeCommand, ["scripts/private-backend-runtime.mjs", "probe"]);
    result = {
      ok: true,
      phase: "complete",
    };
  } catch (error) {
    failure = {
      ok: false,
      phase: error.phase ?? "unknown",
      command: error.command ?? null,
      message: error.message,
      stdoutTail: error.stdoutTail ?? "",
      stderrTail: error.stderrTail ?? "",
    };
  } finally {
    if (shouldCleanupAtExit) {
      try {
        await cleanupRunnerState();
      } catch (error) {
        if (failure) {
          process.stderr.write(`cleanup hopper state failed: ${error?.message ?? String(error)}\n`);
        } else {
          failure = {
            ok: false,
            phase: "cleanup",
            command: null,
            message: error?.message ?? String(error),
            stdoutTail: "",
            stderrTail: "",
          };
        }
      }
    }
  }
  return failure ?? result;
}

async function run(phase, command, args, envOverrides = {}) {
  await new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd: process.cwd(),
        env: {
          ...process.env,
          ...envOverrides,
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      rejectPromise(spawnError(phase, command, error));
      return;
    }
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stderr.write(text);
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });
    child.on("error", (error) => rejectPromise(spawnError(phase, command, error)));
    child.on("close", (code) => {
      if (code === 0) resolvePromise();
      else {
        const error = new Error(`${command} ${args.join(" ")} exited with ${code}`);
        error.phase = phase;
        error.command = command;
        error.stdoutTail = tail(stdout);
        error.stderrTail = tail(stderr);
        rejectPromise(error);
      }
    });
  });
}

function spawnError(phase, command, error) {
  error.phase ??= phase;
  error.command ??= command;
  error.stdoutTail ??= "";
  error.stderrTail ??= "";
  return error;
}

function tail(text, max = 4000) {
  return text.length > max ? text.slice(-max) : text;
}

async function cleanupRunnerState() {
  try {
    await cleanupHopperStateShared({
      ...cleanupCommands,
      extraLaunchctlEnvVars: [
        "HOPPER_MCP_PRIVATE_AGENT_SOCKET",
        "HOPPER_MCP_PRIVATE_TARGET",
      ],
      cwd: process.cwd(),
      env: process.env,
      stderr: process.stderr,
      ...cleanupTiming,
    });
  } catch (error) {
    error.phase ??= "cleanup";
    throw error;
  }
}
