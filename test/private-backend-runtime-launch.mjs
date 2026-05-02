import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_HOPPER_APP_COMMAND,
  DEFAULT_HOPPER_HELPER_COMMAND,
  runPrivateLiveExportWarmup,
  shouldUseLiveExportWarmup,
} from "../src/private-backend-runtime.js";

test("shouldUseLiveExportWarmup only enables the live-export path for the default Hopper launchers without an external agent", () => {
  assert.equal(
    shouldUseLiveExportWarmup({
      hopperCommand: DEFAULT_HOPPER_APP_COMMAND,
      agentCommand: null,
    }),
    true,
  );
  assert.equal(
    shouldUseLiveExportWarmup({
      hopperCommand: DEFAULT_HOPPER_HELPER_COMMAND,
      agentCommand: null,
    }),
    true,
  );
  assert.equal(
    shouldUseLiveExportWarmup({
      hopperCommand: "/tmp/fake-hopper",
      agentCommand: null,
    }),
    false,
  );
  assert.equal(
    shouldUseLiveExportWarmup({
      hopperCommand: DEFAULT_HOPPER_APP_COMMAND,
      agentCommand: "/tmp/fake-agent",
    }),
    false,
  );
});

test("runPrivateLiveExportWarmup sets launchctl env, reuses the live exporter, and returns an env cleanup handle", async () => {
  const launchctlCalls = [];
  const ingestCalls = [];
  const warmup = await runPrivateLiveExportWarmup({
    socket: "/tmp/private-runtime.sock",
    target: "/bin/echo",
    timeoutMs: 15000,
    loader: "Mach-O",
    runCapture: async (command, args) => {
      launchctlCalls.push([command, ...args]);
      return { code: 0, stdout: "", stderr: "" };
    },
    ingest: async (options) => {
      ingestCalls.push(options);
      return {
        launch: {
          launcher: "live-export-fixture",
        },
      };
    },
  });

  assert.deepEqual(launchctlCalls, [
    ["launchctl", "setenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET", "/tmp/private-runtime.sock"],
    ["launchctl", "setenv", "HOPPER_MCP_PRIVATE_TARGET", "/bin/echo"],
  ]);
  assert.deepEqual(ingestCalls, [
    {
      executablePath: "/bin/echo",
      hopperLauncher: DEFAULT_HOPPER_HELPER_COMMAND,
      analysis: false,
      loader: "Mach-O",
      onlyProcedures: true,
      parseObjectiveC: true,
      parseSwift: true,
      parseExceptions: true,
      closeAfterExport: false,
      timeoutMs: 15000,
      maxFunctions: 10,
      maxStrings: 20,
    },
  ]);
  assert.deepEqual(warmup.liveLaunch, { launcher: "live-export-fixture" });

  await warmup.cleanupEnv();
  assert.deepEqual(launchctlCalls, [
    ["launchctl", "setenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET", "/tmp/private-runtime.sock"],
    ["launchctl", "setenv", "HOPPER_MCP_PRIVATE_TARGET", "/bin/echo"],
    ["launchctl", "unsetenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET"],
    ["launchctl", "unsetenv", "HOPPER_MCP_PRIVATE_TARGET"],
  ]);
});

test("runPrivateLiveExportWarmup clears launchctl env when live export startup fails", async () => {
  const launchctlCalls = [];
  await assert.rejects(
    runPrivateLiveExportWarmup({
      socket: "/tmp/private-runtime.sock",
      target: "/bin/echo",
      timeoutMs: 15000,
      loader: "Mach-O",
      runCapture: async (command, args) => {
        launchctlCalls.push([command, ...args]);
        return { code: 0, stdout: "", stderr: "" };
      },
      ingest: async () => {
        throw new Error("live export failed");
      },
    }),
    /live export failed/,
  );
  assert.deepEqual(launchctlCalls, [
    ["launchctl", "setenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET", "/tmp/private-runtime.sock"],
    ["launchctl", "setenv", "HOPPER_MCP_PRIVATE_TARGET", "/bin/echo"],
    ["launchctl", "unsetenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET"],
    ["launchctl", "unsetenv", "HOPPER_MCP_PRIVATE_TARGET"],
  ]);
});
