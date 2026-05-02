import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const PROBE_TIMEOUT_MS = 15_000;

test("private-backend-runtime probe launches Hopper with plugin socket env and verifies the plugin-service bridge", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "private-backend-runtime-"));
  try {
    const plugin = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const launchScript = join(temp, "fake-hopper.sh");
    const launchLog = join(temp, "launch-env.log");
    const socket = join("/tmp", `hopper-private-probe-${process.pid}-${Date.now()}.sock`);
    const serviceName = await serviceNameFor(socket);

    await mkdir(join(plugin, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(plugin, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(plugin, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(launchScript, `#!/bin/sh
printf 'DYLD_INSERT_LIBRARIES=%s\n' "$DYLD_INSERT_LIBRARIES" > ${JSON.stringify(launchLog)}
printf 'HOPPER_MCP_PLUGIN_SOCKET=%s\n' "$HOPPER_MCP_PLUGIN_SOCKET" >> ${JSON.stringify(launchLog)}
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
`, "utf8");
    await chmod(launchScript, 0o755);

    const service = spawn("target/release/hopper-agent", [
      "--service-fixture-name",
      serviceName,
      "--fixture-document-id",
      "doc-private-runtime",
      "--fixture-document-name",
      "PrivateRuntimeFixture",
      "--fixture-procedure",
      "0x5000:private_runtime_entry:80",
    ], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let serviceStderr = "";
    service.stderr.on("data", (chunk) => {
      serviceStderr += chunk.toString();
    });

    try {
      const result = await run("node", [
        "scripts/private-backend-runtime.mjs",
        "probe",
        "--plugin",
        plugin,
        "--dest-root",
        destRoot,
        "--socket",
        socket,
        "--agent-command",
        "target/release/hopper-agent",
        "--hopper-command",
        launchScript,
        "--target",
        "/bin/echo",
        "--timeout-ms",
        String(PROBE_TIMEOUT_MS),
      ]);
      assert.equal(result.code, 0, `${result.stderr}\n${serviceStderr}`);
      const payload = JSON.parse(result.stdout);
      assert.equal(payload.ok, true);
      assert.equal(payload.currentDocument.documentId, "doc-private-runtime");
      assert.equal(payload.procedures.procedures[0].addr, "0x5000");
      assert.equal(payload.cleanup.agentTerminated, true);
      assert.equal(payload.cleanup.hopperTerminated, true);
      await waitForFile(launchLog, PROBE_TIMEOUT_MS);
      const launchEnv = await readFile(launchLog, "utf8");
      assert.match(launchEnv, /^DYLD_INSERT_LIBRARIES=\s*$/m);
      assert.match(launchEnv, new RegExp(`HOPPER_MCP_PLUGIN_SOCKET=${escapeRegex(socket)}`));
      await readFile(join(destRoot, "HopperMCPAgent.hopperTool", "Contents", "MacOS", "Plugin"), "utf8");
    } finally {
      service.kill("SIGTERM");
      await onceClose(service);
      await rm(socket, { force: true }).catch(() => {});
    }

    assert.equal(service.exitCode === 0 || service.signalCode === "SIGTERM", true, serviceStderr);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("private-backend-runtime probe can use a preexisting direct socket server without spawning hopper-agent", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "private-backend-runtime-"));
  try {
    const plugin = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const launchScript = join(temp, "fake-hopper.sh");
    const launchLog = join(temp, "launch-env.log");
    const socket = join("/tmp", `hopper-private-direct-${process.pid}-${Date.now()}.sock`);

    await mkdir(join(plugin, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(plugin, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(plugin, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(launchScript, `#!/bin/sh
printf 'DYLD_INSERT_LIBRARIES=%s\n' "$DYLD_INSERT_LIBRARIES" > ${JSON.stringify(launchLog)}
printf 'HOPPER_MCP_PRIVATE_AGENT_SOCKET=%s\n' "$HOPPER_MCP_PRIVATE_AGENT_SOCKET" >> ${JSON.stringify(launchLog)}
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
`, "utf8");
    await chmod(launchScript, 0o755);

    const server = spawn("target/release/hopper-agent", [
      "--socket",
      socket,
      "--fixture",
      "--fixture-document-id",
      "doc-direct-runtime",
      "--fixture-document-name",
      "DirectRuntimeFixture",
      "--fixture-procedure",
      "0x6000:direct_runtime_entry:64",
    ], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let serverStderr = "";
    server.stderr.on("data", (chunk) => {
      serverStderr += chunk.toString();
    });

    try {
      const result = await run("node", [
        "scripts/private-backend-runtime.mjs",
        "probe",
        "--plugin",
        plugin,
        "--dest-root",
        destRoot,
        "--socket",
        socket,
        "--hopper-command",
        launchScript,
        "--target",
        "/bin/echo",
        "--timeout-ms",
        String(PROBE_TIMEOUT_MS),
      ]);
      assert.equal(result.code, 0, `${result.stderr}\n${serverStderr}`);
      const payload = JSON.parse(result.stdout);
      assert.equal(payload.ok, true);
      assert.equal(payload.currentDocument.documentId, "doc-direct-runtime");
      assert.equal(payload.procedures.procedures[0].addr, "0x6000");
      assert.equal(payload.cleanup.hopperTerminated, true);
    } finally {
      server.kill("SIGTERM");
      await onceClose(server);
      await rm(socket, { force: true }).catch(() => {});
    }

    assert.equal(server.exitCode === 0 || server.signalCode === "SIGTERM", true, serverStderr);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("private-backend-runtime probe fails fast when the plugin bundle is missing", async () => {
  const temp = await mkdtemp(join(tmpdir(), "private-backend-runtime-"));
  try {
    const result = await run("node", [
      "scripts/private-backend-runtime.mjs",
      "probe",
      "--plugin",
      join(temp, "missing.hopperTool"),
    ]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.phase, "pluginLinkage");
    assert.match(payload.message, /plugin bundle has no executable/i);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
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

async function serviceNameFor(socket) {
  const result = await run("node", [
    "scripts/hopper-plugin-runtime.mjs",
    "service-name",
    "--socket",
    socket,
  ]);
  assert.equal(result.code, 0, result.stderr);
  return JSON.parse(result.stdout).serviceName;
}

function onceClose(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("close", resolve);
  });
}

function escapeRegex(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function waitForFile(path, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await readFile(path, "utf8");
      return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for file ${path}`);
}
