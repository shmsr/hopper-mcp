import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expectedCleanupCalls, expectedKillCalls, expectedPgrepCalls } from "../src/hopper-cleanup.js";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const privateCleanupCalls = () => [
  ...expectedCleanupCalls({ extraLaunchctlEnvVars: [
    "HOPPER_MCP_PRIVATE_AGENT_SOCKET",
    "HOPPER_MCP_PRIVATE_TARGET",
  ] }),
  ...expectedPgrepCalls(),
];
const forcedPrivateCleanupCalls = () =>
  expectedKillCalls({ signal: "-9" });

test("private backend gate reports a structured doctor failure without building the agent", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-private-backend-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "private backend doctor stdout"
echo "private backend doctor stderr" >&2
exit 1
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = await readFile(callsFile, "utf8");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "doctor");
  assert.match(payload.message, /cargo run -p hopper-mcpd -- doctor --json --require-hopper --require-private-host exited with 1/);
  assert.match(payload.stdoutTail, /private backend doctor stdout/);
  assert.match(payload.stderrTail, /private backend doctor stderr/);
  assert.match(calls, /^cargo:run -p hopper-mcpd -- doctor --json --require-hopper --require-private-host\n$/);
  assert.doesNotMatch(calls, /^npm:/m);
  assert.doesNotMatch(calls, /^node:/m);
  assert.match(result.stderr, /private backend doctor stdout/);
  assert.match(result.stderr, /private backend doctor stderr/);
});

test("private backend gate reports a structured runtime probe failure after building artifacts", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-private-backend-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "private backend doctor ok"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
if printf '%s' "$*" | grep -q 'scripts/private-backend-runtime.mjs probe'; then
  echo "private backend runtime probe stdout"
  echo "private backend runtime probe stderr" >&2
  exit 1
fi
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pkill"),
    `#!/bin/sh
echo "pkill:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "launchctl"),
    `#!/bin/sh
echo "launchctl:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pgrep"),
    `#!/bin/sh
echo "pgrep:$*" >> "${callsFile}"
exit 1
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = await readFile(callsFile, "utf8");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "runtimeProbe");
  assert.match(payload.message, /node scripts\/private-backend-runtime\.mjs probe exited with 1/);
  assert.match(payload.stdoutTail, /private backend runtime probe stdout/);
  assert.match(payload.stderrTail, /private backend runtime probe stderr/);
  assert.match(
    calls,
    new RegExp(
      `^cargo:run -p hopper-mcpd -- doctor --json --require-hopper --require-private-host\\n` +
      `npm:run build:agent\\n` +
      `npm:run build:hopper-plugin\\n` +
      `${privateCleanupCalls().join("\\n")}\\n` +
      `node:scripts/private-backend-runtime\\.mjs probe\\n` +
      `${privateCleanupCalls().join("\\n")}\\n$`,
    ),
  );
  assert.doesNotMatch(calls, /^node:--test test\/hopper-agent\.mjs/m);
  assert.match(result.stderr, /private backend doctor ok/);
  assert.match(result.stderr, /private backend runtime probe stdout/);
  assert.match(result.stderr, /private backend runtime probe stderr/);
});

test("private backend gate runs doctor, builds artifacts, and probes the live runtime in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-private-backend-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "private backend doctor ok"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "private backend npm $2"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
echo "private backend node $*"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pkill"),
    `#!/bin/sh
echo "pkill:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "launchctl"),
    `#!/bin/sh
echo "launchctl:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pgrep"),
    `#!/bin/sh
echo "pgrep:$*" >> "${callsFile}"
exit 1
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "cargo:run -p hopper-mcpd -- doctor --json --require-hopper --require-private-host",
    "npm:run build:agent",
    "npm:run build:hopper-plugin",
    ...privateCleanupCalls(),
    "node:scripts/private-backend-runtime.mjs probe",
    ...privateCleanupCalls(),
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.match(result.stderr, /private backend doctor ok/);
  assert.match(result.stderr, /private backend npm build:agent/);
  assert.match(result.stderr, /private backend npm build:hopper-plugin/);
  assert.match(result.stderr, /private backend node scripts\/private-backend-runtime\.mjs probe/);
});

test("private backend gate preserves phase and command when a spawned step cannot start", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-private-backend-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pkill"),
    `#!/bin/sh
echo "pkill:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "launchctl"),
    `#!/bin/sh
echo "launchctl:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pgrep"),
    `#!/bin/sh
echo "pgrep:$*" >> "${callsFile}"
exit 1
`,
  );

  const missingNode = join(binDir, "missing-node");
  const result = await runGate({
    PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}`,
    HOPPER_MCP_PRIVATE_BACKEND_NODE: missingNode,
  });
  const payload = JSON.parse(result.stdout);
  const calls = await readFile(callsFile, "utf8");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "runtimeProbe");
  assert.equal(payload.command, missingNode);
  assert.match(payload.message, /ENOENT|spawn/i);
  assert.equal(payload.stdoutTail, "");
  assert.equal(payload.stderrTail, "");
  assert.match(
    calls,
    new RegExp(
      `^cargo:run -p hopper-mcpd -- doctor --json --require-hopper --require-private-host\\n` +
      `npm:run build:agent\\n` +
      `npm:run build:hopper-plugin\\n` +
      `${privateCleanupCalls().join("\\n")}\\n` +
      `${privateCleanupCalls().join("\\n")}\\n$`,
    ),
  );
});

test("private backend gate fails when pre-probe cleanup cannot stop Hopper", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-private-backend-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pkill"),
    `#!/bin/sh
echo "pkill:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "launchctl"),
    `#!/bin/sh
echo "launchctl:$*" >> "${callsFile}"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pgrep"),
    `#!/bin/sh
echo "pgrep:$*" >> "${callsFile}"
echo "12345"
exit 0
`,
  );

  const result = await runGate({
    PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}`,
    HOPPER_MCP_CLEANUP_TIMEOUT_MS: "3",
    HOPPER_MCP_CLEANUP_POLL_MS: "1",
  });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "cleanup");
  assert.match(payload.message, /timed out waiting for Hopper to exit/i);
  assert.deepEqual(
    calls.slice(
      0,
      3 + expectedCleanupCalls({
        extraLaunchctlEnvVars: [
          "HOPPER_MCP_PRIVATE_AGENT_SOCKET",
          "HOPPER_MCP_PRIVATE_TARGET",
        ],
      }).length,
    ),
    [
      "cargo:run -p hopper-mcpd -- doctor --json --require-hopper --require-private-host",
      "npm:run build:agent",
      "npm:run build:hopper-plugin",
      ...expectedCleanupCalls({
        extraLaunchctlEnvVars: [
          "HOPPER_MCP_PRIVATE_AGENT_SOCKET",
          "HOPPER_MCP_PRIVATE_TARGET",
        ],
      }),
    ],
  );
  assert.ok(calls.includes(expectedPgrepCalls()[0]));
  assert.match(calls.join("\n"), new RegExp(forcedPrivateCleanupCalls().join("\\n")));
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runGate(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/private-backend-check.mjs"], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...env,
      },
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
    child.on("error", rejectPromise);
    child.on("close", (code) => {
      resolvePromise({ code, stdout, stderr });
    });
  });
}
