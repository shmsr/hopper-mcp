import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expectedCleanupCalls, expectedKillCalls, expectedPgrepCalls } from "../src/hopper-cleanup.js";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const cleanupCalls = () => [...expectedCleanupCalls(), ...expectedPgrepCalls()];
const forcedCleanupCalls = () => expectedKillCalls({ signal: "-9" });
const cleanupCallsWithRepeatedFirstPgrep = () => [
  ...expectedCleanupCalls(),
  expectedPgrepCalls()[0],
  ...expectedPgrepCalls(),
];
const cleanupCallsWithFirstAndSecondPatternRetries = () => [
  ...expectedCleanupCalls(),
  expectedPgrepCalls()[0],
  expectedPgrepCalls()[0],
  expectedPgrepCalls()[1],
  ...expectedPgrepCalls(),
];

test("live gate reports a structured doctor failure before npm work", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-live-gate-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "live doctor stdout"
echo "live doctor stderr" >&2
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

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = await readFile(callsFile, "utf8");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "doctor");
  assert.match(payload.message, /cargo run -p hopper-mcpd -- doctor --json --require-hopper exited with 1/);
  assert.match(payload.stdoutTail, /live doctor stdout/);
  assert.match(payload.stderrTail, /live doctor stderr/);
  assert.match(calls, /^cargo:run -p hopper-mcpd -- doctor --json --require-hopper\n$/);
  assert.doesNotMatch(calls, /^npm:/m);
  assert.match(result.stderr, /live doctor stdout/);
  assert.match(result.stderr, /live doctor stderr/);
});

test("live gate runs doctor, release check, test:live, and live corpus in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-live-gate-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "live doctor ok"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "live npm $2"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
echo "live node $*"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "pkill"),
    `#!/bin/sh
echo "pkill:$*" >> "${callsFile}"
exit 1
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
    "cargo:run -p hopper-mcpd -- doctor --json --require-hopper",
    "npm:run release:check",
    ...cleanupCalls(),
    "node:--test test/live.mjs",
    "cargo:test -p hopper-mcpd --test live_bridge_contract daemon_default_live_bridge_ingests_echo_when_enabled",
    ...cleanupCalls(),
    "node:scripts/live-corpus.mjs",
    ...cleanupCalls(),
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.match(result.stderr, /live doctor ok/);
  assert.match(result.stderr, /live npm release:check/);
  assert.match(result.stderr, /live node --test test\/live\.mjs/);
  assert.match(result.stderr, /live node scripts\/live-corpus\.mjs/);
});

test("live gate cleans Hopper state before each live phase", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-live-gate-"));
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
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
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
COUNT_FILE="${join(tempDir, "pgrep.count")}"
COUNT=0
if [ -f "$COUNT_FILE" ]; then
  COUNT=$(cat "$COUNT_FILE")
fi
COUNT=$((COUNT + 1))
echo "$COUNT" > "$COUNT_FILE"
echo "pgrep:$*" >> "${callsFile}"
if [ "$COUNT" -eq 1 ] || [ "$COUNT" -eq 3 ]; then
  echo "12345"
  exit 0
fi
exit 1
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "cargo:run -p hopper-mcpd -- doctor --json --require-hopper",
    "npm:run release:check",
    ...cleanupCallsWithFirstAndSecondPatternRetries(),
    "node:--test test/live.mjs",
    "cargo:test -p hopper-mcpd --test live_bridge_contract daemon_default_live_bridge_ingests_echo_when_enabled",
    ...cleanupCalls(),
    "node:scripts/live-corpus.mjs",
    ...cleanupCalls(),
  ]);
});

test("live gate performs final cleanup after a live phase failure", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-live-gate-"));
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
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
if [ "$1" = "--test" ]; then
  echo "live suite failed" >&2
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
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "testLiveJs");
  assert.match(payload.stderrTail, /live suite failed/);
  assert.deepEqual(calls, [
    "cargo:run -p hopper-mcpd -- doctor --json --require-hopper",
    "npm:run release:check",
    ...cleanupCalls(),
    "node:--test test/live.mjs",
    ...cleanupCalls(),
  ]);
});

test("live gate fails when final cleanup cannot stop Hopper after success", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-live-gate-"));
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
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
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
COUNT_FILE="${join(tempDir, "pgrep.count")}"
COUNT=0
if [ -f "$COUNT_FILE" ]; then
  COUNT=$(cat "$COUNT_FILE")
fi
COUNT=$((COUNT + 1))
echo "$COUNT" > "$COUNT_FILE"
echo "pgrep:$*" >> "${callsFile}"
if [ "$COUNT" -le 4 ]; then
  exit 1
fi
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
  assert.deepEqual(calls.slice(0, 2 + cleanupCalls().length), [
    "cargo:run -p hopper-mcpd -- doctor --json --require-hopper",
    "npm:run release:check",
    ...cleanupCalls(),
  ]);
  const afterPrelude = 2 + cleanupCalls().length;
  assert.equal(calls[afterPrelude], "node:--test test/live.mjs");
  assert.equal(calls[afterPrelude + 1], "cargo:test -p hopper-mcpd --test live_bridge_contract daemon_default_live_bridge_ingests_echo_when_enabled");
  assert.deepEqual(
    calls.slice(afterPrelude + 2, afterPrelude + 2 + expectedCleanupCalls().length),
    expectedCleanupCalls(),
  );
  assert.ok(calls.includes(expectedPgrepCalls()[0]));
  assert.match(calls.join("\n"), new RegExp(forcedCleanupCalls().join("\\n")));
});

test("live gate fails before test:live when pre-live cleanup cannot stop Hopper", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-live-gate-"));
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
    join(binDir, "node"),
    `#!/bin/sh
echo "node:$*" >> "${callsFile}"
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
  assert.deepEqual(calls.slice(0, 2 + expectedCleanupCalls().length), [
    "cargo:run -p hopper-mcpd -- doctor --json --require-hopper",
    "npm:run release:check",
    ...expectedCleanupCalls(),
  ]);
  assert.ok(calls.includes(expectedPgrepCalls()[0]));
  assert.match(calls.join("\n"), new RegExp(forcedCleanupCalls().join("\\n")));
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runGate(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/live-check.mjs"], {
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
