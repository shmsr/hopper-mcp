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

test("plugin-live gate reports a structured doctor failure without probing Hopper", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-plugin-live-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "doctor stdout"
echo "doctor stderr" >&2
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
  assert.match(payload.message, /cargo run -p hopper-mcpd -- doctor --json --require-plugin-identity exited with 1/);
  assert.match(payload.stdoutTail, /doctor stdout/);
  assert.match(payload.stderrTail, /doctor stderr/);
  assert.match(calls, /^cargo:run -p hopper-mcpd -- doctor --json --require-plugin-identity\n$/);
  assert.doesNotMatch(calls, /^npm:/m);
  assert.match(result.stderr, /doctor stdout/);
  assert.match(result.stderr, /doctor stderr/);
});

test("plugin-live gate runs doctor and probe in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-plugin-live-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "doctor ok"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "probe ok"
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
    "cargo:run -p hopper-mcpd -- doctor --json --require-plugin-identity",
    ...cleanupCalls(),
    "npm:run hopper-plugin:probe",
    ...cleanupCalls(),
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.match(result.stderr, /doctor ok/);
  assert.match(result.stderr, /probe ok/);
});

test("plugin-live gate performs final cleanup after probe failure", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-plugin-live-"));
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
echo "probe failed" >&2
exit 1
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
  assert.equal(payload.phase, "probe");
  assert.match(payload.stderrTail, /probe failed/);
  assert.deepEqual(calls, [
    "cargo:run -p hopper-mcpd -- doctor --json --require-plugin-identity",
    ...cleanupCalls(),
    "npm:run hopper-plugin:probe",
    ...cleanupCalls(),
  ]);
});

test("plugin-live gate fails when final cleanup cannot stop Hopper after a successful probe", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-plugin-live-"));
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
COUNT_FILE="${join(tempDir, "pgrep.count")}"
COUNT=0
if [ -f "$COUNT_FILE" ]; then
  COUNT=$(cat "$COUNT_FILE")
fi
COUNT=$((COUNT + 1))
echo "$COUNT" > "$COUNT_FILE"
echo "pgrep:$*" >> "${callsFile}"
if [ "$COUNT" -eq 1 ]; then
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
  assert.deepEqual(calls.slice(0, 1 + expectedCleanupCalls().length), [
    "cargo:run -p hopper-mcpd -- doctor --json --require-plugin-identity",
    ...expectedCleanupCalls(),
  ]);
  assert.ok(calls.includes(expectedPgrepCalls()[0]));
  assert.match(calls.join("\n"), new RegExp(forcedCleanupCalls().join("\\n")));
});

test("plugin-live gate fails before probing when pre-probe cleanup cannot stop Hopper", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-plugin-live-"));
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
  assert.deepEqual(calls.slice(0, 1 + expectedCleanupCalls().length), [
    "cargo:run -p hopper-mcpd -- doctor --json --require-plugin-identity",
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
    const child = spawn(process.execPath, ["scripts/plugin-live-check.mjs"], {
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
