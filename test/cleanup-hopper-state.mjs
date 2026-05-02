import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expectedCleanupCalls, expectedKillCalls, expectedPgrepCalls } from "../src/hopper-cleanup.js";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("cleanup hopper state clears GUI socket env and waits for Hopper launcher and GUI executable to exit", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-cleanup-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
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
  echo "12345"
  exit 0
fi
exit 1
`,
  );

  const result = await runCleanup({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.deepEqual(calls, [
    ...expectedCleanupCalls(),
    expectedPgrepCalls()[0],
    expectedPgrepCalls()[0],
    ...expectedPgrepCalls().slice(1),
  ]);
});

test("cleanup hopper state fails when Hopper does not exit before the timeout", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-cleanup-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
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

  const result = await runCleanup({
    PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}`,
    HOPPER_MCP_CLEANUP_TIMEOUT_MS: "3",
  });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "cleanup");
  assert.match(payload.message, /timed out waiting for Hopper to exit/i);
  assert.deepEqual(calls.slice(0, expectedCleanupCalls().length), expectedCleanupCalls());
  assert.ok(calls.includes(expectedPgrepCalls()[0]));
  assert.match(
    calls.join("\n"),
    new RegExp(expectedKillCalls({ signal: "-9" }).join("\\n")),
  );
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runCleanup(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/cleanup-hopper-state.mjs"], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...env,
        HOPPER_MCP_CLEANUP_POLL_MS: "1",
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
