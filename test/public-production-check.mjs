import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("public production gate reports a structured phase failure and stops later signed lanes", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-public-production-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
if [ "$2" = "release:check:distribution" ]; then
  echo "public distribution stdout"
  echo "public distribution stderr" >&2
  exit 1
fi
echo "public npm $2"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "distribution");
  assert.equal(payload.profile, "public");
  assert.match(payload.message, /npm run release:check:distribution exited with 1/);
  assert.match(payload.stdoutTail, /public distribution stdout/);
  assert.match(payload.stderrTail, /public distribution stderr/);
  assert.deepEqual(calls, [
    "npm:run release:check:plugin-live",
    "npm:run release:check:distribution",
  ]);
  assert.match(result.stderr, /public npm release:check:plugin-live/);
  assert.match(result.stderr, /public distribution stdout/);
  assert.match(result.stderr, /public distribution stderr/);
});

test("public production gate runs signed plugin, signed distribution, and notarized release lanes in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-public-production-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "public npm $2"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "npm:run release:check:plugin-live",
    "npm:run release:check:distribution",
    "npm:run release:check:public-release",
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.equal(payload.profile, "public");
  assert.match(result.stderr, /public npm release:check:plugin-live/);
  assert.match(result.stderr, /public npm release:check:distribution/);
  assert.match(result.stderr, /public npm release:check:public-release/);
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runGate(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/public-production-check.mjs"], {
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
