import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("release gate reports a structured phase failure and stops subsequent phases", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-release-gate-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
if [ "$2" = "clippy:rust" ]; then
  echo "clippy stdout"
  echo "clippy stderr" >&2
  exit 1
fi
echo "npm ok $2"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "cargo ok $1"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "clippy");
  assert.match(payload.message, /npm run clippy:rust exited with 1/);
  assert.match(payload.stdoutTail, /clippy stdout/);
  assert.match(payload.stderrTail, /clippy stderr/);
  assert.deepEqual(calls, [
    "npm:run test",
    "cargo:fmt --check",
    "npm:run clippy:rust",
  ]);
  assert.match(result.stderr, /npm ok test/);
  assert.match(result.stderr, /cargo ok fmt/);
  assert.match(result.stderr, /clippy stdout/);
  assert.match(result.stderr, /clippy stderr/);
});

test("release gate runs all non-live verification phases in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-release-gate-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "npm ok $2"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "cargo ok $1"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "npm:run test",
    "cargo:fmt --check",
    "npm:run clippy:rust",
    "cargo:test --workspace",
    "npm:run doctor:json",
    "npm:run package:release:check",
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.match(result.stderr, /npm ok test/);
  assert.match(result.stderr, /cargo ok fmt/);
  assert.match(result.stderr, /npm ok clippy:rust/);
  assert.match(result.stderr, /cargo ok test/);
  assert.match(result.stderr, /npm ok doctor:json/);
  assert.match(result.stderr, /npm ok package:release:check/);
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runGate(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/release-check.mjs"], {
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
