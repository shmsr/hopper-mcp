import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("distribution gate reports a structured doctor failure without running npm", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-distribution-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "distribution doctor stdout"
echo "distribution doctor stderr" >&2
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
  assert.match(payload.message, /cargo run -p hopper-mcpd -- doctor --json --require-distribution-identity --require-clean-git-tree exited with 1/);
  assert.match(payload.stdoutTail, /distribution doctor stdout/);
  assert.match(payload.stderrTail, /distribution doctor stderr/);
  assert.match(calls, /^cargo:run -p hopper-mcpd -- doctor --json --require-distribution-identity --require-clean-git-tree\n$/);
  assert.doesNotMatch(calls, /^npm:/m);
  assert.match(result.stderr, /distribution doctor stdout/);
  assert.match(result.stderr, /distribution doctor stderr/);
});

test("distribution gate runs doctor, release check, and package release in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-distribution-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "distribution doctor ok"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "npm step $2"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "cargo:run -p hopper-mcpd -- doctor --json --require-distribution-identity --require-clean-git-tree",
    "npm:run release:check",
    "npm:run package:release",
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.match(result.stderr, /distribution doctor ok/);
  assert.match(result.stderr, /npm step release:check/);
  assert.match(result.stderr, /npm step package:release/);
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runGate(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/distribution-check.mjs"], {
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
