import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("internal soak gate reports a structured phase failure and stops the soak lane", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-internal-soak-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
if [ "$2" = "test:live:corpus:large-apps" ]; then
  echo "soak stdout"
  echo "soak stderr" >&2
  exit 1
fi
echo "internal soak $2"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "largeAppSoak");
  assert.equal(payload.profile, "internal-soak");
  assert.match(payload.message, /npm run test:live:corpus:large-apps exited with 1/);
  assert.match(payload.stdoutTail, /soak stdout/);
  assert.match(payload.stderrTail, /soak stderr/);
  assert.deepEqual(calls, [
    "npm:run release:check:internal",
    "npm:run test:live:corpus:large-apps",
  ]);
});

test("internal soak gate runs internal profile and large-app corpus in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-internal-soak-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "internal soak $2"
exit 0
`,
  );

  const result = await runGate({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "npm:run release:check:internal",
    "npm:run test:live:corpus:large-apps",
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.equal(payload.profile, "internal-soak");
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runGate(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/internal-soak-check.mjs"], {
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
