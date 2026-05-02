import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("public release gate reports a structured doctor failure without running npm", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-public-release-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "public doctor stdout"
echo "public doctor stderr" >&2
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

  const result = await runPublicReleaseCheck({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = await readFile(callsFile, "utf8");

  assert.equal(result.code, 1);
  assert.equal(payload.ok, false);
  assert.equal(payload.phase, "doctor");
  assert.match(payload.message, /cargo run -p hopper-mcpd -- doctor --json --require-distribution-identity --require-notary-credentials --require-clean-git-tree exited with 1/);
  assert.match(payload.stdoutTail, /public doctor stdout/);
  assert.match(payload.stderrTail, /public doctor stderr/);
  assert.match(calls, /^cargo:run -p hopper-mcpd -- doctor --json --require-distribution-identity --require-notary-credentials --require-clean-git-tree\n$/);
  assert.doesNotMatch(calls, /^npm:/m);
  assert.match(result.stderr, /public doctor stdout/);
  assert.match(result.stderr, /public doctor stderr/);
});

test("public release gate runs doctor, distribution, and notarize in order", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-public-release-"));
  const binDir = join(tempDir, "bin");
  const callsFile = join(tempDir, "calls.log");
  await mkdir(binDir, { recursive: true });
  await writeFile(callsFile, "");
  await writeExecutable(
    join(binDir, "cargo"),
    `#!/bin/sh
echo "cargo:$*" >> "${callsFile}"
echo "public doctor ok"
exit 0
`,
  );
  await writeExecutable(
    join(binDir, "npm"),
    `#!/bin/sh
echo "npm:$*" >> "${callsFile}"
echo "public npm $2"
exit 0
`,
  );

  const result = await runPublicReleaseCheck({ PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` });
  const payload = JSON.parse(result.stdout);
  const calls = (await readFile(callsFile, "utf8")).trim().split("\n");

  assert.equal(result.code, 0);
  assert.deepEqual(calls, [
    "cargo:run -p hopper-mcpd -- doctor --json --require-distribution-identity --require-notary-credentials --require-clean-git-tree",
    "npm:run release:check:distribution",
    `npm:run package:notarize -- ${payload.archive}`,
  ]);
  assert.equal(payload.ok, true);
  assert.equal(payload.phase, "complete");
  assert.equal(
    payload.archive,
    join(repoRoot, "dist", `hopper-mcp-0.1.0-${process.platform}-${process.arch}.tar.gz`),
  );
  assert.match(result.stderr, /public doctor ok/);
  assert.match(result.stderr, /public npm release:check:distribution/);
  assert.match(result.stderr, /public npm package:notarize/);
});

async function writeExecutable(path, contents) {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function runPublicReleaseCheck(env = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["scripts/public-release-check.mjs"], {
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
      resolvePromise({
        code,
        stdout,
        stderr,
      });
    });
  });
}
