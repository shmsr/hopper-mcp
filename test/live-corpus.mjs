import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

test("live corpus dry-run resolves binaries and app bundles", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-corpus-"));
  try {
    const appBundle = join(tempDir, "Fixture.app");
    const executable = join(appBundle, "Contents", "MacOS", "Fixture");
    await mkdir(join(appBundle, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(appBundle, "Contents", "Info.plist"), plist("Fixture"));
    await writeFile(executable, "#!/bin/sh\nexit 0\n");

    const manifest = join(tempDir, "manifest.json");
    await writeFile(manifest, JSON.stringify({
      targets: [
        { id: "echo", path: "/bin/echo" },
        { id: "fixture-app", app_bundle: appBundle },
        { id: "optional-missing", path: join(tempDir, "missing"), optional: true },
      ],
    }));

    const result = await run("node", ["scripts/live-corpus.mjs", "--dry-run", "--manifest", manifest]);
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);

    assert.equal(report.ok, true);
    assert.equal(report.dryRun, true);
    assert.equal(report.summary.ready, 2);
    assert.equal(report.summary.skipped, 1);
    assert.equal(report.targets.find((target) => target.id === "echo").status, "ready");
    assert.equal(report.targets.find((target) => target.id === "fixture-app").executablePath, executable);
    assert.equal(report.targets.find((target) => target.id === "optional-missing").status, "skipped");
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("live corpus dry-run resolves wrapper app bundles that contain a nested executable bundle", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-corpus-wrapper-app-"));
  try {
    const wrapperBundle = join(tempDir, "Wrapper.app");
    const nestedBundle = join(wrapperBundle, "Contents", "Developer", "Applications", "Nested.app");
    const executable = join(nestedBundle, "Contents", "MacOS", "Nested");
    await mkdir(join(nestedBundle, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(nestedBundle, "Contents", "Info.plist"), plist("Nested"));
    await writeFile(executable, "#!/bin/sh\nexit 0\n");

    const manifest = join(tempDir, "manifest.json");
    await writeFile(manifest, JSON.stringify({
      targets: [
        { id: "wrapper-app", app_bundle: wrapperBundle },
      ],
    }));

    const result = await run("node", ["scripts/live-corpus.mjs", "--dry-run", "--manifest", manifest]);
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);

    assert.equal(report.ok, true);
    assert.equal(report.summary.ready, 1);
    assert.equal(report.targets.find((target) => target.id === "wrapper-app").executablePath, executable);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("live corpus report validation fails explicit performance and content budgets", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-corpus-report-"));
  try {
    const reportPath = join(tempDir, "report.json");
    await writeFile(reportPath, JSON.stringify({
      dryRun: false,
      targets: [
        {
          id: "slow-empty",
          status: "passed",
          elapsedMs: 1500,
          functionCount: 0,
          stringCount: 0,
          min_functions: 1,
          max_elapsed_ms: 1000,
        },
      ],
    }));

    const result = await run("node", ["scripts/live-corpus.mjs", "--validate-report", reportPath]);
    assert.notEqual(result.code, 0);
    const report = JSON.parse(result.stdout);
    const target = report.targets.find((item) => item.id === "slow-empty");
    assert.equal(report.ok, false);
    assert.equal(target.status, "failed");
    assert.match(target.assertions.join("\n"), /expected at least 1 function/);
    assert.match(target.assertions.join("\n"), /exceeded max_elapsed_ms 1000/);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("live corpus can write a JSON report artifact", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-corpus-artifact-"));
  try {
    const manifest = join(tempDir, "manifest.json");
    const reportPath = join(tempDir, "reports", "corpus.json");
    await writeFile(manifest, JSON.stringify({
      targets: [
        { id: "echo", path: "/bin/echo" },
      ],
    }));

    const result = await run("node", [
      "scripts/live-corpus.mjs",
      "--dry-run",
      "--manifest",
      manifest,
      "--report",
      reportPath,
    ]);
    assert.equal(result.code, 0, result.stderr);

    const stdoutReport = JSON.parse(result.stdout);
    const fileReport = JSON.parse(await readFile(reportPath, "utf8"));
    assert.deepEqual(fileReport, stdoutReport);
    assert.equal(fileReport.summary.ready, 1);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("live corpus runner escalates timed-out child cleanup", async () => {
  const script = await readFile("scripts/live-corpus.mjs", "utf8");

  assert.match(script, /async function terminateChild/);
  assert.match(script, /SIGTERM/);
  assert.match(script, /SIGKILL/);
});

test("live corpus surfaces MCP tool-level errors instead of JSON parse noise", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-corpus-tool-error-"));
  const realBin = join(process.cwd(), "bin", "hopper-mcp");
  const backupBin = join(tempDir, "hopper-mcp.real");
  try {
    await rename(realBin, backupBin);
    await writeFile(realBin, `#!/bin/sh
printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Live Hopper ingest failed: simulated tool failure"}],"isError":true}}'
`);
    await chmod(realBin, 0o755);

    const manifest = join(tempDir, "manifest.json");
    await writeFile(manifest, JSON.stringify({
      targets: [
        { id: "fixture", path: "/bin/echo" },
      ],
    }));

    const result = await run("node", ["scripts/live-corpus.mjs", "--manifest", manifest]);
    assert.notEqual(result.code, 0);
    const report = JSON.parse(result.stdout);
    const target = report.targets.find((item) => item.id === "fixture");
    assert.equal(report.ok, false);
    assert.equal(target.status, "failed");
    assert.match(target.error, /Live Hopper ingest failed: simulated tool failure/);
    assert.doesNotMatch(target.error, /Unexpected token/);
  } finally {
    await rm(realBin, { force: true });
    await mkdir(dirname(realBin), { recursive: true });
    await rename(backupBin, realBin);
  }
});

function plist(executable) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>${executable}</string>
</dict>
</plist>
`;
}

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
