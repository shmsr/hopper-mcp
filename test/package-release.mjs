import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("release packaging dry-run reports the runtime bundle layout", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  try {
    const result = await run("node", [
      "scripts/package-release.mjs",
      "--dry-run",
      "--out-dir",
      outDir,
    ]);
    assert.equal(result.code, 0, result.stderr);

    const manifest = JSON.parse(result.stdout);
    assert.equal(manifest.dryRun, true);
    assert.match(manifest.archive, /hopper-mcp-0\.1\.0-/);
    assert.match(manifest.sha256File, /hopper-mcp-0\.1\.0-.*\.tar\.gz\.sha256$/);
    assert.ok(manifest.files.includes("bin/hopper-mcp"));
    assert.ok(manifest.files.includes("data/.gitkeep"));
    assert.ok(manifest.files.includes("target/release/hopper-mcpd"));
    assert.ok(manifest.files.includes("target/release/hopper-agent"));
    assert.ok(manifest.files.includes("target/release/HopperMCPAgent.hopperTool/Contents/Info.plist"));
    assert.ok(manifest.files.includes("target/release/HopperMCPAgent.hopperTool/Contents/MacOS/HopperMCPAgent"));
    assert.ok(manifest.files.includes("target/release/HopperMCPAgent.hopperTool/Contents/_CodeSignature/CodeResources"));
    assert.ok(manifest.files.includes("src/live-bridge-cli.js"));
    assert.ok(manifest.files.includes("src/hopper-live.js"));
    assert.ok(manifest.files.includes("scripts/live-corpus.mjs"));
    assert.ok(manifest.files.includes("corpus/live-smoke.json"));
    assert.ok(manifest.files.includes("package-lock.json"));
    assert.ok(manifest.files.includes("release-manifest.json"));
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("release packaging reports invalid arguments as structured CLI errors", async () => {
  const result = await run("node", [
    "scripts/package-release.mjs",
    "--definitely-not-a-real-flag",
  ]);
  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.ok, false);
  assert.equal(payload.code, "invalid_arguments");
  assert.match(payload.message, /unknown argument/i);
});

test("release packaging refuses implicit ad-hoc signing for distribution builds", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  try {
    const result = await run("node", [
      "scripts/package-release.mjs",
      "--out-dir",
      outDir,
    ]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.match(payload.message, /explicit signing identity/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("release packaging rejects explicit non-Developer-ID identities for distribution builds", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const binDir = await mkdtemp(join(tmpdir(), "hopper-mcp-fake-security-"));
  try {
    const security = join(binDir, "security");
    await writeFile(security, `#!/bin/sh
printf '  1) ABCDEF1234567890 "Apple Development: Example Dev (TEAM1234)"\\n'
`, "utf8");
    await chmod(security, 0o755);

    const result = await run("node", [
      "scripts/package-release.mjs",
      "--out-dir",
      outDir,
    ], {
      ...process.env,
      HOPPER_MCP_CODESIGN_IDENTITY: "Apple Development: Example Dev (TEAM1234)",
      HOPPER_MCP_SECURITY: security,
    });
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.code, "release_signing_mode_required");
    assert.match(payload.message, /Developer ID Application/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(binDir, { recursive: true, force: true });
  }
});

test("release packaging requires git provenance before building even in ad-hoc mode", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const binDir = await mkdtemp(join(tmpdir(), "hopper-mcp-fake-git-"));
  try {
    const fakeGit = join(binDir, "git");
    await writeFile(fakeGit, "#!/bin/sh\nexit 1\n", "utf8");
    await chmod(fakeGit, 0o755);

    const result = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ], {
      ...process.env,
      HOPPER_MCP_GIT: fakeGit,
    });
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.code, "release_provenance_unavailable");
    assert.match(payload.message, /git checkout/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(binDir, { recursive: true, force: true });
  }
});

test("release packaging requires a clean git worktree for signed distribution builds", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const binDir = await mkdtemp(join(tmpdir(), "hopper-mcp-fake-git-"));
  try {
    const fakeGit = join(binDir, "git");
    await writeFile(fakeGit, `#!/bin/sh
if [ "$1" = "rev-parse" ] && [ "$2" = "HEAD" ]; then
  printf '0123456789abcdef0123456789abcdef01234567\\n'
  exit 0
fi
if [ "$1" = "status" ] && [ "$2" = "--porcelain" ]; then
  printf ' M README.md\\n'
  exit 0
fi
exit 1
`, "utf8");
    await chmod(fakeGit, 0o755);

    const result = await run("node", [
      "scripts/package-release.mjs",
      "--out-dir",
      outDir,
    ], {
      ...process.env,
      HOPPER_MCP_CODESIGN_IDENTITY: "Developer ID Application: Example Corp (TEAMID1234)",
      HOPPER_MCP_GIT: fakeGit,
    });
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.code, "release_git_tree_dirty");
    assert.match(payload.message, /clean git worktree/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(binDir, { recursive: true, force: true });
  }
});

test("release packaging writes a sha256 checksum for the archive", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  try {
    const result = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(result.code, 0, result.stderr);

    const manifest = JSON.parse(result.stdout);
    const checksum = await readFile(manifest.sha256File, "utf8");
    assert.match(checksum, /^[a-f0-9]{64}  hopper-mcp-0\.1\.0-.*\.tar\.gz\n$/);
    assert.equal(manifest.sha256, checksum.slice(0, 64));
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("release packaging is reproducible in ad-hoc mode", async () => {
  const outDirA = await mkdtemp(join(tmpdir(), "hopper-mcp-package-a-"));
  const outDirB = await mkdtemp(join(tmpdir(), "hopper-mcp-package-b-"));
  try {
    const first = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDirA,
    ]);
    assert.equal(first.code, 0, first.stderr);
    const firstManifest = JSON.parse(first.stdout);

    const second = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDirB,
    ]);
    assert.equal(second.code, 0, second.stderr);
    const secondManifest = JSON.parse(second.stdout);

    assert.equal(firstManifest.sha256, secondManifest.sha256);
  } finally {
    await rm(outDirA, { recursive: true, force: true });
    await rm(outDirB, { recursive: true, force: true });
  }
});

test("release packaging verifies an existing archive checksum", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const verified = await run("node", [
      "scripts/package-release.mjs",
      "--verify",
      manifest.archive,
    ]);
    assert.equal(verified.code, 0, verified.stderr);
    const verifiedManifest = JSON.parse(verified.stdout);
    assert.equal(verifiedManifest.ok, true);
    assert.equal(verifiedManifest.archive, manifest.archive);
    assert.equal(verifiedManifest.sha256, manifest.sha256);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("release packaging smoke-tests an extracted archive", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  try {
    const gitHead = await run("git", ["rev-parse", "HEAD"]);
    assert.equal(gitHead.code, 0, gitHead.stderr);
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const smoked = await run("node", [
      "scripts/package-release.mjs",
      "--smoke",
      manifest.archive,
    ]);
    assert.equal(smoked.code, 0, smoked.stderr);
    const smokeManifest = JSON.parse(smoked.stdout);
    assert.equal(smokeManifest.ok, true);
    assert.equal(smokeManifest.verify.ok, true);
    assert.ok(smokeManifest.packageRoot.endsWith(".tar.gz") === false);
    assert.equal(smokeManifest.releaseManifest.schemaVersion, 3);
    assert.equal(smokeManifest.releaseManifest.source.vcs, "git");
    assert.equal(smokeManifest.releaseManifest.source.commit, gitHead.stdout.trim());
    assert.match(smokeManifest.releaseManifest.source.treeState, /^(clean|dirty)$/);
    assert.equal(smokeManifest.releaseManifest.build.nodeVersion, process.version);
    assert.match(smokeManifest.releaseManifest.build.cargoVersion, /^cargo /);
    assert.equal(smokeManifest.releaseManifest.build.signing.mode, "ad-hoc");
    assert.equal(smokeManifest.releaseManifest.build.signing.identity, null);
    assert.deepEqual(
      smokeManifest.checks.map((check) => check.name),
      ["checksum", "extract", "manifest", "bridge", "agent", "codesign", "plugin_linkage", "doctor", "initialize"],
    );
    assert.match(smokeManifest.checks.find((check) => check.name === "agent").message, /procedure/);
    assert.match(smokeManifest.checks.find((check) => check.name === "plugin_linkage").message, /Foundation-only|framework/i);
    assert.match(smokeManifest.releaseManifest.files["target/release/hopper-mcpd"].sha256, /^[a-f0-9]{64}$/);
    assert.match(smokeManifest.releaseManifest.files["target/release/hopper-agent"].sha256, /^[a-f0-9]{64}$/);
    assert.match(smokeManifest.releaseManifest.files["target/release/HopperMCPAgent.hopperTool/Contents/MacOS/HopperMCPAgent"].sha256, /^[a-f0-9]{64}$/);
    assert.match(smokeManifest.releaseManifest.files["target/release/HopperMCPAgent.hopperTool/Contents/_CodeSignature/CodeResources"].sha256, /^[a-f0-9]{64}$/);
    assert.match(smokeManifest.releaseManifest.files["src/live-bridge-cli.js"].sha256, /^[a-f0-9]{64}$/);
    assert.ok(smokeManifest.checks.every((check) => check.status === "pass"));
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("release packaging smoke rejects archives whose manifest omits build provenance", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const extractDir = await mkdtemp(join(tmpdir(), "hopper-mcp-tamper-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const extracted = await run("tar", ["-xzf", manifest.archive, "-C", extractDir]);
    assert.equal(extracted.code, 0, extracted.stderr);
    const manifestPath = join(extractDir, manifest.packageName, "release-manifest.json");
    const releaseManifest = JSON.parse(await readFile(manifestPath, "utf8"));
    delete releaseManifest.build;
    await writeFile(manifestPath, `${JSON.stringify(releaseManifest, null, 2)}\n`);

    const tamperedArchive = join(outDir, "tampered-no-build.tar.gz");
    const archived = await run("tar", ["-czf", tamperedArchive, "-C", extractDir, manifest.packageName]);
    assert.equal(archived.code, 0, archived.stderr);
    const tamperedSha256 = createHash("sha256")
      .update(await readFile(tamperedArchive))
      .digest("hex");
    await writeFile(`${tamperedArchive}.sha256`, `${tamperedSha256}  tampered-no-build.tar.gz\n`);

    const smoked = await run("node", [
      "scripts/package-release.mjs",
      "--smoke",
      tamperedArchive,
    ]);
    assert.equal(smoked.code, 1);
    const smokeManifest = JSON.parse(smoked.stdout);
    assert.equal(smokeManifest.ok, false);
    assert.equal(smokeManifest.checks.find((check) => check.name === "manifest").status, "fail");
    assert.match(smokeManifest.checks.find((check) => check.name === "manifest").message, /build provenance/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(extractDir, { recursive: true, force: true });
  }
});

test("release packaging smoke rejects archives whose manifest omits source provenance", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const extractDir = await mkdtemp(join(tmpdir(), "hopper-mcp-tamper-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const extracted = await run("tar", ["-xzf", manifest.archive, "-C", extractDir]);
    assert.equal(extracted.code, 0, extracted.stderr);
    const manifestPath = join(extractDir, manifest.packageName, "release-manifest.json");
    const releaseManifest = JSON.parse(await readFile(manifestPath, "utf8"));
    delete releaseManifest.source;
    await writeFile(manifestPath, `${JSON.stringify(releaseManifest, null, 2)}\n`);

    const tamperedArchive = join(outDir, "tampered-no-source.tar.gz");
    const archived = await run("tar", ["-czf", tamperedArchive, "-C", extractDir, manifest.packageName]);
    assert.equal(archived.code, 0, archived.stderr);
    const tamperedSha256 = createHash("sha256")
      .update(await readFile(tamperedArchive))
      .digest("hex");
    await writeFile(`${tamperedArchive}.sha256`, `${tamperedSha256}  tampered-no-source.tar.gz\n`);

    const smoked = await run("node", [
      "scripts/package-release.mjs",
      "--smoke",
      tamperedArchive,
    ]);
    assert.equal(smoked.code, 1);
    const smokeManifest = JSON.parse(smoked.stdout);
    assert.equal(smokeManifest.ok, false);
    assert.equal(smokeManifest.checks.find((check) => check.name === "manifest").status, "fail");
    assert.match(smokeManifest.checks.find((check) => check.name === "manifest").message, /source provenance/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(extractDir, { recursive: true, force: true });
  }
});

test("release packaging smoke rejects archive files missing from the manifest", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const extractDir = await mkdtemp(join(tmpdir(), "hopper-mcp-tamper-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const extracted = await run("tar", ["-xzf", manifest.archive, "-C", extractDir]);
    assert.equal(extracted.code, 0, extracted.stderr);
    await writeFile(join(extractDir, manifest.packageName, "unexpected-payload.txt"), "not in release-manifest\n");

    const tamperedArchive = join(outDir, "tampered.tar.gz");
    const archived = await run("tar", ["-czf", tamperedArchive, "-C", extractDir, manifest.packageName]);
    assert.equal(archived.code, 0, archived.stderr);
    const tamperedSha256 = createHash("sha256")
      .update(await readFile(tamperedArchive))
      .digest("hex");
    await writeFile(`${tamperedArchive}.sha256`, `${tamperedSha256}  tampered.tar.gz\n`);

    const smoked = await run("node", [
      "scripts/package-release.mjs",
      "--smoke",
      tamperedArchive,
    ]);
    assert.equal(smoked.code, 1);
    const smokeManifest = JSON.parse(smoked.stdout);
    assert.equal(smokeManifest.ok, false);
    assert.equal(smokeManifest.checks.find((check) => check.name === "manifest").status, "fail");
    assert.match(smokeManifest.checks.find((check) => check.name === "manifest").message, /unexpected-payload/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(extractDir, { recursive: true, force: true });
  }
});

test("release packaging smoke rejects unexpected top-level archive entries", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const extractDir = await mkdtemp(join(tmpdir(), "hopper-mcp-tamper-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const extracted = await run("tar", ["-xzf", manifest.archive, "-C", extractDir]);
    assert.equal(extracted.code, 0, extracted.stderr);
    await writeFile(join(extractDir, "top-level-extra.txt"), "outside package root\n");

    const tamperedArchive = join(outDir, "tampered-top-level.tar.gz");
    const archived = await run("tar", [
      "-czf",
      tamperedArchive,
      "-C",
      extractDir,
      manifest.packageName,
      "top-level-extra.txt",
    ]);
    assert.equal(archived.code, 0, archived.stderr);
    const tamperedSha256 = createHash("sha256")
      .update(await readFile(tamperedArchive))
      .digest("hex");
    await writeFile(`${tamperedArchive}.sha256`, `${tamperedSha256}  tampered-top-level.tar.gz\n`);

    const smoked = await run("node", [
      "scripts/package-release.mjs",
      "--smoke",
      tamperedArchive,
    ]);
    assert.equal(smoked.code, 1);
    const smokeManifest = JSON.parse(smoked.stdout);
    assert.equal(smokeManifest.ok, false);
    assert.equal(smokeManifest.checks.find((check) => check.name === "extract").status, "fail");
    assert.match(smokeManifest.checks.find((check) => check.name === "extract").message, /top-level-extra/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(extractDir, { recursive: true, force: true });
  }
});

test("release packaging smoke rejects symlink archive entries", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const extractDir = await mkdtemp(join(tmpdir(), "hopper-mcp-tamper-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const extracted = await run("tar", ["-xzf", manifest.archive, "-C", extractDir]);
    assert.equal(extracted.code, 0, extracted.stderr);
    await symlink("README.md", join(extractDir, manifest.packageName, "unexpected-link"));

    const tamperedArchive = join(outDir, "tampered-symlink.tar.gz");
    const archived = await run("tar", ["-czf", tamperedArchive, "-C", extractDir, manifest.packageName]);
    assert.equal(archived.code, 0, archived.stderr);
    const tamperedSha256 = createHash("sha256")
      .update(await readFile(tamperedArchive))
      .digest("hex");
    await writeFile(`${tamperedArchive}.sha256`, `${tamperedSha256}  tampered-symlink.tar.gz\n`);

    const smoked = await run("node", [
      "scripts/package-release.mjs",
      "--smoke",
      tamperedArchive,
    ]);
    assert.equal(smoked.code, 1);
    const smokeManifest = JSON.parse(smoked.stdout);
    assert.equal(smokeManifest.ok, false);
    assert.equal(smokeManifest.checks.find((check) => check.name === "extract").status, "fail");
    assert.match(smokeManifest.checks.find((check) => check.name === "extract").message, /symlink|unsupported archive member/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(extractDir, { recursive: true, force: true });
  }
});

test("release packaging check builds, verifies, and smokes a temporary archive", async () => {
  const result = await run("node", [
    "scripts/package-release.mjs",
    "--check",
  ]);
  assert.equal(result.code, 0, result.stderr);
  const checked = JSON.parse(result.stdout);
  assert.equal(checked.ok, true);
  assert.equal(checked.package.dryRun, false);
  assert.match(checked.package.archive, /hopper-mcp-0\.1\.0-/);
  assert.equal(checked.verify.ok, true);
  assert.equal(checked.smoke.ok, true);
  assert.equal(checked.smoke.releaseManifest.schemaVersion, 3);
  assert.equal(checked.smoke.releaseManifest.source.vcs, "git");
  assert.match(checked.smoke.releaseManifest.source.commit, /^[0-9a-f]{40}$/);
  assert.match(checked.smoke.releaseManifest.source.treeState, /^(clean|dirty)$/);
  assert.equal(checked.smoke.releaseManifest.build.nodeVersion, process.version);
  assert.match(checked.smoke.releaseManifest.build.cargoVersion, /^cargo /);
  assert.equal(checked.smoke.releaseManifest.build.signing.mode, "ad-hoc");
  assert.equal(checked.smoke.releaseManifest.build.signing.identity, null);
  assert.deepEqual(
    checked.smoke.checks.map((check) => check.name),
    ["checksum", "extract", "manifest", "bridge", "agent", "codesign", "plugin_linkage", "doctor", "initialize"],
  );
  assert.match(checked.smoke.checks.find((check) => check.name === "agent").message, /procedure/);
  assert.match(checked.smoke.checks.find((check) => check.name === "plugin_linkage").message, /Foundation-only|framework/i);
  assert.match(checked.smoke.releaseManifest.files["target/release/hopper-mcpd"].sha256, /^[a-f0-9]{64}$/);
  assert.match(checked.smoke.releaseManifest.files["target/release/hopper-agent"].sha256, /^[a-f0-9]{64}$/);
  assert.match(checked.smoke.releaseManifest.files["target/release/HopperMCPAgent.hopperTool/Contents/MacOS/HopperMCPAgent"].sha256, /^[a-f0-9]{64}$/);
});

test("release notarization is explicit and refuses to run without credentials", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  try {
    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const notarized = await run("node", [
      "scripts/package-release.mjs",
      "--notarize",
      manifest.archive,
    ], {
      ...process.env,
      HOPPER_MCP_NOTARY_PROFILE: "",
      APPLE_ID: "",
      APPLE_TEAM_ID: "",
      APPLE_PASSWORD: "",
    });
    assert.equal(notarized.code, 1);
    const result = JSON.parse(notarized.stdout);
    assert.equal(result.ok, false);
    assert.equal(result.code, "missing_notary_credentials");
    assert.equal(result.smoke.ok, true);
    assert.match(result.message, /HOPPER_MCP_NOTARY_PROFILE/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("release notarization refuses ad-hoc signed archives before notarytool", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const binDir = await mkdtemp(join(tmpdir(), "hopper-mcp-fake-xcrun-"));
  try {
    const xcrun = join(binDir, "xcrun");
    await writeFile(xcrun, `#!/bin/sh
printf '{"id":"unexpected-submission","status":"Accepted"}\\n'
exit 0
`);
    await chmod(xcrun, 0o755);

    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const notarized = await run("node", [
      "scripts/package-release.mjs",
      "--notarize",
      manifest.archive,
    ], {
      ...process.env,
      PATH: `${binDir}:${process.env.PATH}`,
      HOPPER_MCP_NOTARY_PROFILE: "ci-profile",
      APPLE_ID: "",
      APPLE_TEAM_ID: "",
      APPLE_PASSWORD: "",
    });
    assert.equal(notarized.code, 1);
    const result = JSON.parse(notarized.stdout);
    assert.equal(result.ok, false);
    assert.equal(result.code, "developer_id_signature_required");
    assert.match(result.message, /Developer ID Application/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(binDir, { recursive: true, force: true });
  }
});

test("release notarization submits a zip payload with a keychain profile", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "hopper-mcp-package-"));
  const binDir = await mkdtemp(join(tmpdir(), "hopper-mcp-fake-xcrun-"));
  const argsFile = join(binDir, "args.txt");
  try {
    const xcrun = join(binDir, "xcrun");
    const codesign = join(binDir, "codesign");
    await writeFile(xcrun, `#!/bin/sh
printf "%s\\n" "$*" > "$NOTARY_ARGS_FILE"
printf '{"id":"fake-submission","status":"Accepted"}\\n'
exit 0
`);
    await chmod(xcrun, 0o755);
    await writeFile(codesign, `#!/bin/sh
if [ "$1" = "-dv" ]; then
  printf 'Authority=Developer ID Application: Example Corp (TEAMID1234)\\nTeamIdentifier=TEAMID1234\\n' >&2
  exit 0
fi
exec /usr/bin/codesign "$@"
`);
    await chmod(codesign, 0o755);

    const packaged = await run("node", [
      "scripts/package-release.mjs",
      "--ad-hoc",
      "--out-dir",
      outDir,
    ]);
    assert.equal(packaged.code, 0, packaged.stderr);
    const manifest = JSON.parse(packaged.stdout);

    const notarized = await run("node", [
      "scripts/package-release.mjs",
      "--notarize",
      manifest.archive,
    ], {
      ...process.env,
      PATH: `${binDir}:${process.env.PATH}`,
      NOTARY_ARGS_FILE: argsFile,
      HOPPER_MCP_NOTARY_PROFILE: "ci-profile",
      APPLE_ID: "",
      APPLE_TEAM_ID: "",
      APPLE_PASSWORD: "",
    });
    assert.equal(notarized.code, 0, notarized.stderr);
    const result = JSON.parse(notarized.stdout);
    assert.equal(result.ok, true);
    assert.equal(result.code, "notarized");
    assert.equal(result.notarytool.id, "fake-submission");
    assert.match(await readFile(argsFile, "utf8"), /notarytool submit .*notary\.zip --wait --output-format json --keychain-profile ci-profile/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
    await rm(binDir, { recursive: true, force: true });
  }
});

function run(command, args, env = process.env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env,
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
