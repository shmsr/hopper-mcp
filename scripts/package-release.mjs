#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import net from "node:net";
import { chmod, cp, lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { writeFile } from "node:fs/promises";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const RELEASE_MANIFEST = "release-manifest.json";
const RELEASE_EPOCH_MS = 0;
await main();

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.verify) {
      const verified = await verifyArchive(resolve(repoRoot, options.verify));
      process.stdout.write(`${JSON.stringify(verified, null, 2)}\n`);
      process.exitCode = verified.ok ? 0 : 1;
      return;
    }
    if (options.smoke) {
      const smoked = await smokeArchive(resolve(repoRoot, options.smoke));
      process.stdout.write(`${JSON.stringify(smoked, null, 2)}\n`);
      process.exitCode = smoked.ok ? 0 : 1;
      return;
    }
    if (options.notarize) {
      const notarized = await notarizeArchive(resolve(repoRoot, options.notarize));
      process.stdout.write(`${JSON.stringify(notarized, null, 2)}\n`);
      process.exitCode = notarized.ok ? 0 : 1;
      return;
    }
    if (options.check) {
      const checked = await checkReleasePackage();
      process.stdout.write(`${JSON.stringify(checked, null, 2)}\n`);
      process.exitCode = checked.ok ? 0 : 1;
      return;
    }

    const manifest = await createReleasePackage({
      dryRun: options.dryRun,
      outDir: options.outDir,
      adHoc: options.adHoc,
    });
    process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
  } catch (error) {
    writeCliError(error);
    process.exitCode = 1;
  }
}

async function createReleasePackage({ dryRun, outDir, adHoc = false }) {
  const pkg = JSON.parse(await readFile(join(repoRoot, "package.json"), "utf8"));
  const packageName = `${pkg.name}-${pkg.version}-${process.platform}-${process.arch}`;
  const resolvedOutDir = resolve(repoRoot, outDir);
  const archive = join(resolvedOutDir, `${packageName}.tar.gz`);
  const sha256File = `${archive}.sha256`;
  const stagedRoot = join(resolvedOutDir, "stage", packageName);
  let files = await releaseFiles();
  let sha256 = null;

  if (!dryRun) {
    const signingIdentity = await requireReleaseSigningMode({ adHoc });
    const source = await releaseSourceProvenance();
    const build = await releaseBuildProvenance(signingIdentity);
    if (!adHoc && source.treeState !== "clean") {
      throw cliError(
        "release_git_tree_dirty",
        "signed distribution packaging requires a clean git worktree; commit or stash changes before building a release artifact",
      );
    }
    await run("cargo", ["build", "--release", "-p", "hopper-mcpd"]);
    await run("make", ["-s", "-C", "agents/hopper-agent"]);
    await runQuiet("node", ["scripts/fetch-hopper-sdk.mjs"]);
    await run("make", ["-s", "-C", "agents/hopper-tool-plugin"]);
    await signReleaseBinary(join(repoRoot, "target", "release", "HopperMCPAgent.hopperTool"), signingIdentity);
    files = await releaseFiles();
    await rm(stagedRoot, { recursive: true, force: true });
    await mkdir(stagedRoot, { recursive: true });
    const sourceFiles = files.filter((file) => file !== RELEASE_MANIFEST);
    for (const file of sourceFiles) {
      await copyReleaseFile(file, stagedRoot);
    }
    await chmod(join(stagedRoot, "bin", "hopper-mcp"), 0o755);
    const daemonPath = join(stagedRoot, "target", "release", "hopper-mcpd");
    await chmod(daemonPath, 0o755);
    const agentPath = join(stagedRoot, "target", "release", "hopper-agent");
    await chmod(agentPath, 0o755);
    const pluginPath = join(stagedRoot, "target", "release", "HopperMCPAgent.hopperTool");
    await signReleaseBinary(daemonPath, signingIdentity);
    await signReleaseBinary(agentPath, signingIdentity);
    await signReleaseBinary(pluginPath, signingIdentity);
    await writeReleaseManifest({ packageName, files: sourceFiles, stagedRoot, source, build });
    await mkdir(resolvedOutDir, { recursive: true });
    await normalizeReleaseTree(stagedRoot);
    await writeDeterministicArchive({
      stageRoot: join(resolvedOutDir, "stage"),
      packageName,
      archive,
    });
    sha256 = await sha256FileHex(archive);
    await writeFile(sha256File, `${sha256}  ${basename(archive)}\n`);
  }

  return {
    dryRun,
    packageName,
    archive,
    sha256,
    sha256File,
    files,
  };
}

async function checkReleasePackage() {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-release-check-"));
  try {
    const packaged = await createReleasePackage({ dryRun: false, outDir: tempDir, adHoc: true });
    const verified = await verifyArchive(packaged.archive);
    const smoked = verified.ok
      ? await smokeArchive(packaged.archive)
      : null;
    return {
      ok: verified.ok && smoked?.ok === true,
      package: packaged,
      verify: verified,
      smoke: smoked,
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function releaseFiles() {
  const files = [
    "README.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "package.json",
    "Cargo.toml",
    "Cargo.lock",
    "bin/hopper-mcp",
    "data/.gitkeep",
    RELEASE_MANIFEST,
    "target/release/hopper-mcpd",
    "target/release/hopper-agent",
    "target/release/HopperMCPAgent.hopperTool/Contents/Info.plist",
    "target/release/HopperMCPAgent.hopperTool/Contents/MacOS/HopperMCPAgent",
    "target/release/HopperMCPAgent.hopperTool/Contents/_CodeSignature/CodeResources",
  ];
  if (await exists(join(repoRoot, "package-lock.json"))) {
    files.push("package-lock.json");
  }
  for (const file of await jsFiles("src")) {
    files.push(file);
  }
  for (const file of await jsFiles("scripts")) {
    files.push(file);
  }
  for (const file of await jsonFiles("corpus")) {
    files.push(file);
  }
  return files.sort();
}

async function jsFiles(dir) {
  const root = join(repoRoot, dir);
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const rel = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await jsFiles(rel));
    } else if (entry.isFile() && (entry.name.endsWith(".js") || entry.name.endsWith(".mjs"))) {
      files.push(rel);
    }
  }
  return files;
}

async function jsonFiles(dir) {
  const root = join(repoRoot, dir);
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const rel = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await jsonFiles(rel));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      files.push(rel);
    }
  }
  return files;
}

async function copyReleaseFile(file, destinationRoot) {
  const source = join(repoRoot, file);
  if (file === "target/release/hopper-mcpd" && !(await exists(source))) {
    throw new Error("target/release/hopper-mcpd is missing; cargo build --release did not produce the daemon");
  }
  if (file === "target/release/hopper-agent" && !(await exists(source))) {
    throw new Error("target/release/hopper-agent is missing; make -C agents/hopper-agent did not produce the agent");
  }
  if (file.startsWith("target/release/HopperMCPAgent.hopperTool/") && !(await exists(source))) {
    throw new Error("target/release/HopperMCPAgent.hopperTool is missing; make -C agents/hopper-tool-plugin did not produce the plugin");
  }
  const destination = join(destinationRoot, file);
  await mkdir(resolve(destination, ".."), { recursive: true });
  await cp(source, destination, { recursive: true });
}

function parseArgs(args) {
  const options = {
    dryRun: false,
    outDir: "dist",
    verify: null,
    smoke: null,
    notarize: null,
    check: false,
    adHoc: false,
  };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--out-dir") {
      const value = args[i + 1];
      if (!value) throw cliError("invalid_arguments", "--out-dir requires a path");
      options.outDir = value;
      i += 1;
    } else if (arg === "--verify") {
      const value = args[i + 1];
      if (!value) throw cliError("invalid_arguments", "--verify requires an archive path");
      options.verify = value;
      i += 1;
    } else if (arg === "--smoke") {
      const value = args[i + 1];
      if (!value) throw cliError("invalid_arguments", "--smoke requires an archive path");
      options.smoke = value;
      i += 1;
    } else if (arg === "--notarize") {
      const value = args[i + 1];
      if (!value) throw cliError("invalid_arguments", "--notarize requires an archive path");
      options.notarize = value;
      i += 1;
    } else if (arg === "--check") {
      options.check = true;
    } else if (arg === "--ad-hoc") {
      options.adHoc = true;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write(`Usage: node scripts/${basename(import.meta.url)} [--dry-run] [--out-dir DIR] [--ad-hoc] [--verify ARCHIVE] [--smoke ARCHIVE] [--notarize ARCHIVE] [--check]\n`);
      process.exit(0);
    } else {
      throw cliError("invalid_arguments", `unknown argument: ${arg}`);
    }
  }
  return options;
}

async function notarizeArchive(archive) {
  const smoke = await smokeArchive(archive);
  if (!smoke.ok) {
    return {
      ok: false,
      code: "smoke_failed",
      archive,
      message: "refusing to notarize an archive that failed package smoke verification",
      smoke,
    };
  }

  const credentials = notaryCredentials();
  if (!credentials.ok) {
    return {
      ok: false,
      code: "missing_notary_credentials",
      archive,
      message: credentials.message,
      smoke,
    };
  }

  if (process.platform !== "darwin") {
    return {
      ok: false,
      code: "notarytool_unsupported_platform",
      archive,
      message: "Apple notarization requires macOS with Xcode command line tools.",
      smoke,
    };
  }

  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-notary-"));
  try {
    const extracted = await extractPackageArchive(archive, tempDir);
    if (extracted.error) {
      return {
        ok: false,
        code: "extract_failed",
        archive,
        message: extracted.error,
        smoke,
      };
    }
    const packageRoot = extracted.packageRoot;
    const distributionSignature = await verifyDistributionSignatures([
      join(packageRoot, "target", "release", "hopper-mcpd"),
      join(packageRoot, "target", "release", "hopper-agent"),
      join(packageRoot, "target", "release", "HopperMCPAgent.hopperTool"),
    ]);
    if (!distributionSignature.ok) {
      return {
        ok: false,
        code: "developer_id_signature_required",
        archive,
        message: distributionSignature.message,
        smoke,
      };
    }
    const zipPath = join(tempDir, `${basename(archive, ".tar.gz")}-notary.zip`);
    await run("ditto", ["-c", "-k", "--keepParent", packageRoot, zipPath]);
    const args = ["notarytool", "submit", zipPath, "--wait", "--output-format", "json", ...credentials.args];
    const submitted = await runCapture("xcrun", args);
    const payload = parseJson(submitted.stdout);
    return {
      ok: submitted.code === 0,
      code: submitted.code === 0 ? "notarized" : "notarytool_failed",
      archive,
      notaryZip: zipPath,
      smoke,
      notarytool: payload ?? {
        stdout: submitted.stdout,
        stderr: submitted.stderr,
      },
      message: submitted.code === 0
        ? "Apple notarization completed successfully."
        : `notarytool failed with code ${submitted.code}: ${submitted.stderr || submitted.stdout}`,
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function notaryCredentials() {
  const profile = nonEmptyEnv("HOPPER_MCP_NOTARY_PROFILE");
  if (profile) {
    return {
      ok: true,
      args: ["--keychain-profile", profile],
    };
  }

  const appleId = nonEmptyEnv("APPLE_ID");
  const teamId = nonEmptyEnv("APPLE_TEAM_ID");
  const password = nonEmptyEnv("APPLE_PASSWORD");
  if (appleId && teamId && password) {
    return {
      ok: true,
      args: ["--apple-id", appleId, "--team-id", teamId, "--password", password],
    };
  }

  return {
    ok: false,
    message: "Set HOPPER_MCP_NOTARY_PROFILE for a notarytool keychain profile, or set APPLE_ID, APPLE_TEAM_ID, and APPLE_PASSWORD.",
  };
}

function nonEmptyEnv(name) {
  const value = process.env[name];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

async function smokeArchive(archive) {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-release-smoke-"));
  const checks = [];
  let packageRoot = null;
  let verify = null;
  try {
    verify = await verifyArchive(archive);
    checks.push(check("checksum", verify.ok, verify.ok
      ? `checksum matches ${basename(`${archive}.sha256`)}`
      : `checksum mismatch: expected ${verify.expected}, got ${verify.sha256}`));
    if (!verify.ok) {
      return smokeResult(false, archive, verify, packageRoot, checks);
    }

    const extractedArchive = await extractPackageArchive(archive, tempDir);
    packageRoot = extractedArchive.packageRoot;
    if (extractedArchive.error) {
      checks.push(check("extract", false, extractedArchive.error));
      return smokeResult(false, archive, verify, packageRoot, checks);
    }
    const extracted = packageRoot
      && await exists(join(packageRoot, "bin", "hopper-mcp"))
      && await exists(join(packageRoot, "target", "release", "hopper-mcpd"))
      && await exists(join(packageRoot, "target", "release", "hopper-agent"))
      && await exists(join(packageRoot, "target", "release", "HopperMCPAgent.hopperTool", "Contents", "MacOS", "HopperMCPAgent"))
      && await exists(join(packageRoot, "src", "live-bridge-cli.js"));
    checks.push(check("extract", Boolean(extracted), extracted
      ? `archive extracted to ${packageRoot}`
      : `archive did not contain the expected runtime layout under ${tempDir}`));
    if (!extracted) {
      return smokeResult(false, archive, verify, packageRoot, checks);
    }

    const releaseManifest = await verifyReleaseManifest(packageRoot);
    checks.push(check("manifest", releaseManifest.ok, releaseManifest.message));
    if (!releaseManifest.ok) {
      return smokeResult(false, archive, verify, packageRoot, checks, releaseManifest.manifest);
    }

    const bridge = await smokePackagedBridge(packageRoot);
    checks.push(check("bridge", bridge.ok, bridge.message));
    if (!bridge.ok) {
      return smokeResult(false, archive, verify, packageRoot, checks, releaseManifest.manifest);
    }

    const agent = await smokePackagedAgent(packageRoot, tempDir);
    checks.push(check("agent", agent.ok, agent.message));
    if (!agent.ok) {
      return smokeResult(false, archive, verify, packageRoot, checks, releaseManifest.manifest);
    }

    const signed = await verifyReleaseSignatures([
      join(packageRoot, "target", "release", "hopper-mcpd"),
      join(packageRoot, "target", "release", "hopper-agent"),
      join(packageRoot, "target", "release", "HopperMCPAgent.hopperTool"),
    ]);
    checks.push(check("codesign", signed.ok, signed.message));
    if (!signed.ok) {
      return smokeResult(false, archive, verify, packageRoot, checks, releaseManifest.manifest);
    }

    const pluginLinkage = await verifyPluginLinkage(
      join(packageRoot, "target", "release", "HopperMCPAgent.hopperTool", "Contents", "MacOS", "HopperMCPAgent"),
    );
    checks.push(check("plugin_linkage", pluginLinkage.ok, pluginLinkage.message));
    if (!pluginLinkage.ok) {
      return smokeResult(false, archive, verify, packageRoot, checks, releaseManifest.manifest);
    }

    const storeDir = join(tempDir, "store");
    await mkdir(storeDir, { recursive: true });
    const env = {
      ...process.env,
      HOPPER_MCP_ROOT: packageRoot,
      HOPPER_MCP_STORE: join(storeDir, "knowledge-store.json"),
    };
    const doctor = await runCapture(join(packageRoot, "bin", "hopper-mcp"), [
      "doctor",
      "--json",
      "--store",
      join(storeDir, "doctor-store.json"),
    ], { cwd: packageRoot, env });
    const doctorOk = doctor.code === 0 && parseJson(doctor.stdout)?.ok === true;
    checks.push(check("doctor", doctorOk, doctorOk
      ? "packaged doctor completed successfully"
      : `packaged doctor failed with code ${doctor.code}: ${doctor.stderr || doctor.stdout}`));
    if (!doctorOk) {
      return smokeResult(false, archive, verify, packageRoot, checks, releaseManifest.manifest);
    }

    const initialized = await initializePackagedServer(packageRoot, env);
    checks.push(check("initialize", initialized.ok, initialized.ok
      ? "packaged MCP server completed initialize handshake"
      : initialized.message));

    return smokeResult(checks.every((item) => item.status === "pass"), archive, verify, packageRoot, checks, releaseManifest.manifest);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function extractPackageArchive(archive, tempDir) {
  const validation = await validateArchiveMembers(archive);
  if (!validation.ok) {
    return {
      packageRoot: null,
      error: validation.message,
    };
  }

  await run("tar", ["-xzf", archive, "-C", tempDir]);
  const entries = (await readdir(tempDir)).filter((entry) => entry !== "store");
  if (entries.length !== 1) {
    return {
      packageRoot: null,
      error: `archive must contain exactly one top-level package directory; found: ${entries.join(", ") || "(none)"}`,
    };
  }
  if (entries[0] !== validation.topLevel) {
    return {
      packageRoot: null,
      error: `archive top-level directory mismatch: expected ${validation.topLevel}, extracted ${entries[0]}`,
    };
  }
  const packageRoot = join(tempDir, entries[0]);
  const metadata = await stat(packageRoot).catch(() => null);
  if (!metadata?.isDirectory()) {
    return {
      packageRoot: null,
      error: `archive top-level entry is not a directory: ${entries[0]}`,
    };
  }
  return {
    packageRoot,
    error: null,
  };
}

async function validateArchiveMembers(archive) {
  const listed = await runCapture("tar", ["-tzf", archive]);
  if (listed.code !== 0) {
    return {
      ok: false,
      message: `archive member listing failed with code ${listed.code}: ${listed.stderr || listed.stdout}`,
    };
  }
  const verbose = await runCapture("tar", ["-tvzf", archive]);
  if (verbose.code !== 0) {
    return {
      ok: false,
      message: `archive member type listing failed with code ${verbose.code}: ${verbose.stderr || verbose.stdout}`,
    };
  }

  const paths = listed.stdout.split("\n").filter(Boolean).map(normalizeArchivePath);
  const typeLines = verbose.stdout.split("\n").filter(Boolean);
  if (paths.length === 0) {
    return {
      ok: false,
      message: "archive contains no members",
    };
  }

  const topLevels = new Set();
  for (const [index, path] of paths.entries()) {
    const unsafe = unsafeArchivePathReason(path);
    if (unsafe) {
      return {
        ok: false,
        message: `unsafe archive member path ${path}: ${unsafe}`,
      };
    }
    const type = typeLines[index]?.[0];
    if (type && type !== "-" && type !== "d") {
      return {
        ok: false,
        message: `unsupported archive member type '${type}' for ${path}`,
      };
    }
    topLevels.add(path.split("/")[0]);
  }

  if (topLevels.size !== 1) {
    return {
      ok: false,
      message: `archive must contain exactly one top-level package directory; found: ${[...topLevels].sort().join(", ") || "(none)"}`,
    };
  }
  return {
    ok: true,
    topLevel: [...topLevels][0],
  };
}

function normalizeArchivePath(path) {
  return path.replace(/^\.\/+/, "").replace(/\/+$/, "");
}

function unsafeArchivePathReason(path) {
  if (!path) return "empty path";
  if (path.startsWith("/")) return "absolute paths are not allowed";
  if (path.split("/").includes("..")) return "parent directory segments are not allowed";
  if (path.includes("\0")) return "NUL bytes are not allowed";
  return null;
}

function smokeResult(ok, archive, verify, packageRoot, checks, releaseManifest = null) {
  return {
    ok,
    archive,
    verify,
    packageRoot,
    checks,
    releaseManifest,
  };
}

function check(name, passed, message) {
  return {
    name,
    status: passed ? "pass" : "fail",
    message,
  };
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function sha256FileHex(path) {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

async function verifyArchive(archive) {
  const checksumPath = `${archive}.sha256`;
  const expectedLine = await readFile(checksumPath, "utf8");
  const expected = expectedLine.trim().split(/\s+/)[0];
  const actual = await sha256FileHex(archive);
  return {
    ok: expected === actual,
    archive,
    sha256File: checksumPath,
    expected,
    sha256: actual,
  };
}

async function writeReleaseManifest({ packageName, files, stagedRoot, source, build }) {
  const manifest = {
    schemaVersion: 3,
    packageName,
    platform: process.platform,
    arch: process.arch,
    source,
    build,
    files: {},
  };
  for (const file of files) {
    const path = join(stagedRoot, file);
    const metadata = await stat(path);
    manifest.files[file] = {
      bytes: metadata.size,
      sha256: await sha256FileHex(path),
    };
  }
  await writeFile(join(stagedRoot, RELEASE_MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function normalizeReleaseTree(root) {
  const metadata = await lstat(root);
  const timestamp = new Date(RELEASE_EPOCH_MS);
  if (metadata.isDirectory()) {
    const entries = await readdir(root, { withFileTypes: true });
    for (const entry of entries) {
      await normalizeReleaseTree(join(root, entry.name));
    }
  }
  await utimes(root, timestamp, timestamp);
}

async function writeDeterministicArchive({ stageRoot, packageName, archive }) {
  const tarPath = `${archive}.tmp`;
  const entries = (await collectPackageFiles(join(stageRoot, packageName)))
    .map((file) => join(packageName, file));
  await runWithEnv(
    "tar",
    [
      "-cf",
      tarPath,
      "--format",
      "ustar",
      "--uid",
      "0",
      "--gid",
      "0",
      "--uname",
      "root",
      "--gname",
      "wheel",
      "-C",
      stageRoot,
      ...entries,
    ],
    { COPYFILE_DISABLE: "1", LANG: "C", LC_ALL: "C" },
  );
  try {
    await runToFile(
      "gzip",
      ["-n", "-c", tarPath],
      archive,
      { COPYFILE_DISABLE: "1", LANG: "C", LC_ALL: "C" },
    );
  } finally {
    await rm(tarPath, { force: true }).catch(() => {});
  }
}

async function verifyReleaseManifest(packageRoot) {
  let manifest;
  try {
    manifest = JSON.parse(await readFile(join(packageRoot, RELEASE_MANIFEST), "utf8"));
  } catch (error) {
    return {
      ok: false,
      message: `release manifest could not be read: ${error.message}`,
      manifest: null,
    };
  }

  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || manifest.schemaVersion !== 3) {
    return {
      ok: false,
      message: "release manifest has an unsupported schema",
      manifest,
    };
  }
  if (!isValidReleaseSource(manifest.source)) {
    return {
      ok: false,
      message: "release manifest is missing valid source provenance",
      manifest,
    };
  }
  if (!isValidReleaseBuild(manifest.build)) {
    return {
      ok: false,
      message: "release manifest is missing valid build provenance",
      manifest,
    };
  }
  if (!manifest.files || typeof manifest.files !== "object" || Array.isArray(manifest.files)) {
    return {
      ok: false,
      message: "release manifest is missing files map",
      manifest,
    };
  }

  const root = resolve(packageRoot);
  for (const [file, expected] of Object.entries(manifest.files)) {
    const path = resolve(packageRoot, file);
    if (!(path === root || path.startsWith(`${root}${sep}`))) {
      return {
        ok: false,
        message: `release manifest contains path outside package root: ${file}`,
        manifest,
      };
    }
    const metadata = await stat(path).catch(() => null);
    if (!metadata?.isFile()) {
      return {
        ok: false,
        message: `release manifest file is missing: ${file}`,
        manifest,
      };
    }
    const actualSha256 = await sha256FileHex(path);
    if (actualSha256 !== expected?.sha256 || metadata.size !== expected?.bytes) {
      return {
        ok: false,
        message: `release manifest mismatch for ${file}`,
        manifest,
      };
    }
  }

  const expectedFiles = new Set([RELEASE_MANIFEST, ...Object.keys(manifest.files)]);
  let actualFiles;
  try {
    actualFiles = await collectPackageFiles(packageRoot);
  } catch (error) {
    return {
      ok: false,
      message: error.message,
      manifest,
    };
  }
  for (const file of actualFiles) {
    if (!expectedFiles.has(file)) {
      return {
        ok: false,
        message: `release manifest does not list file: ${file}`,
        manifest,
      };
    }
  }

  return {
    ok: true,
    message: `release manifest verified ${Object.keys(manifest.files).length} file(s) from ${manifest.source.commit.slice(0, 12)} (${manifest.source.treeState}), signed ${manifest.build.signing.mode}`,
    manifest,
  };
}

async function collectPackageFiles(dir, root = dir, prefix = "") {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relative = prefix ? join(prefix, entry.name) : entry.name;
    const path = join(root, relative);
    const metadata = await lstat(path);
    if (metadata.isDirectory()) {
      files.push(...await collectPackageFiles(path, root, relative));
    } else if (metadata.isFile()) {
      files.push(relative);
    } else {
      throw new Error(`release package contains unsupported file type: ${relative}`);
    }
  }
  return files.sort();
}

async function requireReleaseSigningMode({ adHoc }) {
  const identity = process.env.HOPPER_MCP_CODESIGN_IDENTITY || null;
  if (!identity) {
    if (adHoc) return "-";
    throw cliError(
      "release_signing_mode_required",
      "release packaging requires an explicit signing identity or --ad-hoc; implicit ad-hoc signing is not allowed",
    );
  }
  const validation = await validateDistributionIdentity(identity);
  if (!validation.ok) throw cliError("release_signing_mode_required", validation.message);
  return identity;
}

async function validateDistributionIdentity(identity) {
  if (/Developer ID Application:/i.test(identity)) {
    return { ok: true };
  }
  const securityCommand = process.env.HOPPER_MCP_SECURITY || "security";
  const result = await runCapture(securityCommand, ["find-identity", "-p", "codesigning", "-v"]);
  if (result.code !== 0) {
    return {
      ok: false,
      message: `could not validate HOPPER_MCP_CODESIGN_IDENTITY with ${securityCommand}: ${result.stderr || result.stdout}`,
    };
  }
  const identities = parseCodesignIdentities(result.stdout);
  const matched = identities.find((candidate) => candidate.hash === identity || candidate.name === identity);
  if (matched?.name && /Developer ID Application:/i.test(matched.name)) {
    return { ok: true };
  }
  return {
    ok: false,
    message: "release packaging requires a Developer ID Application identity via HOPPER_MCP_CODESIGN_IDENTITY; Apple Development and other signing identities are not valid for distribution builds",
  };
}

function parseCodesignIdentities(output) {
  return String(output)
    .split("\n")
    .map((line) => line.match(/^\s*\d+\)\s+([0-9A-F]+)\s+\"([^\"]+)\"/i))
    .filter(Boolean)
    .map((match) => ({
      hash: match[1],
      name: match[2],
    }));
}

async function signReleaseBinary(path, identity) {
  if (process.platform !== "darwin") return;
  await run("codesign", ["--force", "--sign", identity, path]);
}

async function verifyReleaseSignature(path) {
  if (process.platform !== "darwin") {
    return {
      ok: true,
      message: "codesign verification skipped on non-darwin platform",
    };
  }
  const result = await runCapture("codesign", ["--verify", "--strict", "--verbose=2", path]);
  return {
    ok: result.code === 0,
    message: result.code === 0
      ? "packaged daemon signature verified with codesign"
      : `codesign verification failed with code ${result.code}: ${result.stderr || result.stdout}`,
  };
}

async function verifyReleaseSignatures(paths) {
  const results = [];
  for (const path of paths) {
    results.push(await verifyReleaseSignature(path));
  }
  const failed = results.find((result) => !result.ok);
  return {
    ok: !failed,
    message: failed?.message ?? `packaged binaries verified with codesign (${paths.length})`,
  };
}

async function verifyPluginLinkage(path) {
  if (process.platform !== "darwin") {
    return {
      ok: true,
      message: "plugin linkage verification skipped on non-darwin platform",
    };
  }
  const result = await runCapture("otool", ["-L", path]);
  if (result.code !== 0) {
    return {
      ok: false,
      message: `otool linkage check failed with code ${result.code}: ${result.stderr || result.stdout}`,
    };
  }
  const details = `${result.stdout}\n${result.stderr}`;
  if (/AppKit\.framework|Cocoa\.framework/i.test(details)) {
    return {
      ok: false,
      message: "packaged Hopper Tool Plugin links AppKit/Cocoa; Hopper live-loading should stay Foundation-only",
    };
  }
  return {
    ok: true,
    message: "packaged Hopper Tool Plugin uses Foundation-only linkage",
  };
}

async function verifyDistributionSignatures(paths) {
  for (const path of paths) {
    const result = await verifyDistributionSignature(path);
    if (!result.ok) return result;
  }
  return {
    ok: true,
    message: `packaged binaries are signed with a Developer ID Application identity (${paths.length})`,
  };
}

async function verifyDistributionSignature(path) {
  const result = await runCapture("codesign", ["-dv", "--verbose=4", path]);
  const details = `${result.stdout}\n${result.stderr}`;
  if (result.code !== 0) {
    return {
      ok: false,
      message: `codesign metadata check failed with code ${result.code}: ${result.stderr || result.stdout}`,
    };
  }
  const hasDeveloperId = /Authority=Developer ID Application:/i.test(details);
  const hasTeamId = /TeamIdentifier=\S+/i.test(details);
  return {
    ok: hasDeveloperId && hasTeamId,
    message: hasDeveloperId && hasTeamId
      ? `${path} is signed with a Developer ID Application identity`
      : `Apple notarization requires a Developer ID Application signature for ${path}; rebuild with HOPPER_MCP_CODESIGN_IDENTITY set to a Developer ID Application identity.`,
  };
}

function parseJson(input) {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}

async function smokePackagedBridge(packageRoot) {
  const result = await runCaptureInput(
    "node",
    [join(packageRoot, "src", "live-bridge-cli.js")],
    "{not json\n",
    {
      cwd: packageRoot,
      env: {
        ...process.env,
        HOPPER_MCP_ROOT: packageRoot,
      },
    },
  );
  const payload = parseJson(result.stdout);
  const ok = result.code === 1 && payload?.error?.code === "invalid_json";
  return {
    ok,
    message: ok
      ? "packaged live bridge returned structured invalid_json error"
      : `packaged live bridge smoke failed with code ${result.code}: ${result.stderr || result.stdout}`,
  };
}

async function smokePackagedAgent(packageRoot, tempDir) {
  const fixture = await smokePackagedAgentOnce(packageRoot, [
    "--socket",
    null,
    "--fixture",
    "--fixture-document-id",
    "package-smoke",
    "--fixture-document-name",
    "PackageSmoke",
    "--fixture-procedure",
    "0x2000:package_smoke:32",
  ], {
    documentId: "package-smoke",
    documentName: "PackageSmoke",
    procedureAddr: "0x2000",
    procedureName: "package_smoke",
  });
  if (!fixture.ok) return fixture;

  const fakeOfficial = join(tempDir, "fake-official-hopper-mcp.mjs");
  await writeFile(fakeOfficial, fakeOfficialMcpServer(), "utf8");
  await chmod(fakeOfficial, 0o755);
  const realBridge = await smokePackagedAgentOnce(packageRoot, [
    "--socket",
    null,
    "--official-mcp-command",
    fakeOfficial,
  ], {
    documentId: "PackageReal",
    documentName: "PackageReal",
    procedureAddr: "0x3000",
    procedureName: "package_real",
  });
  if (!realBridge.ok) return realBridge;

  return {
    ok: true,
    message: "packaged hopper-agent completed fixture and real-bridge hopper-wire procedure smoke",
  };
}

async function smokePackagedAgentOnce(packageRoot, argsTemplate, expected) {
  // Keep the socket path short; sockaddr_un paths are capped near 104 bytes on macOS.
  const socket = join("/tmp", `hpa-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.sock`);
  const args = argsTemplate.map((arg) => arg === null ? socket : arg);
  const child = spawn(join(packageRoot, "target", "release", "hopper-agent"), args, {
    cwd: packageRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForPath(socket, 5000);
    const client = await connectUnixSocket(socket);
    try {
      client.write(`${JSON.stringify({
        type: "handshake",
        wireVersion: 1,
        daemonVersion: "package-smoke",
      })}\n`);
      const handshake = await readSocketJsonLine(client, 5000);
      client.write(`${JSON.stringify({ type: "current_document" })}\n`);
      const document = await readSocketJsonLine(client, 5000);
      client.write(`${JSON.stringify({ type: "list_procedures", maxResults: 10 })}\n`);
      const procedures = await readSocketJsonLine(client, 5000);
      const ok = handshake?.type === "handshake"
        && handshake.accepted === true
        && document?.documentId === expected.documentId
        && document?.name === expected.documentName
        && procedures?.type === "procedures"
        && procedures.procedures?.[0]?.addr === expected.procedureAddr
        && procedures.procedures?.[0]?.name === expected.procedureName;
      return {
        ok,
        message: ok
          ? "packaged hopper-agent completed hopper-wire handshake and procedure smoke"
          : `packaged hopper-agent returned unexpected payload: ${JSON.stringify({ handshake, document, procedures })}`,
      };
    } finally {
      client.destroy();
    }
  } catch (error) {
  return {
    ok: false,
    message: `packaged hopper-agent smoke failed: ${error.message}; stderr: ${stderr}`,
    };
  } finally {
    child.kill("SIGTERM");
    await waitForChildClose(child, 2000);
    await rm(socket, { force: true }).catch(() => {});
  }
}

async function releaseSourceProvenance() {
  const commit = await gitOutput(["rev-parse", "HEAD"], "release packaging requires a git checkout so release-manifest.json can record the source commit");
  const status = await gitOutput(["status", "--porcelain"], "release packaging could not determine whether the git worktree is clean");
  return {
    vcs: "git",
    commit,
    treeState: status ? "dirty" : "clean",
  };
}

async function releaseBuildProvenance(signingIdentity) {
  return {
    nodeVersion: process.version,
    cargoVersion: await commandVersion("cargo", ["--version"], "release packaging could not determine cargo version"),
    signing: {
      mode: signingIdentity === "-" ? "ad-hoc" : "developer-id",
      identity: signingIdentity === "-" ? null : signingIdentity,
    },
  };
}

async function commandVersion(command, args, failureMessage) {
  const result = await runCapture(command, args);
  if (result.code !== 0) {
    throw cliError(
      "release_provenance_unavailable",
      `${failureMessage}: ${result.stderr || result.stdout}`.trim(),
    );
  }
  const value = result.stdout.trim();
  if (!value) {
    throw cliError("release_provenance_unavailable", `${failureMessage}: command returned no output`);
  }
  return value;
}

async function gitOutput(args, failureMessage) {
  const gitCommand = process.env.HOPPER_MCP_GIT || "git";
  const result = await runCapture(gitCommand, args);
  if (result.code !== 0) {
    throw cliError(
      "release_provenance_unavailable",
      `${failureMessage}: ${result.stderr || result.stdout}`.trim(),
    );
  }
  const value = result.stdout.trim();
  if (!value && args.join(" ") !== "status --porcelain") {
    throw cliError("release_provenance_unavailable", `${failureMessage}: git returned no output`);
  }
  return value;
}

function isValidReleaseSource(source) {
  return !!source
    && typeof source === "object"
    && source.vcs === "git"
    && /^[0-9a-f]{40}$/i.test(source.commit)
    && (source.treeState === "clean" || source.treeState === "dirty");
}

function isValidReleaseBuild(build) {
  if (!build || typeof build !== "object" || Array.isArray(build)) return false;
  const signing = build.signing;
  if (!signing || typeof signing !== "object" || Array.isArray(signing)) return false;
  const validMode = signing.mode === "ad-hoc"
    ? signing.identity === null
    : signing.mode === "developer-id" && typeof signing.identity === "string" && signing.identity.length > 0;
  return typeof build.nodeVersion === "string"
    && build.nodeVersion.length > 0
    && typeof build.cargoVersion === "string"
    && build.cargoVersion.length > 0
    && validMode;
}

function cliError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function writeCliError(error) {
  process.stdout.write(`${JSON.stringify({
    ok: false,
    code: error?.code || "release_package_failed",
    message: error?.message || String(error),
  }, null, 2)}\n`);
}

function fakeOfficialMcpServer() {
  return `#!/usr/bin/env node
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "initialize") {
    respond(message.id, { protocolVersion: message.params.protocolVersion, capabilities: {}, serverInfo: { name: "package-fake", version: "1" } });
    return;
  }
  if (message.method === "tools/call") {
    if (message.params.name === "current_document") {
      respond(message.id, text("PackageReal"));
      return;
    }
    if (message.params.name === "list_procedure_size") {
      respond(message.id, text({ "0x3000": { name: "package_real", size: 48, basicblock_count: 2 } }));
      return;
    }
  }
  respond(message.id, text(null));
});
function text(value) {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] };
}
function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\\n");
}
`;
}

async function waitForPath(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await exists(path)) return;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
  }
  throw new Error(`timed out waiting for ${path}`);
}

function connectUnixSocket(socket) {
  return new Promise((resolvePromise, reject) => {
    const client = net.createConnection(socket);
    client.once("connect", () => resolvePromise(client));
    client.once("error", reject);
  });
}

function readSocketJsonLine(client, timeoutMs) {
  return new Promise((resolvePromise, reject) => {
    let buffer = "";
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("timed out waiting for agent response"));
    }, timeoutMs);
    const onData = (chunk) => {
      buffer += chunk.toString();
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      cleanup();
      try {
        resolvePromise(JSON.parse(buffer.slice(0, newline)));
      } catch (error) {
        reject(error);
      }
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      client.off("data", onData);
      client.off("error", onError);
    };
    client.on("data", onData);
    client.on("error", onError);
  });
}

function waitForChildClose(child, timeoutMs) {
  return new Promise((resolvePromise) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolvePromise();
      return;
    }
    const timeout = setTimeout(() => resolvePromise(), timeoutMs);
    child.once("close", () => {
      clearTimeout(timeout);
      resolvePromise();
    });
  });
}

function run(command, args) {
  return runWithEnv(command, args, {});
}

function runWithEnv(command, args, envOverrides) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...envOverrides,
      },
      stdio: ["ignore", "inherit", "inherit"],
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolvePromise();
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}`));
      }
    });
  });
}

function runToFile(command, args, outputPath, envOverrides = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...envOverrides,
      },
      stdio: ["ignore", "pipe", "inherit"],
    });
    const chunks = [];
    child.stdout.on("data", (chunk) => {
      chunks.push(chunk);
    });
    child.on("error", reject);
    child.on("close", async (code) => {
      if (code !== 0) {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}`));
        return;
      }
      try {
        await writeFile(outputPath, Buffer.concat(chunks));
        resolvePromise();
      } catch (error) {
        reject(error);
      }
    });
  });
}

async function runQuiet(command, args) {
  const result = await runCapture(command, args);
  if (result.code !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with ${result.code}: ${result.stderr || result.stdout}`);
  }
  return result;
}

function runCapture(command, args, { cwd = repoRoot, env = process.env } = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd,
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
    child.on("close", (code) => {
      resolvePromise({ code, stdout, stderr });
    });
  });
}

function runCaptureInput(command, args, input, { cwd = repoRoot, env = process.env } = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["pipe", "pipe", "pipe"],
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
    child.on("close", (code) => {
      resolvePromise({ code, stdout, stderr });
    });
    child.stdin.end(input);
  });
}

function initializePackagedServer(packageRoot, env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(join(packageRoot, "bin", "hopper-mcp"), [], {
      cwd: packageRoot,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolvePromise(result);
    };
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      finish({
        ok: false,
        message: `timed out waiting for initialize response\nstderr:\n${stderr}`,
      });
    }, 5000);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      const lineEnd = stdout.indexOf("\n");
      if (lineEnd === -1) return;
      child.kill("SIGTERM");
      const response = parseJson(stdout.slice(0, lineEnd));
      finish({
        ok: response?.result?.serverInfo?.name === "hopper-mcpd",
        message: response
          ? `unexpected initialize response: ${stdout.slice(0, lineEnd)}`
          : `invalid initialize response: ${stdout.slice(0, lineEnd)}\nstderr:\n${stderr}`,
      });
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      clearTimeout(timeout);
      settled = true;
      reject(err);
    });
    child.on("close", (code) => {
      if (!stdout.includes("\n")) {
        finish({
          ok: false,
          message: `process exited before initialize response: ${code}\nstderr:\n${stderr}`,
        });
      }
    });
    child.stdin.end('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}\n');
  });
}
