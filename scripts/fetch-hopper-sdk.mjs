#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const filesApi = "https://www.hopperapp.com/include/files-api.php?request=releases&public=true";
const cacheRoot = resolve(repoRoot, ".cache", "hopper-sdk");

const release = await fetchJson(filesApi);
const sdk = release.SDK;
if (!sdk?.filename || !sdk?.version || !sdk?.file_hash) {
  throw new Error("Hopper files API did not return SDK filename/version/hash");
}

const sdkRoot = join(cacheRoot, sdk.version);
const includeDir = join(sdkRoot, "include", "Hopper");
if (await exists(includeDir)) {
  process.stdout.write(`${JSON.stringify({ ok: true, cached: true, version: sdk.version, sdkRoot }, null, 2)}\n`);
  process.exit(0);
}

await mkdir(cacheRoot, { recursive: true });
const zipPath = join(cacheRoot, basename(new URL(sdk.filename).pathname));
await download(sdk.filename, zipPath);
const sha1 = createHash("sha1").update(await readFile(zipPath)).digest("hex");
if (sha1 !== sdk.file_hash) {
  throw new Error(`Hopper SDK SHA-1 mismatch: expected ${sdk.file_hash}, got ${sha1}`);
}

await rm(sdkRoot, { recursive: true, force: true });
await mkdir(sdkRoot, { recursive: true });
await run("unzip", ["-q", zipPath, "-d", sdkRoot]);

process.stdout.write(`${JSON.stringify({ ok: true, cached: false, version: sdk.version, sdkRoot, sha1 }, null, 2)}\n`);

async function fetchJson(url) {
  const response = await fetch(url, { headers: { "user-agent": "Mozilla/5.0 hopper-mcp-sdk-fetcher" } });
  if (!response.ok) throw new Error(`GET ${url} failed with HTTP ${response.status}`);
  return await response.json();
}

async function download(url, destination) {
  const response = await fetch(url, { headers: { "user-agent": "Mozilla/5.0 hopper-mcp-sdk-fetcher" } });
  if (!response.ok || response.body == null) {
    throw new Error(`GET ${url} failed with HTTP ${response.status}`);
  }
  await pipeline(response.body, createWriteStream(destination));
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function run(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} ${args.join(" ")} failed with code ${code}: ${stderr}`));
    });
  });
}
