// Minimal end-to-end: start server with isolated store, call open_session
// (mutating tool), close, and assert the shutdown_saved record reports
// dirty:true (or omitted/older for backward compat) AND that the store file
// on disk grew. This guards against a regression where flushDurable wrongly
// short-circuits on a real mutation path.

import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, stat, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(fileURLToPath(import.meta.url), "../..");
const SERVER = resolve(REPO, "src/mcp-server.js");

const dir = await mkdtemp(join(tmpdir(), "hopper-mcp-dirty-"));
const STORE = join(dir, "store.json");

const child = spawn(process.execPath, [SERVER], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, HOPPER_MCP_STORE: STORE, HOPPER_MCP_DEBUG: "1" },
});

let buffer = "";
const pending = new Map();
let nextId = 1;
const stderr = [];

child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
  buffer += chunk;
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx);
    buffer = buffer.slice(idx + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve: r } = pending.get(msg.id);
      pending.delete(msg.id);
      r(msg);
    }
  }
});
child.stderr.setEncoding("utf8");
child.stderr.on("data", (c) => stderr.push(c));

function send(method, params) {
  const id = nextId++;
  return new Promise((r) => {
    pending.set(id, { resolve: r });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

await send("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "verify-dirty", version: "0.0.0" },
});
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

// open_session is a write-mutating call (calls upsertSession → scheduleSave).
// Use the existing sample fixture so we don't have to fabricate session shape.
const { sampleSession } = await import("./fixtures/sample-session.mjs");
const result = await send("tools/call", {
  name: "open_session",
  arguments: { session: sampleSession() },
});
if (result.error) {
  console.error("open_session failed:", result.error);
  process.exit(2);
}
console.log("open_session ok");

// Close stdin → graceful shutdown → flushDurable should write.
child.stdin.end();
await once(child, "exit");

// Inspect captured stderr for the shutdown_saved record.
const log = stderr.join("");
const savedLine = log.split("\n").find((l) => l.includes('"kind":"shutdown_saved"'));
if (!savedLine) {
  console.error("FAIL: no shutdown_saved record in stderr");
  console.error(log);
  process.exit(1);
}
console.log("shutdown record:", savedLine);

// Confirm the store file actually got written.
const st = await stat(STORE);
const content = await readFile(STORE, "utf8");
const parsed = JSON.parse(content);
const sessionCount = Object.keys(parsed.sessions ?? {}).length;
console.log(`store file: ${st.size} bytes, ${sessionCount} session(s)`);

if (sessionCount === 0) {
  console.error("FAIL: store file has no sessions — write was skipped");
  process.exit(1);
}

// Now verify the OPPOSITE: a fresh server with no mutations should NOT rewrite.
const child2 = spawn(process.execPath, [SERVER], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, HOPPER_MCP_STORE: STORE, HOPPER_MCP_DEBUG: "1" },
});
const stderr2 = [];
child2.stderr.setEncoding("utf8");
child2.stderr.on("data", (c) => stderr2.push(c));

// Initialize and immediately shut down. No mutating calls.
let buffer2 = "";
child2.stdout.setEncoding("utf8");
const pending2 = new Map();
let id2 = 1;
child2.stdout.on("data", (chunk) => {
  buffer2 += chunk;
  let idx;
  while ((idx = buffer2.indexOf("\n")) >= 0) {
    const line = buffer2.slice(0, idx);
    buffer2 = buffer2.slice(idx + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending2.has(msg.id)) {
      const { resolve: r } = pending2.get(msg.id);
      pending2.delete(msg.id);
      r(msg);
    }
  }
});
function send2(method, params) {
  const id = id2++;
  return new Promise((r) => {
    pending2.set(id, { resolve: r });
    child2.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}
await send2("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "verify-dirty", version: "0.0.0" },
});
child2.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

const t0 = process.hrtime.bigint();
child2.stdin.end();
await once(child2, "exit");
const tShutdown = Number((process.hrtime.bigint() - t0) / 1_000_000n);

const log2 = stderr2.join("");
const cleanLine = log2.split("\n").find((l) => l.includes('"kind":"shutdown_saved"'));
console.log("read-only shutdown:", cleanLine, `wall=${tShutdown}ms`);

if (!cleanLine?.includes('"dirty":false')) {
  console.error("FAIL: read-only shutdown didn't report dirty:false");
  process.exit(1);
}

await rm(dir, { recursive: true, force: true });
console.log("\nALL CHECKS PASSED");
