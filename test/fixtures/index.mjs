import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(fileURLToPath(import.meta.url), "../../..");
const SERVER = join(REPO, "src/mcp-server.js");

export { sampleSession } from "./sample-session.mjs";
import { sampleSession } from "./sample-session.mjs";

// Spawn the MCP server in an isolated store path; returns { call, close }.
export async function startServer({ env = {} } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "hopper-mcp-test-"));
  const child = spawn(process.execPath, [SERVER], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOPPER_MCP_STORE: join(dir, "store.json"), ...env },
  });

  let buffer = "";
  const pending = new Map();
  let nextId = 1;

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
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(Object.assign(new Error(msg.error.message), msg.error));
        else if (msg.result?.isError) {
          const text = msg.result.content?.find((c) => c.type === "text")?.text ?? "tool error";
          reject(new Error(text));
        } else resolve(msg.result);
      }
    }
  });

  child.stderr.on("data", (chunk) => process.stderr.write(`[server] ${chunk}`));

  function drainPending(err) {
    for (const { reject } of pending.values())
      reject(err ?? new Error("server exited unexpectedly"));
    pending.clear();
  }

  child.stdout.on("close", () => drainPending(new Error("server stdout closed")));
  child.on("exit", (code) => {
    if (code !== 0) drainPending(new Error(`server exited with code ${code}`));
  });
  child.on("error", (err) => drainPending(new Error(`server spawn failed: ${err.message}`)));
  child.stdin.on("error", () => {}); // suppress EPIPE on dead process

  function send(method, params) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  await send("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "test-harness", version: "0.0.0" },
  });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

  return {
    call: (name, args = {}) => send("tools/call", { name, arguments: args }),
    listTools: () => send("tools/list", {}),
    readResource: (uri) => send("resources/read", { uri }),
    listResources: () => send("resources/list", {}),
    raw: send,
    async close() {
      child.stdin.end();
      if (child.exitCode === null) {
        try { await once(child, "exit"); } catch {}
      }
      await rm(dir, { recursive: true, force: true });
    },
  };
}

// Decode the JSON content block from a tools/call result.
// structuredContent wraps arrays/scalars as { result: v } (see server-format.js).
// Unwrap that envelope so callers always receive the raw value (array, object, scalar).
export function decodeToolResult(result) {
  const sc = result.structuredContent;
  if (sc !== undefined) {
    // Unwrap the { result: v } envelope that structuredToolContent emits for
    // non-plain-object values (arrays, strings, numbers).
    if (sc !== null && typeof sc === "object" && Object.keys(sc).length === 1 && "result" in sc) {
      return sc.result;
    }
    return sc;
  }
  const block = result.content?.find((c) => c.type === "text");
  return block ? JSON.parse(block.text) : null;
}

// Convenience: starts server, ingests the sample session, returns harness + sessionId.
export async function startWithSample(opts) {
  const harness = await startServer(opts);
  // Sample is loaded via open_session; ingest_sample was removed in Task 16.
  try {
    const result = await harness.call("open_session", { session: sampleSession() });
    const session = decodeToolResult(result);
    return { ...harness, sessionId: session.sessionId };
  } catch (err) {
    await harness.close().catch(() => {});
    throw err;
  }
}
