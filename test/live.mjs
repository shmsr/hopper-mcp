import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { spawn } from "node:child_process";
import { rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { startServer, decodeToolResult } from "./fixtures/index.mjs";

const SKIP = process.env.HOPPER_MCP_LIVE !== "1";
const TARGET = process.env.HOPPER_MCP_LIVE_TARGET ?? "/bin/echo";
const CAPTURE_ONE = "/Applications/Capture One.app/Contents/MacOS/Capture One";
const SKIP_CAPTURE_ONE = SKIP || !existsSync(CAPTURE_ONE);

test("ingest_live_hopper opens, exports, ingests", { skip: SKIP }, async () => {
  const h = await startServer({ env: { LIVE_HOPPER_MAX_FUNCTIONS: "20", LIVE_HOPPER_MAX_STRINGS: "50" } });
  try {
    const out = decodeToolResult(await h.call("ingest_live_hopper", {
      executable_path: TARGET,
      timeout_ms: 90_000,
      max_functions: 20,
      max_strings: 50,
      close_after_export: true,
    }));
    assert.ok(out.session?.sessionId);
  } finally { await h.close(); }
});

test("official_hopper_call list_documents returns the live document set", { skip: SKIP }, async () => {
  const h = await startServer();
  try {
    const out = decodeToolResult(await h.call("official_hopper_call", {
      name: "list_documents", arguments: {},
    }));
    assert.ok(Array.isArray(out) || typeof out === "object");
  } finally { await h.close(); }
});

test("commit_transaction(backend:official) end-to-end", { skip: SKIP }, async () => {
  // Safe live-write coverage: the test opens a throwaway Hopper document,
  // applies a rename to that unsaved document only, then closes it without
  // saving through close_session({close_in_hopper:true}).
  const h = await startServer({ env: { HOPPER_MCP_ENABLE_OFFICIAL_WRITES: "1" } });
  try {
    await h.call("ingest_live_hopper", {
      executable_path: TARGET,
      timeout_ms: 90_000,
      max_functions: 5,
      close_after_export: false,
    });
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const addr = Object.keys(procs)[0];
    const txn = decodeToolResult(await h.call("begin_transaction", {}));
    await h.call("queue", { kind: "rename", addr, value: `live_test_${Date.now()}`, transaction_id: txn.transactionId });
    const out = decodeToolResult(await h.call("commit_transaction", {
      transaction_id: txn.transactionId, backend: "official", confirm_live_write: true,
    }));
    assert.equal(out.status, "committed");
    assert.equal(out.adapterResult?.appliedToHopper, true);
    assert.equal(out.adapterResult?.operations?.[0]?.tool, "set_addresses_names");
  } finally {
    try {
      await h.call("close_session", { session_id: "current", close_in_hopper: true });
    } catch {}
    await h.close();
  }
});

test("hopper-agent real mode reads the live Hopper document through the official MCP subprocess", { skip: SKIP }, async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const h = await startServer();
  const socket = join("/tmp", `hpa-live-${process.pid}-${Date.now()}.sock`);
  const agent = spawn("target/release/hopper-agent", ["--socket", socket], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let agentStderr = "";
  agent.stderr.on("data", (chunk) => {
    agentStderr += chunk.toString();
  });

  try {
    await h.call("ingest_live_hopper", {
      executable_path: TARGET,
      timeout_ms: 90_000,
      max_functions: 5,
      max_strings: 20,
      close_after_export: false,
    });
    await waitForSocket(socket);
    const client = await connect(socket);
    client.write(`${JSON.stringify({
      type: "handshake",
      wireVersion: 1,
      daemonVersion: "live-test",
    })}\n`);
    const handshake = await readJsonLine(client);
    assert.equal(handshake.accepted, true);
    assert.equal(handshake.capabilities.currentDocument, true);
    assert.equal(handshake.capabilities.procedures, true);

    client.write(`${JSON.stringify({ type: "current_document" })}\n`);
    const document = await readJsonLine(client, 30_000);
    assert.equal(document.type, "current_document", JSON.stringify(document));
    assert.ok(document.name.length > 0);

    client.write(`${JSON.stringify({ type: "list_procedures", maxResults: 5 })}\n`);
    const procedures = await readJsonLine(client, 30_000);
    assert.equal(procedures.type, "procedures", JSON.stringify(procedures));
    assert.ok(procedures.procedures.length > 0);
    assert.ok(procedures.procedures.every((procedure) => /^0x[0-9a-fA-F]+$/.test(procedure.addr)));
    client.end();
  } finally {
    agent.kill("SIGTERM");
    await onceClose(agent);
    await rm(socket, { force: true }).catch(() => {});
    try {
      await h.call("close_session", { session_id: "current", close_in_hopper: true });
    } catch {}
    await h.close();
  }

  assert.equal(agent.exitCode === 0 || agent.signalCode === "SIGTERM", true, agentStderr);
});

test("ingest_live_hopper returns an optimized official fallback snapshot for Capture One", { skip: SKIP_CAPTURE_ONE }, async () => {
  const h = await startServer({ env: { LIVE_HOPPER_MAX_FUNCTIONS: "200", LIVE_HOPPER_MAX_STRINGS: "500" } });
  try {
    const out = decodeToolResult(await h.call("ingest_live_hopper", {
      executable_path: CAPTURE_ONE,
      analysis: false,
      wait_for_analysis: false,
      full_export: false,
      only_procedures: true,
      loader: "Mach-O",
      timeout_ms: 120000,
      max_functions: 200,
      max_strings: 500,
      max_blocks_per_function: 4,
      max_instructions_per_block: 8,
      close_after_export: true,
    }));

    assert.equal(out.session?.binary?.name, "Capture One");
    assert.equal(out.session?.capabilities?.liveExport?.backend, "hopper-official-fallback");
    assert.equal(out.session?.capabilities?.liveExport?.fallbackFrom, "hopper-python-bridge");
    assert.match(
      out.session?.capabilities?.liveExport?.fallbackReason ?? "",
      /Hopper launcher exited before writing a session file|Hopper live export produced an empty session|Cannot launch Hopper!/,
    );
    assert.equal(out.launch?.fallbackFrom, "hopper-python-bridge");
    assert.ok((out.session?.capabilities?.officialSnapshot?.totals?.procedures ?? 0) > 0);
    assert.ok((out.session?.capabilities?.liveExport?.exported?.functions ?? 0) > 0);
    assert.ok((out.session?.capabilities?.liveExport?.exported?.functions ?? 0) <= 200);
    assert.equal(out.session?.capabilities?.liveExport?.exported?.strings, 500);
  } finally {
    await h.close();
  }
});

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

async function waitForSocket(socket) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (existsSync(socket)) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for socket: ${socket}`);
}

function connect(socket) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socket);
    client.once("connect", () => resolve(client));
    client.once("error", reject);
  });
}

function readJsonLine(client, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for JSON line; buffered=${JSON.stringify(buffer)}`));
    }, timeoutMs);
    const onData = (chunk) => {
      buffer += chunk.toString();
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      cleanup();
      resolve(JSON.parse(buffer.slice(0, newline)));
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error(`stream closed before JSON line; buffered=${JSON.stringify(buffer)}`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      client.off("data", onData);
      client.off("error", onError);
      client.off("close", onClose);
    };
    client.on("data", onData);
    client.once("error", onError);
    client.once("close", onClose);
  });
}

function onceClose(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("close", resolve);
  });
}
