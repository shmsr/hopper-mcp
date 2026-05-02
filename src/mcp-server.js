#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { KnowledgeStore } from "./knowledge-store.js";
import { TransactionManager } from "./transaction-manager.js";
import { HopperAdapter } from "./hopper-adapter.js";
import { OfficialHopperBackend } from "./official-hopper-backend.js";
import { registerTools } from "./server-tools.js";
import { registerResources } from "./server-resources.js";
import { registerPrompts } from "./server-prompts.js";
import { debugLog, snapshotInFlight, isDebugEnabled, debugLogPath } from "./debug-log.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

const serverInfo = {
  name: "hopper-mcp",
  title: "Hopper MCP",
  version: "0.1.0",
  description: "MCP server for Hopper with resources, tools, prompts, and transaction-safe annotations.",
};

const store = new KnowledgeStore(
  process.env.HOPPER_MCP_STORE ?? join(ROOT, "data", "knowledge-store.json"),
  { sessionCap: Number(process.env.HOPPER_MCP_SESSION_CAP) || undefined },
);
const transactions = new TransactionManager(store);
const officialBackend = new OfficialHopperBackend();
const adapter = new HopperAdapter({
  socketPath: process.env.HOPPER_MCP_SOCKET ?? null,
  hopperLauncher: process.env.HOPPER_LAUNCHER ?? null,
  officialBackend,
});

debugLog({
  kind: "boot",
  node: process.version,
  storePath: process.env.HOPPER_MCP_STORE ?? join(ROOT, "data", "knowledge-store.json"),
  debugLogPath: debugLogPath(),
});

await store.load();
debugLog({ kind: "store_loaded", sessions: store.listSessions().length });

const mcp = new McpServer(serverInfo, {
  capabilities: {
    // listChanged advertises that we'll send tool/resource list-changed
    // notifications; we register everything statically at boot and never
    // emit those notifications, so claim false on both. logging:{} used to
    // be advertised but we never call sendLoggingMessage — drop it so the
    // host doesn't subscribe to a stream that will never fire.
    tools: { listChanged: false },
    resources: { subscribe: false, listChanged: false },
    prompts: { listChanged: false },
  },
  instructions:
    "Use Hopper-backed ingest only: ingest_live_hopper for rich exports, ingest_official_hopper for the installed Hopper MCP snapshot, or open_session for pre-normalized Hopper snapshots. " +
    "Query snapshots with resolve, query, search, list, procedure, and xrefs. Queue annotations through begin_transaction → queue/hypothesis → " +
    "preview_transaction → commit_transaction. Read source/provenance fields and hopper:// resources before naming.",
});

registerTools(mcp, { store, transactions, adapter, officialBackend, serverInfo });
registerResources(mcp, store);
registerPrompts(mcp);

// ── lifecycle ──────────────────────────────────────────────────────────────
let shuttingDown = false;
let stdoutBroken = false;

process.on("exit", () => {
  // Synchronous-only here — Node has stopped the event loop. Long-running
  // cleanup (durable save) happens in gracefulShutdown.
  try { officialBackend.close(); } catch {}
});

// shuttingDown latches: signals can fire repeatedly during shutdown and we
// want exactly one save+exit, not racing copies that double-write the store.
async function gracefulShutdown(signal, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  debugLog({
    kind: "shutdown",
    signal,
    exitCode,
    inFlight: snapshotInFlight(),
  });
  try {
    process.stderr.write(`[hopper-mcp] received ${signal}; flushing knowledge store.\n`);
  } catch {}
  try {
    // flushDurable awaits any in-flight save and only enqueues a fresh write
    // if the store actually diverges from disk. Read-only tool batches leave
    // _dirty=false, so shutdown returns in ~10ms instead of paying for a full
    // re-write of the 145 MB JSON that would just rewrite identical bytes —
    // shrinking the user-visible "tools unavailable" gap if the host respawns.
    await store.flushDurable();
    debugLog({ kind: "shutdown_saved", dirty: store._dirty });
  } catch (err) {
    debugLog({ kind: "shutdown_save_failed", message: err?.message, stack: err?.stack });
    try {
      process.stderr.write(`[hopper-mcp] flush failed: ${err?.stack ?? err}\n`);
    } catch {}
  }
  try { officialBackend.close(); } catch {}
  process.exit(exitCode);
}
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// stdin EOF is the canonical clean-shutdown signal for a stdio MCP server:
// the host has closed the pipe, so flush durably and exit 0.
process.stdin.on("end", () => gracefulShutdown("stdin EOF"));

// uncaughtException / unhandledRejection used to be log-only, leaving the
// process half-alive with corrupted in-memory state. Flush, then exit non-zero
// so the host respawns instead of routing more traffic at us.
process.on("uncaughtException", (err) => {
  debugLog({
    kind: "uncaught_exception",
    message: err?.message,
    stack: err?.stack,
    inFlight: snapshotInFlight(),
  });
  gracefulShutdown(`uncaughtException: ${err?.stack ?? err}`, 1).catch(() => process.exit(1));
});
process.on("unhandledRejection", (reason) => {
  debugLog({
    kind: "unhandled_rejection",
    message: reason?.message ?? String(reason),
    stack: reason?.stack ?? null,
    inFlight: snapshotInFlight(),
  });
  gracefulShutdown(`unhandledRejection: ${reason?.stack ?? reason}`, 1).catch(() => process.exit(1));
});

process.stdin.on("error", (err) => {
  debugLog({ kind: "stdin_error", code: err?.code, message: err?.message });
  try {
    process.stderr.write(`[hopper-mcp] stdin error: ${err?.message ?? err}\n`);
  } catch {}
});
// EPIPE on stdout means the host went away. Previously we exited synchronously,
// which made the server appear to vanish mid-response and prevented graceful
// reconnect. Now we mark stdout broken, kick a durable save, and let stdin EOF
// or SIGTERM trigger the actual exit. If the host abandons us without closing
// stdin, the next signal cleans up.
process.stdout.on("error", (err) => {
  debugLog({
    kind: "stdout_error",
    code: err?.code,
    message: err?.message,
    inFlight: snapshotInFlight(),
  });
  try {
    process.stderr.write(`[hopper-mcp] stdout error (${err?.code ?? "unknown"}): ${err?.message ?? err}\n`);
  } catch {}
  if (err && err.code === "EPIPE" && !stdoutBroken) {
    stdoutBroken = true;
    // Use flushDurable: if nothing changed since the last save, this is a
    // no-op rather than a fresh 145 MB write triggered by a broken pipe.
    store.flushDurable().catch(() => {});
  }
});

const transport = new StdioServerTransport();
await mcp.connect(transport);
debugLog({ kind: "transport_connected", debug: isDebugEnabled() });
