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

await store.load();

const mcp = new McpServer(serverInfo, {
  capabilities: {
    tools: { listChanged: true },
    resources: { subscribe: false, listChanged: true },
    prompts: { listChanged: false },
    logging: {},
  },
  instructions:
    "Use tools to ingest binaries (import_macho, ingest_live_hopper, ingest_official_hopper), query the snapshot " +
    "(resolve, query, list_procedures, search_strings), and queue annotations through begin_transaction → " +
    "queue_* → preview_transaction → commit_transaction. Read provenance via hopper:// resources before naming.",
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
  try {
    process.stderr.write(`[hopper-mcp] received ${signal}; flushing knowledge store.\n`);
  } catch {}
  try {
    await store.save();
  } catch (err) {
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
  gracefulShutdown(`uncaughtException: ${err?.stack ?? err}`, 1).catch(() => process.exit(1));
});
process.on("unhandledRejection", (reason) => {
  gracefulShutdown(`unhandledRejection: ${reason?.stack ?? reason}`, 1).catch(() => process.exit(1));
});

process.stdin.on("error", (err) => {
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
  try {
    process.stderr.write(`[hopper-mcp] stdout error (${err?.code ?? "unknown"}): ${err?.message ?? err}\n`);
  } catch {}
  if (err && err.code === "EPIPE" && !stdoutBroken) {
    stdoutBroken = true;
    store.save().catch(() => {});
  }
});

const transport = new StdioServerTransport();
await mcp.connect(transport);
