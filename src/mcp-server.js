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
const adapter = new HopperAdapter({
  socketPath: process.env.HOPPER_MCP_SOCKET ?? null,
  hopperLauncher: process.env.HOPPER_LAUNCHER ?? null,
});
const officialBackend = new OfficialHopperBackend();

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
process.on("exit", () => {
  officialBackend.close();
});

// On a controlled shutdown, flush any in-flight save before exiting so the
// last upsertSession's mutations are not lost (scheduleSave is fire-and-forget).
async function gracefulShutdown(signal) {
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
  process.exit(0);
}
process.on("SIGINT", () => {
  gracefulShutdown("SIGINT");
});
process.on("SIGTERM", () => {
  gracefulShutdown("SIGTERM");
});

process.on("uncaughtException", (err) => {
  try {
    process.stderr.write(`[hopper-mcp] uncaughtException: ${err?.stack ?? err}\n`);
  } catch {}
});
process.on("unhandledRejection", (reason) => {
  try {
    process.stderr.write(`[hopper-mcp] unhandledRejection: ${reason?.stack ?? reason}\n`);
  } catch {}
});
process.stdin.on("error", (err) => {
  try {
    process.stderr.write(`[hopper-mcp] stdin error: ${err?.message ?? err}\n`);
  } catch {}
});
process.stdout.on("error", (err) => {
  // Log first so the cause is visible in MCP logs (the previous server silently
  // exited on EPIPE, which made it look like the process "vanished" right
  // after returning a large response). Then flush the store.
  try {
    process.stderr.write(`[hopper-mcp] stdout error (${err?.code ?? "unknown"}): ${err?.message ?? err}\n`);
  } catch {}
  if (err && err.code === "EPIPE") {
    store
      .save()
      .catch(() => {})
      .finally(() => process.exit(0));
  }
});

const transport = new StdioServerTransport();
await mcp.connect(transport);
