import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: join(root, "data", "protocol-compat-store.json") },
});

const rl = createInterface({ input: child.stdout });
const responses = new Map();
const notifications = [];

rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (Object.hasOwn(message, "id")) {
    responses.set(message.id, message);
  } else {
    notifications.push(message);
  }
});

async function rpc(id, method, params = {}) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  for (;;) {
    if (responses.has(id)) {
      const response = responses.get(id);
      responses.delete(id);
      if (response.error) throw new Error(response.error.message);
      return response.result;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function notify(method, params = {}) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

try {
  const initialized = await rpc(0, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: { roots: {}, elicitation: {} },
    clientInfo: { name: "protocol-compat-test", version: "0.1.0" },
  });
  notify("notifications/initialized");
  await rpc(2, "ping");
  await rpc(3, "logging/setLevel", { level: "warning" });
  const templates = await rpc(4, "resources/templates/list");
  const ingest = await rpc(5, "tools/call", {
    name: "ingest_sample",
    arguments: {},
    _meta: { progressToken: "ingest-sample-test" },
  });
  const strings = await rpc(6, "tools/call", {
    name: "search_strings",
    arguments: { regex: "license" },
  });
  const matches = await rpc(7, "tools/call", {
    name: "resolve",
    arguments: { query: "license" },
  });

  if (initialized.protocolVersion !== "2025-11-25") {
    throw new Error(`Expected protocolVersion 2025-11-25, got ${initialized.protocolVersion}`);
  }
  const fallback = await withSingleRequest({
    jsonrpc: "2.0",
    id: 0,
    method: "initialize",
    params: {
      protocolVersion: "2099-01-01",
      capabilities: {},
      clientInfo: { name: "protocol-compat-test", version: "0.1.0" },
    },
  });
  if (fallback.result.protocolVersion !== "2025-11-25") {
    throw new Error(`Expected unsupported versions to negotiate to 2025-11-25, got ${fallback.result.protocolVersion}`);
  }
  if (!initialized.capabilities.tools || !initialized.capabilities.resources || !initialized.capabilities.prompts) {
    throw new Error("Initialize response did not advertise core server capabilities.");
  }
  if (!templates.resourceTemplates.some((template) => template.uriTemplate === "hopper://function/{addr}/evidence")) {
    throw new Error("Function evidence resource template was not listed.");
  }
  if (!ingest.structuredContent?.counts?.functions) {
    throw new Error("Tool call did not return structuredContent with the ingested session counts.");
  }
  if (!Array.isArray(strings.structuredContent?.result)) {
    throw new Error("Array tool result was not wrapped in structuredContent.result.");
  }
  if (!Array.isArray(matches.structuredContent?.result)) {
    throw new Error("Resolve tool result was not wrapped in structuredContent.result.");
  }
  if (!notifications.some((message) => message.method === "notifications/progress")) {
    throw new Error("Progress notification was not emitted for a progress-tokened tool call.");
  }
  if (!notifications.some((message) => message.method === "notifications/resources/list_changed")) {
    throw new Error("Resource list changed notification was not emitted after ingest.");
  }

  console.log("protocol compat ok");
} finally {
  child.stdin.end();
  child.kill();
  await once(child, "exit").catch(() => {});
}

async function withSingleRequest(request) {
  const oneShot = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
    stdio: ["pipe", "pipe", "inherit"],
    env: { ...process.env, HOPPER_MCP_STORE: join(root, "data", "protocol-compat-oneshot-store.json") },
  });
  let output = "";
  oneShot.stdout.on("data", (chunk) => {
    output += chunk.toString("utf8");
  });
  oneShot.stdin.end(JSON.stringify(request) + "\n");
  await once(oneShot, "exit");
  const line = output.trim().split("\n").find(Boolean);
  if (!line) throw new Error("One-shot MCP request did not produce a response.");
  return JSON.parse(line);
}
