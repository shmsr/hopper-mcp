import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: join(root, "data", "official-backend-store.json") },
});

const rl = createInterface({ input: child.stdout });
const responses = new Map();
rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (Object.hasOwn(message, "id")) responses.set(message.id, message);
});

let id = 0;
async function rpc(method, params = {}, { timeoutMs = 45000 } = {}) {
  const requestId = ++id;
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params })}\n`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (responses.has(requestId)) {
      const response = responses.get(requestId);
      responses.delete(requestId);
      if (response.error) throw new Error(response.error.message);
      return response.result;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Timed out waiting for ${method} response ${requestId}.`);
}

function payload(result, { allowError = false } = {}) {
  if (result.isError && !allowError) throw new Error(result.content?.[0]?.text ?? "MCP tool call failed.");
  return result.isError ? result.content?.[0]?.text : JSON.parse(result.content[0].text);
}

try {
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "official-backend-test", version: "0.1.0" } });
  const tools = payload(await rpc("tools/call", { name: "official_hopper_tools", arguments: {} }));
  if (!tools.some((tool) => tool.name === "list_documents")) throw new Error("Official Hopper tools did not include list_documents.");

  const documents = payload(await rpc("tools/call", { name: "list_documents", arguments: { backend: "official" } }));
  if (!Array.isArray(documents)) throw new Error("Official backend list_documents did not return an array.");

  const blocked = payload(await rpc("tools/call", {
    name: "official_hopper_call",
    arguments: { name: "set_comment", arguments: { address: "0x0", comment: "blocked" } },
  }), { allowError: true });
  if (!String(blocked).includes("requires HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1")) {
    throw new Error("Official backend write guard did not block set_comment.");
  }

  console.log(JSON.stringify({
    status: "official backend bridge ok",
    officialTools: tools.length,
    documents: documents.length,
  }, null, 2));
} finally {
  child.stdin.end();
  child.kill();
  await once(child, "exit").catch(() => {});
}
