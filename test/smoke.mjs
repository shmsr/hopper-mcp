import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rm } from "node:fs/promises";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const storePath = join(root, "data", "smoke-store.json");
await rm(storePath, { force: true });
const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: storePath },
});

const rl = createInterface({ input: child.stdout });
const responses = new Map();
rl.on("line", (line) => {
  const message = JSON.parse(line);
  responses.set(message.id, message);
});

let id = 0;
async function rpc(method, params = {}) {
  const requestId = ++id;
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
  for (;;) {
    if (responses.has(requestId)) {
      const response = responses.get(requestId);
      responses.delete(requestId);
      if (response.error) throw new Error(response.error.message);
      return response.result;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0.1.0" } });
await rpc("tools/call", { name: "ingest_sample", arguments: {} });
const resources = await rpc("resources/list");
const metadata = await rpc("resources/read", { uri: "hopper://binary/metadata" });
const summary = await rpc("resources/read", { uri: "hopper://function/0x100003f50/summary" });
const analysis = await rpc("tools/call", { name: "analyze_function_deep", arguments: { addr: "0x100003f50" } });
const transaction = await rpc("tools/call", { name: "begin_transaction", arguments: { name: "smoke rename", rationale: "Verify transactional writes." } });
const transactionId = JSON.parse(transaction.content[0].text).transactionId;
await rpc("tools/call", {
  name: "queue",
  arguments: {
    kind: "rename",
    transaction_id: transactionId,
    addr: "0x100003f50",
    value: "validate_license_key",
    rationale: "Smoke test evidence references keychain and SHA256.",
  },
});
const preview = await rpc("tools/call", {
  name: "preview_transaction",
  arguments: { transaction_id: transactionId },
});
const commit = await rpc("tools/call", { name: "commit_transaction", arguments: { transaction_id: transactionId } });
const text = analysis.content[0].text;

if (!resources.resources.some((resource) => resource.uri === "hopper://function/0x100003f50")) {
  throw new Error("Function resource was not listed.");
}
if (!text.includes("_SecItemCopyMatching") || !text.includes("evidenceAnchors")) {
  throw new Error("Deep function analysis did not include expected provenance.");
}
if (!metadata.contents[0].text.includes("SampleMachO") || !summary.contents[0].text.includes("license")) {
  throw new Error("Resource reads did not return expected metadata and function summaries.");
}
if (!preview.content[0].text.includes("sub_100003f50") || !commit.content[0].text.includes("validate_license_key")) {
  throw new Error("Transactional rename preview/commit did not include expected old and new values.");
}

child.stdin.end();
child.kill();
await once(child, "exit");
console.log("smoke ok");
