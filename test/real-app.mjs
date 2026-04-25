import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { importMachO } from "../src/macho-importer.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const target = process.env.REAL_APP_BINARY ?? "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler";
const session = await importMachO(target, { arch: process.env.REAL_APP_ARCH ?? "arm64", maxStrings: 2500 });

if (session.imports.length < 100) throw new Error(`Expected a rich import set, found ${session.imports.length}.`);
if (session.strings.length < 100) throw new Error(`Expected a rich string set, found ${session.strings.length}.`);
if (!session.functions.length) throw new Error("Expected at least one real or synthetic function node.");

const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: join(root, "data", "real-app-store.json") },
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

await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "real-app-test", version: "0.1.0" } });
await rpc("tools/call", { name: "open_session", arguments: { session } });

const metadata = await rpc("resources/read", { uri: "hopper://binary/metadata" });
const resources = await rpc("resources/list");
const security = await rpc("tools/call", { name: "resolve", arguments: { query: "Security" } });
const xpc = await rpc("tools/call", { name: "resolve", arguments: { query: "_xpc_" } });
const strings = await rpc("tools/call", { name: "search", arguments: { kind: "strings", pattern: "Hopper|XPC|BinExport", semantic: true } });

const targetFunction = session.functions.find((fn) => fn.name === "security_api_cluster") ?? session.functions[0];
const analysis = await rpc("tools/call", {
  name: "analyze_function_deep",
  arguments: { addr: targetFunction.addr, detail_level: "full" },
});

const begin = await rpc("tools/call", {
  name: "begin_transaction",
  arguments: { name: "real app test annotation", rationale: "Verify transactional preview on a real imported Mach-O session." },
});
const transactionId = JSON.parse(begin.content[0].text).transactionId;
await rpc("tools/call", {
  name: "queue",
  arguments: {
    kind: "comment",
    transaction_id: transactionId,
    addr: targetFunction.addr,
    value: "Real-app MCP test annotation; do not apply to Hopper until adapter bridge is connected.",
    rationale: "This validates queue/preview semantics using a real imported binary session.",
  },
});
const preview = await rpc("tools/call", {
  name: "preview_transaction",
  arguments: { transaction_id: transactionId },
});
await rpc("tools/call", { name: "rollback_transaction", arguments: { transaction_id: transactionId } });

const assertions = [
  ["metadata contains target name", metadata.contents[0].text.includes("Hopper Disassembler")],
  ["resources include functions", resources.resources.some((resource) => resource.uri.startsWith("hopper://function/"))],
  ["security query finds evidence", security.content[0].text.includes("Security") || security.content[0].text.includes("_Sec")],
  ["xpc query finds evidence", xpc.content[0].text.includes("_xpc_") || xpc.content[0].text.includes("xpc_api_cluster")],
  ["string search returns evidence", strings.content[0].text.includes("Hopper") || strings.content[0].text.includes("XPC") || strings.content[0].text.includes("BinExport")],
  ["deep analysis has provenance", analysis.content[0].text.includes("evidenceAnchors") && analysis.content[0].text.includes("provenance")],
  ["transaction preview has old/new values", preview.content[0].text.includes("Real-app MCP test annotation")],
];

const failed = assertions.filter(([, passed]) => !passed);
child.stdin.end();
child.kill();
await once(child, "exit");

if (failed.length) {
  throw new Error(`Real app MCP test failed: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(JSON.stringify({
  status: "real app mcp test ok",
  target,
  binaryId: session.binaryId,
  counts: {
    functions: session.functions.length,
    imports: session.imports.length,
    exports: session.exports.length,
    strings: session.strings.length,
    objcClasses: session.objcClasses.length,
    swiftSymbols: session.swiftSymbols.length,
    resources: resources.resources.length,
  },
  analyzedFunction: targetFunction.name,
}, null, 2));
