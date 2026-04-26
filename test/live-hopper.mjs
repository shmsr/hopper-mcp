import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const target = process.env.LIVE_HOPPER_BINARY ?? "/bin/ls";
const timeoutMs = Number(process.env.LIVE_HOPPER_TIMEOUT_MS ?? 120000);

const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: join(root, "data", "live-hopper-store.json") },
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

try {
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "live-hopper-test", version: "0.1.0" } });
  const fullExportRequested = process.env.LIVE_HOPPER_FULL_EXPORT === "1";
  const ingestArgs = {
    executable_path: target,
    timeout_ms: timeoutMs,
    analysis: process.env.LIVE_HOPPER_ANALYSIS !== "0",
    parse_objective_c: process.env.LIVE_HOPPER_PARSE_OBJC !== "0",
    parse_swift: process.env.LIVE_HOPPER_PARSE_SWIFT !== "0",
  };
  if (!fullExportRequested || process.env.LIVE_HOPPER_MAX_FUNCTIONS !== undefined) {
    ingestArgs.max_functions = Number(process.env.LIVE_HOPPER_MAX_FUNCTIONS ?? 200);
  }
  if (!fullExportRequested || process.env.LIVE_HOPPER_MAX_STRINGS !== undefined) {
    ingestArgs.max_strings = Number(process.env.LIVE_HOPPER_MAX_STRINGS ?? 500);
  }
  if (process.env.LIVE_HOPPER_WAIT_FOR_ANALYSIS !== undefined) {
    ingestArgs.wait_for_analysis = process.env.LIVE_HOPPER_WAIT_FOR_ANALYSIS === "1";
  }
  if (process.env.LIVE_HOPPER_FULL_EXPORT !== undefined) {
    ingestArgs.full_export = process.env.LIVE_HOPPER_FULL_EXPORT === "1";
  }
  if (process.env.LIVE_HOPPER_FAIL_ON_TRUNCATION !== undefined) {
    ingestArgs.fail_on_truncation = process.env.LIVE_HOPPER_FAIL_ON_TRUNCATION === "1";
  }
  const ingest = await rpc("tools/call", {
    name: "ingest_live_hopper",
    arguments: ingestArgs,
  });
  const repeatedIngest = await rpc("tools/call", {
    name: "ingest_live_hopper",
    arguments: ingestArgs,
  });
  const metadata = await rpc("resources/read", { uri: "hopper://binary/metadata" });
  const binaryStrings = await rpc("resources/read", { uri: "hopper://binary/strings" });
  const resources = await rpc("resources/list");

  if (ingest.isError) {
    throw new Error(ingest.content?.[0]?.text ?? "Live Hopper ingest failed.");
  }
  if (repeatedIngest.isError) {
    throw new Error(repeatedIngest.content?.[0]?.text ?? "Repeated live Hopper ingest failed.");
  }
  const ingestResult = JSON.parse(ingest.content[0].text);
  const repeatedIngestResult = JSON.parse(repeatedIngest.content[0].text);
  const metadataResult = JSON.parse(metadata.contents[0].text);
  const stringResult = JSON.parse(binaryStrings.contents[0].text);

  if (!metadataResult.entryPoint || !Array.isArray(metadataResult.segments) || metadataResult.segments.length === 0) {
    throw new Error("Live Hopper metadata did not include entrypoint and segments.");
  }
  if (!Array.isArray(stringResult) || stringResult.length === 0) {
    throw new Error("Live Hopper string resource did not return indexed strings.");
  }
  if (!metadataResult.segments || !ingestResult.session.capabilities?.liveExport) {
    throw new Error("Live Hopper ingest did not include live export metadata.");
  }
  if (!["reuse_current_document", "cli-python-export", "osascript"].includes(repeatedIngestResult.launch?.mode)) {
    throw new Error(`Repeated live Hopper ingest used an unexpected launch mode: ${JSON.stringify(repeatedIngestResult.launch)}`);
  }

  console.log(JSON.stringify({
    status: "live hopper MCP ingest ok",
    target,
    counts: ingestResult.session.counts,
    resourceCount: resources.resources.length,
    binary: {
      name: metadataResult.name,
      path: metadataResult.path,
      arch: metadataResult.arch,
      entryPoint: metadataResult.entryPoint,
      segments: metadataResult.segments.length,
    },
    liveExport: ingestResult.session.capabilities.liveExport,
    repeatedLaunch: repeatedIngestResult.launch,
  }, null, 2));
} catch (error) {
  const message = String(error.message ?? error);
  if (message.includes("Not authorized to send Apple events")) {
    console.error([
      "Live Hopper ingest is installed, but macOS blocked Automation access.",
      "In System Settings > Privacy & Security > Automation, expand Ghostty and allow it to control Hopper Disassembler, then rerun npm run test:live.",
      "",
      message,
    ].join("\n"));
    process.exitCode = 78;
  } else {
    throw error;
  }
} finally {
  child.stdin.end();
  child.kill();
  await once(child, "exit").catch(() => {});
}
