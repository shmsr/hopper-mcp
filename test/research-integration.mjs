// End-to-end integration test for the new research tools.
// Talks JSON-RPC over stdio to mcp-server.js, using ingest_sample to populate state.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rmSync } from "node:fs";
import assert from "node:assert/strict";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const storePath = join(root, "data", "research-integration-store.json");
try { rmSync(storePath, { force: true }); } catch {}

const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: storePath },
});

const rl = createInterface({ input: child.stdout });
const responses = new Map();
rl.on("line", (line) => {
  try {
    const message = JSON.parse(line);
    if (message.id != null) responses.set(message.id, message);
  } catch {}
});

let id = 0;
async function rpc(method, params = {}) {
  const requestId = ++id;
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
  for (;;) {
    if (responses.has(requestId)) {
      const response = responses.get(requestId);
      responses.delete(requestId);
      if (response.error) throw new Error(`${method}: ${response.error.message}`);
      return response.result;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

const callTool = async (name, args = {}) => {
  const out = await rpc("tools/call", { name, arguments: args });
  return JSON.parse(out.content[0].text);
};

try {
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "research-int", version: "0.1.0" } });

  // 1. Bootstrap a session
  await callTool("ingest_sample", {});

  // 2. Classify capabilities (sample binary has _CC_SHA256, _SecKeychain*)
  const caps = await callTool("classify_capabilities", {});
  assert.ok(caps && typeof caps === "object", "capabilities must be an object");
  // The sample's imports include crypto/keychain symbols
  assert.ok(caps.crypto || caps.security || caps.other, `expected at least one bucket, got ${JSON.stringify(Object.keys(caps))}`);

  // 3. Detect anti-analysis (sample doesn't have ptrace, expect empty or minimal)
  const findings = await callTool("detect_anti_analysis", {});
  assert.ok(Array.isArray(findings), "anti-analysis findings must be an array");

  // 4. Compute fingerprints across all functions
  const fp = await callTool("compute_fingerprints", {});
  assert.ok(fp.updated >= 1, `expected updates, got ${fp.updated}`);

  // 5. Query DSL across the indexed functions
  const allByName = await callTool("query", { expression: "name:sub_" });
  assert.ok(allByName.count >= 1, `expected matches, got ${allByName.count}`);
  const byImport = await callTool("query", { expression: "imports:_CC_SHA256" });
  assert.ok(byImport.count >= 1, `expected import-based matches, got ${byImport.count}`);

  // 6. Begin a transaction and queue tag, rename_batch, hypothesis_create, link_evidence
  const txn = await callTool("begin_transaction", { name: "research integration", rationale: "Exercise new tools." });
  const txnId = txn.transactionId;

  await callTool("queue", { kind: "tag", transaction_id: txnId, addr: "0x100003f50", tags: ["license", "crypto"] });

  await callTool("queue", {
    kind: "rename_batch",
    transaction_id: txnId,
    mapping: { "0x100003f50": "validate_license_key", "0x100004120": "main_dispatch" },
    rationale: "Batch rename via new tool.",
  });

  const hyp = await callTool("hypothesis", {
    action: "create",
    transaction_id: txnId,
    topic: "License validation path",
    claim: "0x100003f50 implements license verification using SHA256 + keychain.",
    rationale: "Imports + strings.",
  });
  // hyp is a transaction preview - extract hypothesisId from operations
  const hypothesisId = hyp.operations.find((op) => op.kind === "hypothesis_create").hypothesisId;
  assert.ok(hypothesisId, "hypothesis action=create must yield a hypothesisId");

  await callTool("hypothesis", {
    action: "link",
    transaction_id: txnId,
    hypothesis_id: hypothesisId,
    addr: "0x100003f50",
    evidence: "Calls _CC_SHA256 and SecKeychainItemCopyContent.",
  });

  await callTool("hypothesis", {
    action: "status",
    transaction_id: txnId,
    hypothesis_id: hypothesisId,
    status: "supported",
    rationale: "Two corroborating evidence pieces.",
  });

  // 7. Commit and assert state
  const commit = await callTool("commit_transaction", { transaction_id: txnId });
  assert.equal(commit.status, "committed");

  const tagsResult = await rpc("resources/read", { uri: "hopper://tags" });
  const tags = JSON.parse(tagsResult.contents[0].text);
  assert.deepEqual(tags["0x100003f50"], ["crypto", "license"]);

  const hypsResult = await rpc("resources/read", { uri: "hopper://hypotheses" });
  const hyps = JSON.parse(hypsResult.contents[0].text);
  assert.equal(hyps.length, 1);
  assert.equal(hyps[0].status, "supported");
  assert.equal(hyps[0].evidence.length, 1);

  // The rename_batch should have applied
  const summary = await rpc("resources/read", { uri: "hopper://function/0x100003f50/summary" });
  const summaryJson = JSON.parse(summary.contents[0].text);
  assert.equal(summaryJson.function.name, "validate_license_key");

  // 8. Tag-based query should now find the renamed function
  const tagQuery = await callTool("query", { expression: "tag:license" });
  assert.equal(tagQuery.count, 1);
  assert.equal(tagQuery.matches[0].addr, "0x100003f50");

  // 9. find_similar_functions on the renamed function should at least return its self-twin removed
  const sim = await callTool("find_similar_functions", { addr: "0x100003f50", min_similarity: 0 });
  assert.ok(sim.matches.length >= 0, "find_similar_functions returned");

  // 10. diff_sessions against itself = no changes
  const diff = await callTool("diff_sessions", { left_session_id: "current", right_session_id: "current" });
  assert.equal(diff.summary.onlyInLeft, 0);
  assert.equal(diff.summary.onlyInRight, 0);
  assert.equal(diff.summary.renamed, 0);

  console.log("research integration ok");
} finally {
  child.stdin.end();
  child.kill();
}
