import test from "node:test";
import assert from "node:assert/strict";
import { decodeToolResult, startMcpProcess } from "./fixtures/index.mjs";

const SKIP = process.env.HOPPER_MCP_PRIVATE_BACKEND_LIVE !== "1";
const cargoCommand = process.env.HOPPER_MCP_PRIVATE_BACKEND_CARGO || "cargo";

test(
  "private backend live probe reaches the configured MCP private backend and ingests the current document",
  { skip: SKIP },
  async () => {
    const harness = await startMcpProcess({
      command: cargoCommand,
      args: ["run", "-p", "hopper-mcpd", "--"],
      env: {
        HOPPER_MCP_DEBUG: "0",
      },
    });

    try {
      const diagnostics = decodeToolResult(await harness.call("backend_diagnostics"));
      assert.equal(diagnostics.backend, "private");
      assert.equal(diagnostics.available, true, JSON.stringify(diagnostics));
      assert.equal(diagnostics.backendMode, "injected_private");
      assert.equal(diagnostics.readiness, "ready");
      assert.equal(diagnostics.capabilities?.privateApi, true);

      const ingested = decodeToolResult(
        await harness.call("ingest_current_hopper", { backend: "private" }),
      );
      assert.match(ingested.sessionId, /^live-/);
      assert.equal(typeof ingested.binary?.name, "string");
      assert.ok(ingested.binary.name.length > 0);
    } finally {
      await harness.close();
    }
  },
);
