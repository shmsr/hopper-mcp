import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("bin/hopper-mcp speaks MCP initialize over stdio", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "hopper-mcp-bin-"));
  const child = spawn("bin/hopper-mcp", [], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOPPER_MCP_STORE: join(tempDir, "store.json"),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });

  try {
    const linePromise = readFirstStdoutLine(child, 5000);
    child.stdin.end('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}\n');

    const line = await linePromise;
    const response = JSON.parse(line);
    assert.equal(response.result.serverInfo.name, "hopper-mcpd");
  } finally {
    child.kill("SIGTERM");
    await rm(tempDir, { recursive: true, force: true });
  }
});

function readFirstStdoutLine(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`timed out waiting for initialize response\nstderr:\n${stderr}`));
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      const lineEnd = stdout.indexOf("\n");
      if (lineEnd !== -1) {
        clearTimeout(timeout);
        resolve(stdout.slice(0, lineEnd));
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (!stdout.includes("\n")) {
        reject(new Error(`process exited before initialize response: ${code}\nstderr:\n${stderr}`));
      }
    });
  });
}
