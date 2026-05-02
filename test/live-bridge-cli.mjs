import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { isMainModule, toLiveOptions } from "../src/live-bridge-cli.js";

test("live bridge CLI returns structured JSON error for malformed stdin", async () => {
  const child = spawn(process.execPath, ["src/live-bridge-cli.js"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.end("{not json}\n");

  const { code, stdout } = await collect(child);
  assert.notEqual(code, 0);
  const payload = JSON.parse(stdout);
  assert.equal(payload.error.code, "invalid_json");
  assert.match(payload.error.message, /JSON/i);
});

test("live bridge CLI maps loader checkboxes into live options", () => {
  const options = toLiveOptions({
    executable_path: "/bin/echo",
    loader: "Mach-O",
    loader_checkboxes: ["Resolve Lazy Bindings=true"],
    max_blocks_per_function: 7,
    max_instructions_per_block: 9,
  });

  assert.deepEqual(options, {
    executablePath: "/bin/echo",
    timeoutMs: undefined,
    maxFunctions: undefined,
    maxStrings: undefined,
    maxBlocksPerFunction: 7,
    maxInstructionsPerBlock: 9,
    analysis: undefined,
    loader: "Mach-O",
    loaderCheckboxes: ["Resolve Lazy Bindings=true"],
    onlyProcedures: undefined,
    parseObjectiveC: undefined,
    parseSwift: undefined,
    parseExceptions: undefined,
    closeAfterExport: false,
    waitForAnalysis: undefined,
    fullExport: undefined,
    includePseudocode: undefined,
    maxPseudocodeFunctions: undefined,
  });
});

test("live bridge CLI main guard treats symlinked temp paths as the same file", () => {
  const main = isMainModule("file:///private/var/folders/aa/bb/T/pkg/src/live-bridge-cli.js", "/var/folders/aa/bb/T/pkg/src/live-bridge-cli.js", {
    resolvePath: (value) => value,
    realpathPath: (value) => value.replace("/var/", "/private/var/"),
  });

  assert.equal(main, true);
});

function collect(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}
