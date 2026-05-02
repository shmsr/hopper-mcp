#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ingestWithLiveHopper } from "./hopper-live.js";

if (isMainModule(import.meta.url)) {
  await main();
}

async function main() {
  try {
    const input = await readStdinJson();
    const live = await ingestWithLiveHopper(toLiveOptions(input));
    process.stdout.write(`${JSON.stringify({
      session: live.session,
      launch: live.launch,
      diagnostics: {
        backend: "node-live-bridge",
      },
    })}\n`);
  } catch (error) {
    const payload = {
      error: {
        code: error?.code ?? (error instanceof SyntaxError ? "invalid_json" : "live_bridge_failed"),
        message: String(error?.message ?? error),
      },
    };
    process.stdout.write(`${JSON.stringify(payload)}\n`);
    process.exitCode = 1;
  }
}

export function isMainModule(importMetaUrl, argv1 = process.argv[1], {
  resolvePath = resolve,
  realpathPath = defaultRealpathPath,
} = {}) {
  if (!argv1) return false;
  const entryPath = realpathPath(resolvePath(argv1));
  return importMetaUrl === pathToFileURL(entryPath).href;
}

function defaultRealpathPath(path) {
  try {
    return realpathSync.native(path);
  } catch {
    return path;
  }
}

async function readStdinJson() {
  const text = await readStdin();
  try {
    return JSON.parse(text);
  } catch (error) {
    error.code = "invalid_json";
    throw error;
  }
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let text = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      text += chunk;
    });
    process.stdin.on("error", reject);
    process.stdin.on("end", () => resolve(text));
  });
}

export function toLiveOptions(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw Object.assign(new Error("Live bridge request must be a JSON object."), {
      code: "invalid_request",
    });
  }
  return {
    executablePath: input.executable_path,
    timeoutMs: input.timeout_ms,
    maxFunctions: input.max_functions,
    maxStrings: input.max_strings,
    maxBlocksPerFunction: input.max_blocks_per_function,
    maxInstructionsPerBlock: input.max_instructions_per_block,
    analysis: input.analysis,
    loader: input.loader,
    loaderCheckboxes: input.loader_checkboxes,
    onlyProcedures: input.only_procedures,
    parseObjectiveC: input.parse_objective_c,
    parseSwift: input.parse_swift,
    parseExceptions: input.parse_exceptions,
    closeAfterExport: input.close_after_export ?? false,
    waitForAnalysis: input.wait_for_analysis,
    fullExport: input.full_export,
    includePseudocode: input.include_pseudocode,
    maxPseudocodeFunctions: input.max_pseudocode_functions,
  };
}
