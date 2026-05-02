#!/usr/bin/env node
import {
  cleanupCommandsFromEnv,
  cleanupHopperState,
  cleanupTimingFromEnv,
} from "../src/hopper-cleanup.js";

const result = await main();
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = result.ok ? 0 : 1;

async function main() {
  try {
    const commands = cleanupCommandsFromEnv();
    const { timeoutMs, pollMs } = cleanupTimingFromEnv();
    await cleanupHopperState({
      ...commands,
      timeoutMs,
      pollMs,
    });
    return {
      ok: true,
      phase: "complete",
    };
  } catch (error) {
    return {
      ok: false,
      phase: "cleanup",
      message: error?.message ?? String(error),
    };
  }
}
