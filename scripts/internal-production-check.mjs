#!/usr/bin/env node
import { spawn } from "node:child_process";

const npmCommand = process.env.HOPPER_MCP_INTERNAL_PRODUCTION_NPM || "npm";

const result = await main();
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = result.ok ? 0 : 1;

async function main() {
  try {
    await run("releaseCheck", npmCommand, ["run", "release:check"]);
    await run("live", npmCommand, ["run", "release:check:live"]);
    await run("privateBackend", npmCommand, ["run", "release:check:private-backend"]);
    return {
      ok: true,
      phase: "complete",
      profile: "internal",
    };
  } catch (error) {
    return {
      ok: false,
      phase: error.phase ?? "unknown",
      profile: "internal",
      command: error.command ?? null,
      message: error.message,
      stdoutTail: error.stdoutTail ?? "",
      stderrTail: error.stderrTail ?? "",
    };
  }
}

async function run(phase, command, args) {
  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stderr.write(text);
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });
    child.on("error", rejectPromise);
    child.on("close", (code) => {
      if (code === 0) resolvePromise();
      else {
        const error = new Error(`${command} ${args.join(" ")} exited with ${code}`);
        error.phase = phase;
        error.command = command;
        error.stdoutTail = tail(stdout);
        error.stderrTail = tail(stderr);
        rejectPromise(error);
      }
    });
  });
}

function tail(text, max = 4000) {
  return text.length > max ? text.slice(-max) : text;
}
