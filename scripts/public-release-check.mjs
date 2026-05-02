#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const pkg = JSON.parse(await readFile(join(repoRoot, "package.json"), "utf8"));
const archive = join(
  repoRoot,
  "dist",
  `${pkg.name}-${pkg.version}-${process.platform}-${process.arch}.tar.gz`,
);

const cargoCommand = process.env.HOPPER_MCP_PUBLIC_RELEASE_CARGO || "cargo";
const npmCommand = process.env.HOPPER_MCP_PUBLIC_RELEASE_NPM || "npm";

const result = await main();
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = result.ok ? 0 : 1;

async function main() {
  try {
    await run("doctor", cargoCommand, [
      "run",
      "-p",
      "hopper-mcpd",
      "--",
      "doctor",
      "--json",
      "--require-distribution-identity",
      "--require-notary-credentials",
      "--require-clean-git-tree",
    ]);
    await run("distribution", npmCommand, ["run", "release:check:distribution"]);
    await run("notarize", npmCommand, ["run", "package:notarize", "--", archive]);
    return {
      ok: true,
      phase: "complete",
      archive,
    };
  } catch (error) {
    return {
      ok: false,
      phase: error.phase ?? "unknown",
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
      cwd: repoRoot,
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
