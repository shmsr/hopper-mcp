// Reproduce the 8-call batch that previously triggered a Claude Code MCP-host
// stdin EOF mid-batch. We bypass the host: spawn the server, init, fire the
// calls in true parallel (pipelined writes), then measure how long each takes
// and how big each response is. Anomalies (e.g. one call returning 5MB of
// text) would explain why a host might bail.
//
// Usage: node test/repro-disconnect.mjs [session_id]
// Default session: real-6749d899185bd74f (Cursor binary, already in store).

import { spawn } from "node:child_process";
import { once } from "node:events";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(fileURLToPath(import.meta.url), "../..");
const SERVER = resolve(REPO, "src/mcp-server.js");
const STORE = resolve(REPO, "data/knowledge-store.json");
const SESSION = process.argv[2] ?? "real-6749d899185bd74f";

// Same 8 calls as the failed batch, plus a 9th (find_functions) that the host
// rejected with "no such tool" after stdin EOF.
const BATCH = [
  ["capabilities", {}],
  ["procedure", { field: "info", procedure: "0x1000004c4", session_id: SESSION }],
  ["procedure", { field: "assembly", procedure: "0x1000004c4", session_id: SESSION }],
  ["search", { kind: "strings", pattern: "ELECTRON", session_id: SESSION }],
  ["search", { kind: "procedures", pattern: "sub_", session_id: SESSION }],
  ["analyze_binary", { kind: "entropy", session_id: SESSION }],
  ["analyze_binary", { kind: "objc", session_id: SESSION }],
  ["find_xrefs", { target_addr: "0x100000610", session_id: SESSION }],
  ["find_functions", { session_id: SESSION }],
];

const child = spawn(process.execPath, [SERVER], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, HOPPER_MCP_STORE: STORE, HOPPER_MCP_DEBUG: "1" },
});

let buffer = "";
const pending = new Map();
let nextId = 1;
const sizes = new Map();   // id -> response byte size
const timings = new Map(); // id -> { sentAt, doneAt }

child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
  buffer += chunk;
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx);
    buffer = buffer.slice(idx + 1);
    if (!line.trim()) continue;
    sizes.set("__bytes_in__", (sizes.get("__bytes_in__") ?? 0) + line.length + 1);
    let msg;
    try { msg = JSON.parse(line); } catch (e) {
      console.error("[parse error]", line.slice(0, 200));
      continue;
    }
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve: r, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      sizes.set(msg.id, line.length);
      const t = timings.get(msg.id);
      if (t) t.doneAt = process.hrtime.bigint();
      if (msg.error) reject(Object.assign(new Error(msg.error.message), msg.error));
      else r(msg.result);
    }
  }
});

child.stderr.on("data", (c) => process.stderr.write(`[srv] ${c}`));
child.on("exit", (code, signal) => {
  console.log(`[child exit] code=${code} signal=${signal}`);
  for (const { reject } of pending.values()) reject(new Error("child exited"));
});
child.stdin.on("error", () => {});

function send(method, params) {
  const id = nextId++;
  return {
    id,
    promise: new Promise((r, reject) => {
      pending.set(id, { resolve: r, reject });
      timings.set(id, { sentAt: process.hrtime.bigint() });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    }),
  };
}

function ms(start, end) {
  return Number((end - start) / 1_000_000n);
}

const T0 = process.hrtime.bigint();

// 1) initialize sequentially
await send("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "repro-disconnect", version: "0.0.0" },
}).promise;
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
console.log(`[t+${ms(T0, process.hrtime.bigint())}ms] initialized`);

// 2) fire all batch calls in parallel — pipelined writes, then await
const inflight = BATCH.map(([name, args]) => {
  const req = send("tools/call", { name, arguments: args });
  return { name, args, ...req };
});
console.log(`[t+${ms(T0, process.hrtime.bigint())}ms] dispatched ${inflight.length} calls in parallel`);

const settled = await Promise.allSettled(inflight.map((x) => x.promise));

const T1 = process.hrtime.bigint();
console.log(`[t+${ms(T0, T1)}ms] all settled\n`);

// 3) report per-call
console.log("id  status     ms    size  tool                  args");
console.log("--  --------  ----  ------  --------------------  ---------");
for (let i = 0; i < inflight.length; i++) {
  const { id, name, args } = inflight[i];
  const t = timings.get(id);
  const elapsed = t?.doneAt ? ms(t.sentAt, t.doneAt) : -1;
  const size = sizes.get(id) ?? 0;
  const status = settled[i].status === "fulfilled" ? "ok" : "ERR";
  const argstr = JSON.stringify(args).slice(0, 60);
  const detail = settled[i].status === "rejected" ? `  ! ${settled[i].reason?.message}` : "";
  console.log(
    `${String(id).padStart(2)}  ${status.padEnd(8)}  ${String(elapsed).padStart(4)}  ${String(size).padStart(6)}  ${name.padEnd(20)}  ${argstr}${detail}`,
  );
}

console.log(`\ntotal stdout bytes: ${sizes.get("__bytes_in__") ?? 0}`);
console.log(`total wall: ${ms(T0, T1)}ms`);

// 4) clean shutdown
child.stdin.end();
if (child.exitCode === null) {
  try { await once(child, "exit"); } catch {}
}
