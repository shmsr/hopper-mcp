// Structured NDJSON debug logger. Default: ON, writing to
// <repo>/data/debug.log relative to this file. The default makes diagnostics
// available without depending on MCP-host env-var propagation, which some
// hosts (Claude Code) cache for the lifetime of the session.
//
// Override knobs:
//   HOPPER_MCP_DEBUG_LOG=/abs/path.log  — write records to this path instead
//   HOPPER_MCP_DEBUG=stderr             — additionally mirror to stderr
//   HOPPER_MCP_DEBUG=0                  — disable entirely (kill switch)
//
// Records are single-line JSON: { ts, pid, kind, ... }. Tool calls get
// matched start/end pairs via a monotonic id so concurrent calls can be
// disambiguated, and a counter of in-flight calls is included so we can
// see when the server is under fan-out load.
//
// Crash sentinels (uncaughtException, unhandledRejection, SIGTERM, EPIPE)
// emit records that include a snapshot of currently in-flight tools — the
// single most useful signal for diagnosing "the MCP died and I don't know
// which call killed it".

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ENABLED = process.env.HOPPER_MCP_DEBUG !== "0";
const MIRROR_STDERR = process.env.HOPPER_MCP_DEBUG === "stderr" || process.env.HOPPER_MCP_DEBUG === "1";
const LOG_FILE = ENABLED ? resolveLogFile() : null;

function resolveLogFile() {
  if (process.env.HOPPER_MCP_DEBUG_LOG) return process.env.HOPPER_MCP_DEBUG_LOG;
  // Default path: <repo>/data/debug.log, computed from this module's location.
  const here = fileURLToPath(import.meta.url);
  const repo = resolve(here, "..", "..");
  return resolve(repo, "data", "debug.log");
}

if (LOG_FILE) {
  try {
    mkdirSync(dirname(LOG_FILE), { recursive: true });
  } catch {}
}

const inFlight = new Map(); // id -> { name, startedAt, args }
let nextId = 1;

function emit(record) {
  if (!ENABLED) return;
  const line =
    JSON.stringify({ ts: new Date().toISOString(), pid: process.pid, ...record }) + "\n";
  if (MIRROR_STDERR) {
    try {
      process.stderr.write(line);
    } catch {}
  }
  if (LOG_FILE) {
    try {
      appendFileSync(LOG_FILE, line);
    } catch {}
  }
}

export function debugLog(record) {
  emit(record);
}

export function isDebugEnabled() {
  return ENABLED;
}

export function debugLogPath() {
  return LOG_FILE;
}

// Wrap a tool handler so every call emits matched start/end (or error)
// records. No-op when debugging is disabled.
export function wrapToolHandler(name, handler) {
  if (!ENABLED) return handler;
  return async function instrumented(args, extra) {
    const id = nextId++;
    const startedAt = process.hrtime.bigint();
    const summary = summarizeArgs(args);
    inFlight.set(id, { name, startedAt, args: summary });
    emit({ kind: "tool_start", id, name, args: summary, inFlight: inFlight.size });
    try {
      const result = await handler(args, extra);
      const ms = elapsedMs(startedAt);
      emit({ kind: "tool_end", id, name, ms, ok: true });
      return result;
    } catch (err) {
      const ms = elapsedMs(startedAt);
      emit({
        kind: "tool_error",
        id,
        name,
        ms,
        code: err?.code ?? null,
        message: err?.message ?? String(err),
        stack: err?.stack ?? null,
      });
      throw err;
    } finally {
      inFlight.delete(id);
    }
  };
}

// Best-effort: dump all in-flight tool calls when the server is going down,
// so we can see "ingest_live_hopper at 12.3s" if that was the call that killed us.
export function snapshotInFlight() {
  const now = process.hrtime.bigint();
  return Array.from(inFlight.entries()).map(([id, entry]) => ({
    id,
    name: entry.name,
    args: entry.args,
    runningMs: Number((now - entry.startedAt) / 1_000_000n),
  }));
}

function elapsedMs(startedAt) {
  return Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
}

// Truncate strings/large arrays so a single fat argument can't bloat every
// log line. We only keep enough to identify the call.
function summarizeArgs(args) {
  if (!args || typeof args !== "object") return args;
  const out = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === "string") {
      out[k] = v.length > 200 ? v.slice(0, 200) + "…" : v;
    } else if (Array.isArray(v)) {
      out[k] = v.length > 20 ? `[Array len=${v.length}]` : v;
    } else if (v && typeof v === "object") {
      const keys = Object.keys(v);
      out[k] = keys.length > 20 ? `{Object keys=${keys.length}}` : v;
    } else {
      out[k] = v;
    }
  }
  return out;
}
