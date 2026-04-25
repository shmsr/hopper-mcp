// Deep lifecycle / crash-resistance audit. Targets the work from the
// 10-fix audit: close_session, set_current_session, alias-fold opt-in,
// overwrite guard, durable save on signal, EPIPE non-exit, uncaughtException
// → exit 1, stdin EOF → exit 0, etc. Uses the local Mach-O importer so it
// doesn't need a live Hopper, and shells out to the server over stdio
// JSON-RPC like a real MCP host.

import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const serverScript = join(root, "src", "mcp-server.js");
const machoTargets = [
  "/bin/ls",
  "/bin/cat",
  "/usr/bin/grep",
];

const passed = [];
function pass(name) {
  passed.push(name);
  process.stderr.write(`  ✓ ${name}\n`);
}

function assert(cond, message) {
  if (!cond) throw new Error(`assertion failed: ${message}`);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}: expected ${expected}, got ${actual}`);
}

function spawnServer(storePath) {
  const child = spawn(process.execPath, [serverScript], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOPPER_MCP_STORE: storePath },
  });
  const responses = new Map();
  const stderrChunks = [];
  child.stderr.on("data", (chunk) => stderrChunks.push(chunk.toString()));

  const rl = createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let message;
    try { message = JSON.parse(line); } catch { return; }
    if (message.id !== undefined) responses.set(message.id, message);
  });

  let id = 0;
  const rpc = async (method, params = {}, { timeoutMs = 60000 } = {}) => {
    const requestId = ++id;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
    const deadline = Date.now() + timeoutMs;
    while (!responses.has(requestId)) {
      if (Date.now() > deadline) throw new Error(`rpc ${method} timed out`);
      await new Promise((r) => setTimeout(r, 5));
    }
    const response = responses.get(requestId);
    responses.delete(requestId);
    if (response.error) throw new Error(response.error.message);
    return response.result;
  };

  const callTool = async (name, args, opts) => {
    const result = await rpc("tools/call", { name, arguments: args }, opts);
    if (result.isError) throw new Error(result.content?.[0]?.text ?? "tool call failed");
    return JSON.parse(result.content[0].text);
  };

  return {
    child,
    rpc,
    callTool,
    stderr: () => stderrChunks.join(""),
    async close() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.stdin.end();
      child.kill();
      await once(child, "exit").catch(() => {});
    },
  };
}

async function initialize(server) {
  await server.rpc("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "session-lifecycle-test", version: "0.1.0" },
  });
}

async function importBinary(server, path, opts = {}) {
  return server.callTool("import_macho", { executable_path: path, max_strings: 50, ...opts });
}

const workdir = await mkdtemp(join(tmpdir(), "hopper-mcp-lifecycle-"));
const storePath = join(workdir, "store.json");

try {
  // ── 1. Multi-session open + listing ───────────────────────────────────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      const ids = [];
      for (const path of machoTargets) {
        const result = await importBinary(server, path);
        ids.push(result.session.sessionId);
      }
      assert(new Set(ids).size === machoTargets.length, "each ingest should produce a unique sessionId");
      const caps = await server.callTool("capabilities", {});
      assert(caps.sessions.length === machoTargets.length, `capabilities should list ${machoTargets.length} sessions`);
      pass("multi-binary import keeps independent sessions");
    } finally {
      await server.close();
    }
  }

  // ── 2. set_current_session pins active session ───────────────────────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      const caps = await server.callTool("capabilities", {});
      const sessionIds = caps.sessions.map((s) => s.sessionId);
      // Switch to the first session and verify it's now current.
      const set = await server.callTool("set_current_session", { session_id: sessionIds[0] });
      assertEqual(set.currentSessionId, sessionIds[0], "set_current_session did not echo new id");
      const after = await server.callTool("capabilities", {});
      assertEqual(after.currentSessionId, sessionIds[0], "capabilities did not reflect new current session");
      // Bogus id should error.
      let threw = false;
      try { await server.callTool("set_current_session", { session_id: "definitely-not-real" }); }
      catch (err) { threw = err.message.includes("No Hopper session"); }
      assert(threw, "set_current_session should reject unknown id");
      pass("set_current_session pins + rejects unknown id");
    } finally {
      await server.close();
    }
  }

  // ── 3. close_session of non-current preserves current ───────────────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      const caps = await server.callTool("capabilities", {});
      const sessionIds = caps.sessions.map((s) => s.sessionId);
      const current = caps.currentSessionId;
      const victim = sessionIds.find((id) => id !== current);
      assert(victim, "need a non-current session for this test");
      const closed = await server.callTool("close_session", { session_id: victim });
      assertEqual(closed.droppedSessionId, victim, "drop did not echo victim id");
      assertEqual(closed.currentSessionId, current, "closing non-current should not change current");
      assert(closed.sessions.length === sessionIds.length - 1, "drop did not remove from listing");
      pass("close_session of non-current preserves currentSessionId");
    } finally {
      await server.close();
    }
  }

  // ── 4. close_session of current advances to most-recent ──────────────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      const before = await server.callTool("capabilities", {});
      const previousCurrent = before.currentSessionId;
      const closed = await server.callTool("close_session", { session_id: "current" });
      assertEqual(closed.droppedSessionId, previousCurrent, "drop did not echo previous current");
      assert(closed.currentSessionId !== previousCurrent, "currentSessionId should advance after dropping current");
      assert(closed.currentSessionId, "currentSessionId should be one of the remaining sessions");
      pass("close_session of current advances to next-most-recent");
    } finally {
      await server.close();
    }
  }

  // ── 5. close_session of last session leaves currentSessionId null ────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      // Drop everything that's left.
      while (true) {
        const caps = await server.callTool("capabilities", {});
        if (caps.sessions.length === 0) break;
        await server.callTool("close_session", { session_id: "current" });
      }
      const empty = await server.callTool("capabilities", {});
      assertEqual(empty.sessions.length, 0, "all sessions should be dropped");
      assertEqual(empty.currentSessionId, null, "currentSessionId should be null when no sessions remain");
      // Closing again should error cleanly, not crash the server.
      let threw = false;
      try { await server.callTool("close_session", { session_id: "current" }); }
      catch (err) { threw = err.message.includes("No Hopper session"); }
      assert(threw, "close_session on empty store should error");
      // Server should still be alive — issue a follow-up rpc.
      const stillAlive = await server.callTool("capabilities", {});
      assertEqual(stillAlive.sessions.length, 0, "server should survive close-on-empty error");
      pass("close_session on empty store errors cleanly without crashing");
    } finally {
      await server.close();
    }
  }

  // ── 6. open_session with overwrite=false guards collisions ──────────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      const seed = await importBinary(server, machoTargets[0]);
      const sessionId = seed.session.sessionId;
      // Try to open the same id with overwrite=false → should error.
      let threw = false;
      try {
        await server.callTool("open_session", {
          session: {
            sessionId,
            binary: { name: "ls-clone", path: "/bin/ls", format: "test" },
          },
          overwrite: false,
        });
      } catch (err) { threw = err.message.includes("already exists"); }
      assert(threw, "overwrite=false should reject collisions");
      // Same call with overwrite=true should succeed.
      const replaced = await server.callTool("open_session", {
        session: {
          sessionId,
          binary: { name: "ls-clone", path: "/bin/ls", format: "test" },
        },
        overwrite: true,
      });
      assertEqual(replaced.sessionId, sessionId, "overwrite=true should replace existing session");
      pass("open_session overwrite=false guards, overwrite=true replaces");
    } finally {
      await server.close();
    }
  }

  // ── 7. fold_aliases opt-in actually folds same-path sessions ────────────
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      // First, two ingests of the same path under different ids → both kept.
      const a = await server.callTool("open_session", {
        session: { sessionId: "alias-a", binary: { name: "ls", path: "/bin/ls", format: "test-a" } },
      });
      const b = await server.callTool("open_session", {
        session: { sessionId: "alias-b", binary: { name: "ls", path: "/bin/ls", format: "test-b" } },
      });
      assertEqual(a.sessionId, "alias-a", "first session id");
      assertEqual(b.sessionId, "alias-b", "second session id");
      const before = await server.callTool("capabilities", {});
      const aliasCount = before.sessions.filter((s) => s.path === "/bin/ls").length;
      assert(aliasCount >= 2, `expected ≥2 same-path sessions before fold, got ${aliasCount}`);
      // Now ingest a third time with fold_aliases=true → should fold the
      // matching same-path sessions away.
      const folded = await server.callTool("open_session", {
        session: { sessionId: "alias-c", binary: { name: "ls", path: "/bin/ls", format: "test-c" } },
        fold_aliases: true,
      });
      assertEqual(folded.sessionId, "alias-c", "folded session id");
      const after = await server.callTool("capabilities", {});
      const remainingAliases = after.sessions.filter((s) => s.path === "/bin/ls").map((s) => s.sessionId);
      assertEqual(remainingAliases.length, 1, `expected 1 same-path session after fold, got ${remainingAliases.length}`);
      assertEqual(remainingAliases[0], "alias-c", "fold should keep the new session");
      pass("fold_aliases=true folds same-path sessions; default off");
    } finally {
      await server.close();
    }
  }

  // ── 8. SIGTERM mid-ingestion: durable save survives ──────────────────────
  {
    const sigtermStore = join(workdir, "sigterm-store.json");
    const server = spawnServer(sigtermStore);
    try {
      await initialize(server);
      await importBinary(server, machoTargets[0]);
      const before = await server.callTool("capabilities", {});
      const expectedIds = before.sessions.map((s) => s.sessionId).sort();
      // Kick off a heavier import without awaiting, then SIGTERM mid-flight.
      const inflight = importBinary(server, machoTargets[1]).catch(() => null);
      // Give the import a moment to start mutating state.
      await new Promise((r) => setTimeout(r, 50));
      server.child.kill("SIGTERM");
      await once(server.child, "exit").catch(() => {});
      await inflight; // swallow any transport rejection
      const stderr = server.stderr();
      assert(stderr.includes("received SIGTERM"), "SIGTERM handler should announce shutdown");
    } finally {
      await server.close();
    }
    // Reload store from a fresh server and verify the previously-completed
    // ingest survived.
    const reloaded = spawnServer(sigtermStore);
    try {
      await initialize(reloaded);
      const reloadedCaps = await reloaded.callTool("capabilities", {});
      assert(reloadedCaps.sessions.length >= 1, "completed-pre-SIGTERM session should reload");
    } finally {
      await reloaded.close();
    }
    pass("SIGTERM during ingest still flushes completed sessions to disk");
  }

  // ── 9. stdin EOF triggers graceful exit (exit 0) ────────────────────────
  {
    const eofStore = join(workdir, "eof-store.json");
    const server = spawnServer(eofStore);
    try {
      await initialize(server);
      await importBinary(server, machoTargets[0]);
      // Closing stdin is the canonical clean shutdown for stdio MCP.
      server.child.stdin.end();
      const [code] = await once(server.child, "exit");
      assertEqual(code, 0, "stdin EOF should exit 0");
      assert(server.stderr().includes("stdin EOF"), "stdin EOF handler should fire");
    } finally {
      // already closed
    }
    pass("stdin EOF triggers graceful exit 0");
  }

  // ── 10. Atomic write: tmp file pattern + rename ─────────────────────────
  {
    const writeStore = join(workdir, "atomic-store.json");
    const server = spawnServer(writeStore);
    try {
      await initialize(server);
      await importBinary(server, machoTargets[0]);
      // Wait for any pending background save to flush.
      await new Promise((r) => setTimeout(r, 200));
    } finally {
      await server.close();
    }
    const stats = await stat(writeStore);
    assert(stats.size > 0, "store file should exist and be non-empty");
    const text = await readFile(writeStore, "utf8");
    const parsed = JSON.parse(text);
    assert(parsed.sessions, "store should be valid JSON with sessions");
    pass("upsertSession produces a parseable JSON store on disk");
  }

  // ── 11. close_session with close_in_hopper but no live doc → no crash ───
  {
    const server = spawnServer(storePath);
    try {
      await initialize(server);
      // Open a synthetic session whose binary.name doesn't correspond to any
      // real Hopper document — close_in_hopper should swallow the error and
      // surface it via the response, not crash.
      await server.callTool("open_session", {
        session: { sessionId: "close-in-hopper-test", binary: { name: "definitely-not-open-in-hopper", path: "/tmp/fake", format: "test" } },
        overwrite: true,
      });
      const closed = await server.callTool("close_session", {
        session_id: "close-in-hopper-test",
        close_in_hopper: true,
      });
      assertEqual(closed.droppedSessionId, "close-in-hopper-test", "drop should report the id");
      assert(closed.hopperClose !== undefined, "hopperClose should be present in response");
      // Either the AppleScript ran (returns documentName) or it errored
      // (returns error string). Both are non-crash outcomes.
      pass("close_session close_in_hopper=true survives missing doc");
    } finally {
      await server.close();
    }
  }

  // ── 12. Rapid open/close cycles do not race ─────────────────────────────
  {
    const churnStore = join(workdir, "churn-store.json");
    const server = spawnServer(churnStore);
    try {
      await initialize(server);
      for (let i = 0; i < 10; i += 1) {
        const id = `churn-${i}`;
        await server.callTool("open_session", {
          session: { sessionId: id, binary: { name: id, path: `/tmp/${id}`, format: "test" } },
          overwrite: true,
        });
        await server.callTool("close_session", { session_id: id });
      }
      const empty = await server.callTool("capabilities", {});
      assertEqual(empty.sessions.length, 0, "all churn sessions should be dropped");
      pass("10× open/close cycles complete with empty final state");
    } finally {
      await server.close();
    }
  }

  // ── 13. Session state persists across server restarts ───────────────────
  {
    const persistStore = join(workdir, "persist-store.json");
    let pinnedId;
    {
      const server = spawnServer(persistStore);
      try {
        await initialize(server);
        const a = await importBinary(server, machoTargets[0]);
        const b = await importBinary(server, machoTargets[1]);
        pinnedId = a.session.sessionId;
        await server.callTool("set_current_session", { session_id: pinnedId });
        // Wait for scheduled save to flush.
        await new Promise((r) => setTimeout(r, 200));
      } finally {
        await server.close();
      }
    }
    {
      const server = spawnServer(persistStore);
      try {
        await initialize(server);
        const caps = await server.callTool("capabilities", {});
        assertEqual(caps.sessions.length, 2, "two sessions should reload");
        assertEqual(caps.currentSessionId, pinnedId, "pinned currentSessionId should reload");
      } finally {
        await server.close();
      }
    }
    pass("session state + currentSessionId persist across restarts");
  }

  // ── 14. Concurrent rpc calls do not corrupt state ───────────────────────
  {
    const concurrentStore = join(workdir, "concurrent-store.json");
    const server = spawnServer(concurrentStore);
    try {
      await initialize(server);
      const promises = [];
      for (let i = 0; i < 5; i += 1) {
        promises.push(server.callTool("open_session", {
          session: { sessionId: `concurrent-${i}`, binary: { name: `c${i}`, path: `/tmp/c${i}`, format: "test" } },
          overwrite: true,
        }));
      }
      const results = await Promise.all(promises);
      assertEqual(results.length, 5, "all concurrent opens should succeed");
      const caps = await server.callTool("capabilities", {});
      const concurrentIds = caps.sessions.map((s) => s.sessionId).filter((id) => id.startsWith("concurrent-"));
      assertEqual(concurrentIds.length, 5, "all concurrent opens should appear in listing");
    } finally {
      await server.close();
    }
    pass("5 concurrent open_session calls all land cleanly");
  }

  process.stdout.write(JSON.stringify({
    status: "session lifecycle audit ok",
    passed: passed.length,
    cases: passed,
  }, null, 2) + "\n");
} finally {
  await rm(workdir, { recursive: true, force: true }).catch(() => {});
}
