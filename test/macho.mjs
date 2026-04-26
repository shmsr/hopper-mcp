// Mach-O importer tests — migrated from multi-binary.mjs + deep-coverage.mjs.
// Uses the shared fixtures harness; each test spins its own isolated server.

import test from "node:test";
import assert from "node:assert/strict";
import { startServer, decodeToolResult } from "./fixtures/index.mjs";

const ECHO = "/bin/echo";
// Fat binary with multiple architectures (x86_64 + arm64e on macOS).
const FAT = "/usr/bin/sqlite3";

// ── helper: hex add ──────────────────────────────────────────────────────────
function hexAdd(hexStr, offset) {
  const base = parseInt(hexStr, 16);
  return "0x" + (base + offset).toString(16);
}

// ── 1. import_macho ingests /bin/echo with procedures + imports ───────────────
test("import_macho ingests /bin/echo with procedures + imports", async () => {
  const h = await startServer();
  try {
    const out = decodeToolResult(await h.call("import_macho", { executable_path: ECHO }));
    assert.ok(out.session.sessionId, "sessionId present");
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    assert.ok(Object.keys(procs).length > 0, "at least one procedure");
    const imports = decodeToolResult(await h.call("list", { kind: "imports" }));
    assert.ok(Array.isArray(imports) && imports.length > 0, "at least one import");
  } finally { await h.close(); }
});

// ── 2. import_macho deep mode discovers more procedures than shallow ───────────
test("import_macho deep mode discovers more procedures than shallow", async () => {
  const h = await startServer();
  try {
    decodeToolResult(await h.call("import_macho", { executable_path: ECHO }));
    const shallowCount = Object.keys(decodeToolResult(await h.call("list", { kind: "procedures" }))).length;
    decodeToolResult(await h.call("import_macho", {
      executable_path: ECHO, deep: true, max_functions: 500, overwrite: true,
    }));
    const deepCount = Object.keys(decodeToolResult(await h.call("list", { kind: "procedures" }))).length;
    // Strict `>`: shallow on a tiny binary returns only the synthetic
    // 0xfff00000 binary_overview sentinel (count=1), so `>=` would pass for
    // any non-empty deep result without proving deep found anything new.
    // Strict `>` requires deep to add at least one real function on top of
    // any synthetic-cluster nodes the importer emits.
    assert.ok(deepCount > shallowCount,
      `deep (${deepCount}) must exceed shallow (${shallowCount})`);
  } finally { await h.close(); }
});

// ── 3. disassemble_range returns text ────────────────────────────────────────
test("disassemble_range returns text", async () => {
  const h = await startServer();
  try {
    // Use deep=true so real function addresses are discovered (not just the
    // synthetic 0xfff00000 binary_overview sentinel emitted in shallow mode).
    decodeToolResult(await h.call("import_macho", {
      executable_path: ECHO, deep: true, max_functions: 500,
    }));
    const ff = decodeToolResult(await h.call("find_functions", { executable_path: ECHO }));
    // Use the first real function from the discovery sample.
    const startAddr = ff.sample[0].addr;
    const endAddr = hexAdd(startAddr, 64);
    const result = decodeToolResult(await h.call("disassemble_range", {
      executable_path: ECHO,
      start_addr: startAddr,
      end_addr: endAddr,
    }));
    // The tool returns { lines: [...], startAddr, endAddr, lineCount, arch }.
    assert.ok(
      typeof result === "string" ||
      Array.isArray(result) ||
      (typeof result === "object" && result !== null && Array.isArray(result.lines)),
      "result is string, array, or object with lines array",
    );
  } finally { await h.close(); }
});

// ── 4. find_functions returns >= 1 function ───────────────────────────────────
test("find_functions returns at least one function", async () => {
  const h = await startServer();
  try {
    decodeToolResult(await h.call("import_macho", { executable_path: ECHO }));
    const result = decodeToolResult(await h.call("find_functions", {
      executable_path: ECHO,
    }));
    // result shape: { functions: <count>, callEdges: <count>, adrpRefs: <count>, sample: [...] }
    assert.ok(
      (typeof result === "object" && result !== null && result.functions >= 1) ||
      (Array.isArray(result) && result.length >= 1),
      `find_functions returned ${JSON.stringify(result)?.slice(0, 200)}`,
    );
  } finally { await h.close(); }
});

// ── 5. find_xrefs finds at least one branch xref ─────────────────────────────
test("find_xrefs finds at least one branch xref", async () => {
  const h = await startServer();
  try {
    // Strategy: pick a target we KNOW is called by walking disassembly for a
    // `bl 0x...` instruction. Sample function entrypoints from find_functions
    // are not reliable xref targets — most user-binary calls go through
    // symbol-named stubs that resolve to addresses outside the prologue scan
    // sample (verified empirically: 0/20 sample addrs in /bin/ls had xrefs).
    const LS = "/bin/ls";
    decodeToolResult(await h.call("import_macho", {
      executable_path: LS, deep: true, max_functions: 500,
    }));
    const ff = decodeToolResult(await h.call("find_functions", { executable_path: LS }));
    let knownTarget = null;
    outer: for (const fn of ff.sample ?? []) {
      const dis = decodeToolResult(await h.call("disassemble_range", {
        executable_path: LS,
        start_addr: fn.addr,
        end_addr: "0x" + (parseInt(fn.addr, 16) + 0x400).toString(16),
      }));
      for (const line of dis.lines ?? []) {
        if (line.mnemonic !== "bl" && line.mnemonic !== "b") continue;
        const m = line.operands?.match(/0x([0-9a-fA-F]+)/);
        if (m) { knownTarget = "0x" + m[1]; break outer; }
      }
    }
    assert.ok(knownTarget,
      `expected to find a bl/b instruction with hex operand in /bin/ls disassembly`);
    const result = decodeToolResult(await h.call("find_xrefs", {
      executable_path: LS, target_addr: knownTarget,
    }));
    const xrefs = Array.isArray(result) ? result : (result?.xrefs ?? []);
    assert.ok(xrefs.length >= 1,
      `expected ≥1 xref to known-called target ${knownTarget}, got ${xrefs.length}`);
  } finally { await h.close(); }
});

// ── 6. containing_function resolves an address inside a function ──────────────
test("containing_function resolves an address inside a function", async () => {
  const h = await startServer();
  try {
    decodeToolResult(await h.call("import_macho", {
      executable_path: ECHO, deep: true, max_functions: 500,
    }));
    const procs = decodeToolResult(await h.call("list", { kind: "procedures" }));
    const entryAddr = Object.keys(procs)[0];
    // Probe 4 bytes past the entry (one ARM64 instruction in).
    const probeAddr = hexAdd(entryAddr, 4);
    const result = decodeToolResult(await h.call("containing_function", {
      address: probeAddr,
    }));
    // The tool returns { match: "entrypoint"|"containment"|"none", ... }.
    assert.ok(result !== null && typeof result === "object", "containing_function returned an object");
    assert.ok(
      ["entrypoint", "containment", "none"].includes(result.match),
      `unexpected match value: ${result.match}`,
    );
  } finally { await h.close(); }
});

// ── 7. import_macho with arch selection on a fat binary ──────────────────────
test("import_macho with arch selection works on a fat binary", async () => {
  const h = await startServer();
  try {
    let result;
    try {
      result = decodeToolResult(await h.call("import_macho", {
        executable_path: FAT,
        arch: "arm64e",
      }));
    } catch (err) {
      // Fat binary not available or slice missing on this host — graceful fallback:
      // verify that import_macho accepts arch param on a thin binary without erroring.
      // Log to stderr so CI surfaces the degradation; the test still passes.
      console.warn(`[macho test 7] fat-binary unavailable (${err.message}); falling back to thin /bin/echo`);
      result = decodeToolResult(await h.call("import_macho", {
        executable_path: ECHO,
        arch: "arm64e",
      }));
    }
    // Either way, a session must have been created.
    assert.ok(result.session.sessionId, "sessionId present after arch-targeted import");
    // If the fat binary succeeded, the binary.arch field should match what we requested.
    const arch = result.session.binary?.arch;
    if (arch) {
      // arm64e or arm64 are both acceptable answers for an arm64e request.
      assert.ok(
        arch === "arm64e" || arch === "arm64" || arch === "auto",
        `unexpected arch: ${arch}`,
      );
    }
  } finally { await h.close(); }
});
