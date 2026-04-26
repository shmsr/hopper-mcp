// Research/forensics tests — analyze_binary kinds, compute_fingerprints, find_similar_functions, diff_sessions.

import test from "node:test";
import assert from "node:assert/strict";
import { startServer, startWithSample, sampleSession, decodeToolResult } from "./fixtures/index.mjs";

const BIN = "/bin/echo";
// /usr/bin/security is richer for code_signing (entitlements, etc.) but falls back to /bin/echo.
const SIGNING_BIN = "/usr/bin/security";

// ── 1. analyze_binary — all 5 kinds against a real binary ────────────────────

for (const kind of ["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]) {
  test(`analyze_binary({kind:'${kind}'}) on ${BIN} returns a value`, async () => {
    const h = await startServer();
    try {
      await h.call("import_macho", { executable_path: BIN });
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.notEqual(out, null);
    } finally { await h.close(); }
  });
}

// ── 2. compute_fingerprints — deterministic across two calls ──────────────────
// NOTE: compute_fingerprints({session_id}) takes no addr — it fingerprints all
// functions in the session and returns { updated: N }. The plan template assumed
// an addr arg that does not exist in the implementation.

test("compute_fingerprints produces deterministic per-function hashes", async () => {
  const { sessionId, ...h } = await startWithSample();
  // The function at 0x100003f50 has imports + strings + basicBlocks, giving a rich fingerprint.
  const ADDR = "0x100003f50";
  try {
    // First round: fingerprint all functions, then retrieve the per-function hash via
    // find_similar_functions — the only public tool that returns target.fingerprint.
    const r1 = decodeToolResult(await h.call("compute_fingerprints", { session_id: sessionId }));
    assert.ok(typeof r1.updated === "number" && r1.updated >= 1,
      `expected updated >= 1, got ${r1.updated}`);
    const sim1 = decodeToolResult(
      await h.call("find_similar_functions", {
        addr: ADDR,
        session_id: sessionId,
        min_similarity: 0,
      })
    );
    const fp1 = sim1.target.fingerprint;
    assert.ok(fp1 !== null && typeof fp1 === "object", "first fingerprint is an object");

    // Second round: recompute and retrieve again.
    const r2 = decodeToolResult(await h.call("compute_fingerprints", { session_id: sessionId }));
    assert.equal(r2.updated, r1.updated, "updated count is stable across calls");
    const sim2 = decodeToolResult(
      await h.call("find_similar_functions", {
        addr: ADDR,
        session_id: sessionId,
        min_similarity: 0,
      })
    );
    const fp2 = sim2.target.fingerprint;

    // Core determinism assertion: the actual hash bytes must be identical.
    assert.deepEqual(fp1, fp2, "fingerprint hashes are byte-identical across two compute_fingerprints calls");
  } finally { await h.close(); }
});

// ── 3. find_similar_functions — returns ≥1 match across two identical sessions ─

test("find_similar_functions returns at least one match across two identical sessions", async () => {
  const h = await startServer();
  try {
    // Open two sessions with identical function shapes so fingerprints overlap.
    const s1 = decodeToolResult(
      await h.call("open_session", { session: { ...sampleSession(), sessionId: "sess-A" } })
    );
    const s2 = decodeToolResult(
      await h.call("open_session", { session: { ...sampleSession(), sessionId: "sess-B" } })
    );

    // Fingerprint both sessions so similarity scores can be computed.
    await h.call("compute_fingerprints", { session_id: s1.sessionId });
    await h.call("compute_fingerprints", { session_id: s2.sessionId });

    // Query from sess-A, first function (has a rich fingerprint with imports + strings).
    const ADDR = "0x100003f50";
    const result = decodeToolResult(
      await h.call("find_similar_functions", {
        addr: ADDR,
        session_id: s1.sessionId,
        target_session_id: s2.sessionId,
        min_similarity: 0.1,
      })
    );

    assert.ok(typeof result === "object" && result !== null, "result is an object");
    assert.ok(Array.isArray(result.matches), "result.matches is an array");
    assert.ok(result.matches.length >= 1,
      `expected >= 1 match, got ${result.matches.length}: ${JSON.stringify(result.matches)}`);
  } finally { await h.close(); }
});

// ── 4. diff_sessions — empty left vs populated right contains expected adds ───

test("diff_sessions between empty and populated session reports added functions", async () => {
  const h = await startServer();
  try {
    // Left: minimal empty session.
    const empty = decodeToolResult(
      await h.call("open_session", {
        session: { sessionId: "empty-left", binary: { name: "empty", arch: "arm64" } },
      })
    );
    // Right: populated sample session with 3 functions.
    const populated = decodeToolResult(
      await h.call("open_session", { session: { ...sampleSession(), sessionId: "populated-right" } })
    );

    const diff = decodeToolResult(
      await h.call("diff_sessions", {
        left_session_id: empty.sessionId,
        right_session_id: populated.sessionId,
      })
    );

    assert.ok(typeof diff === "object" && diff !== null, "diff is an object");
    assert.ok(typeof diff.summary === "object", "diff has summary");
    // The right session has 3 functions; all are absent from the left.
    assert.equal(diff.summary.onlyInRight, 3,
      `expected 3 functions only in right, got ${diff.summary.onlyInRight}`);
    assert.equal(diff.summary.onlyInLeft, 0,
      `expected 0 functions only in left, got ${diff.summary.onlyInLeft}`);
    // Verify the functions.onlyInRight array carries the actual entries.
    assert.ok(Array.isArray(diff.functions?.onlyInRight), "functions.onlyInRight is an array");
    assert.equal(diff.functions.onlyInRight.length, 3,
      `expected 3 entries in functions.onlyInRight`);
  } finally { await h.close(); }
});
