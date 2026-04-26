// Research/forensics tests — analyze_binary kinds, compute_fingerprints, find_similar_functions, diff_sessions.

import test from "node:test";
import assert from "node:assert/strict";
import { startServer, startWithSample, sampleSession, decodeToolResult } from "./fixtures/index.mjs";

const BIN = "/bin/echo";

// ── 1. analyze_binary — all 5 kinds against a real binary ────────────────────

for (const kind of ["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]) {
  test(`analyze_binary({kind:'${kind}'}) on ${BIN} returns a value`, async () => {
    const h = await startServer();
    try {
      await h.call("import_macho", { executable_path: BIN });
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.ok(out !== null && typeof out === "object", `${kind} returned non-object`);
      // per-kind shape check:
      switch (kind) {
        case "capabilities":
          // classifyImports returns { [bucket]: string[] } — each value is a sorted string[].
          // /bin/echo may have very few imports; but the result must be an object (possibly empty).
          assert.ok(
            Object.values(out).every(v => Array.isArray(v)),
            `capabilities: all bucket values should be arrays, got ${JSON.stringify(out)}`,
          );
          break;
        case "anti_analysis":
          // detectAntiAnalysis returns an array of finding objects (possibly empty for /bin/echo).
          assert.ok(Array.isArray(out), `anti_analysis should return an array`);
          break;
        case "entropy":
          // computeSectionEntropy returns an array of section objects, each with an entropy field.
          assert.ok(Array.isArray(out), `entropy should return an array of section objects`);
          if (out.length > 0) {
            const sec = out[0];
            assert.ok(typeof sec.entropy === "number", `entropy[0].entropy should be a number`);
            assert.ok(typeof sec.suspicious === "boolean", `entropy[0].suspicious should be a boolean`);
            assert.ok(typeof sec.sectname === "string", `entropy[0].sectname should be a string`);
          }
          break;
        case "code_signing":
          // extractCodeSigning returns { signed: boolean, format, signer, teamId, identifier, cdHash, flags, entitlements, error }
          assert.ok(typeof out.signed === "boolean",
            `code_signing should expose a signed boolean, got ${JSON.stringify(out)}`);
          break;
        case "objc":
          // analyze_binary(objc) returns { count: number, classes: array }
          assert.ok(typeof out.count === "number",
            `objc should expose a count number, got ${JSON.stringify(out)}`);
          assert.ok(Array.isArray(out.classes),
            `objc should expose a classes array, got ${JSON.stringify(out)}`);
          assert.equal(out.count, out.classes.length,
            `objc count should equal classes.length`);
          break;
      }
    } finally { await h.close(); }
  });
}

// ── 2a. compute_fingerprints — fingerprints all session functions and returns stable updated count ──

test("compute_fingerprints fingerprints all session functions and returns a stable updated count", async () => {
  const h = await startWithSample();
  try {
    const r1 = decodeToolResult(await h.call("compute_fingerprints", { session_id: h.sessionId }));
    assert.ok(typeof r1.updated === "number" && r1.updated >= 1,
      `expected updated >= 1, got ${r1.updated}`);
    const r2 = decodeToolResult(await h.call("compute_fingerprints", { session_id: h.sessionId }));
    assert.equal(r2.updated, r1.updated, "updated count is stable across calls on the same session");
  } finally { await h.close(); }
});

// ── 2b. find_similar_functions — exposes a per-function fingerprint with expected hash fields ──

test("find_similar_functions exposes a per-function fingerprint with expected hash fields", async () => {
  // The function at 0x100003f50 has imports + strings + basicBlocks, giving a rich fingerprint.
  const ADDR = "0x100003f50";
  const h = await startWithSample();
  try {
    await h.call("compute_fingerprints", { session_id: h.sessionId });
    const sim = decodeToolResult(
      await h.call("find_similar_functions", {
        addr: ADDR,
        session_id: h.sessionId,
        min_similarity: 0,
      })
    );
    const fp = sim.target.fingerprint;
    assert.ok(fp !== null && typeof fp === "object", "target.fingerprint is an object");

    // cfgShape: "bb:N/callees:N/callers:N" string
    assert.ok(typeof fp.cfgShape === "string", "fp.cfgShape is a string");
    assert.ok(/^bb:\d+\/callees:\d+\/callers:\d+$/.test(fp.cfgShape),
      `fp.cfgShape should match bb:N/callees:N/callers:N, got ${fp.cfgShape}`);

    // importSignature: string[] (up to 32 elements)
    assert.ok(Array.isArray(fp.importSignature), "fp.importSignature is an array");

    // simhash: "0x" followed by exactly 16 hex chars (64-bit simhash64 result)
    assert.ok(typeof fp.simhash === "string" && /^0x[0-9a-f]{16}$/i.test(fp.simhash),
      `fp.simhash should be 0x + 16 hex chars, got ${fp.simhash}`);

    // minhash: number[] of exactly 32 elements (minhashSignature k=32)
    assert.ok(Array.isArray(fp.minhash), "fp.minhash is an array");
    assert.equal(fp.minhash.length, 32, `fp.minhash should have 32 elements, got ${fp.minhash.length}`);

    // stringBag: string[] (up to 16 tokens)
    assert.ok(Array.isArray(fp.stringBag), "fp.stringBag is an array");
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
