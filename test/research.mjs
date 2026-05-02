// Research/forensics tests — analyze_binary kinds, compute_fingerprints, find_similar_functions, diff_sessions.

import test from "node:test";
import assert from "node:assert/strict";
import { startServer, startWithSample, sampleSession, decodeToolResult } from "./fixtures/index.mjs";

// ── 1. analyze_binary — snapshot-only contract ───────────────────────────────

for (const kind of ["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]) {
  test(`analyze_binary({kind:'${kind}'}) returns a snapshot-derived value`, async () => {
    const h = await startWithSample();
    try {
      const out = decodeToolResult(await h.call("analyze_binary", { kind }));
      assert.ok(out !== null && typeof out === "object", `${kind} returned non-object`);
      // per-kind shape check:
      switch (kind) {
        case "capabilities":
          // classifyImports now returns {totalImports, counts, samples, truncated}
          // so a stripped-Swift binary's massive `swift` bucket can't blow the
          // host's per-tool token budget on first use.
          assert.equal(typeof out.totalImports, "number", "totalImports number");
          assert.ok(out.counts && typeof out.counts === "object", "counts present");
          assert.ok(out.samples && typeof out.samples === "object", "samples present");
          assert.ok(Array.isArray(out.truncated), "truncated array present");
          for (const [bucket, sample] of Object.entries(out.samples)) {
            assert.ok(Array.isArray(sample), `samples[${bucket}] is array`);
            assert.equal(typeof out.counts[bucket], "number", `counts[${bucket}] present`);
            assert.ok(sample.length <= out.counts[bucket], `sample <= count for ${bucket}`);
          }
          break;
        case "anti_analysis":
          // detectAntiAnalysis returns an array of finding objects (possibly empty for /bin/echo).
          assert.ok(Array.isArray(out), `anti_analysis should return an array`);
          break;
        case "entropy":
          assert.equal(out.supported, false, "entropy is unsupported without raw Hopper bytes");
          assert.equal(out.source, "hopper-snapshot");
          break;
        case "code_signing":
          assert.equal(out.supported, false, "code signing is unsupported without Hopper/export metadata");
          assert.equal(out.source, "hopper-snapshot");
          break;
        case "objc":
          assert.ok(typeof out.count === "number",
            `objc should expose a count number, got ${JSON.stringify(out)}`);
          assert.ok(Array.isArray(out.classes),
            `objc should expose a classes array, got ${JSON.stringify(out)}`);
          assert.equal(typeof out.shown, "number", "shown is a number");
          assert.equal(out.shown, out.classes.length,
            `shown should equal classes.length`);
          assert.equal(typeof out.classesTruncated, "boolean",
            "classesTruncated is a boolean");
          assert.ok(Array.isArray(out.methodsTruncated),
            "methodsTruncated is an array");
          // /bin/echo has no ObjC, so count is 0 and truncation flags are
          // off — pin both invariants.
          if (out.count === 0) {
            assert.equal(out.supported, false, "no ObjC metadata means unsupported=false");
            assert.equal(out.classesTruncated, false, "no truncation when count=0");
            assert.equal(out.methodsTruncated.length, 0, "no methods truncated when count=0");
          }
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
    // Default-capped diff still reports truncated:false on a tiny session.
    assert.equal(diff.truncated?.onlyInRight, false, "tiny diff is not truncated");
  } finally { await h.close(); }
});

// Real-binary diff (Cursor vs Raycast) used to overflow the 100KB host budget
// at 140K+ chars. max_per_bucket caps each bucket but keeps full counts in
// `summary` so the caller can paginate.
test("diff_sessions honors max_per_bucket and signals truncation per bucket", async () => {
  const h = await startServer();
  try {
    const right = sampleSession();
    // Pad right with 5 extra functions so onlyInRight clearly exceeds cap=2.
    for (let i = 0; i < 5; i++) {
      const addr = `0x10000800${i}`;
      right.functions.push({
        addr, name: `padfn_${i}`, size: 16, summary: null, confidence: 0.5,
        callers: [], callees: [], strings: [], imports: [], basicBlocks: [],
      });
    }
    const empty = decodeToolResult(
      await h.call("open_session", {
        session: { sessionId: "diff-empty-left", binary: { name: "empty", arch: "arm64" } },
      }),
    );
    const populated = decodeToolResult(
      await h.call("open_session", { session: { ...right, sessionId: "diff-padded-right" } }),
    );
    const diff = decodeToolResult(
      await h.call("diff_sessions", {
        left_session_id: empty.sessionId,
        right_session_id: populated.sessionId,
        max_per_bucket: 2,
      }),
    );
    // 3 sample fns + 5 padded = 8 onlyInRight; cap=2 trims to 2 with truncated flag.
    assert.equal(diff.summary.onlyInRight, 8, "summary keeps full count");
    assert.equal(diff.functions.onlyInRight.length, 2, "bucket trimmed to cap");
    assert.equal(diff.truncated.onlyInRight, true, "truncated flag set");
    assert.equal(diff.maxPerBucket, 2, "echoes cap back");
  } finally { await h.close(); }
});

// ── 5. find_similar_functions — empty-stringBag fingerprints don't false-match ─

// Regression for the cross-binary false-positive seen on Raycast: two unrelated
// 28-byte stubs with no strings/imports used to score ~0.65 similarity because
// their minhash signatures were both [0xffffffff × 32] (the unset sentinel),
// which jaccardMinhash treated as a perfect match. Post-fix: empty-token
// fingerprints emit `minhash: null` and the minhash component scores 0.
test("find_similar_functions: empty-token target emits null minhash and avoids false matches", async () => {
  const h = await startServer();
  try {
    // Two sessions, each with one stub function: no strings, no imports, one
    // basic block, no callers/callees. Pre-fix this pair would minhash-match
    // at 1.0 just because both signatures were unset sentinels.
    const stub = (addr) => ({
      addr, name: `stub_${addr.slice(2)}`, size: 28,
      callers: [], callees: [], strings: [], imports: [],
      basicBlocks: [{ addr, summary: "trivial stub" }],
    });
    const s1 = decodeToolResult(await h.call("open_session", {
      session: {
        sessionId: "empty-A",
        binary: { name: "binA", arch: "arm64" },
        functions: [stub("0x100001000")],
      },
    }));
    const s2 = decodeToolResult(await h.call("open_session", {
      session: {
        sessionId: "empty-B",
        binary: { name: "binB", arch: "arm64" },
        functions: [stub("0x200002000")],
      },
    }));
    await h.call("compute_fingerprints", { session_id: s1.sessionId });
    await h.call("compute_fingerprints", { session_id: s2.sessionId });

    const result = decodeToolResult(await h.call("find_similar_functions", {
      addr: "0x100001000",
      session_id: s1.sessionId,
      target_session_id: s2.sessionId,
      min_similarity: 0,
    }));

    // Target fingerprint records null minhash for empty token sets.
    assert.equal(result.target.fingerprint.minhash, null,
      `expected target.fingerprint.minhash === null for empty stringBag, got ${JSON.stringify(result.target.fingerprint.minhash)}`);

    // Any reported match must score 0 on the minhash component (not 1.0).
    for (const m of result.matches) {
      assert.equal(m.components.minhash, 0,
        `unexpected non-zero minhash component for empty-token match: ${JSON.stringify(m)}`);
    }
  } finally { await h.close(); }
});

// ── 6. analyze_function_deep — unknown callees collapse to thin {addr, known:false} ─

// Regression for the Raycast bloat: analyze_function_deep on a function with
// many unresolved callees used to embed a verbose null-padded placeholder per
// missing addr (5 fields + a 60-char "Referenced function not present in the
// current local slice." summary), inflating responses by ~14 KB on functions
// like main with 59/61 unknown callees. Post-fix: unknown refs are
// `{addr, known:false}` with no other fields.
test("analyze_function_deep: unknown callees serialize as thin {addr, known:false} stubs", async () => {
  const h = await startServer();
  try {
    // One known caller pointing at one unknown callee address. The callee
    // address is intentionally absent from session.functions so it routes
    // through getFunctionIfKnown's not-found branch.
    const session = decodeToolResult(await h.call("open_session", {
      session: {
        sessionId: "unknown-callees",
        binary: { name: "stubBin", arch: "arm64" },
        functions: [{
          addr: "0x100001000", name: "caller", size: 32,
          callers: [], callees: ["0xdeadbeef"],
          strings: [], imports: [],
          basicBlocks: [{ addr: "0x100001000", summary: "calls one external" }],
        }],
      },
    }));

    const out = decodeToolResult(await h.call("analyze_function_deep", {
      addr: "0x100001000",
      session_id: session.sessionId,
    }));

    assert.ok(Array.isArray(out.callees), "callees is an array");
    assert.equal(out.callees.length, 1, "exactly one callee in fixture");
    const cee = out.callees[0];
    assert.equal(cee.known, false, `unknown callee should carry known:false, got ${JSON.stringify(cee)}`);
    assert.equal(cee.addr, "0xdeadbeef", "addr preserved on thin stub");
    // Thin shape: only {addr, known} — no name/size/summary/confidence/fingerprint padding.
    const keys = Object.keys(cee).sort();
    assert.deepEqual(keys, ["addr", "known"],
      `unknown callee should expose only {addr, known}, got keys ${JSON.stringify(keys)}`);

    // get_graph_slice walks the same path; assert the unknown addr surfaces
    // as a thin stub there too so a regression in either codepath gets caught.
    const graph = decodeToolResult(await h.call("get_graph_slice", {
      seed: "0x100001000", radius: 1, kind: "callees", session_id: session.sessionId,
    }));
    const unknownNode = graph.nodes.find((n) => n.addr === "0xdeadbeef");
    assert.ok(unknownNode, `expected 0xdeadbeef node in callees graph; got ${JSON.stringify(graph.nodes)}`);
    assert.equal(unknownNode.known, false, "graph node for unknown ref carries known:false");
    assert.deepEqual(Object.keys(unknownNode).sort(), ["addr", "known"],
      `graph node for unknown ref should be thin, got ${JSON.stringify(unknownNode)}`);
  } finally { await h.close(); }
});

// ── 7. find_similar_functions surfaces the helpful resolveProcedure hint ──
// Pre-fix: passing a mid-function or unknown addr threw a bare
// "Unknown function address: 0x..." from store.getFunction, leaving Raycast
// users (who copy addrs out of disassembly) with no next step. Now it routes
// through resolveProcedure so the address branch's "not the entrypoint of any
// known function ... use 'containing_function'" message comes through.
test("find_similar_functions on unknown addr surfaces containing_function hint", async () => {
  const h = await startServer();
  try {
    await h.call("open_session", {
      session: {
        sessionId: "fsf-unknown",
        binary: { name: "stubBin", arch: "arm64" },
        functions: [{
          addr: "0x100001000", name: "only_fn", size: 64,
          callers: [], callees: [], strings: [], imports: [],
          basicBlocks: [{ addr: "0x100001000", summary: "trivial" }],
        }],
      },
    });
    await assert.rejects(
      () => h.call("find_similar_functions", {
        addr: "0xdeadbeef",
        session_id: "fsf-unknown",
        min_similarity: 0,
      }),
      /containing_function|not the entrypoint/i,
    );
  } finally { await h.close(); }
});
