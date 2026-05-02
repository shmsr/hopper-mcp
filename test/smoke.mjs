import test from "node:test";
import assert from "node:assert/strict";
import { startWithSample, decodeToolResult } from "./fixtures/index.mjs";

const STATIC_RESOURCES = [
  "hopper://session/current",
  "hopper://binary/metadata",
  "hopper://binary/imports",
  "hopper://binary/exports",
  "hopper://binary/strings",
  "hopper://binary/capabilities",
  "hopper://binary/signing",
  "hopper://binary/entropy",
  "hopper://anti-analysis",
  "hopper://tags",
  "hopper://hypotheses",
  "hopper://names",
  "hopper://bookmarks",
  "hopper://comments",
  "hopper://inline-comments",
  "hopper://cursor",
  "hopper://functions",
  "hopper://objc/classes",
  "hopper://swift/symbols",
  "hopper://transactions/pending",
];

test("smoke: capabilities returns a session", async () => {
  const h = await startWithSample();
  try {
    const caps = decodeToolResult(await h.call("capabilities", {}));
    assert.ok(caps.sessions && caps.sessions.length >= 1);
  } finally { await h.close(); }
});

for (const uri of STATIC_RESOURCES) {
  test(`smoke: read ${uri}`, async () => {
    const h = await startWithSample();
    try {
      const res = await h.readResource(uri);
      assert.ok(res.contents && res.contents.length > 0);
    } finally { await h.close(); }
  });
}
