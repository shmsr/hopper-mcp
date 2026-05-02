import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("release:check uses the real package release verifier", async () => {
  const scripts = await packageScripts();
  const releaseCheckScript = await readFile("scripts/release-check.mjs", "utf8");

  assert.match(scripts["clippy:rust"], /cargo clippy --workspace -- -D warnings/);
  assert.match(scripts["build:agent"], /make -C agents\/hopper-agent/);
  assert.equal(
    scripts["build:private-injection"],
    undefined,
    "obsolete private injection build script should not be exposed in package.json",
  );
  assert.match(scripts["doctor:plugin-live"], /doctor --json --require-plugin-identity/);
  assert.match(
    scripts["doctor:distribution"],
    /doctor --json --require-distribution-identity --require-clean-git-tree/,
  );
  assert.match(
    scripts["doctor:public-release"],
    /doctor --json --require-distribution-identity --require-notary-credentials --require-clean-git-tree/,
  );
  assert.match(scripts["package:release:ad-hoc"], /scripts\/package-release\.mjs --ad-hoc/);
  assert.match(scripts["hopper-plugin:install"], /scripts\/hopper-plugin-runtime\.mjs install/);
  assert.match(scripts["hopper-plugin:identities"], /scripts\/hopper-plugin-runtime\.mjs identities/);
  assert.match(scripts["hopper-plugin:probe"], /scripts\/hopper-plugin-runtime\.mjs probe/);
  assert.match(scripts["cleanup:hopper-state"], /scripts\/cleanup-hopper-state\.mjs/);
  assert.match(scripts["test"], /test\/hopper-agent\.mjs/);
  assert.match(scripts["test"], /test\/hopper-plugin-runtime\.mjs/);
  assert.match(scripts["test"], /test\/cleanup-hopper-state\.mjs/);
  assert.match(scripts["test"], /test\/release-check\.mjs/);
  assert.match(scripts["test"], /test\/plugin-live-check\.mjs/);
  assert.match(scripts["test"], /test\/distribution-check\.mjs/);
  assert.match(scripts["test"], /test\/public-release-check\.mjs/);
  assert.match(scripts["test"], /test\/private-backend-check\.mjs/);
  assert.match(scripts["test"], /test\/internal-production-check\.mjs/);
  assert.match(scripts["test"], /test\/internal-soak-check\.mjs/);
  assert.match(scripts["test"], /test\/public-production-check\.mjs/);
  assert.match(scripts["release:check"], /scripts\/release-check\.mjs/);
  assert.match(releaseCheckScript, /run\("test", npmCommand, \["run", "test"\]\)/);
  assert.match(releaseCheckScript, /run\("rustFmt", cargoCommand, \["fmt", "--check"\]\)/);
  assert.match(releaseCheckScript, /run\("clippy", npmCommand, \["run", "clippy:rust"\]\)/);
  assert.match(releaseCheckScript, /run\("rustTests", cargoCommand, \["test", "--workspace"\]\)/);
  assert.match(releaseCheckScript, /run\("doctor", npmCommand, \["run", "doctor:json"\]\)/);
  assert.match(releaseCheckScript, /run\("packageReleaseCheck", npmCommand, \["run", "package:release:check"\]\)/);
});

test("release:check:live includes the live corpus budget gate", async () => {
  const scripts = await packageScripts();
  const liveScript = await readFile("scripts/live-check.mjs", "utf8");

  assert.match(scripts["release:check:live"], /scripts\/live-check\.mjs/);
  assert.match(liveScript, /"--require-hopper"/);
  assert.match(liveScript, /run\("releaseCheck", npmCommand, \["run", "release:check"\]\)/);
  assert.match(liveScript, /await cleanupRunnerState\(\);\s*await run\("testLiveJs", nodeCommand, \["--test", "test\/live\.mjs"\]/);
  assert.match(liveScript, /run\("testLiveJs", nodeCommand, \["--test", "test\/live\.mjs"\]/);
  assert.match(liveScript, /run\("testLiveRust", cargoCommand, \[[\s\S]*"test"[\s\S]*"live_bridge_contract"[\s\S]*"daemon_default_live_bridge_ingests_echo_when_enabled"[\s\S]*\], \{ HOPPER_MCP_LIVE: "1" \}\)/);
  assert.match(liveScript, /run\("liveCorpus", nodeCommand, \["scripts\/live-corpus\.mjs"\]/);
});

test("release:check:plugin-live hard-requires signing readiness before probing the Hopper plugin path", async () => {
  const scripts = await packageScripts();
  const pluginLiveScript = await readFile("scripts/plugin-live-check.mjs", "utf8");

  assert.match(scripts["release:check:plugin-live"], /scripts\/plugin-live-check\.mjs/);
  assert.match(pluginLiveScript, /"--require-plugin-identity"/);
  assert.match(pluginLiveScript, /await cleanupRunnerState\(\);\s*await run\("probe", npmCommand, \["run", "hopper-plugin:probe"\]\)/);
  assert.match(pluginLiveScript, /run\("probe", npmCommand, \["run", "hopper-plugin:probe"\]\)/);
});

test("release:check:distribution requires the signed distribution artifact build", async () => {
  const scripts = await packageScripts();
  const distributionScript = await readFile("scripts/distribution-check.mjs", "utf8");

  assert.match(scripts["release:check:distribution"], /scripts\/distribution-check\.mjs/);
  assert.match(distributionScript, /"--require-distribution-identity"/);
  assert.match(distributionScript, /"--require-clean-git-tree"/);
  assert.match(distributionScript, /run\("releaseCheck", npmCommand, \["run", "release:check"\]\)/);
  assert.match(distributionScript, /run\("packageRelease", npmCommand, \["run", "package:release"\]\)/);
});

test("release:check:public-release chains distribution validation with notarization", async () => {
  const scripts = await packageScripts();
  const publicReleaseScript = await readFile("scripts/public-release-check.mjs", "utf8");

  assert.match(scripts["release:check:public-release"], /scripts\/public-release-check\.mjs/);
  assert.match(publicReleaseScript, /"doctor"/);
  assert.match(publicReleaseScript, /"--json"/);
  assert.match(publicReleaseScript, /"--require-distribution-identity"/);
  assert.match(publicReleaseScript, /"--require-notary-credentials"/);
  assert.match(publicReleaseScript, /"--require-clean-git-tree"/);
  assert.match(publicReleaseScript, /run\("distribution", npmCommand, \["run", "release:check:distribution"\]\)/);
  assert.match(publicReleaseScript, /run\("notarize", npmCommand, \["run", "package:notarize", "--", archive\]\)/);
});

test("release:check:private-backend is wired through the dedicated wrapper", async () => {
  const scripts = await packageScripts();

  assert.match(scripts["release:check:private-backend"], /scripts\/private-backend-check\.mjs/);
});

test("production profile wrappers are exposed through dedicated scripts", async () => {
  const scripts = await packageScripts();
  const internalScript = await readFile("scripts/internal-production-check.mjs", "utf8");
  const internalSoakScript = await readFile("scripts/internal-soak-check.mjs", "utf8");
  const publicScript = await readFile("scripts/public-production-check.mjs", "utf8");

  assert.match(scripts["release:check:internal"], /scripts\/internal-production-check\.mjs/);
  assert.match(scripts["release:check:internal-soak"], /scripts\/internal-soak-check\.mjs/);
  assert.match(scripts["test:live:corpus:large-apps"], /HOPPER_MCP_CLEANUP_TIMEOUT_MS=60000/);
  assert.match(scripts["test:live:corpus:large-apps"], /scripts\/live-corpus\.mjs --manifest corpus\/live-large-apps\.json/);
  assert.match(scripts["release:check:public"], /scripts\/public-production-check\.mjs/);
  assert.match(internalScript, /run\("releaseCheck", npmCommand, \["run", "release:check"\]\)/);
  assert.match(internalScript, /run\("live", npmCommand, \["run", "release:check:live"\]\)/);
  assert.match(internalScript, /run\("privateBackend", npmCommand, \["run", "release:check:private-backend"\]\)/);
  assert.match(internalSoakScript, /run\("internal", npmCommand, \["run", "release:check:internal"\]\)/);
  assert.match(internalSoakScript, /run\("largeAppSoak", npmCommand, \["run", "test:live:corpus:large-apps"\]\)/);
  assert.match(publicScript, /run\("pluginLive", npmCommand, \["run", "release:check:plugin-live"\]\)/);
  assert.match(publicScript, /run\("distribution", npmCommand, \["run", "release:check:distribution"\]\)/);
  assert.match(publicScript, /run\("publicRelease", npmCommand, \["run", "release:check:public-release"\]\)/);
});

test("CI workflow uses least privilege and explicit Hopper runner labels", async () => {
  const workflow = await readFile(".github/workflows/ci.yml", "utf8");

  assert.match(workflow, /^permissions:\n  contents: read$/m);
  assert.match(workflow, /runs-on: \[self-hosted, macOS, hopper\]/);
  assert.doesNotMatch(workflow, /runs-on: self-hosted/);
});

test("CI workflow serializes live Hopper runs and bounds job duration", async () => {
  const workflow = await readFile(".github/workflows/ci.yml", "utf8");

  assert.match(workflow, /live-release-check:[\s\S]*concurrency:\n\s+group: hopper-mcp-live-release-check\n\s+cancel-in-progress: false/);
  assert.match(workflow, /live-release-check:[\s\S]*timeout-minutes:\s*90/);
  assert.match(workflow, /release-check:[\s\S]*timeout-minutes:\s*45/);
});

test("live CI workflow runs the signed Hopper plugin gate on the Hopper runner", async () => {
  const workflow = await readFile(".github/workflows/ci.yml", "utf8");

  assert.match(workflow, /name: Run live release gate[\s\S]*reports\/release-check-live\.json/);
  assert.match(workflow, /name: Run large-app soak\n\s+if: always\(\)[\s\S]*reports\/live-corpus-large-apps\.json/);
  assert.match(workflow, /name: Run private backend gate\n\s+if: always\(\)[\s\S]*reports\/release-check-private-backend\.json/);
  assert.match(workflow, /name: Run signed plugin gate\n\s+if: always\(\)[\s\S]*reports\/release-check-plugin-live\.json/);
  assert.match(workflow, /name: Run distribution gate\n\s+if: always\(\)[\s\S]*reports\/release-check-distribution\.json/);
  assert.match(workflow, /name: Run public release gate\n\s+if: always\(\)[\s\S]*reports\/release-check-public-release\.json/);
  assert.match(workflow, /name: Cleanup Hopper runner state\n\s+if: always\(\)[\s\S]*reports\/cleanup-hopper-state\.json/);
  assert.match(workflow, /name: Upload structured gate reports[\s\S]*actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(workflow, /name: hopper-release-gate-reports/);
  assert.match(workflow, /path: reports\/\*\.json/);
});

test("CI workflow pins GitHub Actions to immutable commit SHAs", async () => {
  const workflow = await readFile(".github/workflows/ci.yml", "utf8");
  const actionRefs = [...workflow.matchAll(/uses:\s+([^\s#]+)/g)].map((match) => match[1]);

  assert.ok(actionRefs.length > 0, "workflow should use at least one action");
  for (const actionRef of actionRefs) {
    assert.match(
      actionRef,
      /^[^@\s]+@[a-f0-9]{40}$/,
      `mutable action ref is not allowed: ${actionRef}`,
    );
  }
});

async function packageScripts() {
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  return pkg.scripts ?? {};
}
