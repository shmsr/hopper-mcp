import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildDismissLoaderDialogAppleScript,
  effectivePythonLaunchAnalysis,
  buildExportScript,
  buildLiveExportLaunchSpec,
  shouldFallbackToOfficialLiveExport,
  shouldFallbackToOfficialLiveExportResult,
  ensureHopperAppReady,
  focusExecutableDocument,
  hopperCliOpenArgs,
  shouldReuseCurrentDocument,
  terminateChild,
  waitForJson,
} from "../src/hopper-live.js";

test("fast Python live export launches Hopper without background analysis", () => {
  assert.equal(effectivePythonLaunchAnalysis({
    analysis: true,
    waitForAnalysis: false,
    fullExport: false,
  }), false);
});

test("full Python live export preserves background analysis", () => {
  assert.equal(effectivePythonLaunchAnalysis({
    analysis: true,
    waitForAnalysis: false,
    fullExport: true,
  }), true);
});

test("explicit wait_for_analysis preserves background analysis", () => {
  assert.equal(effectivePythonLaunchAnalysis({
    analysis: true,
    waitForAnalysis: true,
    fullExport: false,
  }), true);
});

test("Python live export launch spec uses no-analysis flag for fast path", () => {
  const spec = buildLiveExportLaunchSpec({
    executablePath: "/bin/echo",
    scriptPath: "/tmp/export.py",
    analysis: effectivePythonLaunchAnalysis({
      analysis: true,
      waitForAnalysis: false,
      fullExport: false,
    }),
    parseObjectiveC: false,
    parseSwift: false,
    parseExceptions: false,
    hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
  });

  assert.equal(spec.mode, "cli-python-export");
  assert.ok(spec.args.includes("-A"));
  assert.ok(!spec.args.includes("-a"));
});

test("Python live export launch spec can pin loader and request procedure-only sections", () => {
  const spec = buildLiveExportLaunchSpec({
    executablePath: "/bin/echo",
    scriptPath: "/tmp/export.py",
    analysis: false,
    parseObjectiveC: false,
    parseSwift: false,
    parseExceptions: false,
    onlyProcedures: true,
    loader: "Mach-O",
    hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
  });

  assert.deepEqual(spec.args.slice(0, 4), ["-l", "Mach-O", "-e", "/bin/echo"]);
  assert.ok(spec.args.includes("-W"));
});

test("Hopper CLI launch args can preseed loader checkboxes", () => {
  const args = hopperCliOpenArgs({
    executablePath: "/bin/echo",
    analysis: false,
    parseObjectiveC: false,
    parseSwift: false,
    parseExceptions: false,
    loader: "Mach-O",
    loaderCheckboxes: ["Resolve Lazy Bindings=true", "Branch instructions always stops procedures=false"],
  });

  assert.deepEqual(args.slice(0, 8), [
    "-l",
    "Mach-O",
    "-C",
    "Resolve Lazy Bindings=true",
    "-C",
    "Branch instructions always stops procedures=false",
    "-e",
    "/bin/echo",
  ]);
});

test("Hopper CLI launch spec can select a Mach-O slice from a FAT archive", () => {
  const args = hopperCliOpenArgs({
    executablePath: "/bin/echo",
    analysis: false,
    parseObjectiveC: false,
    parseSwift: false,
    parseExceptions: false,
    loader: "Mach-O",
    fatArch: "arm64",
  });

  assert.deepEqual(args.slice(0, 6), ["-l", "FAT", "--aarch64", "-l", "Mach-O", "-e"]);
});

test("close_after_export closes the Hopper document before success JSON is written", () => {
  const script = buildExportScript({
    outputPath: "/tmp/session.json",
    progressPath: "/tmp/progress.json",
    closeAfterExport: true,
  });

  assert.ok(
    script.indexOf("doc.closeDocument()") < script.indexOf("with open(OUTPUT_PATH"),
    "exporter must not signal success until closeDocument has completed",
  );
  assert.ok(script.includes("\nexcept Exception as error:"));
});

test("Python export script writes startup progress breadcrumbs", () => {
  const script = buildExportScript({
    outputPath: "/tmp/session.json",
    progressPath: "/tmp/progress.json",
  });

  assert.match(script, /PROGRESS_PATH = "\/tmp\/progress\.json"/);
  assert.match(script, /write_progress\("started"/);
});

test("Python export script selects the best analyzed document instead of trusting only the current document", () => {
  const script = buildExportScript({
    outputPath: "/tmp/session.json",
    progressPath: "/tmp/progress.json",
  });

  assert.match(script, /Document\.getAllDocuments/);
  assert.match(script, /doc_candidates = \[current_doc\] \+ all_docs/);
  assert.match(script, /best_doc = current_doc/);
  assert.match(script, /best_score = -1/);
});

test("Python live export rejects osascript launch when loader or FAT arch selection is required", () => {
  assert.throws(
    () => buildLiveExportLaunchSpec({
      executablePath: "/bin/echo",
      scriptPath: "/tmp/export.py",
      analysis: false,
      loader: "Mach-O",
      fatArch: "arm64",
      parseObjectiveC: false,
      parseSwift: false,
      parseExceptions: false,
      hopperLauncher: "/usr/bin/osascript",
    }),
    /does not support loader or FAT architecture selection/,
  );
});

test("loader dialog dismiss script targets Hopper's loader modal and confirms it", () => {
  const script = buildDismissLoaderDialogAppleScript();

  assert.match(script, /process "Hopper Disassembler"/);
  assert.match(script, /button "OK"/);
  assert.match(script, /Loader:/);
  assert.match(script, /click button "OK"/);
  assert.match(script, /pop up button 1/);
  assert.match(script, /keystroke return/);
});

test("waitForJson invokes a poll hook while waiting for Hopper export output", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-live-wait-"));
  const outputPath = join(dir, "session.json");
  let polls = 0;

  setTimeout(() => {
    void writeFile(outputPath, '{"ok":true}', "utf8");
  }, 25);

  const payload = await waitForJson(
    outputPath,
    1000,
    () => ({
      childExit: null,
      hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
      args: [],
      mode: "cli-python-export",
      launchAnalysis: false,
      waitForAnalysis: false,
      fullExport: false,
      outputPath,
      stdout: "",
      stderr: "",
    }),
    {
      onPoll: async () => {
        polls += 1;
      },
      pollIntervalMs: 10,
    },
  );

  assert.deepEqual(payload, { ok: true });
  assert.ok(polls >= 1);
});

test("waitForJson fails fast when Hopper exits cleanly before writing progress or session output", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hopper-live-wait-"));
  const outputPath = join(dir, "session.json");

  await assert.rejects(
    waitForJson(
      outputPath,
      50,
      () => ({
        childExit: { code: 0, signal: null },
        hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
        args: ["-Y", "/tmp/export.py"],
        mode: "cli-python-export",
        launchAnalysis: true,
        waitForAnalysis: true,
        fullExport: false,
        outputPath,
        progressPath: join(dir, "progress.json"),
        stdout: "",
        stderr: "",
      }),
      { pollIntervalMs: 5 },
    ),
    /exited before writing a session file/i,
  );
});

test("helper export failures fall back to the official snapshot path", () => {
  assert.equal(
    shouldFallbackToOfficialLiveExport(new Error("Hopper launcher exited before writing a session file. Hopper CLI failed before the exporter script ran.")),
    true,
  );
  assert.equal(
    shouldFallbackToOfficialLiveExport(new Error("Timed out waiting for Hopper live export after 90000ms.")),
    true,
  );
});

test("non-exporter errors do not trigger official fallback", () => {
  assert.equal(
    shouldFallbackToOfficialLiveExport(new Error("ingest_live_hopper requires executable_path.")),
    false,
  );
});

test("empty Python live export results trigger official fallback", () => {
  assert.equal(shouldFallbackToOfficialLiveExportResult({
    functions: [],
    strings: [],
    binary: { name: "Capture One.hop" },
  }), true);

  assert.equal(shouldFallbackToOfficialLiveExportResult({
    functions: [{ addr: "0x1000", name: "main" }],
    strings: [],
  }), false);

  assert.equal(shouldFallbackToOfficialLiveExportResult({
    functions: {
      "0x1000": { addr: "0x1000", name: "main" },
    },
    strings: [],
  }), false);
});

test("official fallback can reject shallow current documents even when procedures exist", async () => {
  const backend = {
    async callTool(name) {
      assert.equal(name, "list_procedures");
      return {
        structuredContent: {
          "0x1000": "sub_1000",
          "0x1010": "sub_1010",
          "0x1020": "sub_1020",
          "0x1030": "sub_1030",
        },
      };
    },
  };

  assert.equal(await shouldReuseCurrentDocument({
    officialBackend: backend,
    executablePath: "/Applications/Capture One.app/Contents/MacOS/Capture One",
    currentDocument: "Capture One",
    minimumProcedureCount: 10,
  }), false);
});

test("official fallback can reuse a matching non-current document instead of relaunching Hopper", async () => {
  const calls = [];
  let selectedDocument = "Untitled 3";
  const backend = {
    async callInternalTool(name, args) {
      calls.push({ kind: "internal", name, args });
      assert.equal(name, "set_current_document");
      assert.deepEqual(args, { document: "Capture One.hop" });
      selectedDocument = "Capture One.hop";
    },
    async callTool(name) {
      calls.push({ kind: "tool", name });
      if (name === "current_document") {
        return {
          content: [{ type: "text", text: selectedDocument }],
        };
      }
      if (name === "list_procedures") {
        return {
          content: [{ type: "text", text: JSON.stringify({
            "0x1000": "sub_1000",
            "0x1010": "sub_1010",
            "0x1020": "sub_1020",
            "0x1030": "sub_1030",
            "0x1040": "sub_1040",
            "0x1050": "sub_1050",
            "0x1060": "sub_1060",
            "0x1070": "sub_1070",
            "0x1080": "sub_1080",
            "0x1090": "sub_1090",
          }) }],
        };
      }
      assert.fail(`unexpected tool call: ${name}`);
    },
  };

  assert.equal(await shouldReuseCurrentDocument({
    officialBackend: backend,
    executablePath: "/Applications/Capture One.app/Contents/MacOS/Capture One",
    currentDocument: "Untitled 3",
    documents: ["Untitled 3", "Capture One.hop"],
    minimumProcedureCount: 10,
  }), true);
  assert.deepEqual(calls, [
    { kind: "internal", name: "set_current_document", args: { document: "Capture One.hop" } },
    { kind: "tool", name: "current_document" },
    { kind: "tool", name: "list_procedures" },
  ]);
});

test("CLI helper live launch prewarms Hopper before dispatching helper commands", async () => {
  const calls = [];

  const result = await ensureHopperAppReady({
    hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
    officialBackend: {},
    timeoutMs: 1234,
    settleDelayMs: 0,
    launchApp: async ({ hopperLauncher, openCommand }) => {
      calls.push({ kind: "launch", hopperLauncher, openCommand });
    },
    waitUntilReady: async ({ officialBackend, timeoutMs }) => {
      calls.push({ kind: "wait", officialBackend, timeoutMs });
    },
  });

  assert.deepEqual(calls, [
    {
      kind: "launch",
      hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
      openCommand: "/usr/bin/open",
    },
    {
      kind: "wait",
      officialBackend: {},
      timeoutMs: 1234,
    },
  ]);
  assert.equal(result.prewarmed, true);
});

test("CLI helper live launch retries transient LaunchServices -600 and -609 prewarm failures", async () => {
  const calls = [];
  let attempts = 0;

  const result = await ensureHopperAppReady({
    hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
    officialBackend: {},
    timeoutMs: 1234,
    settleDelayMs: 0,
    launchApp: async ({ hopperLauncher, openCommand }) => {
      calls.push({ kind: "launch", hopperLauncher, openCommand, attempt: attempts + 1 });
      attempts += 1;
      if (attempts === 1) {
        throw new Error("Command failed: /usr/bin/open -a /Applications/Hopper Disassembler.app\n_LSOpenURLsWithCompletionHandler() failed for the application /Applications/Hopper Disassembler.app with error -609.\n");
      }
    },
    waitUntilReady: async ({ officialBackend, timeoutMs }) => {
      calls.push({ kind: "wait", officialBackend, timeoutMs });
    },
  });

  assert.equal(attempts, 2);
  assert.deepEqual(calls, [
    {
      kind: "launch",
      hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
      openCommand: "/usr/bin/open",
      attempt: 1,
    },
    {
      kind: "launch",
      hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
      openCommand: "/usr/bin/open",
      attempt: 2,
    },
    {
      kind: "wait",
      officialBackend: {},
      timeoutMs: 1234,
    },
  ]);
  assert.equal(result.prewarmed, true);
});

test("CLI helper live launch can wait for Hopper UI settle after readiness", async () => {
  const calls = [];

  await ensureHopperAppReady({
    hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
    officialBackend: {},
    timeoutMs: 1234,
    settleDelayMs: 4321,
    launchApp: async () => {
      calls.push({ kind: "launch" });
    },
    waitUntilReady: async () => {
      calls.push({ kind: "wait" });
    },
    settleAfterReady: async ({ delayMs }) => {
      calls.push({ kind: "settle", delayMs });
    },
  });

  assert.deepEqual(calls, [
    { kind: "launch" },
    { kind: "wait" },
    { kind: "settle", delayMs: 4321 },
  ]);
});

test("CLI helper live launch skips backend readiness probe when none is supplied", async () => {
  const calls = [];

  await ensureHopperAppReady({
    hopperLauncher: "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
    officialBackend: null,
    settleDelayMs: 0,
    launchApp: async () => {
      calls.push({ kind: "launch" });
    },
    waitUntilReady: async () => {
      calls.push({ kind: "wait" });
    },
    settleAfterReady: async () => {
      calls.push({ kind: "settle" });
    },
  });

  assert.deepEqual(calls, [
    { kind: "launch" },
    { kind: "settle" },
  ]);
});

test("focusExecutableDocument switches official MCP current_document to the launched executable", async () => {
  const calls = [];
  const backend = {
    async callInternalTool(name, args) {
      calls.push({ name, args });
      assert.equal(name, "set_current_document");
      assert.deepEqual(args, { document: "echo" });
    },
    async callTool(name) {
      assert.equal(name, "current_document");
      return {
        content: [{ type: "text", text: "echo" }],
      };
    },
  };

  const selected = await focusExecutableDocument({
    officialBackend: backend,
    executablePath: "/bin/echo",
    currentDocument: "Untitled 3",
    documents: ["echo", "Untitled 3"],
  });

  assert.equal(selected, "echo");
  assert.deepEqual(calls, [{ name: "set_current_document", args: { document: "echo" } }]);
});

test("terminateChild escalates to SIGKILL when a child ignores SIGTERM", async () => {
  const child = new EventEmitter();
  const signals = [];
  child.kill = (signal = "SIGTERM") => {
    signals.push(signal);
    if (signal === "SIGKILL") {
      setTimeout(() => child.emit("close", null, "SIGKILL"), 0);
    }
    return true;
  };

  const result = await terminateChild(child, { termGraceMs: 1, killGraceMs: 100 });

  assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(result.escalated, true);
  assert.equal(result.signal, "SIGKILL");
});
