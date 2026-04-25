import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rm } from "node:fs/promises";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const target = process.env.LIVE_HOPPER_BINARY ?? "/bin/ls";
const localMachOTarget = process.env.LOCAL_MACHO_BINARY ?? "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler";
const expectedTools = [
  "capabilities",
  "official_hopper_call",
  "official_hopper_tools",
  "ingest_official_hopper",
  "open_session",
  "ingest_sample",
  "ingest_live_hopper",
  "import_macho",
  "disassemble_range",
  "find_xrefs",
  "find_functions",
  "resolve",
  "analyze_function_deep",
  "get_graph_slice",
  "query",
  "xrefs",
  "list_procedures",
  "procedure",
  "search",
  "begin_transaction",
  "queue",
  "preview_transaction",
  "commit_transaction",
  "rollback_transaction",
  "hypothesis",
];

const storePath = join(root, "data", "all-tools-real-store.json");
await rm(storePath, { force: true });
const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: storePath },
});

const rl = createInterface({ input: child.stdout });
const responses = new Map();
rl.on("line", (line) => {
  const message = JSON.parse(line);
  responses.set(message.id, message);
});

let id = 0;
async function rpc(method, params = {}, { timeoutMs = 180000 } = {}) {
  const requestId = ++id;
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (responses.has(requestId)) {
      const response = responses.get(requestId);
      responses.delete(requestId);
      if (response.error) throw new Error(response.error.message);
      return response.result;
    }
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${method} response ${requestId}.`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function toolPayload(result) {
  if (result.isError) throw new Error(result.content?.[0]?.text ?? "MCP tool call failed.");
  return JSON.parse(result.content[0].text);
}

function resourcePayload(result) {
  return JSON.parse(result.contents[0].text);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function escapeRegex(value) {
  return String(value).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

const checks = [];

async function check(name, fn) {
  await fn();
  checks.push(name);
}

try {
  await check("initialize", async () => {
    const initialized = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "all-tools-real-test", version: "0.1.0" } });
    assert(initialized.serverInfo.name === "hopper-mcp", "initialize returned unexpected server name.");
  });

  await check("tools/list", async () => {
    const listed = await rpc("tools/list");
    const names = listed.tools.map((tool) => tool.name);
    for (const name of expectedTools) assert(names.includes(name), `Missing tool from tools/list: ${name}`);
  });

  await check("prompts/list and prompts/get", async () => {
    const listed = await rpc("prompts/list");
    assert(listed.prompts.some((prompt) => prompt.name === "function_triage"), "function_triage prompt missing.");
    const prompt = await rpc("prompts/get", { name: "hypothesis_workspace", arguments: { topic: "real binary triage" } });
    assert(prompt.messages[0].content.text.includes("real binary triage"), "hypothesis_workspace prompt did not include topic.");
  });

  await check("capabilities", async () => {
    const capabilities = toolPayload(await rpc("tools/call", { name: "capabilities", arguments: {} }));
    assert(capabilities.adapter.liveIngest === true, "capabilities did not report live ingest.");
    assert(capabilities.adapter.currentDocumentIngest === false, "capabilities should not advertise unsupported current-document ingest.");
  });

  await check("local Mach-O helper tools", async () => {
    const imported = toolPayload(await rpc("tools/call", {
      name: "import_macho",
      arguments: {
        executable_path: localMachOTarget,
        max_strings: 100,
      },
    }));
    assert(imported.session.binary.arch, "import_macho did not report selected architecture.");
    const beforeFunctions = imported.session.counts.functions;
    const found = toolPayload(await rpc("tools/call", {
      name: "find_functions",
      arguments: {
        executable_path: localMachOTarget,
        max_functions: 5,
        merge_session: true,
      },
    }));
    assert(found.functions === 5, `find_functions did not honor max_functions=5; got ${found.functions}.`);
    assert(found.merged.afterFunctions > beforeFunctions, "find_functions merge_session did not add discovered functions.");
    const first = found.sample[0];
    assert(first?.addr, "find_functions did not return a sample function.");
    const endAddr = `0x${(parseInt(first.addr, 16) + 0x40).toString(16)}`;
    const disassembly = toolPayload(await rpc("tools/call", {
      name: "disassemble_range",
      arguments: {
        executable_path: localMachOTarget,
        start_addr: first.addr,
        end_addr: endAddr,
        max_lines: 10,
      },
    }));
    assert(disassembly.lineCount > 0, "disassemble_range returned no instructions.");
    const xrefs = toolPayload(await rpc("tools/call", {
      name: "find_xrefs",
      arguments: {
        executable_path: localMachOTarget,
        target_addr: "0x10055de54",
        max_results: 10,
      },
    }));
    assert(Array.isArray(xrefs), "find_xrefs did not return an array.");
    if (localMachOTarget.endsWith("Hopper Disassembler")) {
      assert(xrefs.some((xref) => xref.type === "branch"), "find_xrefs should classify direct b instructions as branch, not call.");
    }
  });

  let sessionId;
  await check("ingest_live_hopper", async () => {
    const ingest = toolPayload(await rpc("tools/call", {
      name: "ingest_live_hopper",
      arguments: {
        executable_path: target,
        timeout_ms: Number(process.env.LIVE_HOPPER_TIMEOUT_MS ?? 180000),
        max_functions: Number(process.env.LIVE_HOPPER_MAX_FUNCTIONS ?? 80),
        max_strings: Number(process.env.LIVE_HOPPER_MAX_STRINGS ?? 200),
        parse_objective_c: process.env.LIVE_HOPPER_PARSE_OBJC !== "0",
        parse_swift: process.env.LIVE_HOPPER_PARSE_SWIFT !== "0",
      },
    }, { timeoutMs: Number(process.env.LIVE_HOPPER_TIMEOUT_MS ?? 180000) + 30000 }));
    sessionId = ingest.session.sessionId;
    assert(ingest.session.counts.functions > 0, "live ingest did not return functions.");
    assert(ingest.session.counts.strings > 0, "live ingest did not return strings.");
    assert(ingest.session.capabilities?.liveExport?.waitForAnalysis === false, "default live ingest should report waitForAnalysis=false.");
    assert(typeof ingest.session.capabilities?.liveExport?.truncated?.functions === "boolean", "live ingest did not report truncation metadata.");
  });

  await check("import_macho", async () => {
    const imported = toolPayload(await rpc("tools/call", {
      name: "import_macho",
      arguments: {
        executable_path: target,
        max_strings: 200,
      },
    }));
    assert(imported.session.counts.strings > 0, "import_macho did not return strings.");
    assert(imported.session.binary.arch === "arm64e" || imported.session.binary.arch === "arm64" || imported.session.binary.arch === "x86_64", "import_macho did not auto-select a valid architecture.");
    assert(imported.source === "local-macho-importer", "import_macho returned unexpected source.");
  });

  let functions;
  let targetFunction;
  let strings;
  await check("resources/list and resources/read", async () => {
    const resources = await rpc("resources/list");
    assert(resources.resources.some((resource) => resource.uri === "hopper://binary/metadata"), "binary metadata resource missing.");
    const metadata = resourcePayload(await rpc("resources/read", { uri: `hopper://binary/metadata?session_id=${sessionId}` }));
    assert(metadata.path === target, "metadata path does not match target.");
    functions = resourcePayload(await rpc("resources/read", { uri: `hopper://functions?session_id=${sessionId}` }));
    strings = resourcePayload(await rpc("resources/read", { uri: `hopper://binary/strings?session_id=${sessionId}` }));
    assert(functions.length > 0, "function resource is empty.");
    assert(strings.length > 0, "string resource is empty.");
    targetFunction = functions.find((fn) => fn.name && !fn.name.startsWith("sub_")) ?? functions[0];
    const evidence = resourcePayload(await rpc("resources/read", { uri: `hopper://function/${targetFunction.addr}/evidence?session_id=${sessionId}` }));
    assert(evidence.function.addr === targetFunction.addr, "function evidence resource returned wrong function.");
  });

  await check("resolve", async () => {
    const byAddress = toolPayload(await rpc("tools/call", { name: "resolve", arguments: { query: targetFunction.addr, session_id: sessionId } }));
    assert(byAddress.some((result) => result.kind === "function"), "resolve by address did not find function.");
    const stringValue = strings.find((item) => item.value?.length)?.value;
    const byString = toolPayload(await rpc("tools/call", { name: "resolve", arguments: { query: stringValue, session_id: sessionId } }));
    assert(byString.some((result) => result.kind === "string"), "resolve by string did not find string.");
  });

  await check("analyze_function_deep", async () => {
    const analysis = toolPayload(await rpc("tools/call", {
      name: "analyze_function_deep",
      arguments: { addr: targetFunction.addr, detail_level: "full", session_id: sessionId },
    }));
    assert(analysis.function.addr === targetFunction.addr, "analyze_function_deep returned wrong function.");
    assert(Array.isArray(analysis.evidenceAnchors), "analyze_function_deep missing evidence anchors.");
    assert(analysis.provenance.source, "analyze_function_deep missing provenance source.");
  });

  await check("get_graph_slice", async () => {
    const graph = toolPayload(await rpc("tools/call", {
      name: "get_graph_slice",
      arguments: { seed: targetFunction.addr, radius: 1, kind: "calls", session_id: sessionId },
    }));
    assert(graph.root.addr === targetFunction.addr, "get_graph_slice returned wrong root.");
    assert(Array.isArray(graph.nodes) && Array.isArray(graph.edges), "get_graph_slice missing nodes/edges.");
  });

  await check("search kind=strings (semantic)", async () => {
    const stringValue = strings.find((item) => item.value?.length)?.value;
    const results = toolPayload(await rpc("tools/call", {
      name: "search",
      arguments: { kind: "strings", pattern: escapeRegex(stringValue), semantic: true, session_id: sessionId },
    }));
    assert(results.some((result) => result.value === stringValue), "search kind=strings did not find selected real string.");
    assert("referencedBy" in results[0], "semantic search kind=strings did not include referencedBy.");
  });

  await check("snapshot tools (unified procedure/search + resources)", async () => {
    const capabilities = toolPayload(await rpc("tools/call", { name: "capabilities", arguments: {} }));
    assert(Array.isArray(capabilities.sessions) && capabilities.sessions.length > 0, "capabilities did not return loaded sessions.");

    const procedures = toolPayload(await rpc("tools/call", { name: "list_procedures", arguments: { session_id: sessionId, max_results: 10 } }));
    assert(procedures[targetFunction.addr] === targetFunction.name, "list_procedures did not include the selected function.");

    const stringValue = strings.find((item) => item.value?.length)?.value;
    const officialStringSearch = toolPayload(await rpc("tools/call", {
      name: "search",
      arguments: { kind: "strings", pattern: escapeRegex(stringValue), session_id: sessionId, max_results: 10 },
    }));
    assert(Object.keys(officialStringSearch).length > 0, "search kind=strings (non-semantic) returned no strings.");

    const procedureSearch = toolPayload(await rpc("tools/call", {
      name: "search",
      arguments: { kind: "procedures", pattern: escapeRegex(targetFunction.name ?? targetFunction.addr), session_id: sessionId, max_results: 10 },
    }));
    assert(procedureSearch[targetFunction.addr] === targetFunction.name, "search kind=procedures did not find selected function.");

    const info = toolPayload(await rpc("tools/call", {
      name: "procedure",
      arguments: { field: "info", procedure: targetFunction.addr, session_id: sessionId },
    }));
    assert(info.entrypoint === targetFunction.addr, "procedure field=info returned wrong procedure.");

    const resolved = toolPayload(await rpc("tools/call", {
      name: "resolve",
      arguments: { query: targetFunction.name ?? targetFunction.addr, session_id: sessionId },
    }));
    assert(resolved.some((r) => r.kind === "function" && r.item?.addr === targetFunction.addr), "resolve did not find the selected function.");

    const assembly = toolPayload(await rpc("tools/call", {
      name: "procedure",
      arguments: { field: "assembly", procedure: targetFunction.addr, session_id: sessionId, max_lines: 20 },
    }));
    assert(typeof assembly === "string", "procedure field=assembly did not return assembly text.");

    const pseudocode = toolPayload(await rpc("tools/call", {
      name: "procedure",
      arguments: { field: "pseudo_code", procedure: targetFunction.addr, session_id: sessionId },
    }));
    assert(typeof pseudocode === "string", "procedure field=pseudo_code did not return a string.");

    const callers = toolPayload(await rpc("tools/call", {
      name: "procedure",
      arguments: { field: "callers", procedure: targetFunction.addr, session_id: sessionId },
    }));
    const callees = toolPayload(await rpc("tools/call", {
      name: "procedure",
      arguments: { field: "callees", procedure: targetFunction.addr, session_id: sessionId },
    }));
    assert(Array.isArray(callers) && Array.isArray(callees), "procedure field=callers/callees did not return arrays.");

    const refs = toolPayload(await rpc("tools/call", { name: "xrefs", arguments: { address: targetFunction.addr, session_id: sessionId } }));
    assert(Array.isArray(refs), "xrefs returned malformed result.");

    const cursor = resourcePayload(await rpc("resources/read", { uri: `hopper://cursor?session_id=${sessionId}` }));
    assert(cursor === null || typeof cursor === "object", "hopper://cursor did not return cursor metadata.");

    const segments = resourcePayload(await rpc("resources/read", { uri: `hopper://binary/metadata?session_id=${sessionId}` }));
    assert(Array.isArray(segments?.segments), "hopper://binary/metadata did not include segments.");

    const listedStrings = resourcePayload(await rpc("resources/read", { uri: `hopper://binary/strings?session_id=${sessionId}` }));
    assert(Array.isArray(listedStrings) && listedStrings.length > 0, "hopper://binary/strings returned no strings.");

    const names = resourcePayload(await rpc("resources/read", { uri: `hopper://names?session_id=${sessionId}` }));
    assert(Array.isArray(names), "hopper://names did not return an array.");
    const firstName = names[0];
    if (firstName) {
      const nameSearch = toolPayload(await rpc("tools/call", {
        name: "search",
        arguments: { kind: "names", pattern: escapeRegex(firstName.name ?? firstName.addr), session_id: sessionId, max_results: 20 },
      }));
      assert(Object.keys(nameSearch).length > 0, "search kind=names did not find a listed name.");
      const addressResolve = toolPayload(await rpc("tools/call", {
        name: "resolve",
        arguments: { query: firstName.addr, session_id: sessionId },
      }));
      assert(addressResolve.length > 0, "resolve did not find the listed address.");
    }
    const bookmarks = resourcePayload(await rpc("resources/read", { uri: `hopper://bookmarks?session_id=${sessionId}` }));
    assert(Array.isArray(bookmarks), "hopper://bookmarks did not return an array.");
  });

  let officialSnapshotSessionId;
  await check("official Hopper snapshot refresh", async () => {
    const refreshed = toolPayload(await rpc("tools/call", {
      name: "ingest_official_hopper",
      arguments: {
        max_procedures: 5,
        include_procedure_info: true,
      },
    }, { timeoutMs: 90000 }));
    officialSnapshotSessionId = refreshed.session.sessionId;
    assert(refreshed.source === "official-hopper-mcp", "ingest_official_hopper returned wrong source.");
    assert(refreshed.session.capabilities.officialSnapshot.exported.procedures <= 5, "ingest_official_hopper ignored max_procedures.");
    assert(refreshed.session.capabilities.officialSnapshot.totals.procedures >= refreshed.session.counts.functions, "official snapshot totals are inconsistent.");
    const procedures = toolPayload(await rpc("tools/call", { name: "list_procedures", arguments: { session_id: officialSnapshotSessionId, max_results: 5 } }));
    assert(procedures && typeof procedures === "object" && !Array.isArray(procedures), "refreshed official snapshot did not list procedures.");
  });

  await check("transaction rollback (queue kind=comment)", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "real rollback test", rationale: "Exercise queue kind=comment and rollback.", session_id: sessionId } }));
    const queued = toolPayload(await rpc("tools/call", {
      name: "queue",
      arguments: {
        kind: "comment",
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        value: "Temporary all-tools test comment.",
        rationale: "Testing rollback path.",
        session_id: sessionId,
      },
    }));
    assert(queued.operations.length === 1, "queue kind=comment did not queue operation.");
    const preview = toolPayload(await rpc("tools/call", { name: "preview_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(preview.operations[0].newValue.includes("Temporary"), "preview_transaction did not show queued comment.");
    const rollback = toolPayload(await rpc("tools/call", { name: "rollback_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(rollback.status === "rolled_back", "rollback_transaction did not roll back.");
  });

  await check("inline comment and type patch rollback (queue kind=inline_comment / type_patch)", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "inline/type rollback test", rationale: "Exercise queue kind=inline_comment and type_patch.", session_id: sessionId } }));
    const inlineQueued = toolPayload(await rpc("tools/call", {
      name: "queue",
      arguments: {
        kind: "inline_comment",
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        value: "Temporary inline all-tools test comment.",
        rationale: "Testing inline comment queue path.",
        session_id: sessionId,
      },
    }));
    assert(inlineQueued.operations.some((op) => op.kind === "inline_comment"), "queue kind=inline_comment did not queue operation.");
    const typeQueued = toolPayload(await rpc("tools/call", {
      name: "queue",
      arguments: {
        kind: "type_patch",
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        value: "int test_signature(void)",
        rationale: "Testing type patch queue path.",
        session_id: sessionId,
      },
    }));
    assert(typeQueued.operations.some((op) => op.kind === "type_patch"), "queue kind=type_patch did not queue operation.");
    const rollback = toolPayload(await rpc("tools/call", { name: "rollback_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(rollback.status === "rolled_back", "inline/type rollback did not roll back.");
  });

  await check("transaction commit (queue kind=rename)", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "real commit test", rationale: "Exercise queue kind=rename and local commit.", session_id: sessionId } }));
    const newName = `mcp_test_${targetFunction.addr.replace(/[^0-9a-f]/gi, "_")}`;
    const queued = toolPayload(await rpc("tools/call", {
      name: "queue",
      arguments: {
        kind: "rename",
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        value: newName,
        rationale: "Testing local commit path.",
        session_id: sessionId,
      },
    }));
    assert(queued.operations[0].oldValue === targetFunction.name, "queue kind=rename did not capture old name.");
    const committed = toolPayload(await rpc("tools/call", { name: "commit_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(committed.status === "committed", "commit_transaction did not commit.");
    assert(committed.adapterResult.appliedToHopper === false, "commit_transaction should not claim Hopper write-back yet.");
    const analysis = toolPayload(await rpc("tools/call", { name: "analyze_function_deep", arguments: { addr: targetFunction.addr, session_id: sessionId } }));
    assert(analysis.function.name === newName, "committed rename was not reflected in knowledge store.");
  });

  await check("official transaction commit guard", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "official guard test", rationale: "Verify official writes are gated.", session_id: officialSnapshotSessionId ?? sessionId } }));
    const officialProcedures = toolPayload(await rpc("tools/call", {
      name: "list_procedures",
      arguments: { session_id: officialSnapshotSessionId ?? sessionId, max_results: 1 },
    }));
    await rpc("tools/call", {
      name: "queue",
      arguments: {
        kind: "comment",
        transaction_id: begun.transactionId,
        addr: Object.keys(officialProcedures)[0] ?? targetFunction.addr,
        value: "Should be blocked unless official writes are enabled.",
        rationale: "Testing official write guard.",
        session_id: officialSnapshotSessionId ?? sessionId,
      },
    });
    const blocked = await rpc("tools/call", {
      name: "commit_transaction",
      arguments: {
        transaction_id: begun.transactionId,
        session_id: officialSnapshotSessionId ?? sessionId,
        backend: "official",
      },
    });
    assert(blocked.isError === true, "official commit without confirmation/env should be blocked.");
    assert(String(blocked.content?.[0]?.text ?? "").includes("requires HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1"), "official commit guard returned the wrong error.");
    const rollback = toolPayload(await rpc("tools/call", { name: "rollback_transaction", arguments: { transaction_id: begun.transactionId, session_id: officialSnapshotSessionId ?? sessionId } }));
    assert(rollback.status === "rolled_back", "official guard transaction did not remain rollback-able.");
  });

  await check("open_session", async () => {
    const opened = toolPayload(await rpc("tools/call", {
      name: "open_session",
      arguments: {
        session: {
          sessionId: `${sessionId}-copy`,
          binaryId: "all-tools-copy",
          binary: { name: "copy", path: target, format: "test-copy", arch: "unknown" },
          functions: [targetFunction],
          strings: strings.slice(0, 1),
        },
      },
    }));
    assert(opened.sessionId === `${sessionId}-copy`, "open_session did not open supplied session.");
  });

  await check("ingest_sample", async () => {
    const sample = toolPayload(await rpc("tools/call", { name: "ingest_sample", arguments: {} }));
    assert(sample.sessionId === "sample", "ingest_sample did not load sample session.");
  });

  console.log(JSON.stringify({
    status: "all MCP tools real-binary audit ok",
    target,
    checked: checks,
  }, null, 2));
} catch (error) {
  const message = String(error.message ?? error);
  if (message.includes("Not authorized to send Apple events")) {
    console.error("macOS Automation blocked Hopper. Enable Ghostty -> Hopper Disassembler in Privacy & Security > Automation.");
    process.exitCode = 78;
  } else {
    throw error;
  }
} finally {
  child.stdin.end();
  child.kill();
  await once(child, "exit").catch(() => {});
}
