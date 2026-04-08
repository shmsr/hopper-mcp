import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const target = process.env.LIVE_HOPPER_BINARY ?? "/bin/ls";
const localMachOTarget = process.env.LOCAL_MACHO_BINARY ?? "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler";
const expectedTools = [
  "capabilities",
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
  "search_strings",
  "list_documents",
  "current_document",
  "list_segments",
  "list_procedures",
  "list_procedure_size",
  "list_procedure_info",
  "list_strings",
  "search_procedures",
  "procedure_info",
  "procedure_address",
  "procedure_assembly",
  "procedure_pseudo_code",
  "procedure_callers",
  "procedure_callees",
  "xrefs",
  "current_address",
  "current_procedure",
  "list_names",
  "search_name",
  "address_name",
  "list_bookmarks",
  "begin_transaction",
  "queue_rename",
  "queue_comment",
  "queue_inline_comment",
  "queue_type_patch",
  "preview_transaction",
  "commit_transaction",
  "rollback_transaction",
];

const child = spawn(process.execPath, [join(root, "src", "mcp-server.js")], {
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, HOPPER_MCP_STORE: join(root, "data", "all-tools-real-store.json") },
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
        arch: "arm64",
        max_strings: 100,
      },
    }));
    const beforeFunctions = imported.session.counts.functions;
    const found = toolPayload(await rpc("tools/call", {
      name: "find_functions",
      arguments: {
        executable_path: localMachOTarget,
        arch: "arm64",
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
        arch: "arm64",
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
        arch: "arm64",
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
        arch: "arm64",
        max_strings: 200,
      },
    }));
    assert(imported.session.counts.strings > 0, "import_macho did not return strings.");
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

  await check("search_strings", async () => {
    const stringValue = strings.find((item) => item.value?.length)?.value;
    const results = toolPayload(await rpc("tools/call", {
      name: "search_strings",
      arguments: { regex: escapeRegex(stringValue), semantic: true, session_id: sessionId },
    }));
    assert(results.some((result) => result.value === stringValue), "search_strings did not find selected real string.");
    assert("referencedBy" in results[0], "semantic search_strings did not include referencedBy.");
  });

  await check("Hopper API snapshot mirror tools", async () => {
    const documents = toolPayload(await rpc("tools/call", { name: "list_documents", arguments: {} }));
    assert(documents.some((document) => typeof document === "string"), "list_documents did not return loaded sessions.");
    const currentDocument = toolPayload(await rpc("tools/call", { name: "current_document", arguments: { session_id: sessionId } }));
    assert(typeof currentDocument === "string" && currentDocument.length > 0, "current_document did not return the live Hopper snapshot name.");
    const segments = toolPayload(await rpc("tools/call", { name: "list_segments", arguments: { session_id: sessionId } }));
    assert(Array.isArray(segments) && segments.length > 0, "list_segments returned no segments.");
    const procedures = toolPayload(await rpc("tools/call", { name: "list_procedures", arguments: { session_id: sessionId, max_results: 10 } }));
    assert(procedures[targetFunction.addr] === targetFunction.name, "list_procedures did not include the selected function.");
    const sizes = toolPayload(await rpc("tools/call", { name: "list_procedure_size", arguments: { session_id: sessionId, max_results: 10 } }));
    assert(sizes[targetFunction.addr]?.basicblock_count >= 0, "list_procedure_size did not include the selected function.");
    const infos = toolPayload(await rpc("tools/call", { name: "list_procedure_info", arguments: { session_id: sessionId, max_results: 10 } }));
    assert(infos[targetFunction.addr]?.entrypoint === targetFunction.addr, "list_procedure_info did not include the selected function.");
    const listedStrings = toolPayload(await rpc("tools/call", { name: "list_strings", arguments: { session_id: sessionId, max_results: 10 } }));
    assert(Object.keys(listedStrings).length > 0, "list_strings returned no strings.");
    const officialStringSearch = toolPayload(await rpc("tools/call", {
      name: "search_strings",
      arguments: { pattern: escapeRegex(strings.find((item) => item.value?.length)?.value), session_id: sessionId, max_results: 10 },
    }));
    assert(Object.keys(officialStringSearch).length > 0, "official-compatible search_strings returned no strings.");
    const procedureSearch = toolPayload(await rpc("tools/call", { name: "search_procedures", arguments: { pattern: escapeRegex(targetFunction.name ?? targetFunction.addr), session_id: sessionId, max_results: 10 } }));
    assert(procedureSearch[targetFunction.addr] === targetFunction.name, "search_procedures did not find selected function.");
    const info = toolPayload(await rpc("tools/call", { name: "procedure_info", arguments: { procedure: targetFunction.addr, session_id: sessionId } }));
    assert(info.entrypoint === targetFunction.addr, "procedure_info returned wrong procedure.");
    const address = toolPayload(await rpc("tools/call", { name: "procedure_address", arguments: { procedure: targetFunction.name ?? targetFunction.addr, session_id: sessionId } }));
    assert(address === targetFunction.addr, "procedure_address returned wrong address.");
    const assembly = toolPayload(await rpc("tools/call", { name: "procedure_assembly", arguments: { procedure: targetFunction.addr, session_id: sessionId, max_lines: 20 } }));
    assert(typeof assembly === "string", "procedure_assembly did not return assembly text.");
    const pseudocode = toolPayload(await rpc("tools/call", { name: "procedure_pseudo_code", arguments: { procedure: targetFunction.addr, session_id: sessionId } }));
    assert(typeof pseudocode === "string", "procedure_pseudo_code did not return a string.");
    const callers = toolPayload(await rpc("tools/call", { name: "procedure_callers", arguments: { procedure: targetFunction.addr, session_id: sessionId } }));
    const callees = toolPayload(await rpc("tools/call", { name: "procedure_callees", arguments: { procedure: targetFunction.addr, session_id: sessionId } }));
    assert(Array.isArray(callers) && Array.isArray(callees), "procedure_callers/callees did not return arrays.");
    const refs = toolPayload(await rpc("tools/call", { name: "xrefs", arguments: { address: targetFunction.addr, session_id: sessionId } }));
    assert(Array.isArray(refs), "xrefs returned malformed result.");
    const currentAddress = toolPayload(await rpc("tools/call", { name: "current_address", arguments: { session_id: sessionId } }));
    assert(currentAddress === null || typeof currentAddress === "string", "current_address did not return captured cursor shape.");
    const currentProcedure = toolPayload(await rpc("tools/call", { name: "current_procedure", arguments: { session_id: sessionId } }));
    assert(currentProcedure === null || typeof currentProcedure === "string", "current_procedure did not return captured cursor shape.");
    const names = toolPayload(await rpc("tools/call", { name: "list_names", arguments: { session_id: sessionId, max_results: 20 } }));
    assert(names && typeof names === "object" && !Array.isArray(names), "list_names did not return an object.");
    const firstNameEntry = Object.entries(names)[0];
    if (firstNameEntry) {
      const [nameAddr, nameValue] = firstNameEntry;
      const nameSearch = toolPayload(await rpc("tools/call", { name: "search_name", arguments: { pattern: escapeRegex(nameValue ?? nameAddr), session_id: sessionId, max_results: 20 } }));
      assert(Object.keys(nameSearch).length > 0, "search_name did not find a listed name.");
      const addressName = toolPayload(await rpc("tools/call", { name: "address_name", arguments: { address: nameAddr, session_id: sessionId } }));
      assert(addressName === nameValue, "address_name returned wrong address.");
    }
    const bookmarks = toolPayload(await rpc("tools/call", { name: "list_bookmarks", arguments: { session_id: sessionId, max_results: 20 } }));
    assert(Array.isArray(bookmarks), "list_bookmarks did not return an array.");
  });

  await check("transaction rollback", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "real rollback test", rationale: "Exercise queue_comment and rollback.", session_id: sessionId } }));
    const queued = toolPayload(await rpc("tools/call", {
      name: "queue_comment",
      arguments: {
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        comment: "Temporary all-tools test comment.",
        rationale: "Testing rollback path.",
        session_id: sessionId,
      },
    }));
    assert(queued.operations.length === 1, "queue_comment did not queue operation.");
    const preview = toolPayload(await rpc("tools/call", { name: "preview_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(preview.operations[0].newValue.includes("Temporary"), "preview_transaction did not show queued comment.");
    const rollback = toolPayload(await rpc("tools/call", { name: "rollback_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(rollback.status === "rolled_back", "rollback_transaction did not roll back.");
  });

  await check("inline comment and type patch rollback", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "inline/type rollback test", rationale: "Exercise queue_inline_comment and queue_type_patch.", session_id: sessionId } }));
    const inlineQueued = toolPayload(await rpc("tools/call", {
      name: "queue_inline_comment",
      arguments: {
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        comment: "Temporary inline all-tools test comment.",
        rationale: "Testing inline comment queue path.",
        session_id: sessionId,
      },
    }));
    assert(inlineQueued.operations.some((op) => op.kind === "inline_comment"), "queue_inline_comment did not queue operation.");
    const typeQueued = toolPayload(await rpc("tools/call", {
      name: "queue_type_patch",
      arguments: {
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        type: "int test_signature(void)",
        rationale: "Testing type patch queue path.",
        session_id: sessionId,
      },
    }));
    assert(typeQueued.operations.some((op) => op.kind === "type_patch"), "queue_type_patch did not queue operation.");
    const rollback = toolPayload(await rpc("tools/call", { name: "rollback_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(rollback.status === "rolled_back", "inline/type rollback did not roll back.");
  });

  await check("transaction commit", async () => {
    const begun = toolPayload(await rpc("tools/call", { name: "begin_transaction", arguments: { name: "real commit test", rationale: "Exercise queue_rename and local commit.", session_id: sessionId } }));
    const newName = `mcp_test_${targetFunction.addr.replace(/[^0-9a-f]/gi, "_")}`;
    const queued = toolPayload(await rpc("tools/call", {
      name: "queue_rename",
      arguments: {
        transaction_id: begun.transactionId,
        addr: targetFunction.addr,
        new_name: newName,
        rationale: "Testing local commit path.",
        session_id: sessionId,
      },
    }));
    assert(queued.operations[0].oldValue === targetFunction.name, "queue_rename did not capture old name.");
    const committed = toolPayload(await rpc("tools/call", { name: "commit_transaction", arguments: { transaction_id: begun.transactionId, session_id: sessionId } }));
    assert(committed.status === "committed", "commit_transaction did not commit.");
    assert(committed.adapterResult.appliedToHopper === false, "commit_transaction should not claim Hopper write-back yet.");
    const analysis = toolPayload(await rpc("tools/call", { name: "analyze_function_deep", arguments: { addr: targetFunction.addr, session_id: sessionId } }));
    assert(analysis.function.name === newName, "committed rename was not reflected in knowledge store.");
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
