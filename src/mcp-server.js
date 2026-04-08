#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { KnowledgeStore } from "./knowledge-store.js";
import { TransactionManager } from "./transaction-manager.js";
import { HopperAdapter } from "./hopper-adapter.js";
import { importMachO, searchMachOStrings, disassembleRange, findXrefs, discoverFunctionsFromDisassembly, mergeFunctionSets } from "./macho-importer.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const store = new KnowledgeStore(process.env.HOPPER_MCP_STORE ?? join(ROOT, "data", "knowledge-store.json"));
const transactions = new TransactionManager(store);
const adapter = new HopperAdapter({
  socketPath: process.env.HOPPER_MCP_SOCKET ?? null,
  hopperLauncher: process.env.HOPPER_LAUNCHER ?? null,
});

await store.load();

const serverInfo = {
  name: "hopper-mcp",
  title: "Hopper MCP",
  version: "0.1.0",
  description: "MCP server for Hopper with resources, tools, prompts, and transaction-safe annotations.",
};

const latestProtocolVersion = "2025-11-25";
const supportedProtocolVersions = new Set([latestProtocolVersion, "2025-06-18", "2025-03-26"]);
const logLevels = new Set(["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]);
let logLevel = "info";

const tools = [
  tool("capabilities", "Report static/dynamic adapter capabilities.", {}),
  tool("open_session", "Create or replace a session from an already-indexed JSON payload.", {
    session: { type: "object", description: "Normalized session document with functions, strings, imports, exports, and metadata." },
  }, ["session"]),
  tool("ingest_sample", "Load a small built-in sample session for smoke tests and client exploration.", {}),
  tool("ingest_live_hopper", "Open an executable in Hopper, run the official Python exporter inside Hopper, and ingest the live analyzed document.", {
    executable_path: { type: "string" },
    timeout_ms: { type: "number" },
    max_functions: { type: "number" },
    max_strings: { type: "number" },
    analysis: { type: "boolean" },
    parse_objective_c: { type: "boolean" },
    parse_swift: { type: "boolean" },
    wait_for_analysis: { type: "boolean" },
    full_export: { type: "boolean" },
    fail_on_truncation: { type: "boolean" },
  }, ["executable_path"]),
  tool("import_macho", "Import Mach-O metadata using local macOS tools. With deep=true, also discovers functions from disassembly, builds call graphs, and resolves string cross-references via ADRP+ADD patterns.", {
    executable_path: { type: "string" },
    arch: { type: "string" },
    max_strings: { type: "number" },
    deep: { type: "boolean" },
    max_functions: { type: "number" },
  }, ["executable_path"]),
  tool("disassemble_range", "Disassemble a specific address range from a Mach-O binary using otool. Returns ARM64 assembly with symbolic names.", {
    executable_path: { type: "string" },
    start_addr: { type: "string" },
    end_addr: { type: "string" },
    arch: { type: "string" },
    max_lines: { type: "number" },
    session_id: { type: "string" },
  }, ["start_addr", "end_addr"]),
  tool("find_xrefs", "Find all code locations that reference a given address. Detects ADRP+ADD, ADRP+LDR, and bl/b patterns in ARM64.", {
    executable_path: { type: "string" },
    target_addr: { type: "string" },
    arch: { type: "string" },
    max_results: { type: "number" },
    session_id: { type: "string" },
  }, ["target_addr"]),
  tool("find_functions", "Discover functions in a region by scanning for ARM64 stp x29,x30 prologues. Optionally merges into current session.", {
    executable_path: { type: "string" },
    start_addr: { type: "string" },
    end_addr: { type: "string" },
    arch: { type: "string" },
    max_functions: { type: "number" },
    merge_session: { type: "boolean" },
    session_id: { type: "string" },
  }),
  tool("resolve", "Resolve an address, name, string, import, or semantic query against the knowledge store.", {
    query: { type: "string" },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }, ["query"]),
  tool("analyze_function_deep", "Return purpose, pseudocode, graph context, evidence anchors, and provenance for a function.", {
    addr: { type: "string" },
    detail_level: { type: "string", enum: ["standard", "full"] },
    session_id: { type: "string" },
  }, ["addr"]),
  tool("get_graph_slice", "Return caller/callee graph neighborhood for a function.", {
    seed: { type: "string" },
    radius: { type: "number" },
    kind: { type: "string", enum: ["calls", "callers", "callees"] },
    session_id: { type: "string" },
  }, ["seed"]),
  tool("search_strings", "Search indexed strings, optionally expanding to semantic references.", {
    regex: { type: "string" },
    semantic: { type: "boolean" },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }, ["regex"]),
  tool("begin_transaction", "Start a reviewed annotation transaction.", {
    name: { type: "string" },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }),
  tool("queue_rename", "Queue a function rename in the active transaction.", {
    transaction_id: { type: "string" },
    addr: { type: "string" },
    new_name: { type: "string" },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["addr", "new_name"]),
  tool("queue_comment", "Queue a function-level comment in the active transaction.", {
    transaction_id: { type: "string" },
    addr: { type: "string" },
    comment: { type: "string" },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["addr", "comment"]),
  tool("queue_inline_comment", "Queue an inline comment in the active transaction.", {
    transaction_id: { type: "string" },
    addr: { type: "string" },
    comment: { type: "string" },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["addr", "comment"]),
  tool("queue_type_patch", "Queue a function type/signature patch in the active transaction.", {
    transaction_id: { type: "string" },
    addr: { type: "string" },
    type: { type: "string" },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["addr", "type"]),
  tool("preview_transaction", "Preview queued writes with old/new values before commit.", {
    transaction_id: { type: "string" },
    session_id: { type: "string" },
  }),
  tool("commit_transaction", "Commit queued writes to the knowledge store and, when connected, Hopper.", {
    transaction_id: { type: "string" },
    session_id: { type: "string" },
  }),
  tool("rollback_transaction", "Roll back an open transaction without applying writes.", {
    transaction_id: { type: "string" },
    session_id: { type: "string" },
  }),
];

const prompts = [
  {
    name: "function_triage",
    title: "Function Triage",
    description: "Guide an agent through provenance-first function analysis.",
    arguments: [{ name: "addr", description: "Function address", required: true }],
  },
  {
    name: "hypothesis_workspace",
    title: "Hypothesis Workspace",
    description: "Create a cautious Hopper hypothesis with evidence gates.",
    arguments: [{ name: "topic", description: "Hypothesis topic, e.g. license check path", required: true }],
  },
];

const handlers = {
  initialize: async (params) => ({
    protocolVersion: negotiateProtocolVersion(params.protocolVersion),
    capabilities: {
      tools: { listChanged: false },
      resources: { subscribe: false, listChanged: true },
      prompts: { listChanged: false },
      logging: {},
    },
    serverInfo,
  }),
  ping: async () => ({}),
  "notifications/initialized": async () => undefined,
  "tools/list": async () => ({ tools }),
  "tools/call": async (params) => {
    if (!tools.some((candidate) => candidate.name === params.name)) {
      throw rpcError(-32602, `Unknown tool: ${params.name}`);
    }
    try {
      return await callTool(params.name, params.arguments ?? {}, params._meta ?? {});
    } catch (error) {
      return toolError(error);
    }
  },
  "resources/list": async () => ({ resources: store.listResources() }),
  "resources/templates/list": async () => ({ resourceTemplates: resourceTemplates() }),
  "resources/read": async (params) => ({
    contents: [
      {
        uri: params.uri,
        mimeType: "application/json",
        text: JSON.stringify(store.getResource(params.uri), null, 2),
      },
    ],
  }),
  "prompts/list": async () => ({ prompts }),
  "prompts/get": async (params) => getPrompt(params.name, params.arguments ?? {}),
  "logging/setLevel": async (params) => {
    if (!logLevels.has(params.level)) throw rpcError(-32602, `Unsupported log level: ${params.level}`);
    logLevel = params.level;
    return {};
  },
};

function negotiateProtocolVersion(requestedVersion) {
  if (supportedProtocolVersions.has(requestedVersion)) return requestedVersion;
  return latestProtocolVersion;
}

let inputBuffer = Buffer.alloc(0);
let outputMode = "line";
let processing = Promise.resolve();

function scheduleDrain() {
  processing = processing.then(() => drainInputBuffer());
  return processing;
}

process.stdin.on("data", (chunk) => {
  inputBuffer = Buffer.concat([inputBuffer, chunk]);
  scheduleDrain();
});

await new Promise((resolve) => process.stdin.on("end", resolve));
await scheduleDrain();

async function dispatch(message) {
  const handler = handlers[message.method];
  if (!handler) throw rpcError(-32601, `Method not found: ${message.method}`);
  return handler(message.params ?? {});
}

async function callTool(name, args, meta = {}) {
  const sessionId = args.session_id ?? "current";
  const progressToken = meta.progressToken;
  let result;

  if (name === "capabilities") {
    result = { server: serverInfo, adapter: adapter.capabilities(), sessions: store.listSessions() };
  } else if (name === "open_session") {
    notifyProgress(progressToken, 0, 1, "Opening indexed session.");
    result = store.describeSession(await store.upsertSession(args.session));
    notifyResourceListChanged();
    notifyProgress(progressToken, 1, 1, "Indexed session opened.");
  } else if (name === "ingest_sample") {
    notifyProgress(progressToken, 0, 1, "Loading sample session.");
    result = store.describeSession(await store.upsertSession(sampleSession()));
    notifyResourceListChanged();
    notifyProgress(progressToken, 1, 1, "Sample session loaded.");
  } else if (name === "ingest_live_hopper") {
    notifyProgress(progressToken, 0, 2, "Opening executable in Hopper.");
    const live = await adapter.ingestExecutable({
      executablePath: args.executable_path,
      timeoutMs: args.timeout_ms,
      maxFunctions: args.max_functions,
      maxStrings: args.max_strings,
      analysis: args.analysis,
      parseObjectiveC: args.parse_objective_c,
      parseSwift: args.parse_swift,
      waitForAnalysis: args.wait_for_analysis,
      fullExport: args.full_export,
      failOnTruncation: args.fail_on_truncation,
    });
    notifyProgress(progressToken, 1, 2, "Ingesting Hopper export.");
    const session = await store.upsertSession(live.session);
    notifyResourceListChanged();
    notifyProgress(progressToken, 2, 2, "Live Hopper session ingested.");
    result = { session: store.describeSession(session), launch: live.launch };
  } else if (name === "import_macho") {
    const isDeep = Boolean(args.deep);
    notifyProgress(progressToken, 0, isDeep ? 3 : 1, isDeep ? "Deep Mach-O import: extracting metadata." : "Importing Mach-O metadata.");
    const imported = await importMachO(args.executable_path, {
      arch: args.arch ?? "arm64",
      maxStrings: args.max_strings ?? 15000,
      deep: isDeep,
      maxFunctions: args.max_functions ?? 30000,
    });
    if (isDeep) notifyProgress(progressToken, 2, 3, "Indexing discovered functions.");
    const session = await store.upsertSession(imported);
    notifyResourceListChanged();
    notifyProgress(progressToken, isDeep ? 3 : 1, isDeep ? 3 : 1, "Mach-O import complete.");
    result = { session: store.describeSession(session), source: isDeep ? "local-macho-deep" : "local-macho-importer" };
  } else if (name === "disassemble_range") {
    const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
    result = await disassembleRange(binaryPath, {
      arch: args.arch ?? "arm64",
      startAddr: args.start_addr,
      endAddr: args.end_addr,
      maxLines: args.max_lines ?? 500,
    });
  } else if (name === "find_xrefs") {
    const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
    notifyProgress(progressToken, 0, 1, "Scanning binary for cross-references (streaming otool).");
    result = await findXrefs(binaryPath, {
      arch: args.arch ?? "arm64",
      targetAddr: args.target_addr,
      maxResults: args.max_results ?? 50,
    });
    notifyProgress(progressToken, 1, 1, `Found ${result.length} xrefs.`);
  } else if (name === "find_functions") {
    const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
    notifyProgress(progressToken, 0, 1, "Scanning for function prologues.");
    const discovery = await discoverFunctionsFromDisassembly(binaryPath, {
      arch: args.arch ?? "arm64",
      maxFunctions: args.max_functions ?? 30000,
      startAddr: args.start_addr ? parseInt(args.start_addr, 16) : null,
      endAddr: args.end_addr ? parseInt(args.end_addr, 16) : null,
    });
    notifyProgress(progressToken, 1, 1, `Discovered ${discovery.functions.length} functions, ${discovery.callEdges.length} call edges.`);
    result = {
      functions: discovery.functions.length,
      callEdges: discovery.callEdges.length,
      adrpRefs: discovery.adrpRefs.length,
      sample: discovery.functions.slice(0, 20),
    };
    if (args.merge_session) {
      const session = store.getSession(sessionId);
      const existingFuncs = Object.values(session.functions ?? {});
      const mergedFunctions = mergeFunctionSets(existingFuncs, discovery, session.strings ?? []);
      const mergedSession = await store.upsertSession({ ...session, functions: mergedFunctions });
      notifyResourceListChanged();
      result.merged = {
        session: store.describeSession(mergedSession),
        beforeFunctions: existingFuncs.length,
        afterFunctions: Object.keys(mergedSession.functions).length,
      };
    }
  } else if (name === "resolve") {
    result = store.resolve(args.query, sessionId);
    if (!result.length) {
      result = await resolveFromBinaryStrings(args.query, { sessionId, maxResults: args.max_results });
    }
  } else if (name === "analyze_function_deep") {
    result = store.analyzeFunctionDeep(args.addr, { detailLevel: args.detail_level, sessionId });
  } else if (name === "get_graph_slice") {
    result = store.getGraphSlice(args.seed, { radius: args.radius ?? 1, kind: args.kind ?? "calls", sessionId });
  } else if (name === "search_strings") {
    result = store.searchStrings(args.regex, { semantic: Boolean(args.semantic), sessionId });
    if (!result.length) {
      result = await searchSessionBinaryStrings(args.regex, { semantic: Boolean(args.semantic), sessionId, maxResults: args.max_results });
    }
  } else if (name === "begin_transaction") {
    result = await transactions.begin({ sessionId, name: args.name, rationale: args.rationale });
  } else if (name === "queue_rename") {
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "rename", addr: args.addr, newValue: args.new_name, rationale: args.rationale }, { sessionId });
  } else if (name === "queue_comment") {
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "comment", addr: args.addr, newValue: args.comment, rationale: args.rationale }, { sessionId });
  } else if (name === "queue_inline_comment") {
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "inline_comment", addr: args.addr, newValue: args.comment, rationale: args.rationale }, { sessionId });
  } else if (name === "queue_type_patch") {
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "type_patch", addr: args.addr, newValue: args.type, rationale: args.rationale }, { sessionId });
  } else if (name === "preview_transaction") {
    result = transactions.preview({ transactionId: args.transaction_id, sessionId });
  } else if (name === "commit_transaction") {
    result = await transactions.commit({ transactionId: args.transaction_id, sessionId, adapter });
    notifyResourceListChanged();
  } else if (name === "rollback_transaction") {
    result = await transactions.rollback({ transactionId: args.transaction_id, sessionId });
  }

  return toolResult(result);
}

async function resolveFromBinaryStrings(query, { sessionId, maxResults }) {
  const strings = await searchSessionBinaryStrings(query, { semantic: false, sessionId, maxResults });
  return strings.map((item) => ({ kind: "string", score: 0.45, item }));
}

async function searchSessionBinaryStrings(pattern, { semantic, sessionId, maxResults }) {
  let session;
  try {
    session = store.getSession(sessionId);
  } catch {
    return [];
  }
  if (!session.binary?.path) return [];
  const strings = await searchMachOStrings(session.binary.path, pattern, { maxMatches: maxResults ?? 50 });
  if (!semantic) return strings;
  return strings.map((item) => ({ ...item, referencedBy: [] }));
}

function toolResult(result) {
  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    structuredContent: structuredToolContent(result),
  };
}

function structuredToolContent(result) {
  if (result && typeof result === "object" && !Array.isArray(result)) return result;
  return { result };
}

function toolError(error) {
  const message = error?.message ?? String(error);
  return {
    content: [{ type: "text", text: message }],
    isError: true,
  };
}

function notifyResourceListChanged() {
  writeNotification("notifications/resources/list_changed");
}

function notifyProgress(progressToken, progress, total, message) {
  if (progressToken === undefined || progressToken === null) return;
  writeNotification("notifications/progress", {
    progressToken,
    progress,
    total,
    message,
  });
}

function writeNotification(method, params) {
  const notification = { jsonrpc: "2.0", method };
  if (params !== undefined) notification.params = params;
  write(notification);
}

function getPrompt(name, args) {
  if (name === "function_triage") {
    return {
      description: "Provenance-first function analysis",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Analyze ${args.addr} using hopper://function/${args.addr}/evidence first. State evidence anchors, confidence, and only then propose names/comments through a transaction preview.`,
          },
        },
      ],
    };
  }
  if (name === "hypothesis_workspace") {
    return {
      description: "Hypothesis workspace",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Build a hypothesis workspace for '${args.topic}'. Separate known facts from guesses, cite addresses/imports/strings, and do not commit annotations until previewed.`,
          },
        },
      ],
    };
  }
  throw rpcError(-32602, `Unknown prompt: ${name}`);
}

function tool(name, description, properties, required = []) {
  return {
    name,
    title: titleize(name),
    description,
    inputSchema: {
      type: "object",
      properties,
      required,
      additionalProperties: false,
    },
  };
}

function titleize(name) {
  return name
    .split(/[_\-.]+/u)
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function resourceTemplates() {
  return [
    {
      uriTemplate: "hopper://function/{addr}",
      name: "function",
      title: "Function",
      description: "Full indexed function record for an address.",
      mimeType: "application/json",
    },
    {
      uriTemplate: "hopper://function/{addr}/summary",
      name: "function_summary",
      title: "Function Summary",
      description: "Compact function summary with confidence.",
      mimeType: "application/json",
    },
    {
      uriTemplate: "hopper://function/{addr}/evidence",
      name: "function_evidence",
      title: "Function Evidence",
      description: "Evidence anchors used for provenance-first analysis.",
      mimeType: "application/json",
    },
    {
      uriTemplate: "hopper://graph/callers/{addr}?radius={radius}",
      name: "graph_callers",
      title: "Caller Graph",
      description: "Caller graph slice rooted at a function address.",
      mimeType: "application/json",
    },
    {
      uriTemplate: "hopper://graph/callees/{addr}?radius={radius}",
      name: "graph_callees",
      title: "Callee Graph",
      description: "Callee graph slice rooted at a function address.",
      mimeType: "application/json",
    },
  ];
}

async function handleMessage(message, mode) {
  outputMode = mode;
  const hasId = Object.hasOwn(message, "id") && message.id !== null;
  try {
    if (!hasId && message.method?.startsWith("notifications/")) return;
    const result = await dispatch(message);
    if (hasId) write({ jsonrpc: "2.0", id: message.id, result }, mode);
  } catch (error) {
    if (hasId) write({ jsonrpc: "2.0", id: message.id, error: { code: error.code ?? -32603, message: error.message } }, mode);
  }
}

async function drainInputBuffer() {
  for (;;) {
    const parsed = parseNextMessage(inputBuffer);
    if (!parsed) return;
    inputBuffer = parsed.rest;
    if (!parsed.message) continue;
    await handleMessage(parsed.message, parsed.mode);
  }
}

function parseNextMessage(buffer) {
  if (!buffer.length) return null;
  const text = buffer.toString("utf8");

  if (text.startsWith("Content-Length:")) {
    const crlfHeaderEnd = text.indexOf("\r\n\r\n");
    const lfHeaderEnd = text.indexOf("\n\n");
    const headerEnd = crlfHeaderEnd === -1 ? lfHeaderEnd : lfHeaderEnd === -1 ? crlfHeaderEnd : Math.min(crlfHeaderEnd, lfHeaderEnd);
    if (headerEnd === -1) return null;
    const header = text.slice(0, headerEnd);
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (!match) throw new Error("Invalid MCP frame: missing Content-Length.");
    const contentLength = Number(match[1]);
    const separatorLength = text.slice(headerEnd, headerEnd + 4).startsWith("\r\n\r\n") ? 4 : 2;
    const bodyStart = Buffer.byteLength(text.slice(0, headerEnd + separatorLength), "utf8");
    const bodyEnd = bodyStart + contentLength;
    if (buffer.length < bodyEnd) return null;
    const body = buffer.subarray(bodyStart, bodyEnd).toString("utf8");
    return {
      mode: "framed",
      message: JSON.parse(body),
      rest: buffer.subarray(bodyEnd),
    };
  }

  const newline = text.indexOf("\n");
  if (newline === -1) return null;
  const line = text.slice(0, newline).trim();
  const rest = buffer.subarray(Buffer.byteLength(text.slice(0, newline + 1), "utf8"));
  if (!line) return { mode: outputMode, message: null, rest };
  return {
    mode: "line",
    message: JSON.parse(line),
    rest,
  };
}

function write(message, mode = outputMode) {
  const payload = JSON.stringify(message);
  if (mode === "framed") {
    process.stdout.write(`Content-Length: ${Buffer.byteLength(payload, "utf8")}\r\n\r\n${payload}`);
  } else {
    process.stdout.write(`${payload}\n`);
  }
}

function rpcError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function sampleSession() {
  return {
    sessionId: "sample",
    binaryId: "sample-macho",
    binary: {
      name: "SampleMachO",
      path: "/tmp/SampleMachO",
      format: "Mach-O",
      arch: "arm64",
      baseAddress: "0x100000000",
    },
    capabilities: { officialApi: true, privateApi: false, dynamicDebugger: false },
    imports: ["_SecItemCopyMatching", "_CC_SHA256", "_ptrace", "_objc_msgSend"],
    exports: ["_main"],
    strings: [
      { addr: "0x100008000", value: "license_key" },
      { addr: "0x100008020", value: "debugger detected" },
      { addr: "0x100008050", value: "https://api.example.invalid/auth" },
    ],
    objcClasses: [{ name: "AuthController", methods: ["-[AuthController validateLicense:]"] }],
    swiftSymbols: [],
    functions: [
      {
        addr: "0x100003f50",
        name: "sub_100003f50",
        size: 192,
        summary: "Checks local license material and hashes a candidate key.",
        confidence: 0.72,
        callers: ["0x100004120"],
        callees: ["0x100004010"],
        strings: ["license_key"],
        imports: ["_SecItemCopyMatching", "_CC_SHA256"],
        pseudocode: "candidate = read_keychain(\"license_key\"); digest = sha256(candidate); return compare_digest(digest);",
        fingerprint: {
          cfgShape: "linear-branch-return",
          importSignature: ["_SecItemCopyMatching", "_CC_SHA256"],
          stringBag: ["license_key"],
        },
        basicBlocks: [
          { addr: "0x100003f50", summary: "Load keychain query and request license_key item." },
          { addr: "0x100003fa8", summary: "Hash candidate bytes with CC_SHA256." },
          { addr: "0x100004000", summary: "Compare digest and return boolean." },
        ],
      },
      {
        addr: "0x100004010",
        name: "sub_100004010",
        size: 80,
        summary: "Compares computed digest against embedded expected bytes.",
        confidence: 0.61,
        callers: ["0x100003f50"],
        callees: [],
        strings: [],
        imports: [],
        basicBlocks: [{ addr: "0x100004010", summary: "Constant-time-ish digest comparison loop." }],
      },
      {
        addr: "0x100004120",
        name: "_main",
        size: 144,
        summary: "Program entrypoint with anti-debug check before license validation.",
        confidence: 0.7,
        callers: [],
        callees: ["0x100003f50"],
        strings: ["debugger detected"],
        imports: ["_ptrace"],
        basicBlocks: [{ addr: "0x100004120", summary: "Calls ptrace and branches before invoking license validation." }],
      },
    ],
  };
}
