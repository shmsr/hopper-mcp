#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { KnowledgeStore, formatAddress, parseAddress } from "./knowledge-store.js";
import { TransactionManager } from "./transaction-manager.js";
import { HopperAdapter } from "./hopper-adapter.js";
import { importMachO, searchMachOStrings, disassembleRange, findXrefs, discoverFunctionsFromDisassembly, mergeFunctionSets } from "./macho-importer.js";
import { OfficialHopperBackend, officialToolPayload } from "./official-hopper-backend.js";
import { buildOfficialSnapshot } from "./official-snapshot.js";
import {
  classifyImports,
  detectAntiAnalysis,
  computeSectionEntropy,
  extractCodeSigning,
  extractObjCRuntime,
  buildFunctionFingerprint,
  functionSimilarity,
  diffSessions,
  queryFunctions,
  discoverX86Functions,
} from "./research-tools.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const store = new KnowledgeStore(process.env.HOPPER_MCP_STORE ?? join(ROOT, "data", "knowledge-store.json"));
const transactions = new TransactionManager(store);
const adapter = new HopperAdapter({
  socketPath: process.env.HOPPER_MCP_SOCKET ?? null,
  hopperLauncher: process.env.HOPPER_LAUNCHER ?? null,
});
const officialBackend = new OfficialHopperBackend();

await store.load();

process.on("exit", () => {
  officialBackend.close();
});

// On a controlled shutdown, flush any in-flight save before exiting so the
// last upsertSession's mutations are not lost (scheduleSave is fire-and-forget).
async function gracefulShutdown(signal) {
  try {
    process.stderr.write(`[hopper-mcp] received ${signal}; flushing knowledge store.\n`);
  } catch {}
  try {
    await store.save();
  } catch (err) {
    try {
      process.stderr.write(`[hopper-mcp] flush failed: ${err?.stack ?? err}\n`);
    } catch {}
  }
  process.exit(0);
}
process.on("SIGINT", () => { gracefulShutdown("SIGINT"); });
process.on("SIGTERM", () => { gracefulShutdown("SIGTERM"); });

const DEBUG_LIFECYCLE = process.env.HOPPER_MCP_DEBUG_LIFECYCLE === "1";
function lifecycleLog(kind, payload) {
  if (!DEBUG_LIFECYCLE) return;
  try {
    process.stderr.write(`[hopper-mcp] ${kind} ${JSON.stringify(payload)}\n`);
  } catch {}
}

process.on("uncaughtException", (err) => {
  try {
    process.stderr.write(`[hopper-mcp] uncaughtException: ${err?.stack ?? err}\n`);
  } catch {}
});
process.on("unhandledRejection", (reason) => {
  try {
    process.stderr.write(`[hopper-mcp] unhandledRejection: ${reason?.stack ?? reason}\n`);
  } catch {}
});
process.stdin.on("error", (err) => {
  try { process.stderr.write(`[hopper-mcp] stdin error: ${err?.message ?? err}\n`); } catch {}
});
process.stdout.on("error", (err) => {
  // The previous handler called process.exit(0) silently, which made the
  // server look like it "vanished" after a successful response if the host
  // closed the pipe. Log first so the cause is visible in MCP logs, then
  // try to flush the store before exiting.
  try {
    process.stderr.write(`[hopper-mcp] stdout error (${err?.code ?? "unknown"}): ${err?.message ?? err}\n`);
  } catch {}
  if (err && err.code === "EPIPE") {
    store.save().catch(() => {}).finally(() => process.exit(0));
    return;
  }
});

const serverInfo = {
  name: "hopper-mcp",
  title: "Hopper MCP",
  version: "0.1.0",
  description: "MCP server for Hopper with resources, tools, prompts, and transaction-safe annotations.",
};

const latestProtocolVersion = "2025-11-25";
const supportedProtocolVersions = new Set([latestProtocolVersion, "2025-06-18", "2025-03-26"]);
const logLevels = new Set(["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]);
const defaultMaxToolTextChars = 120000;
const enableDebugTools = process.env.HOPPER_MCP_ENABLE_DEBUG_TOOLS === "1";
let logLevel = "info";

const tools = [
  tool("capabilities", "Report static/dynamic adapter capabilities.", {}),
  tool("official_hopper_call", "Call Hopper's installed official MCP server. Write/navigation tools require HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 and confirm_live_write=true.", {
    name: { type: "string" },
    arguments: { type: "object" },
    confirm_live_write: { type: "boolean" },
    max_result_chars: { type: "number" },
    include_full_result: { type: "boolean" },
  }, ["name"]),
  tool("official_hopper_tools", "List tools exposed by Hopper's installed official MCP server.", {}),
  ...debugTools(),
  tool("ingest_official_hopper", "Refresh the local snapshot store from Hopper's installed official MCP server.", {
    max_procedures: { type: "number" },
    include_procedure_info: { type: "boolean" },
    include_assembly: { type: "boolean" },
    include_pseudocode: { type: "boolean" },
    include_call_graph: { type: "boolean" },
    fail_on_truncation: { type: "boolean" },
  }),
  tool("refresh_snapshot", "Alias for ingest_official_hopper: refresh the local snapshot from the live official Hopper backend.", {
    max_procedures: { type: "number" },
    include_procedure_info: { type: "boolean" },
    include_assembly: { type: "boolean" },
    include_pseudocode: { type: "boolean" },
    include_call_graph: { type: "boolean" },
    fail_on_truncation: { type: "boolean" },
  }),
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
    include_pseudocode: { type: "boolean" },
    max_pseudocode_functions: { type: "number" },
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
  tool("search_strings", "Search indexed strings. Use pattern/case_sensitive for official-compatible output, or regex/semantic for the extended result shape.", {
    pattern: { type: "string" },
    case_sensitive: { type: "boolean" },
    regex: { type: "string" },
    semantic: { type: "boolean" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("list_documents", "List loaded snapshot sessions.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("current_document", "Return the active snapshot session.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("list_segments", "List segments from the active snapshot.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("list_procedures", "List procedure addresses and names from the active snapshot.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("list_procedure_size", "List procedure sizes and basic-block counts from the active snapshot.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("list_procedure_info", "List compact procedure metadata from the active snapshot.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("list_strings", "List indexed strings from the active snapshot.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("search_procedures", "Search procedure names and metadata in the active snapshot.", {
    pattern: { type: "string" },
    case_sensitive: { type: "boolean" },
    regex: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("procedure_info", "Return full procedure metadata for an address or name.", {
    procedure: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("procedure_address", "Resolve a procedure name or contained address to its entry address.", {
    procedure: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }, ["procedure"]),
  tool("procedure_assembly", "Return assembly captured from Hopper's public Python API.", {
    procedure: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_lines: { type: "number" },
  }),
  tool("procedure_pseudo_code", "Return pseudocode captured during live export, if include_pseudocode was enabled.", {
    procedure: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("procedure_callers", "Return procedure callers from the active snapshot.", {
    procedure: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("procedure_callees", "Return procedure callees from the active snapshot.", {
    procedure: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("xrefs", "Return cross-references to and from an address from the active snapshot.", {
    address: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("current_address", "Return the cursor address captured at export time.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("current_procedure", "Return the cursor procedure captured at export time.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("list_names", "List named addresses captured from Hopper.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("search_name", "Search Hopper names captured in the snapshot.", {
    pattern: { type: "string" },
    case_sensitive: { type: "boolean" },
    regex: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
  tool("address_name", "Return the name for an address, if captured.", {
    address: { type: "string" },
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
  }),
  tool("list_bookmarks", "List Hopper bookmarks captured in the snapshot.", {
    backend: { type: "string", enum: ["snapshot", "official"] },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }),
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
    backend: { type: "string", enum: ["local", "official"] },
    confirm_live_write: { type: "boolean" },
  }),
  tool("rollback_transaction", "Roll back an open transaction without applying writes.", {
    transaction_id: { type: "string" },
    session_id: { type: "string" },
  }),
  tool("classify_capabilities", "Bucket the active session imports into capability groups (network/crypto/file/ipc/proc/anti-analysis/...).", {
    session_id: { type: "string" },
    persist: { type: "boolean", description: "Persist the result onto session.binary.capabilities (default true)." },
  }),
  tool("detect_anti_analysis", "Surface anti-debug, anti-VM, and other anti-analysis patterns in the active session.", {
    session_id: { type: "string" },
    persist: { type: "boolean", description: "Persist findings onto session.antiAnalysisFindings (default true)." },
  }),
  tool("compute_section_entropy", "Compute Shannon entropy per Mach-O section. Flags entropy>=7.5 as suspicious (likely packed).", {
    executable_path: { type: "string" },
    arch: { type: "string" },
    session_id: { type: "string" },
    persist: { type: "boolean" },
    max_bytes_per_section: { type: "number" },
  }),
  tool("extract_code_signing", "Extract code-signing metadata and entitlements via codesign.", {
    executable_path: { type: "string" },
    session_id: { type: "string" },
    persist: { type: "boolean" },
  }),
  tool("extract_objc_runtime", "Recover Objective-C class hierarchy, methods, and IMP addresses from a Mach-O via otool -ov.", {
    executable_path: { type: "string" },
    arch: { type: "string" },
    session_id: { type: "string" },
    max_classes: { type: "number" },
    persist: { type: "boolean" },
  }),
  tool("compute_fingerprints", "Recompute imphash/simhash/minhash fingerprints for the active session's functions.", {
    session_id: { type: "string" },
  }),
  tool("find_similar_functions", "Find functions across loaded sessions that resemble a target by fingerprint.", {
    addr: { type: "string", description: "Function address (defaults to current procedure)." },
    session_id: { type: "string" },
    target_session_id: { type: "string", description: "Restrict results to this session (default: all sessions)." },
    min_similarity: { type: "number", description: "Lower bound on overall similarity (0-1, default 0.4)." },
    max_results: { type: "number" },
  }),
  tool("diff_sessions", "Diff two sessions: added/removed/renamed/changed functions, strings, imports.", {
    left_session_id: { type: "string" },
    right_session_id: { type: "string" },
  }, ["left_session_id", "right_session_id"]),
  tool("query", "Run a structured query against the active session. Predicates: name, calls, callers, callees, imports, string, tag, capability, anti, addr, pseudocode, size. Connectors: AND, OR, NOT, parens.", {
    expression: { type: "string" },
    session_id: { type: "string" },
    max_results: { type: "number" },
  }, ["expression"]),
  tool("queue_tag", "Queue a persistent tag (or list of tags) on an address in the current transaction.", {
    transaction_id: { type: "string" },
    addr: { type: "string" },
    tag: { type: "string" },
    tags: { type: "array", items: { type: "string" } },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["addr"]),
  tool("queue_untag", "Queue removal of one or more tags from an address.", {
    transaction_id: { type: "string" },
    addr: { type: "string" },
    tag: { type: "string" },
    tags: { type: "array", items: { type: "string" } },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["addr"]),
  tool("list_tags", "List address tags in the active session.", {
    session_id: { type: "string" },
  }),
  tool("queue_rename_batch", "Queue a bulk rename mapping {addr: newName} in the active transaction.", {
    transaction_id: { type: "string" },
    mapping: { type: "object", description: "Object whose keys are addresses and values are new names." },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["mapping"]),
  tool("create_hypothesis", "Queue creation of a structured hypothesis record (topic, claim, status).", {
    transaction_id: { type: "string" },
    topic: { type: "string" },
    claim: { type: "string" },
    status: { type: "string", enum: ["open", "supported", "refuted", "abandoned"] },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["topic"]),
  tool("link_evidence", "Queue an evidence link onto a hypothesis (address, string, import, or note).", {
    transaction_id: { type: "string" },
    hypothesis_id: { type: "string" },
    addr: { type: "string" },
    evidence: { type: "string" },
    evidence_kind: { type: "string", enum: ["address", "string", "import", "note", "selector"] },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["hypothesis_id"]),
  tool("set_hypothesis_status", "Queue a status change on a hypothesis (open/supported/refuted/abandoned).", {
    transaction_id: { type: "string" },
    hypothesis_id: { type: "string" },
    status: { type: "string", enum: ["open", "supported", "refuted", "abandoned"] },
    rationale: { type: "string" },
    session_id: { type: "string" },
  }, ["hypothesis_id", "status"]),
  tool("list_hypotheses", "List hypotheses recorded for the active session.", {
    session_id: { type: "string" },
    status: { type: "string", enum: ["open", "supported", "refuted", "abandoned"] },
  }),
];

const officialMirrorTools = new Set([
  "list_documents",
  "current_document",
  "list_segments",
  "list_procedures",
  "list_procedure_size",
  "list_procedure_info",
  "list_strings",
  "search_strings",
  "search_procedures",
  "procedure_info",
  "procedure_address",
  "current_address",
  "current_procedure",
  "procedure_assembly",
  "procedure_pseudo_code",
  "procedure_callers",
  "procedure_callees",
  "xrefs",
  "list_names",
  "search_name",
  "address_name",
  "list_bookmarks",
]);

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

const FRAMED_PREFIX = Buffer.from("Content-Length:", "utf8");
let inputChunks = [];
let inputBytes = 0;
let outputMode = "line";
let processing = Promise.resolve();
let inFlight = 0;
let inFlightDrained = null;

function scheduleDrain() {
  processing = processing.then(() => drainInputBuffer());
  return processing;
}

function trackHandler(promise) {
  inFlight += 1;
  Promise.resolve(promise).finally(() => {
    inFlight -= 1;
    if (inFlight === 0 && inFlightDrained) {
      const resolve = inFlightDrained;
      inFlightDrained = null;
      resolve();
    }
  });
}

function readInputBuffer() {
  if (inputChunks.length === 0) return Buffer.alloc(0);
  if (inputChunks.length === 1) return inputChunks[0];
  const merged = Buffer.concat(inputChunks, inputBytes);
  inputChunks = [merged];
  return merged;
}

function setRemainingInput(rest) {
  if (!rest || rest.length === 0) {
    inputChunks = [];
    inputBytes = 0;
  } else {
    inputChunks = [rest];
    inputBytes = rest.length;
  }
}

process.stdin.on("data", (chunk) => {
  inputChunks.push(chunk);
  inputBytes += chunk.length;
  scheduleDrain();
});

await new Promise((resolve) => process.stdin.on("end", resolve));
await scheduleDrain();
if (inFlight > 0) {
  await new Promise((resolve) => { inFlightDrained = resolve; });
}

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
    result = { server: serverInfo, adapter: adapter.capabilities(), officialBackend: officialBackend.capabilities(), sessions: store.listSessions() };
  } else if (name === "official_hopper_call") {
    const officialResult = await officialBackend.callTool(args.name, args.arguments ?? {}, { confirmLiveWrite: Boolean(args.confirm_live_write) });
    result = officialToolPayload(officialResult);
    return toolResult(result, {
      maxTextChars: boundedNumber(args.max_result_chars, defaultMaxToolTextChars),
      includeFullResult: Boolean(args.include_full_result),
    });
  } else if (name === "official_hopper_tools") {
    result = await officialBackend.listTools();
  } else if (name === "debug_echo") {
    return toolResult(args.value, {
      maxTextChars: boundedNumber(args.max_result_chars, defaultMaxToolTextChars),
      includeFullResult: Boolean(args.include_full_result),
    });
  } else if (name === "ingest_official_hopper" || name === "refresh_snapshot") {
    notifyProgress(progressToken, 0, 2, "Reading live Hopper document through the official MCP backend.");
    const snapshot = await buildOfficialSnapshot(officialBackend, {
      maxProcedures: args.max_procedures,
      includeProcedureInfo: args.include_procedure_info !== false,
      includeAssembly: Boolean(args.include_assembly),
      includePseudocode: Boolean(args.include_pseudocode),
      includeCallGraph: Boolean(args.include_call_graph),
      failOnTruncation: Boolean(args.fail_on_truncation),
    });
    notifyProgress(progressToken, 1, 2, "Updating local snapshot store.");
    const session = await store.upsertSession(snapshot);
    notifyResourceListChanged();
    notifyProgress(progressToken, 2, 2, "Official Hopper snapshot refreshed.");
    result = { session: store.describeSession(session), source: "official-hopper-mcp" };
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
      includePseudocode: args.include_pseudocode,
      maxPseudocodeFunctions: args.max_pseudocode_functions,
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
      arch: args.arch ?? "auto",
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
      arch: args.arch ?? "auto",
      startAddr: args.start_addr,
      endAddr: args.end_addr,
      maxLines: args.max_lines ?? 500,
    });
  } else if (name === "find_xrefs") {
    const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
    notifyProgress(progressToken, 0, 1, "Scanning binary for cross-references (streaming otool).");
    result = await findXrefs(binaryPath, {
      arch: args.arch ?? "auto",
      targetAddr: args.target_addr,
      maxResults: args.max_results ?? 50,
    });
    notifyProgress(progressToken, 1, 1, `Found ${result.length} xrefs.`);
  } else if (name === "find_functions") {
    const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
    notifyProgress(progressToken, 0, 1, "Scanning for function prologues.");
    const discovery = await discoverFunctionsFromDisassembly(binaryPath, {
      arch: args.arch ?? "auto",
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
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const pattern = args.pattern ?? args.regex;
    if (!pattern) throw rpcError(-32602, "search_strings requires pattern or regex.");
    if (args.pattern !== undefined) {
      result = objectFromAddressItems(searchStringsOfficial(pattern, { caseSensitive: Boolean(args.case_sensitive), sessionId, maxResults: args.max_results }), "value");
    } else {
      result = store.searchStrings(pattern, { semantic: Boolean(args.semantic), sessionId, maxResults: args.max_results });
      if (!result.length) {
        result = await searchSessionBinaryStrings(pattern, { semantic: Boolean(args.semantic), sessionId, maxResults: args.max_results });
      }
    }
  } else if (name === "list_documents") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = store.listSessions().map((session) => session.name);
  } else if (name === "current_document") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = store.getSession(sessionId).binary?.name ?? "unknown";
  } else if (name === "list_segments") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = getSessionSegments(sessionId).map(officialSegment);
  } else if (name === "list_procedures") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = objectFromFunctions(listProcedures(sessionId, { maxResults: args.max_results }), (fn) => fn.name ?? fn.addr);
  } else if (name === "list_procedure_size") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = objectFromFunctions(listProcedures(sessionId, { maxResults: args.max_results }), (fn) => ({
      name: fn.name ?? null,
      basicblock_count: fn.basicBlockCount ?? fn.basicBlocks?.length ?? 0,
      size: fn.size ?? null,
    }));
  } else if (name === "list_procedure_info") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = objectFromFunctions(listProcedures(sessionId, { maxResults: args.max_results }), officialProcedureInfo);
  } else if (name === "list_strings") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    result = objectFromAddressItems(limitResults(session.strings ?? [], args.max_results), "value");
  } else if (name === "search_procedures") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const pattern = args.pattern ?? args.regex;
    if (!pattern) throw rpcError(-32602, "search_procedures requires pattern or regex.");
    const regex = new RegExp(pattern, args.case_sensitive ? "" : "i");
    result = objectFromFunctions(
      limitResults(listProcedures(sessionId).filter((fn) => regex.test([fn.addr, fn.name, fn.signature, fn.summary].filter(Boolean).join(" "))), args.max_results),
      (fn) => fn.name ?? fn.addr,
    );
  } else if (name === "procedure_info") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = officialProcedureInfo(resolveProcedure(defaultProcedureQuery(args.procedure, sessionId), sessionId));
  } else if (name === "procedure_address") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = resolveProcedure(defaultProcedureQuery(args.procedure, sessionId), sessionId).addr;
  } else if (name === "procedure_assembly") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const fn = resolveProcedure(defaultProcedureQuery(args.procedure, sessionId), sessionId);
    const lines = assemblyLines(fn);
    result = args.max_lines ? lines.slice(0, args.max_lines).join("\n") : lines.join("\n");
  } else if (name === "procedure_pseudo_code") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const fn = resolveProcedure(defaultProcedureQuery(args.procedure, sessionId), sessionId);
    result = fn.pseudocode ?? "Pseudocode was not captured. Re-run ingest_live_hopper with include_pseudocode=true for selected functions.";
  } else if (name === "procedure_callers") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    const fn = resolveProcedure(defaultProcedureQuery(args.procedure, sessionId), sessionId);
    result = (fn.callers ?? []).map((addr) => store.getFunctionIfKnown(session, addr).name ?? addr);
  } else if (name === "procedure_callees") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    const fn = resolveProcedure(defaultProcedureQuery(args.procedure, sessionId), sessionId);
    result = (fn.callees ?? []).map((addr) => store.getFunctionIfKnown(session, addr).name ?? addr);
  } else if (name === "xrefs") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = snapshotXrefs(defaultAddressQuery(args.address, sessionId), sessionId);
  } else if (name === "current_address") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    result = session.cursor?.address ?? null;
  } else if (name === "current_procedure") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    const addr = session.cursor?.procedure;
    result = addr ? store.getFunctionIfKnown(session, addr).name ?? addr : null;
  } else if (name === "list_names") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    result = objectFromAddressItems(limitResults(session.names ?? [], args.max_results), "name");
  } else if (name === "search_name") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    const pattern = args.pattern ?? args.regex;
    if (!pattern) throw rpcError(-32602, "search_name requires pattern or regex.");
    const regex = new RegExp(pattern, args.case_sensitive ? "" : "i");
    result = objectFromAddressItems(limitResults((session.names ?? []).filter((item) => regex.test([item.addr, item.name, item.demangled].filter(Boolean).join(" "))), args.max_results), "name");
  } else if (name === "address_name") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    result = lookupName(defaultAddressQuery(args.address, sessionId), sessionId).name ?? "There is no name at this address";
  } else if (name === "list_bookmarks") {
    if (shouldUseOfficial(name, args)) {
      result = await callOfficialMirrorTool(name, args);
      return toolResult(result);
    }
    const session = store.getSession(sessionId);
    result = limitResults(session.bookmarks ?? [], args.max_results);
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
    const commitAdapter = args.backend === "official"
      ? {
        applyTransaction: (session, transaction) => officialBackend.applyTransaction(session, transaction, { confirmLiveWrite: Boolean(args.confirm_live_write) }),
      }
      : adapter;
    result = await transactions.commit({ transactionId: args.transaction_id, sessionId, adapter: commitAdapter });
    notifyResourceListChanged();
  } else if (name === "rollback_transaction") {
    result = await transactions.rollback({ transactionId: args.transaction_id, sessionId });
  } else if (name === "classify_capabilities") {
    const session = store.getSession(sessionId);
    const capabilities = classifyImports(session.imports ?? []);
    if (args.persist !== false) {
      session.binary ??= {};
      session.binary.capabilities = capabilities;
      await store.save();
      notifyResourceListChanged();
    }
    result = capabilities;
  } else if (name === "detect_anti_analysis") {
    const session = store.getSession(sessionId);
    const findings = detectAntiAnalysis(session);
    if (args.persist !== false) {
      session.antiAnalysisFindings = findings;
      await store.save();
      notifyResourceListChanged();
    }
    result = findings;
  } else if (name === "compute_section_entropy") {
    const session = sessionOrNull(sessionId);
    const binaryPath = args.executable_path ?? session?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "compute_section_entropy needs executable_path or a session binary path.");
    const entropy = await computeSectionEntropy(binaryPath, args.arch ?? session?.binary?.arch ?? "auto", {
      maxBytes: args.max_bytes_per_section ?? 4 * 1024 * 1024,
    });
    if (args.persist !== false && session) {
      session.binary ??= {};
      session.binary.sectionEntropy = entropy;
      await store.save();
      notifyResourceListChanged();
    }
    result = entropy;
  } else if (name === "extract_code_signing") {
    const session = sessionOrNull(sessionId);
    const binaryPath = args.executable_path ?? session?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "extract_code_signing needs executable_path or a session binary path.");
    const signing = await extractCodeSigning(binaryPath);
    if (args.persist !== false && session) {
      session.binary ??= {};
      session.binary.signing = signing;
      await store.save();
      notifyResourceListChanged();
    }
    result = signing;
  } else if (name === "extract_objc_runtime") {
    const session = sessionOrNull(sessionId);
    const binaryPath = args.executable_path ?? session?.binary?.path;
    if (!binaryPath) throw rpcError(-32602, "extract_objc_runtime needs executable_path or a session binary path.");
    const classes = await extractObjCRuntime(binaryPath, args.arch ?? session?.binary?.arch ?? "auto", { maxClasses: args.max_classes ?? 1000 });
    if (args.persist !== false && session) {
      session.objcClasses = classes;
      await store.save();
      notifyResourceListChanged();
    }
    result = { count: classes.length, classes };
  } else if (name === "compute_fingerprints") {
    const session = store.getSession(sessionId);
    let updated = 0;
    for (const fn of Object.values(session.functions ?? {})) {
      fn.fingerprint = buildFunctionFingerprint(fn, session.imports ?? []);
      updated += 1;
    }
    await store.save();
    notifyResourceListChanged();
    result = { updated };
  } else if (name === "find_similar_functions") {
    result = findSimilarFunctions({
      sessionId,
      addr: args.addr,
      targetSessionId: args.target_session_id,
      minSimilarity: args.min_similarity ?? 0.4,
      maxResults: args.max_results ?? 25,
    });
  } else if (name === "diff_sessions") {
    const left = store.getSession(args.left_session_id);
    const right = store.getSession(args.right_session_id);
    result = diffSessions(left, right);
  } else if (name === "query") {
    const session = store.getSession(sessionId);
    const matches = queryFunctions(session, args.expression, {
      maxResults: args.max_results ?? 50,
      capabilities: session.binary?.capabilities ?? null,
      antiAnalysis: session.antiAnalysisFindings ?? [],
    });
    result = { count: matches.length, matches };
  } else if (name === "queue_tag") {
    const tags = args.tags ?? (args.tag ? [args.tag] : []);
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "tag", addr: args.addr, tags, rationale: args.rationale }, { sessionId });
  } else if (name === "queue_untag") {
    const tags = args.tags ?? (args.tag ? [args.tag] : []);
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "untag", addr: args.addr, tags, rationale: args.rationale }, { sessionId });
  } else if (name === "list_tags") {
    const session = store.getSession(sessionId);
    result = session.tags ?? {};
  } else if (name === "queue_rename_batch") {
    result = await transactions.queue({ transactionId: args.transaction_id, kind: "rename_batch", mapping: args.mapping, rationale: args.rationale }, { sessionId });
  } else if (name === "create_hypothesis") {
    result = await transactions.queue({
      transactionId: args.transaction_id,
      kind: "hypothesis_create",
      topic: args.topic,
      claim: args.claim,
      status: args.status ?? "open",
      rationale: args.rationale,
    }, { sessionId });
  } else if (name === "link_evidence") {
    result = await transactions.queue({
      transactionId: args.transaction_id,
      kind: "hypothesis_link",
      hypothesisId: args.hypothesis_id,
      addr: args.addr,
      evidence: args.evidence,
      evidenceKind: args.evidence_kind ?? (args.addr ? "address" : "note"),
      rationale: args.rationale,
    }, { sessionId });
  } else if (name === "set_hypothesis_status") {
    result = await transactions.queue({
      transactionId: args.transaction_id,
      kind: "hypothesis_status",
      hypothesisId: args.hypothesis_id,
      status: args.status,
      rationale: args.rationale,
    }, { sessionId });
  } else if (name === "list_hypotheses") {
    const session = store.getSession(sessionId);
    const list = session.hypotheses ?? [];
    result = args.status ? list.filter((h) => h.status === args.status) : list;
  }

  return toolResult(result);
}

function sessionOrNull(sessionId) {
  try {
    return store.getSession(sessionId);
  } catch {
    return null;
  }
}

function findSimilarFunctions({ sessionId, addr, targetSessionId, minSimilarity, maxResults }) {
  const session = store.getSession(sessionId);
  const targetAddr = addr ?? session.cursor?.procedure ?? session.cursor?.address;
  if (!targetAddr) throw rpcError(-32602, "find_similar_functions needs addr or a captured cursor.");
  const target = store.getFunction(session, targetAddr);
  if (!target.fingerprint) target.fingerprint = buildFunctionFingerprint(target, session.imports ?? []);

  const sessionsToScan = targetSessionId ? [store.getSession(targetSessionId)] : Object.values(store.state.sessions);
  const results = [];
  for (const candidateSession of sessionsToScan) {
    for (const candidate of Object.values(candidateSession.functions ?? {})) {
      if (candidateSession.sessionId === session.sessionId && candidate.addr === target.addr) continue;
      if (!candidate.fingerprint) candidate.fingerprint = buildFunctionFingerprint(candidate, candidateSession.imports ?? []);
      const score = functionSimilarity(target.fingerprint, candidate.fingerprint);
      if (score.similarity >= minSimilarity) {
        results.push({
          sessionId: candidateSession.sessionId,
          binary: candidateSession.binary?.name ?? null,
          addr: candidate.addr,
          name: candidate.name ?? null,
          summary: candidate.summary ?? null,
          similarity: Number(score.similarity.toFixed(4)),
          components: Object.fromEntries(Object.entries(score.components).map(([k, v]) => [k, Number(v.toFixed(4))])),
        });
      }
    }
  }
  results.sort((a, b) => b.similarity - a.similarity);
  return {
    target: { sessionId: session.sessionId, addr: target.addr, name: target.name ?? null, fingerprint: target.fingerprint },
    matches: results.slice(0, maxResults),
  };
}

function getSessionSegments(sessionId) {
  const session = store.getSession(sessionId);
  return session.binary?.segments ?? [];
}

function shouldUseOfficial(name, args) {
  return officialMirrorTools.has(name) && args.backend === "official";
}

async function callOfficialMirrorTool(name, args) {
  const officialArgs = toOfficialArgs(name, args);
  const result = await officialBackend.callTool(name, officialArgs);
  return officialToolPayload(result);
}

function toOfficialArgs(name, args) {
  const officialArgs = {};
  for (const [key, value] of Object.entries(args)) {
    if (value === undefined) continue;
    if (["backend", "session_id", "max_results", "semantic", "max_lines"].includes(key)) continue;
    if (key === "regex" && args.pattern === undefined && ["search_strings", "search_procedures", "search_name"].includes(name)) {
      officialArgs.pattern = value;
      continue;
    }
    officialArgs[key] = value;
  }
  return officialArgs;
}

function officialSegment(segment) {
  const start = parseAddress(segment.start);
  const length = Number(segment.length ?? 0);
  const end = segment.end ?? (start !== null && length > 0 ? formatAddress(start + length) : null);
  return {
    name: segment.name ?? null,
    start: segment.start ?? null,
    end,
    writable: String(Boolean(segment.writable ?? segment.writeable ?? segment.protection?.includes?.("w"))),
    executable: String(Boolean(segment.executable ?? segment.protection?.includes?.("x"))),
    sections: (segment.sections ?? []).map((section) => {
      const sectionStart = parseAddress(section.start);
      const sectionLength = Number(section.length ?? 0);
      return {
        name: section.name ?? null,
        start: section.start ?? null,
        end: section.end ?? (sectionStart !== null && sectionLength > 0 ? formatAddress(sectionStart + sectionLength) : null),
      };
    }),
  };
}

function listProcedures(sessionId, { maxResults } = {}) {
  const session = store.getSession(sessionId);
  return limitResults(
    Object.values(session.functions ?? {}).sort((a, b) => {
      const aNamed = isMeaningfullyNamedProcedure(a) ? 0 : 1;
      const bNamed = isMeaningfullyNamedProcedure(b) ? 0 : 1;
      if (aNamed !== bNamed) return aNamed - bNamed;
      return (parseAddress(a.addr) ?? 0) - (parseAddress(b.addr) ?? 0);
    }),
    maxResults,
  );
}

function isMeaningfullyNamedProcedure(fn) {
  const name = String(fn?.name ?? "");
  return Boolean(name) && !name.startsWith("sub_");
}

function defaultProcedureQuery(procedure, sessionId) {
  if (procedure) return procedure;
  const session = store.getSession(sessionId);
  if (session.cursor?.procedure) return session.cursor.procedure;
  if (session.cursor?.address) return session.cursor.address;
  throw rpcError(-32602, "No procedure supplied and no current procedure was captured in the snapshot.");
}

function defaultAddressQuery(address, sessionId) {
  if (address) return address;
  const session = store.getSession(sessionId);
  if (session.cursor?.address) return session.cursor.address;
  throw rpcError(-32602, "No address supplied and no current address was captured in the snapshot.");
}

function resolveProcedure(query, sessionId) {
  const session = store.getSession(sessionId);
  const address = parseAddress(query);
  if (address !== null && !Number.isNaN(address)) {
    const exact = session.functions[formatAddress(address)];
    if (exact) return exact;
    const containing = Object.values(session.functions ?? {}).find((fn) => {
      const start = parseAddress(fn.addr);
      const size = Number(fn.size ?? 0);
      return start !== null && size > 0 && address >= start && address < start + size;
    });
    if (containing) return containing;
  }

  const lower = String(query).toLowerCase();
  const matches = Object.values(session.functions ?? {}).filter((fn) => {
    const fields = [fn.name, fn.signature, fn.addr].filter(Boolean).map((value) => String(value).toLowerCase());
    return fields.some((field) => field === lower || field.includes(lower));
  });
  if (!matches.length) throw rpcError(-32602, `Unknown procedure: ${query}`);
  return matches.sort((a, b) => scoreProcedureNameMatch(b, lower) - scoreProcedureNameMatch(a, lower))[0];
}

function scoreProcedureNameMatch(fn, lower) {
  const name = String(fn.name ?? "").toLowerCase();
  if (name === lower) return 3;
  if (name.startsWith(lower)) return 2;
  if (name.includes(lower)) return 1;
  return 0;
}

function officialProcedureInfo(fn) {
  return {
    name: fn.name ?? null,
    entrypoint: fn.addr,
    basicblock_count: fn.basicBlockCount ?? fn.basicBlocks?.length ?? 0,
    basicblocks: (fn.basicBlocks ?? []).map((block) => ({
      from: block.from ?? block.addr ?? null,
      to: block.to ?? block.end ?? block.addr ?? null,
    })),
    length: fn.size ?? null,
    signature: fn.signature ?? null,
    locals: fn.locals ?? [],
  };
}

function assemblyLines(fn) {
  if (fn.assembly) return String(fn.assembly).split("\n").filter(Boolean);
  return (fn.basicBlocks ?? []).flatMap((block) => (block.instructions ?? []).map((instruction) => `${instruction.addr}: ${instruction.text ?? ""}`.trim()));
}

function snapshotXrefs(address, sessionId) {
  const session = store.getSession(sessionId);
  const target = formatAddress(address);
  const refs = [];

  for (const fn of Object.values(session.functions ?? {})) {
    for (const ref of fn.callerRefs ?? []) {
      if (formatAddress(ref.to) === target) refs.push(ref.from);
    }
    for (const ref of fn.calleeRefs ?? []) {
      if (formatAddress(ref.to) === target) refs.push(ref.from);
    }
    if ((fn.callees ?? []).map(formatAddress).includes(target)) refs.push(fn.addr);
    for (const block of fn.basicBlocks ?? []) {
      for (const instruction of block.instructions ?? []) {
        for (const ref of instruction.refsFrom ?? []) {
          if (formatAddress(ref) === target) refs.push(instruction.addr);
        }
      }
    }
  }

  return [...new Set(refs.filter(Boolean).map(formatAddress))];
}

function lookupName(address, sessionId) {
  const session = store.getSession(sessionId);
  const target = formatAddress(address);
  const named = (session.names ?? []).find((item) => formatAddress(item.addr) === target);
  if (named) return named;
  const fn = session.functions?.[target];
  return { addr: target, name: fn?.name ?? null, demangled: null };
}

function limitResults(items, maxResults) {
  const limit = Number(maxResults ?? 0);
  if (!limit || limit < 0) return items;
  return items.slice(0, limit);
}

function boundedNumber(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(0, Math.floor(parsed));
}

function objectFromFunctions(functions, mapper) {
  return Object.fromEntries(functions.map((fn) => [fn.addr, mapper(fn)]));
}

function objectFromAddressItems(items, field) {
  return Object.fromEntries(items.filter((item) => item.addr).map((item) => [formatAddress(item.addr), item[field] ?? null]));
}

function searchStringsOfficial(pattern, { caseSensitive, sessionId, maxResults }) {
  const session = store.getSession(sessionId);
  const regex = new RegExp(pattern, caseSensitive ? "" : "i");
  return limitResults((session.strings ?? []).filter((item) => regex.test(item.value ?? "")), maxResults);
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

function toolResult(result, { maxTextChars = defaultMaxToolTextChars, includeFullResult = true } = {}) {
  const contentText = formatToolText(result, { maxTextChars });
  return {
    content: [{ type: "text", text: contentText }],
    structuredContent: structuredToolContent(result, { maxTextChars, includeFullResult }),
  };
}

function formatToolText(result, { maxTextChars }) {
  const text = JSON.stringify(result, null, 2);
  if (!maxTextChars || maxTextChars < 0 || text.length <= maxTextChars) return text;
  return JSON.stringify({
    truncated: true,
    originalChars: text.length,
    returnedChars: maxTextChars,
    preview: text.slice(0, maxTextChars),
  }, null, 2);
}

function structuredToolContent(result, { maxTextChars = defaultMaxToolTextChars, includeFullResult = true } = {}) {
  if (typeof result === "string") {
    if (!maxTextChars || maxTextChars < 0 || result.length <= maxTextChars) return { result };
    return removeUndefined({
      result: includeFullResult ? result : undefined,
      resultPreview: result.slice(0, maxTextChars),
      truncated: true,
      originalChars: result.length,
      returnedChars: maxTextChars,
    });
  }
  if (result && typeof result === "object" && !Array.isArray(result)) return result;
  return { result };
}

function removeUndefined(object) {
  return Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));
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

function debugTools() {
  if (!enableDebugTools) return [];
  return [
    tool("debug_echo", "Internal test helper that echoes a payload through the MCP result formatter.", {
      value: { type: "string" },
      max_result_chars: { type: "number" },
      include_full_result: { type: "boolean" },
    }, ["value"]),
  ];
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
  const startedAt = Date.now();
  lifecycleLog("request", { id: message.id ?? null, method: message.method });
  try {
    if (!hasId && message.method?.startsWith("notifications/")) return;
    const result = await dispatch(message);
    if (hasId) {
      write({ jsonrpc: "2.0", id: message.id, result }, mode);
      if (DEBUG_LIFECYCLE) {
        // JSON.stringify(result) can be expensive on large results; only
        // pay the cost when lifecycle logging is actually enabled.
        lifecycleLog("response", { id: message.id, method: message.method, ms: Date.now() - startedAt, bytes: JSON.stringify(result).length });
      }
    }
  } catch (error) {
    if (hasId) {
      write({ jsonrpc: "2.0", id: message.id, error: { code: error.code ?? -32603, message: error.message } }, mode);
      lifecycleLog("error", { id: message.id, method: message.method, ms: Date.now() - startedAt, message: error.message });
    }
  }
}

async function drainInputBuffer() {
  for (;;) {
    const buffer = readInputBuffer();
    const parsed = parseNextMessage(buffer);
    if (!parsed) return;
    setRemainingInput(parsed.rest);
    if (!parsed.message) continue;
    trackHandler(handleMessage(parsed.message, parsed.mode));
  }
}

function findHeaderTerminator(buffer) {
  const limit = Math.min(buffer.length, 64 * 1024);
  for (let i = 0; i < limit - 1; i += 1) {
    if (buffer[i] === 0x0a && buffer[i + 1] === 0x0a) {
      return { headerEnd: i, bodyStart: i + 2 };
    }
    if (
      i + 3 < limit &&
      buffer[i] === 0x0d &&
      buffer[i + 1] === 0x0a &&
      buffer[i + 2] === 0x0d &&
      buffer[i + 3] === 0x0a
    ) {
      return { headerEnd: i, bodyStart: i + 4 };
    }
  }
  return null;
}

function parseNextMessage(buffer) {
  if (!buffer.length) return null;

  if (buffer.length >= FRAMED_PREFIX.length && buffer.compare(FRAMED_PREFIX, 0, FRAMED_PREFIX.length, 0, FRAMED_PREFIX.length) === 0) {
    const terminator = findHeaderTerminator(buffer);
    if (!terminator) return null;
    const header = buffer.subarray(0, terminator.headerEnd).toString("utf8");
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (!match) throw new Error("Invalid MCP frame: missing Content-Length.");
    const contentLength = Number(match[1]);
    const bodyEnd = terminator.bodyStart + contentLength;
    if (buffer.length < bodyEnd) return null;
    const body = buffer.subarray(terminator.bodyStart, bodyEnd).toString("utf8");
    return {
      mode: "framed",
      message: JSON.parse(body),
      rest: buffer.subarray(bodyEnd),
    };
  }

  const newline = buffer.indexOf(0x0a);
  if (newline === -1) return null;
  const line = buffer.subarray(0, newline).toString("utf8").trim();
  const rest = buffer.subarray(newline + 1);
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
    names: [
      { addr: "0x100003f50", name: "sub_100003f50", demangled: null },
      { addr: "0x100004120", name: "_main", demangled: null },
    ],
    bookmarks: [{ addr: "0x100003f50", name: "license validation candidate" }],
    comments: [{ addr: "0x100003f50", comment: "Sample prefix comment." }],
    inlineComments: [{ addr: "0x100003fa8", comment: "Sample inline comment." }],
    cursor: { address: "0x100003f50", procedure: "0x100003f50", selection: [] },
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
