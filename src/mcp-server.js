#!/usr/bin/env node
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { KnowledgeStore } from "./knowledge-store.js";
import { TransactionManager } from "./transaction-manager.js";
import { HopperAdapter } from "./hopper-adapter.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const store = new KnowledgeStore(process.env.HOPPER_MCP_STORE ?? join(ROOT, "data", "knowledge-store.json"));
const transactions = new TransactionManager(store);
const adapter = new HopperAdapter({
  socketPath: process.env.HOPPER_MCP_SOCKET ?? null,
  hopperLauncher: process.env.HOPPER_LAUNCHER ?? null,
});

await store.load();

const serverInfo = {
  name: "hopper-mcp-knowledge-engine",
  version: "0.1.0",
};

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
  }, ["executable_path"]),
  tool("resolve", "Resolve an address, name, string, import, or semantic query against the knowledge store.", {
    query: { type: "string" },
    session_id: { type: "string" },
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
    description: "Guide an agent through provenance-first function analysis.",
    arguments: [{ name: "addr", description: "Function address", required: true }],
  },
  {
    name: "hypothesis_workspace",
    description: "Create a cautious reverse-engineering hypothesis with evidence gates.",
    arguments: [{ name: "topic", description: "Hypothesis topic, e.g. license check path", required: true }],
  },
];

const handlers = {
  initialize: async () => ({
    protocolVersion: "2025-06-18",
    capabilities: {
      tools: { listChanged: false },
      resources: { subscribe: false, listChanged: true },
      prompts: { listChanged: false },
      logging: {},
    },
    serverInfo,
  }),
  "notifications/initialized": async () => undefined,
  "tools/list": async () => ({ tools }),
  "tools/call": async (params) => callTool(params.name, params.arguments ?? {}),
  "resources/list": async () => ({ resources: store.listResources() }),
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
};

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  let message = null;
  try {
    message = JSON.parse(line);
    if (!message.id && message.method?.startsWith("notifications/")) continue;
    const result = await dispatch(message);
    if (message.id) write({ jsonrpc: "2.0", id: message.id, result });
  } catch (error) {
    write({ jsonrpc: "2.0", id: message?.id ?? null, error: { code: error.code ?? -32603, message: error.message } });
  }
}

async function dispatch(message) {
  const handler = handlers[message.method];
  if (!handler) throw rpcError(-32601, `Method not found: ${message.method}`);
  return handler(message.params ?? {});
}

async function callTool(name, args) {
  const sessionId = args.session_id ?? "current";
  let result;

  if (name === "capabilities") {
    result = { server: serverInfo, adapter: adapter.capabilities(), sessions: store.listSessions() };
  } else if (name === "open_session") {
    result = await store.upsertSession(args.session);
  } else if (name === "ingest_sample") {
    result = await store.upsertSession(sampleSession());
  } else if (name === "ingest_live_hopper") {
    const live = await adapter.ingestExecutable({
      executablePath: args.executable_path,
      timeoutMs: args.timeout_ms,
      maxFunctions: args.max_functions,
      maxStrings: args.max_strings,
      analysis: args.analysis,
      parseObjectiveC: args.parse_objective_c,
      parseSwift: args.parse_swift,
    });
    const session = await store.upsertSession(live.session);
    result = { session: store.describeSession(session), launch: live.launch };
  } else if (name === "resolve") {
    result = store.resolve(args.query, sessionId);
  } else if (name === "analyze_function_deep") {
    result = store.analyzeFunctionDeep(args.addr, { detailLevel: args.detail_level, sessionId });
  } else if (name === "get_graph_slice") {
    result = store.getGraphSlice(args.seed, { radius: args.radius ?? 1, kind: args.kind ?? "calls", sessionId });
  } else if (name === "search_strings") {
    result = store.searchStrings(args.regex, { semantic: Boolean(args.semantic), sessionId });
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
  } else if (name === "rollback_transaction") {
    result = await transactions.rollback({ transactionId: args.transaction_id, sessionId });
  } else {
    throw rpcError(-32602, `Unknown tool: ${name}`);
  }

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
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
    description,
    inputSchema: {
      type: "object",
      properties,
      required,
      additionalProperties: false,
    },
  };
}

function write(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
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
