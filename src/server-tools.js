import { z } from "zod";
import {
  importMachO,
  searchMachOStrings,
  disassembleRange,
  findXrefs,
  discoverFunctionsFromDisassembly,
  mergeFunctionSets,
} from "./macho-importer.js";
import { officialToolPayload } from "./official-hopper-backend.js";
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
} from "./research-tools.js";
import {
  rpcError,
  sessionOrNull,
  listProcedures,
  defaultProcedureQuery,
  defaultAddressQuery,
  resolveProcedure,
  officialProcedureInfo,
  assemblyLines,
  snapshotXrefs,
  limitResults,
  objectFromFunctions,
  objectFromAddressItems,
  searchStringsOfficial,
} from "./server-helpers.js";
import { toolResult, boundedNumber, DEFAULT_MAX_TOOL_TEXT_CHARS } from "./server-format.js";
import { sampleSession } from "./sample-session.js";

const READ_ONLY = { readOnlyHint: true, openWorldHint: false };
const READ_OPEN_WORLD = { readOnlyHint: true, openWorldHint: true };
const WRITE_LOCAL = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const WRITE_LIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true };

const optionalString = z.string().optional();
const optionalNumber = z.number().optional();
const optionalBool = z.boolean().optional();

export function registerTools(server, ctx) {
  const { store, transactions, adapter, officialBackend, serverInfo } = ctx;
  const enableDebugTools = process.env.HOPPER_MCP_ENABLE_DEBUG_TOOLS === "1";

  const notifyProgress = async (extra, progress, total, message) => {
    const progressToken = extra?._meta?.progressToken;
    if (progressToken === undefined || progressToken === null) return;
    try {
      await extra.sendNotification({
        method: "notifications/progress",
        params: { progressToken, progress, total, message },
      });
    } catch {}
  };

  const notifyResourceListChanged = () => {
    try {
      server.sendResourceListChanged();
    } catch {}
  };

  const sessionFor = (args) => args.session_id ?? "current";

  // ── meta + lifecycle ────────────────────────────────────────────────────
  server.registerTool(
    "capabilities",
    {
      title: "Capabilities",
      description: "Report static/dynamic adapter capabilities and the list of loaded sessions.",
      inputSchema: {},
      annotations: READ_ONLY,
    },
    async () =>
      toolResult({
        server: serverInfo,
        adapter: adapter.capabilities(),
        officialBackend: officialBackend.capabilities(),
        sessions: store.listSessions(),
      }),
  );

  server.registerTool(
    "official_hopper_call",
    {
      title: "Official Hopper Call",
      description:
        "Call Hopper's installed official MCP server directly. The single passthrough — name + arguments map to the official tool. Write/navigation tools require HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 and confirm_live_write=true.",
      inputSchema: {
        name: z.string(),
        arguments: z.record(z.string(), z.any()).optional(),
        confirm_live_write: optionalBool,
        max_result_chars: optionalNumber,
        include_full_result: optionalBool,
      },
      annotations: WRITE_LIVE,
    },
    async (args) => {
      const officialResult = await officialBackend.callTool(args.name, args.arguments ?? {}, {
        confirmLiveWrite: Boolean(args.confirm_live_write),
      });
      const result = officialToolPayload(officialResult);
      return toolResult(result, {
        maxTextChars: boundedNumber(args.max_result_chars, DEFAULT_MAX_TOOL_TEXT_CHARS),
        includeFullResult: Boolean(args.include_full_result),
      });
    },
  );

  server.registerTool(
    "official_hopper_tools",
    {
      title: "Official Hopper Tools",
      description: "List tools exposed by Hopper's installed official MCP server.",
      inputSchema: {},
      annotations: READ_OPEN_WORLD,
    },
    async () => toolResult(await officialBackend.listTools()),
  );

  if (enableDebugTools) {
    server.registerTool(
      "debug_echo",
      {
        title: "Debug Echo",
        description: "Internal test helper that echoes a payload through the MCP result formatter.",
        inputSchema: {
          value: z.string(),
          max_result_chars: optionalNumber,
          include_full_result: optionalBool,
        },
        annotations: READ_ONLY,
      },
      async (args) =>
        toolResult(args.value, {
          maxTextChars: boundedNumber(args.max_result_chars, DEFAULT_MAX_TOOL_TEXT_CHARS),
          includeFullResult: Boolean(args.include_full_result),
        }),
    );
  }

  // ── ingest + import ────────────────────────────────────────────────────
  const ingestSchema = {
    max_procedures: optionalNumber,
    include_procedure_info: optionalBool,
    include_assembly: optionalBool,
    include_pseudocode: optionalBool,
    include_call_graph: optionalBool,
    fail_on_truncation: optionalBool,
  };

  server.registerTool(
    "ingest_official_hopper",
    {
      title: "Ingest Official Hopper",
      description: "Refresh the local snapshot store from Hopper's installed official MCP server.",
      inputSchema: ingestSchema,
      annotations: WRITE_LOCAL,
    },
    async (args, extra) => {
      await notifyProgress(extra, 0, 2, "Reading live Hopper document through the official MCP backend.");
      const snapshot = await buildOfficialSnapshot(officialBackend, {
        maxProcedures: args.max_procedures,
        includeProcedureInfo: args.include_procedure_info !== false,
        includeAssembly: Boolean(args.include_assembly),
        includePseudocode: Boolean(args.include_pseudocode),
        includeCallGraph: Boolean(args.include_call_graph),
        failOnTruncation: Boolean(args.fail_on_truncation),
      });
      await notifyProgress(extra, 1, 2, "Updating local snapshot store.");
      const session = await store.upsertSession(snapshot);
      notifyResourceListChanged();
      await notifyProgress(extra, 2, 2, "Official Hopper snapshot refreshed.");
      return toolResult({ session: store.describeSession(session), source: "official-hopper-mcp" });
    },
  );

  server.registerTool(
    "open_session",
    {
      title: "Open Session",
      description: "Create or replace a session from an already-indexed JSON payload.",
      inputSchema: {
        session: z.record(z.string(), z.any()).describe(
          "Normalized session document with functions, strings, imports, exports, and metadata.",
        ),
      },
      annotations: WRITE_LOCAL,
    },
    async (args, extra) => {
      await notifyProgress(extra, 0, 1, "Opening indexed session.");
      const session = store.describeSession(await store.upsertSession(args.session));
      notifyResourceListChanged();
      await notifyProgress(extra, 1, 1, "Indexed session opened.");
      return toolResult(session);
    },
  );

  server.registerTool(
    "ingest_sample",
    {
      title: "Ingest Sample",
      description: "Load a small built-in sample session for smoke tests and client exploration.",
      inputSchema: {},
      annotations: WRITE_LOCAL,
    },
    async (_args, extra) => {
      await notifyProgress(extra, 0, 1, "Loading sample session.");
      const session = store.describeSession(await store.upsertSession(sampleSession()));
      notifyResourceListChanged();
      await notifyProgress(extra, 1, 1, "Sample session loaded.");
      return toolResult(session);
    },
  );

  server.registerTool(
    "ingest_live_hopper",
    {
      title: "Ingest Live Hopper",
      description:
        "Open an executable in Hopper, run the official Python exporter inside Hopper, and ingest the live analyzed document.",
      inputSchema: {
        executable_path: z.string(),
        timeout_ms: optionalNumber,
        max_functions: optionalNumber,
        max_strings: optionalNumber,
        analysis: optionalBool,
        parse_objective_c: optionalBool,
        parse_swift: optionalBool,
        wait_for_analysis: optionalBool,
        full_export: optionalBool,
        fail_on_truncation: optionalBool,
        include_pseudocode: optionalBool,
        max_pseudocode_functions: optionalNumber,
      },
      annotations: WRITE_LIVE,
    },
    async (args, extra) => {
      await notifyProgress(extra, 0, 2, "Opening executable in Hopper.");
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
      await notifyProgress(extra, 1, 2, "Ingesting Hopper export.");
      const session = await store.upsertSession(live.session);
      notifyResourceListChanged();
      await notifyProgress(extra, 2, 2, "Live Hopper session ingested.");
      return toolResult({ session: store.describeSession(session), launch: live.launch });
    },
  );

  server.registerTool(
    "import_macho",
    {
      title: "Import MachO",
      description:
        "Import Mach-O metadata using local macOS tools. With deep=true, also discovers functions from disassembly, builds call graphs, and resolves string cross-references via ADRP+ADD patterns.",
      inputSchema: {
        executable_path: z.string(),
        arch: optionalString,
        max_strings: optionalNumber,
        deep: optionalBool,
        max_functions: optionalNumber,
      },
      annotations: WRITE_LOCAL,
    },
    async (args, extra) => {
      const isDeep = Boolean(args.deep);
      await notifyProgress(
        extra,
        0,
        isDeep ? 3 : 1,
        isDeep ? "Deep Mach-O import: extracting metadata." : "Importing Mach-O metadata.",
      );
      const imported = await importMachO(args.executable_path, {
        arch: args.arch ?? "auto",
        maxStrings: args.max_strings ?? 15000,
        deep: isDeep,
        maxFunctions: args.max_functions ?? 30000,
      });
      if (isDeep) await notifyProgress(extra, 2, 3, "Indexing discovered functions.");
      const session = await store.upsertSession(imported);
      notifyResourceListChanged();
      await notifyProgress(extra, isDeep ? 3 : 1, isDeep ? 3 : 1, "Mach-O import complete.");
      return toolResult({
        session: store.describeSession(session),
        source: isDeep ? "local-macho-deep" : "local-macho-importer",
      });
    },
  );

  // ── live binary disassembly ────────────────────────────────────────────
  server.registerTool(
    "disassemble_range",
    {
      title: "Disassemble Range",
      description:
        "Disassemble a specific address range from a Mach-O binary using otool. Returns ARM64 assembly with symbolic names.",
      inputSchema: {
        executable_path: optionalString,
        start_addr: z.string(),
        end_addr: z.string(),
        arch: optionalString,
        max_lines: optionalNumber,
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
      if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
      const result = await disassembleRange(binaryPath, {
        arch: args.arch ?? "auto",
        startAddr: args.start_addr,
        endAddr: args.end_addr,
        maxLines: args.max_lines ?? 500,
      });
      return toolResult(result);
    },
  );

  server.registerTool(
    "find_xrefs",
    {
      title: "Find Xrefs",
      description:
        "Live disassembly: find code locations that reference a target address by scanning the binary with otool. For snapshot-based xrefs, use the `xrefs` tool.",
      inputSchema: {
        executable_path: optionalString,
        target_addr: z.string(),
        arch: optionalString,
        max_results: optionalNumber,
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args, extra) => {
      const sessionId = sessionFor(args);
      const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
      if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
      await notifyProgress(extra, 0, 1, "Scanning binary for cross-references (streaming otool).");
      const result = await findXrefs(binaryPath, {
        arch: args.arch ?? "auto",
        targetAddr: args.target_addr,
        maxResults: args.max_results ?? 50,
      });
      await notifyProgress(extra, 1, 1, `Found ${result.length} xrefs.`);
      return toolResult(result);
    },
  );

  server.registerTool(
    "find_functions",
    {
      title: "Find Functions",
      description:
        "Discover functions in a region by scanning for ARM64 stp x29,x30 prologues. Optionally merges into current session.",
      inputSchema: {
        executable_path: optionalString,
        start_addr: optionalString,
        end_addr: optionalString,
        arch: optionalString,
        max_functions: optionalNumber,
        merge_session: optionalBool,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args, extra) => {
      const sessionId = sessionFor(args);
      const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
      if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
      await notifyProgress(extra, 0, 1, "Scanning for function prologues.");
      const discovery = await discoverFunctionsFromDisassembly(binaryPath, {
        arch: args.arch ?? "auto",
        maxFunctions: args.max_functions ?? 30000,
        startAddr: args.start_addr ? parseInt(args.start_addr, 16) : null,
        endAddr: args.end_addr ? parseInt(args.end_addr, 16) : null,
      });
      await notifyProgress(
        extra,
        1,
        1,
        `Discovered ${discovery.functions.length} functions, ${discovery.callEdges.length} call edges.`,
      );
      const result = {
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
      return toolResult(result);
    },
  );

  // ── snapshot resolve / analyze ──────────────────────────────────────────
  server.registerTool(
    "resolve",
    {
      title: "Resolve",
      description:
        "Resolve an address, name, string, import, or semantic query against the knowledge store. Use this instead of dropped helpers like address_name / procedure_address.",
      inputSchema: {
        query: z.string(),
        session_id: optionalString,
        max_results: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      let result = store.resolve(args.query, sessionId);
      if (!result.length) {
        result = await resolveFromBinaryStrings(store, args.query, { sessionId, maxResults: args.max_results });
      }
      return toolResult(result);
    },
  );

  server.registerTool(
    "analyze_function_deep",
    {
      title: "Analyze Function Deep",
      description: "Return purpose, pseudocode, graph context, evidence anchors, and provenance for a function.",
      inputSchema: {
        addr: z.string(),
        detail_level: z.enum(["standard", "full"]).optional(),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) =>
      toolResult(store.analyzeFunctionDeep(args.addr, { detailLevel: args.detail_level, sessionId: sessionFor(args) })),
  );

  server.registerTool(
    "get_graph_slice",
    {
      title: "Get Graph Slice",
      description: "Return caller/callee graph neighborhood for a function.",
      inputSchema: {
        seed: z.string(),
        radius: optionalNumber,
        kind: z.enum(["calls", "callers", "callees"]).optional(),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) =>
      toolResult(
        store.getGraphSlice(args.seed, {
          radius: args.radius ?? 1,
          kind: args.kind ?? "calls",
          sessionId: sessionFor(args),
        }),
      ),
  );

  server.registerTool(
    "query",
    {
      title: "Query",
      description:
        "Run a structured query against the active session. Predicates: name, calls, callers, callees, imports, string, tag, capability, anti, addr, pseudocode, size. Connectors: AND, OR, NOT, parens.",
      inputSchema: { expression: z.string(), session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      const matches = queryFunctions(session, args.expression, {
        maxResults: args.max_results ?? 50,
        capabilities: session.binary?.capabilities ?? null,
        antiAnalysis: session.antiAnalysisFindings ?? [],
      });
      return toolResult({ count: matches.length, matches });
    },
  );

  server.registerTool(
    "xrefs",
    {
      title: "Xrefs (Snapshot)",
      description:
        "Snapshot xrefs: cross-references to/from an address in the active session's indexed metadata. For a live binary scan use `find_xrefs`.",
      inputSchema: { address: optionalString, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      return toolResult(snapshotXrefs(store, defaultAddressQuery(store, args.address, sessionId), sessionId));
    },
  );

  server.registerTool(
    "list_procedures",
    {
      title: "List Procedures",
      description: "List procedure addresses and names from the active snapshot, named-first then by address.",
      inputSchema: { session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) =>
      toolResult(
        objectFromFunctions(
          listProcedures(store, sessionFor(args), { maxResults: args.max_results }),
          (fn) => fn.name ?? fn.addr,
        ),
      ),
  );

  // ── unified procedure / search ─────────────────────────────────────────
  server.registerTool(
    "procedure",
    {
      title: "Procedure",
      description:
        "Read a single field from a procedure: info | assembly | pseudo_code | callers | callees. `procedure` accepts an address or name; defaults to the cursor procedure when omitted.",
      inputSchema: {
        field: z.enum(["info", "assembly", "pseudo_code", "callers", "callees"]),
        procedure: optionalString,
        session_id: optionalString,
        max_lines: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      const fn = resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId);
      switch (args.field) {
        case "info":
          return toolResult(officialProcedureInfo(fn));
        case "assembly": {
          const lines = assemblyLines(fn);
          return toolResult(args.max_lines ? lines.slice(0, args.max_lines).join("\n") : lines.join("\n"));
        }
        case "pseudo_code":
          return toolResult(
            fn.pseudocode ??
              "Pseudocode was not captured. Re-run ingest_live_hopper with include_pseudocode=true for selected functions.",
          );
        case "callers":
        case "callees": {
          const session = store.getSession(sessionId);
          const list = (args.field === "callers" ? fn.callers : fn.callees) ?? [];
          return toolResult(list.map((addr) => store.getFunctionIfKnown(session, addr).name ?? addr));
        }
      }
    },
  );

  server.registerTool(
    "search",
    {
      title: "Search",
      description:
        "Search the active snapshot by kind: strings | procedures | names. `pattern` is treated as a regex unless case_sensitive forces exact handling.",
      inputSchema: {
        kind: z.enum(["strings", "procedures", "names"]),
        pattern: z.string(),
        case_sensitive: optionalBool,
        semantic: optionalBool,
        session_id: optionalString,
        max_results: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      const flags = args.case_sensitive ? "" : "i";
      if (args.kind === "strings") {
        if (args.semantic) {
          let result = store.searchStrings(args.pattern, {
            semantic: true,
            sessionId,
            maxResults: args.max_results,
          });
          if (!result.length) {
            result = await searchSessionBinaryStrings(store, args.pattern, {
              semantic: true,
              sessionId,
              maxResults: args.max_results,
            });
          }
          return toolResult(result);
        }
        return toolResult(
          objectFromAddressItems(
            searchStringsOfficial(store, args.pattern, {
              caseSensitive: Boolean(args.case_sensitive),
              sessionId,
              maxResults: args.max_results,
            }),
            "value",
          ),
        );
      }
      if (args.kind === "procedures") {
        const regex = new RegExp(args.pattern, flags);
        return toolResult(
          objectFromFunctions(
            limitResults(
              listProcedures(store, sessionId).filter((fn) =>
                regex.test([fn.addr, fn.name, fn.signature, fn.summary].filter(Boolean).join(" ")),
              ),
              args.max_results,
            ),
            (fn) => fn.name ?? fn.addr,
          ),
        );
      }
      // names
      const session = store.getSession(sessionId);
      const regex = new RegExp(args.pattern, flags);
      return toolResult(
        objectFromAddressItems(
          limitResults(
            (session.names ?? []).filter((item) =>
              regex.test([item.addr, item.name, item.demangled].filter(Boolean).join(" ")),
            ),
            args.max_results,
          ),
          "name",
        ),
      );
    },
  );

  // ── transactions ─────────────────────────────────────────────────────────
  server.registerTool(
    "begin_transaction",
    {
      title: "Begin Transaction",
      description: "Start a reviewed annotation transaction.",
      inputSchema: { name: optionalString, rationale: optionalString, session_id: optionalString },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.begin({ sessionId: sessionFor(args), name: args.name, rationale: args.rationale }),
      ),
  );

  server.registerTool(
    "queue",
    {
      title: "Queue Annotation",
      description:
        "Queue an annotation in the active transaction. `kind` selects the operation: rename | comment | inline_comment | type_patch | tag | untag | rename_batch. Required fields by kind: rename/comment/inline_comment/type_patch need `addr` + `value`; tag/untag need `addr` + `tag` (or `tags`); rename_batch needs `mapping`.",
      inputSchema: {
        kind: z.enum(["rename", "comment", "inline_comment", "type_patch", "tag", "untag", "rename_batch"]),
        transaction_id: optionalString,
        addr: optionalString,
        value: optionalString,
        tag: optionalString,
        tags: z.array(z.string()).optional(),
        mapping: z.record(z.string(), z.string()).optional(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const op = buildQueueOperation(args);
      return toolResult(
        await transactions.queue(op, { sessionId: sessionFor(args) }),
      );
    },
  );

  server.registerTool(
    "preview_transaction",
    {
      title: "Preview Transaction",
      description: "Preview queued writes with old/new values before commit.",
      inputSchema: { transaction_id: optionalString, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) =>
      toolResult(transactions.preview({ transactionId: args.transaction_id, sessionId: sessionFor(args) })),
  );

  server.registerTool(
    "commit_transaction",
    {
      title: "Commit Transaction",
      description: "Commit queued writes to the knowledge store and, when connected, Hopper.",
      inputSchema: {
        transaction_id: optionalString,
        session_id: optionalString,
        backend: z.enum(["local", "official"]).optional(),
        confirm_live_write: optionalBool,
      },
      annotations: WRITE_LIVE,
    },
    async (args) => {
      const commitAdapter =
        args.backend === "official"
          ? {
              applyTransaction: (session, transaction) =>
                officialBackend.applyTransaction(session, transaction, {
                  confirmLiveWrite: Boolean(args.confirm_live_write),
                }),
            }
          : adapter;
      const result = await transactions.commit({
        transactionId: args.transaction_id,
        sessionId: sessionFor(args),
        adapter: commitAdapter,
      });
      notifyResourceListChanged();
      return toolResult(result);
    },
  );

  server.registerTool(
    "rollback_transaction",
    {
      title: "Rollback Transaction",
      description: "Roll back an open transaction without applying writes.",
      inputSchema: { transaction_id: optionalString, session_id: optionalString },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.rollback({ transactionId: args.transaction_id, sessionId: sessionFor(args) }),
      ),
  );

  // ── hypothesis ────────────────────────────────────────────────────────
  server.registerTool(
    "hypothesis",
    {
      title: "Hypothesis",
      description:
        "Manage research hypotheses. `action=create` creates a hypothesis (requires `topic`); `action=link` attaches evidence (requires `hypothesis_id`); `action=status` updates status (requires `hypothesis_id` + `status`).",
      inputSchema: {
        action: z.enum(["create", "link", "status"]),
        transaction_id: optionalString,
        hypothesis_id: optionalString,
        topic: optionalString,
        claim: optionalString,
        status: z.enum(["open", "supported", "refuted", "abandoned"]).optional(),
        addr: optionalString,
        evidence: optionalString,
        evidence_kind: z.enum(["address", "string", "import", "note", "selector"]).optional(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const op = buildHypothesisOperation(args);
      return toolResult(
        await transactions.queue(op, { sessionId: sessionFor(args) }),
      );
    },
  );

  // ── research / classification ─────────────────────────────────────────────
  server.registerTool(
    "classify_capabilities",
    {
      title: "Classify Capabilities",
      description:
        "Bucket the active session imports into capability groups (network/crypto/file/ipc/proc/anti-analysis/...).",
      inputSchema: {
        session_id: optionalString,
        persist: z.boolean().describe("Persist the result onto session.binary.capabilities (default true).").optional(),
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      const capabilities = classifyImports(session.imports ?? []);
      if (args.persist !== false) {
        session.binary ??= {};
        session.binary.capabilities = capabilities;
        await store.save();
        notifyResourceListChanged();
      }
      return toolResult(capabilities);
    },
  );

  server.registerTool(
    "detect_anti_analysis",
    {
      title: "Detect Anti Analysis",
      description: "Surface anti-debug, anti-VM, and other anti-analysis patterns in the active session.",
      inputSchema: {
        session_id: optionalString,
        persist: z.boolean().describe("Persist findings onto session.antiAnalysisFindings (default true).").optional(),
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      const findings = detectAntiAnalysis(session);
      if (args.persist !== false) {
        session.antiAnalysisFindings = findings;
        await store.save();
        notifyResourceListChanged();
      }
      return toolResult(findings);
    },
  );

  server.registerTool(
    "compute_section_entropy",
    {
      title: "Compute Section Entropy",
      description: "Compute Shannon entropy per Mach-O section. Flags entropy>=7.5 as suspicious (likely packed).",
      inputSchema: {
        executable_path: optionalString,
        arch: optionalString,
        session_id: optionalString,
        persist: optionalBool,
        max_bytes_per_section: optionalNumber,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = sessionOrNull(store, sessionFor(args));
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
      return toolResult(entropy);
    },
  );

  server.registerTool(
    "extract_code_signing",
    {
      title: "Extract Code Signing",
      description: "Extract code-signing metadata and entitlements via codesign.",
      inputSchema: {
        executable_path: optionalString,
        session_id: optionalString,
        persist: optionalBool,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = sessionOrNull(store, sessionFor(args));
      const binaryPath = args.executable_path ?? session?.binary?.path;
      if (!binaryPath) throw rpcError(-32602, "extract_code_signing needs executable_path or a session binary path.");
      const signing = await extractCodeSigning(binaryPath);
      if (args.persist !== false && session) {
        session.binary ??= {};
        session.binary.signing = signing;
        await store.save();
        notifyResourceListChanged();
      }
      return toolResult(signing);
    },
  );

  server.registerTool(
    "extract_objc_runtime",
    {
      title: "Extract ObjC Runtime",
      description: "Recover Objective-C class hierarchy, methods, and IMP addresses from a Mach-O via otool -ov.",
      inputSchema: {
        executable_path: optionalString,
        arch: optionalString,
        session_id: optionalString,
        max_classes: optionalNumber,
        persist: optionalBool,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = sessionOrNull(store, sessionFor(args));
      const binaryPath = args.executable_path ?? session?.binary?.path;
      if (!binaryPath) throw rpcError(-32602, "extract_objc_runtime needs executable_path or a session binary path.");
      const classes = await extractObjCRuntime(binaryPath, args.arch ?? session?.binary?.arch ?? "auto", {
        maxClasses: args.max_classes ?? 1000,
      });
      if (args.persist !== false && session) {
        session.objcClasses = classes;
        await store.save();
        notifyResourceListChanged();
      }
      return toolResult({ count: classes.length, classes });
    },
  );

  server.registerTool(
    "compute_fingerprints",
    {
      title: "Compute Fingerprints",
      description: "Recompute imphash/simhash/minhash fingerprints for the active session's functions.",
      inputSchema: { session_id: optionalString },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      let updated = 0;
      for (const fn of Object.values(session.functions ?? {})) {
        fn.fingerprint = buildFunctionFingerprint(fn, session.imports ?? []);
        updated += 1;
      }
      await store.save();
      notifyResourceListChanged();
      return toolResult({ updated });
    },
  );

  server.registerTool(
    "find_similar_functions",
    {
      title: "Find Similar Functions",
      description: "Find functions across loaded sessions that resemble a target by fingerprint.",
      inputSchema: {
        addr: z.string().describe("Function address (defaults to current procedure).").optional(),
        session_id: optionalString,
        target_session_id: z.string().describe("Restrict results to this session (default: all sessions).").optional(),
        min_similarity: z.number().describe("Lower bound on overall similarity (0-1, default 0.4).").optional(),
        max_results: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) =>
      toolResult(
        findSimilarFunctions(store, {
          sessionId: sessionFor(args),
          addr: args.addr,
          targetSessionId: args.target_session_id,
          minSimilarity: args.min_similarity ?? 0.4,
          maxResults: args.max_results ?? 25,
        }),
      ),
  );

  server.registerTool(
    "diff_sessions",
    {
      title: "Diff Sessions",
      description: "Diff two sessions: added/removed/renamed/changed functions, strings, imports.",
      inputSchema: { left_session_id: z.string(), right_session_id: z.string() },
      annotations: READ_ONLY,
    },
    async (args) => {
      const left = store.getSession(args.left_session_id);
      const right = store.getSession(args.right_session_id);
      return toolResult(diffSessions(left, right));
    },
  );
}

// ── private helpers ────────────────────────────────────────────────────────

function buildQueueOperation(args) {
  const base = {
    transactionId: args.transaction_id,
    rationale: args.rationale ?? null,
  };
  switch (args.kind) {
    case "rename":
    case "comment":
    case "inline_comment":
    case "type_patch": {
      if (!args.addr) throw rpcError(-32602, `queue kind=${args.kind} requires addr.`);
      if (args.value === undefined || args.value === null) {
        throw rpcError(-32602, `queue kind=${args.kind} requires value.`);
      }
      return { ...base, kind: args.kind, addr: args.addr, newValue: args.value };
    }
    case "tag":
    case "untag": {
      if (!args.addr) throw rpcError(-32602, `queue kind=${args.kind} requires addr.`);
      const tags = args.tags ?? (args.tag ? [args.tag] : []);
      if (!tags.length) throw rpcError(-32602, `queue kind=${args.kind} requires tag or tags.`);
      return { ...base, kind: args.kind, addr: args.addr, tags };
    }
    case "rename_batch": {
      if (!args.mapping || typeof args.mapping !== "object") {
        throw rpcError(-32602, "queue kind=rename_batch requires mapping {addr: newName}.");
      }
      return { ...base, kind: "rename_batch", mapping: args.mapping };
    }
  }
  throw rpcError(-32602, `Unknown queue kind: ${args.kind}`);
}

function buildHypothesisOperation(args) {
  const base = {
    transactionId: args.transaction_id,
    rationale: args.rationale ?? null,
  };
  switch (args.action) {
    case "create": {
      if (!args.topic) throw rpcError(-32602, "hypothesis action=create requires topic.");
      return {
        ...base,
        kind: "hypothesis_create",
        topic: args.topic,
        claim: args.claim ?? null,
        status: args.status ?? "open",
      };
    }
    case "link": {
      if (!args.hypothesis_id) throw rpcError(-32602, "hypothesis action=link requires hypothesis_id.");
      return {
        ...base,
        kind: "hypothesis_link",
        hypothesisId: args.hypothesis_id,
        addr: args.addr,
        evidence: args.evidence,
        evidenceKind: args.evidence_kind ?? (args.addr ? "address" : "note"),
      };
    }
    case "status": {
      if (!args.hypothesis_id) throw rpcError(-32602, "hypothesis action=status requires hypothesis_id.");
      if (!args.status) throw rpcError(-32602, "hypothesis action=status requires status.");
      return {
        ...base,
        kind: "hypothesis_status",
        hypothesisId: args.hypothesis_id,
        status: args.status,
      };
    }
  }
  throw rpcError(-32602, `Unknown hypothesis action: ${args.action}`);
}

function findSimilarFunctions(store, { sessionId, addr, targetSessionId, minSimilarity, maxResults }) {
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
      if (!candidate.fingerprint)
        candidate.fingerprint = buildFunctionFingerprint(candidate, candidateSession.imports ?? []);
      const score = functionSimilarity(target.fingerprint, candidate.fingerprint);
      if (score.similarity >= minSimilarity) {
        results.push({
          sessionId: candidateSession.sessionId,
          binary: candidateSession.binary?.name ?? null,
          addr: candidate.addr,
          name: candidate.name ?? null,
          summary: candidate.summary ?? null,
          similarity: Number(score.similarity.toFixed(4)),
          components: Object.fromEntries(
            Object.entries(score.components).map(([k, v]) => [k, Number(v.toFixed(4))]),
          ),
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

async function resolveFromBinaryStrings(store, query, { sessionId, maxResults }) {
  const strings = await searchSessionBinaryStrings(store, query, { semantic: false, sessionId, maxResults });
  return strings.map((item) => ({ kind: "string", score: 0.45, item }));
}

async function searchSessionBinaryStrings(store, pattern, { semantic, sessionId, maxResults }) {
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
