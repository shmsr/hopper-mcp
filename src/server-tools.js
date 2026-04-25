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
  officialSegment,
  officialProcedureInfo,
  assemblyLines,
  snapshotXrefs,
  lookupName,
  limitResults,
  objectFromFunctions,
  objectFromAddressItems,
  searchStringsOfficial,
  getSessionSegments,
} from "./server-helpers.js";
import { toolResult, boundedNumber, DEFAULT_MAX_TOOL_TEXT_CHARS } from "./server-format.js";
import { sampleSession } from "./sample-session.js";

const OFFICIAL_MIRROR_TOOLS = new Set([
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

const READ_ONLY = { readOnlyHint: true, openWorldHint: false };
const READ_OPEN_WORLD = { readOnlyHint: true, openWorldHint: true };
const WRITE_LOCAL = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const WRITE_LIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true };

const backendEnum = z.enum(["snapshot", "official"]).optional();
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

  const callOfficialMirror = async (name, args) => {
    const officialArgs = toOfficialArgs(name, args);
    const result = await officialBackend.callTool(name, officialArgs);
    return officialToolPayload(result);
  };

  const sessionFor = (args) => args.session_id ?? "current";

  // ── meta + lifecycle ────────────────────────────────────────────────────
  server.registerTool(
    "capabilities",
    {
      title: "Capabilities",
      description: "Report static/dynamic adapter capabilities.",
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
        "Call Hopper's installed official MCP server. Write/navigation tools require HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 and confirm_live_write=true.",
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
  const ingestOfficial = async (args, extra) => {
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
  };

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
    ingestOfficial,
  );

  server.registerTool(
    "refresh_snapshot",
    {
      title: "Refresh Snapshot",
      description:
        "Alias for ingest_official_hopper: refresh the local snapshot from the live official Hopper backend.",
      inputSchema: ingestSchema,
      annotations: WRITE_LOCAL,
    },
    ingestOfficial,
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
        "Find all code locations that reference a given address. Detects ADRP+ADD, ADRP+LDR, and bl/b patterns in ARM64.",
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

  // ── resolve / analyze ────────────────────────────────────────────────────
  server.registerTool(
    "resolve",
    {
      title: "Resolve",
      description: "Resolve an address, name, string, import, or semantic query against the knowledge store.",
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

  // ── snapshot read mirrors ────────────────────────────────────────────────
  server.registerTool(
    "search_strings",
    {
      title: "Search Strings",
      description:
        "Search indexed strings. Use pattern/case_sensitive for official-compatible output, or regex/semantic for the extended result shape.",
      inputSchema: {
        pattern: optionalString,
        case_sensitive: optionalBool,
        regex: optionalString,
        semantic: optionalBool,
        backend: backendEnum,
        session_id: optionalString,
        max_results: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("search_strings", args)) {
        return toolResult(await callOfficialMirror("search_strings", args));
      }
      const sessionId = sessionFor(args);
      const pattern = args.pattern ?? args.regex;
      if (!pattern) throw rpcError(-32602, "search_strings requires pattern or regex.");
      let result;
      if (args.pattern !== undefined) {
        result = objectFromAddressItems(
          searchStringsOfficial(store, pattern, {
            caseSensitive: Boolean(args.case_sensitive),
            sessionId,
            maxResults: args.max_results,
          }),
          "value",
        );
      } else {
        result = store.searchStrings(pattern, {
          semantic: Boolean(args.semantic),
          sessionId,
          maxResults: args.max_results,
        });
        if (!result.length) {
          result = await searchSessionBinaryStrings(store, pattern, {
            semantic: Boolean(args.semantic),
            sessionId,
            maxResults: args.max_results,
          });
        }
      }
      return toolResult(result);
    },
  );

  server.registerTool(
    "list_documents",
    {
      title: "List Documents",
      description: "List loaded snapshot sessions.",
      inputSchema: { backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_documents", args)) return toolResult(await callOfficialMirror("list_documents", args));
      return toolResult(store.listSessions().map((session) => session.name));
    },
  );

  server.registerTool(
    "current_document",
    {
      title: "Current Document",
      description: "Return the active snapshot session.",
      inputSchema: { backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("current_document", args)) {
        return toolResult(await callOfficialMirror("current_document", args));
      }
      return toolResult(store.getSession(sessionFor(args)).binary?.name ?? "unknown");
    },
  );

  server.registerTool(
    "list_segments",
    {
      title: "List Segments",
      description: "List segments from the active snapshot.",
      inputSchema: { backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_segments", args)) return toolResult(await callOfficialMirror("list_segments", args));
      return toolResult(getSessionSegments(store, sessionFor(args)).map(officialSegment));
    },
  );

  server.registerTool(
    "list_procedures",
    {
      title: "List Procedures",
      description: "List procedure addresses and names from the active snapshot.",
      inputSchema: { backend: backendEnum, session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_procedures", args)) {
        return toolResult(await callOfficialMirror("list_procedures", args));
      }
      return toolResult(
        objectFromFunctions(
          listProcedures(store, sessionFor(args), { maxResults: args.max_results }),
          (fn) => fn.name ?? fn.addr,
        ),
      );
    },
  );

  server.registerTool(
    "list_procedure_size",
    {
      title: "List Procedure Size",
      description: "List procedure sizes and basic-block counts from the active snapshot.",
      inputSchema: { backend: backendEnum, session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_procedure_size", args)) {
        return toolResult(await callOfficialMirror("list_procedure_size", args));
      }
      return toolResult(
        objectFromFunctions(listProcedures(store, sessionFor(args), { maxResults: args.max_results }), (fn) => ({
          name: fn.name ?? null,
          basicblock_count: fn.basicBlockCount ?? fn.basicBlocks?.length ?? 0,
          size: fn.size ?? null,
        })),
      );
    },
  );

  server.registerTool(
    "list_procedure_info",
    {
      title: "List Procedure Info",
      description: "List compact procedure metadata from the active snapshot.",
      inputSchema: { backend: backendEnum, session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_procedure_info", args)) {
        return toolResult(await callOfficialMirror("list_procedure_info", args));
      }
      return toolResult(
        objectFromFunctions(
          listProcedures(store, sessionFor(args), { maxResults: args.max_results }),
          officialProcedureInfo,
        ),
      );
    },
  );

  server.registerTool(
    "list_strings",
    {
      title: "List Strings",
      description: "List indexed strings from the active snapshot.",
      inputSchema: { backend: backendEnum, session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_strings", args)) return toolResult(await callOfficialMirror("list_strings", args));
      const session = store.getSession(sessionFor(args));
      return toolResult(objectFromAddressItems(limitResults(session.strings ?? [], args.max_results), "value"));
    },
  );

  server.registerTool(
    "search_procedures",
    {
      title: "Search Procedures",
      description: "Search procedure names and metadata in the active snapshot.",
      inputSchema: {
        pattern: optionalString,
        case_sensitive: optionalBool,
        regex: optionalString,
        backend: backendEnum,
        session_id: optionalString,
        max_results: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("search_procedures", args)) {
        return toolResult(await callOfficialMirror("search_procedures", args));
      }
      const pattern = args.pattern ?? args.regex;
      if (!pattern) throw rpcError(-32602, "search_procedures requires pattern or regex.");
      const regex = new RegExp(pattern, args.case_sensitive ? "" : "i");
      return toolResult(
        objectFromFunctions(
          limitResults(
            listProcedures(store, sessionFor(args)).filter((fn) =>
              regex.test([fn.addr, fn.name, fn.signature, fn.summary].filter(Boolean).join(" ")),
            ),
            args.max_results,
          ),
          (fn) => fn.name ?? fn.addr,
        ),
      );
    },
  );

  server.registerTool(
    "procedure_info",
    {
      title: "Procedure Info",
      description: "Return full procedure metadata for an address or name.",
      inputSchema: { procedure: optionalString, backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("procedure_info", args)) {
        return toolResult(await callOfficialMirror("procedure_info", args));
      }
      const sessionId = sessionFor(args);
      return toolResult(
        officialProcedureInfo(resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId)),
      );
    },
  );

  server.registerTool(
    "procedure_address",
    {
      title: "Procedure Address",
      description: "Resolve a procedure name or contained address to its entry address.",
      inputSchema: { procedure: z.string(), backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("procedure_address", args)) {
        return toolResult(await callOfficialMirror("procedure_address", args));
      }
      const sessionId = sessionFor(args);
      return toolResult(
        resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId).addr,
      );
    },
  );

  server.registerTool(
    "procedure_assembly",
    {
      title: "Procedure Assembly",
      description: "Return assembly captured from Hopper's public Python API.",
      inputSchema: {
        procedure: optionalString,
        backend: backendEnum,
        session_id: optionalString,
        max_lines: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("procedure_assembly", args)) {
        return toolResult(await callOfficialMirror("procedure_assembly", args));
      }
      const sessionId = sessionFor(args);
      const fn = resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId);
      const lines = assemblyLines(fn);
      const result = args.max_lines ? lines.slice(0, args.max_lines).join("\n") : lines.join("\n");
      return toolResult(result);
    },
  );

  server.registerTool(
    "procedure_pseudo_code",
    {
      title: "Procedure Pseudo Code",
      description: "Return pseudocode captured during live export, if include_pseudocode was enabled.",
      inputSchema: { procedure: optionalString, backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("procedure_pseudo_code", args)) {
        return toolResult(await callOfficialMirror("procedure_pseudo_code", args));
      }
      const sessionId = sessionFor(args);
      const fn = resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId);
      return toolResult(
        fn.pseudocode ??
          "Pseudocode was not captured. Re-run ingest_live_hopper with include_pseudocode=true for selected functions.",
      );
    },
  );

  server.registerTool(
    "procedure_callers",
    {
      title: "Procedure Callers",
      description: "Return procedure callers from the active snapshot.",
      inputSchema: { procedure: optionalString, backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("procedure_callers", args)) {
        return toolResult(await callOfficialMirror("procedure_callers", args));
      }
      const sessionId = sessionFor(args);
      const session = store.getSession(sessionId);
      const fn = resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId);
      return toolResult(
        (fn.callers ?? []).map((addr) => store.getFunctionIfKnown(session, addr).name ?? addr),
      );
    },
  );

  server.registerTool(
    "procedure_callees",
    {
      title: "Procedure Callees",
      description: "Return procedure callees from the active snapshot.",
      inputSchema: { procedure: optionalString, backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("procedure_callees", args)) {
        return toolResult(await callOfficialMirror("procedure_callees", args));
      }
      const sessionId = sessionFor(args);
      const session = store.getSession(sessionId);
      const fn = resolveProcedure(store, defaultProcedureQuery(store, args.procedure, sessionId), sessionId);
      return toolResult(
        (fn.callees ?? []).map((addr) => store.getFunctionIfKnown(session, addr).name ?? addr),
      );
    },
  );

  server.registerTool(
    "xrefs",
    {
      title: "Xrefs",
      description: "Return cross-references to and from an address from the active snapshot.",
      inputSchema: { address: optionalString, backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("xrefs", args)) return toolResult(await callOfficialMirror("xrefs", args));
      const sessionId = sessionFor(args);
      return toolResult(snapshotXrefs(store, defaultAddressQuery(store, args.address, sessionId), sessionId));
    },
  );

  server.registerTool(
    "current_address",
    {
      title: "Current Address",
      description: "Return the cursor address captured at export time.",
      inputSchema: { backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("current_address", args)) {
        return toolResult(await callOfficialMirror("current_address", args));
      }
      return toolResult(store.getSession(sessionFor(args)).cursor?.address ?? null);
    },
  );

  server.registerTool(
    "current_procedure",
    {
      title: "Current Procedure",
      description: "Return the cursor procedure captured at export time.",
      inputSchema: { backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("current_procedure", args)) {
        return toolResult(await callOfficialMirror("current_procedure", args));
      }
      const session = store.getSession(sessionFor(args));
      const addr = session.cursor?.procedure;
      return toolResult(addr ? store.getFunctionIfKnown(session, addr).name ?? addr : null);
    },
  );

  server.registerTool(
    "list_names",
    {
      title: "List Names",
      description: "List named addresses captured from Hopper.",
      inputSchema: { backend: backendEnum, session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_names", args)) return toolResult(await callOfficialMirror("list_names", args));
      const session = store.getSession(sessionFor(args));
      return toolResult(objectFromAddressItems(limitResults(session.names ?? [], args.max_results), "name"));
    },
  );

  server.registerTool(
    "search_name",
    {
      title: "Search Name",
      description: "Search Hopper names captured in the snapshot.",
      inputSchema: {
        pattern: optionalString,
        case_sensitive: optionalBool,
        regex: optionalString,
        backend: backendEnum,
        session_id: optionalString,
        max_results: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("search_name", args)) return toolResult(await callOfficialMirror("search_name", args));
      const session = store.getSession(sessionFor(args));
      const pattern = args.pattern ?? args.regex;
      if (!pattern) throw rpcError(-32602, "search_name requires pattern or regex.");
      const regex = new RegExp(pattern, args.case_sensitive ? "" : "i");
      return toolResult(
        objectFromAddressItems(
          limitResults(
            (session.names ?? []).filter((item) => regex.test([item.addr, item.name, item.demangled].filter(Boolean).join(" "))),
            args.max_results,
          ),
          "name",
        ),
      );
    },
  );

  server.registerTool(
    "address_name",
    {
      title: "Address Name",
      description: "Return the name for an address, if captured.",
      inputSchema: { address: optionalString, backend: backendEnum, session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("address_name", args)) return toolResult(await callOfficialMirror("address_name", args));
      const sessionId = sessionFor(args);
      return toolResult(
        lookupName(store, defaultAddressQuery(store, args.address, sessionId), sessionId).name ??
          "There is no name at this address",
      );
    },
  );

  server.registerTool(
    "list_bookmarks",
    {
      title: "List Bookmarks",
      description: "List Hopper bookmarks captured in the snapshot.",
      inputSchema: { backend: backendEnum, session_id: optionalString, max_results: optionalNumber },
      annotations: READ_ONLY,
    },
    async (args) => {
      if (shouldUseOfficial("list_bookmarks", args)) {
        return toolResult(await callOfficialMirror("list_bookmarks", args));
      }
      const session = store.getSession(sessionFor(args));
      return toolResult(limitResults(session.bookmarks ?? [], args.max_results));
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
    "queue_rename",
    {
      title: "Queue Rename",
      description: "Queue a function rename in the active transaction.",
      inputSchema: {
        transaction_id: optionalString,
        addr: z.string(),
        new_name: z.string(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "rename",
            addr: args.addr,
            newValue: args.new_name,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "queue_comment",
    {
      title: "Queue Comment",
      description: "Queue a function-level comment in the active transaction.",
      inputSchema: {
        transaction_id: optionalString,
        addr: z.string(),
        comment: z.string(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "comment",
            addr: args.addr,
            newValue: args.comment,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "queue_inline_comment",
    {
      title: "Queue Inline Comment",
      description: "Queue an inline comment in the active transaction.",
      inputSchema: {
        transaction_id: optionalString,
        addr: z.string(),
        comment: z.string(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "inline_comment",
            addr: args.addr,
            newValue: args.comment,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "queue_type_patch",
    {
      title: "Queue Type Patch",
      description: "Queue a function type/signature patch in the active transaction.",
      inputSchema: {
        transaction_id: optionalString,
        addr: z.string(),
        type: z.string(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "type_patch",
            addr: args.addr,
            newValue: args.type,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
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

  // ── tags / hypotheses ────────────────────────────────────────────────────
  const tagSchema = {
    transaction_id: optionalString,
    addr: z.string(),
    tag: optionalString,
    tags: z.array(z.string()).optional(),
    rationale: optionalString,
    session_id: optionalString,
  };

  server.registerTool(
    "queue_tag",
    {
      title: "Queue Tag",
      description: "Queue a persistent tag (or list of tags) on an address in the current transaction.",
      inputSchema: tagSchema,
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const tags = args.tags ?? (args.tag ? [args.tag] : []);
      return toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "tag",
            addr: args.addr,
            tags,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      );
    },
  );

  server.registerTool(
    "queue_untag",
    {
      title: "Queue Untag",
      description: "Queue removal of one or more tags from an address.",
      inputSchema: tagSchema,
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const tags = args.tags ?? (args.tag ? [args.tag] : []);
      return toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "untag",
            addr: args.addr,
            tags,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      );
    },
  );

  server.registerTool(
    "list_tags",
    {
      title: "List Tags",
      description: "List address tags in the active session.",
      inputSchema: { session_id: optionalString },
      annotations: READ_ONLY,
    },
    async (args) => toolResult(store.getSession(sessionFor(args)).tags ?? {}),
  );

  server.registerTool(
    "queue_rename_batch",
    {
      title: "Queue Rename Batch",
      description: "Queue a bulk rename mapping {addr: newName} in the active transaction.",
      inputSchema: {
        transaction_id: optionalString,
        mapping: z
          .record(z.string(), z.string())
          .describe("Object whose keys are addresses and values are new names."),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "rename_batch",
            mapping: args.mapping,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "create_hypothesis",
    {
      title: "Create Hypothesis",
      description: "Queue creation of a structured hypothesis record (topic, claim, status).",
      inputSchema: {
        transaction_id: optionalString,
        topic: z.string(),
        claim: optionalString,
        status: z.enum(["open", "supported", "refuted", "abandoned"]).optional(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "hypothesis_create",
            topic: args.topic,
            claim: args.claim,
            status: args.status ?? "open",
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "link_evidence",
    {
      title: "Link Evidence",
      description: "Queue an evidence link onto a hypothesis (address, string, import, or note).",
      inputSchema: {
        transaction_id: optionalString,
        hypothesis_id: z.string(),
        addr: optionalString,
        evidence: optionalString,
        evidence_kind: z.enum(["address", "string", "import", "note", "selector"]).optional(),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "hypothesis_link",
            hypothesisId: args.hypothesis_id,
            addr: args.addr,
            evidence: args.evidence,
            evidenceKind: args.evidence_kind ?? (args.addr ? "address" : "note"),
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "set_hypothesis_status",
    {
      title: "Set Hypothesis Status",
      description: "Queue a status change on a hypothesis (open/supported/refuted/abandoned).",
      inputSchema: {
        transaction_id: optionalString,
        hypothesis_id: z.string(),
        status: z.enum(["open", "supported", "refuted", "abandoned"]),
        rationale: optionalString,
        session_id: optionalString,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) =>
      toolResult(
        await transactions.queue(
          {
            transactionId: args.transaction_id,
            kind: "hypothesis_status",
            hypothesisId: args.hypothesis_id,
            status: args.status,
            rationale: args.rationale,
          },
          { sessionId: sessionFor(args) },
        ),
      ),
  );

  server.registerTool(
    "list_hypotheses",
    {
      title: "List Hypotheses",
      description: "List hypotheses recorded for the active session.",
      inputSchema: {
        session_id: optionalString,
        status: z.enum(["open", "supported", "refuted", "abandoned"]).optional(),
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      const list = session.hypotheses ?? [];
      return toolResult(args.status ? list.filter((h) => h.status === args.status) : list);
    },
  );
}

// ── private helpers ────────────────────────────────────────────────────────
function shouldUseOfficial(name, args) {
  return OFFICIAL_MIRROR_TOOLS.has(name) && args.backend === "official";
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
