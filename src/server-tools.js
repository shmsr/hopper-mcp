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
  fetchHopperProcedureIndex,
  fetchHopperXrefs,
  fetchHopperNames,
} from "./hopper-bridge.js";
import { closeHopperDocument } from "./hopper-live.js";
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
  listProcedures,
  defaultProcedureQuery,
  defaultAddressQuery,
  resolveProcedure,
  findContainingFunction,
  officialProcedureInfo,
  assemblyLines,
  snapshotXrefs,
  limitResults,
  objectFromFunctions,
  objectFromAddressItems,
  searchStringsOfficial,
} from "./server-helpers.js";
import { toolResult, boundedNumber, DEFAULT_MAX_TOOL_TEXT_CHARS } from "./server-format.js";
import { parseAddress, formatAddress } from "./knowledge-store.js";

const READ_ONLY = { readOnlyHint: true, openWorldHint: false };
const READ_OPEN_WORLD = { readOnlyHint: true, openWorldHint: true };
const WRITE_LOCAL = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const WRITE_LIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true };

const optionalString = z.string().optional();
const optionalNumber = z.number().optional();
const optionalBool = z.boolean().optional();

export function registerTools(server, ctx) {
  const { store, transactions, adapter, officialBackend, serverInfo } = ctx;

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
        currentSessionId: store.state.currentSessionId ?? null,
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

  // ── ingest + import ────────────────────────────────────────────────────
  const ingestSchema = {
    max_procedures: optionalNumber,
    include_procedure_info: optionalBool,
    include_assembly: optionalBool,
    include_pseudocode: optionalBool,
    include_call_graph: optionalBool,
    fail_on_truncation: optionalBool,
    overwrite: optionalBool,
  };

  // Centralizes the upsertSession options for tools that ingest/replace
  // sessions, so the overwrite + alias-fold semantics are consistent across
  // ingest_official_hopper / ingest_live_hopper / import_macho / open_session.
  // fold_aliases is opt-in: cross-source ingests (live ↔ macho ↔ official)
  // produce intentionally different richness, so we don't auto-discard the
  // older one.
  const upsertOptions = (args) => ({
    overwrite: args?.overwrite ?? true,
    foldAliases: args?.fold_aliases ?? false,
  });

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
      const session = await store.upsertSession(snapshot, upsertOptions(args));
      notifyResourceListChanged();
      await notifyProgress(extra, 2, 2, "Official Hopper snapshot refreshed.");
      return toolResult({ session: store.describeSession(session), source: "official-hopper-mcp" });
    },
  );

  server.registerTool(
    "open_session",
    {
      title: "Open Session",
      description:
        "Create or replace a session from an already-indexed JSON payload. Pass overwrite=false to fail when a session with the same id already exists.",
      inputSchema: {
        session: z.record(z.string(), z.any()).describe(
          "Normalized session document with functions, strings, imports, exports, and metadata.",
        ),
        overwrite: optionalBool,
        fold_aliases: optionalBool,
      },
      annotations: WRITE_LOCAL,
    },
    async (args, extra) => {
      await notifyProgress(extra, 0, 1, "Opening indexed session.");
      const session = store.describeSession(await store.upsertSession(args.session, upsertOptions(args)));
      notifyResourceListChanged();
      await notifyProgress(extra, 1, 1, "Indexed session opened.");
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
        parse_exceptions: optionalBool,
        close_after_export: optionalBool,
        live_backend: z.enum(["python", "official"]).optional(),
        wait_for_analysis: optionalBool,
        full_export: optionalBool,
        fail_on_truncation: optionalBool,
        include_pseudocode: optionalBool,
        max_pseudocode_functions: optionalNumber,
        overwrite: optionalBool,
        fold_aliases: optionalBool,
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
        parseExceptions: args.parse_exceptions,
        closeAfterExport: args.close_after_export,
        liveBackend: args.live_backend,
        waitForAnalysis: args.wait_for_analysis,
        fullExport: args.full_export,
        failOnTruncation: args.fail_on_truncation,
        includePseudocode: args.include_pseudocode,
        maxPseudocodeFunctions: args.max_pseudocode_functions,
      });
      await notifyProgress(extra, 1, 2, "Ingesting Hopper export.");
      const session = await store.upsertSession(live.session, upsertOptions(args));
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
        "Import Mach-O metadata using local macOS tools. With deep=true, also discovers functions from disassembly, builds call graphs, and resolves string cross-references via ADRP+ADD patterns. Pass use_hopper=true to additionally fuse Hopper's procedure index into the deep merge — entrypoints, sizes, basicblocks, signatures, and locals from Hopper override the heuristic-derived ones when Hopper has the same binary loaded.",
      inputSchema: {
        executable_path: z.string(),
        arch: optionalString,
        max_strings: optionalNumber,
        deep: optionalBool,
        max_functions: optionalNumber,
        overwrite: optionalBool,
        fold_aliases: optionalBool,
        use_hopper: optionalBool,
        hopper_procedure_info: optionalBool,
        hopper_max_procedure_info: optionalNumber,
        hopper_include_names: optionalBool,
      },
      annotations: WRITE_LOCAL,
    },
    async (args, extra) => {
      const isDeep = Boolean(args.deep);
      const useHopper = Boolean(args.use_hopper) && isDeep;
      const totalSteps = useHopper ? 4 : isDeep ? 3 : 1;
      await notifyProgress(
        extra,
        0,
        totalSteps,
        isDeep ? "Deep Mach-O import: extracting metadata." : "Importing Mach-O metadata.",
      );

      let hopperIndex = null;
      let hopperFusion = null;
      let hopperLabels = null;
      if (useHopper) {
        await notifyProgress(extra, 1, totalSteps, "Fetching Hopper procedure index.");
        const result = await fetchHopperProcedureIndex(officialBackend, {
          expectedDocument: args.executable_path,
          documentMustMatch: true,
          fetchProcedureInfo: Boolean(args.hopper_procedure_info),
          maxProcedureInfo: Number(args.hopper_max_procedure_info ?? 200),
        });
        hopperFusion = {
          reachable: Boolean(result?.reachable),
          documentName: result?.documentName ?? null,
          documentMismatch: result?.documentMismatch ?? null,
          reason: result?.reason ?? null,
          procedureCount: result?.procedures?.map?.size ?? 0,
          procedureError: result?.procedures?.error ?? null,
        };
        if (result?.procedures?.map && !result.documentMismatch) {
          hopperIndex = result.procedures.map;
          // Also pull Hopper's full named-address dictionary (labels for
          // proc starts, vars, string-pool tags, vtables, etc.). On real
          // binaries this is strictly larger than nm because Hopper labels
          // post-discovery targets too — useful for cross-section analysis.
          // Gated behind hopper_include_names so callers can opt out.
          if (args.hopper_include_names !== false) {
            const namesResult = await fetchHopperNames(officialBackend, {
              expectedDocument: args.executable_path,
              documentMustMatch: true,
            });
            if (namesResult?.names instanceof Map) {
              hopperLabels = namesResult.names;
              hopperFusion.namedAddressCount = hopperLabels.size;
            } else if (namesResult?.reason) {
              hopperFusion.namesReason = namesResult.reason;
            }
          }
        }
      }

      const imported = await importMachO(args.executable_path, {
        arch: args.arch ?? "auto",
        maxStrings: args.max_strings ?? 15000,
        deep: isDeep,
        maxFunctions: args.max_functions ?? 30000,
        hopperIndex,
        hopperLabels,
      });
      if (isDeep) await notifyProgress(extra, totalSteps - 1, totalSteps, "Indexing discovered functions.");
      const session = await store.upsertSession(imported, upsertOptions(args));
      notifyResourceListChanged();
      await notifyProgress(extra, totalSteps, totalSteps, "Mach-O import complete.");
      return toolResult({
        session: store.describeSession(session),
        source: hopperIndex ? "local-macho-deep+hopper" : isDeep ? "local-macho-deep" : "local-macho-importer",
        hopperFusion,
      });
    },
  );

  server.registerTool(
    "set_current_session",
    {
      title: "Set Current Session",
      description:
        "Pin a previously-loaded session as the active one for tools that default to session_id='current'.",
      inputSchema: { session_id: z.string() },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const session = store.setCurrentSession(args.session_id);
      notifyResourceListChanged();
      return toolResult({
        currentSessionId: args.session_id,
        session: store.describeSession(session),
        sessions: store.listSessions(),
      });
    },
  );

  server.registerTool(
    "close_session",
    {
      title: "Close Session",
      description:
        "Drop a session from the local store. Pass session_id='current' to drop the active session. Optionally also closes the document inside Hopper for live ingests via close_in_hopper=true.",
      inputSchema: {
        session_id: z.string(),
        close_in_hopper: optionalBool,
      },
      annotations: WRITE_LOCAL,
    },
    async (args) => {
      const dropped = await store.dropSession(args.session_id);
      const documentName = dropped?.binary?.name ?? null;
      let hopperClose = null;
      if (args.close_in_hopper && documentName) {
        try {
          hopperClose = await closeHopperDocument(documentName);
        } catch (err) {
          hopperClose = { error: String(err?.message ?? err), documentName };
        }
      }
      notifyResourceListChanged();
      return toolResult({
        droppedSessionId: dropped?.sessionId ?? null,
        currentSessionId: store.state.currentSessionId ?? null,
        sessions: store.listSessions(),
        hopperClose,
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
        "Cross-references to a target address. By default scans the binary live with otool. Pass use_hopper=true to delegate to Hopper's analyzed `xrefs` tool when Hopper has the same binary loaded — strictly more authoritative because Hopper resolves indirect-jump tables and runtime-dispatch heuristics that pure disassembly can't see. With use_hopper=true and include_callees=true the response also reports the procedures called BY the target (forward call-graph slice). Falls back to otool when Hopper unreachable or document mismatched. For local snapshot-based xrefs, use the `xrefs` tool.",
      inputSchema: {
        executable_path: optionalString,
        target_addr: z.string(),
        arch: optionalString,
        max_results: optionalNumber,
        session_id: optionalString,
        use_hopper: optionalBool,
        include_callees: optionalBool,
      },
      annotations: READ_ONLY,
    },
    async (args, extra) => {
      const sessionId = sessionFor(args);
      const binaryPath = args.executable_path ?? store.getSession(sessionId)?.binary?.path;
      if (!binaryPath) throw rpcError(-32602, "No executable_path and no session binary path available.");
      const maxResults = args.max_results ?? 50;

      if (args.use_hopper) {
        await notifyProgress(extra, 0, 1, "Querying Hopper analyzed xrefs.");
        const hopperRes = await fetchHopperXrefs(officialBackend, args.target_addr, {
          expectedDocument: binaryPath,
          documentMustMatch: true,
          resolveCallers: true,
          includeCallees: Boolean(args.include_callees),
          maxResults,
        });
        if (hopperRes?.xrefs) {
          await notifyProgress(extra, 1, 1, `Hopper returned ${hopperRes.xrefs.length} xrefs.`);
          return toolResult({
            source: "hopper-analyzed",
            documentName: hopperRes.documentName,
            xrefs: hopperRes.xrefs,
            callerProcedures: hopperRes.callerProcedures,
            calleeProcedures: hopperRes.calleeProcedures,
          });
        }
        // Fall through to otool with a note about why Hopper was skipped.
        const reason = hopperRes?.documentMismatch
          ? `Hopper has '${hopperRes.documentMismatch.got}' open, expected '${hopperRes.documentMismatch.expected}'`
          : (hopperRes?.reason ?? "Hopper unavailable");
        await notifyProgress(extra, 0, 1, `Hopper skipped: ${reason}. Falling back to otool scan.`);
        const fallback = await findXrefs(binaryPath, {
          arch: args.arch ?? "auto",
          targetAddr: args.target_addr,
          maxResults,
        });
        await notifyProgress(extra, 1, 1, `otool found ${fallback.length} xrefs.`);
        return toolResult({
          source: "otool-fallback",
          hopperSkippedReason: reason,
          xrefs: fallback,
        });
      }

      await notifyProgress(extra, 0, 1, "Scanning binary for cross-references (streaming otool).");
      const result = await findXrefs(binaryPath, {
        arch: args.arch ?? "auto",
        targetAddr: args.target_addr,
        maxResults,
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

  // ── unified procedure / search ─────────────────────────────────────────
  server.registerTool(
    "procedure",
    {
      title: "Procedure",
      description:
        "Read a single field from a procedure: info | assembly | pseudo_code | callers | callees | comments. `procedure` accepts an address or name; defaults to the cursor procedure when omitted.",
      inputSchema: {
        field: z.enum(["info", "assembly", "pseudo_code", "callers", "callees", "comments"]),
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
        case "comments": {
          const session = store.getSession(sessionId);
          const start = parseAddress(fn.addr);
          if (start === null) return toolResult({ prefix: {}, inline: {} });
          // When size is unknown we can't reliably scope to a range; restrict
          // to the entrypoint only rather than silently returning every comment
          // at-or-after the function start (which would inflate the result for
          // stripped binaries with unresolved function boundaries).
          const end = fn.size ? start + fn.size : null;
          const inRange = (entry) => {
            const a = parseAddress(entry.addr);
            if (a === null) return false;
            return end === null ? a === start : a >= start && a < end;
          };
          const prefix = {};
          const inline = {};
          // Mirror the legacy comment / inline_comment tools' fallback shape
          // (src/server-tools.js:1308, 1325): older sessions may store the text
          // under .value rather than .comment.
          for (const c of session.comments ?? []) if (inRange(c)) prefix[formatAddress(c.addr)] = c.comment ?? c.value;
          for (const c of session.inlineComments ?? []) if (inRange(c)) inline[formatAddress(c.addr)] = c.comment ?? c.value;
          return toolResult({ prefix, inline });
        }
      }
    },
  );

  server.registerTool(
    "list",
    {
      title: "List",
      description:
        "List items from the active session by kind: procedures | strings | names | segments | bookmarks | imports | exports. " +
        "For procedures, optional `detail`: brief (default, addr→name) | size (addr→{name,size,basicblock_count}) | info (addr→full procedure info).",
      inputSchema: {
        kind: z.enum(["procedures", "strings", "names", "segments", "bookmarks", "imports", "exports"]),
        detail: z.enum(["brief", "size", "info"]).optional(),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => toolResult(store.listByKind(sessionFor(args), args.kind, args.detail ?? "brief")),
  );

  // Address-in-range lookup. The 'procedure' tool throws when given an address
  // that isn't a function entrypoint; this tool answers the implicit
  // "what function contains this instruction?" question explicitly.
  server.registerTool(
    "containing_function",
    {
      title: "Containing function",
      description:
        "Find the function whose body covers an address. Requires deep-mode imports (or live Hopper) to have populated function sizes. Returns null when sizes are unavailable instead of guessing.",
      inputSchema: {
        address: z.string().describe("Hex (0x...) or decimal instruction address."),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      const session = store.getSession(sessionId);
      const address = parseAddress(args.address);
      if (address === null || Number.isNaN(address)) {
        throw rpcError(-32602, `containing_function requires a numeric address; got '${args.address}'.`);
      }
      const normalized = formatAddress(address);
      const exact = session.functions[normalized];
      if (exact) {
        return toolResult({
          match: "entrypoint",
          function: officialProcedureInfo(exact),
          offset: 0,
        });
      }
      const containing = findContainingFunction(session, address);
      if (containing) {
        const start = parseAddress(containing.addr) ?? 0;
        return toolResult({
          match: "containment",
          function: officialProcedureInfo(containing),
          offset: address - start,
        });
      }
      const sizedCount = Object.values(session.functions ?? {}).filter((fn) => Number(fn.size ?? 0) > 0).length;
      const totalCount = Object.keys(session.functions ?? {}).length;
      return toolResult({
        match: "none",
        address: normalized,
        sizedFunctions: sizedCount,
        totalFunctions: totalCount,
        hint:
          sizedCount === 0
            ? "No function in this session has a known size. Re-ingest with deep=true (import_macho) or via Hopper to populate function ranges."
            : `Address falls outside all ${sizedCount} sized functions. It may be in stub/PLT code, data, or a region not yet discovered.`,
      });
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
    "analyze_binary",
    {
      title: "Analyze Binary",
      description:
        "Single entry for binary-level forensics. " +
        "kind: capabilities (imports bucketed) | anti_analysis (anti-debug findings) | entropy (per-section entropy) | code_signing (signing + entitlements) | objc (Objective-C runtime metadata).",
      inputSchema: {
        kind: z.enum(["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]),
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      switch (args.kind) {
        case "capabilities":  return toolResult(classifyImports(session.imports ?? []));
        case "anti_analysis": return toolResult(detectAntiAnalysis(session));
        case "entropy": {
          const binaryPath = session.binary?.path;
          if (!binaryPath) throw rpcError(-32602, "analyze_binary(entropy) requires a session with a binary path.");
          return toolResult(await computeSectionEntropy(binaryPath, session.binary?.arch ?? "auto", { maxBytes: 4 * 1024 * 1024 }));
        }
        case "code_signing": {
          const binaryPath = session.binary?.path;
          if (!binaryPath) throw rpcError(-32602, "analyze_binary(code_signing) requires a session with a binary path.");
          return toolResult(await extractCodeSigning(binaryPath));
        }
        case "objc": {
          const binaryPath = session.binary?.path;
          if (!binaryPath) throw rpcError(-32602, "analyze_binary(objc) requires a session with a binary path.");
          const classes = await extractObjCRuntime(binaryPath, session.binary?.arch ?? "auto", { maxClasses: 1000 });
          return toolResult({ count: classes.length, classes });
        }
        default: throw rpcError(-32602, `analyze_binary: unknown kind '${args.kind}'.`);
      }
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
