import { z } from "zod";
import { officialToolPayload } from "./official-hopper-backend.js";
import { buildOfficialSnapshot } from "./official-snapshot.js";
import { closeHopperDocument, ensureHopperAppReady } from "./hopper-live.js";
import {
  classifyImports,
  detectAntiAnalysis,
  buildFunctionFingerprint,
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
  compileUserRegex,
} from "./server-helpers.js";
import { toolResult, boundedNumber, DEFAULT_MAX_TOOL_TEXT_CHARS } from "./server-format.js";
import { parseAddress, formatAddress } from "./knowledge-store.js";
import { buildQueueOperation, buildHypothesisOperation, findSimilarFunctions } from "./tool-handlers.js";
import { wrapToolHandler } from "./debug-log.js";

const READ_ONLY = { readOnlyHint: true, openWorldHint: false };
const READ_OPEN_WORLD = { readOnlyHint: true, openWorldHint: true };
const WRITE_LOCAL = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const WRITE_LIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true };

const optionalString = z.string().optional();
const optionalNumber = z.number().optional();
const optionalBool = z.boolean().optional();
const optionalStringArray = z.array(z.string()).optional();

export function registerTools(server, ctx) {
  const { store, transactions, adapter, officialBackend, serverInfo } = ctx;

  // Auto-wrap every tool handler with (1) a strict-args input schema and
  // (2) debug instrumentation. The MCP SDK builds a Zod object schema in
  // default `.strip()` mode for raw-shape inputSchema, which silently
  // drops unknown keys — so a caller that mistypes `addrs` as `addr` (or
  // passes a removed param) sees a whole-session no-op success instead of
  // a "you typo'd" error. Replace the raw shape with a strict Zod object
  // so unknown keys surface as Zod errors at validation time. Debug
  // instrumentation is a no-op when HOPPER_MCP_DEBUG and
  // HOPPER_MCP_DEBUG_LOG are both unset, so the hot path is unchanged for
  // production callers.
  const rawRegisterTool = server.registerTool.bind(server);
  server.registerTool = (name, definition, handler) => {
    const def = { ...definition };
    const shape = definition.inputSchema;
    // Detect raw shapes: plain objects whose values are Zod schemas, no
    // _def / _zod marker on the container itself. Already-constructed Zod
    // schemas are passed through as-is so callers can opt out by passing
    // their own (e.g. union/intersection) schema.
    if (
      shape &&
      typeof shape === "object" &&
      !shape._def &&
      !shape._zod &&
      Object.values(shape).every((v) => v && typeof v === "object" && (v._def || v._zod || typeof v.parse === "function"))
    ) {
      def.inputSchema = z.strictObject(shape);
    }
    return rawRegisterTool(name, def, wrapToolHandler(name, handler));
  };

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
      await ensureHopperAppReady({ officialBackend });
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
  // ingest_official_hopper / ingest_live_hopper / open_session.
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
        max_blocks_per_function: optionalNumber,
        max_instructions_per_block: optionalNumber,
        analysis: optionalBool,
        loader: z.string().regex(/^[A-Za-z0-9_.-]+$/).optional(),
        loader_checkboxes: optionalStringArray,
        only_procedures: optionalBool,
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
        maxBlocksPerFunction: args.max_blocks_per_function,
        maxInstructionsPerBlock: args.max_instructions_per_block,
        analysis: args.analysis,
        loader: args.loader,
        loaderCheckboxes: args.loader_checkboxes,
        onlyProcedures: args.only_procedures,
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
      // Reject empty/whitespace before either path runs — pre-fix the index
      // path matched every function (haystack.includes("") is always true),
      // returning 20 random fingerprint dumps with no signal value. Better to
      // tell the caller what shape resolve actually accepts.
      if (!String(args.query ?? "").trim()) {
        throw rpcError(
          -32602,
          "resolve() requires a non-empty query — pass an address (0x100003f50), a function name (substring), a string literal, or an import (e.g. _SecItemCopyMatching). Use `list({kind:'procedures'})` to browse the snapshot.",
        );
      }
      let result = store.resolve(args.query, sessionId);
      // When the indexed Hopper snapshot returns empty, give the caller
      // something actionable instead of a bare []. Two common shapes
      // surfaced via Raycast probing:
      //   - Hex addr that exists in the binary but isn't a known function
      //     entrypoint or contained in any indexed body (e.g., __stubs/__got
      //     entries; addresses outside the imported slice). Used to look
      //     identical to "no such address" and gave callers no next step.
      //   - Regex-style query like /^_OBJC_CLASS_/i. resolve() does substring
      //     match, not regex — the slashes were treated as literal characters
      //     and silently produced zero hits with no doc hint.
      if (!result.length) {
        const q = String(args.query).trim();
        if (/^0x[0-9a-fA-F]+$/.test(q)) {
          return toolResult([{
            kind: "unresolved_address",
            addr: q,
            hint: "Address is not a known function entrypoint and is not contained in any indexed function body. May live in __stubs/__got, mid-instruction, or outside the captured Hopper snapshot. Try `containing_function`, or re-run `ingest_live_hopper` / `ingest_official_hopper` after Hopper finishes analysis.",
          }]);
        }
        if (q.startsWith("/") && /\/[gimsuy]*$/.test(q.slice(1))) {
          return toolResult([{
            kind: "regex_unsupported",
            query: q,
            hint: "resolve() does substring matching, not regex. Pass the raw substring (e.g., '_OBJC_CLASS_'), or use `search({kind:'names'|'strings'|'procedures', pattern:...})` for regex.",
          }]);
        }
      }
      // Cap on the way out — the primary store.resolve() path previously
      // ignored max_results entirely, so a fuzzy query like resolve("main")
      // on a 30k-function binary returned ~20 fingerprint-heavy hits even
      // when max_results:5 was passed.
      return toolResult(limitResults(result, args.max_results));
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
      description:
        "Return caller/callee graph neighborhood for a function. `seed` accepts an entrypoint address, a function name, or a mid-function address (resolved to its containing function via the same logic as `procedure`). `max_nodes` (default 200, 0=uncapped) bounds BFS — known nodes ship full fingerprints, so hub functions at radius>=3 can otherwise overflow the host token budget.",
      inputSchema: {
        seed: z.string(),
        radius: optionalNumber,
        kind: z.enum(["calls", "callers", "callees"]).optional(),
        max_nodes: optionalNumber,
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const sessionId = sessionFor(args);
      // Pre-resolve so a name, mid-function addr, or stub address surfaces the
      // same actionable hints procedure()/find_similar_functions emit. Pre-fix
      // the bare 'Unknown function address: X' from store.getFunction left
      // analysts with no next step when X was a known name (e.g. a synthetic
      // cluster node) or a __text addr that wasn't a function entrypoint.
      const target = resolveProcedure(store, args.seed, sessionId);
      return toolResult(
        store.getGraphSlice(target.addr, {
          radius: args.radius ?? 1,
          kind: args.kind ?? "calls",
          maxNodes: args.max_nodes === undefined ? 200 : args.max_nodes,
          sessionId,
        }),
      );
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

  server.registerTool(
    "xrefs",
    {
      title: "Xrefs (Snapshot)",
      description:
        "Snapshot xrefs: cross-references to/from an address in the active session's Hopper-derived indexed metadata.",
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
          // Mirror the pseudo_code branch's "not captured" guidance instead
          // of silently returning "".
          if (!lines.length) {
            return toolResult(
              "Assembly was not captured for this procedure. Re-run ingest_live_hopper after Hopper finishes analysis to populate basic-block instructions.",
            );
          }
          return toolResult(args.max_lines ? lines.slice(0, args.max_lines).join("\n") : lines.join("\n"));
        }
        case "pseudo_code": {
          if (!fn.pseudocode) {
            return toolResult(
              "Pseudocode was not captured. Re-run ingest_live_hopper with include_pseudocode=true for selected functions.",
            );
          }
          // Pre-fix: max_lines was honored for assembly but silently ignored
          // for pseudo_code, so a function with a 10k-line pseudocode block
          // would dump the whole thing regardless of the cap. Apply the same
          // slice-and-mark policy as assembly, with an explicit truncation
          // tail so callers know to widen.
          if (!args.max_lines) return toolResult(fn.pseudocode);
          const lines = fn.pseudocode.split("\n");
          if (lines.length <= args.max_lines) return toolResult(fn.pseudocode);
          const head = lines.slice(0, args.max_lines).join("\n");
          return toolResult(
            `${head}\n... ${lines.length - args.max_lines} more pseudocode lines (pass max_lines=0 for full text).`,
          );
        }
        case "callers":
        case "callees": {
          const session = store.getSession(sessionId);
          const list = (args.field === "callers" ? fn.callers : fn.callees) ?? [];
          // Pre-fix: max_lines was silently ignored on callers/callees, so a
          // hub function with 5000 callees would dump the whole list and blow
          // the host's token budget. Honor max_lines (same convention as
          // assembly: 0/undef = no cap), and append a tail marker so callers
          // know to widen rather than mistaking the cap for the true count.
          const named = list.map((addr) => store.getFunctionIfKnown(session, addr).name ?? addr);
          if (!args.max_lines || named.length <= args.max_lines) return toolResult(named);
          const head = named.slice(0, args.max_lines);
          head.push(`... ${named.length - args.max_lines} more (pass max_lines=0 for full list).`);
          return toolResult(head);
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
        "For procedures, optional `detail`: brief (default, addr→name) | size (addr→{name,size,basicblock_count}) | info (addr→full procedure info). " +
        "max_results caps the number of entries returned (default 500); pass 0 for no cap. Stripped binaries can have thousands of imports — the default exists so a casual `list` doesn't blow the host's per-tool token budget.",
      inputSchema: {
        kind: z.enum(["procedures", "strings", "names", "segments", "bookmarks", "imports", "exports"]),
        detail: z.enum(["brief", "size", "info"]).optional(),
        max_results: optionalNumber,
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) =>
      toolResult(
        store.listByKind(sessionFor(args), args.kind, args.detail ?? "brief", {
          maxResults: args.max_results ?? 500,
        }),
      ),
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
            ? "No function in this session has a known size. Re-ingest from Hopper after analysis completes to populate function ranges."
            : `Address falls outside all ${sizedCount} sized functions. It may be in stub/PLT code, data, or a region not yet discovered.`,
      });
    },
  );

  server.registerTool(
    "search",
    {
      title: "Search",
      description:
        "Search the active snapshot by kind: strings | procedures | names. `pattern` is treated as a regex unless case_sensitive forces exact handling. `max_results` defaults to 500; pass 0 for uncapped (mirrors `list`).",
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
      // search() used to be uncapped on the procedures/names branches: a
      // harmless-looking pattern like '.*' against Raycast (~30k procs) emits a
      // 130KB+ payload that overflows the MCP per-tool token budget and dumps
      // to a file. limitResults treats 0 as "no cap" (matching list()'s
      // documented contract), so callers who genuinely want everything pass 0
      // explicitly.
      const maxResults = args.max_results === undefined ? 500 : args.max_results;
      if (args.kind === "strings") {
        if (args.semantic) {
          const result = store.searchStrings(args.pattern, {
            semantic: true,
            sessionId,
            maxResults,
          });
          return toolResult(result);
        }
        return toolResult(
          objectFromAddressItems(
            searchStringsOfficial(store, args.pattern, {
              caseSensitive: Boolean(args.case_sensitive),
              sessionId,
              maxResults,
            }),
            "value",
          ),
        );
      }
      if (args.kind === "procedures") {
        const regex = compileUserRegex(args.pattern, flags);
        return toolResult(
          objectFromFunctions(
            limitResults(
              listProcedures(store, sessionId).filter((fn) =>
                regex.test([fn.addr, fn.name, fn.signature, fn.summary].filter(Boolean).join(" ")),
              ),
              maxResults,
            ),
            (fn) => fn.name ?? fn.addr,
          ),
        );
      }
      // names
      const session = store.getSession(sessionId);
      const regex = compileUserRegex(args.pattern, flags);
      return toolResult(
        objectFromAddressItems(
          limitResults(
            (session.names ?? []).filter((item) =>
              regex.test([item.addr, item.name, item.demangled].filter(Boolean).join(" ")),
            ),
            maxResults,
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
    async (args) => {
      const preview = transactions.preview({ transactionId: args.transaction_id, sessionId: sessionFor(args) });
      // Surface a warning when the preview shows an empty op list — a commit
      // would be a silent no-op. Pre-fix this returned the bare envelope and
      // analysts would commit nothing without realising it.
      const opsLen = (preview?.operations ?? []).length;
      if (opsLen === 0) {
        return toolResult({
          ...preview,
          warning: "Transaction has no queued operations — committing now would be a no-op. Use `queue` (rename/comment/etc) or `hypothesis` to add ops first.",
        });
      }
      return toolResult(preview);
    },
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
        "Manage research hypotheses. All actions queue an op into the active transaction — call `begin_transaction` first (or pass `transaction_id`) and `commit_transaction` after. `action=create` creates a hypothesis (requires `topic`); `action=link` attaches evidence (requires `hypothesis_id`); `action=status` updates status (requires `hypothesis_id` + `status`).",
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
        "Single entry for Hopper-snapshot binary forensics. " +
        "kind: capabilities (imports bucketed → {totalImports, counts, samples, truncated}; pass max_per_bucket=0 to dump every entry) | anti_analysis (anti-debug findings). entropy/code_signing/objc are reported as unsupported unless a future Hopper export captures that data.",
      inputSchema: {
        kind: z.enum(["capabilities", "anti_analysis", "entropy", "code_signing", "objc"]),
        max_per_bucket: optionalNumber,
        max_classes: optionalNumber,
        max_methods_per_class: optionalNumber,
        session_id: optionalString,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const session = store.getSession(sessionFor(args));
      switch (args.kind) {
        case "capabilities":  return toolResult(
          classifyImports(session.imports ?? [], { maxPerBucket: args.max_per_bucket ?? 25 }),
        );
        case "anti_analysis": return toolResult(detectAntiAnalysis(session));
        case "entropy":
          return toolResult({
            supported: false,
            source: "hopper-snapshot",
            reason: "Hopper's public MCP/export snapshot does not expose raw section bytes. This server no longer invokes local otool fallback for entropy.",
          });
        case "code_signing":
          return toolResult({
            supported: false,
            source: "hopper-snapshot",
            reason: "Code-signing metadata is outside Hopper's MCP/export snapshot. This server no longer invokes local codesign fallback.",
          });
        case "objc": {
          const classes = session.binary?.objcClasses ?? session.objcClasses ?? [];
          const maxClasses = Number(args.max_classes ?? 100);
          const maxMethods = Number(args.max_methods_per_class ?? 25);
          const truncatedMethods = [];
          const slice = maxClasses > 0 ? classes.slice(0, maxClasses) : classes;
          const summarised = slice.map((cls) => {
            const methodCount = (cls.methods ?? []).length;
            const out = { ...cls, methodCount };
            if (maxMethods > 0 && methodCount > maxMethods) {
              out.methods = cls.methods.slice(0, maxMethods);
              out.methodsTruncated = true;
              if (cls.name) truncatedMethods.push(cls.name);
            }
            return out;
          });
          return toolResult({
            supported: classes.length > 0,
            source: "hopper-snapshot",
            count: classes.length,
            shown: summarised.length,
            classes: summarised,
            classesTruncated: maxClasses > 0 && classes.length > maxClasses,
            methodsTruncated: truncatedMethods,
            reason: classes.length ? null : "No Objective-C runtime metadata was present in the Hopper snapshot.",
          });
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
      description:
        "Diff two sessions: added/removed/renamed/changed functions, strings, imports. Each bucket capped at max_per_bucket=200 (pass 0 for uncapped). Real binaries (Cursor vs Raycast) overflow at 140K+ chars without the cap; check `summary` for full counts and `truncated` for which buckets were trimmed.",
      inputSchema: {
        left_session_id: z.string(),
        right_session_id: z.string(),
        max_per_bucket: optionalNumber,
      },
      annotations: READ_ONLY,
    },
    async (args) => {
      const left = store.getSession(args.left_session_id);
      const right = store.getSession(args.right_session_id);
      const maxPerBucket = args.max_per_bucket === undefined ? 200 : args.max_per_bucket;
      return toolResult(diffSessions(left, right, { maxPerBucket }));
    },
  );
}
