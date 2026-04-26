import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { dirname } from "node:path";

const EMPTY_STORE = {
  schemaVersion: 1,
  sessions: {},
};

const DEFAULT_SESSION_CAP = 16;

export class KnowledgeStore {
  // sessionCap bounds how many ingested sessions live on disk; the long-running
  // server otherwise grows unbounded as users open binary after binary (we have
  // observed >100 MiB stores in practice). The current session is never
  // evicted; older entries are dropped by `updatedAt`.
  constructor(path, { sessionCap = DEFAULT_SESSION_CAP } = {}) {
    this.path = path;
    this.sessionCap = Number.isFinite(Number(sessionCap)) && Number(sessionCap) > 0
      ? Math.floor(Number(sessionCap))
      : DEFAULT_SESSION_CAP;
    this.state = structuredClone(EMPTY_STORE);
    this._savePromise = null;
  }

  async load() {
    try {
      const text = await readFile(this.path, "utf8");
      this.state = JSON.parse(text);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.state = structuredClone(EMPTY_STORE);
      await this.save();
    }
  }

  // Durable: resolves once the latest enqueued write has hit disk.
  async save() {
    return this._enqueueSave();
  }

  // Fire-and-forget. Errors get logged to stderr instead of becoming an
  // unhandledRejection. Use this from hot paths where the response should
  // not block on a 100 MB JSON.stringify + writeFile.
  scheduleSave() {
    this._enqueueSave().catch((err) => {
      try {
        process.stderr.write(`[hopper-mcp] knowledge-store save error: ${err?.stack ?? err}\n`);
      } catch {}
    });
  }

  // Single-flight serializer: chains writes so concurrent callers cannot
  // race on the same file, and one failure does not poison the queue.
  _enqueueSave() {
    const next = (this._savePromise ?? Promise.resolve())
      .catch(() => {})
      .then(() => this._writeStateToDisk());
    this._savePromise = next;
    return next;
  }

  async _writeStateToDisk() {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(this.state) + "\n", "utf8");
    await rename(tmp, this.path);
  }

  listSessions() {
    return Object.values(this.state.sessions).map((session) => ({
      sessionId: session.sessionId,
      binaryId: session.binaryId,
      name: session.binary?.name ?? "unknown",
      path: session.binary?.path ?? null,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
    }));
  }

  getSession(sessionId = "current") {
    const id = sessionId === "current" ? this.state.currentSessionId : sessionId;
    if (!id || !this.state.sessions[id]) {
      throw new Error(`No Hopper session is loaded for '${sessionId}'.`);
    }
    return this.state.sessions[id];
  }

  // Pin a previously-loaded session as the active one. Throws when the id is
  // unknown so callers can surface "no such session" instead of silently
  // creating a dangling currentSessionId pointer.
  setCurrentSession(sessionId) {
    if (!sessionId || !this.state.sessions[sessionId]) {
      throw new Error(`No Hopper session loaded for '${sessionId}'.`);
    }
    this.state.currentSessionId = sessionId;
    this.scheduleSave();
    return this.state.sessions[sessionId];
  }

  // Drop a session from disk + memory. Returns the dropped session record so
  // callers can read e.g. binary.name for a live-Hopper close-document call.
  async dropSession(sessionId) {
    const id = sessionId === "current" ? this.state.currentSessionId : sessionId;
    if (!id || !this.state.sessions[id]) {
      throw new Error(`No Hopper session loaded for '${sessionId}'.`);
    }
    const dropped = this.state.sessions[id];
    delete this.state.sessions[id];
    if (this.state.currentSessionId === id) {
      const remaining = Object.values(this.state.sessions)
        .sort((a, b) => String(b.updatedAt ?? "").localeCompare(String(a.updatedAt ?? "")));
      this.state.currentSessionId = remaining[0]?.sessionId;
    }
    // Durable: drops are user-visible state changes that must survive a
    // crash. Use await save instead of fire-and-forget.
    await this.save();
    return dropped;
  }

  async upsertSession(session, { overwrite = true, foldAliases = false } = {}) {
    const now = new Date().toISOString();
    const sessionId = session.sessionId ?? `session-${crypto.randomUUID()}`;
    const existing = this.state.sessions[sessionId];
    if (existing && !overwrite) {
      throw new Error(
        `Session '${sessionId}' already exists. Pass overwrite=true to replace it, or close_session first.`,
      );
    }

    // Optional: fold sessions that point at the same binary into the new one
    // so re-ingesting via a different prefix (live-/official-/macho-) doesn't
    // leave forks behind. Off by default because folding a sparse macho
    // import on top of a rich live-Hopper session would discard the latter's
    // function bodies — only the user's annotations are carried forward by
    // mergeUserAnnotations. Callers that genuinely want to dedupe pass
    // fold_aliases=true (e.g. after confirming both sources are equivalent).
    const incomingPath = session.binary?.path ?? null;
    const aliases = [];
    if (foldAliases && incomingPath) {
      for (const [otherId, other] of Object.entries(this.state.sessions)) {
        if (otherId === sessionId) continue;
        if (other.binary?.path && other.binary.path === incomingPath) aliases.push(other);
      }
    }

    const normalized = normalizeSession({
      ...session,
      sessionId,
      createdAt: session.createdAt ?? existing?.createdAt ?? aliases[0]?.createdAt ?? now,
      updatedAt: now,
    });
    if (existing) mergeUserAnnotations(normalized, existing);
    for (const alias of aliases) {
      mergeUserAnnotations(normalized, alias);
      delete this.state.sessions[alias.sessionId];
    }
    this.state.sessions[sessionId] = normalized;
    this.state.currentSessionId = sessionId;
    this.pruneStaleSessions();
    // Background save: importer paths can produce ~100 MB stringify; keep
    // the response off the event-loop stall. Annotation tools that need
    // durability still call await store.save() explicitly.
    this.scheduleSave();
    return normalized;
  }

  // Drop oldest sessions (by updatedAt) once we exceed the cap, keeping the
  // current session pinned. Returns the IDs that were evicted so callers can
  // log if they want — no caller currently does, but it makes the behaviour
  // testable without inspecting state directly.
  pruneStaleSessions(cap = this.sessionCap) {
    const ids = Object.keys(this.state.sessions);
    if (ids.length <= cap) return [];
    const current = this.state.currentSessionId;
    const evictable = ids
      .filter((id) => id !== current)
      .map((id) => this.state.sessions[id])
      .sort((a, b) => String(a.updatedAt ?? "").localeCompare(String(b.updatedAt ?? "")));
    const overflow = ids.length - cap;
    const evicted = [];
    for (const session of evictable.slice(0, overflow)) {
      delete this.state.sessions[session.sessionId];
      evicted.push(session.sessionId);
    }
    return evicted;
  }

  resolve(query, sessionId = "current") {
    const session = this.getSession(sessionId);
    const q = String(query).trim();
    const lower = q.toLowerCase();
    const byAddress = parseAddress(q);

    const matches = [];
    for (const fn of Object.values(session.functions)) {
      if (byAddress !== null && parseAddress(fn.addr) === byAddress) {
        matches.push({ kind: "function", score: 1, item: publicFunction(fn) });
        continue;
      }
      // Address-in-range: a query for an instruction address inside a known
      // function body should still surface that function (lower score so the
      // exact-entrypoint match always sorts above containment).
      if (byAddress !== null) {
        const start = parseAddress(fn.addr);
        const size = Number(fn.size ?? 0);
        if (start !== null && size > 0 && byAddress > start && byAddress < start + size) {
          matches.push({ kind: "function", score: 0.9, item: publicFunction(fn), containment: { entrypoint: fn.addr, offset: byAddress - start } });
          continue;
        }
      }
      const haystack = [fn.name, fn.summary, ...(fn.strings ?? []), ...(fn.imports ?? [])]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (haystack.includes(lower)) {
        matches.push({ kind: "function", score: fn.name?.toLowerCase() === lower ? 0.95 : 0.65, item: publicFunction(fn) });
      }
    }

    for (const str of session.strings) {
      if (str.value.toLowerCase().includes(lower) || (byAddress !== null && parseAddress(str.addr) === byAddress)) {
        matches.push({ kind: "string", score: 0.55, item: str });
      }
    }

    for (const item of session.names ?? []) {
      const addrMatch = byAddress !== null && parseAddress(item.addr) === byAddress;
      const nameMatch = typeof item.name === "string" && item.name.toLowerCase().includes(lower);
      if (addrMatch || nameMatch) {
        matches.push({ kind: "name", score: addrMatch ? 0.85 : 0.6, item });
      }
    }

    for (const item of session.bookmarks ?? []) {
      const addrMatch = byAddress !== null && parseAddress(item.addr) === byAddress;
      const labelMatch = typeof item.label === "string" && item.label.toLowerCase().includes(lower);
      if (addrMatch || labelMatch) {
        matches.push({ kind: "bookmark", score: addrMatch ? 0.8 : 0.55, item });
      }
    }

    return matches.sort((a, b) => b.score - a.score).slice(0, 20);
  }

  analyzeFunctionDeep(addr, { detailLevel = "standard", sessionId = "current" } = {}) {
    const session = this.getSession(sessionId);
    const fn = this.getFunction(session, addr);
    const callers = (fn.callers ?? []).map((caller) => publicFunction(this.getFunctionIfKnown(session, caller)));
    const callees = (fn.callees ?? []).map((callee) => publicFunction(this.getFunctionIfKnown(session, callee)));
    const evidence = this.getFunctionEvidence(session, fn.addr);
    const includeBlocks = detailLevel === "full";

    return {
      function: publicFunction(fn),
      inferredPurpose: fn.summary ?? inferPurpose(fn),
      confidence: fn.confidence ?? 0.4,
      callers,
      callees,
      stringsTouched: fn.strings ?? [],
      importsTouched: fn.imports ?? [],
      selectorsTouched: fn.selectors ?? [],
      evidenceAnchors: evidence.anchors,
      pseudocode: fn.pseudocode ?? null,
      assemblySlices: includeBlocks ? fn.basicBlocks ?? [] : (fn.basicBlocks ?? []).slice(0, 3),
      provenance: evidence.provenance,
    };
  }

  searchStrings(pattern, { semantic = false, sessionId = "current", maxResults } = {}) {
    const session = this.getSession(sessionId);
    const regex = new RegExp(pattern, "i");
    const matched = session.strings.filter((str) => regex.test(str.value));
    const limit = Number.isFinite(Number(maxResults)) ? Math.max(0, Number(maxResults)) : matched.length;
    const results = matched.slice(0, limit);

    if (!semantic) return results;

    return results.map((str) => ({
      ...str,
      referencedBy: Object.values(session.functions)
        .filter((fn) => (fn.strings ?? []).includes(str.value) || (fn.xrefsTo ?? []).includes(str.addr))
        .map(publicFunction),
    }));
  }

  getGraphSlice(seed, { radius = 1, kind = "calls", sessionId = "current" } = {}) {
    const session = this.getSession(sessionId);
    const root = this.getFunction(session, seed);
    const seen = new Set([root.addr]);
    const edges = [];
    const queue = [{ addr: root.addr, depth: 0 }];

    while (queue.length) {
      const current = queue.shift();
      if (current.depth >= radius) continue;
      const fn = this.getFunction(session, current.addr);
      const next = kind === "callers" ? fn.callers ?? [] : fn.callees ?? [];
      for (const target of next) {
        const normalizedTarget = formatAddress(target);
        edges.push(kind === "callers" ? { from: normalizedTarget, to: fn.addr } : { from: fn.addr, to: normalizedTarget });
      if (!seen.has(normalizedTarget)) {
        seen.add(normalizedTarget);
        if (session.functions[normalizedTarget]) {
          queue.push({ addr: normalizedTarget, depth: current.depth + 1 });
        }
      }
    }
    }

    return {
      root: publicFunction(root),
      nodes: [...seen].map((addr) => publicFunction(this.getFunctionIfKnown(session, addr))),
      edges,
    };
  }

  getTransactionById(session, txnId) {
    const pending = session.transactions?.pending ?? [];
    const txn = pending.find((t) => t.id === txnId);
    if (!txn) throw new Error(`No transaction '${txnId}' in session '${session.sessionId}'.`);
    return txn;
  }

  getResource(uri) {
    const parsed = parseHopperUri(uri);
    const session = this.getSession(parsed.sessionId ?? "current");

    if (parsed.path === "/session/current") return this.describeSession(session);
    if (parsed.path === "/binary/metadata") return session.binary;
    if (parsed.path === "/binary/imports") return session.imports;
    if (parsed.path === "/binary/exports") return session.exports;
    if (parsed.path === "/binary/strings" || parsed.path === "/strings/index") return session.strings;
    if (parsed.path === "/binary/capabilities") return session.binary?.capabilities ?? {};
    if (parsed.path === "/binary/signing") return session.binary?.signing ?? null;
    if (parsed.path === "/binary/entropy") return session.binary?.sectionEntropy ?? [];
    if (parsed.path === "/anti-analysis") return session.antiAnalysisFindings ?? [];
    if (parsed.path === "/tags") return session.tags ?? {};
    if (parsed.path === "/hypotheses") return session.hypotheses ?? [];
    if (parsed.path === "/names") return session.names ?? [];
    if (parsed.path === "/bookmarks") return session.bookmarks ?? [];
    if (parsed.path === "/comments") return session.comments ?? [];
    if (parsed.path === "/inline-comments") return session.inlineComments ?? [];
    if (parsed.path === "/cursor") return session.cursor ?? {};
    if (parsed.path === "/functions") return Object.values(session.functions).map(publicFunction);
    if (parsed.path === "/objc/classes") return session.objcClasses;
    if (parsed.path === "/swift/symbols") return session.swiftSymbols;
    if (parsed.path === "/transactions/pending") return session.transactions?.pending ?? [];
    if (parsed.path.startsWith("/transactions/") && parsed.path !== "/transactions/pending") {
      const id = parsed.path.slice("/transactions/".length);
      return this.getTransactionById(session, id);
    }

    const functionMatch = parsed.path.match(/^\/function\/([^/]+)(?:\/(summary|evidence))?$/);
    if (functionMatch) {
      const fn = this.getFunction(session, functionMatch[1]);
      if (functionMatch[2] === "summary") return { function: publicFunction(fn), summary: fn.summary ?? inferPurpose(fn), confidence: fn.confidence ?? 0.4 };
      if (functionMatch[2] === "evidence") return this.getFunctionEvidence(session, fn.addr);
      return fn;
    }

    const graphMatch = parsed.path.match(/^\/graph\/(callers|callees)\/([^/]+)$/);
    if (graphMatch) return this.getGraphSlice(graphMatch[2], { kind: graphMatch[1], radius: Number(parsed.query.get("radius") ?? 1) });

    throw new Error(`Unknown resource URI: ${uri}`);
  }

  describeSession(session) {
    return {
      sessionId: session.sessionId,
      binaryId: session.binaryId,
      binary: session.binary,
      counts: {
        functions: Object.keys(session.functions).length,
        strings: session.strings.length,
        imports: session.imports.length,
        exports: session.exports.length,
        names: (session.names ?? []).length,
        bookmarks: (session.bookmarks ?? []).length,
        comments: (session.comments ?? []).length,
        inlineComments: (session.inlineComments ?? []).length,
        objcClasses: session.objcClasses.length,
        swiftSymbols: session.swiftSymbols.length,
        tags: Object.keys(session.tags ?? {}).length,
        hypotheses: (session.hypotheses ?? []).length,
        antiAnalysisFindings: (session.antiAnalysisFindings ?? []).length,
        objcMethods: (session.objcClasses ?? []).reduce((acc, cls) => acc + (cls.methods?.length ?? 0), 0),
      },
      capabilities: session.capabilities,
      updatedAt: session.updatedAt,
    };
  }

  getFunction(session, addr) {
    const normalized = formatAddress(addr);
    const fn = session.functions[normalized];
    if (!fn) throw new Error(`Unknown function address: ${addr}`);
    return fn;
  }

  getFunctionIfKnown(session, addr) {
    const normalized = formatAddress(addr);
    return session.functions[normalized] ?? { addr: normalized, name: null, summary: "Referenced function not present in the current local slice.", confidence: 0 };
  }

  getFunctionEvidence(session, addr) {
    const fn = this.getFunction(session, addr);
    const anchors = [
      ...(fn.basicBlocks ?? []).slice(0, 5).map((block) => ({ kind: "basic_block", addr: block.addr, reason: block.summary ?? "selected control-flow evidence" })),
      ...(fn.imports ?? []).map((name) => ({ kind: "import", name, reason: "API dependency" })),
      ...(fn.strings ?? []).map((value) => ({ kind: "string", value, reason: "string referenced by function" })),
    ];
    return {
      function: publicFunction(fn),
      anchors,
      provenance: {
        pseudocode: Boolean(fn.pseudocode),
        assembly: Boolean(fn.basicBlocks?.length),
        metadata: Boolean(fn.imports?.length || fn.selectors?.length),
        source: fn.source ?? "knowledge-store",
      },
    };
  }

  // Single dispatch point used by the `list` tool. Most kinds return shapes
  // compatible with the corresponding pre-overhaul list_* tool. `names`
  // returns the richer {name, demangled} shape.
  listByKind(sessionId, kind, detail = "brief") {
    const session = this.getSession(sessionId);
    switch (kind) {
      case "procedures": return this._listProcedures(session, detail);
      case "strings":    return this._listStrings(session);
      case "names":      return this._listNames(session);
      case "segments":   return (session.binary?.segments ?? []).map(projectSegment);
      case "bookmarks":  return session.bookmarks ?? [];
      case "imports":    return session.imports ?? [];
      case "exports":    return session.exports ?? [];
      default:
        throw new Error(`Unknown list kind '${kind}'. Expected one of procedures|strings|names|segments|bookmarks|imports|exports.`);
    }
  }

  _listProcedures(session, detail) {
    const fns = Object.values(session.functions ?? {});
    const out = {};
    for (const fn of fns) {
      const addr = formatAddress(fn.addr);
      if (detail === "size") {
        out[addr] = {
          name: fn.name ?? null,
          size: fn.size ?? null,
          basicblock_count: fn.basicBlockCount ?? fn.basicBlocks?.length ?? 0,
        };
      } else if (detail === "info") {
        out[addr] = {
          name: fn.name ?? null,
          entrypoint: addr,
          length: fn.size ?? null,
          basicblock_count: fn.basicBlockCount ?? fn.basicBlocks?.length ?? 0,
          basicblocks: fn.basicBlocks ?? [],
          signature: fn.signature ?? null,
          locals: fn.locals ?? [],
        };
      } else {
        out[addr] = fn.name ?? addr;
      }
    }
    return out;
  }

  _listStrings(session) {
    const out = {};
    for (const s of session.strings ?? []) {
      out[formatAddress(s.addr)] = { value: s.value };
    }
    return out;
  }

  _listNames(session) {
    const out = {};
    for (const n of session.names ?? []) {
      out[formatAddress(n.addr)] = { name: n.name, demangled: n.demangled ?? null };
    }
    // Merge in function names so renames show up in `list({kind:"names"})` too.
    for (const fn of Object.values(session.functions ?? {})) {
      if (fn?.addr && fn?.name) {
        const addr = formatAddress(fn.addr);
        if (!(addr in out)) out[addr] = { name: fn.name, demangled: null };
      }
    }
    return out;
  }
}

export function normalizeSession(session) {
  const functions = {};
  const functionItems = Array.isArray(session.functions)
    ? session.functions
    : Object.values(session.functions ?? {});

  for (const fn of functionItems) {
    const addr = formatAddress(fn.addr);
    functions[addr] = {
      ...fn,
      addr,
      callers: (fn.callers ?? []).map(formatAddress),
      callees: (fn.callees ?? []).map(formatAddress),
    };
  }

  return {
    sessionId: session.sessionId,
    binaryId: session.binaryId ?? `binary-${session.sessionId}`,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    binary: session.binary ?? {},
    capabilities: session.capabilities ?? { officialApi: true, privateApi: false, dynamicDebugger: false },
    functions,
    strings: session.strings ?? [],
    names: normalizeAddressItems(session.names ?? []),
    bookmarks: normalizeAddressItems(session.bookmarks ?? []),
    comments: normalizeCommentItems(session.comments ?? []),
    inlineComments: normalizeCommentItems(session.inlineComments ?? []),
    cursor: {
      ...(session.cursor ?? {}),
      address: session.cursor?.address ? formatAddress(session.cursor.address) : null,
      procedure: session.cursor?.procedure ? formatAddress(session.cursor.procedure) : null,
    },
    imports: session.imports ?? [],
    exports: session.exports ?? [],
    objcClasses: session.objcClasses ?? [],
    swiftSymbols: session.swiftSymbols ?? [],
    tags: normalizeTags(session.tags ?? {}),
    hypotheses: session.hypotheses ?? [],
    antiAnalysisFindings: session.antiAnalysisFindings ?? [],
    transactions: session.transactions ?? { pending: [] },
  };
}

function mergeUserAnnotations(target, existing) {
  if (Object.keys(existing.tags ?? {}).length) target.tags = existing.tags;
  if ((existing.hypotheses ?? []).length) target.hypotheses = existing.hypotheses;
  if ((existing.names ?? []).length) target.names = mergeAddressItems(target.names, existing.names);
  if ((existing.bookmarks ?? []).length) target.bookmarks = mergeAddressItems(target.bookmarks, existing.bookmarks);
  if ((existing.comments ?? []).length) target.comments = mergeAddressItems(target.comments, existing.comments);
  if ((existing.inlineComments ?? []).length) target.inlineComments = mergeAddressItems(target.inlineComments, existing.inlineComments);
  if (existing.transactions?.pending?.length) target.transactions = existing.transactions;
  if ((existing.antiAnalysisFindings ?? []).length && !(target.antiAnalysisFindings ?? []).length) {
    target.antiAnalysisFindings = existing.antiAnalysisFindings;
  }
  if (existing.cursor && Object.keys(existing.cursor).length && !Object.keys(target.cursor ?? {}).length) {
    target.cursor = existing.cursor;
  }

  for (const [addr, existingFn] of Object.entries(existing.functions ?? {})) {
    const newFn = target.functions[addr];
    if (!newFn) continue;
    if (existingFn.name && existingFn.name !== newFn.name && !isAutoName(existingFn.name)) {
      newFn.name = existingFn.name;
    }
    if (existingFn.comment) newFn.comment = existingFn.comment;
    if (existingFn.inlineComments && Object.keys(existingFn.inlineComments).length) {
      newFn.inlineComments = { ...(newFn.inlineComments ?? {}), ...existingFn.inlineComments };
    }
    if (existingFn.type) newFn.type = existingFn.type;
    if (existingFn.summary && !newFn.summary) newFn.summary = existingFn.summary;
    if (existingFn.confidence != null && (newFn.confidence ?? 0) < existingFn.confidence) {
      newFn.confidence = existingFn.confidence;
    }
  }
}

function mergeAddressItems(target, existing) {
  const merged = new Map();
  for (const item of target ?? []) {
    if (item?.addr) merged.set(item.addr, item);
  }
  for (const item of existing ?? []) {
    if (item?.addr && !merged.has(item.addr)) merged.set(item.addr, item);
  }
  return [...merged.values()];
}

function isAutoName(name) {
  if (!name) return true;
  if (/^sub_[0-9a-f]+$/i.test(name)) return true;
  if (/^proc_[0-9a-f]+$/i.test(name)) return true;
  if (/^fcn_[0-9a-f]+$/i.test(name)) return true;
  if (/^loc_[0-9a-f]+$/i.test(name)) return true;
  if (name === "__mh_execute_header") return true;
  return false;
}

function normalizeTags(tags) {
  const out = {};
  for (const [addr, value] of Object.entries(tags ?? {})) {
    const key = formatAddress(addr);
    const list = Array.isArray(value) ? value : [value];
    out[key] = [...new Set(list.map(String))].sort();
  }
  return out;
}

function normalizeAddressItems(items) {
  return items.map((item) => ({
    ...item,
    addr: item.addr ? formatAddress(item.addr) : item.addr,
  }));
}

function normalizeCommentItems(items) {
  return items.map((item) => ({
    ...item,
    addr: item.addr ? formatAddress(item.addr) : item.addr,
  }));
}

export function parseAddress(value) {
  if (typeof value === "number") return value;
  if (!value) return null;
  const text = String(value);
  if (/^0x[0-9a-f]+$/i.test(text)) return Number.parseInt(text.slice(2), 16);
  if (/^[0-9]+$/.test(text)) return Number.parseInt(text, 10);
  return null;
}

export function formatAddress(value) {
  const parsed = parseAddress(value);
  if (parsed === null || Number.isNaN(parsed)) return String(value);
  return `0x${parsed.toString(16)}`;
}

function publicFunction(fn) {
  return {
    addr: fn.addr,
    name: fn.name ?? null,
    size: fn.size ?? null,
    summary: fn.summary ?? null,
    confidence: fn.confidence ?? null,
    fingerprint: fn.fingerprint ?? null,
  };
}

function inferPurpose(fn) {
  const imports = (fn.imports ?? []).join(" ").toLowerCase();
  const strings = (fn.strings ?? []).join(" ").toLowerCase();
  if (imports.includes("sec") || strings.includes("keychain")) return "Likely interacts with macOS/iOS security services.";
  if (imports.includes("url") || imports.includes("network")) return "Likely participates in networking behavior.";
  if (imports.includes("ptrace") || strings.includes("debug")) return "Potential anti-debug or debugger-awareness logic.";
  return "Purpose is not yet inferred; inspect evidence anchors before naming.";
}

// Inline projection for segments — mirrors officialSegment in server-helpers.js
// without importing it (server-helpers imports from this module, so the inverse
// would create a circular dependency).
function projectSegment(segment) {
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
        end:
          section.end ??
          (sectionStart !== null && sectionLength > 0 ? formatAddress(sectionStart + sectionLength) : null),
      };
    }),
  };
}

function parseHopperUri(uri) {
  const parsed = new URL(uri);
  if (parsed.protocol !== "hopper:") throw new Error(`Unsupported URI protocol: ${parsed.protocol}`);
  return {
    sessionId: parsed.searchParams.get("session_id"),
    path: `/${parsed.hostname}${parsed.pathname}`,
    query: parsed.searchParams,
  };
}
