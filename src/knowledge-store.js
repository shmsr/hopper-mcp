import { readFile, writeFile, mkdir, rename, unlink, readdir } from "node:fs/promises";
import { dirname, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { looksLikeCatastrophicRegex } from "./server-helpers.js";

const EMPTY_STORE = {
  schemaVersion: 1,
  sessions: {},
};

const DEFAULT_SESSION_CAP = 16;

// Names cap: Hopper's `list_names` exposes every labeled address — for the
// WhatsApp main executable that's 756,174 entries totalling ~75 MB JSON. Left
// unbounded, the on-disk store hit 222 MB and every save did a synchronous
// JSON.stringify on the whole blob (~1.5 s event-loop stall on Apple silicon),
// which very plausibly tipped the MCP host into "tool unavailable" on the next
// call. 100k is more than enough for normal binaries (Raycast: 0, Cursor: 0,
// even the live ImageCore session is at 113k); operators with deliberately
// massive symbol tables can raise via HOPPER_MCP_MAX_NAMES.
const DEFAULT_MAX_NAMES_PER_SESSION = 100_000;
function getMaxNamesPerSession() {
  const env = Number(process.env.HOPPER_MCP_MAX_NAMES);
  return Number.isFinite(env) && env > 0 ? Math.floor(env) : DEFAULT_MAX_NAMES_PER_SESSION;
}

// Reviver that drops `__proto__` and `constructor.prototype` keys at parse
// time. Without this, a malicious or corrupted on-disk store can pollute
// Object.prototype as soon as we JSON.parse it — every later property lookup
// in the process would inherit attacker-controlled keys. The on-disk store
// is normally produced by us, but it's still user-modifiable JSON, so treat
// it as untrusted input.
function safeJsonReviver(key, value) {
  if (key === "__proto__") return undefined;
  if (key === "prototype" && value && typeof value === "object") return undefined;
  return value;
}

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
    // Tracks whether in-memory state diverges from disk. save()/scheduleSave()
    // set it; _writeStateToDisk clears it just before JSON.stringify (so any
    // mutation racing the write is captured in the next save). flushDurable()
    // uses it to skip the shutdown write when the store is already on disk —
    // that turns a 750ms shutdown (full re-write of a 145 MB store) into a
    // ~10ms exit on read-only-tool batches.
    this._dirty = false;
  }

  async load() {
    try {
      const text = await readFile(this.path, "utf8");
      this.state = JSON.parse(text, safeJsonReviver);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.state = structuredClone(EMPTY_STORE);
      await this.save();
    }
    // Retroactively cap sessions that were upserted before the Round-17a cap
    // existed. Stops a pre-existing 222 MB store from paying full sync-stringify
    // cost on every save forever — once trimmed, the next save shrinks the on-
    // disk file permanently. Round-17b.
    this._retrofitNamesCaps();
    await this._sweepOrphanTmps();
  }

  // Walks every session and applies applyNamesCap; if any session was trimmed,
  // marks the store dirty and schedules a save so the shrunken state lands on
  // disk before the next mutation. Idempotent: a second call after a successful
  // save is a no-op.
  _retrofitNamesCaps() {
    let trimmed = false;
    for (const session of Object.values(this.state.sessions ?? {})) {
      const before = (session.names ?? []).length;
      applyNamesCap(session);
      if ((session.names ?? []).length !== before) trimmed = true;
    }
    if (trimmed) this.scheduleSave();
  }

  // Called once from load() at startup, before the MCP transport accepts
  // requests, so no in-flight _writeStateToDisk can have a tmpfile open at
  // this point. Anything matching `<basename>.<pid>.<ts>.tmp` is from a
  // crashed prior process and safe to remove.
  async _sweepOrphanTmps() {
    const dir = dirname(this.path);
    const base = basename(this.path);
    let entries;
    try { entries = await readdir(dir); } catch { return; }
    const prefix = `${base}.`;
    const suffix = ".tmp";
    for (const name of entries) {
      if (!name.startsWith(prefix) || !name.endsWith(suffix)) continue;
      try {
        await unlink(`${dir}/${name}`);
      } catch (err) {
        try {
          process.stderr.write(`[hopper-mcp] knowledge-store sweep failed for ${name}: ${err?.stack ?? err}\n`);
        } catch {}
      }
    }
  }

  // Durable: resolves once the latest enqueued write has hit disk.
  async save() {
    this._dirty = true;
    return this._enqueueSave();
  }

  // Fire-and-forget. Errors get logged to stderr instead of becoming an
  // unhandledRejection. Use this from hot paths where the response should
  // not block on a 100 MB JSON.stringify + writeFile.
  scheduleSave() {
    this._dirty = true;
    this._enqueueSave().catch((err) => {
      try {
        process.stderr.write(`[hopper-mcp] knowledge-store save error: ${err?.stack ?? err}\n`);
      } catch {}
    });
  }

  // Shutdown-only flush: drain any in-flight writes, then issue exactly one
  // more save IFF the in-memory state has diverged from disk. Read-only tool
  // batches leave _dirty=false the whole time, so this returns near-instantly
  // instead of paying for another full 145 MB write that would just rewrite
  // the same bytes.
  async flushDurable() {
    if (this._savePromise) {
      try { await this._savePromise; } catch {}
    }
    if (this._dirty) {
      return this._enqueueSave();
    }
  }

  // Single-flight serializer: chains writes so concurrent callers cannot
  // race on the same file, and one failure does not poison the queue.
  // Coalesces: if the previously-queued write already captured the latest
  // state, the next one becomes a no-op. Without this, N concurrent
  // annotation saves on a 150 MB store paid N × ~700 ms of redundant sync
  // stringify + writeFile when one was sufficient — same on-disk bytes,
  // N event-loop stalls. _dirty=false is the invariant: cleared at the
  // top of _writeStateToDisk before stringify; set true by save/scheduleSave
  // synchronously, after the mutation that warrants a write.
  _enqueueSave() {
    const next = (this._savePromise ?? Promise.resolve())
      .catch(() => {})
      .then(() => {
        if (!this._dirty) return;
        return this._writeStateToDisk();
      });
    this._savePromise = next;
    return next;
  }

  async _writeStateToDisk() {
    // Clear _dirty BEFORE the synchronous stringify so any mutation that
    // races the in-flight writeFile is correctly observed as "still dirty"
    // for the NEXT save. Mutations between here and stringify can't happen
    // (single-threaded JS, stringify is synchronous), so we always capture a
    // consistent snapshot.
    this._dirty = false;
    await mkdir(dirname(this.path), { recursive: true });
    // Crypto-random suffix instead of pid+ts: predictable tmp paths in a
    // shared dir invite a TOCTOU symlink swap (attacker pre-creates
    // `<store>.<pid>.<approx ts>.tmp` as a symlink to a sensitive file; our
    // writeFile then truncates that target). UUID suffix removes the predict-
    // ability without changing the orphan-sweep glob (`<base>.*.tmp`).
    const tmp = `${this.path}.${randomUUID()}.tmp`;
    const snapshot = JSON.stringify(this.state) + "\n";
    try {
      await writeFile(tmp, snapshot, "utf8");
      await rename(tmp, this.path);
    } catch (err) {
      // Re-mark dirty so the next save retries. Best-effort cleanup so we
      // don't leak tmpfiles on write/rename failure.
      this._dirty = true;
      try { await unlink(tmp); } catch {}
      throw err;
    }
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
    // Apply the names cap AFTER merge: a second ingest can otherwise compose
    // 80k existing + 80k new names → 160k, bypassing the cap that the first
    // ingest enforced. Done in-place since `normalized` is the just-built
    // record about to be stored — no aliasing risk.
    applyNamesCap(normalized);
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

    // Empty/whitespace query used to match everything — String.includes("")
    // is true for every haystack, so resolve("") returned 20 random
    // fingerprint dumps with no signal value. Return empty so the
    // tool-layer can emit a clear "pass an addr/name/string" message.
    if (!q && byAddress === null) return [];

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
    // V8's regex engine has no execution-time fence: an unguarded `(a+)+b`
    // burns 60+ seconds on ~30 chars of input and freezes the JSON-RPC loop.
    // Mirror the guards compileUserRegex applies on every other public regex
    // entry point — length cap, catastrophic-shape blacklist, syntax error
    // wrapping. Plain Errors here become InvalidParams at the tool boundary.
    if (typeof pattern !== "string" || pattern.length === 0) {
      throw new Error("Search pattern must be a non-empty string.");
    }
    if (pattern.length > 256) {
      throw new Error(
        `Search pattern is ${pattern.length} chars (cap is 256). Most patterns are <50 chars; this looks like an accidental paste.`,
      );
    }
    if (looksLikeCatastrophicRegex(pattern)) {
      throw new Error(
        `Pattern '${pattern}' has nested unbounded quantifiers (e.g. '(a+)+', '(.*)+'). ` +
          `That shape causes catastrophic backtracking on V8's engine and would freeze the server. ` +
          `Rewrite without the nested quantifier (try '(?:a+)' or 'a+' instead of '(a+)+').`,
      );
    }
    let regex;
    try {
      regex = new RegExp(pattern, "i");
    } catch (err) {
      throw new Error(`Invalid regular expression '${pattern}': ${err?.message ?? err}`);
    }
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

  // maxNodes bounds BFS payload — known callees ship full fingerprints
  // (simhash + minhash + stringBag), so a hub function at radius 3+ can
  // serialize past the host's 100 KB tool budget. Default 200 fits a
  // typical neighborhood; pass 0 for uncapped (legacy behavior).
  getGraphSlice(seed, { radius = 1, kind = "calls", sessionId = "current", maxNodes = 200 } = {}) {
    const session = this.getSession(sessionId);
    const root = this.getFunction(session, seed);
    const seen = new Set([root.addr]);
    const edges = [];
    const queue = [{ addr: root.addr, depth: 0 }];
    let truncated = false;

    while (queue.length) {
      const current = queue.shift();
      if (current.depth >= radius) continue;
      const fn = this.getFunction(session, current.addr);
      const next = kind === "callers" ? fn.callers ?? [] : fn.callees ?? [];
      for (const target of next) {
        const normalizedTarget = formatAddress(target);
        edges.push(kind === "callers" ? { from: normalizedTarget, to: fn.addr } : { from: fn.addr, to: normalizedTarget });
        if (!seen.has(normalizedTarget)) {
          if (maxNodes && seen.size >= maxNodes) {
            // Frontier cap reached: drop any further node additions but keep
            // emitting edges from the current frontier so the caller sees the
            // shape of what was cut.
            truncated = true;
            continue;
          }
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
      truncated,
      maxNodes,
    };
  }

  // Searches session.transactions.pending only; that array is currently the
  // authoritative store for both open and committed/rolled-back transactions
  // (transaction-manager mutates status in place rather than moving entries).
  // If transactions are ever split into separate buckets, widen this lookup.
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
    // Single-segment id only — rejects empty (`/transactions/`) and nested
    // (`/transactions/abc/operations`) forms so future sub-resources don't get
    // pre-empted as a literal id and so empty-id lookups fail with a clearer
    // error than `No transaction ''...`.
    const txnMatch = parsed.path.match(/^\/transactions\/([^/]+)$/);
    if (txnMatch && txnMatch[1] !== "pending") {
      return this.getTransactionById(session, txnMatch[1]);
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
      // Project a thin binary slice. The full blob can be hundreds of KB
      // (Raycast: 88 dylibs + 13 segments + per-section entropy), and the
      // heavy fields are already exposed via dedicated `hopper://binary/*`
      // resources (libraries→imports/metadata, segments, signing, entropy,
      // capabilities) and the `list` tool. Returning the whole object here
      // blew the per-tool token budget on large Hopper session reads.
      binary: projectBinarySummary(session.binary),
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
      // Surface ingest-time truncation so callers can see when a cap dropped
      // data. Omitted entirely for sessions that fit under the cap to avoid
      // adding noise to the typical describe payload.
      ...(session.truncation ? { truncation: session.truncation } : {}),
      updatedAt: session.updatedAt,
    };
  }

  getFunction(session, addr) {
    const normalized = formatAddress(addr);
    const fn = session.functions[normalized];
    if (!fn) throw new Error(`Unknown function address: ${addr}`);
    return fn;
  }

  // Returns the real function record OR a thin "{addr, known:false}" stub for
  // unknown refs. The stub used to carry a verbose 60-char placeholder summary
  // plus null name/size/summary/confidence/fingerprint fields; on functions
  // with many unresolved callees (Raycast: 59/61 unknown) that ballooned
  // analyze_function_deep + get_graph_slice responses by ~14 KB of constant
  // string repetition. publicFunction detects `known:false` and emits the
  // same thin shape so callers can act on the addr without parsing noise.
  getFunctionIfKnown(session, addr) {
    const normalized = formatAddress(addr);
    return session.functions[normalized] ?? { addr: normalized, known: false };
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
  // maxResults caps the returned entries; 0/null/negative mean uncapped.
  // Object-keyed kinds (procedures/strings/names) are sliced by entry order
  // to preserve their addr→info shape.
  listByKind(sessionId, kind, detail = "brief", { maxResults = 0 } = {}) {
    const session = this.getSession(sessionId);
    const limit = Number(maxResults ?? 0);
    const capArr = (arr) => (limit > 0 ? arr.slice(0, limit) : arr);
    const capObj = (obj) => (limit > 0 ? Object.fromEntries(Object.entries(obj).slice(0, limit)) : obj);
    switch (kind) {
      case "procedures": return capObj(this._listProcedures(session, detail));
      case "strings":    return capObj(this._listStrings(session));
      case "names":      return capObj(this._listNames(session));
      case "segments":   return capArr((session.binary?.segments ?? []).map(projectSegment));
      case "bookmarks":  return capArr(session.bookmarks ?? []);
      case "imports":    return capArr(session.imports ?? []);
      case "exports":    return capArr(session.exports ?? []);
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

// Bound the names array post-merge. Mutates session in place; idempotent below
// the cap. Records the cut on session.truncation.names so describeSession can
// surface it without callers re-deriving it from counts.
function applyNamesCap(session) {
  const cap = getMaxNamesPerSession();
  const all = session.names ?? [];
  if (all.length <= cap) return;
  const dropped = all.length - cap;
  session.names = all.slice(0, cap);
  session.truncation = {
    ...(session.truncation ?? {}),
    names: { kept: cap, dropped, cap, original: all.length },
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

// Address overflow guard: anything beyond MAX_SAFE_INTEGER rounds when
// stored as a JS Number, so 0xdeadbeefdeadbeef silently mutates to
// 0xdeadbeefdeadc000 by the time it round-trips through formatAddress.
// Real Mach-O addresses on macOS sit comfortably below 2^48 so this
// never trips on production binaries, but the silent corruption hit
// during fuzzy probing — better to fail loudly than corrupt a queue
// addr or a transaction commit. Throws so callers like queue() and
// resolveProcedure surface the failure as InvalidParams instead of
// proceeding with a mangled value.
export function parseAddress(value) {
  if (typeof value === "number") return value;
  if (!value) return null;
  const text = String(value);
  let parsed;
  if (/^0x[0-9a-f]+$/i.test(text)) parsed = Number.parseInt(text.slice(2), 16);
  else if (/^[0-9]+$/.test(text)) parsed = Number.parseInt(text, 10);
  else return null;
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(
      `Address ${text} exceeds Number.MAX_SAFE_INTEGER and cannot be represented without precision loss. ` +
        `Pass an address below 0x20000000000000 (2^53) — real Mach-O VM addresses fit; this typically only triggers on synthetic/fuzz addrs.`,
    );
  }
  return parsed;
}

export function formatAddress(value) {
  const parsed = parseAddress(value);
  if (parsed === null || Number.isNaN(parsed)) return String(value);
  return `0x${parsed.toString(16)}`;
}

function publicFunction(fn) {
  // Thin shape for unknown refs surfaced by getFunctionIfKnown — drops the
  // null-padded {name,size,summary,confidence,fingerprint} fields that used
  // to bloat analyze_function_deep / get_graph_slice when callees lived
  // outside the imported slice. Callers detect via `known === false`.
  if (fn?.known === false) return { addr: fn.addr, known: false };
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

// Identifying metadata only — the heavy fields (libraries, segments,
// sectionEntropy, capabilities, signing) belong on dedicated resources.
// Counts are surfaced separately so callers can decide whether to fetch
// the heavy slices.
function projectBinarySummary(binary) {
  if (!binary || typeof binary !== "object") return binary ?? null;
  return {
    name: binary.name ?? null,
    path: binary.path ?? null,
    format: binary.format ?? null,
    arch: binary.arch ?? null,
    requestedArch: binary.requestedArch ?? null,
    availableArchs: binary.availableArchs ?? null,
    fileInfo: binary.fileInfo ?? null,
    imphash: binary.imphash ?? null,
    counts: {
      libraries: Array.isArray(binary.libraries) ? binary.libraries.length : 0,
      segments: Array.isArray(binary.segments) ? binary.segments.length : 0,
      sectionEntropyEntries: Array.isArray(binary.sectionEntropy) ? binary.sectionEntropy.length : 0,
    },
  };
}

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
