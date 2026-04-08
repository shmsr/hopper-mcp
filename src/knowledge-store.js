import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

const EMPTY_STORE = {
  schemaVersion: 1,
  sessions: {},
  snapshots: {},
};

export class KnowledgeStore {
  constructor(path) {
    this.path = path;
    this.state = structuredClone(EMPTY_STORE);
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

  async save() {
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, JSON.stringify(this.state, null, 2) + "\n", "utf8");
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

  async upsertSession(session) {
    const now = new Date().toISOString();
    const sessionId = session.sessionId ?? `session-${crypto.randomUUID()}`;
    const normalized = normalizeSession({
      ...session,
      sessionId,
      createdAt: session.createdAt ?? now,
      updatedAt: now,
    });
    this.state.sessions[sessionId] = normalized;
    this.state.currentSessionId = sessionId;
    await this.save();
    return normalized;
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

  searchStrings(pattern, { semantic = false, sessionId = "current" } = {}) {
    const session = this.getSession(sessionId);
    const regex = new RegExp(pattern, "i");
    const results = session.strings.filter((str) => regex.test(str.value));

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

  getResource(uri) {
    const parsed = parseHopperUri(uri);
    const session = this.getSession(parsed.sessionId ?? "current");

    if (parsed.path === "/session/current") return this.describeSession(session);
    if (parsed.path === "/binary/metadata") return session.binary;
    if (parsed.path === "/binary/imports") return session.imports;
    if (parsed.path === "/binary/exports") return session.exports;
    if (parsed.path === "/binary/strings" || parsed.path === "/strings/index") return session.strings;
    if (parsed.path === "/functions") return Object.values(session.functions).map(publicFunction);
    if (parsed.path === "/objc/classes") return session.objcClasses;
    if (parsed.path === "/swift/symbols") return session.swiftSymbols;
    if (parsed.path === "/transactions/pending") return session.transactions?.pending ?? [];

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

  listResources() {
    const resources = [
      ["hopper://session/current", "Current Hopper session"],
      ["hopper://binary/metadata", "Binary metadata"],
      ["hopper://binary/imports", "Imported symbols"],
      ["hopper://binary/exports", "Exported symbols"],
      ["hopper://binary/strings", "String index"],
      ["hopper://functions", "Function index"],
      ["hopper://objc/classes", "Objective-C classes"],
      ["hopper://swift/symbols", "Swift symbols"],
      ["hopper://transactions/pending", "Pending annotation transactions"],
    ];

    try {
      const session = this.getSession();
      for (const fn of Object.values(session.functions).slice(0, 100)) {
        resources.push([`hopper://function/${fn.addr}`, `Function ${fn.name ?? fn.addr}`]);
        resources.push([`hopper://function/${fn.addr}/evidence`, `Evidence for ${fn.name ?? fn.addr}`]);
      }
    } catch {
      // No loaded session yet. The static resource list is still useful.
    }

    return resources.map(([uri, name]) => ({ uri, name, mimeType: "application/json" }));
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
        objcClasses: session.objcClasses.length,
        swiftSymbols: session.swiftSymbols.length,
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
    imports: session.imports ?? [],
    exports: session.exports ?? [],
    objcClasses: session.objcClasses ?? [],
    swiftSymbols: session.swiftSymbols ?? [],
    transactions: session.transactions ?? { pending: [] },
  };
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

function parseHopperUri(uri) {
  const parsed = new URL(uri);
  if (parsed.protocol !== "hopper:") throw new Error(`Unsupported URI protocol: ${parsed.protocol}`);
  return {
    sessionId: parsed.searchParams.get("session_id"),
    path: `/${parsed.hostname}${parsed.pathname}`,
    query: parsed.searchParams,
  };
}
