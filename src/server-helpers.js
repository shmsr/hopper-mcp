// Tool body helpers extracted from the original monolithic server. Each helper
// takes the store explicitly so the unit can be reused outside the SDK
// registrations (e.g. tests, scripts). RPC errors use code -32602 so they
// surface as InvalidParams when an MCP client supplies bad input.

import { formatAddress, parseAddress } from "./knowledge-store.js";

export function rpcError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export function listProcedures(store, sessionId, { maxResults } = {}) {
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

export function isMeaningfullyNamedProcedure(fn) {
  const name = String(fn?.name ?? "");
  return Boolean(name) && !name.startsWith("sub_");
}

export function defaultProcedureQuery(store, procedure, sessionId) {
  if (procedure) return procedure;
  const session = store.getSession(sessionId);
  if (session.cursor?.procedure) return session.cursor.procedure;
  if (session.cursor?.address) return session.cursor.address;
  throw rpcError(-32602, "No procedure supplied and no current procedure was captured in the snapshot.");
}

export function defaultAddressQuery(store, address, sessionId) {
  if (address) return address;
  const session = store.getSession(sessionId);
  if (session.cursor?.address) return session.cursor.address;
  throw rpcError(-32602, "No address supplied and no current address was captured in the snapshot.");
}

// Find the function whose body contains `address`, if any. We require a
// known size (deep-mode discovery sets it; skeleton imports do not) so we
// never silently invent a containing function from a zero-length record.
export function findContainingFunction(session, address) {
  if (address === null || Number.isNaN(address)) return null;
  let best = null;
  for (const fn of Object.values(session.functions ?? {})) {
    const start = parseAddress(fn.addr);
    const size = Number(fn.size ?? 0);
    if (start === null || size <= 0) continue;
    if (address < start || address >= start + size) continue;
    if (!best || size < Number(best.size ?? 0)) best = fn;
  }
  return best;
}

// Numeric queries must NEVER fall through to substring-name matching.
// Address digits collide constantly (every "0x100..." prefix matches),
// so a query like 0x100079808 used to silently return some unrelated
// function whose addr/name happened to share digits. Refusing instead
// pushes the user toward containing_function or re-ingest with deep=true.
export function resolveProcedure(store, query, sessionId) {
  const session = store.getSession(sessionId);
  const address = parseAddress(query);
  if (address !== null && !Number.isNaN(address)) {
    const normalized = formatAddress(address);
    const exact = session.functions[normalized];
    if (exact) return exact;
    const containing = findContainingFunction(session, address);
    if (containing) return containing;
    throw rpcError(
      -32602,
      `Address ${normalized} is not the entrypoint of any known function and is not contained in any known function body. ` +
        `Use 'containing_function' to query for the covering function (sizes are populated only by deep-mode imports), ` +
        `or re-ingest with deep=true / via Hopper to populate function ranges.`,
    );
  }

  const lower = String(query).toLowerCase();
  const matches = Object.values(session.functions ?? {}).filter((fn) => {
    const fields = [fn.name, fn.signature].filter(Boolean).map((value) => String(value).toLowerCase());
    return fields.some((field) => field === lower || field.includes(lower));
  });
  // Bare "Unknown procedure: foo" gave the user no next step. The address
  // branch above already nudges toward containing_function; mirror that
  // helpfulness for name misses by pointing at resolve() (substring + name
  // index) and search({kind:'names'|'procedures'}) (regex), which is how
  // callers find the right name when they only know a fragment.
  if (!matches.length) {
    throw rpcError(
      -32602,
      `Unknown procedure: ${query}. Try \`resolve\` for a substring match against names/strings/imports, ` +
        `or \`search({kind:'names'|'procedures', pattern: ...})\` for regex.`,
    );
  }
  return matches.sort((a, b) => scoreProcedureNameMatch(b, lower) - scoreProcedureNameMatch(a, lower))[0];
}

function scoreProcedureNameMatch(fn, lower) {
  const name = String(fn.name ?? "").toLowerCase();
  if (name === lower) return 3;
  if (name.startsWith(lower)) return 2;
  if (name.includes(lower)) return 1;
  return 0;
}


export function officialProcedureInfo(fn) {
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

export function assemblyLines(fn) {
  if (fn.assembly) return String(fn.assembly).split("\n").filter(Boolean);
  return (fn.basicBlocks ?? []).flatMap((block) =>
    (block.instructions ?? []).map((instruction) => `${instruction.addr}: ${instruction.text ?? ""}`.trim()),
  );
}

export function snapshotXrefs(store, address, sessionId) {
  const session = store.getSession(sessionId);
  const target = formatAddress(address);
  const refs = [];

  // The deep importer canonicalizes target.callers to entrypoints (via
  // containingRange-style resolution may store callees as raw
  // edge.to addresses. The scan loop below would only find a match if some
  // function's callees list contains target verbatim — which is unreliable
  // when call sites land mid-function. Pulling target.callers directly is
  // the authoritative inbound list and keeps `xrefs` consistent with what
  // `procedure({field:"callers"})` reports for the same address.
  const targetFn = session.functions?.[target];
  if (Array.isArray(targetFn?.callers)) refs.push(...targetFn.callers);

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

export function limitResults(items, maxResults) {
  const limit = Number(maxResults ?? 0);
  if (!limit || limit < 0) return items;
  return items.slice(0, limit);
}

export function objectFromFunctions(functions, mapper) {
  return Object.fromEntries(functions.map((fn) => [fn.addr, mapper(fn)]));
}

export function objectFromAddressItems(items, field) {
  return Object.fromEntries(
    items.filter((item) => item.addr).map((item) => [formatAddress(item.addr), item[field] ?? null]),
  );
}

export function searchStringsOfficial(store, pattern, { caseSensitive, sessionId, maxResults }) {
  const session = store.getSession(sessionId);
  const regex = compileUserRegex(pattern, caseSensitive ? "" : "i");
  return limitResults((session.strings ?? []).filter((item) => regex.test(item.value ?? "")), maxResults);
}

// User-supplied regex patterns can be syntactically invalid (RegExp throws
// SyntaxError), arrive as non-strings, or exceed Node's pattern length. Wrap
// the call so we surface InvalidParams with the offending pattern instead of
// a raw 'Invalid regular expression: /…/i: …' that escapes as an MCP server
// error and looks like a server bug to the host.
export function compileUserRegex(pattern, flags = "") {
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw rpcError(-32602, "Search pattern must be a non-empty string.");
  }
  // Cap pattern length: 256 chars is well above any realistic search pattern
  // and well below the size where pathological patterns become tempting.
  if (pattern.length > 256) {
    throw rpcError(
      -32602,
      `Search pattern is ${pattern.length} chars (cap is 256). Most patterns are <50 chars; this looks like an accidental paste.`,
    );
  }
  // V8's regex engine is a backtracking matcher with no execution-time fence.
  // Patterns like `(a+)+`, `(.*)*`, or `(a|a)+` against ~30 chars of input
  // burn 60+ seconds of CPU in the JSON-RPC loop, which freezes the entire
  // MCP session for the host. Detect the common ReDoS shape — a quantified
  // group whose body contains another unbounded quantifier — and reject it
  // with a clear hint. This is a known-pattern blacklist, not a full safety
  // proof; clever attackers can write equivalent forms with alternation, but
  // typos and pasted log lines won't.
  if (looksLikeCatastrophicRegex(pattern)) {
    throw rpcError(
      -32602,
      `Pattern '${pattern}' has nested unbounded quantifiers (e.g. '(a+)+', '(.*)+'). ` +
        `That shape causes catastrophic backtracking on V8's engine and would freeze the server. ` +
        `Rewrite without the nested quantifier (try '(?:a+)' or 'a+' instead of '(a+)+').`,
    );
  }
  try {
    return new RegExp(pattern, flags);
  } catch (err) {
    throw rpcError(-32602, `Invalid regular expression '${pattern}': ${err?.message ?? err}`);
  }
}

// Detect the canonical ReDoS shape: a parenthesised group ending in an
// unbounded quantifier (+, *, {n,}), where the group's body itself contains
// an unbounded quantifier. This catches `(a+)+`, `(.+)*`, `(a*){2,}`, and
// the wrappers thereof. Strips character classes first so `[a+]+` (a literal
// '+' in a class, then a quantifier on the class) doesn't trip the check.
export function looksLikeCatastrophicRegex(pattern) {
  // Strip character classes — they treat metacharacters literally.
  const noClasses = pattern.replace(/\[(?:\\.|[^\]\\])*\]/g, "X");
  // Find every quantified group `(...)+` `(...)*` `(...){n,}` at the top
  // level and check whether the body itself contains an unbounded quantifier
  // unguarded by a class. We don't try to handle balanced nested parens
  // with full precision — false-positive on a complex ok-pattern is fine
  // (caller rewrites it), false-negative on a catastrophic one is not.
  const quantifiedGroup = /\(([^()]*)\)\s*(?:[*+]|\{\d+,\d*\}|\{,\d+\})/g;
  let m;
  while ((m = quantifiedGroup.exec(noClasses)) !== null) {
    const body = m[1];
    if (/(?:[*+]|\{\d+,\d*\}|\{,\d+\})/.test(body)) return true;
  }
  return false;
}
