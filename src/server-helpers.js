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

export function sessionOrNull(store, sessionId) {
  try {
    return store.getSession(sessionId);
  } catch {
    return null;
  }
}

export function getSessionSegments(store, sessionId) {
  const session = store.getSession(sessionId);
  return session.binary?.segments ?? [];
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

export function resolveProcedure(store, query, sessionId) {
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

export function officialSegment(segment) {
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

export function lookupName(store, address, sessionId) {
  const session = store.getSession(sessionId);
  const target = formatAddress(address);
  const named = (session.names ?? []).find((item) => formatAddress(item.addr) === target);
  if (named) return named;
  const fn = session.functions?.[target];
  return { addr: target, name: fn?.name ?? null, demangled: null };
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
  const regex = new RegExp(pattern, caseSensitive ? "" : "i");
  return limitResults((session.strings ?? []).filter((item) => regex.test(item.value ?? "")), maxResults);
}
