import { formatAddress, parseAddress } from "./knowledge-store.js";
import { officialToolPayload } from "./official-hopper-backend.js";

// Library default: no implicit procedure cap. Capping was previously 500,
// which silently truncated mid-analysis on real binaries (cursorsandbox
// alone has thousands of procedures). Callers that need a cap pass one
// explicitly; the tool layer surfaces it as max_procedures so the cap is
// visible in the request rather than buried in a constant.
const DEFAULT_MAX_PROCEDURES = null;

export async function buildOfficialSnapshot(backend, {
  maxProcedures = DEFAULT_MAX_PROCEDURES,
  includeProcedureInfo = true,
  includeAssembly = false,
  includePseudocode = false,
  includeCallGraph = false,
  failOnTruncation = false,
} = {}) {
  const documentName = await officialPayload(backend, "current_document");
  if (!documentName || typeof documentName !== "string") {
    throw new Error("Official Hopper backend did not return a current document name.");
  }

  const procedureNames = await officialPayload(backend, "list_procedures");
  if (!procedureNames || typeof procedureNames !== "object" || Array.isArray(procedureNames)) {
    throw new Error("Official Hopper backend did not return a procedure index for the current document.");
  }

  const [segments, procedureSizes, strings, names, bookmarks, currentAddress, currentProcedureName] = await Promise.all([
    optionalOfficialPayload(backend, "list_segments", {}, []),
    optionalOfficialPayload(backend, "list_procedure_size", {}, {}),
    optionalOfficialPayload(backend, "list_strings", {}, {}),
    optionalOfficialPayload(backend, "list_names", {}, {}),
    optionalOfficialPayload(backend, "list_bookmarks", {}, []),
    optionalOfficialPayload(backend, "current_address", {}, null),
    optionalOfficialPayload(backend, "current_procedure", {}, null),
  ]);

  const procedureEntries = Object.entries(procedureNames ?? {}).sort(([left], [right]) => (parseAddress(left) ?? 0) - (parseAddress(right) ?? 0));
  const procedureLimit = normalizeLimit(maxProcedures);
  const selectedProcedures = procedureLimit ? procedureEntries.slice(0, procedureLimit) : procedureEntries;
  const truncated = {
    procedures: Boolean(procedureLimit && procedureEntries.length > selectedProcedures.length),
  };

  if (truncated.procedures && failOnTruncation) {
    throw new Error(`Official Hopper snapshot would truncate procedures: ${selectedProcedures.length}/${procedureEntries.length}. Increase max_procedures or set fail_on_truncation=false.`);
  }

  const nameToAddr = new Map(procedureEntries.map(([addr, name]) => [String(name), formatAddress(addr)]));
  const functions = [];

  for (const [addr, name] of selectedProcedures) {
    const normalizedAddr = formatAddress(addr);
    const sizeInfo = procedureSizes?.[addr] ?? procedureSizes?.[normalizedAddr] ?? {};
    const info = includeProcedureInfo
      ? await optionalOfficialPayload(backend, "procedure_info", { procedure: normalizedAddr }, null)
      : null;
    const assembly = includeAssembly
      ? await optionalOfficialPayload(backend, "procedure_assembly", { procedure: normalizedAddr }, null)
      : null;
    const pseudocode = includePseudocode
      ? await optionalOfficialPayload(backend, "procedure_pseudo_code", { procedure: normalizedAddr }, null)
      : null;
    const callers = includeCallGraph
      ? normalizeProcedureRefs(await optionalOfficialPayload(backend, "procedure_callers", { procedure: normalizedAddr }, []), nameToAddr)
      : [];
    const callees = includeCallGraph
      ? normalizeProcedureRefs(await optionalOfficialPayload(backend, "procedure_callees", { procedure: normalizedAddr }, []), nameToAddr)
      : [];

    functions.push({
      addr: normalizedAddr,
      name: info?.name ?? name ?? null,
      size: info?.length ?? sizeInfo?.size ?? null,
      signature: info?.signature ?? null,
      locals: info?.locals ?? [],
      callers,
      callees,
      basicBlockCount: info?.basicblock_count ?? sizeInfo?.basicblock_count ?? 0,
      basicBlocks: normalizeBasicBlocks(info?.basicblocks ?? []),
      assembly: typeof assembly === "string" ? assembly : null,
      pseudocode: typeof pseudocode === "string" ? pseudocode : null,
      confidence: 0.85,
      source: "official-hopper-mcp",
    });
  }

  const sessionId = `official-${safeId(documentName)}`;
  const currentProcedure = nameToAddr.get(String(currentProcedureName)) ?? (parseAddress(currentProcedureName) === null ? null : formatAddress(currentProcedureName));

  return {
    sessionId,
    binaryId: `official-${safeId(documentName)}`,
    binary: {
      name: documentName,
      format: "Hopper official MCP document",
      arch: null,
      segments: normalizeSegments(segments),
    },
    capabilities: {
      officialApi: true,
      privateApi: false,
      dynamicDebugger: false,
      officialBackend: true,
      officialSnapshot: {
        source: "official-hopper-mcp",
        document: documentName,
        totals: {
          procedures: procedureEntries.length,
          strings: Object.keys(strings ?? {}).length,
          names: Object.keys(names ?? {}).length,
          bookmarks: Array.isArray(bookmarks) ? bookmarks.length : 0,
        },
        exported: {
          procedures: functions.length,
          strings: Object.keys(strings ?? {}).length,
          names: Object.keys(names ?? {}).length,
          bookmarks: Array.isArray(bookmarks) ? bookmarks.length : 0,
        },
        truncated,
        options: {
          maxProcedures: procedureLimit,
          includeProcedureInfo,
          includeAssembly,
          includePseudocode,
          includeCallGraph,
        },
      },
    },
    functions,
    strings: objectToAddressItems(strings, "value"),
    names: objectToAddressItems(names, "name"),
    bookmarks: normalizeBookmarks(bookmarks),
    comments: [],
    inlineComments: [],
    cursor: {
      address: parseAddress(currentAddress) === null ? null : formatAddress(currentAddress),
      procedure: currentProcedure,
      procedureName: currentProcedureName ?? null,
      selection: [],
    },
    imports: [],
    exports: [],
    objcClasses: [],
    swiftSymbols: [],
  };
}

async function officialPayload(backend, name, args = {}) {
  return officialToolPayload(await backend.callTool(name, args));
}

async function optionalOfficialPayload(backend, name, args, fallback) {
  try {
    return await officialPayload(backend, name, args);
  } catch {
    return fallback;
  }
}

function normalizeLimit(value) {
  if (value === null || value === undefined) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
}

function normalizeSegments(segments) {
  if (!Array.isArray(segments)) return [];
  return segments.map((segment) => ({
    ...segment,
    start: segment.start ? formatAddress(segment.start) : segment.start,
    end: segment.end ? formatAddress(segment.end) : segment.end,
    sections: Array.isArray(segment.sections)
      ? segment.sections.map((section) => ({
        ...section,
        start: section.start ? formatAddress(section.start) : section.start,
        end: section.end ? formatAddress(section.end) : section.end,
      }))
      : [],
  }));
}

function normalizeBasicBlocks(blocks) {
  if (!Array.isArray(blocks)) return [];
  return blocks.map((block) => ({
    addr: block.from ? formatAddress(block.from) : block.addr ? formatAddress(block.addr) : null,
    from: block.from ? formatAddress(block.from) : null,
    to: block.to ? formatAddress(block.to) : null,
  }));
}

function normalizeProcedureRefs(refs, nameToAddr) {
  if (!Array.isArray(refs)) return [];
  return refs
    .map((ref) => {
      if (parseAddress(ref) !== null) return formatAddress(ref);
      return nameToAddr.get(String(ref)) ?? null;
    })
    .filter(Boolean);
}

function objectToAddressItems(object, field) {
  if (!object || typeof object !== "object" || Array.isArray(object)) return [];
  return Object.entries(object)
    .filter(([addr]) => parseAddress(addr) !== null)
    .map(([addr, value]) => ({ addr: formatAddress(addr), [field]: value }));
}

function normalizeBookmarks(bookmarks) {
  if (!Array.isArray(bookmarks)) return [];
  return bookmarks.map((bookmark) => {
    if (typeof bookmark === "string") return { addr: formatAddress(bookmark), name: null };
    const rawAddress = bookmark.addr ?? bookmark.address;
    return {
      ...bookmark,
      addr: rawAddress ? formatAddress(rawAddress) : rawAddress,
    };
  });
}

function safeId(value) {
  return String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "document";
}
