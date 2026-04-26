// Pure helpers extracted from server-tools.js so the registration file
// stays under the plan's 1100-line ceiling. Each function takes the store
// (or whatever it needs) explicitly and is independent of the SDK.

import { searchMachOStrings } from "./macho-importer.js";
import { buildFunctionFingerprint, functionSimilarity } from "./research-tools.js";
import { rpcError } from "./server-helpers.js";

export function buildQueueOperation(args) {
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

export function buildHypothesisOperation(args) {
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

export function findSimilarFunctions(store, { sessionId, addr, targetSessionId, minSimilarity, maxResults }) {
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

export async function resolveFromBinaryStrings(store, query, { sessionId, maxResults }) {
  const strings = await searchSessionBinaryStrings(store, query, { semantic: false, sessionId, maxResults });
  return strings.map((item) => ({ kind: "string", score: 0.45, item }));
}

export async function searchSessionBinaryStrings(store, pattern, { semantic, sessionId, maxResults }) {
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
