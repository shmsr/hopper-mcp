import { formatAddress } from "./knowledge-store.js";

export class TransactionManager {
  constructor(store) {
    this.store = store;
  }

  async begin({ sessionId = "current", name = "annotation transaction", rationale = null } = {}) {
    const session = this.store.getSession(sessionId);
    const id = `txn-${crypto.randomUUID()}`;
    session.transactions.pending.push({
      id,
      name,
      rationale,
      status: "open",
      queuedAt: new Date().toISOString(),
      operations: [],
    });
    await this.store.save();
    return this.preview({ transactionId: id, sessionId });
  }

  async queue(operation, { sessionId = "current" } = {}) {
    const session = this.store.getSession(sessionId);
    const txn = this.currentTransaction(session, operation.transactionId);
    const normalized = normalizeOperation(operation);
    txn.operations.push({
      ...normalized,
      queuedAt: new Date().toISOString(),
      oldValue: readCurrentValue(session, normalized),
    });
    await this.store.save();
    return this.preview({ transactionId: txn.id, sessionId });
  }

  preview({ transactionId, sessionId = "current" } = {}) {
    const session = this.store.getSession(sessionId);
    const txn = this.currentTransaction(session, transactionId);
    return {
      transactionId: txn.id,
      status: txn.status,
      name: txn.name,
      rationale: txn.rationale,
      operations: txn.operations,
      warnings: txn.operations
        .filter((op) => op.oldValue === undefined)
        .map((op) => ({ operationId: op.operationId, message: "Target does not currently have a known value in the knowledge store." })),
    };
  }

  async commit({ transactionId, sessionId = "current", adapter = null } = {}) {
    const session = this.store.getSession(sessionId);
    const txn = this.currentTransaction(session, transactionId);
    const committedAt = new Date().toISOString();
    const adapterResult = adapter
      ? await adapter.applyTransaction(session, txn)
      : { appliedToHopper: false, reason: "No in-process Hopper adapter is connected yet." };

    for (const operation of txn.operations) {
      applyToKnowledgeStore(session, operation);
    }

    txn.status = "committed";
    txn.committedAt = committedAt;
    txn.adapterResult = adapterResult;

    await this.store.save();
    return {
      transactionId: txn.id,
      status: txn.status,
      committedAt,
      adapterResult: txn.adapterResult,
      operations: txn.operations,
    };
  }

  async rollback({ transactionId, sessionId = "current" } = {}) {
    const session = this.store.getSession(sessionId);
    const txn = this.currentTransaction(session, transactionId);
    txn.status = "rolled_back";
    txn.rolledBackAt = new Date().toISOString();
    await this.store.save();
    return { transactionId: txn.id, status: txn.status };
  }

  currentTransaction(session, transactionId) {
    const pending = session.transactions.pending;
    const txn = transactionId
      ? pending.find((candidate) => candidate.id === transactionId)
      : [...pending].reverse().find((candidate) => candidate.status === "open");
    if (!txn) throw new Error("No open transaction. Call begin_transaction first.");
    if (txn.status !== "open") throw new Error(`Transaction ${txn.id} is ${txn.status}, not open.`);
    return txn;
  }
}

const ADDRESSLESS_KINDS = new Set(["rename_batch", "hypothesis_create", "hypothesis_link", "hypothesis_status"]);

function normalizeOperation(operation) {
  const operationId = operation.operationId ?? `op-${crypto.randomUUID()}`;
  if (!operation.kind) throw new Error("Transaction operation requires a kind.");
  if (!ADDRESSLESS_KINDS.has(operation.kind) && !operation.addr) {
    throw new Error("Transaction operation requires an addr.");
  }

  const normalized = {
    operationId,
    kind: operation.kind,
    addr: operation.addr ? formatAddress(operation.addr) : null,
    newValue: operation.newValue ?? operation.value ?? null,
    rationale: operation.rationale ?? null,
  };
  if (operation.kind === "rename_batch") {
    if (!operation.mapping || typeof operation.mapping !== "object") {
      throw new Error("rename_batch requires a mapping of {addr: newName}.");
    }
    normalized.mapping = Object.fromEntries(
      Object.entries(operation.mapping).map(([addr, name]) => [formatAddress(addr), name]),
    );
  }
  if (operation.kind === "tag" || operation.kind === "untag") {
    const tags = Array.isArray(operation.tags) ? operation.tags : operation.tag ? [operation.tag] : [];
    if (!tags.length) throw new Error(`${operation.kind} requires tag or tags.`);
    normalized.tags = tags.map(String);
  }
  if (operation.kind === "hypothesis_create") {
    if (!operation.topic) throw new Error("hypothesis_create requires a topic.");
    normalized.hypothesisId = operation.hypothesisId ?? `hyp-${crypto.randomUUID()}`;
    normalized.topic = String(operation.topic);
    normalized.claim = operation.claim ?? null;
    normalized.status = operation.status ?? "open";
  }
  if (operation.kind === "hypothesis_link") {
    if (!operation.hypothesisId) throw new Error("hypothesis_link requires hypothesisId.");
    normalized.hypothesisId = String(operation.hypothesisId);
    normalized.evidence = operation.evidence ?? operation.note ?? null;
    normalized.evidenceKind = operation.evidenceKind ?? "address";
  }
  if (operation.kind === "hypothesis_status") {
    if (!operation.hypothesisId) throw new Error("hypothesis_status requires hypothesisId.");
    if (!operation.status) throw new Error("hypothesis_status requires status.");
    normalized.hypothesisId = String(operation.hypothesisId);
    normalized.status = String(operation.status);
  }
  return normalized;
}

function readCurrentValue(session, operation) {
  if (operation.kind === "rename_batch") {
    const out = {};
    for (const [addr, _name] of Object.entries(operation.mapping ?? {})) {
      out[addr] = session.functions[addr]?.name ?? null;
    }
    return out;
  }
  if (operation.kind === "tag" || operation.kind === "untag") {
    return [...(session.tags?.[operation.addr] ?? [])];
  }
  if (operation.kind === "hypothesis_create") return null;
  if (operation.kind === "hypothesis_link") {
    const hyp = (session.hypotheses ?? []).find((h) => h.id === operation.hypothesisId);
    return hyp ? [...(hyp.evidence ?? [])] : undefined;
  }
  if (operation.kind === "hypothesis_status") {
    const hyp = (session.hypotheses ?? []).find((h) => h.id === operation.hypothesisId);
    return hyp ? hyp.status : undefined;
  }
  const fn = session.functions[operation.addr];
  if (!fn) return undefined;
  if (operation.kind === "rename") return fn.name;
  if (operation.kind === "comment") return fn.comment;
  if (operation.kind === "inline_comment") return fn.inlineComments?.[operation.addr];
  if (operation.kind === "type_patch") return fn.type;
  return undefined;
}

function applyToKnowledgeStore(session, operation) {
  if (operation.kind === "rename_batch") {
    for (const [addr, name] of Object.entries(operation.mapping ?? {})) {
      const fn = session.functions[addr];
      if (fn) fn.name = name;
    }
    return;
  }
  if (operation.kind === "tag") {
    session.tags ??= {};
    const list = new Set(session.tags[operation.addr] ?? []);
    for (const tag of operation.tags) list.add(tag);
    session.tags[operation.addr] = [...list].sort();
    return;
  }
  if (operation.kind === "untag") {
    if (!session.tags?.[operation.addr]) return;
    const remove = new Set(operation.tags);
    session.tags[operation.addr] = session.tags[operation.addr].filter((tag) => !remove.has(tag));
    if (!session.tags[operation.addr].length) delete session.tags[operation.addr];
    return;
  }
  if (operation.kind === "hypothesis_create") {
    session.hypotheses ??= [];
    session.hypotheses.push({
      id: operation.hypothesisId,
      topic: operation.topic,
      claim: operation.claim,
      status: operation.status ?? "open",
      evidence: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    return;
  }
  if (operation.kind === "hypothesis_link") {
    const hyp = (session.hypotheses ??= []).find((h) => h.id === operation.hypothesisId);
    if (!hyp) throw new Error(`Unknown hypothesis: ${operation.hypothesisId}`);
    hyp.evidence ??= [];
    hyp.evidence.push({
      kind: operation.evidenceKind,
      addr: operation.addr,
      note: operation.evidence,
      linkedAt: new Date().toISOString(),
    });
    hyp.updatedAt = new Date().toISOString();
    return;
  }
  if (operation.kind === "hypothesis_status") {
    const hyp = (session.hypotheses ??= []).find((h) => h.id === operation.hypothesisId);
    if (!hyp) throw new Error(`Unknown hypothesis: ${operation.hypothesisId}`);
    hyp.status = operation.status;
    hyp.updatedAt = new Date().toISOString();
    return;
  }
  const fn = session.functions[operation.addr];
  if (!fn) return;
  if (operation.kind === "rename") fn.name = operation.newValue;
  if (operation.kind === "comment") fn.comment = operation.newValue;
  if (operation.kind === "inline_comment") {
    fn.inlineComments ??= {};
    fn.inlineComments[operation.addr] = operation.newValue;
  }
  if (operation.kind === "type_patch") fn.type = operation.newValue;
}
