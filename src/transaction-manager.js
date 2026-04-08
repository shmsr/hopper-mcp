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

function normalizeOperation(operation) {
  const operationId = operation.operationId ?? `op-${crypto.randomUUID()}`;
  if (!operation.kind) throw new Error("Transaction operation requires a kind.");
  if (!operation.addr) throw new Error("Transaction operation requires an addr.");

  return {
    operationId,
    kind: operation.kind,
    addr: formatAddress(operation.addr),
    newValue: operation.newValue ?? operation.value,
    rationale: operation.rationale ?? null,
  };
}

function readCurrentValue(session, operation) {
  const fn = session.functions[operation.addr];
  if (!fn) return undefined;
  if (operation.kind === "rename") return fn.name;
  if (operation.kind === "comment") return fn.comment;
  if (operation.kind === "inline_comment") return fn.inlineComments?.[operation.addr];
  if (operation.kind === "type_patch") return fn.type;
  return undefined;
}

function applyToKnowledgeStore(session, operation) {
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
