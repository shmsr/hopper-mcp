import { formatAddress } from "./knowledge-store.js";

export class TransactionManager {
  constructor(store) {
    this.store = store;
  }

  async begin({ sessionId = "current", name = "annotation transaction", rationale = null } = {}) {
    const session = this.store.getSession(sessionId);
    // Every other prose path (queue.rationale, comments, hypothesis topic /
    // claim / evidence) routes through validateProseValue. begin's `name`
    // and `rationale` were the lone gap — passed straight through with no
    // length cap, NUL byte rejection, or type check. A 5MB name pollutes
    // hopper://transactions/pending on every read and bloats the per-save
    // stringify; a NUL byte breaks log pipelines and on-disk store cat.
    validateProseValue(name, "begin_transaction", { field: "name", maxLen: 4096 });
    validateProseValue(rationale, "begin_transaction", { field: "rationale", maxLen: 4096 });
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
    // Flip status synchronously BEFORE any await so a concurrent commit or
    // rollback that re-enters currentTransaction sees status !== "open" and
    // refuses. Without this, two awaited callers could both pass the
    // "open" check, then both apply the same operations.
    txn.status = "committing";
    const committedAt = new Date().toISOString();
    try {
      // Apply local first: if the adapter call later fails, we still have a
      // coherent local state with the user's annotations. Inverting the order
      // (adapter then local) leaves the caller's Hopper UI mutated while the
      // snapshot rolls back, which is the worse of the two failure modes.
      for (const operation of txn.operations) {
        applyToKnowledgeStore(session, operation);
      }
      const adapterResult = adapter
        ? await adapter.applyTransaction(session, txn)
        : { appliedToHopper: false, reason: "No in-process Hopper adapter is connected yet." };
      txn.status = "committed";
      txn.committedAt = committedAt;
      txn.adapterResult = adapterResult;
      // Bump session.updatedAt so pruneStaleSessions ranks by actual user
      // activity instead of just initial-ingest time. Without this, a session
      // the user has been heavily annotating for hours still looks "old" the
      // next time eviction runs, and the 17th ingest can wipe it.
      session.updatedAt = committedAt;
    } catch (err) {
      // Mark failed so the operator can inspect and decide; never bounce back
      // to "open" because applyToKnowledgeStore may have partially mutated
      // session state, and a retry would double-apply the prefix that did
      // succeed.
      txn.status = "failed";
      txn.failedAt = new Date().toISOString();
      txn.error = err?.message ?? String(err);
      await this.store.save();
      throw err;
    }

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
    // Same synchronous flip rationale as commit: prevent commit+rollback
    // races where both pass the open check and both succeed.
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
    if (!txn) {
      // Distinguish "no id passed at all" from "id passed but unknown" so the
      // caller knows which knob to turn — typo in transactionId vs. forgot to
      // call begin_transaction.
      if (transactionId) {
        throw new Error(
          `Transaction '${transactionId}' not found in session '${session.sessionId}'. ` +
            `Check the id from begin_transaction's response, or omit transaction_id to target the latest open one.`,
        );
      }
      throw new Error(
        "No open transaction. Call begin_transaction first — every queue/hypothesis/commit/rollback op runs inside a transaction.",
      );
    }
    if (txn.status !== "open") throw new Error(`Transaction ${txn.id} is ${txn.status}, not open.`);
    return txn;
  }
}

const ADDRESSLESS_KINDS = new Set(["rename_batch", "hypothesis_create", "hypothesis_link", "hypothesis_status"]);

// Label validation shared by single-rename, each entry of a rename_batch,
// and tag/untag entries. All three used to skip per-value validation, so a
// single bad string (empty, embedded whitespace, NUL, etc.) corrupted the
// symbol table or tag set on commit. The contract: non-empty, ≤maxLen chars,
// no surrounding/embedded whitespace, no C0/DEL controls. Tag callers pass
// {field:'tag', maxLen:256, noun:'tag'} so error messages point at the right
// key and convey realistic length expectations.
function validateRenameValue(
  value,
  kindLabel = "rename",
  { addr = null, field = "value", maxLen = 1024, noun = "symbol name" } = {},
) {
  const where = addr ? ` (addr=${addr})` : "";
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(
      `${kindLabel} requires a non-empty ${field}${where} (got ${JSON.stringify(value)}). ` +
        `Pass the desired ${noun} in '${field}'.`,
    );
  }
  if (value.length > maxLen) {
    throw new Error(
      `${kindLabel} ${field} is ${value.length} chars${where} (cap is ${maxLen}). ` +
        `This looks like an accidentally pasted blob.`,
    );
  }
  if (value !== value.trim()) {
    throw new Error(
      `${kindLabel} ${field} has leading/trailing whitespace${where} (${JSON.stringify(value)}). Trim it before queuing.`,
    );
  }
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f\s]/.test(value)) {
    throw new Error(
      `${kindLabel} ${field} ${JSON.stringify(value)}${where} contains whitespace or a control character. ` +
        `Use _ instead of spaces; Hopper ${noun}s can't safely carry tabs/newlines/NULs.`,
    );
  }
}

// Prose validator for free-form text fields (topics, claims, evidence,
// rationale, comments, type strings). Unlike validateRenameValue, this
// allows internal whitespace including \t \n \r — those are common in prose.
// What it rejects: NUL/DEL and other non-whitespace C0 controls (these break
// log pipelines, JSON streaming, and every editor's display), pathological
// lengths (50KB stack-trace pastes silently committed), and — when required
// — empty/whitespace-only values (typos that previously committed empty
// topics/claims).
function validateProseValue(
  value,
  kindLabel,
  { field = "value", maxLen = 4096, required = false } = {},
) {
  if (value == null) {
    if (required) {
      throw new Error(
        `${kindLabel} requires a ${field} (got ${JSON.stringify(value)}). ` +
          `Pass the desired text in '${field}'.`,
      );
    }
    return;
  }
  if (typeof value !== "string") {
    throw new Error(
      `${kindLabel} ${field} must be a string (got ${typeof value}).`,
    );
  }
  if (required && !value.trim()) {
    throw new Error(
      `${kindLabel} requires a non-empty ${field} (got ${JSON.stringify(value)}). ` +
        `Whitespace-only values are almost always typos.`,
    );
  }
  if (value.length > maxLen) {
    throw new Error(
      `${kindLabel} ${field} is ${value.length} chars (cap is ${maxLen}). ` +
        `Long pastes (logs, pseudocode dumps) clog the knowledge store; trim or summarise before queuing.`,
    );
  }
  // Allow prose whitespace (\t=0x09, \n=0x0a, \r=0x0d) but ban the rest of
  // C0 plus DEL — those break log/JSON pipelines and crash some viewers.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) {
    throw new Error(
      `${kindLabel} ${field} contains a non-whitespace control character (NUL, DEL, BEL, etc.). ` +
        `Strip these — they break log/JSON pipelines and crash some viewers.`,
    );
  }
}

function normalizeOperation(operation) {
  const operationId = operation.operationId ?? `op-${crypto.randomUUID()}`;
  if (!operation.kind) throw new Error("Transaction operation requires a kind.");
  if (!ADDRESSLESS_KINDS.has(operation.kind) && !operation.addr) {
    throw new Error("Transaction operation requires an addr.");
  }

  const newValue = operation.newValue ?? operation.value ?? null;
  // Empty/whitespace newValue used to be silently accepted for rename ops,
  // queueing a destructive overwrite to "" — typos and accidental empty
  // args quietly corrupted the symbol table when committed. Reject early so
  // callers either fix the typo or use a clearer, named clear-op when
  // we add one. Other value-bearing kinds (comment, inline_comment,
  // type_patch) can legitimately want to clear text, so leave them alone —
  // but they still get a size cap + NUL/DEL check via validateProseValue
  // below so a 50KB stack-trace paste doesn't silently corrupt the store.
  if (operation.kind === "rename") {
    validateRenameValue(newValue, "rename");
  } else if (operation.kind === "comment" || operation.kind === "inline_comment") {
    validateProseValue(newValue, operation.kind, { field: "value", maxLen: 16384 });
  } else if (operation.kind === "type_patch") {
    validateProseValue(newValue, "type_patch", { field: "value", maxLen: 1024 });
  }

  // rationale is operator-supplied prose attached to almost every op kind.
  // Pre-fix it was passed through unchanged: a multi-MB rationale string
  // would commit straight into the journal, and embedded NULs would corrupt
  // any consumer that streams JSONL.
  validateProseValue(operation.rationale, operation.kind ?? "operation", {
    field: "rationale",
    maxLen: 4096,
  });

  const normalized = {
    operationId,
    kind: operation.kind,
    addr: operation.addr ? formatAddress(operation.addr) : null,
    newValue,
    rationale: operation.rationale ?? null,
  };
  if (operation.kind === "rename_batch") {
    if (!operation.mapping || typeof operation.mapping !== "object") {
      throw new Error("rename_batch requires a mapping of {addr: newName}.");
    }
    const entries = Object.entries(operation.mapping);
    if (!entries.length) {
      throw new Error("rename_batch mapping is empty; queue at least one {addr: newName} entry.");
    }
    // Each entry must satisfy the same rules as a single rename — pre-fix
    // rename_batch let any value through (empty, embedded space, NUL, etc.)
    // and committed straight to fn.name, corrupting the symbol table.
    normalized.mapping = Object.fromEntries(
      entries.map(([addr, name]) => {
        const formattedAddr = formatAddress(addr);
        validateRenameValue(name, "rename_batch", { addr: formattedAddr });
        return [formattedAddr, name];
      }),
    );
  }
  if (operation.kind === "tag" || operation.kind === "untag") {
    const tags = Array.isArray(operation.tags) ? operation.tags : operation.tag ? [operation.tag] : [];
    if (!tags.length) throw new Error(`${operation.kind} requires tag or tags.`);
    // Pre-fix: tag values were `tags.map(String)` with zero validation, so
    // empty strings, embedded whitespace, tabs, newlines, and NULs all flowed
    // straight into session.tags[addr]. Same class of footgun as rename_batch
    // — a single bad entry corrupts the tag set on commit. Validate each one
    // with the same rules as a symbol-name label.
    normalized.tags = tags.map((tag) => {
      const stringified = String(tag);
      validateRenameValue(stringified, operation.kind, {
        addr: normalized.addr,
        field: "tag",
        maxLen: 256,
        noun: "tag",
      });
      return stringified;
    });
  }
  if (operation.kind === "hypothesis_create") {
    // Pre-fix `if (!operation.topic)` only caught undefined/null/empty —
    // whitespace-only strings ("   ") were truthy and committed verbatim,
    // leaving silent ghost hypotheses with blank topics in the UI.
    validateProseValue(operation.topic, "hypothesis_create", {
      field: "topic",
      maxLen: 1024,
      required: true,
    });
    validateProseValue(operation.claim, "hypothesis_create", {
      field: "claim",
      maxLen: 4096,
    });
    normalized.hypothesisId = operation.hypothesisId ?? `hyp-${crypto.randomUUID()}`;
    normalized.topic = String(operation.topic);
    normalized.claim = operation.claim ?? null;
    normalized.status = operation.status ?? "open";
  }
  if (operation.kind === "hypothesis_link") {
    if (!operation.hypothesisId) throw new Error("hypothesis_link requires hypothesisId.");
    validateProseValue(operation.evidence ?? operation.note, "hypothesis_link", {
      field: "evidence",
      maxLen: 4096,
    });
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
