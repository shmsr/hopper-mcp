import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const DEFAULT_OFFICIAL_MCP = "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer";
const OFFICIAL_PROTOCOL_VERSION = "2025-03-26";
const STDERR_CAP_BYTES = 8000;

const WRITE_TOOLS = new Set([
  "set_current_document",
  "goto_address",
  "set_comment",
  "set_inline_comment",
  "set_address_name",
  "set_addresses_names",
  "set_bookmark",
  "unset_bookmark",
]);

export class OfficialHopperBackend {
  constructor({
    command = process.env.HOPPER_OFFICIAL_MCP_COMMAND ?? DEFAULT_OFFICIAL_MCP,
    timeoutMs = Number(process.env.HOPPER_OFFICIAL_MCP_TIMEOUT_MS ?? 30000),
    enableWrites = process.env.HOPPER_MCP_ENABLE_OFFICIAL_WRITES === "1",
  } = {}) {
    this.command = command;
    this.timeoutMs = timeoutMs;
    this.enableWrites = enableWrites;
    this.child = null;
    this.pending = new Map();
    this.stderrChunks = [];
    this.stderrBytes = 0;
    this.nextId = 0;
    this.initialized = false;
    this.tools = null;
    this.startPromise = null;
    this.callQueue = Promise.resolve();
  }

  capabilities() {
    return {
      command: this.command,
      protocolVersion: OFFICIAL_PROTOCOL_VERSION,
      connected: Boolean(this.child && !this.child.killed && this.initialized),
      enabledWrites: this.enableWrites,
      mode: "official-hopper-mcp-subprocess",
    };
  }

  isWriteTool(name) {
    return WRITE_TOOLS.has(name);
  }

  async listTools() {
    await this.start();
    if (this.tools) return this.tools;
    const result = await this.request("tools/list");
    this.tools = result.tools ?? [];
    return this.tools;
  }

  async callTool(name, args = {}, { confirmLiveWrite = false, validate = true } = {}) {
    return this.#enqueueCall(() => this.#callToolUnlocked(name, args, { confirmLiveWrite, validate }));
  }

  async #callToolUnlocked(name, args = {}, { confirmLiveWrite = false, validate = true } = {}) {
    if (this.isWriteTool(name) && (!this.enableWrites || !confirmLiveWrite)) {
      throw new Error(`Official Hopper write/navigation tool '${name}' requires HOPPER_MCP_ENABLE_OFFICIAL_WRITES=1 and confirm_live_write=true.`);
    }
    await this.start();
    if (validate) {
      // Lazy-load tool catalog and validate args against the published
      // schema. The most common foot-gun is parameter-name drift between
      // tools (e.g. xrefs uses `address`, search_* uses `pattern`); when an
      // unrecognized field is passed, Hopper silently returns null rather
      // than erroring, which is invisible to callers. Catch it here.
      const validationError = await this.#validateArgs(name, args);
      if (validationError) throw validationError;
    }
    const result = await this.request("tools/call", { name, arguments: args });
    return normalizeOfficialResult(name, result);
  }

  async #enqueueCall(work) {
    const run = this.callQueue
      .catch(() => {})
      .then(work);
    this.callQueue = run.catch(() => {});
    return await run;
  }

  async #validateArgs(name, args) {
    if (!this.tools) {
      try {
        await this.listTools();
      } catch {
        return null; // tolerate; schema validation is best-effort
      }
    }
    const schema = this.tools?.find?.((t) => t.name === name);
    if (!schema) {
      return new Error(`Unknown official Hopper tool '${name}'. Call official_hopper_call with name="list_tools" to see available tools.`);
    }
    const props = schema.inputSchema?.properties ?? {};
    const allowed = new Set(Object.keys(props));
    const required = new Set(schema.inputSchema?.required ?? []);
    const passed = args && typeof args === "object" ? Object.keys(args) : [];
    const unknown = passed.filter((k) => !allowed.has(k));
    if (unknown.length) {
      const allowedList = [...allowed].join(", ") || "(none)";
      return new Error(`Official Hopper tool '${name}' rejected unknown argument(s): ${unknown.join(", ")}. Allowed: ${allowedList}.`);
    }
    const missing = [...required].filter((k) => !(k in (args ?? {})));
    if (missing.length) {
      return new Error(`Official Hopper tool '${name}' missing required argument(s): ${missing.join(", ")}.`);
    }
    return null;
  }

  async applyTransaction(_session, transaction, { confirmLiveWrite = false } = {}) {
    // Validate every op upfront so we fail fast before issuing any writes.
    for (const op of transaction.operations) {
      if (op.kind === "rename") continue; // batched below via set_addresses_names
      if (!officialOperation(op)) {
        throw new Error(`Official Hopper backend does not support transaction operation '${op.kind}'.`);
      }
    }

    const operations = [];
    const ops = transaction.operations;
    let i = 0;
    while (i < ops.length) {
      const op = ops[i];
      if (op.kind === "rename") {
        // Group consecutive renames into one set_addresses_names call. Hopper
        // documents this as the preferred batch path; for transactions with
        // many renames we go from N round-trips to 1.
        const batch = [];
        while (i < ops.length && ops[i].kind === "rename") {
          batch.push(ops[i]);
          i++;
        }
        const names = {};
        for (const r of batch) names[r.addr] = r.newValue;
        const response = await this.callTool(
          "set_addresses_names",
          { names },
          { confirmLiveWrite },
        );
        const payload = officialToolPayload(response);
        for (const r of batch) {
          operations.push({
            operationId: r.operationId,
            kind: r.kind,
            tool: "set_addresses_names",
            result: payload,
            batched: batch.length > 1 ? batch.length : undefined,
          });
        }
      } else {
        const mapped = officialOperation(op);
        const response = await this.callTool(mapped.name, mapped.arguments, { confirmLiveWrite });
        operations.push({
          operationId: op.operationId,
          kind: op.kind,
          tool: mapped.name,
          result: officialToolPayload(response),
        });
        i++;
      }
    }

    return {
      appliedToHopper: true,
      backend: "official-hopper-mcp",
      transactionId: transaction.id,
      operations,
    };
  }

  async start() {
    if (this.initialized && this.child && !this.child.killed) return;
    if (this.startPromise) return this.startPromise;
    this.startPromise = this.#start().finally(() => {
      this.startPromise = null;
    });
    return this.startPromise;
  }

  async #start() {
    this.child = spawn(this.command, [], { stdio: ["pipe", "pipe", "pipe"] });

    this.child.stderr.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      this.stderrChunks.push(text);
      this.stderrBytes += text.length;
      this.#trimStderr();
    });

    this.child.on("exit", (code, signal) => {
      this.initialized = false;
      this.tools = null;
      const reason = signal ? `signal ${signal}` : `exit ${code}`;
      const tail = this.#stderrTail();
      const error = new Error(`Official Hopper MCP server terminated (${reason}). stderr: ${tail}`);
      const pending = Array.from(this.pending.values());
      this.pending.clear();
      for (const entry of pending) {
        clearTimeout(entry.timer);
        entry.reject(error);
      }
    });

    this.child.on("error", (err) => {
      this.#noteStderr(`\n[child error] ${err?.message ?? err}`);
    });

    const rl = createInterface({ input: this.child.stdout });
    rl.on("line", (line) => {
      if (!line.trim()) return;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        this.#noteStderr(`\n[non-json stdout] ${line}`);
        return;
      }
      if (!Object.hasOwn(message, "id")) return;
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.error) entry.reject(new Error(message.error.message));
      else entry.resolve(message.result ?? {});
    });

    const initialized = await this.request("initialize", {
      protocolVersion: OFFICIAL_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "hopper-mcp-official-backend", version: "0.1.0" },
    });
    if (initialized.protocolVersion !== OFFICIAL_PROTOCOL_VERSION) {
      throw new Error(`Unexpected official Hopper MCP protocol version: ${initialized.protocolVersion}`);
    }
    this.initialized = true;
  }

  request(method, params = {}, timeoutMs = this.timeoutMs) {
    if (!this.child || this.child.killed) {
      return Promise.reject(new Error("Official Hopper MCP server is not running."));
    }
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.pending.delete(id)) return;
        reject(new Error(`Timed out waiting for official Hopper MCP ${method} after ${timeoutMs}ms. stderr: ${this.#stderrTail()}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      } catch (err) {
        if (this.pending.delete(id)) clearTimeout(timer);
        reject(err);
      }
    });
  }

  close() {
    this.child?.kill();
    this.child = null;
    this.initialized = false;
    this.tools = null;
    const pending = Array.from(this.pending.values());
    this.pending.clear();
    const error = new Error("Official Hopper MCP backend closed.");
    for (const entry of pending) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
  }

  #noteStderr(text) {
    this.stderrChunks.push(text);
    this.stderrBytes += text.length;
    this.#trimStderr();
  }

  #trimStderr() {
    while (this.stderrBytes > STDERR_CAP_BYTES && this.stderrChunks.length > 1) {
      this.stderrBytes -= this.stderrChunks[0].length;
      this.stderrChunks.shift();
    }
    if (this.stderrChunks.length === 1 && this.stderrBytes > STDERR_CAP_BYTES) {
      const overflow = this.stderrBytes - STDERR_CAP_BYTES;
      this.stderrChunks[0] = this.stderrChunks[0].slice(overflow);
      this.stderrBytes -= overflow;
    }
  }

  #stderrTail() {
    if (this.stderrChunks.length === 0) return "";
    const joined = this.stderrChunks.length === 1 ? this.stderrChunks[0] : this.stderrChunks.join("");
    return joined.slice(-1000);
  }
}

export function officialToolPayload(result) {
  const text = result?.content?.find?.((item) => item.type === "text")?.text ?? "";
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// Hopper's MCP returns inconsistent shapes across tool families:
//   - search_strings/search_procedures/search_name return `null` when no
//     matches, but an object map when there are hits.
//   - xrefs returns [] for no matches.
// Normalize the search_* family to {} so callers can iterate without
// special-casing null. We touch the wrapped MCP response in place because
// downstream code parses via officialToolPayload (which JSON.parses the
// content[0].text payload).
const SEARCH_TOOLS_RETURNING_OBJECT = new Set([
  "search_strings",
  "search_procedures",
  "search_name",
]);

export function normalizeOfficialResult(name, result) {
  if (!SEARCH_TOOLS_RETURNING_OBJECT.has(name)) return result;
  const text = result?.content?.find?.((item) => item.type === "text")?.text;
  if (text !== "null" && text !== null && text !== undefined) return result;
  // Replace the null payload with an empty object payload, preserving the
  // outer wrapper shape so downstream parsers still work.
  return {
    ...result,
    content: [{ type: "text", text: "{}" }],
  };
}

function officialOperation(operation) {
  // Renames are batched at the call site via set_addresses_names; this
  // mapping intentionally omits rename so the validator catches any caller
  // that bypasses applyTransaction.
  if (operation.kind === "comment") {
    return {
      name: "set_comment",
      arguments: { address: operation.addr, comment: operation.newValue },
    };
  }
  if (operation.kind === "inline_comment") {
    return {
      name: "set_inline_comment",
      arguments: { address: operation.addr, comment: operation.newValue },
    };
  }
  return null;
}
