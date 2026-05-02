import { createHash } from "node:crypto";
import { looksLikeCatastrophicRegex } from "./server-helpers.js";

// ─── Capability classification ────────────────────────────────────────────

const CAPABILITY_RULES = [
  // Anti-analysis goes first so a debugger import doesn't get bucketed elsewhere.
  ["antiAnalysis", /^_(?:ptrace|sysctl|sysctlbyname|task_threads|task_for_pid|mach_task_self|amfi_check_dyld_policy_self|csops|csops_audittoken|isatty|getppid)$/i],
  ["antiAnalysis", /(?:AmIBeingDebugged|sysctl_debug|denyAttach|PT_DENY|amfi)/i],
  ["crypto", /^_(?:CC_(?:SHA|MD|HMAC)|CCCrypt|CCKey|EVP_|AES_|RSA_|DH_|EC_|RAND_|SecKey|SecRandom|CommonCrypto|kSec)/i],
  ["network", /^_(?:CFURL|CFNetwork|CFHTTP|NSURL|NSStream|NSXPC|NWConnection|nw_|getaddrinfo|gethostbyname|connect|socket|sendto|recvfrom|SSL|TLS|cURL|CFRead|CFWrite)/i],
  ["network", /(?:URLSession|HTTPRequest|WebSocket|Socket|TCP|UDP|HTTP)/],
  ["file", /^_(?:open|openat|read|write|close|stat|lstat|fstat|fopen|fread|fwrite|fclose|access|unlink|rename|mkdir|rmdir|chmod|chown|fcntl|mmap|munmap|NSFileManager|NSData|NSFileHandle|CFData|CFFileDescriptor)/i],
  ["ipc", /^_(?:xpc_|mach_msg|mach_port|bootstrap_|notify_|CFMessagePort|kqueue|dispatch_)/i],
  ["proc", /^_(?:fork|vfork|posix_spawn|exec[lvp]+|wait[pid]*|kill|signal|sigaction|setuid|setgid|getpid|setpgid|setsid|atexit)/i],
  ["exec", /^_(?:dlopen|dlsym|dlclose|NSCreateObjectFileImageFromMemory|NSLinkModule|loadAndStartMachOImage)/i],
  ["persistence", /(?:LSSharedFileList|LaunchServices|SMLoginItem|SMAppService|launchd|cron|com\.apple\.launchd|LaunchAgent|LaunchDaemon|WindowServer)/i],
  ["security", /^_(?:Sec[A-Z]|kSec|SCDynamicStore|AuthorizationCopyRights|AuthorizationCreate|AuthorizationFree|AuthorizationExecute)/i],
  ["objc", /^_(?:objc_|class_|sel_|method_|protocol_|ivar_|object_|imp_)/],
  ["swift", /^_\$s/],
  ["ui", /^_(?:NSWindow|NSView|NSApplication|UIView|UIApplication|UIWindow|CGContext|CGEventSource|CGImage|CALayer|CFBundle)/i],
  ["fs_metadata", /^_(?:getxattr|setxattr|listxattr|removexattr|getattrlist|setattrlist|copyfile)/],
];

// Returns { totalImports, counts, samples, truncated } where:
//   counts:    bucket → total dedup count (always full)
//   samples:   bucket → first maxPerBucket sorted imports (sliced)
//   truncated: list of buckets where samples < count
// maxPerBucket defaults to 25; 0 / negative means uncapped.
//
// Older shape was just { bucket: string[] } unconditionally. On a stripped
// Swift binary (e.g. Raycast: ~6000 _$s mangled imports in the `swift`
// bucket), that produced 124 KB+ responses that blew the host's per-tool
// token budget. Counts are universally useful; samples illustrate without
// dumping the full set. Callers needing the full dump can pass
// maxPerBucket: 0 explicitly.
// Per-function tag set: scan a function's imports against CAPABILITY_RULES and
// return the unique bucket names it touched. Used by snapshot ingest to label
// each function (fn.capabilityTags). Keeping this separate from the
// classifyImports response shape lets that response stay capped/sample-only
// for token-budget reasons while per-function tagging remains accurate.
export function capabilityTagsFor(funcImports = []) {
  const tags = new Set();
  for (const sym of funcImports) {
    const name = String(sym);
    let placed = false;
    for (const [bucket, pattern] of CAPABILITY_RULES) {
      if (pattern.test(name)) {
        tags.add(bucket);
        placed = true;
        break;
      }
    }
    if (!placed) tags.add("other");
  }
  return [...tags].sort();
}

export function classifyImports(imports = [], { maxPerBucket = 25 } = {}) {
  const raw = Object.create(null);
  for (const name of imports) {
    const sym = String(name);
    let placed = false;
    for (const [bucket, pattern] of CAPABILITY_RULES) {
      if (pattern.test(sym)) {
        (raw[bucket] ??= []).push(sym);
        placed = true;
        break;
      }
    }
    if (!placed) (raw.other ??= []).push(sym);
  }
  const counts = Object.create(null);
  const samples = Object.create(null);
  const truncated = [];
  const cap = Number(maxPerBucket ?? 0);
  for (const key of Object.keys(raw)) {
    const dedup = [...new Set(raw[key])].sort();
    counts[key] = dedup.length;
    samples[key] = cap > 0 ? dedup.slice(0, cap) : dedup;
    if (cap > 0 && dedup.length > cap) truncated.push(key);
  }
  return {
    totalImports: imports.length,
    counts,
    samples,
    truncated,
  };
}

// ─── Anti-analysis detection ──────────────────────────────────────────────

const ANTI_ANALYSIS_PATTERNS = [
  { kind: "ptrace_deny_attach", severity: "high", import: /^_ptrace$/, evidence: "_ptrace import; check operands for PT_DENY_ATTACH (0x1f / 31)." },
  { kind: "sysctl_debug_check", severity: "high", import: /^_(?:sysctl|sysctlbyname)$/, evidence: "sysctl call; check for KERN_PROC + KERN_PROC_PID and P_TRACED flag inspection." },
  { kind: "amfi_dyld_policy", severity: "med", import: /amfi/i, evidence: "AMFI policy check; library validation often used to detect injected dylibs." },
  { kind: "task_inspection", severity: "med", import: /^_(?:task_threads|task_for_pid|mach_task_self)$/, evidence: "Mach task inspection used by anti-debugger logic." },
  { kind: "csops_check", severity: "med", import: /^_csops/, evidence: "Code-signing flag inspection (csops) used to detect debugger-attach via CS_OPS_STATUS." },
  { kind: "exit_on_isatty", severity: "low", import: /^_isatty$/, evidence: "isatty present; can be used to alter behavior under TTY/pipe." },
  { kind: "dlopen_ptrace", severity: "high", import: /^_dlsym$/, evidence: "dlsym present; commonly used to resolve _ptrace at runtime to evade static detection." },
];

const ANTI_ANALYSIS_STRING_PATTERNS = [
  { kind: "debugger_string", severity: "low", regex: /\b(?:debugger|debugging|debug build|gdb|lldb|frida|objection|cycript|ssh|jailbreak|rooted)\b/i },
  { kind: "anti_vm_string", severity: "low", regex: /\b(?:vmware|virtualbox|qemu|parallels|hypervisor)\b/i },
  { kind: "trace_string", severity: "low", regex: /\b(?:PT_DENY_ATTACH|sysctl|KERN_PROC|P_TRACED|kIsDebuggedKey)\b/i },
];

export function detectAntiAnalysis(session) {
  const findings = [];
  const imports = session?.imports ?? [];
  const importSet = new Set(imports);
  for (const rule of ANTI_ANALYSIS_PATTERNS) {
    for (const sym of imports) {
      if (rule.import.test(sym)) {
        findings.push({ kind: rule.kind, severity: rule.severity, import: sym, evidence: rule.evidence });
        break;
      }
    }
  }
  for (const str of session?.strings ?? []) {
    for (const rule of ANTI_ANALYSIS_STRING_PATTERNS) {
      if (rule.regex.test(str.value ?? "")) {
        findings.push({ kind: rule.kind, severity: rule.severity, addr: str.addr, value: str.value, evidence: `string at ${str.addr}` });
      }
    }
  }
  // Boost severity when sysctl + KERN_PROC string co-exist.
  const haveSysctl = importSet.has("_sysctl") || importSet.has("_sysctlbyname");
  const haveKernProc = (session?.strings ?? []).some((s) => /KERN_PROC|P_TRACED/i.test(s.value ?? ""));
  if (haveSysctl && haveKernProc) {
    findings.push({
      kind: "sysctl_isdebugged_pattern",
      severity: "high",
      evidence: "sysctl import co-occurs with KERN_PROC/P_TRACED string; this matches the canonical Apple-published 'AmIBeingDebugged' check.",
    });
  }
  return dedupeFindings(findings);
}

function dedupeFindings(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = `${f.kind}:${f.import ?? f.addr ?? f.value ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

// ─── Fingerprints ─────────────────────────────────────────────────────────

export function md5Hex(value) {
  return createHash("md5").update(String(value)).digest("hex");
}

export function computeImphash(imports = []) {
  const normalized = [...new Set(imports.map((s) => String(s).toLowerCase().replace(/^_/, "")))].sort();
  return md5Hex(normalized.join(","));
}

export function tokeniseStringBag(values = []) {
  const out = new Set();
  for (const v of values) {
    const text = String(v ?? "").toLowerCase();
    for (const tok of text.split(/[^a-z0-9_]+/)) {
      if (tok.length >= 4) out.add(tok);
    }
  }
  return out;
}

export function minhashSignature(tokens, k = 64) {
  const arr = tokens instanceof Set ? [...tokens] : tokens;
  const sig = new Uint32Array(k);
  for (let i = 0; i < k; i += 1) sig[i] = 0xffffffff;
  if (!arr.length) return sig;
  for (const tok of arr) {
    const base = fnv1a32(String(tok));
    for (let i = 0; i < k; i += 1) {
      const h = mix32(base, i + 1);
      if (h < sig[i]) sig[i] = h;
    }
  }
  return sig;
}

// 0xffffffff is minhashSignature's "unset" sentinel — the initial value before
// any token has been hashed in. Two empty-token fingerprints both end up with
// signatures of [0xffffffff × k], which would otherwise score as a perfect
// minhash match (1.0). Across binaries that produced false 0.65 similarity
// scores between unrelated 28-byte stubs that just shared bb:0/callees:1
// structure. Treat positions where both sides are unset as "no signal" and
// fall back to 0 when every position is unset.
const MINHASH_UNSET = 0xffffffff;
export function jaccardMinhash(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let agree = 0;
  let observed = 0;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] === MINHASH_UNSET && b[i] === MINHASH_UNSET) continue;
    observed += 1;
    if (a[i] === b[i]) agree += 1;
  }
  return observed ? agree / observed : 0;
}

export function computeCfgSimhash(fn) {
  const features = [];
  const blocks = fn?.basicBlocks ?? [];
  features.push(`bb:${blocks.length}`);
  features.push(`callees:${(fn?.callees ?? []).length}`);
  features.push(`callers:${(fn?.callers ?? []).length}`);
  features.push(`size:${Math.floor((fn?.size ?? 0) / 16)}`);
  for (const block of blocks) {
    features.push(`block:${(block.successors ?? block.to ?? []).length}`);
    for (const instr of block.instructions ?? []) {
      const text = (instr.text ?? instr.raw ?? "").split(/\s+/)[0];
      if (text) features.push(`op:${text.toLowerCase()}`);
    }
  }
  for (const sym of (fn?.imports ?? []).slice(0, 32)) features.push(`imp:${sym.toLowerCase()}`);
  return simhash64(features);
}

export function simhash64(features) {
  const counters = new Array(64).fill(0);
  for (const feature of features) {
    const hash = fnv1a64(String(feature));
    for (let i = 0; i < 64; i += 1) {
      const bit = (hash >> BigInt(i)) & 1n;
      counters[i] += bit === 1n ? 1 : -1;
    }
  }
  let result = 0n;
  for (let i = 0; i < 64; i += 1) {
    if (counters[i] > 0) result |= 1n << BigInt(i);
  }
  return `0x${result.toString(16).padStart(16, "0")}`;
}

export function hammingDistance64(a, b) {
  let x = BigInt(a) ^ BigInt(b);
  let count = 0;
  while (x) {
    if (x & 1n) count += 1;
    x >>= 1n;
  }
  return count;
}

function fnv1a32(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function mix32(value, salt) {
  let h = (value ^ Math.imul(salt | 0, 0x9e3779b1)) >>> 0;
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b) >>> 0;
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
}

function fnv1a64(text) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = (1n << 64n) - 1n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * prime) & mask;
  }
  return hash;
}

export function buildFunctionFingerprint(fn, sessionImports = []) {
  const importSig = (fn.imports ?? []).slice(0, 32);
  const stringTokens = tokeniseStringBag(fn.strings ?? []);
  const simhash = computeCfgSimhash(fn);
  const cfgShape = `bb:${(fn.basicBlocks ?? []).length}/callees:${(fn.callees ?? []).length}/callers:${(fn.callers ?? []).length}`;
  const imphash = importSig.length ? computeImphash(importSig) : null;
  // Skip minhash entirely when there are no tokens to hash: a minhash of
  // [0xffffffff × k] is the unset initial state, not a real signature, and
  // jaccardMinhash on two such arrays used to return 1.0 — producing false
  // cross-binary matches between unrelated empty-stub functions. Null tells
  // functionSimilarity to score this component as 0.
  const minhash = stringTokens.size > 0 ? [...minhashSignature(stringTokens, 32)] : null;
  return {
    cfgShape,
    importSignature: importSig,
    stringBag: [...stringTokens].slice(0, 16),
    imphash,
    simhash,
    minhash,
  };
}

export function functionSimilarity(a, b) {
  if (!a || !b) return { similarity: 0, components: {} };
  const minhashScore = a.minhash && b.minhash ? jaccardMinhash(a.minhash, b.minhash) : 0;
  const importOverlap = jaccardSet(new Set(a.importSignature ?? []), new Set(b.importSignature ?? []));
  let simhashScore = 0;
  if (a.simhash && b.simhash) {
    const distance = hammingDistance64(a.simhash, b.simhash);
    simhashScore = 1 - distance / 64;
  }
  const stringScore = jaccardSet(new Set(a.stringBag ?? []), new Set(b.stringBag ?? []));
  const cfgScore = a.cfgShape && b.cfgShape && a.cfgShape === b.cfgShape ? 1 : 0;
  const similarity = 0.4 * simhashScore + 0.3 * importOverlap + 0.2 * minhashScore + 0.05 * stringScore + 0.05 * cfgScore;
  return { similarity, components: { simhash: simhashScore, importOverlap, minhash: minhashScore, stringBag: stringScore, cfgShape: cfgScore } };
}

export function jaccardSet(a, b) {
  if (!a.size && !b.size) return 0;
  let intersection = 0;
  for (const v of a) if (b.has(v)) intersection += 1;
  const union = a.size + b.size - intersection;
  return union ? intersection / union : 0;
}

// ─── Session diff ─────────────────────────────────────────────────────────

// Diffing two real Mach-O sessions (e.g. Cursor vs Raycast) blows past the
// host's per-tool token budget — onlyInLeft/onlyInRight alone can produce
// 10K+ entries, and `changed` carries old/new pseudocode pairs. Cap each
// bucket and surface `truncated:true` + `total` so the caller can paginate
// or opt out via maxPerBucket=0.
export function diffSessions(left, right, { maxPerBucket = 200 } = {}) {
  const leftFns = left?.functions ?? {};
  const rightFns = right?.functions ?? {};
  const leftAddrs = new Set(Object.keys(leftFns));
  const rightAddrs = new Set(Object.keys(rightFns));

  const onlyInLeft = [];
  const onlyInRight = [];
  const renamed = [];
  const changed = [];

  for (const addr of leftAddrs) {
    if (!rightAddrs.has(addr)) onlyInLeft.push({ addr, name: leftFns[addr].name });
  }
  for (const addr of rightAddrs) {
    if (!leftAddrs.has(addr)) onlyInRight.push({ addr, name: rightFns[addr].name });
  }
  for (const addr of leftAddrs) {
    if (!rightAddrs.has(addr)) continue;
    const a = leftFns[addr];
    const b = rightFns[addr];
    if ((a.name ?? null) !== (b.name ?? null)) renamed.push({ addr, from: a.name ?? null, to: b.name ?? null });
    let differs = false;
    const diff = { addr, fields: {} };
    for (const field of ["size", "summary", "comment", "type", "pseudocode", "confidence"]) {
      if ((a[field] ?? null) !== (b[field] ?? null)) {
        differs = true;
        diff.fields[field] = { from: a[field] ?? null, to: b[field] ?? null };
      }
    }
    const aImports = new Set(a.imports ?? []);
    const bImports = new Set(b.imports ?? []);
    const importDelta = setDelta(aImports, bImports);
    if (importDelta.added.length || importDelta.removed.length) {
      differs = true;
      diff.fields.imports = importDelta;
    }
    if (differs) changed.push(diff);
  }

  const leftStrings = new Set((left?.strings ?? []).map((s) => s.value));
  const rightStrings = new Set((right?.strings ?? []).map((s) => s.value));
  const stringDelta = setDelta(leftStrings, rightStrings);

  const importDelta = setDelta(new Set(left?.imports ?? []), new Set(right?.imports ?? []));

  const cappedFunctions = {
    onlyInLeft: cap(onlyInLeft, maxPerBucket),
    onlyInRight: cap(onlyInRight, maxPerBucket),
    renamed: cap(renamed, maxPerBucket),
    changed: cap(changed, maxPerBucket),
  };
  const cappedStrings = capDelta(stringDelta, maxPerBucket);
  const cappedImports = capDelta(importDelta, maxPerBucket);

  return {
    summary: {
      leftFunctions: leftAddrs.size,
      rightFunctions: rightAddrs.size,
      onlyInLeft: onlyInLeft.length,
      onlyInRight: onlyInRight.length,
      renamed: renamed.length,
      changed: changed.length,
      stringsAdded: stringDelta.added.length,
      stringsRemoved: stringDelta.removed.length,
      importsAdded: importDelta.added.length,
      importsRemoved: importDelta.removed.length,
    },
    functions: {
      onlyInLeft: cappedFunctions.onlyInLeft.items,
      onlyInRight: cappedFunctions.onlyInRight.items,
      renamed: cappedFunctions.renamed.items,
      changed: cappedFunctions.changed.items,
    },
    strings: cappedStrings.delta,
    imports: cappedImports.delta,
    truncated: {
      onlyInLeft: cappedFunctions.onlyInLeft.truncated,
      onlyInRight: cappedFunctions.onlyInRight.truncated,
      renamed: cappedFunctions.renamed.truncated,
      changed: cappedFunctions.changed.truncated,
      stringsAdded: cappedStrings.addedTruncated,
      stringsRemoved: cappedStrings.removedTruncated,
      importsAdded: cappedImports.addedTruncated,
      importsRemoved: cappedImports.removedTruncated,
    },
    maxPerBucket,
  };
}

function cap(list, max) {
  if (!max || list.length <= max) return { items: list, truncated: false };
  return { items: list.slice(0, max), truncated: true };
}

function capDelta(delta, max) {
  if (!max) return { delta, addedTruncated: false, removedTruncated: false };
  const out = { added: delta.added, removed: delta.removed };
  let addedTruncated = false;
  let removedTruncated = false;
  if (delta.added.length > max) {
    out.added = delta.added.slice(0, max);
    addedTruncated = true;
  }
  if (delta.removed.length > max) {
    out.removed = delta.removed.slice(0, max);
    removedTruncated = true;
  }
  return { delta: out, addedTruncated, removedTruncated };
}

function setDelta(a, b) {
  const added = [];
  const removed = [];
  for (const v of a) if (!b.has(v)) removed.push(v);
  for (const v of b) if (!a.has(v)) added.push(v);
  return { added: added.sort(), removed: removed.sort() };
}

// ─── Query DSL ────────────────────────────────────────────────────────────

// Grammar (left-to-right, parens supported, precedence: NOT > AND > OR):
//   expr      := orExpr
//   orExpr    := andExpr ( ("OR"|"or"|"|") andExpr )*
//   andExpr   := unary ( ("AND"|"and"|"&" | implicit) unary )*
//   unary     := ("NOT"|"not"|"!")? atom
//   atom      := "(" expr ")" | predicate
//   predicate := KEY ":" VALUE
// Supported KEYs: name, calls, callers, callees, imports, import, string, strings, tag, size, capability, anti, addr, pseudocode

const PREDICATES = {
  name: (fn, val) => regexOrEqual(val).test(fn.name ?? ""),
  calls: (fn, val) => (fn.callees ?? []).some((c) => regexOrEqual(val).test(String(c))),
  callers: (fn, val) => (fn.callers ?? []).some((c) => regexOrEqual(val).test(String(c))),
  callees: (fn, val) => (fn.callees ?? []).some((c) => regexOrEqual(val).test(String(c))),
  imports: importsPredicate,
  import: importsPredicate,
  string: (fn, val) => (fn.strings ?? []).some((s) => regexOrEqual(val).test(String(s))),
  strings: (fn, val) => (fn.strings ?? []).some((s) => regexOrEqual(val).test(String(s))),
  tag: (fn, val, ctx) => (ctx.tags?.[fn.addr] ?? []).some((tag) => regexOrEqual(val).test(tag)),
  size: (fn, val) => evalNumeric(fn.size ?? 0, val),
  capability: (fn, val, ctx) => fnHasCapability(fn, val, ctx),
  anti: (fn, val, ctx) => (ctx.antiAnalysis ?? []).some((f) => regexOrEqual(val).test(`${f.kind}:${f.import ?? f.addr ?? ""}`)),
  addr: (fn, val) => regexOrEqual(val).test(fn.addr ?? ""),
  pseudocode: (fn, val) => regexOrEqual(val).test(fn.pseudocode ?? ""),
};

function importsPredicate(fn, val) {
  return (fn.imports ?? []).some((s) => regexOrEqual(val).test(String(s)));
}

function fnHasCapability(fn, val, ctx) {
  const buckets = ctx.capabilities ?? {};
  for (const sym of fn.imports ?? []) {
    if ((buckets[val] ?? []).includes(sym)) return true;
  }
  return false;
}

function regexOrEqual(value) {
  const m = String(value).match(/^\/(.+)\/([imsuy]*)$/);
  if (m) {
    const body = m[1];
    if (body.length > 256) {
      throw new Error(
        `Regex body is ${body.length} chars (cap is 256). Most patterns are <50 chars; this looks like an accidental paste.`,
      );
    }
    if (looksLikeCatastrophicRegex(body)) {
      throw new Error(
        `Regex '${body}' has nested unbounded quantifiers ((a+)+, (.*)*, …). ` +
          `That shape causes catastrophic backtracking on V8 and would freeze the server. ` +
          `Rewrite without the nested quantifier.`,
      );
    }
    return new RegExp(body, m[2] || "i");
  }
  const text = String(value);
  return { test: (candidate) => String(candidate).toLowerCase().includes(text.toLowerCase()) };
}

function evalNumeric(actual, expr) {
  const m = String(expr).match(/^(<=|>=|<|>|=)?\s*(\d+)$/);
  if (!m) return false;
  const op = m[1] ?? "=";
  const value = Number(m[2]);
  switch (op) {
    case "<": return actual < value;
    case "<=": return actual <= value;
    case ">": return actual > value;
    case ">=": return actual >= value;
    case "=": return actual === value;
    default: return false;
  }
}

export function tokeniseQuery(input) {
  const tokens = [];
  const text = String(input).trim();
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === " " || ch === "\t") { i += 1; continue; }
    if (ch === "(" || ch === ")") { tokens.push({ kind: ch }); i += 1; continue; }
    if (ch === "!") { tokens.push({ kind: "not" }); i += 1; continue; }
    if (ch === "&") { tokens.push({ kind: "and" }); i += 1; continue; }
    if (ch === "|") { tokens.push({ kind: "or" }); i += 1; continue; }

    // Read predicate or keyword
    let buf = "";
    let inString = false;
    let regexDepth = 0;
    while (i < text.length) {
      const c = text[i];
      if (!inString && !regexDepth && (c === " " || c === "\t" || c === "(" || c === ")")) break;
      if (c === "\"") inString = !inString;
      if (!inString) {
        if (c === "/") regexDepth = regexDepth ? 0 : 1;
      }
      buf += c;
      i += 1;
    }
    // Unterminated " or / used to silently eat the rest of the input and
    // produce a degenerate predicate that matched nothing — making malformed
    // queries indistinguishable from "no results". Reject explicitly so the
    // caller knows their expression failed to parse.
    if (inString) throw new Error(`Unclosed quote in query expression: ${input}`);
    if (regexDepth) throw new Error(`Unclosed regex literal in query expression: ${input}`);
    if (!buf) continue;
    if (/^(and|AND)$/.test(buf)) tokens.push({ kind: "and" });
    else if (/^(or|OR)$/.test(buf)) tokens.push({ kind: "or" });
    else if (/^(not|NOT)$/.test(buf)) tokens.push({ kind: "not" });
    else if (buf.includes(":")) {
      const idx = buf.indexOf(":");
      let value = buf.slice(idx + 1);
      if (value.startsWith("\"") && value.endsWith("\"")) value = value.slice(1, -1);
      tokens.push({ kind: "predicate", key: buf.slice(0, idx).toLowerCase(), value });
    } else {
      tokens.push({ kind: "predicate", key: "name", value: buf, bare: true });
    }
  }
  return tokens;
}

export function parseQuery(input) {
  const tokens = tokeniseQuery(input);
  // Empty input used to fall through parseAtom's `if (!tok) return {true}`
  // and silently match every function in the session, capped to maxResults —
  // making "" indistinguishable from a deliberate "list everything" query.
  // Reject so callers see why they got nothing useful back.
  if (!tokens.length) throw new Error("Query expression is empty.");
  let pos = 0;
  const peek = () => tokens[pos];
  const consume = (kind) => {
    const tok = tokens[pos];
    if (!tok || tok.kind !== kind) return null;
    pos += 1;
    return tok;
  };

  const parseAtom = () => {
    const tok = peek();
    if (!tok) return { kind: "true" };
    if (tok.kind === "(") {
      pos += 1;
      const expr = parseOr();
      consume(")");
      return expr;
    }
    if (tok.kind === "predicate") {
      // Catch unknown predicates at parse time: evalQuery's `!handler` branch
      // used to silently treat them as "matches no function" — count:0 with
      // no hint that the predicate name was the problem.
      if (!Object.prototype.hasOwnProperty.call(PREDICATES, tok.key)) {
        const supported = Object.keys(PREDICATES).sort().join(", ");
        throw new Error(`Unknown query predicate '${tok.key}'. Supported: ${supported}.`);
      }
      // A bare token whose value is itself a predicate keyword (e.g. `size`
      // alone, or the leading `size` from a malformed `size > 100`) almost
      // always means the caller forgot the colon. Pre-fix this fell through
      // as `name:size` AND'd with the next bare token AND'd with the value,
      // returning a confident count:0 even when thousands of functions
      // match. Throw with a hint pointing at the colon syntax.
      if (
        tok.bare &&
        Object.prototype.hasOwnProperty.call(PREDICATES, tok.value.toLowerCase())
      ) {
        throw new Error(
          `Bare token '${tok.value}' is also a query predicate keyword. Did you mean '${tok.value}:VALUE' (e.g. '${tok.value}:>100' for numeric, '${tok.value}:foo' for substring)? Pass 'name:${tok.value}' if you really wanted to search function names for the literal string.`,
        );
      }
      // Empty value used to match everything (regexOrEqual("") returns a
      // matcher whose .test() is always true via String.includes("")), so
      // `name:` quietly returned the entire function table capped at
      // max_results. Reject explicitly — pass `name:.*` (regex) for "all".
      if (tok.value === "" || tok.value == null) {
        throw new Error(
          `Predicate '${tok.key}:' has an empty value. Pass a substring, '/regex/i' literal, or numeric expression. Use '${tok.key}:.*' (regex) if you really want to match everything.`,
        );
      }
      // Numeric predicates ('size') used to silently return zero hits when
      // the value didn't match /^(<=|>=|<|>|=)?\d+$/, e.g. `size:abc` or
      // `size:1k`. Surface the parse error so a typo isn't masked.
      if (tok.key === "size" && !/^(<=|>=|<|>|=)?\s*\d+$/.test(String(tok.value))) {
        throw new Error(
          `Predicate 'size:${tok.value}' is malformed. Expected '<N', '<=N', '>N', '>=N', '=N', or 'N'.`,
        );
      }
      pos += 1;
      return { kind: "pred", key: tok.key, value: tok.value };
    }
    pos += 1;
    return { kind: "true" };
  };

  const parseUnary = () => {
    if (consume("not")) return { kind: "not", child: parseUnary() };
    return parseAtom();
  };

  const parseAnd = () => {
    let left = parseUnary();
    while (true) {
      const tok = peek();
      if (!tok) break;
      if (tok.kind === "and") { pos += 1; left = { kind: "and", left, right: parseUnary() }; continue; }
      if (tok.kind === "or" || tok.kind === ")") break;
      // implicit AND for bare predicates / not
      if (tok.kind === "predicate" || tok.kind === "not" || tok.kind === "(") {
        left = { kind: "and", left, right: parseUnary() };
        continue;
      }
      break;
    }
    return left;
  };

  const parseOr = () => {
    let left = parseAnd();
    while (consume("or")) {
      left = { kind: "or", left, right: parseAnd() };
    }
    return left;
  };

  return parseOr();
}

export function evalQuery(node, fn, ctx) {
  if (!node) return true;
  if (node.kind === "true") return true;
  if (node.kind === "pred") {
    const handler = PREDICATES[node.key];
    if (!handler) return false;
    return Boolean(handler(fn, node.value, ctx));
  }
  if (node.kind === "not") return !evalQuery(node.child, fn, ctx);
  if (node.kind === "and") return evalQuery(node.left, fn, ctx) && evalQuery(node.right, fn, ctx);
  if (node.kind === "or") return evalQuery(node.left, fn, ctx) || evalQuery(node.right, fn, ctx);
  return false;
}

export function queryFunctions(session, query, { maxResults = 50, capabilities = null, antiAnalysis = null } = {}) {
  if (!session) return [];
  const ast = parseQuery(query);
  const ctx = {
    tags: session.tags ?? {},
    capabilities: capabilities ?? session.binary?.capabilities ?? null,
    antiAnalysis: antiAnalysis ?? session.antiAnalysisFindings ?? [],
  };
  const out = [];
  for (const fn of Object.values(session.functions ?? {})) {
    if (evalQuery(ast, fn, ctx)) {
      out.push({
        addr: fn.addr,
        name: fn.name ?? null,
        size: fn.size ?? null,
        summary: fn.summary ?? null,
        confidence: fn.confidence ?? null,
        tags: ctx.tags[fn.addr] ?? [],
        imports: (fn.imports ?? []).slice(0, 8),
        strings: (fn.strings ?? []).slice(0, 8),
      });
      if (out.length >= maxResults) break;
    }
  }
  return out;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function fmtAddr(n) {
  return `0x${n.toString(16)}`;
}
