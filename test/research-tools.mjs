import assert from "node:assert/strict";
import { test } from "node:test";

import {
  classifyImports,
  detectAntiAnalysis,
  shannonEntropy,
  parseMachOSections,
  scanX86Disassembly,
  parseEntitlementsXml,
  parseObjCRuntime,
  md5Hex,
  computeImphash,
  tokeniseStringBag,
  minhashSignature,
  jaccardMinhash,
  computeCfgSimhash,
  simhash64,
  hammingDistance64,
  buildFunctionFingerprint,
  functionSimilarity,
  jaccardSet,
  diffSessions,
  tokeniseQuery,
  parseQuery,
  evalQuery,
  queryFunctions,
} from "../src/research-tools.js";

// ─── classifyImports ──────────────────────────────────────────────────────

test("classifyImports buckets common Apple symbols", () => {
  const buckets = classifyImports([
    "_ptrace",
    "_CC_SHA256",
    "_CFURLCreateWithString",
    "_open",
    "_xpc_connection_create",
    "_dlopen",
    "_objc_msgSend",
    "_NSWindow",
    "_unknown_symbol",
  ]);

  assert.deepEqual(buckets.antiAnalysis, ["_ptrace"]);
  assert.deepEqual(buckets.crypto, ["_CC_SHA256"]);
  assert.deepEqual(buckets.network, ["_CFURLCreateWithString"]);
  assert.deepEqual(buckets.file, ["_open"]);
  assert.deepEqual(buckets.ipc, ["_xpc_connection_create"]);
  assert.deepEqual(buckets.exec, ["_dlopen"]);
  assert.deepEqual(buckets.objc, ["_objc_msgSend"]);
  assert.deepEqual(buckets.ui, ["_NSWindow"]);
  assert.deepEqual(buckets.other, ["_unknown_symbol"]);
});

test("classifyImports prefers antiAnalysis over exec for ptrace", () => {
  const buckets = classifyImports(["_ptrace", "_dlopen", "_dlsym"]);
  assert.ok(buckets.antiAnalysis.includes("_ptrace"));
  assert.ok(buckets.exec.includes("_dlopen"));
});

test("classifyImports dedupes and sorts within buckets", () => {
  const buckets = classifyImports(["_open", "_open", "_close", "_read"]);
  assert.deepEqual(buckets.file, ["_close", "_open", "_read"]);
});

// ─── detectAntiAnalysis ───────────────────────────────────────────────────

test("detectAntiAnalysis flags ptrace + sysctl + KERN_PROC pattern", () => {
  const findings = detectAntiAnalysis({
    imports: ["_ptrace", "_sysctl"],
    strings: [{ addr: "0x1000", value: "KERN_PROC P_TRACED" }],
  });

  const kinds = new Set(findings.map((f) => f.kind));
  assert.ok(kinds.has("ptrace_deny_attach"));
  assert.ok(kinds.has("sysctl_debug_check"));
  assert.ok(kinds.has("trace_string"));
  assert.ok(kinds.has("sysctl_isdebugged_pattern"));
  // sysctl_isdebugged_pattern is the high-severity composite
  const composite = findings.find((f) => f.kind === "sysctl_isdebugged_pattern");
  assert.equal(composite.severity, "high");
});

test("detectAntiAnalysis returns empty for clean session", () => {
  const findings = detectAntiAnalysis({
    imports: ["_open", "_read"],
    strings: [{ addr: "0x1000", value: "Hello world" }],
  });
  assert.deepEqual(findings, []);
});

test("detectAntiAnalysis dedupes repeated imports", () => {
  const findings = detectAntiAnalysis({
    imports: ["_ptrace", "_ptrace", "_ptrace"],
    strings: [],
  });
  const ptraceFindings = findings.filter((f) => f.kind === "ptrace_deny_attach");
  assert.equal(ptraceFindings.length, 1);
});

// ─── shannonEntropy + parseMachOSections ──────────────────────────────────

test("shannonEntropy is 0 for uniform input", () => {
  assert.equal(shannonEntropy(Buffer.alloc(1024, 0x41)), 0);
});

test("shannonEntropy approaches 8 for high-entropy input", () => {
  const buf = Buffer.alloc(4096);
  for (let i = 0; i < buf.length; i += 1) buf[i] = i & 0xff;
  const entropy = shannonEntropy(buf);
  assert.ok(entropy > 7.9, `expected >7.9, got ${entropy}`);
});

test("shannonEntropy of empty input is 0", () => {
  assert.equal(shannonEntropy(Buffer.alloc(0)), 0);
  assert.equal(shannonEntropy(null), 0);
});

test("parseMachOSections reads otool -l output", () => {
  const sample = `
Load command 1
      cmd LC_SEGMENT_64
  cmdsize 472
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000004000
  fileoff 0
 filesize 16384
Section
  sectname __text
   segname __TEXT
      addr 0x0000000100003a98
      size 0x000000000000058c
    offset 15000
     align 2^2 (4)
Section
  sectname __cstring
   segname __TEXT
      addr 0x0000000100004024
      size 0x000000000000004f
    offset 16420
`;
  const sections = parseMachOSections(sample);
  assert.equal(sections.length, 2);
  assert.equal(sections[0].sectname, "__text");
  assert.equal(sections[0].segname, "__TEXT");
  assert.equal(sections[0].size, 0x58c);
  assert.equal(sections[0].fileStart, 15000);
  assert.equal(sections[1].sectname, "__cstring");
});

// ─── scanX86Disassembly ───────────────────────────────────────────────────

test("scanX86Disassembly detects push rbp / mov rbp,rsp prologue", () => {
  const text = `
0000000100003a98 push %rbp
0000000100003a99 movq %rsp, %rbp
0000000100003a9c subq $0x10, %rsp
0000000100003aa0 callq 0x100003e00
0000000100003aa5 leaq 0x100(%rip), %rdi
0000000100003aac retq
0000000100003ab0 push %rbp
0000000100003ab1 movq %rsp, %rbp
0000000100003ab4 retq
`;
  const result = scanX86Disassembly(text);
  assert.equal(result.functions.length, 2, JSON.stringify(result.functions));
  assert.equal(result.functions[0].addr, "0x100003a98");
  assert.equal(result.functions[1].addr, "0x100003ab0");
  assert.equal(result.callEdges.length, 1);
  assert.equal(result.callEdges[0].to, "0x100003e00");
  assert.equal(result.adrpRefs.length, 1);
});

test("scanX86Disassembly detects endbr64 entry under CFI builds", () => {
  const text = `
0000000100003a98 endbr64
0000000100003a9c subq $0x10, %rsp
0000000100003aa0 callq 0x100003e00
0000000100003aa5 retq
`;
  const result = scanX86Disassembly(text);
  assert.equal(result.functions.length, 1);
  assert.equal(result.functions[0].addr, "0x100003a98");
  assert.equal(result.callEdges.length, 1);
});

// ─── parseEntitlementsXml ────────────────────────────────────────────────

test("parseEntitlementsXml decodes plist entitlements", () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.app-sandbox</key>
  <true/>
  <key>com.apple.security.files.user-selected.read-only</key>
  <true/>
  <key>com.apple.security.network.client</key>
  <false/>
  <key>com.apple.developer.team-identifier</key>
  <string>ABCD123XYZ</string>
  <key>com.apple.security.application-groups</key>
  <array>
    <string>group.example.first</string>
    <string>group.example.second</string>
  </array>
  <key>com.apple.developer.heartbeat-rate</key>
  <integer>42</integer>
</dict>
</plist>`;
  const ents = parseEntitlementsXml(xml);
  assert.equal(ents["com.apple.security.app-sandbox"], true);
  assert.equal(ents["com.apple.security.network.client"], false);
  assert.equal(ents["com.apple.developer.team-identifier"], "ABCD123XYZ");
  assert.deepEqual(ents["com.apple.security.application-groups"], ["group.example.first", "group.example.second"]);
  assert.equal(ents["com.apple.developer.heartbeat-rate"], 42);
});

test("parseEntitlementsXml returns {} when no dict found", () => {
  assert.deepEqual(parseEntitlementsXml("<plist></plist>"), {});
});

// ─── parseObjCRuntime ────────────────────────────────────────────────────

test("parseObjCRuntime extracts class+method names from otool dump", () => {
  const text = `
Contents of (__DATA,__objc_classlist) section
00000001000080a0 0x100008100 _OBJC_CLASS_$_AuthController
           isa 0x100008180 _OBJC_METACLASS_$_AuthController
    superclass 0x0 _OBJC_CLASS_$_NSObject
          name 0x100004130 AuthController
   baseMethods 0x100008200
        entsize 24
          count 2
              name 0x100004200 validateLicense:
             types 0x100004220 c24@0:8@16
               imp 0x100003f50
              name 0x100004240 saveToken:
             types 0x100004260 v24@0:8@16
               imp 0x100004010
   baseProtocols 0x0
_OBJC_METACLASS_$_AuthController
           isa 0x100008300 _OBJC_METACLASS_$_NSObject
          name 0x100004130 AuthController
   baseMethods 0x100008400
              name 0x100004280 sharedInstance
             types 0x1000042a0 @16@0:8
               imp 0x1000040a0
   baseProtocols 0x0
`;
  const classes = parseObjCRuntime(text);
  assert.equal(classes.length, 1);
  const cls = classes[0];
  assert.equal(cls.name, "AuthController");
  assert.equal(cls.superclass, "NSObject");
  // 2 instance + 1 class methods
  assert.equal(cls.methods.length, 3);
  const validate = cls.methods.find((m) => m.name === "validateLicense:");
  assert.equal(validate.kind, "instance");
  assert.equal(validate.addr, "0x100003f50");
  const shared = cls.methods.find((m) => m.name === "sharedInstance");
  assert.equal(shared.kind, "class");
  assert.equal(shared.addr, "0x1000040a0");
});

test("parseObjCRuntime returns [] for empty input", () => {
  assert.deepEqual(parseObjCRuntime(""), []);
});

// ─── Hashing utilities ────────────────────────────────────────────────────

test("md5Hex matches RFC 1321 vectors", () => {
  assert.equal(md5Hex(""), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(md5Hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
});

test("computeImphash is order-independent and case-insensitive", () => {
  const a = computeImphash(["_open", "_READ", "_write"]);
  const b = computeImphash(["write", "READ", "open"]);
  const c = computeImphash(["_open", "_read"]);
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{32}$/);
});

test("tokeniseStringBag drops short tokens and lowercases", () => {
  const tokens = tokeniseStringBag(["Hello WORLD!", "id=42 tokenize this", ""]);
  assert.ok(tokens.has("hello"));
  assert.ok(tokens.has("world"));
  assert.ok(tokens.has("tokenize"));
  assert.ok(tokens.has("this"));
  // length < 4 dropped
  assert.ok(!tokens.has("id"));
  assert.ok(!tokens.has("42"));
});

test("minhashSignature gives identical sigs for identical inputs and high jaccard for near sets", () => {
  const a = minhashSignature(new Set(["alpha", "beta", "gamma", "delta", "epsilon"]));
  const b = minhashSignature(new Set(["alpha", "beta", "gamma", "delta", "epsilon"]));
  const c = minhashSignature(new Set(["alpha", "beta", "gamma", "delta", "zeta"]));
  const d = minhashSignature(new Set(["totally", "different", "tokens", "everywhere"]));
  assert.equal(jaccardMinhash(a, b), 1);
  const near = jaccardMinhash(a, c);
  const far = jaccardMinhash(a, d);
  assert.ok(near > 0.4, `near ${near} > 0.4`);
  assert.ok(far < 0.4, `far ${far} < 0.4`);
});

test("simhash64 + hammingDistance64 produce stable, comparable hashes", () => {
  const a = simhash64(["op:mov", "op:push", "imp:_open", "bb:3"]);
  const b = simhash64(["op:mov", "op:push", "imp:_open", "bb:3"]);
  const c = simhash64(["op:mov", "op:push", "imp:_open", "bb:4"]);
  const d = simhash64(["op:syscall", "imp:_kill"]);
  assert.equal(a, b);
  assert.equal(hammingDistance64(a, b), 0);
  assert.ok(hammingDistance64(a, c) <= hammingDistance64(a, d));
  assert.match(a, /^0x[0-9a-f]{16}$/);
});

test("computeCfgSimhash is deterministic for same fn", () => {
  const fn = {
    basicBlocks: [
      { successors: ["bb1"], instructions: [{ text: "mov rax, rbx" }, { text: "ret" }] },
      { successors: [], instructions: [{ text: "ret" }] },
    ],
    callees: ["0x100"],
    callers: [],
    size: 32,
    imports: ["_open"],
  };
  const a = computeCfgSimhash(fn);
  const b = computeCfgSimhash(fn);
  assert.equal(a, b);
});

test("buildFunctionFingerprint + functionSimilarity rank near-twin above stranger", () => {
  const base = {
    addr: "0x100", size: 200,
    callees: ["0x200", "0x300"], callers: ["0x50"],
    imports: ["_open", "_read", "_write"],
    strings: ["validate license key", "decrypt aes-256", "verify keychain item"],
    basicBlocks: [
      { successors: ["b1"], instructions: [{ text: "stp x29, x30, [sp]" }, { text: "bl _open" }] },
      { successors: [], instructions: [{ text: "ret" }] },
    ],
  };
  const twin = JSON.parse(JSON.stringify(base));
  twin.addr = "0x500";
  const stranger = {
    addr: "0x900", size: 32,
    callees: [], callers: [],
    imports: ["_NSWindow"],
    strings: ["window title", "menu bar"],
    basicBlocks: [
      { successors: [], instructions: [{ text: "ret" }] },
    ],
  };

  const baseFp = buildFunctionFingerprint(base);
  const twinFp = buildFunctionFingerprint(twin);
  const strangerFp = buildFunctionFingerprint(stranger);

  const twinScore = functionSimilarity(baseFp, twinFp);
  const strangerScore = functionSimilarity(baseFp, strangerFp);

  assert.ok(twinScore.similarity > 0.9, `twin ${twinScore.similarity} > 0.9`);
  assert.ok(twinScore.similarity > strangerScore.similarity);
  assert.equal(twinScore.components.cfgShape, 1);
  assert.equal(twinScore.components.simhash, 1);
});

test("jaccardSet handles empty and disjoint sets", () => {
  assert.equal(jaccardSet(new Set(), new Set()), 0);
  assert.equal(jaccardSet(new Set(["a"]), new Set(["b"])), 0);
  assert.equal(jaccardSet(new Set(["a", "b"]), new Set(["b", "c"])), 1 / 3);
});

// ─── diffSessions ─────────────────────────────────────────────────────────

test("diffSessions reports adds, removes, renames, and field changes", () => {
  const left = {
    functions: {
      "0x100": { addr: "0x100", name: "old_name", size: 64, imports: ["_open"] },
      "0x200": { addr: "0x200", name: "kept", size: 32, imports: [] },
      "0x300": { addr: "0x300", name: "removed_only", size: 16, imports: [] },
    },
    strings: [{ value: "hello" }, { value: "world" }],
    imports: ["_open", "_close"],
  };
  const right = {
    functions: {
      "0x100": { addr: "0x100", name: "new_name", size: 96, imports: ["_open", "_read"] },
      "0x200": { addr: "0x200", name: "kept", size: 32, imports: [] },
      "0x400": { addr: "0x400", name: "added_only", size: 8, imports: [] },
    },
    strings: [{ value: "hello" }, { value: "extra" }],
    imports: ["_open", "_write"],
  };
  const diff = diffSessions(left, right);
  assert.equal(diff.summary.onlyInLeft, 1);
  assert.equal(diff.summary.onlyInRight, 1);
  assert.equal(diff.summary.renamed, 1);
  assert.equal(diff.summary.changed, 1);
  assert.equal(diff.functions.renamed[0].from, "old_name");
  assert.equal(diff.functions.renamed[0].to, "new_name");
  const change = diff.functions.changed[0];
  assert.equal(change.addr, "0x100");
  assert.equal(change.fields.size.from, 64);
  assert.equal(change.fields.size.to, 96);
  assert.deepEqual(change.fields.imports.added, ["_read"]);
  assert.deepEqual(diff.strings.added, ["extra"]);
  assert.deepEqual(diff.strings.removed, ["world"]);
  assert.deepEqual(diff.imports.added, ["_write"]);
  assert.deepEqual(diff.imports.removed, ["_close"]);
});

// ─── Query DSL ────────────────────────────────────────────────────────────

const querySession = {
  tags: { "0x100": ["license"], "0x200": ["network"] },
  binary: {
    capabilities: { crypto: ["_CC_SHA256"], network: ["_CFURLCreateWithString"] },
  },
  antiAnalysisFindings: [{ kind: "ptrace_deny_attach", import: "_ptrace" }],
  functions: {
    "0x100": {
      addr: "0x100", name: "validate_license", size: 256,
      callees: ["0x300"], callers: [], imports: ["_CC_SHA256"],
      strings: ["LICENSE_KEY"], pseudocode: "if (key_ok) { return 1; }",
    },
    "0x200": {
      addr: "0x200", name: "fetch_remote", size: 512,
      callees: [], callers: ["0x100"], imports: ["_CFURLCreateWithString"],
      strings: ["https://api.example.com"], pseudocode: "url = CFURLCreate();",
    },
    "0x300": {
      addr: "0x300", name: "small_helper", size: 16,
      callees: [], callers: ["0x100"], imports: [],
      strings: [], pseudocode: "ret;",
    },
  },
};

test("tokeniseQuery splits keywords and predicates", () => {
  const tokens = tokeniseQuery("name:validate AND imports:/_CC_/ OR NOT tag:network");
  assert.deepEqual(tokens.map((t) => t.kind), ["predicate", "and", "predicate", "or", "not", "predicate"]);
  assert.equal(tokens[0].key, "name");
  assert.equal(tokens[0].value, "validate");
  assert.equal(tokens[2].value, "/_CC_/");
});

test("parseQuery + evalQuery handle implicit AND, OR, NOT precedence", () => {
  const ast = parseQuery("name:validate imports:_CC_SHA256");
  assert.equal(ast.kind, "and");
  const matches = queryFunctions(querySession, "name:validate imports:_CC_SHA256");
  assert.equal(matches.length, 1);
  assert.equal(matches[0].addr, "0x100");
});

test("queryFunctions supports tag, capability, anti, size, addr, pseudocode predicates", () => {
  assert.equal(queryFunctions(querySession, "tag:license").length, 1);
  assert.equal(queryFunctions(querySession, "capability:crypto").length, 1);
  assert.equal(queryFunctions(querySession, "capability:network").length, 1);
  assert.equal(queryFunctions(querySession, "anti:ptrace").length, 3, "anti predicate is global → matches all");
  assert.equal(queryFunctions(querySession, "size:>=256").length, 2);
  assert.equal(queryFunctions(querySession, "size:<32").length, 1);
  assert.equal(queryFunctions(querySession, "addr:0x300").length, 1);
  assert.equal(queryFunctions(querySession, "pseudocode:CFURLCreate").length, 1);
});

test("queryFunctions supports OR, NOT, regex literals", () => {
  const orMatches = queryFunctions(querySession, "name:validate OR name:fetch_remote");
  assert.equal(orMatches.length, 2);
  const notMatches = queryFunctions(querySession, "NOT name:helper");
  assert.equal(notMatches.length, 2);
  const regexMatches = queryFunctions(querySession, "imports:/_CFURL/");
  assert.equal(regexMatches.length, 1);
  assert.equal(regexMatches[0].addr, "0x200");
});

test("queryFunctions parens override precedence", () => {
  const matches = queryFunctions(querySession, "(name:validate OR name:fetch_remote) AND size:>=300");
  assert.equal(matches.length, 1);
  assert.equal(matches[0].addr, "0x200");
});

test("queryFunctions returns at most max_results", () => {
  const matches = queryFunctions(querySession, "anti:ptrace", { maxResults: 2 });
  assert.equal(matches.length, 2);
});
