import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

export function classifyImports(imports = []) {
  const buckets = Object.create(null);
  for (const name of imports) {
    const sym = String(name);
    let placed = false;
    for (const [bucket, pattern] of CAPABILITY_RULES) {
      if (pattern.test(sym)) {
        (buckets[bucket] ??= []).push(sym);
        placed = true;
        break;
      }
    }
    if (!placed) (buckets.other ??= []).push(sym);
  }
  for (const key of Object.keys(buckets)) {
    buckets[key] = [...new Set(buckets[key])].sort();
  }
  return buckets;
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

// ─── Section entropy ──────────────────────────────────────────────────────

export function shannonEntropy(buffer) {
  if (!buffer || !buffer.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i += 1) counts[buffer[i]] += 1;
  const len = buffer.length;
  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    const c = counts[i];
    if (!c) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export async function computeSectionEntropy(path, arch = "auto", { maxBytes = 4 * 1024 * 1024, maxSections = 64 } = {}) {
  const sections = await listMachOSections(path, arch);
  const sliceOffset = await fatSliceOffset(path, arch);
  const handle = await open(path, "r");
  try {
    const out = [];
    for (const section of sections.slice(0, maxSections)) {
      if (!Number.isFinite(section.fileStart) || !Number.isFinite(section.size) || section.size === 0) continue;
      const length = Math.min(section.size, maxBytes);
      const buf = Buffer.alloc(length);
      await handle.read(buf, 0, length, section.fileStart + sliceOffset);
      const entropy = shannonEntropy(buf);
      out.push({
        segname: section.segname,
        sectname: section.sectname,
        vmStart: section.vmStart != null ? `0x${section.vmStart.toString(16)}` : null,
        fileStart: section.fileStart + sliceOffset,
        size: section.size,
        sampledBytes: length,
        entropy: Number(entropy.toFixed(4)),
        suspicious: entropy >= 7.5,
      });
    }
    return out;
  } finally {
    await handle.close();
  }
}

async function listMachOSections(path, arch = "auto") {
  const args = arch && arch !== "auto" ? ["-arch", arch, "-l", path] : ["-l", path];
  const { stdout } = await execFileAsync("otool", args, { maxBuffer: 64 * 1024 * 1024 });
  return parseMachOSections(stdout);
}

// Returns the byte offset of the requested arch slice within a fat (universal) Mach-O file.
// Returns 0 for thin files or when arch resolution fails.
export async function fatSliceOffset(path, arch) {
  if (!arch || arch === "auto") return 0;
  try {
    const { stdout } = await execFileAsync("lipo", ["-detailed_info", path], { maxBuffer: 4 * 1024 * 1024 });
    if (!/^Fat header/m.test(stdout)) return 0;
    const blocks = stdout.split(/^architecture\s+/m).slice(1);
    for (const block of blocks) {
      const archName = block.split(/\s+/, 1)[0];
      if (archName === arch) {
        const offsetMatch = block.match(/^\s*offset\s+(\d+)/m);
        if (offsetMatch) return Number(offsetMatch[1]);
      }
    }
    return 0;
  } catch {
    return 0;
  }
}

export function parseMachOSections(output) {
  const sections = [];
  let currentSegment = null;
  let currentSection = null;

  const finalize = () => {
    if (
      currentSection &&
      currentSection.sectname &&
      Number.isFinite(currentSection.fileStart) &&
      Number.isFinite(currentSection.size) &&
      currentSection.size > 0
    ) {
      sections.push({
        segname: currentSection.segname ?? currentSegment ?? null,
        sectname: currentSection.sectname,
        vmStart: currentSection.vmStart,
        fileStart: currentSection.fileStart,
        size: currentSection.size,
      });
    }
    currentSection = null;
  };

  for (const rawLine of output.split("\n")) {
    const line = rawLine.trim();
    if (line === "Section") {
      finalize();
      currentSection = { segname: currentSegment };
      continue;
    }
    if (line.startsWith("segname ")) {
      currentSegment = line.split(/\s+/)[1] ?? null;
      if (currentSection) currentSection.segname = currentSegment;
      continue;
    }
    if (!currentSection) continue;
    const [key, value] = line.split(/\s+/, 2);
    if (!value) continue;
    if (key === "sectname") currentSection.sectname = value;
    else if (key === "segname") currentSection.segname = value;
    else if (key === "addr") currentSection.vmStart = parseInt(value, 16);
    else if (key === "size") currentSection.size = parseInt(value, 16);
    else if (key === "offset") currentSection.fileStart = parseInt(value, 10);
  }
  finalize();
  return sections;
}

// ─── x86_64 prologue scanning (deep mode) ─────────────────────────────────

const X86_PROLOGUE_REGEX = /\b(?:push\s+%rbp|push\s+rbp|endbr64|endbr32)\b/;
const X86_MOV_RBP_RSP = /\b(?:movq?\s+%rsp,\s*%rbp|mov\s+rbp,\s*rsp)\b/;
const X86_CALLQ_DIRECT = /\bcallq?\s+0x([0-9a-fA-F]+)/;
const X86_LEA_RIP_REL = /\blea(?:q)?\s+(?:0x([0-9a-fA-F]+)\(%rip\),\s*%[a-z0-9]+|[a-z0-9]+,\s*\[rip\s*\+\s*0x([0-9a-fA-F]+)\])/;

export function scanX86Disassembly(text, { maxFunctions = 30000, startAddr = null, endAddr = null } = {}) {
  const functions = [];
  const callEdges = [];
  const adrpRefs = [];
  let currentFunc = null;
  let prevAddr = null;
  let pendingRbpPush = null;

  const lines = text.split("\n");
  for (const rawLine of lines) {
    if (functions.length >= maxFunctions) break;
    const m = rawLine.match(/^\s*([0-9a-fA-F]{6,16})[:\s]+(.+)/);
    if (!m) continue;
    const addr = parseInt(m[1], 16);
    if (!Number.isFinite(addr)) continue;
    if (startAddr !== null && addr < startAddr) continue;
    if (endAddr !== null && addr > endAddr) break;

    const instr = m[2].trim();

    // endbr64 alone is a function entry under control-flow integrity builds.
    if (/\bendbr64\b/.test(instr) || /\bendbr32\b/.test(instr)) {
      if (currentFunc) currentFunc.size = addr - currentFunc.addrNum;
      finalize(functions, currentFunc, prevAddr);
      currentFunc = { addr: fmtAddr(addr), addrNum: addr, size: null };
      pendingRbpPush = null;
    } else if (/\bpush\s+%?rbp\b/.test(instr)) {
      pendingRbpPush = addr;
    } else if (X86_MOV_RBP_RSP.test(instr) && pendingRbpPush !== null && addr - pendingRbpPush <= 8) {
      finalize(functions, currentFunc, prevAddr);
      currentFunc = { addr: fmtAddr(pendingRbpPush), addrNum: pendingRbpPush, size: null };
      pendingRbpPush = null;
    } else if (!X86_MOV_RBP_RSP.test(instr)) {
      // reset pending if intervening instruction breaks the pattern beyond a small window.
      if (pendingRbpPush !== null && addr - pendingRbpPush > 8) pendingRbpPush = null;
    }

    const callMatch = instr.match(X86_CALLQ_DIRECT);
    if (callMatch && currentFunc) {
      callEdges.push({ from: currentFunc.addr, to: fmtAddr(parseInt(callMatch[1], 16)) });
    }

    const leaMatch = instr.match(X86_LEA_RIP_REL);
    if (leaMatch && currentFunc) {
      const offset = parseInt(leaMatch[1] ?? leaMatch[2], 16);
      const target = addr + offset + 7; // approximate: lea rip+disp32 is 7 bytes
      adrpRefs.push({ instrAddr: fmtAddr(addr), targetAddr: fmtAddr(target), functionAddr: currentFunc.addr });
    }

    prevAddr = addr;
  }
  finalize(functions, currentFunc, prevAddr);
  return { functions, callEdges, adrpRefs };
}

function finalize(out, currentFunc, prevAddr) {
  if (!currentFunc || prevAddr === null) return;
  if (out.length === 0 || out[out.length - 1].addr !== currentFunc.addr) {
    currentFunc.size = currentFunc.size ?? prevAddr - currentFunc.addrNum + 4;
    out.push({ addr: currentFunc.addr, size: currentFunc.size });
  }
}

export async function discoverX86Functions(path, { arch = "x86_64", maxFunctions = 30000, startAddr = null, endAddr = null } = {}) {
  if (maxFunctions <= 0) return { functions: [], callEdges: [], adrpRefs: [] };
  const child = spawn("otool", ["-arch", arch, "-tv", path], { stdio: ["ignore", "pipe", "pipe"] });
  let buffer = "";
  let stderr = "";
  let stopped = false;
  const collected = { functions: [], callEdges: [], adrpRefs: [] };
  const localState = { currentFunc: null, prevAddr: null, pendingRbpPush: null };

  const stop = () => {
    stopped = true;
    child.kill();
  };

  const handleLine = (line) => {
    if (stopped) return;
    const m = line.match(/^\s*([0-9a-fA-F]{6,16})[:\s]+(.+)/);
    if (!m) return;
    const addr = parseInt(m[1], 16);
    if (!Number.isFinite(addr)) return;
    if (startAddr !== null && addr < startAddr) return;
    if (endAddr !== null && addr > endAddr) {
      finalize(collected.functions, localState.currentFunc, localState.prevAddr);
      stop();
      return;
    }
    const instr = m[2].trim();

    if (/\bendbr64\b/.test(instr) || /\bendbr32\b/.test(instr)) {
      finalize(collected.functions, localState.currentFunc, localState.prevAddr);
      localState.currentFunc = { addr: fmtAddr(addr), addrNum: addr, size: null };
      localState.pendingRbpPush = null;
    } else if (/\bpush\s+%?rbp\b/.test(instr)) {
      localState.pendingRbpPush = addr;
    } else if (X86_MOV_RBP_RSP.test(instr) && localState.pendingRbpPush !== null && addr - localState.pendingRbpPush <= 8) {
      finalize(collected.functions, localState.currentFunc, localState.prevAddr);
      localState.currentFunc = { addr: fmtAddr(localState.pendingRbpPush), addrNum: localState.pendingRbpPush, size: null };
      localState.pendingRbpPush = null;
    } else if (localState.pendingRbpPush !== null && addr - localState.pendingRbpPush > 8) {
      localState.pendingRbpPush = null;
    }

    const callMatch = instr.match(X86_CALLQ_DIRECT);
    if (callMatch && localState.currentFunc) {
      collected.callEdges.push({ from: localState.currentFunc.addr, to: fmtAddr(parseInt(callMatch[1], 16)) });
    }
    const leaMatch = instr.match(X86_LEA_RIP_REL);
    if (leaMatch && localState.currentFunc) {
      const offset = parseInt(leaMatch[1] ?? leaMatch[2], 16);
      const target = addr + offset + 7;
      collected.adrpRefs.push({ instrAddr: fmtAddr(addr), targetAddr: fmtAddr(target), functionAddr: localState.currentFunc.addr });
    }

    localState.prevAddr = addr;
    if (collected.functions.length >= maxFunctions) stop();
  };

  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      handleLine(line);
      if (stopped) return;
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (!stopped && buffer) handleLine(buffer);
      if (!stopped) finalize(collected.functions, localState.currentFunc, localState.prevAddr);
      if (code && signal !== "SIGTERM") {
        reject(new Error(`otool exited with code ${code}: ${stderr.slice(-1000)}`));
        return;
      }
      resolve();
    });
  });

  return collected;
}

// ─── Code signing + entitlements ──────────────────────────────────────────

export async function extractCodeSigning(path) {
  const out = { signed: false, format: null, signer: null, teamId: null, identifier: null, cdHash: null, flags: null, entitlements: null, error: null };
  try {
    const { stderr } = await execFileAsync("codesign", ["-dvvv", path], { maxBuffer: 8 * 1024 * 1024 });
    const text = stderr ?? "";
    out.signed = /Signature=/.test(text) || /Identifier=/.test(text);
    out.format = matchFirst(text, /Format=(.+)/);
    out.identifier = matchFirst(text, /Identifier=(.+)/);
    out.teamId = matchFirst(text, /TeamIdentifier=(.+)/);
    out.signer = matchFirst(text, /Authority=(.+)/);
    out.cdHash = matchFirst(text, /CDHash=(.+)/);
    out.flags = matchFirst(text, /CodeDirectory.*flags=(0x[0-9a-fA-F]+|\S+)/);
  } catch (error) {
    out.error = (error.stderr ?? error.message).toString().trim();
  }
  try {
    const { stdout } = await execFileAsync("codesign", ["-d", "--entitlements", "-", "--xml", path], { maxBuffer: 8 * 1024 * 1024 });
    if (stdout && stdout.includes("<?xml")) {
      const xml = stdout.slice(stdout.indexOf("<?xml"));
      out.entitlements = parseEntitlementsXml(xml);
    }
  } catch (error) {
    if (!out.entitlements) {
      const stderr = (error.stderr ?? error.message ?? "").toString();
      if (stderr.includes("not signed")) {
        out.signed = false;
      } else if (out.error) {
        out.error += `; entitlements: ${stderr.slice(0, 200)}`;
      } else if (!stderr.includes("does not contain any entitlements")) {
        out.error = `entitlements: ${stderr.slice(0, 200)}`;
      }
    }
  }
  return out;
}

export function parseEntitlementsXml(xml) {
  // Lightweight plist parser sufficient for entitlements (key/string/true/false/array).
  const result = {};
  const dictMatch = xml.match(/<dict>([\s\S]*?)<\/dict>/);
  if (!dictMatch) return result;
  const body = dictMatch[1];
  const pairRegex = /<key>([^<]+)<\/key>\s*(<true\/>|<false\/>|<string>([\s\S]*?)<\/string>|<integer>([\s\S]*?)<\/integer>|<array>([\s\S]*?)<\/array>|<dict>([\s\S]*?)<\/dict>)/g;
  let match;
  while ((match = pairRegex.exec(body)) !== null) {
    const key = match[1];
    if (match[2] === "<true/>") result[key] = true;
    else if (match[2] === "<false/>") result[key] = false;
    else if (match[3] !== undefined) result[key] = match[3];
    else if (match[4] !== undefined) result[key] = Number(match[4]);
    else if (match[5] !== undefined) result[key] = [...match[5].matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) => m[1]);
    else if (match[6] !== undefined) result[key] = parseEntitlementsXml(`<dict>${match[6]}</dict>`);
  }
  return result;
}

function matchFirst(text, regex) {
  const m = text.match(regex);
  return m ? m[1].trim() : null;
}

// ─── ObjC class+method extraction ─────────────────────────────────────────

export async function extractObjCRuntime(path, arch = "auto", { maxClasses = 1000 } = {}) {
  const args = arch && arch !== "auto" ? ["-arch", arch, "-ov", path] : ["-ov", path];
  let stdout = "";
  try {
    const result = await execFileAsync("otool", args, { maxBuffer: 128 * 1024 * 1024 });
    stdout = result.stdout ?? "";
  } catch (error) {
    if (error.stdout) stdout = error.stdout;
    else throw error;
  }
  return parseObjCRuntime(stdout, { maxClasses });
}

export function parseObjCRuntime(text, { maxClasses = 1000 } = {}) {
  const classes = [];
  const blocks = text.split(/^Contents of \(__DATA[_,\.]?CONST?,__objc_classlist\)/m).slice(1);
  if (!blocks.length) {
    return parseObjCRuntimeFromClassDump(text, { maxClasses });
  }
  // Otool's ObjC dump produces a sequence of class decls separated by blank lines after the classlist header.
  return parseObjCRuntimeFromClassDump(text, { maxClasses });
}

function parseObjCRuntimeFromClassDump(text, { maxClasses = 1000 } = {}) {
  const classes = [];
  const lines = text.split("\n");
  let current = null;
  let methodList = null;
  let inMethods = false;
  let pendingMethod = null;

  const finalize = () => {
    if (!current) return;
    if (pendingMethod) { methodList.push(pendingMethod); pendingMethod = null; }
    if (classes.length < maxClasses) classes.push(current);
    current = null;
    methodList = null;
    inMethods = false;
  };

  // Real-name regex rejects the offset placeholder form `0x4ec50 (0x... extends past end of file)`.
  const realName = /^\s*name\s+0x[0-9a-fA-F]+\s+([^()].*)/;
  const realSuper = /^\s*superclass\s+0x[0-9a-fA-F]+\s+(.+)/;
  // Methods within the modern dump may be offsets; treat any name/types/imp that isn't a placeholder as a method.
  const methodName = /^\s*name\s+0x[0-9a-fA-F]+(?:\s+\(.+\))?/;
  const methodTypes = /^\s*types\s+0x[0-9a-fA-F]+/;
  const methodImp = /^\s*imp\s+(0x[0-9a-fA-F]+)/;
  // Modern header: two hex addresses on one line, possibly preceded by indent. e.g. "0000000100152380 0x100158ff8".
  const modernHeader = /^\s*[0-9a-fA-F]{6,16}\s+0x[0-9a-fA-F]+\s*$/;
  const metaMarker = /^\s*Meta Class\s*$/;

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");
    const trimmed = line.trim();

    if (/^Contents of \(__DATA[_,]?(?:CONST,)?__objc_classlist\)/.test(line)) {
      finalize();
      continue;
    }

    // Format A: bare _OBJC_(META)CLASS_$_X header
    const classHeader = trimmed.match(/_OBJC_(META)?CLASS_\$_([A-Za-z0-9_$.]+)/);
    if (classHeader && (/^_OBJC_/.test(trimmed) || /^[0-9a-fA-F]{6,16}\s+0x[0-9a-fA-F]+\s+_OBJC_/.test(trimmed))) {
      finalize();
      current = {
        name: classHeader[2].replace(/:$/, "").trim(),
        superclass: null,
        methods: [],
        protocols: [],
        properties: [],
        type: classHeader[1] === "META" ? "metaclass" : "class",
      };
      methodList = current.methods;
      inMethods = false;
      continue;
    }

    // Format B: modern Apple dump header (vmaddr ptr).
    if (modernHeader.test(trimmed)) {
      finalize();
      current = { name: null, superclass: null, methods: [], protocols: [], properties: [], type: "class" };
      methodList = current.methods;
      inMethods = false;
      continue;
    }

    // Format B: "Meta Class" marker indicates the metaclass block for the current entry.
    if (metaMarker.test(line) && current) {
      // Switch the current entry's role to metaclass for accumulating "class" methods.
      // We don't replace current (we keep its name) — but we do reset method state.
      if (pendingMethod) { methodList.push(pendingMethod); pendingMethod = null; }
      // Push current as instance class, start a new metaclass shadow entry that merges by name later.
      if (current.name) {
        if (classes.length < maxClasses) classes.push(current);
        const meta = { name: current.name, superclass: current.superclass, methods: [], protocols: [], properties: [], type: "metaclass" };
        current = meta;
        methodList = meta.methods;
        inMethods = false;
      }
      continue;
    }

    if (!current) continue;

    if (!inMethods) {
      const nm = line.match(realName);
      if (nm) {
        const value = nm[1].trim();
        // First "name" we see at top-level is the class name.
        if (!current.name) current.name = value;
        continue;
      }
      const sm = line.match(realSuper);
      if (sm) {
        let value = sm[1].trim();
        // skip placeholder "0x... extends past end" or "__mh_execute_header"
        if (!/^\(/.test(value) && value !== "__objc_empty_cache" && value !== "__mh_execute_header") {
          current.superclass = value.replace(/^_OBJC_(?:META)?CLASS_\$_/, "");
        }
        continue;
      }
      if (/^\s*baseMethods\s+0x[0-9a-fA-F]+/.test(line) && !/__mh_execute_header/.test(line)) {
        inMethods = true;
        continue;
      }
      // Format A also uses "baseMethods 0x..." then nested name/types/imp; covered above.
    } else {
      // We're inside a baseMethods block. End it on baseProtocols / weakIvarLayout / next data section.
      if (/^\s*(baseProtocols|baseProperties|weakIvarLayout|ivarLayout|ivars)\b/.test(line)) {
        if (pendingMethod) { methodList.push(pendingMethod); pendingMethod = null; }
        inMethods = false;
        continue;
      }
      if (modernHeader.test(trimmed) || metaMarker.test(line)) {
        // a new class entry is starting; back out of method mode and re-process the line.
        if (pendingMethod) { methodList.push(pendingMethod); pendingMethod = null; }
        inMethods = false;
        // Fall through by recursively re-handling — easier to just create the new class now.
        finalize();
        if (modernHeader.test(trimmed)) {
          current = { name: null, superclass: null, methods: [], protocols: [], properties: [], type: "class" };
        } else {
          current = { name: null, superclass: null, methods: [], protocols: [], properties: [], type: "metaclass" };
        }
        methodList = current.methods;
        continue;
      }

      const nameTok = line.match(methodName);
      const typesTok = line.match(methodTypes);
      const impTok = line.match(methodImp);

      if (nameTok) {
        if (pendingMethod) methodList.push(pendingMethod);
        // Extract trailing string portion if present (Format A); else null name and we still record the slot.
        const trailing = line.match(/^\s*name\s+0x[0-9a-fA-F]+\s+([^()].*)/);
        pendingMethod = { name: trailing ? trailing[1].trim() : null, types: null, addr: null };
      } else if (typesTok && pendingMethod) {
        const trailing = line.match(/^\s*types\s+0x[0-9a-fA-F]+\s+([^()].*)/);
        if (trailing) pendingMethod.types = trailing[1].trim();
      } else if (impTok && pendingMethod) {
        pendingMethod.addr = impTok[1].trim();
        methodList.push(pendingMethod);
        pendingMethod = null;
      }
    }
  }
  if (current) finalize();

  // Merge metaclass methods into class entries by name (skipping anonymous entries).
  const byName = new Map();
  for (const cls of classes) {
    if (!cls.name) continue;
    const key = cls.name;
    if (!byName.has(key)) byName.set(key, { name: cls.name, superclass: cls.superclass, methods: [], protocols: [], properties: [] });
    const target = byName.get(key);
    if (cls.superclass && !target.superclass) target.superclass = cls.superclass;
    for (const m of cls.methods) {
      const kind = cls.type === "metaclass" ? "class" : "instance";
      target.methods.push({ ...m, kind });
    }
  }
  return [...byName.values()];
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

export function jaccardMinhash(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let agree = 0;
  for (let i = 0; i < a.length; i += 1) if (a[i] === b[i]) agree += 1;
  return agree / a.length;
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
  const minhash = minhashSignature(stringTokens, 32);
  const simhash = computeCfgSimhash(fn);
  const cfgShape = `bb:${(fn.basicBlocks ?? []).length}/callees:${(fn.callees ?? []).length}/callers:${(fn.callers ?? []).length}`;
  const imphash = importSig.length ? computeImphash(importSig) : null;
  return {
    cfgShape,
    importSignature: importSig,
    stringBag: [...stringTokens].slice(0, 16),
    imphash,
    simhash,
    minhash: [...minhash],
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

export function diffSessions(left, right) {
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
    functions: { onlyInLeft, onlyInRight, renamed, changed },
    strings: stringDelta,
    imports: importDelta,
  };
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
  if (m) return new RegExp(m[1], m[2] || "i");
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
      tokens.push({ kind: "predicate", key: "name", value: buf });
    }
  }
  return tokens;
}

export function parseQuery(input) {
  const tokens = tokeniseQuery(input);
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
