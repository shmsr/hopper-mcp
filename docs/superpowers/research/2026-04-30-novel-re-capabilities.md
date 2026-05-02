# Novel Reverse-Engineering Capability Research

Date: 2026-04-30

## Question

What can this project do that is meaningfully stronger than Hopper's official MCP and stronger than existing Hopper-specific MCP alternatives, using ideas from Ghidra, IDA, Binary Ninja, radare2, Frida, angr, malware triage, binary diffing, and recent MCP security research?

## High-Level Finding

The opportunity is not "more Hopper tools." Existing Ghidra/Binary Ninja MCPs are already moving toward large tool surfaces. The defensible advantage is a smaller, evidence-driven reverse-engineering platform around Hopper:

- Hopper remains the interactive authority for decompilation, pseudocode, comments, names, and analyst edits.
- The Rust daemon becomes the provenance, indexing, similarity, diffing, rules, and transaction engine.
- Optional companion engines add semantic validation, dynamic traces, capability rules, and corpus memory.

This points to two products:

1. A better Hopper MCP: precise, safe, fast, provenance-rich access to Hopper and its analysis state.
2. A companion RE workbench/indexer: cross-tool function intelligence, capability matching, dynamic/static reconciliation, and long-term knowledge reuse.

## Capability Ideas Worth Building

### 1. Behavioral Function Knowledge Base

Inspired by Ghidra BSim and IDA Lumina.

BSim generates per-function feature vectors from decompiler-derived data/control-flow features and compares them with cosine similarity, using locality-sensitive hashing for large collections. IDA Lumina stores function metadata keyed by hashes and can apply names, prototypes, comments, stack variables, and operand representations to future databases.

For us:

- Build `hopper-kb`: a local function intelligence database.
- Store function fingerprints, normalized calls/imports/strings, CFG shape, pseudocode-derived tokens, recovered names, comments, prototypes, and analyst quality score.
- Let the MCP answer: "have I seen this function before?", "which project named this best?", "apply suggested metadata as a transaction."
- Keep binary contents out of the shared KB by default; store hashes, normalized features, and user-approved metadata.

Why this is novel for Hopper MCP:

- Hopper's official MCP is per-document and live-state oriented.
- A KB makes Hopper cumulative across projects and versions.
- Transaction-gated application avoids unsafe Lumina-style silent overwrite.

Placement: separate companion service plus MCP tools/resources.

### 2. Version Tracking And Markup Transfer

Inspired by Ghidra Version Tracking and modern binary diffing.

Ghidra's Version Tracking workflow validates inputs, matches functions/data, lets users accept/reject/tag matches, and transfers markup. Research on binary diffing frames function matching as both content similarity and call-graph alignment.

For us:

- Add `version_track_sessions`: compare two Hopper sessions.
- Score candidate matches with combined features: address delta, name, normalized bytes, imports, strings, CFG, call graph neighbors, pseudocode tokens.
- Expose match states: proposed, accepted, rejected, applied.
- Apply accepted names/comments/types/bookmarks through existing transaction preview.

Why this matters:

- Reverse engineering often happens across app updates.
- Hopper has no MCP-level session for "carry my hard-won annotations forward."
- This is a high-value tool for macOS/iOS app RE.

Placement: core MCP after live backend parity.

### 3. Multi-Evidence Function Similarity

Inspired by BSim, REFuSe/modern function similarity benchmarks, Diaphora, BinDiff, and QBinDiff-style graph alignment.

Current project fingerprints are basic. A stronger engine should use layered evidence:

- Exact identity: address, bytes hash, normalized instruction hash.
- Structural identity: CFG shape, block count, edge profile, cyclomatic complexity.
- Semantic hints: constants, strings, imports, Objective-C selectors, Swift symbols.
- Neighborhood: callers/callees, nearby functions, library clusters.
- Decompiled view: pseudocode token shingles and recovered locals/prototypes.

The key research lesson is to avoid pretending one score is truth. Return a ranked result with feature-level explanation:

- "matched because same selector set and similar CFG"
- "not matched because call graph changed"
- "weak match: same constants but different imports"

Placement: core MCP/indexer.

### 4. Static-Dynamic Reconciliation

Inspired by Frida Stalker, Frida Interceptor, and angr CFGFast/CFGEmulated distinction.

angr distinguishes fast static CFG from slower symbolic/emulated CFG, and Frida Stalker can collect executed blocks/functions/call summaries. This suggests an integrated workflow:

- Import Hopper's static CFG/calls/xrefs.
- Collect runtime traces from Frida as optional evidence: executed functions, hot edges, call counts, arguments snapshots.
- Reconcile traces with Hopper addresses and annotate hot paths, dead paths, unresolved indirect calls, and dynamically resolved imports.
- Let analysts ask: "show functions Hopper thinks reachable but never executed", "show runtime-only calls", "open hot call path in Hopper."

Why this is valuable:

- Static-only MCPs miss runtime dispatch, plugins, Objective-C message sends, Swift dynamic behavior, and anti-analysis paths.
- Hopper is good at static UX; Frida is good at runtime truth.

Placement: separate companion tool with MCP integration. Do not put Frida inside the core Hopper MCP daemon.

### 5. Capability Rule Overlay

Inspired by Mandiant capa, YARA, and Sigma.

capa matches expert rules over features at instruction/basic-block/function/file scopes and supports multiple backends including IDA, Ghidra, Binary Ninja, CAPE, DRAKVUF, VMRay, and BinExport. YARA is the standard for file/string/byte-pattern rules. Sigma gives a portable detection-rule model for logs.

For us:

- Extract Hopper-derived features into a rule engine: imports, strings, constants, calls, xrefs, selectors, Mach-O entitlements, Objective-C classes, Swift metadata, anti-analysis hints.
- Support capa-like rules for binary behavior and YARA-like byte/string rules.
- Optionally generate Sigma-like detections from dynamic traces, e.g. process/file/network behavior observed through Frida or sandbox logs.
- Render matches as Hopper annotations/resources: "this function likely performs keychain access", "this block matches FNV hash loop."

Placement: separate `hopper-capabilities` crate/service, exposed through MCP.

### 6. Decompiler Correctness And Trust Scoring

Inspired by Bin2Wrong and decompiler-fuzzing research.

Bin2Wrong found real semantic decompiler bugs across major decompilers by varying source, compilers, optimization flags, formats, and constructs. The practical lesson for an MCP is: never treat pseudocode as ground truth.

For us:

- Add function-level trust signals: decompiler timed out, too many basic blocks, irreducible control flow, suspicious switch recovery, indirect calls, opaque predicates, missing symbols, invalid stack deltas.
- Compare Hopper pseudocode against alternate evidence where available: assembly CFG, runtime traces, optional Ghidra/angr output.
- Warn the model: "do not base final conclusion only on pseudocode for this function."

Placement: core MCP analysis metadata, with optional companion validators.

### 7. Analyst Hypothesis Graph

Inspired by investigation workflows more than one specific tool.

The current project already has hypotheses. Extend it into a first-class graph:

- Nodes: functions, addresses, strings, selectors, rules, runtime events, files, hypotheses.
- Edges: calls, references, matched-rule, observed-runtime, supports-hypothesis, contradicts-hypothesis.
- Query: "what evidence supports this function being crypto?", "what did we rename because of this rule?", "what changed after version tracking?"

Why this matters:

- LLM reverse engineering fails when it loses evidence provenance.
- A hypothesis graph makes reasoning auditable and resumable.

Placement: core MCP.

### 8. Type And ABI Recovery Assistant

Inspired by IDA/Lumina metadata, Binary Ninja data-flow improvements, Hopper's Objective-C/Swift parsing, and decompiler usability work.

For macOS/iOS targets, Hopper can parse Objective-C and Swift metadata, but the MCP should make type recovery more systematic:

- Extract Objective-C classes, selectors, ivars, method type encodings, Swift symbols, protocol conformances.
- Propose prototypes and struct layouts from callsites, selector patterns, constants, and data-flow evidence.
- Apply only through transactions.
- Score suggestions and show evidence anchors.

Placement: Hopper-specific core/private backend later. This is one area where Hopper-native integration is likely better than generic tooling.

### 9. Secure MCP Execution Model

Inspired by recent MCP security research.

Recent papers identify MCP risks around capability attestation, implicit trust, tool-origin confusion, and server-side prompt/tool injection. Reverse-engineering MCPs are high-risk because they process attacker-controlled binaries and produce attacker-influenced strings, comments, symbols, and pseudocode.

For us:

- Treat all binary-derived text as untrusted evidence, not instructions.
- Include provenance labels on every content block.
- Disable tool-origin ambiguity: strict schemas, read-only annotations, explicit write confirmations.
- Add capability attestation: server version, enabled backends, binary hashes, tool allowlist, write gates.
- Add red-team tests with malicious strings/comments trying to inject instructions into the agent.

Placement: core MCP requirement before public release.

## Tooling Lessons

### Ghidra

Useful ideas:

- Headless analyzer for automation at scale.
- P-code as a stable IR for data-flow analysis.
- BSim for behavior-level function similarity.
- Version Tracking for structured match triage and markup transfer.

What to copy:

- Validation before diff/version tracking.
- Cursor/pagination for large outputs.
- Separated project/session state.

What not to copy blindly:

- Huge tool surfaces. Too many tools increase model confusion and MCP attack surface.

### IDA

Useful ideas:

- FLIRT-style library identification.
- Lumina-style metadata reuse.
- Microcode/decompiler IR inspection.
- Rich metadata transfer including comments, prototypes, stack variables, operand representations.

What to copy:

- Metadata repository with quality scoring and history.
- Function-identification pipeline that distinguishes library code from analyst-worthy code.

What not to copy blindly:

- Silent metadata overwrite. Use transactions and previews.

### Binary Ninja

Useful ideas:

- Tiered IL model: LLIL, MLIL, HLIL.
- User-Informed Data Flow: analyst hints influence higher-level output.
- Pattern outlining for transforming low-level memory patterns into semantic calls.
- Strong API-first automation culture.

What to copy:

- Expose confidence and data-flow assumptions.
- Let users provide hints that improve future analysis.

What Hopper gap remains:

- Hopper does not expose a comparable stable public IL through MCP. We can compensate with derived features and optional companion IR engines, but should not fabricate an IR.

### radare2

Useful ideas:

- Composable command-line workflows.
- r2pipe simplicity.
- ESIL/emulation as a lightweight semantic layer.

What to copy:

- Scriptable pipelines and deterministic command logs.

What not to copy:

- Stringly-typed command APIs as the main MCP surface.

### Frida

Useful ideas:

- Runtime instrumentation and call summaries.
- Block/function execution tracing.
- Dynamic import/message-send observation.

What to copy:

- Optional trace import and static-dynamic reconciliation.

Boundary:

- Keep Frida as a separate dynamic backend/companion. It has a different security and permission model than Hopper.

### angr

Useful ideas:

- Explicit split between fast static CFG and slower symbolic/emulated CFG.
- Path exploration for reachability questions.
- Backward slicing and symbolic input discovery.

What to copy:

- Offer "prove/reach/slice" workflows as optional expensive tools with caps and timeouts.

Boundary:

- Do not make symbolic execution a default MCP path. It is expensive and failure-prone.

## Recommended Product Shape

### Core Hopper MCP

Build into `hopper-mcpd`:

- Strict official/live backend client.
- Cursor-paginated resources.
- Provenance everywhere.
- Transaction-gated writes.
- Version tracking/diff sessions.
- Function similarity with explainable feature scores.
- Hypothesis graph.
- Trust scoring for decompiler output.
- MCP security hardening and malicious-evidence tests.

### Hopper Companion Workbench

Separate process/service:

- Function knowledge base.
- Capability rule engine.
- Dynamic trace ingest from Frida.
- Optional Ghidra/angr/radare2 cross-check runners.
- Corpus indexing and search.
- YARA/capa/Sigma export/import.

This should not be mandatory for basic Hopper MCP use.

### Private Hopper Agent

Use only where official/Python backends cannot provide enough data:

- Stable document IDs.
- Faster batch reads.
- Richer Objective-C/Swift metadata.
- Lower-latency current-document operations.
- Potential private CFG/decompiler internals if selector probing is reliable.

## Prioritized Roadmap

1. Official backend client with live cassettes and strict normalization.
2. Cursor/pagination plus provenance labels for all large results.
3. Explainable function fingerprint v2.
4. Version tracking sessions with transaction-gated markup transfer.
5. Hypothesis graph and evidence anchors.
6. Capability rule overlay using Hopper-derived features.
7. Knowledge base for metadata reuse across binaries.
8. Frida trace import and static-dynamic reconciliation.
9. Optional symbolic/slicing companion integration.
10. Private Objective-C++ agent only after safe backends and mock wire protocol are stable.

## Rejection Criteria

Do not build an idea if:

- It requires treating decompiler pseudocode as authoritative.
- It requires unbounded output in MCP responses.
- It cannot label provenance.
- It writes into Hopper without transaction preview.
- It requires private injection for functionality that the official XPC or Python backend already provides.
- It turns the MCP into a generic shell over `otool`, `r2`, or arbitrary commands.

## Sources

- Ghidra BSim documentation: `https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_Intro.html`
- Ghidra Version Tracking documentation: `https://ghidradocs.com/9.0.2_PUBLIC/docs/GhidraClass/Intermediate/VersionTracking.html`
- Ghidra P-Code reference: `https://ghidra.re/ghidra_docs/languages/html/pcoderef.html`
- Binary Ninja MLIL documentation: `https://docs.binary.ninja/dev/bnil-mlil.html`
- Binary Ninja User-Informed Data Flow: `https://docs.binary.ninja/dev/uidf.html`
- IDA Lumina server documentation: `https://docs.hex-rays.com/admin-guide/lumina-server`
- IDA FLIRT documentation: `https://docs.hex-rays.com/8.4/user-guide/signatures/flirt`
- radare2 r2pipe: `https://www.radare.org/n/r2pipe.html`
- Official radare2 book: `https://book.rada.re/`
- Frida Stalker documentation: `https://frida.re/docs/stalker/`
- angr CFG documentation: `https://api.angr.io/en/latest/analyses/cfg.html`
- Mandiant capa: `https://mandiant.github.io/capa/`
- YARA documentation: `https://yara.readthedocs.io/en/latest/`
- Sigma rule format: `https://sigmahq.io/sigma/`
- GhidraMCP listing: `https://mcpservers.org/servers/themixednuts/GhidraMCP`
- Binary Ninja MCP: `https://github.com/fosdickio/binary_ninja_mcp`
- BinAssistMCP: `https://github.com/symgraph/BinAssistMCP`
- ReVa Ghidra MCP: `https://github.com/cyberkaida/reverse-engineering-assistant`
- Function similarity benchmark: `https://proceedings.neurips.cc/paper_files/paper/2024/file/2663c994c84a79b338bca613fe1ae223-Paper-Datasets_and_Benchmarks_Track.pdf`
- Bin2Wrong decompiler testing: `https://www.usenix.org/system/files/atc25-yang-zao.pdf`
- MCP security analysis: `https://arxiv.org/abs/2601.17549`
- MCPShield: `https://arxiv.org/abs/2602.14281`
- QBinDiff/network-alignment diffing: `https://arxiv.org/abs/2112.15337`
