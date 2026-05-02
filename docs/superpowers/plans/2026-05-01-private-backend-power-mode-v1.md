# Private Backend Power Mode v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> Revision note: the final shipped v1 private backend kept the gate structure
> and `hopper-wire` contract from this plan, but the original
> `DYLD_INSERT_LIBRARIES` injection runtime was abandoned after Hopper proved
> unstable under launch-time injection. The supported implementation uses the
> Hopper Tool Plugin to host the private socket server inside Hopper instead.

**Goal:** Add a first production private Hopper backend lane for SIP-disabled systems without destabilizing the existing official/public path.

**Architecture:** Keep `hopper-mcpd` as the only MCP server and extend the existing `hopper-wire` boundary so the daemon can talk to a provider-aware native agent. The first slice adds explicit private-lane state and diagnostics, introduces a provider split inside `hopper-agent`, and lands a minimal injected read-only path with its own release gate.

**Tech Stack:** Rust (`hopper-mcpd`, `hopper-wire`, contract tests), Objective-C++ (`hopper-agent`), Node test/runtime wrappers, Unix sockets, gated Hopper live checks on SIP-disabled macOS hosts.

---

### File Map

**Create:**
- `crates/hopper-wire/tests/private_backend_contract.rs`
- `agents/hopper-agent/src/provider.hh`
- `agents/hopper-agent/src/provider.mm`
- `agents/hopper-agent/src/injector.hh`
- `agents/hopper-agent/src/injector.mm`
- `scripts/private-backend-check.mjs`
- `test/private-backend-check.mjs`

**Modify:**
- `crates/hopper-wire/src/lib.rs`
- `crates/hopper-mcpd/src/backend.rs`
- `crates/hopper-mcpd/src/tools.rs`
- `crates/hopper-mcpd/src/doctor.rs`
- `crates/hopper-mcpd/tests/backend_contract.rs`
- `crates/hopper-mcpd/tests/doctor_contract.rs`
- `agents/hopper-agent/Makefile`
- `agents/hopper-agent/src/main.mm`
- `test/hopper-agent.mjs`
- `test/release-scripts.mjs`
- `package.json`
- `README.md`
- `CONTRIBUTING.md`

---

### Task 1: Extend `hopper-wire` For Explicit Private-Lane State

**Files:**
- Modify: `crates/hopper-wire/src/lib.rs`
- Create: `crates/hopper-wire/tests/private_backend_contract.rs`

- [ ] **Step 1: Write the failing wire-contract test**

Create `crates/hopper-wire/tests/private_backend_contract.rs` with:

```rust
use hopper_wire::{
    AgentCapabilities, AgentRequest, AgentResponse, AgentStatus, BackendMode,
    ReadinessState, WireProcedure, decode, encode,
};

#[test]
fn wire_status_round_trips_private_backend_metadata() {
    let message = AgentResponse::Status(AgentStatus {
        backend_mode: BackendMode::InjectedPrivate,
        readiness: ReadinessState::Ready,
        hopper_version: Some("6.2.8".to_string()),
        hopper_build: Some("stable".to_string()),
        capabilities: AgentCapabilities {
            current_document: true,
            procedures: true,
            writes: false,
            private_api: true,
            injected: true,
            status: true,
        },
        unsupported_reason: None,
    });

    let text = encode(&message).unwrap();
    let decoded: AgentResponse = decode(&text).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn wire_request_round_trips_status_query() {
    let message = AgentRequest::Status;
    let text = encode(&message).unwrap();
    let decoded: AgentRequest = decode(&text).unwrap();
    assert_eq!(decoded, message);
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
cargo test -p hopper-wire --test private_backend_contract
```

Expected: fail because `AgentStatus`, `BackendMode`, `ReadinessState`, and
`AgentRequest::Status` do not exist yet.

- [ ] **Step 3: Extend the wire types**

In `crates/hopper-wire/src/lib.rs`, add:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    Fixture,
    OfficialMcp,
    PluginBridge,
    InjectedPrivate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Unavailable,
    Injecting,
    Ready,
    Analyzing,
    NoDocument,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    pub backend_mode: BackendMode,
    pub readiness: ReadinessState,
    pub hopper_version: Option<String>,
    pub hopper_build: Option<String>,
    pub capabilities: AgentCapabilities,
    pub unsupported_reason: Option<String>,
}
```

Extend `AgentCapabilities` and the request/response enums:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    pub current_document: bool,
    pub procedures: bool,
    pub writes: bool,
    pub private_api: bool,
    pub injected: bool,
    pub status: bool,
}

pub enum AgentRequest {
    Handshake(HandshakeRequest),
    Status,
    CurrentDocument,
    ListProcedures { max_results: Option<u64> },
}

pub enum AgentResponse {
    Handshake(HandshakeResponse),
    Status(AgentStatus),
    CurrentDocument { document_id: String, name: String },
    Procedures { procedures: Vec<WireProcedure>, truncated: bool },
    Error { code: String, message: String },
}
```

- [ ] **Step 4: Re-run the wire-contract test**

Run:

```bash
cargo test -p hopper-wire --test private_backend_contract
```

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/hopper-wire/src/lib.rs crates/hopper-wire/tests/private_backend_contract.rs
git commit -m "wire: add private backend status contract"
```

Expected: commit succeeds with only the wire changes staged.

---

### Task 2: Surface Provider State In The Rust Backend And Tool Contracts

**Files:**
- Modify: `crates/hopper-mcpd/src/backend.rs`
- Modify: `crates/hopper-mcpd/src/tools.rs`
- Modify: `crates/hopper-mcpd/tests/backend_contract.rs`

- [ ] **Step 1: Write the failing backend-diagnostics test**

Add this test to `crates/hopper-mcpd/tests/backend_contract.rs`:

```rust
#[test]
fn backend_diagnostics_reports_private_backend_mode_and_readiness() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("hopper-agent.sock");
    let server = start_status_agent(
        &socket,
        hopper_wire::BackendMode::InjectedPrivate,
        hopper_wire::ReadinessState::Ready,
    );
    let mut daemon = Daemon::with_backend(Box::new(UnixWireBackend::new(&socket)));

    let diagnostics = call(&mut daemon, "backend_diagnostics", json!({}));

    assert_eq!(diagnostics["backend"], "private");
    assert_eq!(diagnostics["backendMode"], "injected_private");
    assert_eq!(diagnostics["readiness"], "ready");
    assert_eq!(diagnostics["capabilities"]["privateApi"], true);
    assert_eq!(diagnostics["capabilities"]["injected"], true);
    server.join().unwrap();
}
```

- [ ] **Step 2: Run the focused backend-contract test**

Run:

```bash
cargo test -p hopper-mcpd backend_diagnostics_reports_private_backend_mode_and_readiness
```

Expected: fail because `backend_diagnostics` does not expose provider mode or
readiness.

- [ ] **Step 3: Extend backend status/diagnostics**

In `crates/hopper-mcpd/src/backend.rs`, add a richer status model:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub current_document: bool,
    pub procedures: bool,
    pub writes: bool,
    pub private_api: bool,
    pub injected: bool,
    pub status: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatus {
    pub name: String,
    pub available: bool,
    pub reason: Option<String>,
    pub backend_mode: Option<String>,
    pub readiness: Option<String>,
    pub hopper_version: Option<String>,
    pub hopper_build: Option<String>,
    pub capabilities: Option<BackendCapabilities>,
}
```

Teach `UnixWireBackend::status()` to send `AgentRequest::Status` after a
successful handshake and translate the `AgentStatus` response into this richer
status object.

In `crates/hopper-mcpd/src/tools.rs`, return the new fields from
`backend_status()` and `backend_diagnostics()`:

```rust
json!({
    "backend": status.name,
    "available": status.available,
    "reason": status.reason,
    "backendMode": status.backend_mode,
    "readiness": status.readiness,
    "hopperVersion": status.hopper_version,
    "hopperBuild": status.hopper_build,
    "capabilities": status.capabilities,
    "wireVersion": hopper_wire::WIRE_VERSION,
    "liveBridge": live_bridge.status(),
})
```

- [ ] **Step 4: Re-run the focused test and the backend contract file**

Run:

```bash
cargo test -p hopper-mcpd backend_diagnostics_reports_private_backend_mode_and_readiness
cargo test -p hopper-mcpd --test backend_contract
```

Expected: both pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/hopper-mcpd/src/backend.rs crates/hopper-mcpd/src/tools.rs crates/hopper-mcpd/tests/backend_contract.rs
git commit -m "mcp: expose private backend readiness diagnostics"
```

Expected: commit succeeds with daemon/backend changes only.

---

### Task 3: Split `hopper-agent` Into Providers And Add Minimal Injected Mode

**Files:**
- Create: `agents/hopper-agent/src/provider.hh`
- Create: `agents/hopper-agent/src/provider.mm`
- Create: `agents/hopper-agent/src/injector.hh`
- Create: `agents/hopper-agent/src/injector.mm`
- Modify: `agents/hopper-agent/src/main.mm`
- Modify: `agents/hopper-agent/Makefile`
- Modify: `test/hopper-agent.mjs`

- [ ] **Step 1: Write the failing injected-mode test**

Add this test to `test/hopper-agent.mjs`:

```js
test("hopper-agent injected mode reports injected private status before serving document data", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-injected-test-"));
  const socket = join(temp, "hopper-agent.sock");
  const child = spawn("target/release/hopper-agent", [
    "--socket",
    socket,
    "--private-provider",
    "fixture-injected",
    "--fixture-document-id",
    "doc-injected",
    "--fixture-document-name",
    "InjectedDoc",
    "--fixture-procedure",
    "0x3000:injected_main:48",
  ], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });

  try {
    await waitForSocket(socket);
    const client = await connect(socket);
    client.write(`${JSON.stringify({ type: "handshake", wireVersion: 1, daemonVersion: "test-daemon" })}\n`);
    const handshake = await readJsonLine(client);
    assert.equal(handshake.accepted, true);

    client.write(`${JSON.stringify({ type: "status" })}\n`);
    const status = await readJsonLine(client);
    assert.equal(status.type, "status");
    assert.equal(status.backendMode, "injected_private");
    assert.equal(status.readiness, "ready");
    assert.equal(status.capabilities.privateApi, true);
    assert.equal(status.capabilities.injected, true);

    client.write(`${JSON.stringify({ type: "current_document" })}\n`);
    const document = await readJsonLine(client);
    assert.equal(document.documentId, "doc-injected");
    client.end();
  } finally {
    child.kill("SIGTERM");
    await onceClose(child);
    await rm(temp, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run the focused Node test and verify it fails**

Run:

```bash
node --test test/hopper-agent.mjs --test-name-pattern "injected mode reports injected private status"
```

Expected: fail because `hopper-agent` does not support `--private-provider` or
the `status` request.

- [ ] **Step 3: Refactor provider logic out of `main.mm`**

Create `agents/hopper-agent/src/provider.hh`:

```objc
@class NSString;
@class NSDictionary;
@class NSNumber;

struct AgentStatusRecord {
  std::string backend_mode;
  std::string readiness;
  bool private_api = false;
  bool injected = false;
};

class EvidenceProvider {
 public:
  virtual ~EvidenceProvider() = default;
  virtual NSDictionary *Status(NSString **error) = 0;
  virtual NSDictionary *CurrentDocument(NSString **error) = 0;
  virtual NSDictionary *Procedures(NSUInteger max_results, NSString **error) = 0;
};
```

Create `agents/hopper-agent/src/injector.hh` with the initial minimal injector
surface:

```objc
class HopperInjector {
 public:
  explicit HopperInjector(const Options &options);
  bool EnsureInjected(NSString **error);
  NSDictionary *Status() const;
  NSDictionary *CurrentDocument(NSString **error) const;
  NSDictionary *Procedures(NSUInteger max_results, NSString **error) const;
};
```

Update `agents/hopper-agent/Makefile` so all `.mm` files build:

```make
SRC := src/main.mm src/provider.mm src/injector.mm

$(OUT): $(SRC)
	mkdir -p "$(dir $(OUT))"
	clang++ -std=c++17 -Wall -Wextra -Werror -Wno-deprecated-declarations -ObjC++ -framework Foundation $(SRC) -o "$(OUT)"
```

- [ ] **Step 4: Implement `fixture-injected` as the first minimal injected lane**

In `agents/hopper-agent/src/main.mm`, add a provider selection flag:

```objc
struct Options {
  std::string socket_path;
  std::string private_provider = "official";
  std::string document_id = "fixture-document";
  std::string document_name = "Fixture";
  std::vector<Procedure> procedures;
  std::string plugin_service_name;
  std::string service_fixture_name;
  std::string official_mcp_command =
      "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer";
  int official_timeout_ms = kOfficialProtocolTimeoutMs;
  bool fixture_mode = false;
};
```

Parse:

```objc
} else if (arg == "--private-provider") {
  const char *value = require_value("--private-provider");
  if (value == nullptr) return false;
  options->private_provider = value;
}
```

Implement request handling through `EvidenceProvider` with a first
`fixture-injected` provider that:

```objc
Status => {
  @"backendMode": @"injected_private",
  @"readiness": @"ready",
  @"hopperVersion": @"fixture",
  @"capabilities": @{
    @"currentDocument": @YES,
    @"procedures": @YES,
    @"writes": @NO,
    @"privateApi": @YES,
    @"injected": @YES,
    @"status": @YES,
  }
}
```

and serves document/procedure data without going through the official MCP
subprocess.

- [ ] **Step 5: Re-run the focused test and full `hopper-agent` suite**

Run:

```bash
node --test test/hopper-agent.mjs --test-name-pattern "injected mode reports injected private status"
node --test test/hopper-agent.mjs
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add agents/hopper-agent/Makefile agents/hopper-agent/src/main.mm agents/hopper-agent/src/provider.hh agents/hopper-agent/src/provider.mm agents/hopper-agent/src/injector.hh agents/hopper-agent/src/injector.mm test/hopper-agent.mjs
git commit -m "hopper: add provider-aware private agent mode"
```

Expected: commit succeeds with native-agent and test changes only.

---

### Task 4: Wire Private-Lane Readiness Into `doctor` And A Dedicated Release Gate

**Files:**
- Modify: `crates/hopper-mcpd/src/doctor.rs`
- Modify: `crates/hopper-mcpd/tests/doctor_contract.rs`
- Create: `scripts/private-backend-check.mjs`
- Create: `test/private-backend-check.mjs`
- Modify: `test/release-scripts.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write the failing doctor-contract test**

Add this test to `crates/hopper-mcpd/tests/doctor_contract.rs`:

```rust
#[test]
fn doctor_reports_private_lane_prerequisites_when_required() {
    let report = run_doctor(&DoctorOptions {
        require_hopper: false,
        require_plugin_identity: false,
        require_distribution_identity: false,
        require_notary_credentials: false,
        require_clean_git_tree: false,
        require_private_backend: true,
        ..DoctorOptions::from_env()
    });

    let private_check = report
        .checks
        .iter()
        .find(|check| check.name == "privateBackendReady")
        .expect("missing privateBackendReady check");
    assert!(matches!(private_check.status, DoctorStatus::Warn | DoctorStatus::Fail));
}
```

- [ ] **Step 2: Run the focused doctor-contract test**

Run:

```bash
cargo test -p hopper-mcpd doctor_reports_private_lane_prerequisites_when_required
```

Expected: fail because `require_private_backend` and `privateBackendReady` do
not exist.

- [ ] **Step 3: Add private-backend doctor support and gate wrapper**

Extend `DoctorOptions` and `run_doctor()` in
`crates/hopper-mcpd/src/doctor.rs`:

```rust
pub struct DoctorOptions {
    pub store_path: PathBuf,
    pub node_command: OsString,
    pub git_command: OsString,
    pub security_command: OsString,
    pub live_bridge_script: PathBuf,
    pub hopper_app: PathBuf,
    pub private_agent_socket: Option<PathBuf>,
    pub require_hopper: bool,
    pub require_plugin_identity: bool,
    pub require_distribution_identity: bool,
    pub require_notary_credentials: bool,
    pub require_clean_git_tree: bool,
    pub require_private_backend: bool,
}
```

Add:

```rust
fn check_private_backend_ready(required: bool) -> DoctorCheck {
    let sip_disabled = std::env::var("HOPPER_MCP_ASSUME_SIP_DISABLED").ok().as_deref() == Some("1");
    if sip_disabled {
        return DoctorCheck {
            name: "privateBackendReady",
            status: DoctorStatus::Pass,
            message: "private backend prerequisites explicitly enabled for this host".to_string(),
            remediation: None,
        };
    }

    DoctorCheck {
        name: "privateBackendReady",
        status: if required { DoctorStatus::Fail } else { DoctorStatus::Warn },
        message: "private injected backend requires a SIP-disabled host plus explicit injector setup".to_string(),
        remediation: Some("run the private gate only on a designated SIP-disabled Hopper machine and export HOPPER_MCP_ASSUME_SIP_DISABLED=1 for that runner".to_string()),
    }
}
```

Create `scripts/private-backend-check.mjs` that:

```js
1. runs `cargo run -p hopper-mcpd -- doctor --json --require-private-backend`
2. runs `npm run build:agent`
3. runs `node --test test/hopper-agent.mjs --test-name-pattern "injected mode reports injected private status"`
4. prints one final JSON object with `phase`
```

Add scripts to `package.json`:

```json
"release:check:private-backend": "node scripts/private-backend-check.mjs"
```

- [ ] **Step 4: Re-run doctor and wrapper tests**

Run:

```bash
cargo test -p hopper-mcpd --test doctor_contract
node --test test/private-backend-check.mjs test/release-scripts.mjs
```

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/hopper-mcpd/src/doctor.rs crates/hopper-mcpd/tests/doctor_contract.rs scripts/private-backend-check.mjs test/private-backend-check.mjs test/release-scripts.mjs package.json
git commit -m "repo: add private backend release gate"
```

Expected: commit succeeds with doctor/gate changes only.

---

### Task 5: Document The Private Power Lane And Re-Run The Production Checklist

**Files:**
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`

- [ ] **Step 1: Add README usage docs**

Document:

```md
### SIP-Off Private Backend Power Mode

This lane is explicit and separate from the signed public Hopper path.

- select with `backend: "private"`
- diagnose with `backend_status` and `backend_diagnostics`
- validate on a SIP-disabled host with `npm run --silent release:check:private-backend`
```

- [ ] **Step 2: Add contributor guidance**

Document in `CONTRIBUTING.md`:

```md
Run `npm run --silent release:check:private-backend` only on designated
SIP-disabled Hopper runners. Success here does not satisfy
`release:check:plugin-live`, `release:check:distribution`, or
`release:check:public-release`.
```

- [ ] **Step 3: Run the verification matrix**

Run:

```bash
node --test test/hopper-agent.mjs test/private-backend-check.mjs test/release-scripts.mjs
cargo test -p hopper-wire --test private_backend_contract
cargo test -p hopper-mcpd --test backend_contract --test doctor_contract
npm run --silent release:check
```

On a designated SIP-disabled Hopper host, also run:

```bash
npm run --silent release:check:private-backend
```

Expected:
- offline/unit/contract matrix passes locally
- non-live release gate stays green
- private-backend gate is green only on the designated SIP-disabled runner

- [ ] **Step 4: Commit**

Run:

```bash
git add README.md CONTRIBUTING.md
git commit -m "docs: document private backend power mode"
```

Expected: commit succeeds with documentation only.

---

### Self-Review Checklist

- [ ] Spec coverage: every approved design section maps to at least one task
  above.
- [ ] No placeholders: no `TODO`, `TBD`, or vague “handle it later” steps remain.
- [ ] Type consistency: `BackendMode`, `ReadinessState`, `AgentStatus`,
  `privateBackendReady`, and `release:check:private-backend` use the same names
  in code, tests, and docs.
