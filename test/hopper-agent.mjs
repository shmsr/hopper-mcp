import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("Objective-C++ hopper-agent speaks the hopper-wire handshake and current_document protocol", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);
  const builtDaemon = await run("cargo", ["build", "-p", "hopper-mcpd"]);
  assert.equal(builtDaemon.code, 0, builtDaemon.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-test-"));
  const socket = join(temp, "hopper-agent.sock");
  const child = spawn("target/release/hopper-agent", [
    "--socket",
    socket,
    "--fixture",
    "--fixture-document-id",
    "doc-agent",
    "--fixture-document-name",
    "AgentFixture",
    "--fixture-procedure",
    "0x2000:agent_func:32",
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForSocket(socket);
    const client = await connect(socket);
    client.write(`${JSON.stringify({
      type: "handshake",
      wireVersion: 1,
      daemonVersion: "test-daemon",
    })}\n`);
    const handshake = await readJsonLine(client);
    assert.equal(handshake.type, "handshake");
    assert.equal(handshake.accepted, true);
    assert.equal(handshake.wireVersion, 1);
    assert.equal(handshake.capabilities.currentDocument, true);

    client.write(`${JSON.stringify({ type: "current_document" })}\n`);
    const document = await readJsonLine(client);
    assert.deepEqual(document, {
      type: "current_document",
      documentId: "doc-agent",
      name: "AgentFixture",
    });
    client.write(`${JSON.stringify({ type: "list_procedures", maxResults: 10 })}\n`);
    const procedures = await readJsonLine(client);
    assert.equal(procedures.type, "procedures");
    assert.deepEqual(procedures.procedures, [{
      addr: "0x2000",
      name: "agent_func",
      size: 32,
    }]);
    assert.equal(procedures.truncated, false);
    client.end();
  } finally {
    child.kill("SIGTERM");
    await onceClose(child);
    await rm(temp, { recursive: true, force: true });
  }

  assert.equal(child.exitCode === 0 || child.signalCode === "SIGTERM", true, stderr);
});

test("hopper-agent real mode bridges current document and procedures through an official MCP command", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-official-test-"));
  const socket = join(temp, "hopper-agent.sock");
  const fakeOfficial = join(temp, "fake-official.mjs");
  await writeFile(fakeOfficial, fakeOfficialMcpServer(), "utf8");
  await chmod(fakeOfficial, 0o755);

  const child = spawn("target/release/hopper-agent", [
    "--socket",
    socket,
    "--official-mcp-command",
    fakeOfficial,
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForSocket(socket);
    const client = await connect(socket);
    client.write(`${JSON.stringify({
      type: "handshake",
      wireVersion: 1,
      daemonVersion: "test-daemon",
    })}\n`);
    const handshake = await readJsonLine(client);
    assert.equal(handshake.type, "handshake");
    assert.equal(handshake.accepted, true);
    assert.equal(handshake.capabilities.currentDocument, true);
    assert.equal(handshake.capabilities.procedures, true);

    client.write(`${JSON.stringify({ type: "current_document" })}\n`);
    const document = await readJsonLine(client);
    assert.deepEqual(document, {
      type: "current_document",
      documentId: "OfficialDoc",
      name: "OfficialDoc",
    });

    client.write(`${JSON.stringify({ type: "list_procedures", maxResults: 1 })}\n`);
    const procedures = await readJsonLine(client);
    assert.equal(procedures.type, "procedures");
    assert.deepEqual(procedures.procedures, [{
      addr: "0x1000",
      name: "official_main",
      size: 64,
    }]);
    assert.equal(procedures.truncated, true);
    client.end();
  } finally {
    child.kill("SIGTERM");
    await onceClose(child);
    await rm(temp, { recursive: true, force: true });
  }

  assert.equal(child.exitCode === 0 || child.signalCode === "SIGTERM", true, stderr);
});

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

    client.write(`${JSON.stringify({ type: "list_procedures", maxResults: 10 })}\n`);
    const procedures = await readJsonLine(client);
    assert.equal(procedures.type, "procedures");
    assert.deepEqual(procedures.procedures, [{
      addr: "0x3000",
      name: "injected_main",
      size: 48,
    }]);
    assert.equal(procedures.truncated, false);
    client.end();
  } finally {
    child.kill("SIGTERM");
    await onceClose(child);
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-agent rejects fixture-injected provider combined with fixture mode", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-invalid-provider-test-"));
  const socket = join("/tmp", `hpa-invalid-${process.pid}-${Date.now()}.sock`);

  try {
    const result = await runWithTimeout("target/release/hopper-agent", [
      "--socket",
      socket,
      "--fixture",
      "--private-provider",
      "fixture-injected",
    ], 1000);
    assert.notEqual(result.code, 0);
    assert.equal(result.timedOut, false, `process unexpectedly kept running: ${result.stderr}`);
    assert.match(result.stderr, /fixture-injected/);
  } finally {
    await rm(socket, { force: true }).catch(() => {});
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-agent real mode returns structured errors instead of fixture data when official MCP has no document", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-no-doc-test-"));
  const socket = join(temp, "hopper-agent.sock");
  const fakeOfficial = join(temp, "fake-official-no-doc.mjs");
  await writeFile(fakeOfficial, fakeOfficialMcpServer({ noDocument: true }), "utf8");
  await chmod(fakeOfficial, 0o755);

  const child = spawn("target/release/hopper-agent", [
    "--socket",
    socket,
    "--official-mcp-command",
    fakeOfficial,
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForSocket(socket);
    const client = await connect(socket);
    client.write(`${JSON.stringify({
      type: "handshake",
      wireVersion: 1,
      daemonVersion: "test-daemon",
    })}\n`);
    const handshake = await readJsonLine(client);
    assert.equal(handshake.accepted, true);

    client.write(`${JSON.stringify({ type: "current_document" })}\n`);
    const response = await readJsonLine(client);
    assert.equal(response.type, "error");
    assert.equal(response.code, "official_mcp_failed");
    assert.match(response.message, /No document/);
    client.end();
  } finally {
    child.kill("SIGTERM");
    await onceClose(child);
    await rm(temp, { recursive: true, force: true });
  }

  assert.equal(child.exitCode === 0 || child.signalCode === "SIGTERM", true, stderr);
});

test("hopper-mcpd ingests current document through the Objective-C++ private agent", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-daemon-test-"));
  const socket = join("/tmp", `hpa-daemon-${process.pid}-${Date.now()}.sock`);
  const agent = spawn("target/release/hopper-agent", [
    "--socket",
    socket,
    "--fixture",
    "--fixture-document-id",
    "doc-private-agent",
    "--fixture-document-name",
    "PrivateAgentDoc",
    "--fixture-procedure",
    "0x2000:agent_func:32",
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let agentStderr = "";
  agent.stderr.on("data", (chunk) => {
    agentStderr += chunk.toString();
  });

  const daemon = spawn("target/debug/hopper-mcpd", [], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOPPER_MCP_PRIVATE_AGENT_SOCKET: socket,
      HOPPER_MCP_STORE: join(temp, "store.json"),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let daemonStderr = "";
  daemon.stderr.on("data", (chunk) => {
    daemonStderr += chunk.toString();
  });

  try {
    await waitForSocket(socket);
    daemon.stdin.write(`${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "ingest_current_hopper",
        arguments: { backend: "private" },
      },
    })}\n`);
    const response = await readJsonLine(daemon.stdout, 5000);
    assert.equal(response.error, undefined, daemonStderr);
    assert.equal(response.result.structuredContent.sessionId, "live-doc-private-agent");
    assert.equal(response.result.structuredContent.binary.name, "PrivateAgentDoc");
    assert.equal(response.result.structuredContent.counts.functions, 1);

    daemon.stdin.write(`${JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "procedure",
        arguments: { field: "info", procedure: "0x2000" },
      },
    })}\n`);
    const procedure = await readJsonLine(daemon.stdout, 5000);
    assert.equal(procedure.error, undefined, daemonStderr);
    assert.equal(procedure.result.structuredContent.name, "agent_func");
    assert.equal(procedure.result.structuredContent.size, 32);
  } finally {
    daemon.kill("SIGTERM");
    agent.kill("SIGTERM");
    await Promise.all([onceClose(daemon), onceClose(agent)]);
    await rm(socket, { force: true }).catch(() => {});
    await rm(temp, { recursive: true, force: true });
  }

  assert.equal(agent.exitCode === 0 || agent.signalCode === "SIGTERM", true, agentStderr);
});

test("hopper-agent plugin-service mode bridges current document and procedures through a distributed fixture service", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-agent-plugin-service-test-"));
  const socket = join("/tmp", `hpa-plugin-${process.pid}-${Date.now()}.sock`);
  const serviceName = `dev.hopper-mcp.test.${process.pid}.${Date.now()}`;

  const service = spawn("target/release/hopper-agent", [
    "--service-fixture-name",
    serviceName,
    "--fixture-document-id",
    "doc-plugin-service",
    "--fixture-document-name",
    "PluginServiceDoc",
    "--fixture-procedure",
    "0x3000:plugin_entry:48",
    "--fixture-procedure",
    "0x3010:plugin_helper:16",
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serviceStderr = "";
  service.stderr.on("data", (chunk) => {
    serviceStderr += chunk.toString();
  });

  const child = spawn("target/release/hopper-agent", [
    "--socket",
    socket,
    "--plugin-service",
    serviceName,
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForSocket(socket, 15_000);
    const client = await connect(socket);
    client.write(`${JSON.stringify({
      type: "handshake",
      wireVersion: 1,
      daemonVersion: "test-daemon",
    })}\n`);
    const handshake = await readJsonLine(client);
    assert.equal(handshake.type, "handshake");
    assert.equal(handshake.accepted, true);
    assert.equal(handshake.capabilities.currentDocument, true);
    assert.equal(handshake.capabilities.procedures, true);

    client.write(`${JSON.stringify({ type: "current_document" })}\n`);
    const document = await readJsonLine(client);
    assert.deepEqual(document, {
      type: "current_document",
      documentId: "doc-plugin-service",
      name: "PluginServiceDoc",
    });

    client.write(`${JSON.stringify({ type: "list_procedures", maxResults: 1 })}\n`);
    const procedures = await readJsonLine(client);
    assert.equal(procedures.type, "procedures");
    assert.deepEqual(procedures.procedures, [{
      addr: "0x3000",
      name: "plugin_entry",
      size: 48,
    }]);
    assert.equal(procedures.truncated, true);
    client.end();
  } finally {
    child.kill("SIGTERM");
    service.kill("SIGTERM");
    await Promise.all([onceClose(child), onceClose(service)]);
    await rm(socket, { force: true }).catch(() => {});
    await rm(temp, { recursive: true, force: true });
  }

  assert.equal(child.exitCode === 0 || child.signalCode === "SIGTERM", true, stderr);
  assert.equal(service.exitCode === 0 || service.signalCode === "SIGTERM", true, serviceStderr);
});

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function runWithTimeout(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal, stdout, stderr, timedOut });
    });
  });
}

function fakeOfficialMcpServer({ noDocument = false } = {}) {
  return `#!/usr/bin/env node
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "initialize") {
    respond(message.id, { protocolVersion: message.params.protocolVersion, capabilities: {}, serverInfo: { name: "fake", version: "1" } });
    return;
  }
  if (message.method === "tools/call") {
    const name = message.params.name;
    if (${JSON.stringify(noDocument)} && name === "current_document") {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32000, message: "No document" } }) + "\\n");
      return;
    }
    if (name === "current_document") {
      respond(message.id, text("OfficialDoc"));
      return;
    }
    if (name === "list_procedure_size") {
      respond(message.id, text({
        "0x1000": { name: "official_main", size: 64, basicblock_count: 3 },
        "0x2000": { name: "helper", length: 12, basicblock_count: 1 },
      }));
      return;
    }
    respond(message.id, text(null));
    return;
  }
  respond(message.id, {});
});
function text(value) {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] };
}
function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\\n");
}
`;
}

async function waitForSocket(socket, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(socket)) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for socket: ${socket}`);
}

function connect(socket) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socket);
    client.once("connect", () => resolve(client));
    client.once("error", reject);
  });
}

function readJsonLine(client, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for JSON line; buffered=${JSON.stringify(buffer)}`));
    }, timeoutMs);
    const onData = (chunk) => {
      buffer += chunk.toString();
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      cleanup();
      resolve(JSON.parse(buffer.slice(0, newline)));
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error(`stream closed before JSON line; buffered=${JSON.stringify(buffer)}`));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      client.off("data", onData);
      client.off("error", onError);
      client.off("close", onClose);
      client.off("end", onClose);
    };
    client.on("data", onData);
    client.on("error", onError);
    client.on("close", onClose);
    client.on("end", onClose);
  });
}

function onceClose(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
    } else {
      child.once("close", resolve);
    }
  });
}
