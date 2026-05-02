import test from "node:test";
import assert from "node:assert/strict";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

test("hopper-plugin-runtime derives the same service name from a socket path", async () => {
  const result = await run("node", [
    "scripts/hopper-plugin-runtime.mjs",
    "service-name",
    "--socket",
    "/tmp/hopper-plugin-live.sock",
  ]);
  assert.equal(result.code, 0, result.stderr);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.serviceName, "dev.hopper-mcp.plugin.-tmp-hopper-plugin-live-sock");
});

test("hopper-plugin-runtime parses codesigning identities through an injected security command", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const security = join(temp, "security");
    await writeFile(security, `#!/bin/sh
printf '  1) ABCDEF1234567890 "Apple Development: Example Dev (TEAM1234)"\\n'
printf '  2) 1234567890ABCDEF "Developer ID Application: Example Corp (TEAM5678)"\\n'
`, "utf8");
    await chmod(security, 0o755);

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "identities",
      "--security-command",
      security,
    ]);
    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.identities.length, 2);
    assert.equal(payload.identities[0].hash, "ABCDEF1234567890");
    assert.match(payload.identities[1].name, /Developer ID Application/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime installs the plugin bundle and signs it through an injected codesign command", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const source = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const codesign = join(temp, "codesign");
    const codesignLog = join(temp, "codesign.log");
    await mkdir(join(source, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(source, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(source, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(codesign, `#!/bin/sh
printf '%s\\n' "$@" >> ${JSON.stringify(codesignLog)}
`, "utf8");
    await chmod(codesign, 0o755);

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "install",
      "--plugin",
      source,
      "--dest-root",
      destRoot,
      "--codesign-command",
      codesign,
      "--identity",
      "Developer ID Application: Example Corp (TEAM5678)",
    ]);
    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    await readFile(join(destRoot, "HopperMCPAgent.hopperTool", "Contents", "MacOS", "Plugin"), "utf8");
    const signedArgs = await readFile(codesignLog, "utf8");
    assert.match(signedArgs, /--force/);
    assert.match(signedArgs, /Developer ID Application: Example Corp \(TEAM5678\)/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime install fails fast when no explicit signing mode is provided", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const source = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    await mkdir(join(source, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(source, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(source, "Contents", "MacOS", "Plugin"), "binary", "utf8");

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "install",
      "--plugin",
      source,
      "--dest-root",
      destRoot,
    ]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.match(payload.message, /explicit signing identity/i);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime install allows explicit ad-hoc signing when requested", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const source = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const codesign = join(temp, "codesign");
    const codesignLog = join(temp, "codesign.log");
    await mkdir(join(source, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(source, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(source, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(codesign, `#!/bin/sh
printf '%s\\n' "$@" >> ${JSON.stringify(codesignLog)}
`, "utf8");
    await chmod(codesign, 0o755);

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "install",
      "--plugin",
      source,
      "--dest-root",
      destRoot,
      "--codesign-command",
      codesign,
      "--ad-hoc",
    ]);
    assert.equal(result.code, 0, result.stderr);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.identity, "-");
    const signedArgs = await readFile(codesignLog, "utf8");
    assert.match(signedArgs, /\n-\n/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime install fails fast when the plugin links AppKit or Cocoa", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const source = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const otool = join(temp, "otool");
    await mkdir(join(source, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(source, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(source, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(otool, `#!/bin/sh
cat <<'EOF'
/tmp/Plugin:
\t/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
\t/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
EOF
`, "utf8");
    await chmod(otool, 0o755);

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "install",
      "--plugin",
      source,
      "--dest-root",
      destRoot,
      "--otool-command",
      otool,
      "--ad-hoc",
    ]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.phase, "pluginLinkage");
    assert.match(payload.message, /AppKit|Cocoa/i);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime probe fails fast when no valid codesigning identities are available", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const plugin = join(temp, "Source.hopperTool");
    const security = join(temp, "security");
    await mkdir(join(plugin, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(plugin, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(plugin, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(security, "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(security, 0o755);

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "probe",
      "--plugin",
      plugin,
      "--security-command",
      security,
    ]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.phase, "codesignIdentity");
    assert.match(payload.message, /no valid codesigning identities found/i);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime probe fails fast when the plugin links AppKit or Cocoa", async () => {
  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const plugin = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const otool = join(temp, "otool");
    await mkdir(join(plugin, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(plugin, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(plugin, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(otool, `#!/bin/sh
cat <<'EOF'
/tmp/Plugin:
\t/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa
EOF
`, "utf8");
    await chmod(otool, 0o755);

    const result = await run("node", [
      "scripts/hopper-plugin-runtime.mjs",
      "probe",
      "--plugin",
      plugin,
      "--dest-root",
      destRoot,
      "--otool-command",
      otool,
      "--skip-sign",
    ]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, false);
    assert.equal(payload.phase, "pluginLinkage");
    assert.match(payload.message, /AppKit|Cocoa/i);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime probe installs, launches, and verifies the plugin-service bridge with injected commands", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const plugin = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const launchScript = join(temp, "fake-hopper.sh");
    const launchEnvLog = join(temp, "launch-env.log");
    const socket = join("/tmp", `hopper-plugin-probe-${process.pid}-${Date.now()}.sock`);
    const serviceName = await serviceNameFor(socket);

    await mkdir(join(plugin, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(plugin, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(plugin, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(launchScript, `#!/bin/sh
printf '%s\n' "$HOPPER_MCP_PLUGIN_SOCKET" > ${JSON.stringify(launchEnvLog)}
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
`, "utf8");
    await chmod(launchScript, 0o755);

    const service = spawn("target/release/hopper-agent", [
      "--service-fixture-name",
      serviceName,
      "--fixture-document-id",
      "doc-probe",
      "--fixture-document-name",
      "ProbeFixture",
      "--fixture-procedure",
      "0x4000:probe_func:96",
    ], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let serviceStderr = "";
    service.stderr.on("data", (chunk) => {
      serviceStderr += chunk.toString();
    });

    try {
      const result = await run("node", [
        "scripts/hopper-plugin-runtime.mjs",
        "probe",
        "--plugin",
        plugin,
        "--dest-root",
        destRoot,
        "--skip-sign",
        "--socket",
        socket,
        "--agent-command",
        "target/release/hopper-agent",
        "--hopper-command",
        launchScript,
        "--target",
        "/bin/echo",
        "--timeout-ms",
        "15000",
      ]);
      assert.equal(result.code, 0, `${result.stderr}\n${serviceStderr}`);
      const payload = JSON.parse(result.stdout);
      assert.equal(payload.ok, true);
      assert.equal(payload.currentDocument.documentId, "doc-probe");
      assert.equal(payload.currentDocument.name, "ProbeFixture");
      assert.equal(payload.procedures.procedures[0].addr, "0x4000");
      assert.equal(payload.cleanup.agentTerminated, true);
      assert.equal(payload.cleanup.hopperTerminated, true);
      const loggedSocket = await readFile(launchEnvLog, "utf8");
      assert.equal(loggedSocket.trim(), socket);
      await readFile(join(destRoot, "HopperMCPAgent.hopperTool", "Contents", "MacOS", "Plugin"), "utf8");
    } finally {
      service.kill("SIGTERM");
      await onceClose(service);
      await rm(socket, { force: true }).catch(() => {});
    }

    assert.equal(service.exitCode === 0 || service.signalCode === "SIGTERM", true, serviceStderr);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("hopper-plugin-runtime probe propagates the plugin socket through launchctl for GUI Hopper launches", async () => {
  const built = await run("npm", ["run", "build:agent"]);
  assert.equal(built.code, 0, built.stderr);

  const temp = await mkdtemp(join(tmpdir(), "hopper-plugin-runtime-"));
  try {
    const plugin = join(temp, "Source.hopperTool");
    const destRoot = join(temp, "dest");
    const launchctlScript = join(temp, "fake-launchctl.sh");
    const launchctlLog = join(temp, "launchctl.log");
    const hopperScript = join(temp, "fake-hopper.sh");
    const socket = join("/tmp", `hopper-plugin-probe-${process.pid}-${Date.now()}-launchctl.sock`);
    const serviceName = await serviceNameFor(socket);

    await mkdir(join(plugin, "Contents", "MacOS"), { recursive: true });
    await writeFile(join(plugin, "Contents", "Info.plist"), "<plist/>", "utf8");
    await writeFile(join(plugin, "Contents", "MacOS", "Plugin"), "binary", "utf8");
    await writeFile(launchctlScript, `#!/bin/sh
printf '%s\\n' \"$*\" >> ${JSON.stringify(launchctlLog)}
`, "utf8");
    await chmod(launchctlScript, 0o755);
    await writeFile(hopperScript, `#!/bin/sh
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
`, "utf8");
    await chmod(hopperScript, 0o755);

    const service = spawn("target/release/hopper-agent", [
      "--service-fixture-name",
      serviceName,
      "--fixture-document-id",
      "doc-probe",
      "--fixture-document-name",
      "ProbeFixture",
      "--fixture-procedure",
      "0x4000:probe_func:96",
    ], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let serviceStderr = "";
    service.stderr.on("data", (chunk) => {
      serviceStderr += chunk.toString();
    });

    try {
      const result = await run("node", [
        "scripts/hopper-plugin-runtime.mjs",
        "probe",
        "--plugin",
        plugin,
        "--dest-root",
        destRoot,
        "--skip-sign",
        "--socket",
        socket,
        "--launchctl-command",
        launchctlScript,
        "--agent-command",
        "target/release/hopper-agent",
        "--hopper-command",
        hopperScript,
        "--target",
        "/bin/echo",
        "--timeout-ms",
        "15000",
      ]);
      assert.equal(result.code, 0, `${result.stderr}\n${serviceStderr}`);
      const launchctlCalls = await readFile(launchctlLog, "utf8");
      assert.match(launchctlCalls, new RegExp(`setenv HOPPER_MCP_PLUGIN_SOCKET ${socket.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
      assert.match(launchctlCalls, /unsetenv HOPPER_MCP_PLUGIN_SOCKET/);
    } finally {
      service.kill("SIGTERM");
      await onceClose(service);
      await rm(socket, { force: true }).catch(() => {});
    }

    assert.equal(service.exitCode === 0 || service.signalCode === "SIGTERM", true, serviceStderr);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
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

async function serviceNameFor(socket) {
  const result = await run("node", [
    "scripts/hopper-plugin-runtime.mjs",
    "service-name",
    "--socket",
    socket,
  ]);
  assert.equal(result.code, 0, result.stderr);
  return JSON.parse(result.stdout).serviceName;
}

function onceClose(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("close", resolve);
  });
}
