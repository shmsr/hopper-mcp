import { resolve } from "node:path";

export const DEFAULT_HOPPER_APP_COMMAND = "/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler";
export const DEFAULT_HOPPER_HELPER_COMMAND = "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper";

export function shouldUseLiveExportWarmup({
  hopperCommand,
  agentCommand,
  appCommand = DEFAULT_HOPPER_APP_COMMAND,
  helperCommand = DEFAULT_HOPPER_HELPER_COMMAND,
}) {
  if (agentCommand) return false;
  const resolved = resolve(String(hopperCommand || appCommand));
  return resolved === resolve(appCommand) || resolved === resolve(helperCommand);
}

export async function runPrivateLiveExportWarmup({
  socket,
  target,
  timeoutMs,
  loader,
  ingest,
  runCapture,
  helperCommand = DEFAULT_HOPPER_HELPER_COMMAND,
}) {
  let cleanedUp = false;
  const cleanupEnv = async () => {
    if (cleanedUp) return;
    cleanedUp = true;
    await unsetLaunchctlPrivateEnv({ runCapture });
  };

  await setLaunchctlPrivateEnv({ socket, target, runCapture });
  try {
    const live = await ingest({
      executablePath: target,
      hopperLauncher: helperCommand,
      analysis: false,
      loader,
      onlyProcedures: true,
      parseObjectiveC: true,
      parseSwift: true,
      parseExceptions: true,
      closeAfterExport: false,
      timeoutMs,
      maxFunctions: 10,
      maxStrings: 20,
    });
    return {
      liveLaunch: live.launch ?? null,
      cleanupEnv,
    };
  } catch (error) {
    await cleanupEnv().catch(() => {});
    throw error;
  }
}

export async function setLaunchctlPrivateEnv({ socket, target, runCapture }) {
  await runCapture("launchctl", ["setenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET", socket]);
  await runCapture("launchctl", ["setenv", "HOPPER_MCP_PRIVATE_TARGET", target]);
}

export async function unsetLaunchctlPrivateEnv({ runCapture }) {
  await runCapture("launchctl", ["unsetenv", "HOPPER_MCP_PRIVATE_AGENT_SOCKET"]).catch(() => {});
  await runCapture("launchctl", ["unsetenv", "HOPPER_MCP_PRIVATE_TARGET"]).catch(() => {});
}
