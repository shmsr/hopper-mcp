# Hopper Private API Feasibility Notes

Date: 2026-05-01

## Current Evidence

- `hopper-agent` now has two explicit modes:
  - `--fixture` for tests/package smoke only.
  - non-fixture mode that bridges real Hopper evidence through Hopper's bundled `HopperMCPServer` subprocess.
- The daemon-side private backend is a fail-closed `hopper-wire` Unix-socket client.
- Full release checks and live Hopper checks pass for the official-subprocess-backed path.

## Runtime Attach Attempt

- Frida MCP enumerated local devices and found the running Hopper process.
- Attach to `Hopper Disassembler` PID `74686` timed out.
- Attach to Hopper `ExternalAPI` XPC PID `34598` also timed out.
- No direct runtime injection/private API call path is verified from this session.

This means direct in-process private API mode must remain incomplete until an attach or plugin loading path is verified.

## Static Hopper Surface

Static inspection used `strings`, `nm`, and `otool` together. This was not used as a replacement for Hopper evidence in the MCP; it was only feasibility research.

Useful Objective-C/XPC selectors found in `ExternalAPI.xpc`:

- `documentListWithReply:`
- `currentDocumentWithReply:`
- `setCurrentDocument:withReply:`
- `segmentListWithReply:`
- `procedureListWithReply:`
- `procedureSizeListWithReply:`
- `procedureInfoListWithReply:`
- `stringListWithReply:`
- `addressOfProcedure:withReply:`
- `currentAddressWithReply:`
- `currentProcedureWithReply:`
- `gotoAddress:withReply:`
- `infoOfProcedure:withReply:`
- `asmOfProcedure:withReply:`
- `pseudoCodeOfProcedure:withReply:`
- `callersOfProcedure:withReply:`
- `calleesOfProcedure:withReply:`
- `referencesToAddress:withReply:`
- comment/name/bookmark/search setters and readers.

Useful Hopper app strings/classes:

- `HopperExternalAPI`
- `HopperServerAPI`
- `ExternalAPIProtocol`
- `DocumentHandler`
- `HopperPluginManager`
- `HopperPlugin`
- `PluginLoader`
- `PluginXPCProxy`
- `loadPluginsIncludingUserPlugins:`
- `instantiatePluginWithHopperServices:`
- `pluginIsSafe:error:`
- `pluginContainsIllegalInstructions:`
- `Looking for Tool plugins into %@`

## Best Next Direct-Private Route

The least brittle direct route is likely a Hopper Tool Plugin, not ad-hoc process injection:

1. Build a minimal signed Hopper Tool Plugin that conforms to `HopperPlugin`.
2. Let Hopper load it through its normal `PluginLoader`/plugin safety path.
3. Inside the plugin, expose the same `hopper-wire` Unix socket that `hopper-agent` currently exposes.
4. Reuse the existing Rust daemon private backend unchanged.
5. Add live tests that start Hopper with the plugin installed, configure `HOPPER_MCP_PRIVATE_AGENT_SOCKET`, and verify `ingest_current_hopper backend: private` without `HopperMCPServer`.

This preserves the clean architecture: MCP protocol stays in `hopper-mcpd`, Hopper process code stays behind `hopper-wire`, and fixture data remains test-only.

## Current Blockers

- The Hopper plugin SDK/header layout is not present in `/Applications/Hopper Disassembler.app` in this installation.
- Frida attach timed out for both Hopper app and ExternalAPI XPC.
- Apple Developer ID signing/notarization has not been executed with real credentials.

