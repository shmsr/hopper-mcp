import { ingestWithLiveHopper } from "./hopper-live.js";

export class HopperAdapter {
  constructor({ socketPath = null, hopperLauncher = null } = {}) {
    this.socketPath = socketPath;
    this.hopperLauncher = hopperLauncher;
  }

  capabilities() {
    return {
      connected: true,
      officialApi: true,
      privateApi: false,
      dynamicDebugger: false,
      liveIngest: true,
      currentDocumentIngest: false,
      transactionApply: false,
      reason: "Live ingest uses Hopper's official launcher + Python scripting. Current-document ingest and transaction commits need a persistent in-process Hopper bridge.",
    };
  }

  async ingestExecutable(options) {
    return ingestWithLiveHopper({
      ...options,
      hopperLauncher: options.hopperLauncher ?? this.hopperLauncher ?? undefined,
    });
  }

  async ingestCurrentDocument(options) {
    throw new Error("Current-document ingest is not supported by Hopper's AppleScript interface. Use ingest_live_hopper or import_macho until the in-process bridge is available.");
  }

  async applyTransaction(_session, transaction) {
    return {
      appliedToHopper: false,
      transactionId: transaction.id,
      reason: "The in-process Hopper plugin bridge has not been connected yet.",
    };
  }
}
