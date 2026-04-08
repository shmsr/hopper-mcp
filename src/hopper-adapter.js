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
      transactionApply: false,
      reason: "Live ingest uses Hopper's official launcher + Python scripting. Transaction commits are still local-only until a persistent in-process bridge is added.",
    };
  }

  async ingestExecutable(options) {
    return ingestWithLiveHopper({
      ...options,
      hopperLauncher: options.hopperLauncher ?? this.hopperLauncher ?? undefined,
    });
  }

  async applyTransaction(_session, transaction) {
    return {
      appliedToHopper: false,
      transactionId: transaction.id,
      reason: "The in-process Hopper plugin bridge has not been connected yet.",
    };
  }
}
