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

  // Default branch of commit_transaction when args.backend !== "official".
  // The in-process Hopper plugin bridge isn't connected, so we report a
  // no-op adapter result; the knowledge-store mutations still apply.
  async applyTransaction(_session, transaction) {
    return {
      appliedToHopper: false,
      transactionId: transaction.id,
      reason: "The in-process Hopper plugin bridge has not been connected yet.",
    };
  }
}
