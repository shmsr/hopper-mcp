import { z } from "zod";
import { rpcError } from "./server-helpers.js";

// Prompts are tiny right now, but registered through the SDK's registerPrompt
// so clients see consistent metadata via prompts/list and can drive them via
// prompts/get. The argsSchema validates inbound prompt args.
export function registerPrompts(server) {
  server.registerPrompt(
    "function_triage",
    {
      title: "Function Triage",
      description: "Guide an agent through provenance-first function analysis.",
      argsSchema: { addr: z.string().describe("Function address") },
    },
    ({ addr }) => ({
      description: "Provenance-first function analysis",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Analyze ${addr} using hopper://function/${addr}/evidence first. State evidence anchors, confidence, and only then propose names/comments through a transaction preview.`,
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    "hypothesis_workspace",
    {
      title: "Hypothesis Workspace",
      description: "Create a cautious Hopper hypothesis with evidence gates.",
      argsSchema: { topic: z.string().describe("Hypothesis topic, e.g. license check path") },
    },
    ({ topic }) => ({
      description: "Hypothesis workspace",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Build a hypothesis workspace for '${topic}'. Separate known facts from guesses, cite addresses/imports/strings, and do not commit annotations until previewed.`,
          },
        },
      ],
    }),
  );
}

// Re-exported for callers that want to surface unknown-prompt errors with a
// canonical JSON-RPC code rather than a bare Error.
export { rpcError };
