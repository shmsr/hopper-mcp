import test from "node:test";
import assert from "node:assert/strict";
import { buildOfficialSnapshot } from "../src/official-snapshot.js";

function toolResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
  };
}

test("buildOfficialSnapshot recovers the document name from list_documents when current_document is boolean true", async () => {
  const backend = {
    async callTool(name) {
      switch (name) {
        case "current_document":
          return toolResult(true);
        case "list_documents":
          return toolResult(["true"]);
        case "list_procedures":
          return toolResult({ "0x100000368": "EntryPoint" });
        case "list_segments":
          return toolResult([]);
        case "list_procedure_size":
          return toolResult({});
        case "list_strings":
          return toolResult({});
        case "list_names":
          return toolResult({});
        case "list_bookmarks":
          return toolResult([]);
        case "current_address":
          return toolResult(null);
        case "current_procedure":
          return toolResult(null);
        case "procedure_info":
          return toolResult({
            name: "EntryPoint",
            length: 4,
            locals: [],
            basicblock_count: 1,
            basicblocks: [],
          });
        case "procedure_assembly":
          return toolResult("ret");
        case "procedure_callers":
        case "procedure_callees":
          return toolResult([]);
        default:
          throw new Error(`unexpected tool ${name}`);
      }
    },
  };

  const snapshot = await buildOfficialSnapshot(backend, {
    maxProcedures: 30,
    includeProcedureInfo: true,
    includeAssembly: true,
    includePseudocode: false,
    includeCallGraph: true,
  });

  assert.equal(snapshot.binary.name, "true");
  assert.equal(snapshot.sessionId, "official-true");
  assert.equal(snapshot.functions.length, 1);
  assert.equal(snapshot.functions[0].name, "EntryPoint");
});
