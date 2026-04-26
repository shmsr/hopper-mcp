import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";

const STATIC_RESOURCES = [
  ["hopper://session/current", "Current Hopper session"],
  ["hopper://binary/metadata", "Binary metadata"],
  ["hopper://binary/imports", "Imported symbols"],
  ["hopper://binary/exports", "Exported symbols"],
  ["hopper://binary/strings", "String index"],
  ["hopper://binary/capabilities", "Imports bucketed by capability"],
  ["hopper://binary/signing", "Code signing + entitlements"],
  ["hopper://binary/entropy", "Section entropy"],
  ["hopper://anti-analysis", "Anti-analysis findings"],
  ["hopper://tags", "Address tags"],
  ["hopper://hypotheses", "Researcher hypotheses"],
  ["hopper://names", "Named addresses"],
  ["hopper://bookmarks", "Bookmarks"],
  ["hopper://comments", "Prefix comments"],
  ["hopper://inline-comments", "Inline comments"],
  ["hopper://cursor", "Captured cursor"],
  ["hopper://functions", "Function index"],
  ["hopper://objc/classes", "Objective-C classes"],
  ["hopper://swift/symbols", "Swift symbols"],
  ["hopper://transactions/pending", "Pending annotation transactions"],
];

// Bridges KnowledgeStore.getResource(uri) into the SDK's resource registration
// API. Static URIs each get their own registration so they show up in
// resources/list, and the per-function expansion is handled via templates with
// a `list` callback that enumerates the current session's functions.
export function registerResources(server, store) {
  const read = (uri) => ({
    contents: [
      {
        uri: uri.toString(),
        mimeType: "application/json",
        text: JSON.stringify(store.getResource(uri.toString())),
      },
    ],
  });

  // Each static URI is registered twice: a bare-string registration so it
  // shows up in resources/list, plus a hidden template that picks up the
  // ?session_id query variant so callers can address other sessions.
  for (const [uri, name] of STATIC_RESOURCES) {
    server.registerResource(name, uri, { name, mimeType: "application/json" }, read);
    server.registerResource(
      `${name} (session)`,
      new ResourceTemplate(`${uri}{?session_id}`, { list: undefined }),
      { name, mimeType: "application/json" },
      read,
    );
  }

  const listFunctions = () => {
    try {
      const session = store.getSession();
      const functions = Object.values(session.functions ?? {}).slice(0, 100);
      return {
        resources: functions.map((fn) => ({
          uri: `hopper://function/${fn.addr}`,
          name: `Function ${fn.name ?? fn.addr}`,
          mimeType: "application/json",
        })),
      };
    } catch {
      return { resources: [] };
    }
  };

  const listFunctionEvidence = () => {
    try {
      const session = store.getSession();
      const functions = Object.values(session.functions ?? {}).slice(0, 100);
      return {
        resources: functions.map((fn) => ({
          uri: `hopper://function/${fn.addr}/evidence`,
          name: `Evidence for ${fn.name ?? fn.addr}`,
          mimeType: "application/json",
        })),
      };
    } catch {
      return { resources: [] };
    }
  };

  // Each function/graph template gets a paired `{?session_id}` variant so
  // callers can address resources for sessions other than `current`. The
  // bare-form template carries the `list` callback to keep resources/list
  // tidy; the session-scoped variant stays hidden from listings.
  const fnDesc = "Full indexed function record for an address.";
  server.registerResource(
    "function",
    new ResourceTemplate("hopper://function/{addr}", { list: listFunctions }),
    { title: "Function", description: fnDesc, mimeType: "application/json" },
    read,
  );
  server.registerResource(
    "function (session)",
    new ResourceTemplate("hopper://function/{addr}{?session_id}", { list: undefined }),
    { title: "Function", description: fnDesc, mimeType: "application/json" },
    read,
  );

  const summaryDesc = "Compact function summary with confidence.";
  server.registerResource(
    "function_summary",
    new ResourceTemplate("hopper://function/{addr}/summary", { list: undefined }),
    { title: "Function Summary", description: summaryDesc, mimeType: "application/json" },
    read,
  );
  server.registerResource(
    "function_summary (session)",
    new ResourceTemplate("hopper://function/{addr}/summary{?session_id}", { list: undefined }),
    { title: "Function Summary", description: summaryDesc, mimeType: "application/json" },
    read,
  );

  const evidenceDesc = "Evidence anchors used for provenance-first analysis.";
  server.registerResource(
    "function_evidence",
    new ResourceTemplate("hopper://function/{addr}/evidence", { list: listFunctionEvidence }),
    { title: "Function Evidence", description: evidenceDesc, mimeType: "application/json" },
    read,
  );
  server.registerResource(
    "function_evidence (session)",
    new ResourceTemplate("hopper://function/{addr}/evidence{?session_id}", { list: undefined }),
    { title: "Function Evidence", description: evidenceDesc, mimeType: "application/json" },
    read,
  );

  server.registerResource(
    "graph_callers",
    new ResourceTemplate("hopper://graph/callers/{addr}?radius={radius}", { list: undefined }),
    {
      title: "Caller Graph",
      description: "Caller graph slice rooted at a function address.",
      mimeType: "application/json",
    },
    read,
  );

  server.registerResource(
    "graph_callees",
    new ResourceTemplate("hopper://graph/callees/{addr}?radius={radius}", { list: undefined }),
    {
      title: "Callee Graph",
      description: "Callee graph slice rooted at a function address.",
      mimeType: "application/json",
    },
    read,
  );

  server.registerResource(
    "transaction",
    new ResourceTemplate("hopper://transactions/{id}", { list: undefined }),
    {
      title: "Transaction",
      description: "Read a specific local transaction by id.",
      mimeType: "application/json",
    },
    read,
  );
}
