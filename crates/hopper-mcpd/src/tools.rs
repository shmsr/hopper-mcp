use crate::backend::Backend;
use crate::content::{tool_error, tool_result};
use crate::live::{LiveIngestRequest, NodeLiveBridge};
use crate::protocol::JsonRpcError;
use crate::query::{Predicate, parse_expression};
use crate::store::{
    Binary, Function, Session, SnapshotStore, names_object, normalize_addr, object_from_functions,
    parse_addr, strings_object, xrefs,
};
use crate::transactions;
use regex::RegexBuilder;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

struct ToolDef {
    name: &'static str,
    description: &'static str,
    input_schema: fn() -> Value,
}

const MAX_LIVE_TIMEOUT_MS: u64 = 600_000;
const MAX_LIVE_FUNCTIONS: u64 = 50_000;
const MAX_LIVE_STRINGS: u64 = 250_000;
const MAX_LIVE_PSEUDOCODE_FUNCTIONS: u64 = 1_000;

const TOOL_REGISTRY: &[ToolDef] = &[
    ToolDef {
        name: "capabilities",
        description: "Report daemon capabilities and loaded sessions.",
        input_schema: schema_capabilities,
    },
    ToolDef {
        name: "backend_status",
        description: "Report availability of the configured Hopper backend.",
        input_schema: schema_backend_status,
    },
    ToolDef {
        name: "backend_diagnostics",
        description: "Report backend availability and Hopper wire compatibility details.",
        input_schema: schema_backend_status,
    },
    ToolDef {
        name: "ingest_current_hopper",
        description: "Ingest the current Hopper document through the configured backend.",
        input_schema: schema_ingest_current_hopper,
    },
    ToolDef {
        name: "ingest_live_hopper",
        description: "Open an executable in Hopper through the configured live bridge and ingest the exported session.",
        input_schema: schema_ingest_live_hopper,
    },
    ToolDef {
        name: "open_session",
        description: "Create or replace a normalized Hopper snapshot session.",
        input_schema: schema_open_session,
    },
    ToolDef {
        name: "list",
        description: "List procedures, strings, names, segments, imports, exports, or bookmarks.",
        input_schema: schema_list,
    },
    ToolDef {
        name: "search",
        description: "Regex search over Hopper snapshot strings, procedures, or names.",
        input_schema: schema_search,
    },
    ToolDef {
        name: "resolve",
        description: "Resolve an address, name, string, or import against the snapshot.",
        input_schema: schema_resolve,
    },
    ToolDef {
        name: "procedure",
        description: "Read procedure info, assembly, pseudocode, callers, callees, or comments.",
        input_schema: schema_procedure,
    },
    ToolDef {
        name: "xrefs",
        description: "Return snapshot cross-references to/from an address.",
        input_schema: schema_xrefs,
    },
    ToolDef {
        name: "containing_function",
        description: "Find the function body containing an instruction address.",
        input_schema: schema_containing_function,
    },
    ToolDef {
        name: "get_graph_slice",
        description: "Return a bounded caller/callee graph neighborhood around a function.",
        input_schema: schema_get_graph_slice,
    },
    ToolDef {
        name: "analyze_function_deep",
        description: "Return purpose, pseudocode, graph context, evidence anchors, and provenance for a function.",
        input_schema: schema_analyze_function_deep,
    },
    ToolDef {
        name: "compute_fingerprints",
        description: "Compute stable per-function fingerprints from Hopper snapshot evidence.",
        input_schema: schema_compute_fingerprints,
    },
    ToolDef {
        name: "find_similar_functions",
        description: "Find functions with similar imports, strings, and graph shape.",
        input_schema: schema_find_similar_functions,
    },
    ToolDef {
        name: "diff_sessions",
        description: "Diff two Hopper snapshots by functions, strings, and imports.",
        input_schema: schema_diff_sessions,
    },
    ToolDef {
        name: "query",
        description: "Run a simple predicate query over functions: name, imports, string, addr.",
        input_schema: schema_query,
    },
    ToolDef {
        name: "begin_transaction",
        description: "Start a local annotation transaction.",
        input_schema: schema_begin_transaction,
    },
    ToolDef {
        name: "queue",
        description: "Queue a local transaction operation.",
        input_schema: schema_queue,
    },
    ToolDef {
        name: "preview_transaction",
        description: "Preview queued local transaction operations.",
        input_schema: schema_transaction_id,
    },
    ToolDef {
        name: "commit_transaction",
        description: "Apply queued local transaction operations.",
        input_schema: schema_transaction_id,
    },
    ToolDef {
        name: "rollback_transaction",
        description: "Roll back a local transaction without applying it.",
        input_schema: schema_transaction_id,
    },
];

pub fn list_tools() -> Vec<Value> {
    TOOL_REGISTRY
        .iter()
        .map(|def| tool(def.name, def.description, (def.input_schema)()))
        .collect()
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "title": titleize(name),
        "description": description,
        "inputSchema": input_schema,
        "annotations": { "readOnlyHint": !["ingest_current_hopper", "ingest_live_hopper", "open_session", "begin_transaction", "queue", "commit_transaction", "rollback_transaction"].contains(&name), "openWorldHint": false }
    })
}

fn titleize(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn strict_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn limit_schema() -> Value {
    json!({ "type": "integer", "minimum": 0 })
}

fn capped_limit_schema(maximum: u64) -> Value {
    json!({ "type": "integer", "minimum": 0, "maximum": maximum })
}

fn schema_capabilities() -> Value {
    strict_schema(json!({}), &[])
}

fn schema_backend_status() -> Value {
    strict_schema(json!({}), &[])
}

fn schema_ingest_current_hopper() -> Value {
    strict_schema(
        json!({ "backend": { "enum": ["auto", "mock", "private"] } }),
        &[],
    )
}

fn schema_ingest_live_hopper() -> Value {
    strict_schema(
        json!({
            "executable_path": { "type": "string" },
            "timeout_ms": capped_limit_schema(MAX_LIVE_TIMEOUT_MS),
            "max_functions": capped_limit_schema(MAX_LIVE_FUNCTIONS),
            "max_strings": capped_limit_schema(MAX_LIVE_STRINGS),
            "analysis": { "type": "boolean" },
            "loader": { "type": "string", "pattern": "^[A-Za-z0-9_.-]+$" },
            "only_procedures": { "type": "boolean" },
            "parse_objective_c": { "type": "boolean" },
            "parse_swift": { "type": "boolean" },
            "parse_exceptions": { "type": "boolean" },
            "close_after_export": { "type": "boolean" },
            "wait_for_analysis": { "type": "boolean" },
            "full_export": { "type": "boolean" },
            "include_pseudocode": { "type": "boolean" },
            "max_pseudocode_functions": capped_limit_schema(MAX_LIVE_PSEUDOCODE_FUNCTIONS),
            "overwrite": { "type": "boolean" }
        }),
        &["executable_path"],
    )
}

fn schema_open_session() -> Value {
    strict_schema(
        json!({
            "session": { "type": "object" },
            "overwrite": { "type": "boolean" }
        }),
        &["session"],
    )
}

fn schema_list() -> Value {
    strict_schema(
        json!({
            "kind": { "enum": ["procedures", "strings", "names", "segments", "bookmarks", "imports", "exports"] },
            "session_id": { "type": "string" },
            "max_results": limit_schema()
        }),
        &["kind"],
    )
}

fn schema_search() -> Value {
    strict_schema(
        json!({
            "kind": { "enum": ["strings", "procedures", "names"] },
            "pattern": { "type": "string", "maxLength": 512 },
            "case_sensitive": { "type": "boolean" },
            "session_id": { "type": "string" },
            "max_results": limit_schema()
        }),
        &["kind", "pattern"],
    )
}

fn schema_resolve() -> Value {
    strict_schema(
        json!({
            "query": { "type": "string" },
            "session_id": { "type": "string" },
            "max_results": limit_schema()
        }),
        &["query"],
    )
}

fn schema_procedure() -> Value {
    strict_schema(
        json!({
            "field": { "enum": ["info", "assembly", "pseudo_code", "callers", "callees", "comments"] },
            "procedure": { "type": "string" },
            "session_id": { "type": "string" },
            "max_lines": limit_schema()
        }),
        &["field"],
    )
}

fn schema_xrefs() -> Value {
    strict_schema(
        json!({ "address": { "type": "string" }, "session_id": { "type": "string" } }),
        &[],
    )
}

fn schema_containing_function() -> Value {
    strict_schema(
        json!({ "address": { "type": "string" }, "session_id": { "type": "string" } }),
        &["address"],
    )
}

fn schema_get_graph_slice() -> Value {
    strict_schema(
        json!({
            "seed": { "type": "string" },
            "radius": { "type": "number" },
            "kind": { "enum": ["calls", "callers", "callees"] },
            "max_nodes": limit_schema(),
            "session_id": { "type": "string" }
        }),
        &["seed"],
    )
}

fn schema_analyze_function_deep() -> Value {
    strict_schema(
        json!({
            "addr": { "type": "string" },
            "detail_level": { "enum": ["standard", "full"] },
            "session_id": { "type": "string" }
        }),
        &["addr"],
    )
}

fn schema_compute_fingerprints() -> Value {
    strict_schema(json!({ "session_id": { "type": "string" } }), &[])
}

fn schema_find_similar_functions() -> Value {
    strict_schema(
        json!({
            "addr": { "type": "string" },
            "target_session_id": { "type": "string" },
            "min_similarity": { "type": "number" },
            "max_results": limit_schema(),
            "session_id": { "type": "string" }
        }),
        &[],
    )
}

fn schema_diff_sessions() -> Value {
    strict_schema(
        json!({
            "left_session_id": { "type": "string" },
            "right_session_id": { "type": "string" },
            "max_per_bucket": limit_schema()
        }),
        &["left_session_id", "right_session_id"],
    )
}

fn schema_query() -> Value {
    strict_schema(
        json!({
            "expression": { "type": "string" },
            "session_id": { "type": "string" },
            "max_results": limit_schema()
        }),
        &["expression"],
    )
}

fn schema_begin_transaction() -> Value {
    strict_schema(json!({ "name": { "type": "string" } }), &[])
}

fn schema_queue() -> Value {
    strict_schema(
        json!({
            "transaction_id": { "type": "string" },
            "kind": { "enum": ["rename", "comment", "inline_comment"] },
            "addr": { "type": "string" },
            "value": { "type": "string" }
        }),
        &["transaction_id", "kind", "addr", "value"],
    )
}

fn schema_transaction_id() -> Value {
    strict_schema(
        json!({ "transaction_id": { "type": "string" } }),
        &["transaction_id"],
    )
}

pub fn call_tool(
    store: &mut SnapshotStore,
    backend: &(dyn Backend + Send + Sync),
    live_bridge: &NodeLiveBridge,
    name: &str,
    args: Value,
) -> Result<Value, JsonRpcError> {
    let args = expect_args(args)?;
    let raw = match name {
        "capabilities" => capabilities(store, backend, live_bridge),
        "backend_status" => backend_status(backend, &args),
        "backend_diagnostics" => backend_diagnostics(backend, live_bridge, &args),
        "ingest_current_hopper" => ingest_current_hopper(store, backend, &args),
        "ingest_live_hopper" => {
            return match ingest_live_hopper(store, live_bridge, &args)? {
                Ok(raw) => Ok(tool_result(raw)),
                Err(message) => Ok(tool_error(message)),
            };
        }
        "open_session" => open_session(store, &args),
        "list" => list(store, &args),
        "search" => search(store, &args),
        "resolve" => resolve(store, &args),
        "procedure" => procedure(store, &args),
        "xrefs" => snapshot_xrefs(store, &args),
        "containing_function" => containing_function(store, &args),
        "get_graph_slice" => get_graph_slice(store, &args),
        "analyze_function_deep" => analyze_function_deep(store, &args),
        "compute_fingerprints" => compute_fingerprints(store, &args),
        "find_similar_functions" => find_similar_functions(store, &args),
        "diff_sessions" => diff_sessions(store, &args),
        "query" => query(store, &args),
        "begin_transaction" => begin_transaction(store, &args),
        "queue" => queue(store, &args),
        "preview_transaction" => preview_transaction(store, &args),
        "commit_transaction" => commit_transaction(store, &args),
        "rollback_transaction" => rollback_transaction(store, &args),
        other => Err(JsonRpcError::method_not_found(format!(
            "Unknown tool: {other}"
        ))),
    }?;
    Ok(tool_result(raw))
}

fn capabilities(
    _store: &SnapshotStore,
    backend: &(dyn Backend + Send + Sync),
    live_bridge: &NodeLiveBridge,
) -> Result<Value, JsonRpcError> {
    let status = backend.status();
    Ok(json!({
        "server": "hopper-mcpd",
        "implementation": "rust",
        "privateBackend": { "available": status.available, "reason": status.reason },
        "liveIngest": live_bridge.diagnostics(),
        "localFallbackTools": false
    }))
}

fn backend_status(
    backend: &(dyn Backend + Send + Sync),
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &[])?;
    let status = backend.status();
    Ok(json!({
        "backend": status.name,
        "available": status.available,
        "reason": status.reason,
        "backendMode": status.backend_mode,
        "readiness": status.readiness,
        "hopperVersion": status.hopper_version,
        "hopperBuild": status.hopper_build,
        "capabilities": status.capabilities
    }))
}

fn backend_diagnostics(
    backend: &(dyn Backend + Send + Sync),
    live_bridge: &NodeLiveBridge,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &[])?;
    let status = backend.status();
    Ok(json!({
        "backend": status.name,
        "available": status.available,
        "reason": status.reason,
        "backendMode": status.backend_mode,
        "readiness": status.readiness,
        "hopperVersion": status.hopper_version,
        "hopperBuild": status.hopper_build,
        "capabilities": status.capabilities,
        "wireVersion": hopper_wire::WIRE_VERSION,
        "liveBridge": live_bridge.diagnostics()
    }))
}

fn ingest_current_hopper(
    store: &mut SnapshotStore,
    backend: &(dyn Backend + Send + Sync),
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["backend"])?;
    match args.get("backend") {
        Some(Value::String(value)) if value == "auto" => {}
        Some(Value::String(value)) if value == backend.name() => {}
        Some(Value::String(value)) if value == "private" => {
            return Err(JsonRpcError::invalid_params(format!(
                "private backend requested but configured backend is {}",
                backend.name()
            )));
        }
        Some(Value::String(value)) if value == "mock" => {
            return Err(JsonRpcError::invalid_params(format!(
                "mock backend requested but configured backend is {}",
                backend.name()
            )));
        }
        Some(Value::String(_)) => {
            return Err(JsonRpcError::invalid_params(
                "backend must be one of: auto, mock, private",
            ));
        }
        Some(_) => {
            return Err(JsonRpcError::invalid_params("backend must be a string"));
        }
        None => {}
    }

    let doc = backend
        .current_document()
        .map_err(|err| JsonRpcError::invalid_params(format!("Backend unavailable: {err}")))?;
    let procedures = backend
        .list_procedures(Some(MAX_LIVE_FUNCTIONS))
        .map_err(|err| JsonRpcError::invalid_params(format!("Backend unavailable: {err}")))?;
    let session = Session {
        session_id: format!("live-{}", doc.document_id),
        binary: Binary {
            name: Some(doc.name),
            format: Some("hopper-live".to_string()),
            ..Binary::default()
        },
        functions: procedures
            .into_iter()
            .map(|procedure| {
                let addr = procedure.addr;
                (
                    addr.clone(),
                    Function {
                        addr,
                        name: procedure.name,
                        size: procedure.size,
                        ..Function::default()
                    },
                )
            })
            .collect(),
        ..Session::default()
    };
    store.open_session(session, true)
}

fn ingest_live_hopper(
    store: &mut SnapshotStore,
    live_bridge: &NodeLiveBridge,
    args: &serde_json::Map<String, Value>,
) -> Result<Result<Value, String>, JsonRpcError> {
    require_only(
        args,
        &[
            "executable_path",
            "timeout_ms",
            "max_functions",
            "max_strings",
            "analysis",
            "loader",
            "only_procedures",
            "parse_objective_c",
            "parse_swift",
            "parse_exceptions",
            "close_after_export",
            "wait_for_analysis",
            "full_export",
            "include_pseudocode",
            "max_pseudocode_functions",
            "overwrite",
        ],
    )?;
    if !args.contains_key("executable_path") {
        return Err(JsonRpcError::invalid_params(
            "ingest_live_hopper requires executable_path",
        ));
    }
    let executable_path = str_arg(args, "executable_path")?;
    if executable_path.trim().is_empty() {
        return Err(JsonRpcError::invalid_params(
            "ingest_live_hopper requires executable_path",
        ));
    }
    let full_export = bool_arg(args, "full_export")?;
    let max_functions = optional_capped_u64_arg(args, "max_functions", MAX_LIVE_FUNCTIONS)?;
    let max_strings = optional_capped_u64_arg(args, "max_strings", MAX_LIVE_STRINGS)?;
    let request = LiveIngestRequest {
        executable_path: executable_path.to_string(),
        timeout_ms: optional_capped_u64_arg(args, "timeout_ms", MAX_LIVE_TIMEOUT_MS)?,
        max_functions: max_functions
            .or_else(|| full_export.unwrap_or(false).then_some(MAX_LIVE_FUNCTIONS)),
        max_strings: max_strings
            .or_else(|| full_export.unwrap_or(false).then_some(MAX_LIVE_STRINGS)),
        analysis: bool_arg(args, "analysis")?,
        loader: optional_string_arg(args, "loader")?,
        only_procedures: bool_arg(args, "only_procedures")?,
        parse_objective_c: bool_arg(args, "parse_objective_c")?,
        parse_swift: bool_arg(args, "parse_swift")?,
        parse_exceptions: bool_arg(args, "parse_exceptions")?,
        close_after_export: bool_arg(args, "close_after_export")?,
        wait_for_analysis: bool_arg(args, "wait_for_analysis")?,
        full_export,
        include_pseudocode: bool_arg(args, "include_pseudocode")?,
        max_pseudocode_functions: optional_capped_u64_arg(
            args,
            "max_pseudocode_functions",
            MAX_LIVE_PSEUDOCODE_FUNCTIONS,
        )?,
    };
    let overwrite = bool_arg(args, "overwrite")?.unwrap_or(true);
    let live = match live_bridge.ingest(&request) {
        Ok(live) => live,
        Err(err) => return Ok(Err(format!("Live Hopper ingest failed: {err}"))),
    };
    let session = store.open_session(live.session, overwrite)?;
    Ok(Ok(json!({
        "session": session,
        "launch": live.launch,
        "diagnostics": live.diagnostics
    })))
}

fn open_session(
    store: &mut SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["session", "overwrite"])?;
    let session_value = args
        .get("session")
        .ok_or_else(|| JsonRpcError::invalid_params("open_session requires session"))?;
    let session = serde_json::from_value(session_value.clone())
        .map_err(|err| JsonRpcError::invalid_params(format!("Invalid session payload: {err}")))?;
    let overwrite = bool_arg(args, "overwrite")?.unwrap_or(true);
    store.open_session(session, overwrite)
}

fn list(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["kind", "session_id", "max_results"])?;
    let kind = str_arg(args, "kind")?;
    let session = store.session(optional_str(args, "session_id"))?;
    let max = max_results(args, 500)?;
    let value = match kind {
        "procedures" => object_from_functions(limit(session.functions.values(), max)),
        "strings" => strings_object(
            &limit(session.strings.iter(), max)
                .cloned()
                .collect::<Vec<_>>(),
        ),
        "names" => names_object(
            &limit(session.names.iter(), max)
                .cloned()
                .collect::<Vec<_>>(),
        ),
        "segments" => json!(
            limit(session.binary.segments.iter(), max)
                .cloned()
                .collect::<Vec<_>>()
        ),
        "bookmarks" => json!(
            limit(session.bookmarks.iter(), max)
                .cloned()
                .collect::<Vec<_>>()
        ),
        "imports" => json!(
            limit(session.imports.iter(), max)
                .cloned()
                .collect::<Vec<_>>()
        ),
        "exports" => json!(
            limit(session.exports.iter(), max)
                .cloned()
                .collect::<Vec<_>>()
        ),
        _ => {
            return Err(JsonRpcError::invalid_params(
                "list.kind must be procedures|strings|names|segments|bookmarks|imports|exports",
            ));
        }
    };
    Ok(value)
}

fn search(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(
        args,
        &[
            "kind",
            "pattern",
            "case_sensitive",
            "session_id",
            "max_results",
        ],
    )?;
    let kind = str_arg(args, "kind")?;
    let pattern = str_arg(args, "pattern")?;
    if pattern.len() > 512 {
        return Err(JsonRpcError::invalid_params(
            "search.pattern must be 512 bytes or fewer",
        ));
    }
    let session = store.session(optional_str(args, "session_id"))?;
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(!bool_arg(args, "case_sensitive")?.unwrap_or(false))
        .build()
        .map_err(|err| JsonRpcError::invalid_params(format!("Invalid regex pattern: {err}")))?;
    let max = max_results(args, 500)?;
    match kind {
        "strings" => {
            let matches: Vec<_> = session
                .strings
                .iter()
                .filter(|item| regex.is_match(&item.value))
                .take(max)
                .cloned()
                .collect();
            Ok(strings_object(&matches))
        }
        "procedures" => {
            let matches = session.functions.values().filter(|function| {
                regex.is_match(&format!(
                    "{} {} {} {}",
                    function.addr,
                    function.name.as_deref().unwrap_or(""),
                    function.signature.as_deref().unwrap_or(""),
                    function.summary.as_deref().unwrap_or("")
                ))
            });
            Ok(object_from_functions(limit(matches, max)))
        }
        "names" => {
            let matches: Vec<_> = session
                .names
                .iter()
                .filter(|name| {
                    regex.is_match(&format!(
                        "{} {} {}",
                        name.addr,
                        name.name,
                        name.demangled.as_deref().unwrap_or("")
                    ))
                })
                .take(max)
                .cloned()
                .collect();
            Ok(names_object(&matches))
        }
        _ => Err(JsonRpcError::invalid_params(
            "search.kind must be strings|procedures|names",
        )),
    }
}

fn resolve(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["query", "session_id", "max_results"])?;
    let query = str_arg(args, "query")?.trim();
    if query.is_empty() {
        return Err(JsonRpcError::invalid_params(
            "resolve requires a non-empty query",
        ));
    }
    let session = store.session(optional_str(args, "session_id"))?;
    let q_lower = query.to_lowercase();
    let max = max_results(args, 20)?;
    let mut out = Vec::new();

    if let Some(function) = session.functions.get(&normalize_addr(query)) {
        out.push(resolve_function(function, 1.0));
    }
    for function in session.functions.values() {
        if out.len() >= max {
            break;
        }
        if function.name.as_deref() == Some(query)
            && !out.iter().any(|item| item["addr"] == function.addr)
        {
            out.push(resolve_function(function, 1.0));
        }
    }
    for name in &session.names {
        if out.len() >= max {
            break;
        }
        if (name.name == query || name.demangled.as_deref() == Some(query))
            && !out.iter().any(|item| item["addr"] == name.addr)
        {
            out.push(json!({
                "kind": "name",
                "score": 1.0,
                "addr": name.addr,
                "name": name.name,
                "demangled": name.demangled
            }));
        }
    }
    for item in &session.strings {
        if out.len() >= max {
            break;
        }
        if item.value == query || item.value.to_lowercase().contains(&q_lower) {
            out.push(
                json!({ "kind": "string", "score": 0.7, "addr": item.addr, "value": item.value }),
            );
        }
    }
    for import in &session.imports {
        if out.len() >= max {
            break;
        }
        if import == query || import.to_lowercase().contains(&q_lower) {
            out.push(json!({ "kind": "import", "score": 0.6, "name": import }));
        }
    }
    Ok(json!(out))
}

fn procedure(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["field", "procedure", "session_id", "max_lines"])?;
    let field = str_arg(args, "field")?;
    let session = store.session(optional_str(args, "session_id"))?;
    let function = session.function_by_query(optional_str(args, "procedure"))?;
    let max_lines = max_arg(args, "max_lines", usize::MAX)?;
    match field {
        "info" => Ok(procedure_info(function)),
        "assembly" => {
            let mut lines = Vec::new();
            for block in &function.basic_blocks {
                lines.push(format!(
                    "{}: {}",
                    block.addr,
                    block.summary.as_deref().unwrap_or("basic block")
                ));
                lines.extend(block.instructions.iter().map(render_instruction));
            }
            Ok(json!(
                lines
                    .into_iter()
                    .take(max_lines)
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
        "pseudo_code" => Ok(json!(limit_text_lines(
            &function.pseudocode.clone().unwrap_or_default(),
            max_lines
        ))),
        "callers" => Ok(json!(
            limit(function.callers.iter(), max_lines)
                .cloned()
                .collect::<Vec<_>>()
        )),
        "callees" => Ok(json!(
            limit(function.callees.iter(), max_lines)
                .cloned()
                .collect::<Vec<_>>()
        )),
        "comments" => {
            let start = parse_addr(&function.addr).unwrap_or(0);
            let end = function
                .size
                .map(|size| start.saturating_add(size))
                .unwrap_or(start + 1);
            let mut prefix = serde_json::Map::new();
            let mut inline = serde_json::Map::new();
            for comment in &session.comments {
                if addr_in_range(&comment.addr, start, end) {
                    prefix.insert(
                        comment.addr.clone(),
                        json!(comment.comment.as_ref().or(comment.value.as_ref())),
                    );
                }
            }
            for comment in &session.inline_comments {
                if addr_in_range(&comment.addr, start, end) {
                    inline.insert(
                        comment.addr.clone(),
                        json!(comment.comment.as_ref().or(comment.value.as_ref())),
                    );
                }
            }
            Ok(json!({ "prefix": prefix, "inline": inline }))
        }
        _ => Err(JsonRpcError::invalid_params(
            "procedure.field must be info|assembly|pseudo_code|callers|callees|comments",
        )),
    }
}

fn render_instruction(instruction: &Value) -> String {
    if let Some(text) = instruction.as_str() {
        return text.to_string();
    }
    if let Some(object) = instruction.as_object() {
        let addr = object.get("addr").and_then(Value::as_str);
        let text = object.get("text").and_then(Value::as_str).unwrap_or("");
        let args = object
            .get("args")
            .and_then(Value::as_array)
            .map(|args| {
                args.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let rendered = if args.is_empty() {
            text.to_string()
        } else {
            format!("{text} {args}")
        };
        return match addr {
            Some(addr) if !rendered.is_empty() => format!("{addr}: {rendered}"),
            Some(addr) => addr.to_string(),
            None => rendered,
        };
    }
    instruction.to_string()
}

fn snapshot_xrefs(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["address", "session_id"])?;
    let session = store.session(optional_str(args, "session_id"))?;
    let address = optional_str(args, "address")
        .or(session.cursor.address.as_deref())
        .ok_or_else(|| {
            JsonRpcError::invalid_params("xrefs requires address or a captured cursor")
        })?;
    Ok(json!(xrefs(session, address)))
}

fn containing_function(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["address", "session_id"])?;
    let session = store.session(optional_str(args, "session_id"))?;
    let address_raw = str_arg(args, "address")?;
    let address = parse_addr(address_raw).ok_or_else(|| {
        JsonRpcError::invalid_params(format!(
            "containing_function requires a numeric address; got {address_raw}"
        ))
    })?;
    if let Some(function) = session.functions.get(&normalize_addr(address_raw)) {
        return Ok(
            json!({ "match": "entrypoint", "function": procedure_info(function), "offset": 0 }),
        );
    }
    if let Some(function) = session.containing_function(address) {
        let start = parse_addr(&function.addr).unwrap_or(address);
        return Ok(
            json!({ "match": "containment", "function": procedure_info(function), "offset": address - start }),
        );
    }
    Ok(json!({
        "match": "none",
        "address": normalize_addr(address_raw),
        "sizedFunctions": session.functions.values().filter(|function| function.size.unwrap_or(0) > 0).count(),
        "totalFunctions": session.functions.len()
    }))
}

fn get_graph_slice(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["seed", "radius", "kind", "max_nodes", "session_id"])?;
    let session = store.session(optional_str(args, "session_id"))?;
    let seed = str_arg(args, "seed")?;
    let root = graph_seed_function(session, seed)?;
    let radius = number_arg(args, "radius")?.unwrap_or(1.0).max(0.0) as usize;
    let max_nodes = max_arg(args, "max_nodes", 200)?;
    let kind = optional_str(args, "kind").unwrap_or("calls");
    if !["calls", "callers", "callees"].contains(&kind) {
        return Err(JsonRpcError::invalid_params(
            "get_graph_slice.kind must be calls|callers|callees",
        ));
    }

    let mut queue = VecDeque::from([(root.addr.clone(), 0usize)]);
    let mut seen = BTreeSet::new();
    let mut node_addrs = Vec::new();
    let mut nodes = Vec::new();
    let mut truncated = false;

    while let Some((addr, depth)) = queue.pop_front() {
        if seen.contains(&addr) {
            continue;
        }
        if node_addrs.len() >= max_nodes {
            truncated = true;
            break;
        }
        let Some(function) = session.functions.get(&addr) else {
            continue;
        };
        seen.insert(addr.clone());
        node_addrs.push(addr.clone());
        nodes.push(json!({
            "addr": function.addr,
            "name": function.name,
            "depth": depth,
            "summary": function.summary
        }));
        if depth >= radius {
            continue;
        }
        for neighbor in graph_neighbors(function, kind) {
            if seen.contains(&neighbor) || queue.iter().any(|(addr, _)| addr == &neighbor) {
                continue;
            }
            if node_addrs.len() + queue.len() >= max_nodes {
                truncated = true;
            } else if session.functions.contains_key(&neighbor) {
                queue.push_back((neighbor, depth + 1));
            }
        }
    }

    let included = node_addrs.iter().cloned().collect::<BTreeSet<_>>();
    let mut edges = Vec::new();
    for addr in &node_addrs {
        let Some(function) = session.functions.get(addr) else {
            continue;
        };
        if kind == "calls" || kind == "callees" {
            for callee in &function.callees {
                let callee = normalize_addr(callee);
                if included.contains(&callee) {
                    edges.push(json!({ "from": function.addr, "to": callee, "kind": "call" }));
                }
            }
        }
        if kind == "calls" || kind == "callers" {
            for caller in &function.callers {
                let caller = normalize_addr(caller);
                if included.contains(&caller) {
                    edges.push(json!({ "from": caller, "to": function.addr, "kind": "call" }));
                }
            }
        }
    }

    Ok(json!({
        "seed": root.addr,
        "kind": kind,
        "radius": radius,
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated,
        "maxNodes": max_nodes
    }))
}

fn analyze_function_deep(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["addr", "detail_level", "session_id"])?;
    let session = store.session(optional_str(args, "session_id"))?;
    let function = session.function_by_query(Some(str_arg(args, "addr")?))?;
    let detail = optional_str(args, "detail_level").unwrap_or("standard");
    if !["standard", "full"].contains(&detail) {
        return Err(JsonRpcError::invalid_params(
            "detail_level must be standard|full",
        ));
    }
    let callers = function
        .callers
        .iter()
        .map(|addr| ref_info(session, addr))
        .collect::<Vec<_>>();
    let callees = function
        .callees
        .iter()
        .map(|addr| ref_info(session, addr))
        .collect::<Vec<_>>();
    let mut evidence_anchors = Vec::new();
    if let Some(assembly) = &function.assembly {
        evidence_anchors.push(json!({
            "kind": "assembly",
            "addr": function.addr,
            "preview": limit_text_lines(assembly, 8)
        }));
    }
    if let Some(pseudocode) = &function.pseudocode {
        evidence_anchors.push(json!({
            "kind": "pseudocode",
            "addr": function.addr,
            "preview": limit_text_lines(pseudocode, 8)
        }));
    }
    for import in &function.imports {
        evidence_anchors.push(json!({ "kind": "import", "value": import }));
    }
    for string in &function.strings {
        evidence_anchors.push(json!({ "kind": "string", "value": string }));
    }
    let basic_blocks = if detail == "full" {
        json!(function.basic_blocks)
    } else {
        json!(
            function
                .basic_blocks
                .iter()
                .map(|block| json!({ "addr": block.addr, "summary": block.summary }))
                .collect::<Vec<_>>()
        )
    };
    Ok(json!({
        "function": procedure_info(function),
        "purpose": function.summary,
        "pseudocode": function.pseudocode,
        "graph": { "callers": callers, "callees": callees },
        "evidenceAnchors": evidence_anchors,
        "basicBlocks": basic_blocks,
        "provenance": {
            "source": "hopper-snapshot",
            "localFallback": false
        }
    }))
}

fn compute_fingerprints(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["session_id"])?;
    let session = store.session(optional_str(args, "session_id"))?;
    let fingerprints = session
        .functions
        .values()
        .map(|function| (function.addr.clone(), function_fingerprint(function)))
        .collect::<BTreeMap<_, _>>();
    Ok(json!({
        "sessionId": session.session_id,
        "updated": fingerprints.len(),
        "fingerprints": fingerprints
    }))
}

fn find_similar_functions(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(
        args,
        &[
            "addr",
            "target_session_id",
            "min_similarity",
            "max_results",
            "session_id",
        ],
    )?;
    let session = store.session(optional_str(args, "session_id"))?;
    let target = session.function_by_query(optional_str(args, "addr"))?;
    let target_session_id = optional_str(args, "target_session_id");
    let min_similarity = number_arg(args, "min_similarity")?.unwrap_or(0.4);
    let max = max_results(args, 20)?;
    let target_fp = fingerprint_parts(target);
    let mut matches = Vec::new();

    let sessions: Vec<&Session> = if let Some(id) = target_session_id {
        vec![store.session(Some(id))?]
    } else {
        store.sessions().collect()
    };
    for candidate_session in sessions {
        for candidate in candidate_session.functions.values() {
            if candidate_session.session_id == session.session_id && candidate.addr == target.addr {
                continue;
            }
            let candidate_fp = fingerprint_parts(candidate);
            let score = if target_fp.stable == candidate_fp.stable {
                1.0
            } else {
                similarity(&target_fp, &candidate_fp)
            };
            if score >= min_similarity {
                matches.push(json!({
                    "sessionId": candidate_session.session_id,
                    "binary": candidate_session.binary.name,
                    "addr": candidate.addr,
                    "name": candidate.name,
                    "similarity": round4(score),
                    "summary": candidate.summary
                }));
            }
        }
    }
    matches.sort_by(|a, b| {
        b["similarity"]
            .as_f64()
            .partial_cmp(&a["similarity"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    matches.truncate(max);
    Ok(json!({
        "target": {
            "sessionId": session.session_id,
            "addr": target.addr,
            "name": target.name,
            "fingerprint": function_fingerprint(target)
        },
        "matches": matches
    }))
}

fn diff_sessions(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(
        args,
        &["left_session_id", "right_session_id", "max_per_bucket"],
    )?;
    let left = store.session(Some(str_arg(args, "left_session_id")?))?;
    let right = store.session(Some(str_arg(args, "right_session_id")?))?;
    let cap = max_arg(args, "max_per_bucket", 200)?;

    let left_funcs = left.functions.keys().cloned().collect::<BTreeSet<_>>();
    let right_funcs = right.functions.keys().cloned().collect::<BTreeSet<_>>();
    let left_function_names = function_name_set(left);
    let right_function_names = function_name_set(right);
    let left_imports = left.imports.iter().cloned().collect::<BTreeSet<_>>();
    let right_imports = right.imports.iter().cloned().collect::<BTreeSet<_>>();
    let left_strings = left
        .strings
        .iter()
        .map(|item| item.value.clone())
        .collect::<BTreeSet<_>>();
    let right_strings = right
        .strings
        .iter()
        .map(|item| item.value.clone())
        .collect::<BTreeSet<_>>();
    let renamed_functions = left
        .functions
        .iter()
        .filter_map(|(addr, left_function)| {
            let right_function = right.functions.get(addr)?;
            if left_function.name == right_function.name {
                None
            } else {
                Some(json!({
                    "addr": addr,
                    "leftName": left_function.name,
                    "rightName": right_function.name
                }))
            }
        })
        .take(cap)
        .collect::<Vec<_>>();
    let renamed_total = left
        .functions
        .iter()
        .filter(|(addr, left_function)| {
            right
                .functions
                .get(*addr)
                .map(|right_function| left_function.name != right_function.name)
                .unwrap_or(false)
        })
        .count();

    Ok(json!({
        "leftSessionId": left.session_id,
        "rightSessionId": right.session_id,
        "summary": {
            "functionsAdded": right_funcs.difference(&left_funcs).count(),
            "functionsRemoved": left_funcs.difference(&right_funcs).count(),
            "functionsRenamed": renamed_total,
            "functionNamesAdded": right_function_names.difference(&left_function_names).count(),
            "functionNamesRemoved": left_function_names.difference(&right_function_names).count(),
            "importsAdded": right_imports.difference(&left_imports).count(),
            "importsRemoved": left_imports.difference(&right_imports).count(),
            "stringsAdded": right_strings.difference(&left_strings).count(),
            "stringsRemoved": left_strings.difference(&right_strings).count()
        },
        "functions": {
            "added": capped_diff(&right_funcs, &left_funcs, cap),
            "removed": capped_diff(&left_funcs, &right_funcs, cap),
            "renamed": {
                "items": renamed_functions,
                "total": renamed_total,
                "truncated": renamed_total > cap
            }
        },
        "functionNames": {
            "added": capped_diff(&right_function_names, &left_function_names, cap),
            "removed": capped_diff(&left_function_names, &right_function_names, cap)
        },
        "imports": {
            "added": capped_diff(&right_imports, &left_imports, cap),
            "removed": capped_diff(&left_imports, &right_imports, cap)
        },
        "strings": {
            "added": capped_diff(&right_strings, &left_strings, cap),
            "removed": capped_diff(&left_strings, &right_strings, cap)
        }
    }))
}

fn query(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["expression", "session_id", "max_results"])?;
    let (predicate, needle) =
        parse_expression(str_arg(args, "expression")?).map_err(JsonRpcError::invalid_params)?;
    let session = store.session(optional_str(args, "session_id"))?;
    let needle = needle.to_lowercase();
    let max = max_results(args, 50)?;
    let matches = session
        .functions
        .values()
        .filter(|function| query_matches(function, &predicate, &needle))
        .take(max)
        .map(procedure_info)
        .collect::<Vec<_>>();
    Ok(json!({ "count": matches.len(), "matches": matches }))
}

fn begin_transaction(
    store: &mut SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["name"])?;
    let name = match args.get("name") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => return Err(JsonRpcError::invalid_params("name must be a string")),
        None => None,
    };
    store.begin_transaction(name)
}

fn queue(
    store: &mut SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["transaction_id", "kind", "addr", "value"])?;
    let transaction_id = str_arg(args, "transaction_id")?;
    let kind = str_arg(args, "kind")?;
    let addr_raw = str_arg(args, "addr")?;
    let addr = crate::address::normalize_addr(addr_raw).ok_or_else(|| {
        JsonRpcError::invalid_params(format!(
            "queue.addr must be a numeric address; got {addr_raw}"
        ))
    })?;
    let value = str_arg(args, "value")?.to_string();
    let operation = match kind {
        "rename" => transactions::rename_op(addr, value)?,
        "comment" | "inline_comment" => transactions::comment_op(kind, addr, value)?,
        _ => {
            return Err(JsonRpcError::invalid_params(format!(
                "Unsupported queue kind: {kind}. Supported kinds: rename, comment, inline_comment"
            )));
        }
    };
    store.queue_operation(transaction_id, operation)
}

fn preview_transaction(
    store: &SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["transaction_id"])?;
    store.preview_transaction(str_arg(args, "transaction_id")?)
}

fn commit_transaction(
    store: &mut SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["transaction_id"])?;
    store.commit_transaction(str_arg(args, "transaction_id")?)
}

fn rollback_transaction(
    store: &mut SnapshotStore,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, JsonRpcError> {
    require_only(args, &["transaction_id"])?;
    store.rollback_transaction(str_arg(args, "transaction_id")?)
}

fn procedure_info(function: &Function) -> Value {
    json!({
        "addr": function.addr,
        "name": function.name,
        "size": function.size,
        "signature": function.signature,
        "summary": function.summary,
        "confidence": function.confidence,
        "callers": function.callers,
        "callees": function.callees,
        "strings": function.strings,
        "imports": function.imports,
        "basicBlockCount": function.basic_blocks.len()
    })
}

fn resolve_function(function: &Function, score: f64) -> Value {
    let mut item = match procedure_info(function) {
        Value::Object(object) => object,
        _ => serde_json::Map::new(),
    };
    item.insert("kind".to_string(), json!("function"));
    item.insert("score".to_string(), json!(score));
    Value::Object(item)
}

fn ref_info(session: &Session, addr: &str) -> Value {
    let normalized = normalize_addr(addr);
    if let Some(function) = session.functions.get(&normalized) {
        json!({ "addr": function.addr, "name": function.name, "known": true })
    } else {
        json!({ "addr": normalized, "known": false })
    }
}

fn graph_seed_function<'a>(session: &'a Session, seed: &str) -> Result<&'a Function, JsonRpcError> {
    if let Some(function) = session.functions.get(&normalize_addr(seed)) {
        return Ok(function);
    }
    if let Some(address) = parse_addr(seed)
        && let Some(function) = session.containing_function(address)
    {
        return Ok(function);
    }
    session.function_by_query(Some(seed))
}

fn graph_neighbors(function: &Function, kind: &str) -> Vec<String> {
    let mut neighbors = Vec::new();
    if kind == "calls" || kind == "callees" {
        neighbors.extend(function.callees.iter().map(|addr| normalize_addr(addr)));
    }
    if kind == "calls" || kind == "callers" {
        neighbors.extend(function.callers.iter().map(|addr| normalize_addr(addr)));
    }
    neighbors
}

fn function_fingerprint(function: &Function) -> Value {
    let parts = fingerprint_parts(function);
    json!({
        "stableHash": parts.stable,
        "imphash": stable_hash(&encoded_sorted_set(parts.imports.iter().cloned())),
        "stringhash": stable_hash(&encoded_sorted_set(
            function.strings.iter().map(|value| value.to_lowercase())
        )),
        "cfgHash": stable_hash(&format!("bb:{}:callers:{}:callees:{}:size:{}",
            function.basic_blocks.len(),
            function.callers.len(),
            function.callees.len(),
            function.size.unwrap_or(0) / 16
        )),
        "imports": parts.imports,
        "strings": parts.strings,
        "shape": {
            "basicBlocks": function.basic_blocks.len(),
            "callers": function.callers.len(),
            "callees": function.callees.len(),
            "sizeBucket": function.size.unwrap_or(0) / 16
        }
    })
}

#[derive(Debug)]
struct FingerprintParts {
    stable: String,
    imports: BTreeSet<String>,
    strings: BTreeSet<String>,
    shape: BTreeSet<String>,
}

fn fingerprint_parts(function: &Function) -> FingerprintParts {
    let imports = function.imports.iter().map(|v| v.to_lowercase()).collect();
    let strings = function
        .strings
        .iter()
        .flat_map(|value| value.split(|c: char| !c.is_ascii_alphanumeric() && c != '_'))
        .filter(|token| token.len() >= 4)
        .map(|token| token.to_lowercase())
        .collect();
    let shape = [
        format!("bb:{}", function.basic_blocks.len()),
        format!("callers:{}", function.callers.len()),
        format!("callees:{}", function.callees.len()),
        format!("size:{}", function.size.unwrap_or(0) / 16),
    ]
    .into_iter()
    .collect();
    let stable = stable_hash(
        &[
            function.addr.to_lowercase(),
            function.name.as_deref().unwrap_or("").to_lowercase(),
            encoded_sorted_set(function.callees.iter().map(|value| normalize_addr(value))),
            encoded_sorted_set(function.callers.iter().map(|value| normalize_addr(value))),
            encoded_sorted_set(function.strings.iter().map(|value| value.to_lowercase())),
            encoded_sorted_set(function.imports.iter().map(|value| value.to_lowercase())),
        ]
        .join("|"),
    );
    FingerprintParts {
        stable,
        imports,
        strings,
        shape,
    }
}

fn similarity(left: &FingerprintParts, right: &FingerprintParts) -> f64 {
    let import_score = jaccard(&left.imports, &right.imports);
    let string_score = jaccard(&left.strings, &right.strings);
    let shape_score = jaccard(&left.shape, &right.shape);
    (import_score * 0.45) + (string_score * 0.35) + (shape_score * 0.20)
}

fn jaccard(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 0.0;
    }
    let intersection = left.intersection(right).count() as f64;
    let union = left.union(right).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn function_name_set(session: &Session) -> BTreeSet<String> {
    session
        .functions
        .values()
        .filter_map(|function| function.name.clone())
        .collect()
}

fn stable_hash(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn encoded_sorted_set(values: impl IntoIterator<Item = String>) -> String {
    let values = values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    serde_json::to_string(&values).expect("serializing string evidence cannot fail")
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn capped_diff(left: &BTreeSet<String>, right: &BTreeSet<String>, cap: usize) -> Value {
    let items = left
        .difference(right)
        .take(cap)
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "items": items,
        "total": left.difference(right).count(),
        "truncated": left.difference(right).count() > cap
    })
}

fn query_matches(function: &Function, predicate: &Predicate, needle: &str) -> bool {
    match predicate {
        Predicate::Name => function
            .name
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains(needle),
        Predicate::Addr => function.addr.to_lowercase().contains(needle),
        Predicate::Imports => function
            .imports
            .iter()
            .any(|value| value.to_lowercase().contains(needle)),
        Predicate::String => function
            .strings
            .iter()
            .any(|value| value.to_lowercase().contains(needle)),
    }
}

fn expect_args(args: Value) -> Result<serde_json::Map<String, Value>, JsonRpcError> {
    match args {
        Value::Object(map) => Ok(map),
        _ => Err(JsonRpcError::invalid_params(
            "Tool arguments must be an object",
        )),
    }
}

fn require_only(
    args: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), JsonRpcError> {
    for key in args.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(JsonRpcError::invalid_params(format!(
                "Unrecognized key: {key}"
            )));
        }
    }
    Ok(())
}

fn str_arg<'a>(
    args: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, JsonRpcError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError::invalid_params(format!("{key} must be a string")))
}

fn optional_str<'a>(args: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn optional_string_arg(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, JsonRpcError> {
    match args.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(JsonRpcError::invalid_params(format!(
            "{key} must be a string"
        ))),
        None => Ok(None),
    }
}

fn bool_arg(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, JsonRpcError> {
    match args.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(JsonRpcError::invalid_params(format!(
            "{key} must be a boolean"
        ))),
        None => Ok(None),
    }
}

fn optional_u64_arg(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, JsonRpcError> {
    match args.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| JsonRpcError::invalid_params(format!("{key} must be an integer >= 0"))),
        Some(_) => Err(JsonRpcError::invalid_params(format!(
            "{key} must be an integer >= 0"
        ))),
        None => Ok(None),
    }
}

fn optional_capped_u64_arg(
    args: &serde_json::Map<String, Value>,
    key: &str,
    maximum: u64,
) -> Result<Option<u64>, JsonRpcError> {
    let value = optional_u64_arg(args, key)?;
    if let Some(value) = value
        && value > maximum
    {
        return Err(JsonRpcError::invalid_params(format!(
            "{key} must be an integer between 0 and {maximum}"
        )));
    }
    Ok(value)
}

fn number_arg(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<f64>, JsonRpcError> {
    match args.get(key) {
        Some(Value::Number(value)) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| JsonRpcError::invalid_params(format!("{key} must be a finite number"))),
        Some(_) => Err(JsonRpcError::invalid_params(format!(
            "{key} must be a number"
        ))),
        None => Ok(None),
    }
}

fn max_results(
    args: &serde_json::Map<String, Value>,
    default: usize,
) -> Result<usize, JsonRpcError> {
    max_arg(args, "max_results", default)
}

fn max_arg(
    args: &serde_json::Map<String, Value>,
    key: &str,
    default: usize,
) -> Result<usize, JsonRpcError> {
    match args.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(limit_value)
            .ok_or_else(|| JsonRpcError::invalid_params(format!("{key} must be an integer >= 0"))),
        Some(_) => Err(JsonRpcError::invalid_params(format!(
            "{key} must be an integer >= 0"
        ))),
        None => Ok(default),
    }
}

fn limit_value(value: u64) -> usize {
    if value == 0 {
        usize::MAX
    } else {
        value as usize
    }
}

fn limit_text_lines(text: &str, max: usize) -> String {
    text.lines().take(max).collect::<Vec<_>>().join("\n")
}

fn limit<I>(iter: I, max: usize) -> impl Iterator<Item = I::Item>
where
    I: IntoIterator,
{
    iter.into_iter().take(max)
}

fn addr_in_range(addr: &str, start: u64, end: u64) -> bool {
    parse_addr(addr)
        .map(|value| value >= start && value < end)
        .unwrap_or(false)
}

#[allow(dead_code)]
fn _session_debug_name(session: &Session) -> String {
    session
        .binary
        .name
        .clone()
        .unwrap_or_else(|| session.session_id.clone())
}
