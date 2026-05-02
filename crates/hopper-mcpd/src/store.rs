use crate::address;
use crate::model::{Transaction, TransactionOperation, TransactionStatus};
use crate::protocol::JsonRpcError;
use crate::resources;
use crate::transactions;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub use crate::model::{
    AddressString, BasicBlock, Binary, Bookmark, Comment, Cursor, Function, NameEntry, Session,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotStore {
    #[serde(default)]
    sessions: BTreeMap<String, Session>,
    #[serde(default)]
    session_generations: BTreeMap<String, u64>,
    #[serde(default)]
    current_session_id: Option<String>,
    #[serde(default)]
    transactions: BTreeMap<String, Transaction>,
    #[serde(default)]
    next_transaction_number: u64,
}

impl SnapshotStore {
    pub(crate) fn rehydrate_after_load(&mut self) {
        self.session_generations
            .retain(|session_id, _| self.sessions.contains_key(session_id));
        for session_id in self.sessions.keys() {
            self.session_generations
                .entry(session_id.clone())
                .or_insert(1);
        }
        if self
            .current_session_id
            .as_ref()
            .is_some_and(|session_id| !self.sessions.contains_key(session_id))
        {
            self.current_session_id = None;
        }
        if let Some(max_transaction_number) = self
            .transactions
            .keys()
            .filter_map(|transaction_id| transaction_id.strip_prefix("txn-")?.parse::<u64>().ok())
            .max()
        {
            self.next_transaction_number = self.next_transaction_number.max(max_transaction_number);
        }
    }

    pub fn upsert_session(&mut self, session: Session) -> Result<&Session, JsonRpcError> {
        let id = self.insert_session(session, true)?;
        Ok(self.sessions.get(&id).expect("inserted session missing"))
    }

    pub fn open_session(
        &mut self,
        session: Session,
        overwrite: bool,
    ) -> Result<Value, JsonRpcError> {
        let id = self.insert_session(session, overwrite)?;
        let session = self.sessions.get(&id).expect("inserted session missing");
        Ok(self.describe_session(session))
    }

    fn insert_session(
        &mut self,
        mut session: Session,
        overwrite: bool,
    ) -> Result<String, JsonRpcError> {
        if session.session_id.trim().is_empty() {
            return Err(JsonRpcError::invalid_params(
                "open_session requires session.sessionId",
            ));
        }
        session.session_id = session.session_id.trim().to_string();
        if !overwrite && self.sessions.contains_key(&session.session_id) {
            return Err(JsonRpcError::invalid_params(format!(
                "Session already exists: {}",
                session.session_id
            )));
        }
        normalize_session(&mut session);
        let id = session.session_id.clone();
        let generation = self.session_generation(&id).unwrap_or(0) + 1;
        self.sessions.insert(id.clone(), session);
        self.session_generations.insert(id.clone(), generation);
        self.current_session_id = Some(id.clone());
        Ok(id)
    }

    pub fn current_session_id(&self) -> Option<&str> {
        self.current_session_id.as_deref()
    }

    pub fn session(&self, session_id: Option<&str>) -> Result<&Session, JsonRpcError> {
        self.current_session(session_id)
    }

    pub fn current_session(&self, session_id: Option<&str>) -> Result<&Session, JsonRpcError> {
        let id = match session_id {
            Some("current") | None => self.current_session_id.as_deref().ok_or_else(|| {
                JsonRpcError::invalid_params("No current session. Call open_session first.")
            })?,
            Some(id) => id,
        };
        self.sessions
            .get(id)
            .ok_or_else(|| JsonRpcError::invalid_params(format!("Unknown session: {id}")))
    }

    pub fn function(
        &self,
        procedure: &str,
        session_id: Option<&str>,
    ) -> Result<&Function, JsonRpcError> {
        let session = self.current_session(session_id)?;
        if let Some(function) = session.functions.get(&normalize_addr(procedure)) {
            return Ok(function);
        }
        if let Some(function) = session
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(procedure))
        {
            return Ok(function);
        }
        Err(JsonRpcError::invalid_params(format!(
            "Unknown procedure: {procedure}. Try resolve or list(kind:'procedures')."
        )))
    }

    pub fn describe_session(&self, session: &Session) -> Value {
        json!({
            "sessionId": session.session_id,
            "binary": {
                "name": session.binary.name,
                "format": session.binary.format,
                "arch": session.binary.arch,
                "baseAddress": session.binary.base_address
            },
            "counts": {
                "functions": session.functions.len(),
                "strings": session.strings.len(),
                "imports": session.imports.len(),
                "exports": session.exports.len(),
                "names": session.names.len(),
                "segments": session.binary.segments.len()
            }
        })
    }

    pub fn list_sessions(&self) -> Vec<Value> {
        self.sessions
            .values()
            .map(|session| self.describe_session(session))
            .collect()
    }

    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }

    pub fn resources(&self) -> Vec<Value> {
        resources::resource_values()
    }

    pub fn resource(&self, uri: &str) -> Result<Value, JsonRpcError> {
        let session = self.session(None)?;
        match uri {
            resources::SESSION_CURRENT_URI => Ok(self.describe_session(session)),
            resources::BINARY_METADATA_URI => Ok(json!(session.binary)),
            resources::FUNCTIONS_URI => Ok(capped(session.functions.values())),
            resources::STRINGS_URI | resources::BINARY_STRINGS_URI => {
                Ok(capped(session.strings.iter()))
            }
            resources::NAMES_URI => Ok(capped(session.names.iter())),
            resources::TRANSACTIONS_PENDING_URI => Ok(json!({
                "transactions": self.transactions.values().filter(|txn| txn.status == TransactionStatus::Open).collect::<Vec<_>>()
            })),
            _ => Err(JsonRpcError::invalid_params(format!(
                "Unknown resource: {uri}"
            ))),
        }
    }

    pub fn begin_transaction(&mut self, name: Option<String>) -> Result<Value, JsonRpcError> {
        let session_id = self
            .current_session_id
            .as_deref()
            .ok_or_else(|| {
                JsonRpcError::invalid_params("No current session. Call open_session first.")
            })?
            .to_string();
        let session_generation = self.session_generation(&session_id)?;
        self.next_transaction_number += 1;
        let transaction_id = format!("txn-{}", self.next_transaction_number);
        let transaction = transactions::new_transaction(
            transaction_id.clone(),
            session_id,
            session_generation,
            name,
        );
        self.transactions
            .insert(transaction_id.clone(), transaction.clone());
        Ok(json!(transaction))
    }

    pub fn queue_operation(
        &mut self,
        transaction_id: &str,
        operation: TransactionOperation,
    ) -> Result<Value, JsonRpcError> {
        self.open_transaction(transaction_id)?;
        let transaction = self.open_transaction_mut(transaction_id)?;
        transaction.operations.push(operation);
        Ok(json!(transaction))
    }

    pub fn preview_transaction(&self, transaction_id: &str) -> Result<Value, JsonRpcError> {
        let transaction = self.open_transaction(transaction_id)?;
        Ok(json!(transaction))
    }

    pub fn commit_transaction(&mut self, transaction_id: &str) -> Result<Value, JsonRpcError> {
        let transaction = self.open_transaction(transaction_id)?;
        let session_id = transaction.session_id.clone();
        let operations = transaction.operations.clone();
        let mut draft = self.current_session(Some(&session_id))?.clone();

        for operation in &operations {
            apply_operation_to_session(&mut draft, operation)?;
        }

        let next_generation = self.session_generation(&session_id)? + 1;
        self.sessions.insert(session_id.clone(), draft);
        self.session_generations.insert(session_id, next_generation);
        let transaction = self.open_transaction_mut(transaction_id)?;
        transaction.status = TransactionStatus::Committed;
        Ok(json!({
            "transactionId": transaction.transaction_id,
            "status": transaction.status,
            "applied": true,
            "operations": transaction.operations
        }))
    }

    pub fn rollback_transaction(&mut self, transaction_id: &str) -> Result<Value, JsonRpcError> {
        let transaction = self.open_transaction_mut(transaction_id)?;
        transaction.status = TransactionStatus::RolledBack;
        Ok(json!({
            "transactionId": transaction.transaction_id,
            "status": transaction.status,
            "applied": false,
            "operations": transaction.operations
        }))
    }

    fn transaction(&self, transaction_id: &str) -> Result<&Transaction, JsonRpcError> {
        self.transactions.get(transaction_id).ok_or_else(|| {
            JsonRpcError::invalid_params(format!("Unknown transaction: {transaction_id}"))
        })
    }

    fn open_transaction(&self, transaction_id: &str) -> Result<&Transaction, JsonRpcError> {
        let transaction = self.transaction(transaction_id)?;
        if transaction.status != TransactionStatus::Open {
            return Err(JsonRpcError::invalid_params(format!(
                "Transaction is not open: {transaction_id}"
            )));
        }
        self.ensure_transaction_session_current(transaction)?;
        Ok(transaction)
    }

    fn open_transaction_mut(
        &mut self,
        transaction_id: &str,
    ) -> Result<&mut Transaction, JsonRpcError> {
        let transaction = self.transactions.get_mut(transaction_id).ok_or_else(|| {
            JsonRpcError::invalid_params(format!("Unknown transaction: {transaction_id}"))
        })?;
        if transaction.status != TransactionStatus::Open {
            return Err(JsonRpcError::invalid_params(format!(
                "Transaction is not open: {transaction_id}"
            )));
        }
        Ok(transaction)
    }

    fn ensure_transaction_session_current(
        &self,
        transaction: &Transaction,
    ) -> Result<(), JsonRpcError> {
        let current_generation = self.session_generation(&transaction.session_id)?;
        if current_generation != transaction.session_generation {
            return Err(JsonRpcError::invalid_params(format!(
                "Transaction session generation changed for {}: expected {}, found {}",
                transaction.session_id, transaction.session_generation, current_generation
            )));
        }
        Ok(())
    }

    fn session_generation(&self, session_id: &str) -> Result<u64, JsonRpcError> {
        self.session_generations
            .get(session_id)
            .copied()
            .ok_or_else(|| JsonRpcError::invalid_params(format!("Unknown session: {session_id}")))
    }
}

fn apply_operation_to_session(
    session: &mut Session,
    operation: &TransactionOperation,
) -> Result<(), JsonRpcError> {
    match operation.kind.as_str() {
        "rename" => {
            let function = session.functions.get_mut(&operation.addr).ok_or_else(|| {
                JsonRpcError::invalid_params(format!(
                    "Unknown procedure address: {}",
                    operation.addr
                ))
            })?;
            function.name = Some(operation.value.clone());
            upsert_name(&mut session.names, &operation.addr, &operation.value);
            Ok(())
        }
        "comment" => {
            upsert_comment(&mut session.comments, &operation.addr, &operation.value);
            Ok(())
        }
        "inline_comment" => {
            upsert_comment(
                &mut session.inline_comments,
                &operation.addr,
                &operation.value,
            );
            Ok(())
        }
        _ => Err(JsonRpcError::invalid_params(format!(
            "Unsupported transaction operation kind: {}",
            operation.kind
        ))),
    }
}

fn upsert_name(names: &mut Vec<NameEntry>, addr: &str, value: &str) {
    if let Some(name) = names.iter_mut().find(|name| name.addr == addr) {
        name.name = value.to_string();
        return;
    }
    names.push(NameEntry {
        addr: addr.to_string(),
        name: value.to_string(),
        demangled: None,
    });
}

fn upsert_comment(comments: &mut Vec<Comment>, addr: &str, value: &str) {
    if let Some(comment) = comments.iter_mut().find(|comment| comment.addr == addr) {
        comment.comment = Some(value.to_string());
        comment.value = None;
        return;
    }
    comments.push(Comment {
        addr: addr.to_string(),
        comment: Some(value.to_string()),
        value: None,
    });
}

fn capped<'a, T: serde::Serialize + 'a>(items: impl Iterator<Item = &'a T>) -> Value {
    let items: Vec<_> = items.collect();
    let total = items.len();
    let limited: Vec<_> = items.into_iter().take(resources::RESOURCE_LIMIT).collect();
    json!({
        "total": total,
        "truncated": total > resources::RESOURCE_LIMIT,
        "limit": resources::RESOURCE_LIMIT,
        "items": limited
    })
}

impl Session {
    pub fn function_by_query(&self, query: Option<&str>) -> Result<&Function, JsonRpcError> {
        let q = query
            .or(self.cursor.procedure.as_deref())
            .or(self.cursor.address.as_deref())
            .ok_or_else(|| {
                JsonRpcError::invalid_params("procedure requires procedure or a captured cursor")
            })?;
        if let Some(function) = self.functions.get(&normalize_addr(q)) {
            return Ok(function);
        }
        let q_lower = q.to_lowercase();
        let matches: Vec<&Function> = self
            .functions
            .values()
            .filter(|function| {
                function
                    .name
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q_lower)
            })
            .collect();
        match matches.as_slice() {
            [function] => Ok(function),
            [] => Err(JsonRpcError::invalid_params(format!(
                "Unknown procedure: {q}. Try resolve or list(kind:'procedures')."
            ))),
            _ => Err(JsonRpcError::invalid_params(format!(
                "Ambiguous procedure query: {q}"
            ))),
        }
    }

    pub fn containing_function(&self, address: u64) -> Option<&Function> {
        self.functions
            .values()
            .filter_map(|function| {
                let start = parse_addr(&function.addr)?;
                let size = function.size?;
                if address >= start && address < start.saturating_add(size) {
                    Some((size, start, function))
                } else {
                    None
                }
            })
            .min_by_key(|(size, start, _)| (*size, *start))
            .map(|(_, _, function)| function)
    }
}

pub fn object_from_functions<'a>(functions: impl IntoIterator<Item = &'a Function>) -> Value {
    let mut object = serde_json::Map::new();
    for function in functions {
        object.insert(function.addr.clone(), json!(function));
    }
    Value::Object(object)
}

pub fn names_object(names: &[NameEntry]) -> Value {
    let mut object = serde_json::Map::new();
    for name in names {
        object.insert(
            name.addr.clone(),
            json!({ "name": name.name, "demangled": name.demangled }),
        );
    }
    Value::Object(object)
}

pub fn strings_object(strings: &[AddressString]) -> Value {
    let mut object = serde_json::Map::new();
    for string in strings {
        object.insert(string.addr.clone(), json!(string.value));
    }
    Value::Object(object)
}

pub fn xrefs(session: &Session, address: &str) -> Vec<Value> {
    let target = normalize_addr(address);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    if let Some(function) = session.functions.get(&target) {
        for caller in &function.callers {
            let key = format!("call:{caller}:{target}");
            if seen.insert(key) {
                out.push(json!({ "kind": "caller", "from": caller, "to": target }));
            }
        }
    }
    for function in session.functions.values() {
        for callee in &function.callees {
            if normalize_addr(callee) == target {
                let key = format!("edge:{}:{target}", function.addr);
                if seen.insert(key) {
                    out.push(json!({ "kind": "call", "from": function.addr, "to": target }));
                }
            }
        }
    }
    out
}

pub fn parse_addr(input: &str) -> Option<u64> {
    address::parse_addr(input)
}

pub fn normalize_addr(input: &str) -> String {
    address::normalize_addr(input).unwrap_or_else(|| input.to_string())
}

fn normalize_session(session: &mut Session) {
    let mut functions = BTreeMap::new();
    for (_, mut function) in std::mem::take(&mut session.functions) {
        function.addr = normalize_addr(&function.addr);
        function.callers = function.callers.iter().map(|a| normalize_addr(a)).collect();
        function.callees = function.callees.iter().map(|a| normalize_addr(a)).collect();
        functions.insert(function.addr.clone(), function);
    }
    session.functions = functions;
    for string in &mut session.strings {
        string.addr = normalize_addr(&string.addr);
    }
    for name in &mut session.names {
        name.addr = normalize_addr(&name.addr);
    }
    for bookmark in &mut session.bookmarks {
        bookmark.addr = normalize_addr(&bookmark.addr);
    }
    for comment in &mut session.comments {
        comment.addr = normalize_addr(&comment.addr);
    }
    for comment in &mut session.inline_comments {
        comment.addr = normalize_addr(&comment.addr);
    }
    if let Some(address) = &mut session.cursor.address {
        *address = normalize_addr(address);
    }
    if let Some(procedure) = &mut session.cursor.procedure {
        *procedure = normalize_addr(procedure);
    }
}
