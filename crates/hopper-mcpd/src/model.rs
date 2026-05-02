use crate::address::normalize_addr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session_id: String,
    #[serde(default)]
    pub binary_id: Option<String>,
    #[serde(default)]
    pub binary: Binary,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub exports: Vec<String>,
    #[serde(default)]
    pub strings: Vec<AddressString>,
    #[serde(default)]
    pub names: Vec<NameEntry>,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    #[serde(default)]
    pub comments: Vec<Comment>,
    #[serde(default, rename = "inlineComments")]
    pub inline_comments: Vec<Comment>,
    #[serde(default)]
    pub cursor: Cursor,
    #[serde(default, deserialize_with = "deserialize_functions")]
    pub functions: BTreeMap<String, Function>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Binary {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub base_address: Option<String>,
    #[serde(default)]
    pub segments: Vec<Value>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddressString {
    pub addr: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NameEntry {
    pub addr: String,
    pub name: String,
    #[serde(default)]
    pub demangled: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Bookmark {
    pub addr: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Comment {
    pub addr: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Cursor {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub procedure: Option<String>,
    #[serde(default)]
    pub selection: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub callers: Vec<String>,
    #[serde(default)]
    pub callees: Vec<String>,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub assembly: Option<String>,
    #[serde(default, alias = "pseudo_code")]
    pub pseudocode: Option<String>,
    #[serde(default)]
    pub basic_blocks: Vec<BasicBlock>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BasicBlock {
    pub addr: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub instructions: Vec<Value>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub transaction_id: String,
    pub session_id: String,
    pub session_generation: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: TransactionStatus,
    #[serde(default)]
    pub operations: Vec<TransactionOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    #[default]
    Open,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOperation {
    pub kind: String,
    pub addr: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FunctionInput {
    Array(Vec<Function>),
    Map(BTreeMap<String, Function>),
}

fn deserialize_functions<'de, D>(deserializer: D) -> Result<BTreeMap<String, Function>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let input = Option::<FunctionInput>::deserialize(deserializer)?;
    let mut out = BTreeMap::new();
    match input {
        Some(FunctionInput::Array(functions)) => {
            for mut function in functions {
                function.addr = normalize_lossy(&function.addr);
                out.insert(function.addr.clone(), function);
            }
        }
        Some(FunctionInput::Map(functions)) => {
            for (addr, mut function) in functions {
                if function.addr.is_empty() {
                    function.addr = addr;
                }
                function.addr = normalize_lossy(&function.addr);
                out.insert(function.addr.clone(), function);
            }
        }
        None => {}
    }
    Ok(out)
}

fn normalize_lossy(value: &str) -> String {
    normalize_addr(value).unwrap_or_else(|| value.to_string())
}
