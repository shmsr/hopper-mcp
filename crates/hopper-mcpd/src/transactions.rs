use crate::model::{Transaction, TransactionOperation};
use crate::protocol::JsonRpcError;

const MAX_RENAME_LEN: usize = 256;
const MAX_COMMENT_LEN: usize = 8192;

pub fn new_transaction(
    transaction_id: String,
    session_id: String,
    session_generation: u64,
    name: Option<String>,
) -> Transaction {
    Transaction {
        transaction_id,
        session_id,
        session_generation,
        name,
        ..Transaction::default()
    }
}

pub fn rename_op(addr: String, value: String) -> Result<TransactionOperation, JsonRpcError> {
    validate_rename_value(&value)?;
    Ok(TransactionOperation {
        kind: "rename".to_string(),
        addr,
        value,
    })
}

pub fn comment_op(
    kind: &str,
    addr: String,
    value: String,
) -> Result<TransactionOperation, JsonRpcError> {
    validate_comment_value(&value)?;
    Ok(TransactionOperation {
        kind: kind.to_string(),
        addr,
        value,
    })
}

fn validate_rename_value(value: &str) -> Result<(), JsonRpcError> {
    if value.is_empty() {
        return Err(JsonRpcError::invalid_params(
            "rename value must be non-empty",
        ));
    }
    if value.len() > MAX_RENAME_LEN {
        return Err(JsonRpcError::invalid_params(format!(
            "rename value must be {MAX_RENAME_LEN} bytes or fewer"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(JsonRpcError::invalid_params(
            "rename value must not contain whitespace",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(JsonRpcError::invalid_params(
            "rename value must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_comment_value(value: &str) -> Result<(), JsonRpcError> {
    if value.len() > MAX_COMMENT_LEN {
        return Err(JsonRpcError::invalid_params(format!(
            "comment value must be {MAX_COMMENT_LEN} bytes or fewer"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(JsonRpcError::invalid_params(
            "comment value must not contain control characters",
        ));
    }
    Ok(())
}
