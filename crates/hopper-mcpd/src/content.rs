use serde_json::{Value, json};

pub fn tool_result(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": false
    })
}

pub fn tool_error(message: impl Into<String>) -> Value {
    let message = message.into();
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}
