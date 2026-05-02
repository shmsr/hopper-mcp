use crate::protocol::JsonRpcError;
use serde_json::{Value, json};

pub fn list_prompts() -> Value {
    json!({
        "prompts": [
            {
                "name": "function_triage",
                "description": "Inspect a function and summarize behavior, risk, and next reverse-engineering steps.",
                "arguments": [
                    {
                        "name": "addr",
                        "description": "Function entry address to triage.",
                        "required": true
                    }
                ]
            },
            {
                "name": "hypothesis_workspace",
                "description": "Create a focused workspace for tracking evidence around a reverse-engineering hypothesis.",
                "arguments": [
                    {
                        "name": "topic",
                        "description": "Hypothesis topic or research question.",
                        "required": true
                    }
                ]
            }
        ]
    })
}

pub fn get_prompt(name: &str, arguments: &Value) -> Result<Value, JsonRpcError> {
    match name {
        "function_triage" => function_triage(arguments),
        "hypothesis_workspace" => hypothesis_workspace(arguments),
        _ => Err(JsonRpcError::invalid_params(format!(
            "Unknown prompt: {name}"
        ))),
    }
}

fn function_triage(arguments: &Value) -> Result<Value, JsonRpcError> {
    let addr = required_string(arguments, "addr", "function_triage")?;
    Ok(json!({
        "description": "Inspect a function and summarize behavior, risk, and next reverse-engineering steps.",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": format!("Triage function {addr}. Summarize likely purpose, important callees/callers, strings/imports evidence, risks, and next reverse-engineering steps.")
                }
            }
        ]
    }))
}

fn hypothesis_workspace(arguments: &Value) -> Result<Value, JsonRpcError> {
    let topic = required_string(arguments, "topic", "hypothesis_workspace")?;
    Ok(json!({
        "description": "Create a focused workspace for tracking evidence around a reverse-engineering hypothesis.",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": format!("Build a hypothesis workspace for: {topic}. Identify the claim, supporting and refuting evidence to collect, relevant functions/resources, and next validation steps.")
                }
            }
        ]
    }))
}

fn required_string<'a>(
    arguments: &'a Value,
    field: &str,
    prompt: &str,
) -> Result<&'a str, JsonRpcError> {
    arguments.get(field).and_then(Value::as_str).ok_or_else(|| {
        JsonRpcError::invalid_params(format!("{prompt} requires string argument {field}"))
    })
}
