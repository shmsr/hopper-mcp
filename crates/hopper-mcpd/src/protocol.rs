use serde::{Deserialize, Serialize, de};
use serde_json::Value;

#[derive(Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

impl<'de> Deserialize<'de> for JsonRpcRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut object = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        let jsonrpc = optional_string(&mut object, "jsonrpc")?;
        let method = required_string(&mut object, "method")?;
        let params = object.remove("params");
        let id = object.remove("id");
        Ok(Self {
            jsonrpc,
            id,
            method,
            params,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

fn optional_string<E>(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, E>
where
    E: de::Error,
{
    match object.remove(key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(E::custom(format!("{key} must be a string"))),
        None => Ok(None),
    }
}

fn required_string<E>(object: &mut serde_json::Map<String, Value>, key: &str) -> Result<String, E>
where
    E: de::Error,
{
    match object.remove(key) {
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(E::custom(format!("{key} must be a string"))),
        None => Err(E::custom(format!("missing field `{key}`"))),
    }
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }
    }
}

impl JsonRpcError {
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: message.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }

    pub fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: message.into(),
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: message.into(),
        }
    }
}
