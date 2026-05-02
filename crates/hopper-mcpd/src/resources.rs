use serde_json::{Value, json};

pub const RESOURCE_LIMIT: usize = 500;
pub const SESSION_CURRENT_URI: &str = "hopper://session/current";
pub const BINARY_METADATA_URI: &str = "hopper://binary/metadata";
pub const FUNCTIONS_URI: &str = "hopper://functions";
pub const STRINGS_URI: &str = "hopper://strings";
pub const BINARY_STRINGS_URI: &str = "hopper://binary/strings";
pub const NAMES_URI: &str = "hopper://names";
pub const TRANSACTIONS_PENDING_URI: &str = "hopper://transactions/pending";

#[derive(Debug, Clone, Copy)]
pub struct ResourceDescriptor {
    pub uri: &'static str,
    pub name: &'static str,
}

pub const RESOURCE_DESCRIPTORS: &[ResourceDescriptor] = &[
    ResourceDescriptor {
        uri: SESSION_CURRENT_URI,
        name: "Current Hopper session",
    },
    ResourceDescriptor {
        uri: BINARY_METADATA_URI,
        name: "Binary metadata",
    },
    ResourceDescriptor {
        uri: FUNCTIONS_URI,
        name: "Functions",
    },
    ResourceDescriptor {
        uri: STRINGS_URI,
        name: "Strings",
    },
    ResourceDescriptor {
        uri: NAMES_URI,
        name: "Names",
    },
    ResourceDescriptor {
        uri: TRANSACTIONS_PENDING_URI,
        name: "Pending transactions",
    },
];

pub fn list_resources() -> Value {
    json!({
        "resources": resource_values()
    })
}

pub fn resource_values() -> Vec<Value> {
    RESOURCE_DESCRIPTORS
        .iter()
        .map(|descriptor| {
            json!({
                "uri": descriptor.uri,
                "name": descriptor.name,
                "mimeType": "application/json"
            })
        })
        .collect()
}
