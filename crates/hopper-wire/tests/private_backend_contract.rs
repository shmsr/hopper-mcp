use hopper_wire::{
    AgentCapabilities, AgentRequest, AgentResponse, AgentStatus, BackendMode, ReadinessState,
    decode, encode,
};
use serde_json::json;

#[test]
fn wire_status_round_trips_private_backend_metadata() {
    let message = AgentResponse::Status(AgentStatus {
        backend_mode: BackendMode::InjectedPrivate,
        readiness: ReadinessState::Ready,
        hopper_version: Some("6.2.8".to_string()),
        hopper_build: Some("stable".to_string()),
        capabilities: AgentCapabilities {
            current_document: true,
            procedures: true,
            writes: false,
            private_api: true,
            injected: true,
            status: true,
        },
        unsupported_reason: None,
    });

    let text = encode(&message).unwrap();
    let decoded: AgentResponse = decode(&text).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn wire_status_matches_private_backend_json_contract() {
    let message = AgentResponse::Status(AgentStatus {
        backend_mode: BackendMode::InjectedPrivate,
        readiness: ReadinessState::Ready,
        hopper_version: Some("6.2.8".to_string()),
        hopper_build: Some("stable".to_string()),
        capabilities: AgentCapabilities {
            current_document: true,
            procedures: true,
            writes: false,
            private_api: true,
            injected: true,
            status: true,
        },
        unsupported_reason: None,
    });
    let expected = json!({
        "type": "status",
        "backendMode": "injected_private",
        "readiness": "ready",
        "hopperVersion": "6.2.8",
        "hopperBuild": "stable",
        "capabilities": {
            "currentDocument": true,
            "procedures": true,
            "writes": false,
            "privateApi": true,
            "injected": true,
            "status": true
        },
        "unsupportedReason": null
    });

    let encoded = serde_json::to_value(&message).unwrap();
    assert_eq!(encoded, expected);

    let decoded: AgentResponse = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn wire_request_status_matches_json_contract() {
    let message = AgentRequest::Status;
    let text = encode(&message).unwrap();
    assert_eq!(text, r#"{"type":"status"}"#);
    let decoded: AgentRequest = decode(&text).unwrap();
    assert_eq!(decoded, message);
}
