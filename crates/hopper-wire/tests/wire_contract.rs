use hopper_wire::{
    AgentCapabilities, AgentRequest, AgentResponse, HandshakeRequest, HandshakeResponse,
    WIRE_VERSION, WireProcedure, decode,
};
use serde_json::json;

#[test]
fn handshake_round_trips_and_reports_capabilities() {
    let request = HandshakeRequest {
        wire_version: WIRE_VERSION,
        daemon_version: "0.1.0".to_string(),
    };
    let text = serde_json::to_string(&request).unwrap();
    let decoded: HandshakeRequest = serde_json::from_str(&text).unwrap();
    assert_eq!(decoded.wire_version, 1);

    let response = HandshakeResponse {
        accepted: true,
        wire_version: WIRE_VERSION,
        agent_version: "0.1.0".to_string(),
        hopper_version: Some("6.x".to_string()),
        capabilities: AgentCapabilities {
            current_document: true,
            procedures: true,
            writes: false,
            private_api: false,
            injected: false,
            status: false,
        },
        unsupported_reason: None,
    };
    assert!(response.capabilities.procedures);
}

#[test]
fn handshake_response_deserializes_legacy_capabilities_without_private_flags() {
    let legacy = json!({
        "accepted": true,
        "wireVersion": WIRE_VERSION,
        "agentVersion": "0.1.0",
        "hopperVersion": "6.x",
        "capabilities": {
            "currentDocument": true,
            "procedures": true,
            "writes": false
        },
        "unsupportedReason": null
    });

    let decoded: HandshakeResponse = serde_json::from_value(legacy).unwrap();

    assert_eq!(
        decoded.capabilities,
        AgentCapabilities {
            current_document: true,
            procedures: true,
            writes: false,
            private_api: false,
            injected: false,
            status: false,
        }
    );
}

#[test]
fn agent_request_handshake_matches_wire_contract() {
    let request = AgentRequest::Handshake(HandshakeRequest {
        wire_version: WIRE_VERSION,
        daemon_version: "0.1.0".to_string(),
    });
    let expected = json!({
        "type": "handshake",
        "wireVersion": WIRE_VERSION,
        "daemonVersion": "0.1.0"
    });

    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded, expected);

    let decoded: AgentRequest = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn agent_request_list_procedures_matches_wire_contract() {
    let request = AgentRequest::ListProcedures {
        max_results: Some(7),
    };
    let expected = json!({
        "type": "list_procedures",
        "maxResults": 7
    });

    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded, expected);

    let decoded: AgentRequest = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn agent_request_status_matches_wire_contract() {
    let request = AgentRequest::Status;

    let encoded = serde_json::to_string(&request).unwrap();
    assert_eq!(encoded, r#"{"type":"status"}"#);

    let decoded: AgentRequest = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn agent_response_current_document_matches_wire_contract() {
    let response = AgentResponse::CurrentDocument {
        document_id: "doc-1".to_string(),
        name: "Calculator".to_string(),
    };
    let expected = json!({
        "type": "current_document",
        "documentId": "doc-1",
        "name": "Calculator"
    });

    let encoded = serde_json::to_value(&response).unwrap();
    assert_eq!(encoded, expected);

    let decoded: AgentResponse = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn agent_response_procedures_matches_wire_contract() {
    let response = AgentResponse::Procedures {
        procedures: vec![WireProcedure {
            addr: "0x1000".to_string(),
            name: Some("main".to_string()),
            size: Some(42),
        }],
        truncated: false,
    };
    let expected = json!({
        "type": "procedures",
        "procedures": [
            {
                "addr": "0x1000",
                "name": "main",
                "size": 42
            }
        ],
        "truncated": false
    });

    let encoded = serde_json::to_value(&response).unwrap();
    assert_eq!(encoded, expected);

    let decoded: AgentResponse = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn decode_reports_wire_error_for_invalid_json() {
    let error = decode::<AgentRequest>("not json").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("failed to deserialize wire message")
    );
}
