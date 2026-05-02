use hopper_mcpd::model::{Function, Session};

pub fn sample_session() -> Session {
    Session {
        session_id: "sample".to_string(),
        functions: [
            (
                "0x100003f50".to_string(),
                Function {
                    addr: "0x100003f50".to_string(),
                    name: Some("sub_100003f50".to_string()),
                    size: Some(128),
                    callers: vec!["0x100004120".to_string()],
                    callees: vec!["0x100004010".to_string()],
                    assembly: Some("stp x29, x30, [sp, #-0x10]!".to_string()),
                    pseudocode: Some("return validate_license();".to_string()),
                    ..Function::default()
                },
            ),
            (
                "0x100004120".to_string(),
                Function {
                    addr: "0x100004120".to_string(),
                    name: Some("_main".to_string()),
                    size: Some(96),
                    callees: vec!["0x100003f50".to_string()],
                    ..Function::default()
                },
            ),
        ]
        .into(),
        ..Session::default()
    }
}
