#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Name,
    Imports,
    String,
    Addr,
}

pub fn parse_expression(expression: &str) -> Result<(Predicate, String), String> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err("query expression cannot be empty".to_string());
    }
    let (predicate, value) = expression
        .split_once(':')
        .ok_or_else(|| "query expression must use predicate:value syntax".to_string())?;
    let value = value.trim();
    if value.is_empty() {
        return Err("query predicate value cannot be empty".to_string());
    }
    let predicate = match predicate.trim() {
        "name" => Predicate::Name,
        "imports" => Predicate::Imports,
        "string" => Predicate::String,
        "addr" => Predicate::Addr,
        other => {
            return Err(format!(
                "unsupported query predicate: {other}; supported predicates are name|imports|string|addr"
            ));
        }
    };
    Ok((predicate, value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{Predicate, parse_expression};

    #[test]
    fn parses_supported_predicates() {
        assert_eq!(
            parse_expression("name:_main").unwrap(),
            (Predicate::Name, "_main".to_string())
        );
        assert_eq!(
            parse_expression(" imports : malloc ").unwrap(),
            (Predicate::Imports, "malloc".to_string())
        );
        assert_eq!(
            parse_expression("string:license").unwrap(),
            (Predicate::String, "license".to_string())
        );
        assert_eq!(
            parse_expression("addr:0x1000").unwrap(),
            (Predicate::Addr, "0x1000".to_string())
        );
    }

    #[test]
    fn rejects_invalid_expressions() {
        assert_eq!(
            parse_expression("").unwrap_err(),
            "query expression cannot be empty"
        );
        assert_eq!(
            parse_expression("name").unwrap_err(),
            "query expression must use predicate:value syntax"
        );
        assert_eq!(
            parse_expression("name:").unwrap_err(),
            "query predicate value cannot be empty"
        );
        assert_eq!(
            parse_expression("calls:_main").unwrap_err(),
            "unsupported query predicate: calls; supported predicates are name|imports|string|addr"
        );
    }
}
