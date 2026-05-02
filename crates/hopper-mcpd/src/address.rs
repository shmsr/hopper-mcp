pub fn parse_addr(value: &str) -> Option<u64> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

pub fn format_addr(value: u64) -> String {
    format!("0x{value:x}")
}

pub fn normalize_addr(value: &str) -> Option<String> {
    parse_addr(value).map(format_addr)
}
