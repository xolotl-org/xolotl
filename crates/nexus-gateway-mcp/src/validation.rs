use crate::McpGatewayError;

pub(crate) fn validate_mcp_name(name: &str, label: &'static str) -> Result<(), McpGatewayError> {
    if is_mcp_name_segment(name) {
        Ok(())
    } else {
        Err(McpGatewayError::BadPublication(format!(
            "{label} must be one stable ASCII segment"
        )))
    }
}

pub(crate) fn validate_mcp_uri(uri: &str, label: &'static str) -> Result<(), McpGatewayError> {
    if is_mcp_uri(uri) {
        Ok(())
    } else {
        Err(McpGatewayError::BadPublication(format!(
            "{label} must be a non-empty URI without whitespace"
        )))
    }
}

pub(crate) fn is_mcp_name_segment(name: &str) -> bool {
    if name == "*" || name == "**" {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
}

pub(crate) fn is_mcp_uri(uri: &str) -> bool {
    !uri.trim().is_empty()
        && uri
            .chars()
            .all(|ch| !ch.is_ascii_control() && !ch.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_ascii_segments() {
        for name in ["", "two/segments", " two", "*", "**", "工具"] {
            assert!(!is_mcp_name_segment(name));
        }
        assert!(is_mcp_name_segment("echo.search-v1"));
    }
}
