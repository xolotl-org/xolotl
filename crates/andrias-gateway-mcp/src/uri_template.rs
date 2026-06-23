use crate::McpGatewayError;
use crate::validation::is_mcp_uri;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, Eq, PartialEq)]
enum UriTemplateSegment {
    Literal(String),
    Expression(String),
}

pub(crate) fn validate_mcp_uri_template(template: &str) -> Result<(), McpGatewayError> {
    if !is_mcp_uri(template) {
        return Err(McpGatewayError::BadPublication(
            "resource template URI must be non-empty and contain no whitespace".into(),
        ));
    }
    let substitutions: HashMap<String, stduritemplate::Value> = HashMap::new();
    stduritemplate::expand(template, &substitutions).map_err(|error| {
        McpGatewayError::BadPublication(format!("resource template is not RFC6570: {error}"))
    })?;
    mcp_uri_template_segments(template)?;
    Ok(())
}

fn mcp_uri_template_segments(template: &str) -> Result<Vec<UriTemplateSegment>, McpGatewayError> {
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut expression = String::new();
    let mut in_expression = false;
    for ch in template.chars() {
        match (in_expression, ch) {
            (false, '{') => {
                if !literal.is_empty() {
                    segments.push(UriTemplateSegment::Literal(literal.clone()));
                    literal.clear();
                }
                in_expression = true;
                expression.clear();
            }
            (false, '}') => {
                return Err(McpGatewayError::BadPublication(
                    "resource template has unmatched closing brace".into(),
                ));
            }
            (false, ch) => literal.push(ch),
            (true, '{') => {
                return Err(McpGatewayError::BadPublication(
                    "resource template has nested opening brace".into(),
                ));
            }
            (true, '}') => {
                if expression.trim().is_empty() {
                    return Err(McpGatewayError::BadPublication(
                        "resource template expression must not be empty".into(),
                    ));
                }
                segments.push(UriTemplateSegment::Expression(expression.clone()));
                expression.clear();
                in_expression = false;
            }
            (true, ch) if ch.is_ascii_control() || ch.is_ascii_whitespace() => {
                return Err(McpGatewayError::BadPublication(
                    "resource template expression contains whitespace".into(),
                ));
            }
            (true, ch) => expression.push(ch),
        }
    }
    if in_expression {
        return Err(McpGatewayError::BadPublication(
            "resource template has unterminated expression".into(),
        ));
    }
    if !literal.is_empty() {
        segments.push(UriTemplateSegment::Literal(literal));
    }
    Ok(segments)
}

pub(crate) fn mcp_uri_template_variable_names(
    template: &str,
) -> Result<BTreeSet<String>, McpGatewayError> {
    let mut out = BTreeSet::new();
    for segment in mcp_uri_template_segments(template)? {
        if let UriTemplateSegment::Expression(expression) = segment {
            for variable in mcp_uri_template_expression_variables(&expression)? {
                out.insert(variable);
            }
        }
    }
    Ok(out)
}

fn mcp_uri_template_expression_variables(expression: &str) -> Result<Vec<String>, McpGatewayError> {
    let expression = match expression.chars().next() {
        Some(ch) if matches!(ch, '+' | '#' | '.' | '/' | ';' | '?' | '&') => {
            expression.get(ch.len_utf8()..).unwrap_or_default()
        }
        _ => expression,
    };
    let mut out = Vec::new();
    for part in expression.split(',') {
        let variable = match part.split(':').next() {
            Some(value) => value.trim_end_matches('*'),
            None => "",
        };
        if variable.is_empty()
            || variable
                .chars()
                .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
        {
            return Err(McpGatewayError::BadPublication(
                "resource template expression contains invalid variable".into(),
            ));
        }
        out.push(variable.to_string());
    }
    Ok(out)
}

pub(crate) fn mcp_uri_template_specificity(template: &str) -> Result<usize, McpGatewayError> {
    mcp_uri_template_segments(template).map(|segments| {
        segments
            .into_iter()
            .map(|segment| match segment {
                UriTemplateSegment::Literal(value) => value.len(),
                UriTemplateSegment::Expression(_) => 0,
            })
            .sum()
    })
}

pub(crate) fn mcp_uri_template_matches(template: &str, uri: &str) -> Result<bool, McpGatewayError> {
    let segments = mcp_uri_template_segments(template)?;
    match_uri_template_segments(&segments, uri, 0, 0)
}

fn match_uri_template_segments(
    segments: &[UriTemplateSegment],
    uri: &str,
    segment_index: usize,
    uri_index: usize,
) -> Result<bool, McpGatewayError> {
    if segment_index == segments.len() {
        return Ok(uri_index == uri.len());
    }
    match &segments[segment_index] {
        UriTemplateSegment::Literal(literal) => {
            let Some(rest) = uri.get(uri_index..) else {
                return Ok(false);
            };
            if rest.starts_with(literal) {
                Ok(match_uri_template_segments(
                    segments,
                    uri,
                    segment_index.saturating_add(1),
                    uri_index.saturating_add(literal.len()),
                )?)
            } else {
                Ok(false)
            }
        }
        UriTemplateSegment::Expression(_) => {
            let next_literal = next_literal_segment(segments, segment_index.saturating_add(1));
            match next_literal {
                Some(literal) => {
                    let Some(rest) = uri.get(uri_index..) else {
                        return Ok(false);
                    };
                    for (offset, _) in rest.match_indices(literal) {
                        if match_uri_template_segments(
                            segments,
                            uri,
                            segment_index.saturating_add(1),
                            uri_index.saturating_add(offset),
                        )? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                None => Ok(match_uri_template_segments(
                    segments,
                    uri,
                    segment_index.saturating_add(1),
                    uri.len(),
                )?),
            }
        }
    }
}

fn next_literal_segment(segments: &[UriTemplateSegment], start: usize) -> Option<&str> {
    segments
        .iter()
        .skip(start)
        .find_map(|segment| match segment {
            UriTemplateSegment::Literal(literal) if !literal.is_empty() => Some(literal.as_str()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn templates_match_and_expose_variables() -> anyhow::Result<()> {
        ensure!(
            mcp_uri_template_matches("andrias://files/{path}", "andrias://files/a/b")?,
            "path template did not match nested path"
        );
        ensure!(
            mcp_uri_template_matches("andrias://files/{+path}", "andrias://files/a/b")?,
            "reserved expansion template did not match nested path"
        );
        ensure!(
            mcp_uri_template_variable_names("andrias://files/{+path}{?rev}")?
                .into_iter()
                .collect::<Vec<_>>()
                == vec!["path".to_string(), "rev".to_string()],
            "template variable names mismatch"
        );
        ensure!(
            !mcp_uri_template_matches("andrias://files/{path}.md", "andrias://files/a.txt")?,
            "template matched a mismatched extension"
        );
        ensure!(
            validate_mcp_uri_template("andrias://bad/{").is_err(),
            "invalid template was accepted"
        );
        Ok(())
    }
}
