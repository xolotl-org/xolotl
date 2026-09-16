//! Admission for MCP's finite ordinary-JSON response projection.

use crate::McpGatewayError;
use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter};
use std::io::{self, Write};
use xolotl_gateway::value_inspection::{ValueAdmissionLimits, admit};
use xolotl_types::Value;

/// Maximum resident depth supported by this recursive ordinary-JSON adapter.
///
/// MCP envelopes and metadata add levels beyond the resident Value. Larger or
/// deeper results belong behind resource references or a streaming transport;
/// this bound does not constrain resident kernel tasks or cumulative streams.
pub const MAX_MCP_JSON_VALUE_DEPTH: usize = 64;

/// Explicit budgets for one MCP JSON-RPC response.
///
/// Admission runs before projecting resident Values into ordinary JSON. It
/// measures logical occurrences, including every use of a shared descendant.
/// Final encoded JSON bytes are checked separately, including MCP envelopes.
#[derive(Clone, Copy, Debug)]
pub struct McpOutputLimits {
    /// Logical resident node occurrences available to one result/page.
    pub max_value_nodes: usize,
    /// Value depth; must not exceed [`MAX_MCP_JSON_VALUE_DEPTH`].
    pub max_value_depth: usize,
    /// Inline accounting bytes before JSON projection; excludes object content.
    pub max_inline_bytes: usize,
    /// Materialized JSON value nodes available to projections and the final response.
    /// This includes byte-array elements and media metadata fields. Must be at
    /// least 8 to permit a compact protocol error.
    pub max_json_nodes: usize,
    /// Maximum encoded response bytes, including JSON escaping and envelopes.
    /// Must be at least 256 to permit a compact protocol error.
    pub max_message_bytes: usize,
}

impl Default for McpOutputLimits {
    fn default() -> Self {
        Self {
            max_value_nodes: 65_536,
            max_value_depth: 32,
            max_inline_bytes: 8 * 1024 * 1024,
            max_json_nodes: 65_536,
            max_message_bytes: 16 * 1024 * 1024,
        }
    }
}

impl McpOutputLimits {
    pub(crate) fn validate(self) -> Result<(), McpGatewayError> {
        if self.max_value_depth > MAX_MCP_JSON_VALUE_DEPTH
            || self.max_json_nodes < 8
            || self.max_message_bytes < 256
        {
            return Err(McpGatewayError::OutputLimit(
                "invalid MCP output limit configuration",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_message(self, message: &impl Serialize) -> Result<(), McpGatewayError> {
        let mut nodes = self.max_json_nodes;
        count_json(message, &mut nodes, self.max_message_bytes)
    }
}

pub(crate) struct OutputBudget {
    remaining: ValueAdmissionLimits,
    remaining_json_nodes: usize,
    max_message_bytes: usize,
}

impl OutputBudget {
    pub(crate) fn new(limits: McpOutputLimits) -> Self {
        Self {
            remaining: ValueAdmissionLimits {
                max_nodes: limits.max_value_nodes,
                max_depth: limits.max_value_depth,
                max_inline_bytes: limits.max_inline_bytes,
            },
            remaining_json_nodes: limits.max_json_nodes,
            max_message_bytes: limits.max_message_bytes,
        }
    }

    pub(crate) fn value(&mut self, value: &Value) -> Result<(), McpGatewayError> {
        let size = admit(value, self.remaining).ok_or(McpGatewayError::OutputLimit(
            "MCP value exceeds configured node, depth, or inline output budget",
        ))?;
        self.remaining.max_nodes -= size.nodes;
        self.remaining.max_inline_bytes -= size.inline_bytes;
        Ok(())
    }

    /// Project already depth-admitted data after counting the actual Serde
    /// output without allocating a JSON tree or encoded byte buffer. All
    /// resident Values must first be admitted through `value` at their root.
    /// The JSON counter also protects non-Value DTOs such as prompt arguments.
    pub(crate) fn json(
        &mut self,
        value: &impl Serialize,
    ) -> Result<serde_json::Value, McpGatewayError> {
        count_json(
            value,
            &mut self.remaining_json_nodes,
            self.max_message_bytes,
        )?;
        Ok(serde_json::to_value(value)?)
    }
}

fn count_json(
    value: &impl Serialize,
    remaining_nodes: &mut usize,
    max_bytes: usize,
) -> Result<(), McpGatewayError> {
    let mut formatter = JsonNodeBudget(remaining_nodes);
    formatter
        .charge()
        .map_err(|_error| McpGatewayError::OutputLimit("MCP JSON node budget exceeded"))?;
    let mut serializer = serde_json::Serializer::with_formatter(ByteBudget(max_bytes), formatter);
    value.serialize(&mut serializer).map_err(|error| {
        if error.is_io() {
            McpGatewayError::OutputLimit("MCP JSON projection exceeds node or encoded byte budget")
        } else {
            McpGatewayError::Serialize(error)
        }
    })
}

// One root is charged up front. Every array element or object value adds
// exactly one JSON node, regardless of which resident type emitted it.
struct JsonNodeBudget<'a>(&'a mut usize);
impl JsonNodeBudget<'_> {
    fn charge(&mut self) -> io::Result<()> {
        *self.0 = self
            .0
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("MCP JSON node budget exceeded"))?;
        Ok(())
    }
}

impl Formatter for JsonNodeBudget<'_> {
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.charge()?;
        CompactFormatter.begin_array_value(writer, first)
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.charge()?;
        CompactFormatter.begin_object_value(writer)
    }
}

struct ByteBudget(usize);
impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("MCP response byte budget exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shared_and_deep_outputs_reject_before_recursive_json_projection() -> anyhow::Result<()> {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut shared = Value::from("result");
                for _ in 0..192 {
                    shared = Value::list(vec![shared.clone(), shared]);
                }
                anyhow::ensure!(
                    OutputBudget::new(McpOutputLimits::default())
                        .value(&shared)
                        .is_err()
                );
                let mut deep = Value::null();
                for _ in 0..20_000 {
                    deep = Value::list(vec![deep]);
                }
                anyhow::ensure!(
                    OutputBudget::new(McpOutputLimits::default())
                        .value(&deep)
                        .is_err()
                );
                Ok::<(), anyhow::Error>(())
            })?
            .join()
            .map_err(|_error| anyhow::anyhow!("output admission worker panicked"))??;
        Ok(())
    }

    #[test]
    fn output_budgets_accumulate_per_page_and_check_escaped_message_bytes() {
        let limits = McpOutputLimits {
            max_value_nodes: 3,
            max_inline_bytes: 16,
            max_message_bytes: 256,
            ..McpOutputLimits::default()
        };
        let value = Value::list(vec![Value::from("hi")]);
        let mut page = OutputBudget::new(limits);
        assert!(page.value(&value).is_ok());
        assert!(page.value(&value).is_err());
        assert!(
            limits
                .check_message(&json!({"text": "\n".repeat(128)}))
                .is_err()
        );
        let larger = McpOutputLimits {
            max_message_bytes: 512,
            ..limits
        };
        assert!(
            larger
                .check_message(&json!({"text": "\n".repeat(128)}))
                .is_ok()
        );
        assert!(OutputBudget::new(limits).value(&value).is_ok());
    }

    #[test]
    fn json_node_budget_counts_byte_expansion_but_accepts_base64_resources() -> anyhow::Result<()> {
        let limits = McpOutputLimits {
            max_json_nodes: 64,
            ..McpOutputLimits::default()
        };
        let bytes = Value::bytes(vec![255; 128 * 1024]);
        let mut output = OutputBudget::new(limits);
        output.value(&bytes)?;
        anyhow::ensure!(output.json(&bytes).is_err());

        let resource = crate::render::mcp_resource_result_json(
            bytes,
            "xolotl://binary",
            Some("application/octet-stream"),
            limits,
        )?;
        limits.check_message(&resource)?;
        anyhow::ensure!(
            resource["contents"][0]["blob"]
                .as_str()
                .is_some_and(|blob| blob.len() > 128 * 1024)
        );
        Ok(())
    }

    #[test]
    fn projection_counts_accumulate_and_include_generated_media_fields() -> anyhow::Result<()> {
        let limits = McpOutputLimits {
            max_json_nodes: 8,
            ..McpOutputLimits::default()
        };
        let tensor = Value::tensor(
            xolotl_types::BlobRef {
                hash: "unloaded".into(),
                size: 32,
                mime: None,
            },
            xolotl_types::DType::F32,
            vec![2, 2, 2],
        );
        let mut output = OutputBudget::new(limits);
        output.value(&tensor)?;
        anyhow::ensure!(output.json(&tensor).is_err());

        let mut page = OutputBudget::new(limits);
        let value = Value::list(vec![Value::null(); 3]);
        page.value(&value)?;
        page.json(&value)?;
        page.value(&value)?;
        page.json(&value)?;
        anyhow::ensure!(page.json(&Value::null()).is_err());
        Ok(())
    }
}
