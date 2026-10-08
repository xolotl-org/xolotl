use crate::jsonrpc::{
    JSONRPC_EXECUTION_FAILED, JSONRPC_OUTCOME_UNKNOWN, jsonrpc_error, jsonrpc_gateway_error,
    jsonrpc_ok,
};
use crate::output::OutputBudget;
use crate::publication::McpPromptDescriptor;
use crate::render::{
    mcp_prompt_result_json, mcp_resource_result_json, mcp_tool_outcome_result_json,
};
use crate::{McpGatewayError, McpJsonRpcResponse, McpOutputLimits};
use serde::Serialize;
use serde_json::Value as JsonValue;
use xolotl_gateway::{GatewayAccepted, GatewayError, GatewaySubmitResult};
use xolotl_types::{CompletionOrigin, Failure, Outcome, TaintSet, UnresolvedOperations};

pub(crate) enum ResultFormat<'a> {
    Tool,
    Resource {
        uri: &'a str,
        mime_type: Option<&'a str>,
    },
    Prompt(&'a McpPromptDescriptor),
}

#[derive(Serialize)]
struct Accepted<'a> {
    submission_id: &'a str,
    trace_root: &'a str,
    profile_rev: u64,
    surface_id: &'a str,
}

impl<'a> From<&'a GatewayAccepted> for Accepted<'a> {
    fn from(accepted: &'a GatewayAccepted) -> Self {
        Self {
            submission_id: &accepted.submission_id,
            trace_root: &accepted.trace_root,
            profile_rev: accepted.profile_rev,
            surface_id: &accepted.surface_id,
        }
    }
}

#[derive(Serialize)]
struct Metadata<'a> {
    accepted: Accepted<'a>,
    outcome_status: &'static str,
    taint: &'a TaintSet,
    origin: &'static str,
    unresolved_operations: &'a UnresolvedOperations,
}

impl<'a> From<&'a GatewaySubmitResult> for Metadata<'a> {
    fn from(result: &'a GatewaySubmitResult) -> Self {
        Self {
            accepted: (&result.accepted).into(),
            outcome_status: match &result.output.outcome {
                Outcome::Done(_) => "done",
                Outcome::Short(_) => "short",
                Outcome::Fail(_) => "fail",
            },
            taint: &result.output.taint,
            origin: match result.origin {
                CompletionOrigin::CurrentAttempt => "current_attempt",
                CompletionOrigin::CachedOutcome => "cached_outcome",
            },
            unresolved_operations: &result.output.unresolved_operations,
        }
    }
}

#[derive(Serialize)]
struct KnownFailure<'a> {
    #[serde(rename = "xolotl/gateway")]
    metadata: Metadata<'a>,
    failure: &'a Failure,
}

#[derive(Serialize)]
struct Unknown<'a> {
    code: &'static str,
    reason_code: &'a str,
    accepted: Accepted<'a>,
    unresolved_operations: &'a UnresolvedOperations,
}

pub(crate) fn submission_response(
    id: JsonValue,
    result: GatewaySubmitResult,
    format: ResultFormat<'_>,
    limits: McpOutputLimits,
) -> McpJsonRpcResponse {
    let response = (|| -> Result<McpJsonRpcResponse, McpGatewayError> {
        if let Outcome::Fail(failure) = &result.output.outcome
            && !matches!(format, ResultFormat::Tool)
        {
            let data = OutputBudget::new(limits).json(&KnownFailure {
                metadata: (&result).into(),
                failure,
            })?;
            let mut response = jsonrpc_error(id.clone(), JSONRPC_EXECUTION_FAILED);
            if let Some(error) = &mut response.error {
                error.data = Some(data);
            }
            limits.check_message(&response)?;
            return Ok(response);
        }
        let mut rendered = match format {
            ResultFormat::Tool => {
                mcp_tool_outcome_result_json(result.output.outcome.clone(), limits)?
            }
            ResultFormat::Resource { uri, mime_type } => mcp_resource_result_json(
                result
                    .output
                    .outcome
                    .value()
                    .ok_or_else(|| {
                        McpGatewayError::BadResult("resource result has no value".into())
                    })?
                    .clone(),
                uri,
                mime_type,
                limits,
            )?,
            ResultFormat::Prompt(descriptor) => mcp_prompt_result_json(
                result
                    .output
                    .outcome
                    .value()
                    .ok_or_else(|| McpGatewayError::BadResult("prompt result has no value".into()))?
                    .clone(),
                descriptor,
                limits,
            )?,
        };
        let metadata = OutputBudget::new(limits).json(&Metadata::from(&result))?;
        let object = rendered
            .as_object_mut()
            .ok_or_else(|| McpGatewayError::BadResult("MCP result is not an object".into()))?;
        let metadata_object = object
            .entry("_meta")
            .or_insert_with(|| JsonValue::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or_else(|| {
                McpGatewayError::BadResult("MCP result metadata is not an object".into())
            })?;
        metadata_object.insert("xolotl/gateway".into(), metadata);
        let response = jsonrpc_ok(id.clone(), rendered);
        limits.check_message(&response)?;
        Ok(response)
    })();
    match response {
        Ok(response) => response,
        Err(error) => gateway_error_response(
            id,
            "mcp_result_delivery",
            McpGatewayError::Gateway(GatewayError::submission_indeterminate(
                result.accepted,
                result.output.unresolved_operations,
                "response_encoding_failed",
                error.to_string(),
            )),
            limits,
        ),
    }
}

pub(crate) fn gateway_error_response(
    mut id: JsonValue,
    label: &'static str,
    error: McpGatewayError,
    limits: McpOutputLimits,
) -> McpJsonRpcResponse {
    let evidence = match &error {
        McpGatewayError::Gateway(GatewayError::SubmissionIndeterminate(evidence)) => {
            Some(evidence.as_ref())
        }
        McpGatewayError::Gateway(GatewayError::Indeterminate(_)) => None,
        _ => return jsonrpc_gateway_error(id, label, error),
    };
    tracing::warn!(label, error = ?error, "mcp gateway response failed");
    loop {
        if let Some(evidence) = evidence {
            let mut unresolved = UnresolvedOperations::default();
            unresolved.merge(&evidence.unresolved_operations);
            loop {
                let data = OutputBudget::new(limits).json(&Unknown {
                    code: "outcome_unknown",
                    reason_code: evidence.reason_code,
                    accepted: (&evidence.accepted).into(),
                    unresolved_operations: &unresolved,
                });
                if let Ok(data) = data {
                    let mut response = jsonrpc_error(id.clone(), JSONRPC_OUTCOME_UNKNOWN);
                    if let Some(error) = &mut response.error {
                        error.data = Some(data);
                    }
                    if limits.check_message(&response).is_ok() {
                        return response;
                    }
                }
                if unresolved.operation_ids.pop().is_none() {
                    break;
                }
                unresolved.identities_incomplete = true;
            }
        } else {
            let response = jsonrpc_error(id.clone(), JSONRPC_OUTCOME_UNKNOWN);
            if limits.check_message(&response).is_ok() {
                return response;
            }
        }
        if id.is_null() {
            return jsonrpc_error(JsonValue::Null, JSONRPC_OUTCOME_UNKNOWN);
        }
        id = JsonValue::Null;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use xolotl_types::{ExecutionOutput, Path, TaintSource, Value};

    fn accepted() -> GatewayAccepted {
        GatewayAccepted {
            submission_id: "original-submission".into(),
            trace_root: "original-trace".into(),
            profile_rev: 7,
            surface_id: "surface".into(),
        }
    }

    #[test]
    fn unknown_evidence_is_bounded_without_becoming_a_rejection() -> Result<()> {
        let mut unresolved = UnresolvedOperations::default();
        for index in 0..64 {
            ensure!(unresolved.record(&format!("operation-{index:03}-{}", "x".repeat(128))));
        }
        for structured in [false, true] {
            for already_incomplete in [false, true] {
                unresolved.identities_incomplete = already_incomplete;
                for limits in [
                    McpOutputLimits::default(),
                    McpOutputLimits {
                        max_message_bytes: 1024,
                        ..McpOutputLimits::default()
                    },
                    McpOutputLimits {
                        max_message_bytes: 256,
                        max_json_nodes: 8,
                        ..McpOutputLimits::default()
                    },
                ] {
                    limits.validate()?;
                    for id in [
                        JsonValue::from("request"),
                        JsonValue::from("request".repeat(4096)),
                    ] {
                        let error = if structured {
                            GatewayError::submission_indeterminate(
                                accepted(),
                                unresolved.clone(),
                                "settlement_failed",
                                "private bearer credential".into(),
                            )
                        } else {
                            GatewayError::Indeterminate("private bearer credential".into())
                        };
                        let response = gateway_error_response(id, "fixture", error.into(), limits);
                        limits.check_message(&response)?;
                        let encoded = serde_json::to_string(&response)?;
                        ensure!(!encoded.contains("private bearer credential"));
                        let error = response.error.context("unknown error missing")?;
                        ensure!(error.code == JSONRPC_OUTCOME_UNKNOWN);
                        ensure!(error.message == "outcome unknown; reconcile before retrying");
                        if let Some(data) = error.data {
                            ensure!(structured);
                            ensure!(data["accepted"]["submission_id"] == "original-submission");
                            ensure!(data["reason_code"] == "settlement_failed");
                            let retained: UnresolvedOperations =
                                serde_json::from_value(data["unresolved_operations"].clone())?;
                            ensure!(retained.validate());
                            ensure!(
                                retained.operation_ids
                                    == unresolved.operation_ids[..retained.operation_ids.len()]
                            );
                            ensure!(
                                retained.identities_incomplete
                                    == (already_incomplete
                                        || retained.operation_ids.len()
                                            != unresolved.operation_ids.len())
                            );
                            if limits.max_message_bytes
                                == McpOutputLimits::default().max_message_bytes
                            {
                                ensure!(retained == unresolved);
                            } else {
                                ensure!(retained.identities_incomplete);
                            }
                        } else {
                            ensure!(!structured || limits.max_json_nodes == 8);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn completed_results_keep_provenance_origin_and_known_failures() -> Result<()> {
        let failure = Failure::Custom {
            kind: "business_failure".into(),
            message: "known failure".into(),
        };
        let taint = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://protected/value")?,
        });
        let mut unresolved = UnresolvedOperations::default();
        ensure!(unresolved.record("earlier-effect"));
        for outcome in [
            Outcome::Done(Value::from("payload")),
            Outcome::Short(Value::from("payload")),
            Outcome::Fail(failure.clone()),
        ] {
            for tool in [false, true] {
                let result = GatewaySubmitResult {
                    accepted: accepted(),
                    output: ExecutionOutput::new(outcome.clone(), taint.clone())
                        .with_unresolved_operations(unresolved.clone()),
                    origin: CompletionOrigin::CachedOutcome,
                };
                let format = if tool {
                    ResultFormat::Tool
                } else {
                    ResultFormat::Resource {
                        uri: "xolotl://resource",
                        mime_type: None,
                    }
                };
                let response = submission_response(
                    JsonValue::from(1),
                    result,
                    format,
                    McpOutputLimits::default(),
                );
                let metadata = if !tool && matches!(outcome, Outcome::Fail(_)) {
                    let error = response.error.context("known failure error missing")?;
                    ensure!(error.code == JSONRPC_EXECUTION_FAILED);
                    let data = error.data.context("known failure data missing")?;
                    ensure!(data["failure"] == serde_json::to_value(&failure)?);
                    data["xolotl/gateway"].clone()
                } else {
                    ensure!(response.error.is_none());
                    let result = response.result.context("completed result missing")?;
                    if tool {
                        ensure!(result["isError"] == matches!(outcome, Outcome::Fail(_)));
                    }
                    result["_meta"]["xolotl/gateway"].clone()
                };
                ensure!(metadata["accepted"]["trace_root"] == "original-trace");
                ensure!(metadata["origin"] == "cached_outcome");
                ensure!(
                    metadata["outcome_status"]
                        == match outcome {
                            Outcome::Done(_) => "done",
                            Outcome::Short(_) => "short",
                            Outcome::Fail(_) => "fail",
                        }
                );
                ensure!(serde_json::from_value::<TaintSet>(metadata["taint"].clone())? == taint);
                ensure!(
                    serde_json::from_value::<UnresolvedOperations>(
                        metadata["unresolved_operations"].clone()
                    )? == unresolved
                );
            }
        }
        let result = GatewaySubmitResult {
            accepted: accepted(),
            output: ExecutionOutput::new(
                Outcome::Done(Value::integer(1)),
                TaintSet::of(TaintSource::Fetched {
                    host: "private-source".repeat(4096).into(),
                }),
            ),
            origin: CompletionOrigin::CurrentAttempt,
        };
        let response = submission_response(
            JsonValue::from(1),
            result,
            ResultFormat::Tool,
            McpOutputLimits {
                max_message_bytes: 1024,
                ..McpOutputLimits::default()
            },
        );
        let error = response
            .error
            .context("oversized sources were silently discarded")?;
        ensure!(error.code == JSONRPC_OUTCOME_UNKNOWN);
        let data = error
            .data
            .context("oversized sources lost acceptance evidence")?;
        ensure!(data["accepted"]["submission_id"] == "original-submission");
        ensure!(data["reason_code"] == "response_encoding_failed");
        ensure!(response.result.is_none());
        Ok(())
    }
}
