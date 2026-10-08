//! Privileged inspection of Source commit evidence.
//!
//! Exact claim identities can come from trusted host incident logs; a retained
//! accepted event decision can also locate its claim. Source ACKs disclose
//! neither. This service owns authorization; the injected storage facet owns
//! consistent read-only evidence. Hosts choose disclosure observation policy;
//! no second private Source audit is required. Absence and errors never permit replay.

use super::{
    ConsoleError, actions::ActionContext, input_map, input_value, map_value, optional_string_arg,
    require_step_up, string_arg,
};
use crate::auth::{AuthError, ConsolePrincipal};
use crate::protocol::ActionCall;
use xolotl_source::{
    MAX_ID_BYTES, SourceClaim, SourceClaimEvidence, SourceClaimId, SourceEventDecisionInspection,
    SourceEvidenceInspection,
};
use xolotl_types::{Path, Value, ValueMap};

struct SourceScope {
    installation_id: String,
    projection_id: String,
    scope_epoch: u64,
    stream_epoch: Option<u64>,
    event_id: String,
}

pub(super) async fn inspect_claim(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Value, ConsoleError> {
    require_step_up(principal)?;
    let (scope, mut input) = parse_scope(&call.input)?;
    let raw_claim_id = string_arg(&mut input, "claim_id")?;
    let claim_id = parse_claim_id(&raw_claim_id)?;
    reject_extra_fields(input)?;
    justification(call)?;
    inspection_target(principal, &scope, "claims")?;
    let inspection = context.state.source_management.as_ref().ok_or_else(|| {
        ConsoleError::BadRequest("Source claim inspection is not installed by this host".into())
    })?;
    let claim = SourceClaim {
        installation_id: &scope.installation_id,
        projection_id: &scope.projection_id,
        scope_epoch: scope.scope_epoch,
        stream_epoch: scope.stream_epoch,
        event_id: &scope.event_id,
        claim_id,
    };
    let evidence = inspection
        .inspect(SourceEvidenceInspection { claim })
        .await
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    evidence_value(evidence, &scope, Some(claim_id))
}

pub(super) async fn inspect_event(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Value, ConsoleError> {
    require_step_up(principal)?;
    let (scope, input) = parse_scope(&call.input)?;
    reject_extra_fields(input)?;
    justification(call)?;
    inspection_target(principal, &scope, "events")?;
    let inspection = context.state.source_management.as_ref().ok_or_else(|| {
        ConsoleError::BadRequest("Source event inspection is not installed by this host".into())
    })?;
    let evidence = inspection
        .inspect_event(SourceEventDecisionInspection {
            installation_id: &scope.installation_id,
            projection_id: &scope.projection_id,
            scope_epoch: scope.scope_epoch,
            stream_epoch: scope.stream_epoch,
            event_id: &scope.event_id,
        })
        .await
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    evidence_value(evidence, &scope, None)
}

fn parse_scope(input: &Value) -> Result<(SourceScope, ValueMap), ConsoleError> {
    let mut input = input_map(input_value(input)?)?;
    let installation_id = string_arg(&mut input, "installation_id")?;
    let projection_id = string_arg(&mut input, "projection_id")?;
    let scope_epoch = string_arg(&mut input, "scope_epoch")?
        .parse::<u64>()
        .ok()
        .filter(|epoch| *epoch > 0)
        .ok_or_else(|| {
            ConsoleError::BadRequest("scope_epoch must be a positive decimal u64".into())
        })?;
    let stream_epoch = optional_string_arg(&mut input, "stream_epoch")?
        .map(|raw| {
            raw.parse::<u64>()
                .ok()
                .filter(|epoch| *epoch > 0)
                .ok_or_else(|| {
                    ConsoleError::BadRequest("stream_epoch must be a positive decimal u64".into())
                })
        })
        .transpose()?;
    let event_id = string_arg(&mut input, "event_id")?;
    for (label, segment) in [
        ("installation_id", installation_id.as_str()),
        ("projection_id", projection_id.as_str()),
        ("event_id", event_id.as_str()),
    ] {
        if segment.is_empty() || segment.len() > MAX_ID_BYTES {
            return Err(ConsoleError::BadRequest(format!("invalid Source {label}")));
        }
        // Match Gateway literal identity rules rather than interpreting any
        // input as a path, wildcard, cluster, or private storage key.
        Path::try_new("state")?.try_push_literal(segment)?;
    }
    Ok((
        SourceScope {
            installation_id,
            projection_id,
            scope_epoch,
            stream_epoch,
            event_id,
        },
        input,
    ))
}

fn reject_extra_fields(input: ValueMap) -> Result<(), ConsoleError> {
    if input.is_empty() {
        Ok(())
    } else {
        Err(ConsoleError::BadRequest(
            "unknown Source inspection input field".into(),
        ))
    }
}

fn justification(call: &ActionCall) -> Result<&str, ConsoleError> {
    call.justification
        .as_deref()
        .filter(|reason| reason.len() <= 1024)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .ok_or_else(|| {
            ConsoleError::BadRequest(
                "Source inspection requires justification of 1..=1024 bytes".into(),
            )
        })
}

fn inspection_target(
    principal: &ConsolePrincipal,
    scope: &SourceScope,
    kind: &str,
) -> Result<Path, ConsoleError> {
    let target = Path::parse("effect://external/source")?
        .try_push_literal(&scope.installation_id)?
        .try_push_literal(&scope.projection_id)?
        .try_push_literal(kind)?
        .try_push_literal("inspect")?;
    if !principal.grants.contains("perform", &target) {
        return Err(AuthError::PermissionDenied.into());
    }
    Ok(target)
}

fn evidence_value(
    evidence: SourceClaimEvidence,
    scope: &SourceScope,
    claim_id: Option<SourceClaimId>,
) -> Result<Value, ConsoleError> {
    match evidence {
        SourceClaimEvidence::Committed(receipt) => {
            // Custom storage adapters must honor the exact scope and, where
            // available, the exact claim contract before Console discloses it.
            if receipt.installation_id != scope.installation_id
                || receipt.projection_id != scope.projection_id
                || receipt.scope_epoch != scope.scope_epoch
                || receipt.stream_epoch != scope.stream_epoch
                || receipt.event_id != scope.event_id
                || claim_id.is_some_and(|claim_id| receipt.claim_id != claim_id)
            {
                return Err(ConsoleError::Operation(
                    "Source inspection returned a different event or claim".into(),
                ));
            }
            Ok(map_value([
                ("status", Value::string("committed".into())),
                (
                    "receipt",
                    map_value([
                        ("installation_id", Value::string(receipt.installation_id)),
                        ("projection_id", Value::string(receipt.projection_id)),
                        (
                            "scope_epoch",
                            Value::string(receipt.scope_epoch.to_string()),
                        ),
                        (
                            "stream_epoch",
                            receipt
                                .stream_epoch
                                .map_or(Value::null(), |epoch| Value::string(epoch.to_string())),
                        ),
                        ("event_id", Value::string(receipt.event_id)),
                        ("claim_id", Value::string(receipt.claim_id.to_string())),
                        ("sink", Value::string(receipt.sink.to_string())),
                        ("received_at_ms", Value::integer(receipt.received_at_ms)),
                    ]),
                ),
            ]))
        }
        SourceClaimEvidence::Unproven => {
            Ok(map_value([("status", Value::string("unproven".into()))]))
        }
    }
}

fn parse_claim_id(raw: &str) -> Result<SourceClaimId, ConsoleError> {
    let mut bytes = [0; 16];
    if raw.len() != 32
        || data_encoding::HEXLOWER
            .decode_mut(raw.as_bytes(), &mut bytes)
            .is_err()
    {
        return Err(ConsoleError::BadRequest(
            "claim_id must be the 32 lowercase hexadecimal digits from the host incident log"
                .into(),
        ));
    }
    Ok(SourceClaimId::from_bytes(bytes))
}

#[cfg(test)]
mod tests;
