//! Versioned request records. State's required envelope owns result provenance;
//! the payload preserves typed outcomes and acceptance, without stream history.
//! Acceptance revision representation is defined by [`crate::GatewayAccepted::profile_rev`].
//! Summary projection omits result disclosure and failure JSON parsing, but the
//! store has already decoded the original bounded record before this module runs.

use std::collections::BTreeMap;
use xolotl_types::execution::{
    MAX_UNRESOLVED_OPERATION_ID_BYTES, MAX_UNRESOLVED_OPERATION_IDS,
    MAX_UNRESOLVED_OPERATION_TOTAL_BYTES,
};
use xolotl_types::{
    CompletionOrigin, ExecutionOutput, Failure, Outcome, TaintedValue, UnresolvedOperations, Value,
    ValueMap,
};

use super::{SubmissionIdempotency, SubmissionIdempotencyFingerprint};
use crate::{
    GatewayAccepted, GatewayError, GatewayRequestEvidence, GatewayRequestResultClass,
    GatewayRequestSummary, GatewaySubmitResult,
};

const SCHEMA: &str = "gateway-idempotency-v1";

pub(super) fn pending(
    fingerprint: &SubmissionIdempotencyFingerprint,
    now_ms: i64,
    reservation_id: String,
) -> Value {
    let mut map = base(fingerprint);
    map.insert("state".into(), Value::string("pending".into()));
    map.insert("created_at_ms".into(), Value::integer(now_ms));
    // Wall-clock equality must not let an old owner replace a later reservation.
    map.insert("reservation_id".into(), Value::string(reservation_id));
    Value::map(map)
}

pub(super) fn committed(
    fingerprint: &SubmissionIdempotencyFingerprint,
    accepted: &GatewayAccepted,
    output: &ExecutionOutput,
    now_ms: i64,
) -> Result<Value, GatewayError> {
    if !output.unresolved_operations.validate() {
        return Err(GatewayError::Rejected(
            "idempotency reconciliation state is invalid".into(),
        ));
    }
    if accepted.profile_rev == 0 || accepted.profile_rev.to_string() != fingerprint.profile_rev {
        return Err(GatewayError::Rejected(
            "idempotency accepted profile rev is invalid".into(),
        ));
    }
    let mut map = base(fingerprint);
    map.insert("state".into(), Value::string("committed".into()));
    map.insert("committed_at_ms".into(), Value::integer(now_ms));
    map.insert(
        "accepted_submission_id".into(),
        Value::string(accepted.submission_id.clone()),
    );
    map.insert(
        "accepted_trace_root".into(),
        Value::string(accepted.trace_root.clone()),
    );
    map.insert(
        "accepted_profile_rev".into(),
        match i64::try_from(accepted.profile_rev) {
            Ok(revision) => Value::integer(revision),
            Err(_) => Value::string(accepted.profile_rev.to_string()),
        },
    );
    map.insert(
        "accepted_surface_id".into(),
        Value::string(accepted.surface_id.clone()),
    );
    map.insert(
        "unresolved_operations".into(),
        Value::map(BTreeMap::from([
            (
                "operation_ids".into(),
                Value::list(
                    output
                        .unresolved_operations
                        .operation_ids
                        .iter()
                        .cloned()
                        .map(Value::string)
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "identities_incomplete".into(),
                Value::boolean(output.unresolved_operations.identities_incomplete),
            ),
        ])),
    );
    match &output.outcome {
        Outcome::Done(value) => {
            map.insert("outcome_status".into(), Value::string("done".into()));
            map.insert("outcome_value".into(), value.clone());
        }
        Outcome::Short(value) => {
            map.insert("outcome_status".into(), Value::string("short".into()));
            map.insert("outcome_value".into(), value.clone());
        }
        Outcome::Fail(failure) => {
            map.insert("outcome_status".into(), Value::string("fail".into()));
            map.insert(
                "failure_json".into(),
                Value::string(serde_json::to_string(failure).map_err(|error| {
                    GatewayError::Rejected(format!("idempotency outcome encode failed: {error}"))
                })?),
            );
        }
    }
    Ok(Value::map(map))
}

pub(super) fn replay(
    record: TaintedValue,
    fingerprint: &SubmissionIdempotencyFingerprint,
) -> Result<SubmissionIdempotency, GatewayError> {
    let (evidence, result) = decode(record, fingerprint, true)?;
    match evidence {
        GatewayRequestEvidence::Settled(_) => result
            .map(SubmissionIdempotency::Replay)
            .ok_or_else(|| GatewayError::Rejected("retained result unavailable".into())),
        GatewayRequestEvidence::Reserved => Err(GatewayError::LimitExceeded(
            "idempotent result is unsettled; execution liveness is not proven".into(),
        )),
        GatewayRequestEvidence::Retired => Err(GatewayError::Rejected(
            "idempotent result was retired; the original request cannot execute again".into(),
        )),
        GatewayRequestEvidence::Unproven => Err(GatewayError::Rejected(
            "idempotency record did not provide replay evidence".into(),
        )),
    }
}

pub(super) fn submission_hash(record: &TaintedValue) -> Result<String, GatewayError> {
    let map = record
        .value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("idempotency record must be a map".into()))?;
    let hash = required_str(map, "submission_hash")?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayError::Rejected(
            "idempotency submission hash is invalid".into(),
        ));
    }
    Ok(hash.to_owned())
}

pub(super) fn decode(
    record: TaintedValue,
    fingerprint: &SubmissionIdempotencyFingerprint,
    retain_result: bool,
) -> Result<(GatewayRequestEvidence, Option<Box<GatewaySubmitResult>>), GatewayError> {
    let TaintedValue { value, taint } = record;
    let Some(mut map) = value.into_map() else {
        return Err(GatewayError::Rejected(
            "idempotency record must be a map".into(),
        ));
    };
    validate_fingerprint(&map, fingerprint)?;
    match required_str(&map, "state")? {
        "pending" => {
            required_str(&map, "reservation_id")?;
            required_i64(&map, "created_at_ms")?;
            Ok((GatewayRequestEvidence::Reserved, None))
        }
        "committed" => {
            required_i64(&map, "committed_at_ms")?;
            let accepted = accepted(&map, fingerprint)?;
            let unresolved_operations = unresolved_operations(&map)?;
            let result_class = match required_str(&map, "outcome_status")? {
                "done" => GatewayRequestResultClass::Done,
                "short" => GatewayRequestResultClass::Short,
                "fail" => GatewayRequestResultClass::Fail,
                _ => {
                    return Err(GatewayError::Rejected(
                        "idempotency record has invalid outcome status".into(),
                    ));
                }
            };
            match result_class {
                GatewayRequestResultClass::Done | GatewayRequestResultClass::Short => {
                    if !map.contains_key("outcome_value") {
                        return Err(GatewayError::Rejected(
                            "idempotency record is missing outcome value".into(),
                        ));
                    }
                }
                GatewayRequestResultClass::Fail => {
                    required_str(&map, "failure_json")?;
                }
            }
            let evidence = GatewayRequestEvidence::Settled(Box::new(GatewayRequestSummary {
                accepted: accepted.clone(),
                result_class,
                unresolved_operations: unresolved_operations.clone(),
            }));
            if !retain_result {
                return Ok((evidence, None));
            }
            let outcome = match result_class {
                GatewayRequestResultClass::Done => Outcome::Done(take_outcome_value(&mut map)?),
                GatewayRequestResultClass::Short => Outcome::Short(take_outcome_value(&mut map)?),
                GatewayRequestResultClass::Fail => {
                    let failure =
                        serde_json::from_str::<Failure>(required_str(&map, "failure_json")?)
                            .map_err(|error| {
                                GatewayError::Rejected(format!(
                                    "idempotency failure decode failed: {error}"
                                ))
                            })?;
                    Outcome::Fail(failure)
                }
            };
            Ok((
                evidence,
                Some(Box::new(GatewaySubmitResult {
                    accepted,
                    output: ExecutionOutput::new(outcome, taint)
                        .with_unresolved_operations(unresolved_operations),
                    origin: CompletionOrigin::CachedOutcome,
                })),
            ))
        }
        "retired" => Ok((GatewayRequestEvidence::Retired, None)),
        _ => Err(GatewayError::Rejected(
            "idempotency record has invalid state".into(),
        )),
    }
}

fn take_outcome_value(map: &mut ValueMap) -> Result<Value, GatewayError> {
    map.remove("outcome_value")
        .ok_or_else(|| GatewayError::Rejected("idempotency record is missing outcome value".into()))
}

fn accepted(
    map: &ValueMap,
    fingerprint: &SubmissionIdempotencyFingerprint,
) -> Result<GatewayAccepted, GatewayError> {
    let profile_rev = accepted_profile_rev(map)?;
    if profile_rev.to_string() != fingerprint.profile_rev {
        return Err(GatewayError::Rejected(
            "idempotency accepted profile rev is invalid".into(),
        ));
    }
    let surface_id = required_str(map, "accepted_surface_id")?;
    if surface_id != fingerprint.surface_id {
        return Err(GatewayError::Rejected(
            "idempotency accepted surface does not match the request".into(),
        ));
    }
    Ok(GatewayAccepted {
        submission_id: required_str(map, "accepted_submission_id")?.to_string(),
        trace_root: required_str(map, "accepted_trace_root")?.to_string(),
        profile_rev,
        surface_id: surface_id.to_string(),
    })
}

fn accepted_profile_rev(map: &ValueMap) -> Result<u64, GatewayError> {
    let invalid = || GatewayError::Rejected("idempotency accepted profile rev is invalid".into());
    let value = map.get("accepted_profile_rev").ok_or_else(invalid)?;
    if let Some(revision) = value.as_int() {
        return u64::try_from(revision)
            .ok()
            .filter(|revision| *revision > 0)
            .ok_or_else(invalid);
    }
    let text = value.as_str().ok_or_else(invalid)?;
    if text.is_empty()
        || text.len() > 20
        || text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    text.parse::<u64>()
        .ok()
        .filter(|revision| i64::try_from(*revision).is_err())
        .ok_or_else(invalid)
}

fn base(fingerprint: &SubmissionIdempotencyFingerprint) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "retry_epoch".into(),
            Value::string(fingerprint.retry_epoch.to_string()),
        ),
        ("schema".into(), Value::string(SCHEMA.into())),
        (
            "effective_key_hash".into(),
            Value::string(fingerprint.effective_key_hash.clone()),
        ),
        (
            "submission_hash".into(),
            Value::string(fingerprint.submission_hash.clone()),
        ),
        (
            "caller_material_kind".into(),
            Value::string(fingerprint.caller_material_kind.into()),
        ),
        (
            "caller_material_hash".into(),
            Value::string(fingerprint.caller_material_hash.clone()),
        ),
        (
            "profile_name".into(),
            Value::string(fingerprint.profile_name.clone()),
        ),
        (
            "profile_rev".into(),
            Value::string(fingerprint.profile_rev.clone()),
        ),
        (
            "principal_id".into(),
            Value::string(fingerprint.principal_id.clone()),
        ),
        (
            "surface_id".into(),
            Value::string(fingerprint.surface_id.clone()),
        ),
    ])
}

fn validate_fingerprint(
    map: &ValueMap,
    fingerprint: &SubmissionIdempotencyFingerprint,
) -> Result<(), GatewayError> {
    if required_str(map, "schema")? != SCHEMA {
        return Err(GatewayError::Rejected(
            "unsupported idempotency record schema".into(),
        ));
    }
    let epoch = match map.get("retry_epoch") {
        None => 0,
        Some(value) => value
            .as_str()
            .and_then(|text| {
                text.parse::<u64>()
                    .ok()
                    .filter(|epoch| epoch.to_string() == text)
            })
            .ok_or_else(|| GatewayError::Rejected("invalid idempotency retry epoch".into()))?,
    };
    let matches = epoch == fingerprint.retry_epoch
        && required_str(map, "effective_key_hash")? == fingerprint.effective_key_hash
        && required_str(map, "submission_hash")? == fingerprint.submission_hash
        && required_str(map, "caller_material_kind")? == fingerprint.caller_material_kind
        && required_str(map, "caller_material_hash")? == fingerprint.caller_material_hash
        && required_str(map, "profile_name")? == fingerprint.profile_name
        && required_str(map, "profile_rev")? == fingerprint.profile_rev
        && required_str(map, "principal_id")? == fingerprint.principal_id
        && required_str(map, "surface_id")? == fingerprint.surface_id;
    if matches {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "idempotency record fingerprint mismatch".into(),
        ))
    }
}

fn required_str<'a>(map: &'a ValueMap, key: &'static str) -> Result<&'a str, GatewayError> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GatewayError::Rejected(format!("idempotency record has invalid {key}")))
}

fn required_i64(map: &ValueMap, key: &'static str) -> Result<i64, GatewayError> {
    map.get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| GatewayError::Rejected(format!("idempotency record has invalid {key}")))
}

fn unresolved_operations(map: &ValueMap) -> Result<UnresolvedOperations, GatewayError> {
    let invalid = || GatewayError::Rejected("idempotency reconciliation record is invalid".into());
    let saved = map
        .get("unresolved_operations")
        .and_then(Value::as_map)
        .ok_or_else(invalid)?;
    let ids = saved
        .get("operation_ids")
        .and_then(Value::as_list)
        .ok_or_else(invalid)?;
    let identities_incomplete = saved
        .get("identities_incomplete")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    if ids.len() > MAX_UNRESOLVED_OPERATION_IDS {
        return Err(invalid());
    }
    let mut operation_ids = Vec::with_capacity(ids.len());
    let mut bytes = 0usize;
    for item in ids.iter() {
        let id = item.as_str().ok_or_else(invalid)?;
        bytes = bytes.checked_add(id.len()).ok_or_else(invalid)?;
        if id.is_empty()
            || id.len() > MAX_UNRESOLVED_OPERATION_ID_BYTES
            || bytes > MAX_UNRESOLVED_OPERATION_TOTAL_BYTES
            || operation_ids
                .last()
                .is_some_and(|last: &String| last.as_str() >= id)
        {
            return Err(invalid());
        }
        operation_ids.push(id.to_owned());
    }
    Ok(UnresolvedOperations {
        operation_ids,
        identities_incomplete,
    })
}
