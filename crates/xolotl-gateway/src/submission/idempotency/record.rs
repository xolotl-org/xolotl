//! Versioned request records. State's required envelope owns result provenance;
//! the payload preserves typed outcomes and acceptance, without stream history.

use std::collections::BTreeMap;
use xolotl_types::{
    CompletionOrigin, ExecutionOutput, Failure, Outcome, TaintedValue, Value, ValueMap,
};

use super::{SubmissionIdempotency, SubmissionIdempotencyFingerprint};
use crate::{GatewayAccepted, GatewayError, GatewaySubmitResult, now_millis};

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
    outcome: &Outcome,
) -> Result<Value, GatewayError> {
    let mut map = base(fingerprint);
    map.insert("state".into(), Value::string("committed".into()));
    map.insert("committed_at_ms".into(), Value::integer(now_millis()));
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
        Value::integer(i64::try_from(accepted.profile_rev).map_err(|_error| {
            GatewayError::Rejected("idempotency accepted profile rev is out of range".into())
        })?),
    );
    map.insert(
        "accepted_surface_id".into(),
        Value::string(accepted.surface_id.clone()),
    );
    match outcome {
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
            Err(GatewayError::LimitExceeded(
                "idempotent submission is already in flight".into(),
            ))
        }
        "committed" => {
            required_i64(&map, "committed_at_ms")?;
            let accepted = accepted(&map, fingerprint)?;
            let outcome = match required_str(&map, "outcome_status")? {
                "done" => Outcome::Done(take_outcome_value(&mut map)?),
                "short" => Outcome::Short(take_outcome_value(&mut map)?),
                "fail" => {
                    let failure =
                        serde_json::from_str::<Failure>(required_str(&map, "failure_json")?)
                            .map_err(|error| {
                                GatewayError::Rejected(format!(
                                    "idempotency failure decode failed: {error}"
                                ))
                            })?;
                    Outcome::Fail(failure)
                }
                _ => {
                    return Err(GatewayError::Rejected(
                        "idempotency record has invalid outcome status".into(),
                    ));
                }
            };
            Ok(SubmissionIdempotency::Replay(Box::new(
                GatewaySubmitResult {
                    accepted,
                    output: ExecutionOutput::new(outcome, taint),
                    origin: CompletionOrigin::CachedOutcome,
                },
            )))
        }
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
    let profile_rev = required_i64(map, "accepted_profile_rev")?;
    if profile_rev < 1 || profile_rev.to_string() != fingerprint.profile_rev {
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
        profile_rev: profile_rev as u64,
        surface_id: surface_id.to_string(),
    })
}

fn base(fingerprint: &SubmissionIdempotencyFingerprint) -> BTreeMap<String, Value> {
    BTreeMap::from([
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
    let matches = required_str(map, "effective_key_hash")? == fingerprint.effective_key_hash
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
