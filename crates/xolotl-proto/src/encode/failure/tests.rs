use super::*;
use crate::failure_from_pb;
use anyhow::{Result, ensure};
use prost::Message;

fn failures() -> Result<Vec<Failure>> {
    let path = Path::parse("path://remote_eu/state/vault/document")?;
    Ok(vec![
        Failure::PermissionDenied {
            required: vec![
                "invoke://effect/模型".into(),
                "".into(),
                "x".into(),
                "x".into(),
            ],
            actual: vec!["read://state/public".into()],
        },
        Failure::NoHandler { path: path.clone() },
        Failure::BudgetExhausted {
            dim: "tokens".into(),
        },
        Failure::RateLimited,
        Failure::ApprovalPending {
            approval_key: "approval/42".into(),
            reason: "检查\n详情".into(),
        },
        Failure::Timeout,
        Failure::Cancelled,
        Failure::Quarantined {
            op_id: "op-unique".into(),
            reason: "unknown commit".into(),
        },
        Failure::InvalidInput {
            reason: "  precise reason  ".into(),
        },
        Failure::HandlerError {
            kind: "provider-quota".into(),
            message: "".into(),
        },
        Failure::KernelNamespaceProtected,
        Failure::PolicyViolation {
            policy: "disclosure".into(),
            detail: "protected input".into(),
        },
        Failure::PathInvalid {
            path,
            reason: "requires one segment".into(),
        },
        Failure::Custom {
            kind: "application/type".into(),
            message: "diagnostic".into(),
        },
        Failure::InvalidInput {
            reason: String::new(),
        },
        Failure::BudgetExhausted { dim: String::new() },
        Failure::Custom {
            kind: String::new(),
            message: String::new(),
        },
    ])
}

#[test]
fn every_failure_round_trips_all_fields_at_its_exact_wire_budget() -> Result<()> {
    for failure in failures()? {
        let expected = failure_to_pb(&failure);
        let bytes = expected.encode_to_vec();
        ensure!(failure_to_pb_bounded(&failure, bytes.len())? == expected);
        ensure!(failure_to_pb_bounded(&failure, bytes.len() - 1).is_err());
        let restored = pb::Failure::decode(bytes.as_slice())?;
        ensure!(failure_from_pb(&restored)? == failure);
    }
    Ok(())
}

#[test]
fn repeated_empty_labels_and_varint_boundaries_are_admitted_before_cloning() -> Result<()> {
    let wide = Failure::PermissionDenied {
        required: vec![String::new(); 65_536],
        actual: Vec::new(),
    };
    ensure!(failure_to_pb_bounded(&wide, 256).is_err());
    for len in [0, 1, 127, 128, 16_383, 16_384] {
        let failure = Failure::ApprovalPending {
            approval_key: "a".repeat(len),
            reason: "b".repeat(len),
        };
        let size = failure_to_pb(&failure).encoded_len();
        ensure!(failure_to_pb_bounded(&failure, size)?.encoded_len() == size);
        ensure!(failure_to_pb_bounded(&failure, size - 1).is_err());
    }
    Ok(())
}

#[test]
fn missing_unknown_and_malformed_failure_variants_fail_closed() -> Result<()> {
    ensure!(failure_from_pb(&pb::Failure { kind: None }).is_err());
    // Unknown length-delimited alternative 15: prost skips it, leaving no kind.
    let unknown = pb::Failure::decode([0x7a, 0].as_slice())?;
    ensure!(failure_from_pb(&unknown).is_err());
    let missing_path = pb::Failure {
        kind: Some(pb::failure::Kind::PathInvalid(pb::failure::PathInvalid {
            path: None,
            reason: "reason".into(),
        })),
    };
    ensure!(failure_from_pb(&missing_path).is_err());
    let malformed_path = pb::Failure {
        kind: Some(pb::failure::Kind::NoHandler(pb::Path {
            cluster: None,
            scheme: "bad scheme".into(),
            segments: vec!["input".into()],
        })),
    };
    ensure!(failure_from_pb(&malformed_path).is_err());
    Ok(())
}
