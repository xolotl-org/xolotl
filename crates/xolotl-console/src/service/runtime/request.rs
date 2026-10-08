//! Decode-free Rust requests alongside the protocol's argument maps.

use crate::{
    protocol::{
        self, ACTION_RUNTIME_OPERATION_INVOKE, ACTION_RUNTIME_OPERATION_SUBMIT,
        ACTION_RUNTIME_PROGRAM_RUN, ACTION_RUNTIME_PROGRAM_SUBMIT, ActionCall, StreamCall,
    },
    runtime::{RuntimeCode, RuntimeRequest, RuntimeSubmissionIdentity},
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use xolotl_graph::portable::{Expression, Program};
use xolotl_types::{BudgetSpec, Value};

pub(super) fn submission_identity(
    value: Option<Value>,
) -> Result<Option<RuntimeSubmissionIdentity>, super::ConsoleError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut fields = super::input_map(value)?;
    let registry_instance = super::string_arg(&mut fields, "registry_instance")?;
    let epoch = super::string_arg(&mut fields, "retry_epoch")?;
    if epoch.is_empty()
        || epoch.len() > 20
        || !epoch.bytes().all(|byte| byte.is_ascii_digit())
        || (epoch.len() > 1 && epoch.starts_with('0'))
    {
        return Err(super::ConsoleError::BadRequest(
            "retry_epoch must be canonical unsigned decimal".into(),
        ));
    }
    let retry_epoch = epoch.parse::<u64>().map_err(|_error| {
        super::ConsoleError::BadRequest("retry_epoch must be canonical unsigned decimal".into())
    })?;
    let nonce = super::string_arg(&mut fields, "nonce")?;
    if !fields.is_empty() {
        return Err(super::ConsoleError::BadRequest(
            "unknown submission identity field".into(),
        ));
    }
    Ok(Some(RuntimeSubmissionIdentity {
        registry_instance,
        retry_epoch,
        nonce,
    }))
}

pub(crate) struct TypedRuntimeInput {
    pub(super) program: Program,
    pub(super) input: Value,
    pub(super) budget: BudgetSpec,
    pub(super) timeout_ms: Option<u64>,
    pub(super) submission_identity: Option<RuntimeSubmissionIdentity>,
    pub(super) limits_admitted: bool,
}

impl TypedRuntimeInput {
    pub(super) fn submission_fingerprint(&self) -> Result<[u8; 32], super::ConsoleError> {
        let mut program = FingerprintWriter(Sha256::new());
        serde_json::to_writer(&mut program, &self.program).map_err(|_error| {
            super::ConsoleError::BadRequest("invalid submission program".into())
        })?;
        let mut budget = FingerprintWriter(Sha256::new());
        serde_json::to_writer(&mut budget, &self.budget).map_err(|_error| {
            super::ConsoleError::BadRequest("invalid submission budget".into())
        })?;
        let mut digest = Sha256::new();
        digest.update(b"xolotl-console-root-submission-v1\0");
        digest.update(program.0.finalize());
        digest.update(self.input.semantic_digest());
        digest.update(budget.0.finalize());
        match self.timeout_ms {
            Some(timeout) => {
                digest.update([1]);
                digest.update(timeout.to_le_bytes());
            }
            None => digest.update([0]),
        }
        Ok(digest.finalize().into())
    }
}

struct FingerprintWriter(Sha256);

impl Write for FingerprintWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn action(request: RuntimeRequest, submission: bool) -> (ActionCall, TypedRuntimeInput) {
    let RuntimeRequest {
        code,
        input,
        budget,
        timeout_ms,
        scope,
        justification,
        ttl_ms,
        registry_rev,
        submission_identity,
    } = request;
    let (action, program) = match code {
        RuntimeCode::Operation { operation } => {
            let program = Program::new(Expression::Invoke { operation });
            (
                if submission {
                    ACTION_RUNTIME_OPERATION_SUBMIT
                } else {
                    ACTION_RUNTIME_OPERATION_INVOKE
                },
                program,
            )
        }
        RuntimeCode::Program(program) => (
            if submission {
                ACTION_RUNTIME_PROGRAM_SUBMIT
            } else {
                ACTION_RUNTIME_PROGRAM_RUN
            },
            program,
        ),
    };
    (
        ActionCall {
            action: action.into(),
            input: Value::null(),
            scope: Some(scope),
            justification: Some(justification),
            ttl_ms: Some(ttl_ms),
            registry_rev,
        },
        TypedRuntimeInput {
            program,
            input,
            budget,
            timeout_ms,
            submission_identity,
            limits_admitted: false,
        },
    )
}

pub(crate) fn stream(request: RuntimeRequest) -> (StreamCall, TypedRuntimeInput) {
    let RuntimeRequest {
        code,
        input,
        budget,
        timeout_ms,
        scope,
        justification,
        ttl_ms,
        registry_rev,
        submission_identity,
    } = request;
    let (stream, program) = match code {
        RuntimeCode::Operation { operation } => {
            let program = Program::new(Expression::Invoke { operation });
            (protocol::STREAM_RUNTIME_OPERATION, program)
        }
        RuntimeCode::Program(program) => (protocol::STREAM_RUNTIME_PROGRAM, program),
    };
    (
        StreamCall {
            stream: stream.into(),
            input: Value::null(),
            scope: Some(scope),
            justification: Some(justification),
            ttl_ms: Some(ttl_ms),
            registry_rev,
        },
        TypedRuntimeInput {
            program,
            input,
            budget,
            timeout_ms,
            submission_identity,
            limits_admitted: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    fn identity(epoch: &str) -> Value {
        crate::service::map_value([
            ("registry_instance", Value::string("test-registry".into())),
            ("retry_epoch", Value::string(epoch.into())),
            ("nonce", Value::string("request-1".into())),
        ])
    }

    #[test]
    fn retry_epoch_uses_canonical_strings_across_the_full_u64_range() -> anyhow::Result<()> {
        for (epoch, expected) in [("0", 0), ("18446744073709551615", u64::MAX)] {
            let decoded = submission_identity(Some(identity(epoch)))?.context("identity")?;
            ensure!(decoded.retry_epoch == expected);
        }
        for invalid in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1.0",
            "１",
            "18446744073709551616",
        ] {
            ensure!(submission_identity(Some(identity(invalid))).is_err());
        }
        Ok(())
    }
}
