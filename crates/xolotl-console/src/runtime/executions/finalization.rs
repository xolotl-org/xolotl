use super::{ConsoleError, ConsoleErrorCode, ConsoleFailure, map_value, serde_value};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::io::Write;
use std::sync::Arc;
use xolotl_kernel::ProcessFinalizationReport;
use xolotl_types::{ProcessStatus, TaintSet, TaintedFailure, Value};

#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) enum FinalizationProjection {
    #[default]
    Pending,
    Committed(Arc<Vec<u8>>),
    Omitted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use xolotl_types::{Failure, TaintSource};

    fn report() -> ProcessFinalizationReport {
        let taint = TaintSet::from_recorded_sources(vec![
            TaintSource::ModelOutput,
            TaintSource::AuthorConstant,
        ]);
        ProcessFinalizationReport {
            status: ProcessStatus::Failed,
            taint: taint.clone(),
            unresolved_operations: Default::default(),
            finalizer_failures: vec![
                (
                    7,
                    TaintedFailure::new(
                        Failure::Custom {
                            kind: "secret-kind".into(),
                            message: "secret-diagnostic".repeat(100_000),
                        },
                        taint,
                    ),
                ),
                (2, TaintedFailure::pristine(Failure::Cancelled)),
            ],
            released_handles: 3,
            revoked_handles: 4,
        }
    }

    #[test]
    fn projection_redacts_diagnostics_preserves_order_and_charges_encoded_bytes()
    -> anyhow::Result<()> {
        let report = report();
        let projection = FinalizationProjection::encode(&report, 4096);
        let FinalizationProjection::Committed(bytes) = &projection else {
            anyhow::bail!("bounded report omitted")
        };
        ensure!(bytes.len() < 4096);
        let text = std::str::from_utf8(bytes)?;
        ensure!(!text.contains("secret"));
        let projected: serde_json::Value = serde_json::from_slice(bytes)?;
        ensure!(projected["taint"] == serde_json::to_value(&report.taint)?);
        ensure!(
            projected["finalizer_failures"][0]["taint"]
                == serde_json::to_value(&report.finalizer_failures[0].1.taint)?
        );
        ensure!(projected["finalizer_failures"][0]["index"] == 7);
        ensure!(projected["finalizer_failures"][1]["index"] == 2);
        ensure!(projected["released_handles"] == 3);
        ensure!(projected["revoked_handles"] == 4);
        ensure!(matches!(
            FinalizationProjection::encode(&report, bytes.len()),
            FinalizationProjection::Committed(_)
        ));
        let omitted = FinalizationProjection::encode(&report, bytes.len() - 1);
        ensure!(matches!(omitted, FinalizationProjection::Omitted));
        let value = omitted.value()?;
        let fields = value.as_map().context("projection envelope")?;
        ensure!(fields.get("status").and_then(Value::as_str) == Some("omitted"));
        ensure!(fields.get("report") == Some(&Value::null()));
        ensure!(
            fields
                .get("retention_failure")
                .is_some_and(|value| *value != Value::null())
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct Report<'a> {
    status: ProcessStatus,
    taint: &'a TaintSet,
    finalizer_failures: Failures<'a>,
    released_handles: usize,
    revoked_handles: usize,
}

struct Failures<'a>(&'a [(usize, TaintedFailure)]);

impl Serialize for Failures<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Failure<'a> {
            index: usize,
            failure: ConsoleFailure,
            taint: &'a TaintSet,
        }
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (index, failure) in self.0 {
            sequence.serialize_element(&Failure {
                index: *index,
                failure: ConsoleFailure::from_runtime_failure(&failure.failure),
                taint: &failure.taint,
            })?;
        }
        sequence.end()
    }
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("finalization projection byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl FinalizationProjection {
    pub(crate) fn encode(report: &ProcessFinalizationReport, limit: usize) -> Self {
        let mut encoded = BoundedBytes {
            bytes: Vec::new(),
            limit,
        };
        let projected = Report {
            status: report.status,
            taint: &report.taint,
            finalizer_failures: Failures(&report.finalizer_failures),
            released_handles: report.released_handles,
            revoked_handles: report.revoked_handles,
        };
        if serde_json::to_writer(&mut encoded, &projected).is_ok() {
            Self::Committed(Arc::new(encoded.bytes))
        } else {
            Self::Omitted
        }
    }

    pub(crate) fn value(&self) -> Result<Value, ConsoleError> {
        let (status, report, failure) = match self {
            Self::Pending => ("pending", Value::null(), Value::null()),
            Self::Committed(bytes) => (
                "available",
                serde_json::from_slice::<Value>(bytes.as_slice()).map_err(|_error| {
                    ConsoleError::Operation("retained finalization projection is invalid".into())
                })?,
                Value::null(),
            ),
            Self::Omitted => (
                "omitted",
                Value::null(),
                serde_value(ConsoleFailure::new(
                    ConsoleErrorCode::Internal,
                    "finalization report exceeds the host retention limit".into(),
                ))?,
            ),
        };
        Ok(map_value([
            ("status", Value::string(status.into())),
            ("report", report),
            ("retention_failure", failure),
        ]))
    }
}
