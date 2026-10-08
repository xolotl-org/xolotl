//! Failures retain all sources observed by a Standard capability invocation.
//!
//! Local input admission stays ordinary DriverErrors. State's unknown commit
//! or unread provenance retains an explicit handler kind. Observed sources
//! reach the same result boundary as successful values.

use xolotl_kernel::{DriverError, DriverOutput};
use xolotl_state::{StateError, StateFailure};
use xolotl_types::{Failure, Outcome, TaintSet};

#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub(crate) struct ObservedFailure {
    pub(crate) error: ObservedError,
    pub(crate) taint: TaintSet,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ObservedError {
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error(transparent)]
    Failure(#[from] Failure),
}

impl From<DriverError> for ObservedFailure {
    fn from(error: DriverError) -> Self {
        Self {
            error: error.into(),
            taint: TaintSet::pristine(),
        }
    }
}

impl From<StateFailure> for ObservedFailure {
    fn from(failure: StateFailure) -> Self {
        let kind = match &failure.error {
            StateError::CommitUncertain(_) => Some("state_commit_uncertain"),
            StateError::RowTooLarge(row) if !row.provenance_observed => {
                Some("state_provenance_unavailable")
            }
            StateError::PointTooLarge(row) if !row.provenance_observed => {
                Some("state_provenance_unavailable")
            }
            _ => None,
        };
        let message = failure.error.to_string();
        let error = match kind {
            Some(kind) => Failure::HandlerError {
                kind: kind.into(),
                message,
            }
            .into(),
            None => DriverError::Other(message).into(),
        };
        Self {
            error,
            taint: failure.taint,
        }
    }
}

impl From<Failure> for ObservedFailure {
    fn from(failure: Failure) -> Self {
        Self {
            error: failure.into(),
            taint: TaintSet::pristine(),
        }
    }
}

impl ObservedFailure {
    pub(crate) fn with_taint(mut self, taint: &TaintSet) -> Self {
        self.taint.union(taint);
        self
    }

    pub(crate) fn into_output(self, kind: &str) -> Result<DriverOutput, DriverError> {
        match self.error {
            ObservedError::Failure(failure) => {
                Ok(DriverOutput::new(Outcome::Fail(failure)).with_taint(self.taint))
            }
            ObservedError::Driver(error) if self.taint.is_pristine() => Err(error),
            ObservedError::Driver(error) => Ok(DriverOutput::new(Outcome::Fail(Failure::Custom {
                kind: kind.into(),
                message: error.to_string(),
            }))
            .with_taint(self.taint)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_failures_retain_identity_and_merge_observed_sources() -> anyhow::Result<()> {
        let prior = TaintSet::of(xolotl_types::TaintSource::ModelOutput);
        let additional = TaintSet::of(xolotl_types::TaintSource::Fetched {
            host: "downstream".into(),
        });
        let mut combined = prior.clone();
        combined.union(&additional);
        for failure in [
            Failure::Timeout,
            Failure::Custom {
                kind: "downstream_custom".into(),
                message: "custom detail".into(),
            },
            Failure::HandlerError {
                kind: "downstream_handler".into(),
                message: "handler detail".into(),
            },
            Failure::OutcomeUnknown {
                operation_ids: vec!["operation-a".into(), "operation-b".into()],
                reason: "acknowledgement lost".into(),
            },
        ] {
            for (sources, expected) in [
                (vec![], TaintSet::pristine()),
                (vec![&prior], prior.clone()),
                (vec![&prior, &additional, &prior], combined.clone()),
            ] {
                let mut observed = ObservedFailure::from(failure.clone());
                for source in sources {
                    observed = observed.with_taint(source);
                }
                let output = observed.into_output("replacement_kind")?;
                anyhow::ensure!(output.outcome == Outcome::Fail(failure.clone()));
                anyhow::ensure!(output.taint == expected);
            }
        }
        Ok(())
    }

    #[test]
    fn ordinary_driver_errors_keep_pristine_and_observed_behavior() -> anyhow::Result<()> {
        let error = DriverError::InvalidInput("invalid weight".into());
        anyhow::ensure!(matches!(
            ObservedFailure::from(error.clone()).into_output("rank"),
            Err(returned) if returned == error
        ));
        let taint = TaintSet::of(xolotl_types::TaintSource::ModelOutput);
        let output = ObservedFailure::from(error.clone())
            .with_taint(&taint)
            .into_output("rank")?;
        anyhow::ensure!(
            output.outcome
                == Outcome::Fail(Failure::Custom {
                    kind: "rank".into(),
                    message: error.to_string(),
                })
        );
        anyhow::ensure!(output.taint == taint);
        Ok(())
    }

    #[test]
    fn unread_state_provenance_retains_class_and_prior_sources() -> anyhow::Result<()> {
        let path = xolotl_types::Path::parse("state://unread")?;
        for taint in [
            TaintSet::pristine(),
            TaintSet::of(xolotl_types::TaintSource::ModelOutput),
        ] {
            for error in [
                StateError::RowTooLarge(Box::new(xolotl_state::StateRowTooLarge {
                    path: path.clone(),
                    encoded_bytes: 512,
                    provenance_observed: false,
                    retry: None,
                    resume: xolotl_state::StateCursor(path.to_string().into_bytes()),
                })),
                StateError::PointTooLarge(Box::new(xolotl_state::StatePointTooLarge {
                    path: path.clone(),
                    encoded_bytes: 512,
                    limit_encoded_bytes: core::num::NonZeroUsize::MIN,
                    provenance_observed: false,
                })),
            ] {
                let output = ObservedFailure::from(StateFailure::new(error, taint.clone()))
                    .into_output("state");
                anyhow::ensure!(matches!(output, Ok(DriverOutput {
                    outcome: Outcome::Fail(Failure::HandlerError { kind, .. }),
                    taint: observed,
                    ..
                }) if kind == "state_provenance_unavailable" && observed == taint));
            }
        }
        Ok(())
    }

    #[test]
    fn uncertain_state_commit_remains_structured_without_observed_taint() {
        let output = ObservedFailure::from(StateFailure::from(StateError::CommitUncertain(
            "lost storage acknowledgement".into(),
        )))
        .into_output("state");
        assert!(matches!(
            output,
            Ok(DriverOutput {
                outcome: Outcome::Fail(Failure::HandlerError { kind, .. }),
                ..
            }) if kind == "state_commit_uncertain"
        ));
    }
}
