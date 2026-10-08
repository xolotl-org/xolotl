//! Scheduling and result classification for hosted Fact I/O.

use super::DataPlane;
use crate::fact::{FactError, FactErrorKind};
use crate::host::{BlockingSpawnError, BlockingTaskError};
use xolotl_types::{Fact, Failure, OperationId};

/// Where the hosted data plane performs synchronous Fact I/O.
///
/// `Inline` avoids scheduling overhead for memory-backed stores. Select
/// `Blocking` for selected stores whose writes can wait for
/// persistent I/O. Both modes use the same [`crate::FactSink`] rules.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FactIoMode {
    /// Perform Fact I/O while polling the invocation.
    #[default]
    Inline,
    /// Transfer owned Fact work to the host's bounded blocking executor.
    Blocking,
}

#[derive(Clone, Copy)]
pub(crate) enum FactWriteStage {
    Begin,
    Complete,
}

#[derive(Debug)]
pub(crate) enum FactWriteError {
    Store(FactError),
    NotAdmitted(BlockingSpawnError),
    ResultUnknown(BlockingTaskError),
}

impl FactWriteError {
    /// A confirmed scheduling rejection did not touch the store. A worker
    /// failure is different: its Fact may already have committed. The driver
    /// result, if one exists, stays in the caller's `InvocationResult`.
    pub(crate) fn failure(&self, id: OperationId, stage: FactWriteStage) -> Failure {
        let phase = match stage {
            FactWriteStage::Begin => "begin",
            FactWriteStage::Complete => "completion",
        };
        match self {
            Self::Store(error) if error.kind() == FactErrorKind::Other => Failure::policy(
                "fact_recording",
                format!("Fact {phase} failed for {id}: {error}"),
            ),
            Self::Store(error) => Failure::Custom {
                kind: match error.kind() {
                    FactErrorKind::CommitOutcomeUnknown => "fact_commit_outcome_unknown",
                    FactErrorKind::ReopenRequired => "fact_store_reopen_required",
                    FactErrorKind::Other => "fact_store_error",
                }
                .into(),
                message: format!("Fact {phase} failed for {id}: {error}"),
            },
            Self::NotAdmitted(error) => Failure::Custom {
                kind: "fact_write_not_admitted".into(),
                message: format!("Fact {phase} was not admitted for {id}: {error}"),
            },
            Self::ResultUnknown(error) => Failure::Custom {
                kind: "fact_write_result_unknown".into(),
                message: format!("Fact {phase} result is unknown for {id}: {error}"),
            },
        }
    }
}

impl DataPlane {
    pub(crate) async fn write_fact(
        &self,
        stage: FactWriteStage,
        fact: Fact,
    ) -> Result<(), FactWriteError> {
        if self.fact_io_mode == FactIoMode::Inline {
            return match stage {
                FactWriteStage::Begin => self.facts.begin(fact),
                FactWriteStage::Complete => self.facts.complete(fact),
            }
            .map_err(FactWriteError::Store);
        }

        // The worker owns only one Fact and a shared sink handle. Once
        // admitted, dropping the awaiter does not revoke this write.
        let sink = self.facts.clone();
        let task = self
            .host_runtime
            .dispatch_blocking(move || match stage {
                FactWriteStage::Begin => sink.begin(fact),
                FactWriteStage::Complete => sink.complete(fact),
            })
            .map_err(FactWriteError::NotAdmitted)?;
        match task.await {
            Ok(result) => result.map_err(FactWriteError::Store),
            Err(error) => {
                self.facts.mark_host_write_unknown();
                Err(FactWriteError::ResultUnknown(error))
            }
        }
    }
}
