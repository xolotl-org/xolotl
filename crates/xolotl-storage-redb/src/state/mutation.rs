//! One transaction owns the current-value observation, mutation, and history.

use super::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use xolotl_kernel::host::{BlockingTask, blocking::dispatch};

pub(super) struct WriteOwner {
    pub(super) db: Arc<Database>,
    publication: Arc<Publication>,
    pub(super) history: RedbHistory,
    absence_limits: xolotl_state::AbsenceLimits,
}

impl WriteOwner {
    fn from_backend(backend: &RedbStateBackend) -> Self {
        Self {
            db: Arc::clone(&backend.db),
            publication: Arc::clone(&backend.publication),
            history: backend.history,
            absence_limits: backend.absence_limits,
        }
    }
}

struct PreparedMutation {
    stored: Option<xolotl_state::StateObservation>,
    event: StateEvent,
}

impl PreparedMutation {
    fn set(path: &Path, stored: TaintedValue) -> Self {
        Self {
            event: StateEvent::Set {
                path: path.clone(),
                value: stored.value.clone(),
                taint: stored.taint.clone(),
            },
            stored: Some(stored.into()),
        }
    }

    fn delete(path: &Path, mut current_taint: TaintSet, taint: TaintSet) -> Self {
        current_taint.union(&taint);
        Self {
            stored: Some(xolotl_state::StateObservation {
                value: None,
                taint: current_taint,
            }),
            event: StateEvent::Delete {
                path: path.clone(),
                taint,
            },
        }
    }
}

impl WriteOwner {
    fn commit_mutation(
        &self,
        path: &Path,
        mutation: StateMutation,
        max_current_encoded_bytes: Option<NonZeroUsize>,
    ) -> StateResult<StateCommit> {
        let mut observed = mutation.input_taint().clone();
        let result = (|| -> StateResult<()> {
            let replacement_bytes = match &mutation {
                StateMutation::Set(value) => {
                    Some(list::EncodedValue::prepare(&value.value, &value.taint)?)
                }
                _ => None,
            };
            let append_bytes = match &mutation {
                StateMutation::Append(value) => Some(list::encode_item(&value.value)?),
                _ => None,
            };
            let txn = self.db.begin_write().map_err(backend_error)?;
            let event = {
                let key = path.to_string();
                let mut table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
                let (current, segmented, present) =
                    match table.get(key.as_str()).map_err(backend_error)? {
                        Some(guard) => {
                            if let Some(limit) = max_current_encoded_bytes {
                                let encoded_bytes = list::record_size(guard.value(), key.len())?;
                                if encoded_bytes > limit.get() {
                                    return Err(StateError::PointTooLarge(Box::new(
                                        StatePointTooLarge {
                                            path: path.clone(),
                                            encoded_bytes,
                                            limit_encoded_bytes: limit,
                                            provenance_observed: false,
                                        },
                                    ))
                                    .into());
                                }
                            }
                            let segmented = list::marker(guard.value())?;
                            let absence = if matches!(&mutation, StateMutation::Set(_)) {
                                None
                            } else {
                                codec::decode_absence(guard.value())?
                            };
                            let present = absence.is_none();
                            let read_taint = || match &segmented {
                                Some(marker) => Ok(marker.taint.clone()),
                                None => list::taint(guard.value()),
                            };
                            let current = if matches!(&mutation, StateMutation::Set(_))
                                || (segmented.is_some()
                                    && matches!(&mutation, StateMutation::Append(_)))
                            {
                                observed.union(&read_taint()?);
                                None
                            } else if let Some(taint) = absence {
                                Some(xolotl_state::StateObservation { value: None, taint })
                            } else if matches!(&mutation, StateMutation::Delete(_)) {
                                Some(xolotl_state::StateObservation {
                                    value: None,
                                    taint: read_taint()?,
                                })
                            } else if segmented.is_some() {
                                let items = txn
                                    .open_table(crate::schema::STATE_LIST_ITEMS_TABLE)
                                    .map_err(backend_error)?;
                                Some(list::materialize(&items, guard.value())?.into())
                            } else {
                                Some(decode_envelope(guard.value())?.into())
                            };
                            if let Some(current) = &current {
                                observed.union(&current.taint);
                            }
                            (current, segmented, present)
                        }
                        None => (Some(xolotl_state::StateObservation::default()), None, false),
                    };
                let incremental =
                    segmented.is_some() && matches!(&mutation, StateMutation::Append(_));
                let prepared = match mutation {
                    StateMutation::Set(value) => PreparedMutation::set(path, value),
                    StateMutation::Append(value) if incremental => PreparedMutation {
                        stored: None,
                        event: StateMutation::prepare_append_event(
                            path,
                            value,
                            Some(true),
                            observed.clone(),
                        )?,
                    },
                    StateMutation::Delete(_) => {
                        if !present {
                            return Ok(());
                        }
                        PreparedMutation::delete(
                            path,
                            current
                                .ok_or_else(|| backend_error("current observation missing"))?
                                .taint,
                            observed.clone(),
                        )
                    }
                    mutation => {
                        let current =
                            current.ok_or_else(|| backend_error("current observation missing"))?;
                        let Some(event) = mutation.prepare_event(
                            path,
                            current.value.as_ref(),
                            observed.clone(),
                        )?
                        else {
                            return Ok(());
                        };
                        let mut stored = current;
                        xolotl_state::apply_history_event(&mut stored, &event)?;
                        PreparedMutation {
                            stored: Some(stored),
                            event,
                        }
                    }
                };
                if incremental {
                    let mut marker =
                        segmented.ok_or_else(|| backend_error("State List marker missing"))?;
                    marker.taint.union(prepared.event.taint());
                    list::append_item(
                        &txn,
                        &mut marker,
                        append_bytes
                            .as_deref()
                            .ok_or_else(|| backend_error("State List append item missing"))?,
                    )?;
                    let bytes = marker.encode()?;
                    list::record_size(&bytes, key.len())?;
                    absence::replacing(&txn, &table, &key, Some(&bytes), self.absence_limits)?;
                    table
                        .insert(key.as_str(), bytes.as_slice())
                        .map_err(backend_error)?;
                } else {
                    let stored = prepared
                        .stored
                        .ok_or_else(|| backend_error("prepared observation missing"))?;
                    if let Some(marker) = &segmented {
                        let mut items = list::item_table(&txn)?;
                        list::remove_items(&mut items, marker)?;
                    }
                    if let Some(value) = stored.value {
                        let encoded = match replacement_bytes {
                            Some(bytes) => bytes,
                            None => match append_bytes {
                                Some(bytes) => list::EncodedValue::List(vec![bytes]),
                                None => list::EncodedValue::prepare(&value, &stored.taint)?,
                            },
                        };
                        let bytes = encoded.store(&txn, stored.taint)?;
                        list::record_size(&bytes, key.len())?;
                        absence::replacing(&txn, &table, &key, Some(&bytes), self.absence_limits)?;
                        table
                            .insert(key.as_str(), bytes.as_slice())
                            .map_err(backend_error)?;
                    } else if stored.taint.is_pristine() {
                        absence::replacing(&txn, &table, &key, None, self.absence_limits)?;
                        table.remove(key.as_str()).map_err(backend_error)?;
                    } else {
                        let bytes = codec::encode_absence(&stored.taint)?;
                        absence::replacing(&txn, &table, &key, Some(&bytes), self.absence_limits)?;
                        table
                            .insert(key.as_str(), bytes.as_slice())
                            .map_err(backend_error)?;
                    }
                }
                prepared.event
            };
            if self.history == RedbHistory::Full && xolotl_state::history_retains_path(path) {
                RedbStateBackend::record_history_in_txn(&txn, &event)?;
            }
            self.publication
                .commit(txn, event)
                .map_err(|failure| match failure {
                    PublishFailure::Backpressure => {
                        backend_error("state notification backlog is full")
                    }
                    PublishFailure::Commit(error) => commit_error(error),
                })?;
            Ok(())
        })();
        result.map_err(|failure| failure.with_taint(&observed))?;
        Ok(StateCommit { taint: observed })
    }
}

/// A redb write admitted on its first poll. Once admitted, the worker owns the
/// whole transaction and any notification independently of the result waiter.
pub struct RedbWriteFuture<'a, A, O, T> {
    backend: &'a RedbStateBackend,
    phase: WritePhase<A, T>,
    own: fn(A) -> O,
    write: fn(&WriteOwner, O) -> StateResult<T>,
    input_taint: TaintSet,
}

enum WritePhase<A, T> {
    New(A),
    Running(BlockingTask<StateResult<T>>),
    Done,
}

impl<'a, A, O, T> RedbWriteFuture<'a, A, O, T> {
    pub(super) fn new(
        backend: &'a RedbStateBackend,
        request: A,
        own: fn(A) -> O,
        write: fn(&WriteOwner, O) -> StateResult<T>,
        input_taint: TaintSet,
    ) -> Self {
        Self {
            backend,
            phase: WritePhase::New(request),
            own,
            write,
            input_taint,
        }
    }
}

impl<A, O, T> Future for RedbWriteFuture<'_, A, O, T>
where
    A: Unpin,
    O: Send + 'static,
    T: Send + Unpin + 'static,
{
    type Output = StateResult<T>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut task = match std::mem::replace(&mut this.phase, WritePhase::Done) {
            WritePhase::New(request) => {
                let owned = (this.own)(request);
                let owner = WriteOwner::from_backend(this.backend);
                let write = this.write;
                match dispatch(this.backend.blocking_spawner.as_ref(), move || {
                    write(&owner, owned)
                }) {
                    Ok(task) => task,
                    Err(error) => {
                        return Poll::Ready(Err(backend_error(format!(
                            "state write admission failed: {error}"
                        ))
                        .with_taint(&this.input_taint)));
                    }
                }
            }
            WritePhase::Running(task) => task,
            WritePhase::Done => {
                return Poll::Ready(Err(backend_error("write future polled after completion")
                    .with_taint(&this.input_taint)));
            }
        };
        match Pin::new(&mut task).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(error)) => Poll::Ready(Err(StateFailure::new(
                StateError::CommitUncertain(format!("state write worker failed: {error}")),
                this.input_taint.clone(),
            ))),
            Poll::Pending => {
                this.phase = WritePhase::Running(task);
                Poll::Pending
            }
        }
    }
}

impl StateWrite for RedbStateBackend {
    type Write<'a> =
        RedbWriteFuture<'a, (&'a Path, StateMutation), (Path, StateMutation), StateCommit>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        let input_taint = mutation.input_taint().clone();
        RedbWriteFuture::new(
            self,
            (path, mutation),
            |(path, mutation)| (path.clone(), mutation),
            |owner, (path, mutation)| owner.commit_mutation(&path, mutation, None),
            input_taint,
        )
    }
}

impl StateBoundedWrite for RedbStateBackend {
    type BoundedWrite<'a> = RedbWriteFuture<
        'a,
        (&'a Path, StateMutation, NonZeroUsize),
        (Path, StateMutation, NonZeroUsize),
        StateCommit,
    >;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        let input_taint = value.taint.clone();
        RedbWriteFuture::new(
            self,
            (
                path,
                StateMutation::CompareSet { expected, value },
                max_current_encoded_bytes,
            ),
            |(path, mutation, limit)| (path.clone(), mutation, limit),
            |owner, (path, mutation, limit)| owner.commit_mutation(&path, mutation, Some(limit)),
            input_taint,
        )
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        let input_taint = taint.clone();
        RedbWriteFuture::new(
            self,
            (
                path,
                StateMutation::CompareDelete { expected, taint },
                max_current_encoded_bytes,
            ),
            |(path, mutation, limit)| (path.clone(), mutation, limit),
            |owner, (path, mutation, limit)| owner.commit_mutation(&path, mutation, Some(limit)),
            input_taint,
        )
    }
}
