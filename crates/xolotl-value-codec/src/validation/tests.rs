use super::*;
use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use anyhow::{Context as _, bail, ensure};
use core::{
    cell::Cell,
    future::pending,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use thiserror::Error as ThisError;
use xolotl_types::value::event::{Atom, Kind, ValidationError};

fn ready<F: Future>(future: F) -> anyhow::Result<F::Output> {
    match core::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => Ok(result),
        Poll::Pending => bail!("resident operation unexpectedly suspended"),
    }
}

fn memory_options(page_bytes: usize) -> anyhow::Result<MemoryKeyOptions> {
    Ok(MemoryKeyOptions {
        page_bytes: NonZeroUsize::new(page_bytes).context("zero test page size")?,
        max_keys: None,
        max_bytes: None,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Create,
    Compare,
    Append,
    Release,
}

const OPERATIONS: [Operation; 4] = [
    Operation::Create,
    Operation::Compare,
    Operation::Append,
    Operation::Release,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Pending,
    Fail,
}

#[derive(Debug, ThisError)]
enum TestError {
    #[error("injected {0:?} failure")]
    Injected(Operation),
    #[error(transparent)]
    Memory(#[from] MemoryKeyError),
}

#[derive(Default)]
struct Probe {
    fault: Cell<Option<(Operation, Fault)>>,
    calls: Cell<usize>,
    last_operation: Cell<Option<Operation>>,
    active_requests: Cell<usize>,
    cancelled_requests: Cell<usize>,
    dropped_stores: Cell<usize>,
    wrong_drop_order: Cell<bool>,
}

struct RequestGuard(Rc<Probe>);

impl RequestGuard {
    fn new(probe: &Rc<Probe>) -> Self {
        probe.active_requests.set(probe.active_requests.get() + 1);
        Self(probe.clone())
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.0.active_requests.set(self.0.active_requests.get() - 1);
        self.0
            .cancelled_requests
            .set(self.0.cancelled_requests.get() + 1);
    }
}

// Rc deliberately keeps the port and its request futures local and non-Send.
struct TrackedStore {
    memory: MemoryKeyStore,
    probe: Rc<Probe>,
}

impl TrackedStore {
    fn new(probe: Rc<Probe>) -> anyhow::Result<Self> {
        Ok(Self {
            memory: MemoryKeyStore::new(memory_options(7)?),
            probe,
        })
    }

    async fn acknowledge(&self, operation: Operation) -> Result<(), TestError> {
        self.probe.calls.set(self.probe.calls.get() + 1);
        self.probe.last_operation.set(Some(operation));
        match self.probe.fault.get() {
            Some((selected, Fault::Fail)) if selected == operation => {
                Err(TestError::Injected(operation))
            }
            Some((selected, Fault::Pending)) if selected == operation => {
                let _guard = RequestGuard::new(&self.probe);
                pending::<()>().await;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl Drop for TrackedStore {
    fn drop(&mut self) {
        if self.probe.active_requests.get() != 0 {
            self.probe.wrong_drop_order.set(true);
        }
        self.probe
            .dropped_stores
            .set(self.probe.dropped_stores.get() + 1);
    }
}

type Request<'a, T> = Pin<Box<dyn Future<Output = Result<T, TestError>> + 'a>>;

impl KeyStore for TrackedStore {
    type Error = TestError;
    type Create<'a> = Request<'a, ()>;
    type ComparePrefix<'a> = Request<'a, Ordering>;
    type Append<'a> = Request<'a, ()>;
    type Release<'a> = Request<'a, ()>;

    fn create(&mut self, key: KeyId) -> Self::Create<'_> {
        Box::pin(async move {
            self.memory.create(key).await?;
            self.acknowledge(Operation::Create).await
        })
    }

    fn compare_prefix<'a>(
        &'a mut self,
        key: KeyId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a> {
        Box::pin(async move {
            let result = self.memory.compare_prefix(key, offset, bytes).await?;
            self.acknowledge(Operation::Compare).await?;
            Ok(result)
        })
    }

    fn append<'a>(&'a mut self, key: KeyId, offset: u64, bytes: &'a [u8]) -> Self::Append<'a> {
        Box::pin(async move {
            self.memory.append(key, offset, bytes).await?;
            self.acknowledge(Operation::Append).await
        })
    }

    fn release(&mut self, key: KeyId) -> Self::Release<'_> {
        Box::pin(async move {
            self.memory.release(key).await?;
            self.acknowledge(Operation::Release).await
        })
    }
}

fn accept_all<'a>(
    owner: &mut EventValidator<TrackedStore>,
    events: impl IntoIterator<Item = Event<'a>>,
) -> anyhow::Result<()> {
    for event in events {
        ready(owner.accept(event))??;
    }
    Ok(())
}

fn before(
    operation: Operation,
) -> anyhow::Result<(EventValidator<TrackedStore>, Rc<Probe>, Event<'static>)> {
    let probe = Rc::new(Probe::default());
    let mut owner = EventValidator::new(TrackedStore::new(probe.clone())?, None);
    accept_all(
        &mut owner,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Begin(Kind::Map),
        ],
    )?;
    if operation == Operation::Create {
        return Ok((owner, probe, Event::Begin(Kind::Key)));
    }
    accept_all(&mut owner, [Event::Begin(Kind::Key)])?;
    if operation == Operation::Append {
        return Ok((owner, probe, Event::Data(b"a")));
    }
    accept_all(
        &mut owner,
        [
            Event::Data(b"a"),
            Event::End(Kind::Key),
            Event::Atom(Atom::Null),
            Event::Begin(Kind::Key),
        ],
    )?;
    if operation == Operation::Compare {
        return Ok((owner, probe, Event::Data(b"b")));
    }
    accept_all(&mut owner, [Event::Data(b"b")])?;
    Ok((owner, probe, Event::End(Kind::Key)))
}

#[test]
fn cancelling_each_polled_effect_drops_requests_then_the_workspace_immediately()
-> anyhow::Result<()> {
    for operation in OPERATIONS {
        let (mut owner, probe, event) = before(operation)?;
        probe.fault.set(Some((operation, Fault::Pending)));
        let mut accept = Box::pin(owner.accept(event));
        ensure!(
            accept
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ensure!(probe.last_operation.get() == Some(operation));
        ensure!(probe.active_requests.get() == 1 && probe.dropped_stores.get() == 0);
        drop(accept);
        ensure!(!owner.is_open());
        ensure!(probe.active_requests.get() == 0 && probe.cancelled_requests.get() == 1);
        ensure!(probe.dropped_stores.get() == 1 && !probe.wrong_drop_order.get());
        ensure!(matches!(ready(owner.accept(event))?, Err(Error::Closed)));
        ensure!(matches!(owner.finish(), Err(Error::Closed)));
        drop(owner);
        ensure!(probe.dropped_stores.get() == 1);
    }
    Ok(())
}

#[test]
fn dropping_unpolled_accept_futures_preserves_every_workspace_operation() -> anyhow::Result<()> {
    for operation in OPERATIONS {
        let (mut owner, probe, event) = before(operation)?;
        probe.fault.set(Some((operation, Fault::Pending)));
        let calls = probe.calls.get();
        drop(owner.accept(event));
        ensure!(owner.is_open());
        ensure!(probe.calls.get() == calls && probe.active_requests.get() == 0);
        ensure!(probe.dropped_stores.get() == 0);
        probe.fault.set(None);
        ready(owner.accept(event))??;
        ensure!(owner.is_open() && probe.dropped_stores.get() == 0);
        drop(owner);
        ensure!(probe.dropped_stores.get() == 1);
    }
    Ok(())
}

#[test]
fn every_workspace_error_closes_and_drops_the_owner_after_partial_effects() -> anyhow::Result<()> {
    for operation in OPERATIONS {
        let (mut owner, probe, event) = before(operation)?;
        probe.fault.set(Some((operation, Fault::Fail)));
        ensure!(
            matches!(ready(owner.accept(event))?, Err(Error::Workspace(TestError::Injected(actual))) if actual == operation)
        );
        ensure!(!owner.is_open() && probe.dropped_stores.get() == 1);
        ensure!(probe.active_requests.get() == 0 && !probe.wrong_drop_order.get());
        ensure!(matches!(ready(owner.accept(event))?, Err(Error::Closed)));
        ensure!(matches!(owner.finish(), Err(Error::Closed)));
    }
    Ok(())
}

#[test]
fn semantic_errors_and_frame_admission_failures_also_release_workspaces() -> anyhow::Result<()> {
    for (bytes, expected) in [
        (&[0xff][..], ValidationError::Utf8),
        (&b"0"[..], ValidationError::MapKeyOrder),
    ] {
        let (mut owner, probe, _) = before(Operation::Compare)?;
        ensure!(
            matches!(ready(owner.accept(Event::Data(bytes)))?, Err(Error::Validation(actual)) if actual == expected)
        );
        ensure!(!owner.is_open() && probe.dropped_stores.get() == 1);
    }
    let probe = Rc::new(Probe::default());
    let mut owner = EventValidator::new(TrackedStore::new(probe.clone())?, Some(0));
    ensure!(matches!(
        ready(owner.accept(Event::Begin(Kind::Document)))?,
        Err(Error::Validation(ValidationError::FrameBudget { limit: 0 }))
    ));
    ensure!(!owner.is_open() && probe.dropped_stores.get() == 1);
    Ok(())
}

#[test]
fn successful_and_incomplete_finish_both_release_the_workspace_once() -> anyhow::Result<()> {
    let probe = Rc::new(Probe::default());
    let mut owner = EventValidator::new(TrackedStore::new(probe.clone())?, None);
    accept_all(
        &mut owner,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Atom(Atom::Null),
            Event::End(Kind::Document),
        ],
    )?;
    ensure!(owner.is_open() && probe.dropped_stores.get() == 0);
    owner.finish()?;
    ensure!(!owner.is_open() && probe.dropped_stores.get() == 1);
    ensure!(matches!(owner.finish(), Err(Error::Closed)));

    let (mut owner, probe, _) = before(Operation::Compare)?;
    ensure!(matches!(
        owner.finish(),
        Err(Error::Validation(ValidationError::IncompleteDocument))
    ));
    ensure!(!owner.is_open() && probe.dropped_stores.get() == 1);
    ensure!(matches!(owner.finish(), Err(Error::Closed)));
    Ok(())
}

#[test]
fn trailing_events_and_dropping_an_idle_owner_release_all_key_state() -> anyhow::Result<()> {
    let probe = Rc::new(Probe::default());
    let mut owner = EventValidator::new(TrackedStore::new(probe.clone())?, None);
    accept_all(
        &mut owner,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Atom(Atom::Null),
            Event::End(Kind::Document),
        ],
    )?;
    ensure!(matches!(
        ready(owner.accept(Event::Begin(Kind::Document)))?,
        Err(Error::Validation(ValidationError::UnexpectedEvent {
            context: None
        }))
    ));
    ensure!(!owner.is_open() && probe.dropped_stores.get() == 1);
    let (owner, probe, _) = before(Operation::Compare)?;
    drop(owner);
    ensure!(probe.dropped_stores.get() == 1 && !probe.wrong_drop_order.get());
    Ok(())
}

// Obtain opaque identities through real pure-validator effects. Each map has
// one empty key, so no workspace contents or comparison answers are invented.
pub(super) fn key_ids(count: usize) -> anyhow::Result<Vec<KeyId>> {
    let mut grammar = Validator::new(None);
    let mut ids = Vec::new();
    let header = [
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::End(Kind::Taint),
        Event::Begin(Kind::List),
    ];
    let entry = [
        Event::Begin(Kind::Map),
        Event::Begin(Kind::Key),
        Event::End(Kind::Key),
        Event::Atom(Atom::Null),
        Event::End(Kind::Map),
    ];
    let end = [Event::End(Kind::List), Event::End(Kind::Document)];
    for event in header
        .into_iter()
        .chain((0..count).flat_map(|_index| entry))
        .chain(end)
    {
        let mut transaction = grammar.begin(event)?;
        let mut completion = None;
        loop {
            match transaction.advance(completion)? {
                ValidationStep::Accepted => break,
                ValidationStep::Effect(KeyEffect::Create { key }) => {
                    ids.push(key);
                    completion = Some(KeyCompletion::Done);
                }
                ValidationStep::Effect(KeyEffect::Release { .. }) => {
                    completion = Some(KeyCompletion::Done)
                }
                ValidationStep::Effect(_) => bail!("empty key unexpectedly needed data storage"),
            }
        }
    }
    grammar.finish()?;
    ensure!(ids.len() == count);
    Ok(ids)
}

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn paged_memory_matches_byte_order_for_random_offsets_and_fragmentation() -> anyhow::Result<()> {
    let id = key_ids(1)?[0];
    let mut seed = 0x7182_93a4_b5c6_d7e8;
    let bytes = (0..2_049)
        .map(|_index| random(&mut seed) as u8)
        .collect::<Vec<_>>();
    for page_bytes in [1, 3, 7, 31] {
        let mut store = MemoryKeyStore::new(memory_options(page_bytes)?);
        ready(store.create(id))??;
        let mut offset = 0;
        while offset < bytes.len() {
            let size = ((random(&mut seed) % 47) as usize + 1).min(bytes.len() - offset);
            ready(store.append(id, u64::try_from(offset)?, &bytes[offset..offset + size]))??;
            offset += size;
        }
        for trial in 0..700 {
            let offset = (random(&mut seed) as usize) % (bytes.len() + 1);
            let length = (random(&mut seed) % 83) as usize;
            let end = bytes.len().min(offset + length);
            let mut input = bytes[offset..end].to_vec();
            if trial % 3 == 1 && !input.is_empty() {
                let at = (random(&mut seed) as usize) % input.len();
                input[at] ^= 0x80;
            } else if trial % 3 == 2 {
                input.extend_from_slice(&[0, 255, 128]);
            }
            let end = bytes.len().min(offset + input.len());
            let expected = bytes[offset..end].cmp(&input);
            let actual = ready(store.compare_prefix(id, u64::try_from(offset)?, &input))??;
            ensure!(
                actual == expected,
                "page={page_bytes} offset={offset} trial={trial}"
            );
        }
        ready(store.release(id))??;
        ensure!(store.reserved_bytes() == 0 && store.key_count() == 0);
    }
    Ok(())
}

#[test]
fn long_common_prefix_comparison_crosses_pages_without_retaining_input_fragments()
-> anyhow::Result<()> {
    let id = key_ids(1)?[0];
    let mut store = MemoryKeyStore::new(memory_options(17)?);
    ready(store.create(id))??;
    let mut previous = vec![b'a'; 128 * 1024];
    previous.push(b'b');
    let mut offset = 0;
    for fragment in previous.chunks(29) {
        ready(store.append(id, offset, fragment))??;
        offset += u64::try_from(fragment.len())?;
    }
    let reserved = store.reserved_bytes();
    let last = previous.len() - 1;
    ensure!(ready(store.compare_prefix(id, 0, &previous[..last]))?? == Ordering::Equal);
    previous[last] = b'c';
    ensure!(ready(store.compare_prefix(id, 0, &previous))?? == Ordering::Less);
    previous[last] = b'a';
    ensure!(ready(store.compare_prefix(id, 0, &previous))?? == Ordering::Greater);
    ensure!(store.reserved_bytes() == reserved);
    ready(store.release(id))??;
    ensure!(store.reserved_bytes() == 0);
    Ok(())
}

#[test]
fn page_budgets_count_unused_tails_and_release_reclaims_capacity_for_new_keys() -> anyhow::Result<()>
{
    let ids = key_ids(3)?;
    let mut options = memory_options(8)?;
    options.max_keys = Some(2);
    options.max_bytes = Some(24);
    let mut store = MemoryKeyStore::new(options);
    ready(store.create(ids[0]))??;
    ensure!(store.reserved_bytes() == 0);
    ready(store.append(ids[0], 0, b"123456789"))??;
    ensure!(store.reserved_bytes() == 16);
    ready(store.create(ids[1]))??;
    ready(store.append(ids[1], 0, b"abcdefgh"))??;
    ensure!(store.reserved_bytes() == 24);
    ensure!(matches!(
        ready(store.create(ids[2]))?,
        Err(MemoryKeyError::KeyBudget(2))
    ));
    ready(store.append(ids[0], 9, b"0123456"))??;
    ensure!(matches!(
        ready(store.append(ids[0], 16, b"x"))?,
        Err(MemoryKeyError::ByteBudget(24))
    ));
    ensure!(ready(store.compare_prefix(ids[0], 0, b"1234567890123456"))?? == Ordering::Equal);
    ready(store.release(ids[1]))??;
    ensure!(store.reserved_bytes() == 16);
    ready(store.append(ids[0], 16, b"x"))??;
    ensure!(store.reserved_bytes() == 24);
    ready(store.release(ids[0]))??;
    ensure!(store.reserved_bytes() == 0 && store.key_count() == 0);
    ready(store.create(ids[2]))??;
    ready(store.append(ids[2], 0, &[42; 24]))??;
    ensure!(store.reserved_bytes() == 24);
    ready(store.release(ids[2]))??;
    ensure!(store.reserved_bytes() == 0);
    Ok(())
}

#[test]
fn zero_byte_budget_still_supports_empty_keys_without_page_allocation() -> anyhow::Result<()> {
    let id = key_ids(1)?[0];
    let mut options = memory_options(16)?;
    options.max_bytes = Some(0);
    let mut store = MemoryKeyStore::new(options);
    ready(store.create(id))??;
    ready(store.append(id, 0, b""))??;
    ensure!(ready(store.compare_prefix(id, 0, b""))?? == Ordering::Equal);
    ensure!(ready(store.compare_prefix(id, 0, b"x"))?? == Ordering::Less);
    ensure!(matches!(
        ready(store.append(id, 0, b"x"))?,
        Err(MemoryKeyError::ByteBudget(0))
    ));
    ensure!(store.reserved_bytes() == 0);
    ready(store.release(id))??;
    ensure!(store.key_count() == 0);
    Ok(())
}

#[test]
fn memory_ports_reject_invalid_identities_and_offsets_but_ignore_unoffered_suffixes()
-> anyhow::Result<()> {
    let ids = key_ids(2)?;
    let mut store = MemoryKeyStore::new(memory_options(2)?);
    ready(store.create(ids[0]))??;
    ensure!(matches!(
        ready(store.create(ids[0]))?,
        Err(MemoryKeyError::Identity(_))
    ));
    ensure!(matches!(
        ready(store.append(ids[0], 1, b"a"))?,
        Err(MemoryKeyError::Offset(1))
    ));
    ready(store.append(ids[0], 0, b"abc"))??;
    ensure!(ready(store.compare_prefix(ids[0], 0, b"a"))?? == Ordering::Equal);
    ensure!(ready(store.compare_prefix(ids[0], 1, b"bc"))?? == Ordering::Equal);
    ensure!(ready(store.compare_prefix(ids[0], 1, b"bcd"))?? == Ordering::Less);
    ensure!(ready(store.compare_prefix(ids[0], 3, b""))?? == Ordering::Equal);
    ensure!(matches!(
        ready(store.compare_prefix(ids[0], 4, b""))?,
        Err(MemoryKeyError::Offset(4))
    ));
    ensure!(matches!(
        ready(store.append(ids[0], 0, b"abc"))?,
        Err(MemoryKeyError::Offset(0))
    ));
    ensure!(matches!(
        ready(store.compare_prefix(ids[1], 0, b""))?,
        Err(MemoryKeyError::Identity(_))
    ));
    ensure!(matches!(
        ready(store.release(ids[1]))?,
        Err(MemoryKeyError::Identity(_))
    ));
    ready(store.release(ids[0]))??;
    ensure!(matches!(
        ready(store.release(ids[0]))?,
        Err(MemoryKeyError::Identity(_))
    ));
    Ok(())
}
