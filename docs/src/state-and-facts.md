# State And Facts

Xolotl separates mutable state from the Fact stream.

## State Path

The `state://` path is served by independently composable `StateRead`,
`StateWrite`, `StateQuery`, `StateHistory`, `StateWatch`, and `StateFlush`
capabilities in `xolotl-state`. They use associated futures without requiring
`Send`, shared ownership, or a particular scheduler. A static implementation
can return `Ready` without allocating a future. The optional host `Backend`
erases only capabilities installed with `with_read`, `with_write`, and the
corresponding builders. An absent capability returns `MissingCapability`.

State-driver Operations expose `read`, `write`, `append`, `delete`, `list`,
and `compare_set`. `write` always stores its complete input as data, including
maps containing `cas` or `value`. `compare_set` accepts a map with required
`value` and optional `expected`: omitting `expected` requires an absent path;
`expected: null` matches an explicitly stored null. Unknown options are errors.

The underlying `StateWrite` capability also supports atomic conditional deletion
through `StateMutation::CompareDelete` and `write_compare_delete`. It compares
the current value and removes it within one backend commit, without requiring
`StateRead`. `None` matches absence and succeeds unchanged; `Some(Value::null())`
matches a stored null. A mismatch returns `CasFailed` without changing the value,
provenance, history or notifications. Gateway uses this operation to release
only its uniquely identified idempotency reservation. A delayed release cannot
delete a replacement reservation, and successful release leaves no current row.
Mutation history still follows the backend's selected retention policy.

Because state access goes through Operations, capability checks, residual
policy, taint propagation, and audit apply to state reads and writes just like
they apply to other effects.

Subscriptions use the event bus facade `effect://events/subscribe`, backed by
the same state backend subscription channel. Executor `Wait(Signal)` nodes also
wait on that backend subscription. Watch contracts expose a polling interface
and explicit lag or closure; Tokio receivers are confined to the optional
`host/broadcast.rs` adapter. Signal waits subscribe before their initial read.
Memory and redb share `host/watch.rs`: registration storage is allocated on
the first subscription, and the subscription's RAII guard removes its entry
immediately on drop. Backend shutdown closes remaining subscriptions without
creating a task or retaining the backend through the subscription.

In stream mode, `effect://events/subscribe` continues until cancellation, source
closure or deletion of the matching topic. Optional `max_events` is an explicit
nonnegative stopping count; zero finishes before subscribing. Successful completion
returns the exact delivered count as a decimal string. A deletion emits no data
chunk. The count and late failures retain all observed topic sources, while each
data chunk carries its event's sources. Publishing appends to the topic's stored
sequence; persistence and retention remain separate from the stream credit window.

## Tainted Values

State stores a `TaintedValue`: value plus provenance. A write carries the input
taint into the backend envelope. Reads return the stored taint, preserving
protected or low-trust provenance across the state boundary.
`TaintedValue` is defined once in `xolotl-types`; State reexports it. Historical
reads replay the value and taint together, including the union of appended items.
The memory driver retains persisted provenance through recall, consolidation,
and index restoration, and checks it before invoking a remote embedding backend.

`StateResult<T>` returns `StateFailure { error: StateError, taint: TaintSet }`
on failure. Backends capture the sources of comparisons, partial scans and
decoded records inside the same lock or transaction that observed them.
Consumers preserve these sources when rejecting the operation or returning a
fallback; rereading the path after failure cannot reconstruct that observation.
Comparison diagnostics do not print stored values. Structured inspection of a
failure remains an explicit data access and carries the failure's sources.

Successful mutations return `StateCommit { taint }` from the same atomic
boundary. Compare-set stores the union of the current and incoming sources,
even if another writer changed only the sources of an otherwise identical value.
Append and merge retain their participating sources; conditional deletion returns
the observed sources in its receipt. An unconditional Set explicitly replaces
stored provenance, while its receipt still describes the backend's observations.
State notifications retain those observations as well, including Append and
Delete. A history window containing only the deletion still carries its sources;
it does not need the earlier value's Set event to recover them.

## State Pages

`StateScan` and `StateHistoryQuery` have independent nonzero budgets for returned
entries, examined candidates, and encoded bytes. Defaults are 256 entries,
4,096 candidates and 1 MiB. `StatePager` and `StateHistoryPager` hold one page's
continuation; callers process each page before requesting the next. Each page
is consistent, while later pages observe live state. Ordering and opaque byte
cursors belong to the backend; cursors must be reused with the same query.

An empty page can have `next`. Continue until `next` is absent, including when
a limit is reached exactly at the last record. Oversized rows return
`StateFailure` containing `StateError::RowTooLarge`, the path, required encoding size, a retry cursor
and an explicit resume cursor. The backend does not silently skip them. redb
checks stored key and record lengths before decoding; memory counts the
borrowed lossless encoding before cloning a matching value.

The standard `list` input is null or an options map containing `cursor` (bytes),
`limit`, `max_examined`, and `max_encoded_bytes`. Its output has `entries`, `next`,
`examined`, and `encoded_bytes`; each entry contains `path` and `value`. Output
taint covers all records observed by the page, including a row examined before
deferring it to the next page. `StatePage::taint` and `StateHistoryPage::taint`
also preserve sources that affect cursors and byte accounting.

History intervals are half-open `[from_millis, to_millis)` and reversed bounds
are rejected. `read_at(path, 0)` selects the current value; other timestamps
reconstruct history at that instant. This convenience can replay the entire
path history. Use history pages when the caller needs explicit work budgets.
Page budgets do not bound retained history, a single decoded value, or total
application work. Applications collecting all pages own the resulting memory.

## Facts

Facts are append-only records of operation attempts. Recovery, audit
projection, trace projection, billing projection, and `why_not` explanations
are built from those records.

The hot path keeps Facts compact by storing refs and lightweight tags. Large
content is represented with blob, tensor, or frame references.

## Bounded Reads

`FactQuery` describes an append interval `[from, before)`, optional caller filter,
`FactOrder::{Forward, Reverse}`, and independent `limit`, `max_examined` and
`max_encoded_bytes` budgets. `FactQuery::new` defaults to forward order and an
examination budget equal to the result limit. `FactSink::scan` validates the
adapter's returned bounds and accounting before its callers process the page.

Use `query.next_page(&page)` to continue with the same direction, filter and
budgets. `page.next = None` means exhaustion. An empty `facts` array can still
have a continuation: memory scans charge unrelated slots against `max_examined`.
Indexed adapters can skip unrelated callers. A byte-rejected candidate counts
as examined but stays unread; if it is the first match, the read returns an error.
`lookup(FactLookup)` locates an operation by index and filters its current caller
before checking the byte budget or copying/decoding, all in one storage view.
It distinguishes `Found`, `Missing` and `FilteredOut`; an oversized matching record
is an error. `get_bounded(id, bytes)` is the unfiltered convenience wrapper.

Forward continuation fixes `before` to the first page's `end`; reverse continuation
shrinks `before` to `next` and retains `from`. Each page's `end` is its own captured
upper bound. Appends beyond that range are excluded, while completion can still
replace outcomes or caller membership inside it. These cursors are append
positions, not timestamps, filtered-row offsets or durable subscription revisions.

The standard `read` method at `state://fact` or `state://fact/<process>` accepts
`from`, `before`, `order`, `limit`, `max_bytes` and `max_examined`. It returns an
object with `items`, `from`, `end`, `next`, `order`, `complete`, `examined` and
`encoded_bytes`. Cursors and projected numeric identifiers are exact decimal strings;
cursor inputs also accept nonnegative integers. The default is 64 results,
256 KiB of encoded data and 4,096 examined candidates. Limits above 256 results,
256 KiB or 65,536 candidates, zero budgets and unknown fields are rejected.

```json
{"from":"0","before":"1200","order":"reverse","limit":32,"max_bytes":65536,"max_examined":256}
```

Process inspection reads Facts only when `include_recent_facts` is true and an
explicit `process` is selected, using the same query parser and page projection,
defaulting to reverse order and 32 results. Requiring one process keeps enumeration
from multiplying the Fact budget. `recent_facts` is a page. Process and child
enumeration have separate retention costs.

These budgets bound returned encodings and examined candidates, not stored
history, decoded heap, total RSS or elapsed time. Inspecting one large value can
still be expensive. Exact analytics over all history require explicit bounded
passes or a separately maintained projection; one page is not a global total.
`get`, `all_facts`, `facts_of` and `recover_process` remain explicit unbounded
diagnostic conveniences.

## Storage Backends

Persistent values use explicit node tables shared by State, history, Facts and
program constants. Bytes, maps, complete object descriptors, stream markers and
floating-point bit patterns retain their types. State, history and Fact formats
are first-release formats. Missing provenance, malformed tables and unknown
formats fail explicitly. Stores initialize only empty schemas; they do not
backfill metadata or reinterpret existing records.

Ordinary JSON used by external application schemas is a different representation.
Do not serialize a persistent value through an intermediate untagged JSON value.
Fact input is a complete Value and its successful outcome is an optional Value.
The recorded decision distinguishes pending work from a failed or denied call;
`Some(Value::null())` is a successful null result. Console details project these
typed values directly, retaining tensor and frame metadata.

`xolotl-state` keeps portable contracts in `read.rs`, `write.rs`, `query.rs`,
`history.rs`, and `watch.rs`; host type erasure lives in `host.rs`. Building
without default features uses `no_std + alloc`. `std` enables host composition
without Tokio, `tokio` enables broadcast adaptation, and `memory` enables the
in-process backend. `memory/storage.rs` owns compact or sharded map locking and
bounded snapshots. Current values use ordered maps without a second global
index. `MemoryHistory::Disabled` retains current values without mutation history;
`Full` retains all history and is unbounded.

`InMemoryOptions` independently selects read shards, history and notification
capacity. With the SDK's `host` feature, configure these choices through the
backend injection point:

```rust
use std::{num::NonZeroUsize, sync::Arc};
use xolotl_sdk::{InMemoryBackend, InMemoryOptions, MemoryHistory, XolotlBuilder};

let state = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
    read_shards: NonZeroUsize::new(32).ok_or("zero read shards")?,
    history: MemoryHistory::Disabled,
    ..InMemoryOptions::default()
})?);
let host = XolotlBuilder::new().with_state_backend(state).build();
```

More shards can reduce contention between different keys but add storage and
locking costs. Disabling history does not bound current values, subscribers or
the host's total memory. See [API Reference](api-reference.md) for all options.

`xolotl-storage-redb` implements the same capabilities with transactional pages
in `state/read.rs` and lossless storage encoding in `state/codec.rs`. Memory and
redb expose `into_backend()` to assemble supported host capabilities. Custom
hosts can install fewer capabilities or combine implementations independently.
`FactStore` adapters remain separate from mutable State capabilities.

`xolotl.toml` chooses storage at bootstrap time. Runtime state managed by the
console is stored in Xolotl state.
