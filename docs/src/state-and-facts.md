# State And Facts

Xolotl separates mutable state from the Fact stream.

Hosted idempotent calls retain provenance from the cache observation, including absence. A miss carries those control sources into dispatch, pre-dispatch rejection, results and selected Facts; protected control sources are checked before calling a method that requires unprotected input. A hit preserves cached-output provenance even if delivery is revoked. Stream cancellation retains observations already acquired; an unfinished read does not establish provenance. None of these guarantees requires Fact recording.

## State Path

The `state://` path is served by independently composable `StateRead`, `StateBoundedRead`, `StateWrite`, `StateBoundedWrite`, `StateQuery`, `StateHistory`, `StateWatch`, and `StateFlush` capabilities in `xolotl-state`. They use associated futures without requiring `Send`, shared ownership, or a particular scheduler. A static implementation can return `Ready` without allocating a future. The optional host `Backend` erases only capabilities installed with `with_read`, `with_write`, and the corresponding builders. An absent capability returns `MissingCapability`.

`StateRead::read_tainted(path)` and `StateBoundedRead::read_tainted_bounded(path, max_encoded_bytes)` return `StateObservation { value: Option<Value>, taint: TaintSet }` from one consistent current view. `None` denotes absence with its provenance; `Some(Value::null())` denotes a present Null. Standard read projects absence to Null without discarding provenance. `read` is an explicit value-only projection. The bounded method reads one exact current path. The host `Backend::read_bounded` projects away provenance only for trusted metadata; it never falls back to unrestricted `StateRead` or a prefix query. The nonzero budget covers the backend's encoded key and record, including provenance. For a redb Source sink, that record is physically segmented: `encoded_bytes` counts the path and marker plus every item key and value. The size is known before materializing the logical List; the byte budget does not bound the resident Value allocation.

An oversized row returns typed `PointTooLarge` before redb decodes its payload or provenance; memory measures its already resident value while borrowed, before cloning it. `provenance_observed = false` on a redb size-only rejection means provenance is unknown: a pristine failure taint must not authorize an untainted fallback. This read limit does not bound resident heap, history, or a later conditional mutation.

`StateBoundedWrite` separately provides `compare_set_bounded` and `compare_delete_bounded`. Each checks the current record's nonzero encoded-byte limit inside the same atomic commit as its comparison, before copying or decoding an oversized value. The host `Backend` installs this port explicitly with `with_bounded_write`; it never substitutes ordinary `StateWrite`. A bounded read cannot constrain a concurrent replacement before a later write.

An oversized redb current row reports `PointTooLarge(provenance_observed = false)`, with its sources unknown; a comparison within budget retains the same observation's actual value and sources on `CasFailed`. This write limit covers the observed current row, not the incoming replacement, retained history, or resident heap.

Deletion carries invocation provenance too: `StateMutation::Delete(taint)`, `CompareDelete { expected, taint }`, and `compare_delete_bounded(path, expected, taint, max_current_encoded_bytes)` explicitly receive deletion input or control sources. The commit, failures, and actual Delete notifications/history retain those sources together with current-record sources observed in the same domain. Use `write_delete_tainted`, `write_compare_delete_tainted`, or `write_compare_delete_tainted_bounded` for sourced inputs; helpers without taint explicitly supply pristine input, and the standard delete method does not use them to discard Operation sources. Current absence retains deletion provenance independently of history; point reads return it in `StateObservation::taint`.

Hosts combining read and write ports for one workflow must provide a consistent commit domain. Console authentication requires this composition for its credential vault and shared challenge ledger. Both private rows use the same encoded-row budget for their bounded point read and conditional CAS; a host that installs only ordinary State read/write ports cannot serve those authentication operations.

State-driver Operations expose `read`, `write`, `append`, `delete`, `list`, and `compare_set`. `write` always stores its complete input as data, including maps containing `cas` or `value`. `compare_set` accepts a map with required `value` and optional `expected`: omitting `expected` requires an absent path; `expected: null` matches an explicitly stored null. Unknown options are errors.

The underlying, unrestricted `StateWrite` capability also supports atomic conditional deletion through `StateMutation::CompareDelete` and `write_compare_delete`. It compares the current value and removes it within one backend commit, without requiring `StateRead`. `None` matches absence and succeeds unchanged; `Some(Value::null())` matches a stored null. A mismatch returns `CasFailed` without changing the value, provenance, history or notifications.

Gateway request reservations and retained results belong to its explicitly installed `GatewayIdempotencyStore`, not ordinary State or State history. Gateway uses State conditional deletion for object authorization records; their provenance and retention follow the State contract. See [Application Gateway](application-gateway.md).

The standard state driver's `compare_set` uses this unrestricted write capability; its current-record size is not limited by `StateBoundedWrite` unless a trusted host explicitly chooses that separate port.

Because state access goes through Operations, capability checks, residual policy, taint propagation, and audit apply to state reads and writes just like they apply to other effects.

Subscriptions use the event bus facade `effect://events/subscribe`, backed by the state backend subscription channel. The standard state driver's signal method requires an explicitly installed `Backend::with_signal` port. It registers the subscription before reading the current value from the same commit domain; separate read and watch ports do not enable this method. Signal waits for a currently present value, not an event payload: an initial present value returns in full; initial absence seeds the accumulated provenance. Each matching notification contributes its provenance, then `Backend::observe_signal_current` rereads the paired current domain. Absence continues waiting; presence returns the complete current Value, including the full List after Append. Lag or closure fails explicitly with accumulated provenance; no history lookup or persistent wait is added. Other `Wait(Signal)` targets can provide their own unary `subscribe` method. Watch contracts expose a polling interface and explicit lag or closure; Tokio receivers are confined to the optional `host/broadcast.rs` adapter.

For this order to prevent a missed concurrent write, the installed read and watch ports must observe the same commit domain: a write after registration must appear in the read or reach that subscription, with its committed value and provenance, or yield an explicit lag, invalidation or error. Ports may be separate implementations if the host coordinates this contract. Merely installing each port does not provide it, and `StateFlush` does not establish cross-port consistency or durability by itself.

Memory and redb share `host/watch.rs`: registration storage is allocated on the first subscription, and the subscription's RAII guard removes its entry immediately on drop. Backend shutdown closes remaining subscriptions without creating a task or retaining the backend through the subscription. The redb store shares one publication coordinator across its State adapters and Source sink. It serializes subscription registration with the commit and queues matching notifications in commit order; subscribers await the coordinator asynchronously while a storage commit is in progress. Queued and currently delivering notifications share limits of 1,024 events and 8 MiB of accounted bytes. The charge is the lossless serialized `StateEvent` length, counted without retaining encoded bytes, plus the notification struct and allocated sender slots. Before serialization builds a value index, a borrowed walk also stops at 262,144 distinct nodes, 8,192 levels or 8 MiB of raw leaf and map-key bytes; this may invalidate a subscription even when the final encoding would be smaller. An event that cannot fit by itself commits successfully and invalidates matching subscriptions; temporary aggregate saturation rejects the write before commit. Source `DropOldest` publishes a `DropPrefixAppend` event carrying the actual removed count and the new item, so the List payload in its notification does not grow with the retained sink. The conservative provenance set can still grow, and an oversized event can still invalidate subscribers. Subscribers can replay it without the Source capacity declaration. These limits do not bound subscriber broadcast buffers, exact resident heap or total RSS. Delivery may finish after the write result when another worker is draining, and the draining writer can have a long return latency under sustained traffic.

In stream mode, `effect://events/subscribe` continues until cancellation, source closure or deletion of the matching topic. Optional `max_events` is an explicit nonnegative stopping count; zero finishes before subscribing. Successful completion returns the exact delivered count as a decimal string. A deletion emits no data chunk. The count and late failures retain all observed topic sources, while each data chunk carries its event's sources. Publishing appends to the topic's stored sequence; persistence and retention remain separate from the stream credit window.

## Tainted Values

State stores a `TaintedValue`: value plus provenance. A write carries the input taint into the backend envelope. Reads return the stored taint, preserving protected or low-trust provenance across the state boundary. `TaintedValue` is defined once in `xolotl-types`; State reexports it. Historical reads replay the value and taint together, including the union of appended items. The memory driver retains persisted provenance through recall, consolidation, and index restoration, and checks it before invoking a remote embedding backend.

`StateResult<T>` returns `StateFailure { error: StateError, taint: TaintSet }` on failure. Backends capture the sources of comparisons, partial scans and decoded records inside the same lock or transaction that observed them. Consumers preserve these sources when rejecting the operation or returning a fallback; rereading the path after failure cannot reconstruct that observation. Comparison diagnostics do not print stored values. Structured inspection of a failure remains an explicit data access and carries the failure's sources.

For redb writes, `StateError::CommitUncertain` means storage reported an error during commit and the mutation may already be durable. The host must stop using all adapters sharing that database instance, release its database users and reopen it before authoritative reconciliation or deciding whether to repeat an append or merge. This recovery requirement applies across State, Source, Facts, identity and execution-ID stores, and any installed Gateway, Console or Federation stores, not only the affected State path. A panic during commit also requires recovery; `redb::CommitError::TransactionPoisoned` alone establishes rollback. An ordinary backend error does not itself prove that a mutation was or was not committed. The error retains the sources observed by that mutation. See the [RedbStore recovery contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-storage-redb/src/lib.rs).

All adapters from one `RedbStore` share a recovery owner. Commit uncertainty or a panic during commit makes that instance require reopening: new database transactions, subscriptions and checked hints reject across domains. `RedbStore::requires_reopen()` exposes the shared terminal state. Previously admitted snapshots and confirmed immutable execution-ID reservations remain valid, but an older value, absence or provenance cannot establish rollback of the uncertain mutation. After releasing and reopening the instance, reconcile actual data and applicable retained evidence; the fence neither rolls back a commit nor restores ordinary execution.

An uncertain redb commit invalidates all live State subscriptions and closes Fact notification sources sharing the instance, including unrelated paths and adapters. An individual committed notification that cannot fit its publication budget invalidates only matching State subscriptions; ordinary reread/resubscribe can then recover a best-effort observation without reopening the database. Recovery wakeups occur after notification-order locks are released. For an uncertain storage commit, recover the database before authoritative reconciliation or resubscribing; a notification is never a commit receipt. The standard State driver returns an uncertain writer outcome as a structured failure with `kind = "state_commit_uncertain"`, even when no additional source was observed.

Successful mutations return `StateCommit { taint }` from the same atomic boundary. Compare-set stores the union of the current and incoming sources, even if another writer changed only the sources of an otherwise identical value. Append and merge retain their participating sources; conditional deletion returns the observed sources in its receipt. An unconditional Set explicitly replaces stored provenance, while its receipt still describes the backend's observations. State notifications retain those observations as well, including Append and Delete. A history window containing only the deletion still carries its sources; it does not need the earlier value's Set event to recover them.

## State Pages

`StateScan` and `StateHistoryQuery` have independent nonzero budgets for returned entries, examined candidates, and encoded bytes. Defaults are 256 entries, 4,096 candidates and 1 MiB. `StatePager` and `StateHistoryPager` hold one page's continuation; callers process each page before requesting the next. Each page is consistent, while later pages observe live state. Ordering and opaque byte cursors belong to the backend; cursors must be reused with the same query.

An empty page can have `next`. Continue until `next` is absent, including when a limit is reached exactly at the last record. Exhausting any budget ends the page before inspecting another row. If an oversized row follows consumed candidates, the backend first returns the partial page with `next` before that row, including an empty page after out-of-scope history candidates. Without consumption progress, it returns `StateFailure` containing `StateError::RowTooLarge`, the path, required encoding size, the request's starting cursor for retry, and an explicit resume cursor after that row. This preserves preceding records when callers explicitly point-read or skip an oversized row. Other failures, including corrupt encodings, remain failures. redb checks stored key and record lengths before decoding; memory counts the borrowed lossless encoding before cloning a matching value.

A prefix includes its exact path and descendants, not textual-prefix neighbors. Scope is checked from keys before observing content or provenance. `examined` charges physical candidates, including out-of-scope history keys when a backend scans a shared journal; those keys do not contribute content sources or encoded bytes. Current pages charge full consumed records, including sourced absence. History pages charge full matching records and only key/provenance metadata for time-filtered records; filtered payloads are not materialized.

Each in-scope key/provenance header must fit the full page byte budget before its sources are accumulated. A rejected header reports `provenance_observed = false` and retains previously observed sources. While budget remains, one admitted boundary row may contribute sources without being consumed or included in `encoded_bytes`. Consumed provenance input plus that boundary is bounded by twice the page byte limit, not by a whole-process memory limit. For header admission or time-filtered history, the required size in `RowTooLarge` is its key/provenance metadata size; matching-payload rejection reports the complete record size.

Standard preserves unread provenance as `Failure::HandlerError` with kind `state_provenance_unavailable`, including previously observed sources. An empty failure taint does not establish pristine provenance for the rejected record. This is distinct from `state_commit_uncertain`, which describes an unknown data-commit result.

The standard `list` input is null or an options map containing `cursor` (bytes), `limit`, `max_examined`, and `max_encoded_bytes`. Its output has `entries`, `next`, `examined`, and `encoded_bytes`; each entry contains `path` and `value`. Output taint covers all records observed by the page, including a row examined before deferring it to the next page. `StatePage::taint` and `StateHistoryPage::taint` also preserve sources that affect cursors and byte accounting.

`list` authorizes the queried prefix as one collection resource: `read://state/work` permits listing its descendant values, even though it does not authorize a separate `read` call on each descendant path. Keep data with different read audiences under separate collection prefixes or apply a policy to the list method.

Collection grants do not bypass reserved namespaces. Generic State handles cannot open local kernel, vault or raw Fact paths. Standard `list` rejects the local `state://` root before querying because that collection contains reserved namespaces, even with a wildcard grant. Use the dedicated Fact resource for its public projection. Trusted hosts may still query State roots directly; the backend does not implement application authorization or silently filter rows.

History intervals are half-open `[from_millis, to_millis)` and reversed bounds are rejected. The history port returns `StateObservation`, distinguishing sourced absence from a present Null. `read_at(path, 0)` reads the current observation; other timestamps reconstruct the observation at that instant, starting from a retained path baseline if history has been trimmed. Reads before the global retention floor return `HistoryTrimmed { retained_from_millis }`, including paths never seen before. History pages contain original mutations, not synthetic baseline events; their cursors are bound to the path, time interval, and current retention floor.

The protected `state://vault/**` namespace retains current values only, even with `Full` history. Nonzero historical reads and vault-prefix history pages return `HistoryExcluded`; wider scans contain no vault mutations. This excludes old credential verifiers from logical history, but does not securely erase redb copy-on-write pages or backups.

`read_at` reconstructs a value from retained changes at or before the requested instant. A long path history can still require substantial work, with no per-call budget. Use history pages for explicit traversal budgets; they do not bound retained history, one decoded value, or total application work. Applications collecting all pages own the resulting memory.

## Facts

Facts are explicitly selected observations of operation attempts. Audit, trace and `why_not` projections can be built from them; records are not authority for permissions, account balances or external-effect commits, and do not restore program control flow. Fact storage commits follow the selected backend contract.

Ordinary Executor calls do not record Facts by default. Select `Executor::with_fact_recording(true)` for recorded execution or `InvocationOptions::record` for direct calls. KernelBuilder defaults to a disabled Fact sink; install a sink explicitly before selecting recording. Installing a Fact backend alone does not enable recording. Disabled writes and checked reads report uninstalled observation storage, not empty history; explicitly requested recording fails closed. Built-in memory and redb retention is bounded with no automatic retirement; defaults and assembly are listed in [Fact Observation](api-reference.md#fact-observation). Retained payloads and backend writes are costs of that explicit observation policy.

The hot path keeps Facts compact by storing refs and lightweight tags. Large content is represented with blob, tensor, or frame references.

Identity fields describe separate facts:

| Field | Meaning |
| --- | --- |
| `caller` | The calling `ProcessId`; its numeric value is not an identity. |
| `caller_identity: Option<IdentityRef>` | The caller process's default identity, as observed once by the trusted host before admission. `None` explicitly means unknown. |
| `acting` | The identity selected for this operation attempt. |

An Executor created from a `ProcessTable` takes the baseline from that table; a standalone Executor requires an explicit identity. Direct DataPlane callers and portable hosts supply their baseline, or retain `None` when it is unknown. Pending, completion and denial records for the same invocation reuse its admission snapshot.

A new invocation that hits an idempotency cache records its own caller identity, not the cache producer's.

`AuditTag::CrossIdentity` is derived only when `caller_identity` is `Some` and differs from `acting`, including switches to or from root. It records an attempted identity switch, not proof that delegation was authorized or the effect occurred. An unknown baseline produces no such tag; absence of the tag does not prove that identities were equal. Neither a `ProcessId` nor the selected acting identity can fill in missing baseline evidence. Gateway audit Facts use root for both identities.

Hosts can explicitly add application audit events to the same stream. `Bootstrap::record_gateway_audit` accepts `GatewayAudit`: `event`, `outcome`, optional `username`, `source_addr` and application-owned `details`. The caller redacts secrets before submission. The kernel neither authenticates these labels nor interprets authentication claims in `details`.

`xolotl_types::audit::gateway_audit_event` recognizes the complete administrative envelope, including `GATEWAY_AUDIT_NODE`, invocation ticket zero, inactive handle coordinates, root baseline and acting identities, and observation metadata. The position alone is insufficient. Valid events receive `AuditTag::Custom` for any nonempty host event name; no Console prefix is required. An ordinary Operation's `event` output cannot impersonate this envelope. Recognition validates structure from a trusted Fact writer, not the authenticity of an arbitrary imported Fact. Console places its session summary inside `details.authentication`; the common envelope has no MFA field.

The redb Fact adapter treats a storage error from commit as an unknown outcome: the record may already be durable. Its shared database recovery owner closes live Fact notification sources, invalidates State subscriptions and rejects new database operations until reopening, regardless of the originating adapter. A poisoned transaction that was rolled back does not require this recovery transition. New execution-ID reservations reject as well; already confirmed cached ranges remain usable. A closed subscription requires reopening followed by a fresh bounded scan, including older slots whose completion may have changed. The returned error never proves that the attempted Fact is absent.

A failed redb commit can leave the current instance reading an older root even when reopening recovers a durable row. Thus `cursor()` remains only a local hint; `FactSink::observed_cursor()` fails while the outcome is unknown, so response revisions must not present that hint as current. After reopening, `scan` captures the head of its own read view for reconciliation. `FactError::kind()` distinguishes `CommitOutcomeUnknown` from the later `ReopenRequired` state; callers use this category rather than parsing diagnostic text. `Other` by itself does not prove whether an external effect ran.

After reopening, a caller must reconcile the full `OperationId` before retrying an effect or completion. This does not turn the append cursor into a completion revision or make a live notification stream durable.

## Bounded Reads

`FactQuery` describes an append interval `[from, before)`, optional caller filter, `FactOrder::{Forward, Reverse}`, and independent `limit`, `max_examined` and `max_encoded_bytes` budgets. `FactQuery::new` defaults to forward order and an examination budget equal to the result limit. `FactSink::scan` validates the adapter's returned bounds and accounting before its callers process the page.

Use `query.next_page(&page)` to continue with the same direction, filter and budgets. `page.next = None` means exhaustion. An empty `facts` array can still have a continuation: memory scans charge unrelated slots against `max_examined`. Indexed adapters can skip unrelated callers. A byte-rejected candidate counts as examined but stays unread; if it is the first match, the read returns an error.

`lookup(FactLookup)` locates an operation by index and filters its current caller before checking the byte budget or copying/decoding, all in one storage view. It distinguishes `Found`, `Missing` and `FilteredOut`; an oversized matching record is an error. `get_bounded(id, bytes)` is the unfiltered convenience wrapper.

Forward continuation fixes `before` to the first page's `end`; reverse continuation shrinks `before` to `next` and retains `from`. Each page's `end` is its own captured upper bound. Appends beyond that range are excluded, while completion can still replace outcomes or caller membership inside it. These cursors are append positions, not timestamps, filtered-row offsets or durable subscription revisions.

The standard `read` method at `state://fact` or `state://fact/<process>` accepts `from`, `before`, `order`, `limit`, `max_bytes` and `max_examined`. It returns an object with `items`, `from`, `end`, `next`, `order`, `complete`, `examined` and `encoded_bytes`. Cursors and projected numeric identifiers are exact decimal strings; cursor inputs also accept nonnegative integers. The default is 64 results, 256 KiB of encoded data and 4,096 examined candidates. Limits above 256 results, 256 KiB or 65,536 candidates, zero budgets and unknown fields are rejected.

```json
{"from":"0","before":"1200","order":"reverse","limit":32,"max_bytes":65536,"max_examined":256}
```

Process inspection reads Facts only when `include_recent_facts` is true and an explicit `process` is selected, using the same query parser and page projection, defaulting to reverse order and 32 results. Requiring one process keeps enumeration from multiplying the Fact budget. `recent_facts` is a page. Process and child enumeration have separate retention costs.

These budgets bound returned encodings and examined candidates, not stored history, decoded heap, total RSS or elapsed time. Inspecting one large value can still be expensive. Exact analytics over all history require explicit bounded passes or a separately maintained projection; one page is not a global total. `get`, `all_facts` and `facts_of` remain explicit unbounded diagnostic conveniences.

## Storage Backends

Filesystem `max_uploads` is upload-only: it covers upload creation, live upload records, lost receipts and deferred upload cleanup. Retired-object deletion does not consume that capacity, so filling upload slots must not newly block foreground object deletion. Foreground filesystem jobs retain their separate I/O admission limit.

During live ownership, the filesystem object adapter retains an abandoned upload's admission slot and staging-root lease until its staging directory is removed (or already absent). Failed deletion stays charged and is retried by the cleanup worker while it is live; it does not require the cancelled caller or its Tokio runtime to return. Closing the last sender makes a final attempt and leaves any failed directories for a later cold open. A concurrently open store must not reclaim another live owner's staging. Registered pending uploads exclude deferred cleanup, so a zero pending-upload count does not prove that upload capacity is free. This is object-storage cleanup, not State rollback or a durable execution checkpoint.

`AbsenceLimits` charges retained sourced-absence records and each backend's complete absence encoding plus key. Memory and redb default to 65,536 records and 64 MiB; `None` explicitly removes a dimension and zero prohibits new charge. Reject growing over-budget transitions atomically without losing provenance, history or notifications. Reopen preserves redb accounting; lowered quotas permit non-growing usage without erasing evidence. Backend encodings may charge different byte counts for the same observation.

Source fingerprint admission bounds traversal before descent as well as exact encoding, counting resident identity-deduplicated nodes, every collection reference, keys and string/byte content. Accepted fingerprints preserve the tagged representation without buffering its complete encoding. During history trim, the first Set for a path replaces the baseline without reading it; Append, Delete and prefix-append still depend on the prior observation.

Redb owns every top-level List as a current State marker plus independently encoded items, including Lists written by ordinary Set, compare-set, and merge. These items are the current value, not a side index or another copy. Ordinary Append inserts only the new item and updates the marker; retained item keys and bytes remain unchanged. A subsequent Source append uses the same representation without rebuilding the List. Replacing or deleting a List removes its old items in the same transaction. Comparisons and general merges may still materialize the current Value; Full history and Set notifications still retain their complete event payloads.

Bounded reads and comparisons charge the path key, marker, provenance, and all item keys and bytes. Source entry and byte limits apply at Source admission, not at generic State List decoding. The State-owned format uses `XSL1`, `state_list_items_v1`, and `state_list_meta_v1`.

Memory uses persistent List updates and prefix pruning, but Source byte admission still measures the exact complete tagged List envelope inside the commit lock. Bounded current observations also measure their complete envelope. Counting avoids a full output buffer, not value-graph traversal or encoding-index allocations; cross-item sharing prevents substituting a sum of independently encoded items. Neither representation's encoded-byte charge is an RSS limit.

Persistent values use explicit node tables shared by State, history, Facts and program constants. Bytes, maps, complete object descriptors, stream markers and floating-point bit patterns retain their types. State, history and Fact formats are v1 formats. Missing provenance, malformed tables and unknown formats fail explicitly. Stores initialize only empty schemas; they do not synthesize missing authority, identity or commit evidence or reinterpret existing records. Derived accounting can be reconstructed from retained data where the owning contract explicitly permits it.

The canonical v1 Fact field `caller_identity` is required and nullable. A stored null means unknown; an omitted field is invalid. No older missing-field form is accepted, and decoding does not infer a baseline from `caller` or `acting`.

Ordinary JSON used by external application schemas is a different representation. Do not serialize a persistent value through an intermediate untagged JSON value. Fact input is a complete Value and its successful outcome is an optional Value. The recorded decision distinguishes pending work from a failed or denied call; `Some(Value::null())` is a successful null result. Console details project these typed values directly, retaining tensor and frame metadata.

`xolotl-state` keeps portable contracts in `read.rs`, `write.rs`, `query.rs`, `history.rs`, and `watch.rs`; host type erasure lives in `host.rs`. Building without default features uses `no_std + alloc`. `std` enables host composition without Tokio, `tokio` enables broadcast adaptation, and `memory` enables the in-process backend. `memory/storage.rs` owns compact or sharded map locking and bounded snapshots. Current values use ordered maps without a second global index.

The in-memory default, `MemoryHistory::Disabled`, retains current live values and sourced absence without mutation history. It does not install the history capability. `Full` must be selected explicitly and retains every non-vault mutation until the host explicitly advances its retention floor.

`InMemoryOptions` independently selects read shards, history, notification capacity, Source stream identities and absence budgets; see [API Reference](api-reference.md#in-memory-state) for fields and defaults. Enable the SDK's `memory` feature to use this backend, then select full history when needed:

```rust
use std::num::NonZeroUsize;
use xolotl_sdk::{InMemoryBackend, InMemoryOptions, KernelBuilder, MemoryHistory, Xolotl};

let state = InMemoryBackend::with_options(InMemoryOptions {
    read_shards: NonZeroUsize::new(32).ok_or("zero read shards")?,
    history: MemoryHistory::Full,
    ..InMemoryOptions::default()
})?
.into_backend();
let kernel = KernelBuilder::new(state).build();
let host = Xolotl::from_kernel(kernel);
```

More shards can reduce contention between different keys but add storage and locking costs. The default history-free mode does not bound current values, subscribers or the host's total memory. Untrimmed `Full` history grows with every mutation.

Its independent `StateHistoryRetention` port exposes `retained_from()` and `trim_before(floor, limits)`; the dynamic `Backend` uses `trim_history_before`: a bounded trim atomically folds older mutations into exact-path value and provenance baselines. An over-budget trim changes nothing. Earlier reads then fail explicitly, and old history cursors cannot resume after the floor advances. The daemon schedules bounded trims only when `[storage.history_maintenance]` explicitly authorizes a time window; `Full` without it retains history until manually trimmed. See [API Reference](api-reference.md) for all options.

`xolotl-storage-redb` implements the same capabilities with transactional pages in `state/read.rs` and lossless storage encoding in `state/codec.rs`. `RedbStore::open` defaults to `RedbHistory::CurrentOnly`; select `Full` with `RedbStore::open_with_history(path, RedbHistory::Full)` before creating the State backend. Both modes keep current values; only `Full` installs history and history-retention maintenance ports and writes non-vault mutation records. The chosen mode and retention floor are stored in redb metadata and survive restart. The mode cannot change on reopen; databases missing the required schema or markers are rejected.

After stopping State and Source producers, `RedbStore::wait_idle()` waits for accepted State/Source blocking jobs to release their database captures, including jobs whose result waiters disappeared. Its returned future owns only the completion tracker, so an in-process reopen can take the future, drop the adapters and store, then await it. Synchronous Fact operations, Console stores and other database users must be stopped and released separately; this is not a global database shutdown operation.

A trim deletes old logical history rows in the same transaction that publishes path baselines and the floor. The path-first history table serves queries; a separate time-first index lets retention visit only rows before the requested floor. Ordinary State writes and Source sink commits update both orders in one transaction. Event and encoded-byte budgets bound a trim's candidate work and staged baselines; an over-budget trim leaves the floor unchanged. The extra index increases `Full` write/storage cost, and deletion need not shrink the redb file immediately.

With Federation enabled, redb checks up to 64 explicitly registered State publisher pins in the same write transaction before deleting history. Registration also checks the current floor in its write transaction, preventing a trim/register race. Pending pages pin their unconsumed timestamp (including unscanned events sharing that timestamp); completed cursors pin the next timestamp. Invalid or over-budget pin metadata rejects trim. Removing stock publication configuration retains the pin; a trusted host must settle pending pages and explicitly release the exact completed cursor. This is not a global reader registry: consumers without durable pins still depend on the host’s explicit retention-window policy.

Publisher-pin metadata is a required physical table even in builds without Federation. Such builds can reopen and use State, but reject retention advancement while any pin remains; a Federation-enabled owner must settle or release it. Missing pin metadata rejects reopen instead of creating empty retention evidence.

The daemon's optional time-window policy does not track active readers or audit/replay requirements. The host must decide which historical reads may expire before enabling it; see [Configuration](configuration.md#state-history-maintenance).

Memory and redb expose `into_backend()` to assemble supported host capabilities. Custom hosts can install fewer capabilities or combine implementations independently. `FactStore` adapters remain separate from mutable State capabilities.

`xolotl.toml` chooses storage at bootstrap time. Runtime state managed by the console is stored in Xolotl state.
