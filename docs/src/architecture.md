# Architecture

Xolotl keeps the execution hot path small:

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

The hosted runtime has four code paths. Below them, `xolotl-core` owns only
structured control flow, fixed storage and host requests. It has no dependency
on the hosted value model, Tokio, a registry, storage or providers.

The rest of the manual follows this split. Concept pages explain Process,
Resource, Capability, Operation, Fact, and replay. Gateway pages explain how
outside clients enter the runtime. Configuration pages explain which
listeners, features, and runtime declarations expose those pieces in a host.

## Control Path

The control path parses, validates, resolves, and compiles. It owns registries,
resource naming, admission checks, policy compilation, binding resolution, and
`open()` handle compilation.

The key rule is that parsing and registry walking happen before execution.
Once a Process owns a Handle, execution can use compiled ids,
rights bitmaps, driver plans, and policy snapshots.

## Data Path

The data path executes one Operation through a compiled Handle. It checks
ownership, handle liveness, rights, residual policy if needed, dispatches the
DriverPlan, and records a Fact when the operation must be durable.

An opened `MethodContract` freezes method rights, output support, replay class,
cost, batching and cleanup admission. `Invocation` also binds the operation's
owner and acting identity. All direct and executor-driven calls use this boundary.
`DriverOutput` carries the outcome, provenance and optional measured usage together.
The host charges the owner and retained ancestor accounts atomically; asynchronous
process adaptation charges the child effect once. Scheduling windows do not limit
cumulative task bytes or transitions.

Methods declare whether they require unprotected input. The executor does not
infer this from an effect name. Inference, retrieval and storage drivers attach
the provenance of the data they actually produce or read.

Optional provider input guards are frozen at open time and run outside table
locks before policy and records; rejected inputs carry an explicit safe audit
projection. Unauthorized inputs are omitted. Cleanup permissions are also frozen:
owner-scoped permission remains tied to the resource owner after delegation.

`kernel::runtime` supplies `LinkedExecution` for `no_std + alloc` embeddings.
Its request adapter, GAT drivers and account ports use the same method admission,
value semantics, reservation ownership and Fact construction as Tokio. A compiler
artifact can transfer its constants through `CompiledProgram::with_provenance`
without cloning payload buffers. The host supplies time, I/O and wakeups.

The data path receives compiled ids, rights bitmaps, driver plans, and policy
snapshots.

## External Adapters

External adapters project outside systems into the same runtime model.
Providers expose `effect://...` resources through Drivers or remote bindings.
Sources write inbound events into declared state streams. gRPC and WebSocket
are transport implementations for the same Provider/Source gateway.

## Program Execution

Portable `Program` documents and Rust expressions use one compiler to produce
core instructions. `PreparedProgram` shares immutable host instructions,
constants and resource analysis across runs. The core derives peak capacities
from control flow, and the compiler reuses slots after lexical scopes end;
instruction count does not directly determine execution storage. Existing `DoNode` and
`ExecutionGraph` programs lower to the same machine; process-local Steps remain
an optional native extension with bounded expansion.

The core advances control flow and returns requests. The host resolves imports,
checks authority, drives concurrent I/O and delivers ticketed completions.
Cancellation, error recovery and lexical cleanup have one implementation in the
core. Within the Executor, `image` handles lowering, `config` bounds admission,
`buffers` manages caller-owned reusable allocations, `machine` drives requests,
and optional `durable` handles checkpoint barriers. The core's `frame` module
manages a bounded shared arena with independent per-task depth and total capacity.
Execution exits release stored values; callers choose whether to retain empty
capacity. The kernel maintains no implicit global buffer pool.

Native extensions use the same derived admission layout. The host analyzes each
new subprogram and reserves growth against the active invocation bounds and byte
budget. `suspend` and `resume` transfer the controller around a checked storage
handoff; pending requests keep their tickets. Failed admission or reservation
rolls back the new image segment before error recovery. Core execution remains
allocation-free with nonallocating values and caller-provided storage.

`image::arena` owns the lifetime and placement of loadable program fragments.
Native graph Steps and portable program loaders share fragment analysis,
relocation, admission and reclamation. Each fragment uses stable address ranges;
code, imports and binding values are released after its continuation has returned.
Free ranges are reused across out-of-order completion without moving live code.
Source positions stay local to each module; invocation tickets distinguish
repeated calls independently of reused addresses. There is no implicit cache of
every loaded module. The allocator is local to one hosted execution;
the dependency-free core only exposes active continuations
and explicit binding release. Fragmentation and retained container capacity are
documented separately from live storage in the portable guide.

Value ownership follows the execution: sequential stages and completed branches
transfer results. Hosts can retain compact error provenance through
`Values::retain_control`, while pending requests retain full inputs for recovery.
The core imposes no shared-pointer, allocator or hosted-taint representation.

Checkpoint restoration includes lexical values, tasks, continuations, execution
identity and dynamic invocation tickets. Facts classify completed and uncertain
effects; they cannot reconstruct native continuations or concurrent scheduling.
Execution recovery uses complete portable checkpoints, including active module
fragments and their continuation ranges. Program loaders declare a separate
`LoaderRevision`; recovery reattaches the host's `StepModule` and checks those
revisions before resuming the saved image. Missing loaders, changed revisions and
invalid cross-module references reject recovery while preserving the journal.
Volatile native closures remain outside durable execution. See
[Core And Portable Programs](core-and-portable.md).

## Execution Identity

Each independent evaluation receives an `ExecutionId`. Machine request tickets
become full-width `InvocationId`s; source `NodeId`s retain their static meaning.
`OperationId` is 32 bytes: process, execution, invocation, position and explicit
retry attempt. Repeated calls, concurrent visits, actor bodies and finalizers
remain distinct even at the same source position. Restoring a checkpoint reuses
both its execution scope and pending tickets. Explicit retry increments only
`attempt`, with checked exhaustion.

`ExecutionIds` is a replaceable host adapter over `ExecutionIdSource`. It shares
a small range cache and reserves up to 256 scopes at once, with one cache lock
per evaluation and no identity allocation per operation. Persistent adapters
commit the high-water mark before issuing a range, independently of Fact or
checkpoint retention. The dependency-free core has no new fields or dependencies.

Assembly selects one source: explicit `with_execution_ids`, otherwise the
checkpoint adapter when configured, otherwise the Fact adapter. Configure this
before executing any work. Every host writing into the same identity namespace
must retain and share its source, including hosts with different state, Fact or
checkpoint adapters. Sharing Facts while selecting unrelated allocators is not
a valid composition: use the explicit override. redb adapters for one database
share one high-water table; separately retained stores can share
`RedbStore::execution_id_source()` or another host source. Checkpoints restore
within their original namespace and cannot bind to an unrelated allocator.

Ordinary request lifecycle identity is initialized lazily, stored in the Process
snapshot and uses invocation zero. Actor admission reserves a separate scope
before directory publication; process and execution together identify its owner.
Finalization markers include that scope, avoiding stale
markers when a local ProcessId is reused. Restart admission restores an already
committed lifecycle Fact, preserving its timestamp and revocation count across
marker failures. Recovery admission uses an indexed lookup of that lifecycle
operation, independent of the process's retained history size.

## Workspace Map

| Crate | Role |
| --- | --- |
| `xolotl-core` | Host-independent `no_std` control flow, bounded storage, capability linking and channels. |
| `xolotl-types` | Core ids, paths, values, capabilities, operations, audit, trace, external access, and process data. |
| `xolotl-value-codec` | Portable event validation with selectable key workspace and optional incremental CBOR encoding. |
| `xolotl-value-object` | Explicit encoded references and incremental value reads, writes and copies through portable object ports. |
| `xolotl-graph` | Portable Rust/JSON source compiler, `DoNode`, `ExecutionGraph` and `ActorSpec` linting. |
| `xolotl-state` | Independent portable State and object capabilities, optional host composition and memory adapters. |
| `xolotl-kernel` | Portable invocation/scope/stream rules and optional hosted dispatch, scheduling, registry and recovery. |
| `xolotl-storage-redb` | redb-backed state and fact storage. |
| `xolotl-storage-fs` | Incremental immutable objects, staged uploads, atomic publication and optional file key workspaces. |
| `xolotl-standard` | Standard in-process Provider and Source implementations. |
| `xolotl-gateway` | Profiles, submission ownership, sessions, provenance, object access and output disclosure. |
| `xolotl-gateway-grpc` | Application and external Provider/Source gRPC adapters; optional structured object output. |
| `xolotl-gateway-websocket` | External Provider/Source WebSocket adapter. |
| `xolotl-gateway-mcp` | MCP server-side adapter for selected Gateway publication kinds. |
| `xolotl-proto` | Protobuf schema and vendored Rust bindings. |
| `xolotl-console` | Management actions, configuration admission and Console transport. |
| `xolotl-daemon` | `xolotld`, the long-running host process. |
| `xolotl-sdk` | Minimal embedded facade for in-process kernel use. |
| `xolotl-plan` | Plan document parsing and lowering. |
| `xolotl-sim` | Deterministic simulation and replay helpers. |

## Embedded Hosts

`xolotl-sdk` defaults to the allocator-free core. Enable `host` for the in-memory
host and portable program API. `XolotlBuilder` lets
embedded hosts provide their own state backend and fact sink before the
`Bootstrap` is seeded. The SDK `standard` feature exposes the standard package
installation API for hosts that include the standard in-process providers.
Embedders can provide their own policy sources, drivers, and host assembly.
`ExecutionConfig` belongs to the kernel, so every derived Executor inherits its
storage and work ceilings. Payloads and driver memory require separate bounds.

Execution storage and request lifecycle have separate owners. The SDK's ordinary
run helpers use `RequestProcess`; a bare Executor can be reused under host-owned
authority. `bootstrap::request` owns scope abandonment and explicit cleanup
draining, while `bootstrap::finalize` advances process finalizers and commits
lifecycle records. Progress lives in a lazily allocated process-table record,
not in a particular Future. This permits cleanup retries after task cancellation
or runtime shutdown without allocating housekeeping tasks for successful runs.
Requests, Actors and async outputs share atomic child admission. Checkpoint
restoration also rechecks the parent while inserting. Closing a tree marks all
descendants, aborts bodies and waits for their futures to drop before finalizers
start. `process::task` owns the start gate, body lifetime and exit notification.
Bodies cannot run before attachment; normal completion retains the outcome and
terminal intent before releasing body ownership. Interrupted recovered tasks
preserve unfinished checkpoints without implicitly publishing terminal markers.
`process::retention` owns process capacity and explicit leaf reaping. Capacity
counts the root, running processes, pending cleanup and terminal records. A ready
queue receives committed terminal leaves only after task and finalizer ownership
have ended. Reaping unlinks children in constant time and makes newly eligible
parents available in the same batch; it does not scan unrelated processes or run
user destructors under the table lock. Parents with independently running children
remain reachable. Table allocation can be reused after reaping.

`XolotlBuilder::with_process_capacity` selects the initial limit;
`ProcessTable::set_capacity` adjusts it across shared hosts without evicting records.
Hosts call `reap_finalized(limit)` explicitly and handle admission exhaustion.
The first actual removal closes checkpoint import into this process table, so old
executors and scopes cannot regain authority through a restored ProcessId. Import
arbitrary snapshots into a new Kernel after that point. A separate private admission
path requires ownership of a current checkpoint row and its retained lease, allowing
backlogs to advance after earlier rows are retired and reaped. Process identifiers never wrap.
Bootstrap assembly on clones of one Kernel shares a single root and its grant;
pre-request gateway audit Facts use that root with separate execution identities.
Checkpoints retire after lifecycle publication, preserving the durable process high water.
State markers, Facts and unfinished checkpoints still need independent retention;
the process limit does not bound their payloads or the host's total memory.
Fact reconciliation reads retained Facts independently of the process table, so
reaped or not-yet-restored owners do not hide uncertain external effects.

`bootstrap::actor` owns declaration checks and directory admission;
`dataplane::async_process` adapts async results. Both implement the same
`ProcessPublication` interface. The table retains their result and publication
until the lifecycle Fact, marker and terminal projection commit. This shared
record preserves the single-process or tree scope across retries. The
commit path needs only processes, handles, Facts and state; the data plane does
not hold an entire Kernel. Actor directory CAS validates process and execution
ownership. Cancelled admission can reserve a terminal entry to prevent a late
initial CAS from resurrecting running status. Async result paths include process
and execution identity, and initial status uses CAS against an absent value.

Normal completion finishes one process; independently started Actors and async
result tasks may continue. Explicit tree closure reaches all descendants even
through finished ancestors, cancelling live processes without a prior outcome.
A body or finalizer trying to await its own exit receives `ProcessBusy`; it can
request cancellation and return control to its owner.

`ActorSpec` is a declaration for a named long-lived Process. It carries a
serializable `DoNode` body, declared capabilities, budget, and finalizers.
`Bootstrap::spawn_actor_under` checks the body and finalizers
against the declared capability ceiling, derives process-attached grants from
the parent Process, writes `state://agents/<identity>/<name>`, and runs the body
with the ordinary Executor. If the body or finalizers use process-local
`StepRef`s, the host passes those step functions to
`Bootstrap::spawn_actor_under_with_steps` so they are installed before execution
starts.

Native step references carry names and arguments. Hosts assemble validated
`StepModule`s independently of process creation, combine modules with duplicate
checks, and share their immutable name tables and functions. Each process owns a
module used by its body and finalizers; derived executors borrow functions from
their module snapshot without reading a global step registry. Empty modules
allocate nothing. Standalone executors and ordinary requests accept the same
module type. Process cleanup releases its module outside the process-table lock,
while retained executors stop executing once the process is terminal.

Dynamically returned subgraphs bind structured `state://process/self/...` paths
to the invoking process in place. Request grant templates bind the corresponding
placeholder before capability attenuation, so sharing code does not share authority.

## Durable Process Boundaries

Checkpoint recovery crosses storage, execution and process lifecycles. Each rule
has one owner:

| Module | Responsibility |
| --- | --- |
| `process/checkpoint.rs` | Process snapshots, journal lifecycle states, admission and terminal-decision reconciliation |
| `process/retention.rs` | Process capacity, parent/child links and explicit reaping |
| `executor/durable.rs` | Machine snapshots, checkpoint store contracts and execution commit barriers |
| `bootstrap/durable.rs` | Decode committed lifecycle Facts and check current request authority |
| `bootstrap/durable/recovery.rs` | Advance bounded metadata pages and share recovery capacity |
| `bootstrap/durable/recovery/admission.rs` | Validate machine execution and transfer the program, journal lease and capacity into a task |
| `bootstrap/finalize.rs` | Commit lifecycle effects, then retire the checkpoint before releasing process cleanup |
| `xolotl-storage-redb/src/checkpoint.rs` | Implement exclusive leases, bounded storage reads/writes and durable retirement |

Process admission produces either `Ready` or `Cleanup(status)`. Snapshot terminal
status, saved intent, committed Fact and any retained process decision must agree
when present. An older running snapshot can continue already-chosen cleanup.
A `Finalizing` snapshot without a known outcome remains held for reconciliation.

The process table computes an admission plan without mutation, then applies it
under the same write lock. All rejection paths precede changes to process status,
cleanup progress, budgets, identities or child links. The host can preview this
plan before validating machine imports, but actual admission always recomputes
it because cancellation or task ownership may have changed. Durable process tests
live beside this implementation in `process/checkpoint/tests.rs`.

## Storage Contracts

`FactStore` requires bounded `scan(FactQuery)` and indexed `lookup(FactLookup)`
reads. The page query independently limits
returned records, examined candidates and JSON bytes. It supports forward or
reverse append order, an optional caller filter and an exclusive upper bound
captured from the same storage view as the page. `query.next_page(&page)` preserves
the filters and budgets while advancing the correct interval boundary. Empty
filtered pages can have a continuation; only `next = None` means exhaustion.
Candidate limits bound visits, not the time to examine or serialize one value.

`FactLookup` carries the operation identity, optional current-caller filter and
encoded-byte budget. The adapter locates and filters in one storage view before
copying or decoding, returning `Found`, `Missing` or `FilteredOut`. This prevents
unrelated oversized records from exhausting a scoped reader's budget while still
distinguishing lost records. `get_bounded` and `get` are unfiltered conveniences.

Completion updates an existing slot, so a fixed append interval does not freeze
outcomes. Subscriptions are invalidation hints: reread the current operation after
an event, and rescan the entire retained interval after lag. Console closes a
lagged audit subscription and requires the client to reconcile and resubscribe.
`all_facts`, `facts_of` and the single-record `get` remain explicit convenience
reads without byte limits.

Automatic reconciliation processes one page at a time and persists quarantine
entries individually. `RecoveryLimits` defaults to 256 records and 1 MiB of
encoded input per page. Oversized records and backend errors stop recovery after
any earlier quarantine writes; no evidence is silently skipped. A host needing
stable classification must quiesce writers. These read limits do not bound retained
history, quarantine storage or decoded heap size. JSON size counting uses a bounded
writer in memory and the stored byte length in redb before decoding.

Fact read responsibilities are organized by owning layer:

| Module | Responsibility |
| --- | --- |
| `xolotl-kernel/src/fact/scan.rs` | Query/page contract, adapter validation and bounded memory traversal |
| `xolotl-kernel/src/fact/lookup.rs` | Scoped point-query contract, result states and adapter-result validation |
| `xolotl-storage-redb/src/fact/read.rs` | Transactional directional reads, process indexes and bounded indexed lookup |
| `xolotl-standard/src/fact/read.rs` | Shared standard Provider input parsing and audit page projection |
| `xolotl-console/src/ws/facts.rs` | Console read policy, projections, sampled health statistics and scoped live rereads |

Console dispatch retains authorization and audit recording. The query contract
does not depend on the management protocol. Process inspection reads Facts only
for an explicitly selected process when requested, so enumeration cannot multiply
the Fact budget. Console recent/trace reads expose continuation; health labels
its aggregates as a bounded sample rather than total-history statistics.

`InMemoryBackend::with_options(InMemoryOptions)` independently selects
`read_shards`, `history` and `notification_capacity` when constructing the backend.
The default uses one inline map and allocates no shard array. Larger shard counts
allocate padded map locks; point reads then take only the matching shard lock.
Both layouts share one commit implementation. Sharded writers take the journal
lock before the value shard, and prefix reads hold the journal read lock across
all shards to capture one consistent snapshot. Writes remain serialized; large
prefix or history reads can delay them. Replaced values are destroyed after all
guards are released. Construction starts no background tasks.

`MemoryHistory::Full`, the default, retains every mutation and commits values,
provenance, timestamps and history atomically. `MemoryHistory::Disabled` skips
history storage and timestamps while preserving current values, provenance and
notifications. Historical `read_at` queries and `read_range` return `Unsupported`;
`read_at(path, 0)` still returns the current value. These are fixed construction
choices, not rolling history retention. Current values and payload sizes remain
unbounded in either mode.

Notifications follow commit order outside all locks. A full pending delivery
queue rejects matching writes before commit; slow broadcast receivers can still
lag. No subscriber means no notification allocation. Queue capacity counts
events, not bytes. `with_options` and `with_notification_capacity` return
`StateResult<InMemoryBackend>` and reject unsupported notification capacities;
shard reservation failures also return errors. These checks do not turn later
allocation failures into recoverable errors.

The redb adapter commits each merge in one write transaction. Its history clock
is durable metadata updated in that same transaction, so restart and wall-clock rollback cannot reorder newly
committed history. An existing store must contain this metadata; incomplete
schemas fail instead of reconstructing a clock from history. Values,
history and the clock all roll back on transaction failure.
Both preserve existing provenance during merge;
the trait default returns `Unsupported` when an adapter provides no atomic merge.
Notifications are not a durable event log, and redb does not guarantee their global
delivery order across concurrent writers. Read history for committed state order.

## Console Host Boundaries

Console transport policy is separate from the kernel's storage and execution
contracts. Shared `xolotl-proto/src/encode.rs` performs allocation-free Value
admission before calling the canonical converter. It bounds nodes, nesting and
inline metadata without duplicating the protobuf mapping.
`xolotl-console/src/wire/encode.rs` owns frame-field conversion, typed paths and
the exact final protobuf byte check. `ws/outbound.rs` owns send deadlines and
correlated errors when an action's result exceeds the wire budget.

`ws/subscriptions.rs` owns State and Fact tasks, cancellation, visibility deadlines,
generations, completion handling and a queue bounded by both entries and encoded
bytes. Workers prepare frames before admission and terminate if the queue is full.
Task completion is independent of queue space and invalidates that generation's
unsent tail. Dropping the owner aborts its tasks; no worker is intentionally detached.
Dispatch retains authorization and audit recording. Session reauthentication or
changed authority invalidates previous subscriptions.

These limits bound conversion work and retained encoded event bytes. They do not
bound native values already materialized by actions or broadcast backends, temporary
conversion storage, transport buffers, storage history or total RSS. The portable
core and minimal SDK do not acquire Console, protobuf or Tokio dependencies.

## Remaining Architecture Work

- State markers, Facts and unfinished checkpoints need explicit bounded retention.
  Checkpoint recovery has paged metadata, encoded read/write limits and shared
  concurrency admission; completed lifecycles delete their active rows. Process
  capacity and reaping bound entry counts, not values, state history, handles or
  driver allocations; these still require separate host limits.
- Process and child enumeration, state-prefix listing and other management
  collections still materialize their selected records. Fact paging does not
  impose result or traversal budgets on those independent APIs.
- In-memory history supports full retention or disabled historical reads. Bounded
  history with valid historical queries still needs a coverage boundary and a
  reconstruction baseline; sharded reads do not supply a retention limit.
- Native fragment allocation reuses stable ranges and coalesces adjacent free
  ranges, but cannot move live fragments. Fragmentation may still prevent a
  large allocation even when aggregate free space is sufficient.

## Standard Package Features

`xolotl-standard` contains the standard in-process Provider and Source
implementations. A binary can compile only the modules it needs, and compiled
code is separate from installed Resources.

High-risk in-process implementations such as `fetch`, `fs`, and `terminal`
must stay behind separate `xolotl-standard` features. A daemon or embedded host may
expose them only through kernel-state declarations admitted by `config.*`.

Optional in-process projection declarations are runtime state under
`state://kernel/projections/in-process/<id>`. They use generic `config.*`
Console actions, shared kernel state admission, and host-side reconciliation
into ordinary Resource, Interface, Driver, and Binding registry entries.
Reconcile results are stored under
`state://kernel/projection-status/in-process/<id>` and read through
`projection.in_process.status.*`.

For deployment-level feature choices and runtime declaration paths, use
[Configuration](configuration.md). For HTTP model-provider dialects, use
[HTTP Inference Providers](http-inference-providers.md). For embedding APIs,
use [API Reference](api-reference.md).
