# Core And Portable Programs

Xolotl separates control flow from model execution and host services. Agent,
retrieval, tool-use and workflow patterns compose ordinary programs and
capability-checked imports. The core does not contain a model inference engine.

## Layers

```text
Rust expressions / portable JSON         DoNode / Plan / protobuf
             |                                     |
      portable compiler                    ExecutionGraph lowering
             +------------------+------------------+
                                |
                 xolotl-core instruction machine
             caller-owned tasks, frames and bindings
                                |
                    requests and completions
                                |
       portable LinkedExecution OR optional Tokio host
       shared invocation, value, scope and stream contracts
                                |
           chosen I/O, scheduling and storage adapters
                                |
              models, tools, state and connectors
```

`xolotl-core` always builds with `no_std`, forbids unsafe and has no dependencies
by default. The host supplies value semantics through `Values`; scalar or
fixed-capacity values keep execution allocation-free. An allocating `Clone` or
custom host implementation is outside this guarantee.

Sequential continuations and completed parallel branches transfer owned results.
Hosts with provenance-bearing errors override `Values::influence_result` to
attach controls to both success and failure. `retain_result` obtains a control
snapshot from either branch. `retain_control`
defaults to cloning the input; shared `RuntimeValues` retains only taint and does
not render failure diagnostics for snapshots. Snapshots only influence results;
they never replace program payloads or replayed inputs. Waiting requests and
scope authorization keep full inputs. Branch fan-out, lexical bindings, original
inputs needed by conditions or cleanup, and the checkpointable
result returned by `Advance::Done` retain shared ownership with `RuntimeValues`.
Custom `Values` implementations determine their own cloning costs.

`ProgramImage` borrows instructions. `Execution` borrows task, frame and binding
arrays. `advance` takes a work quantum and returns `Request`, `Waiting`,
`Yielded`, `Cancel` or `Done`. The host drives I/O and calls
`complete(task, ticket, event, &image, &mut values)` with the matching task and
ticket. Valid responses attach their provenance before implicit continuations or
capacity errors can select another result. Stale responses do not change task
provenance. `Execution::retain_control` captures current live dependencies for a
host failure that prevents further execution. It does not collect operation or
chunk history. The core starts no threads, timers or background work.
Task stacks share one caller-owned bounded frame pool. Push, pop and reclamation
are constant-time operations. The frame slice length bounds total capacity;
`ExecutionLimits::frames_per_task` independently bounds each task's stack depth.

Minimal hosts can use `LinkedProgram` and the core `HandleTable` to validate
import ownership, generations, method rights and delegated ancestry before
dispatch. Revoking an ancestor invalidates descendants. The fixed-capacity
`Channel` returns rejected items with `Full` or `Closed`; it does not silently
discard data. Synchronization and wakeups belong to the host.

## Feature Selection

| SDK feature | Components |
| --- | --- |
| none, the default | `xolotl_sdk::core`; no allocator or runtime required |
| `serde` | Optional generic core serialization, still `no_std` |
| `program` | Shared values and portable compilation with `no_std + alloc`; no Tokio or storage |
| `runtime` | Cooperative execution, shared invocation and scope accounting, State and stream ports; `no_std + alloc` |
| `host` | Hosted values, compiler, Tokio current-thread support, in-memory state/facts |
| `multi-thread` | `host` plus Tokio multi-thread runtime support |
| `plan` | `host` plus the existing Plan frontend |
| `standard` | `host` plus standard providers |
| `durable` | `host` plus checkpoint contracts and serialization; a store is required |

Features are additive. `durable` requires neither `standard` nor gateways.
`xolotl-storage-redb/durable` supplies an independent checkpoint adapter.
Compiling components, installing resources and granting authority are separate
host actions. `Xolotl` and `XolotlBuilder` require `host`; the default SDK exposes
only the core.

## Portable Runtime

The `runtime` feature supplies `LinkedExecution` over the same core machine.
`program.compile()?.with_provenance()` consumes the compiled artifact and moves
constant payloads into `TaintedValue` and static failures into `TaintedFailure`;
both portable and Tokio execution use `RuntimeValues`. Hosted
`PreparedProgram::from_compiled` uses this same conversion.

Program inputs are `TaintedValue { value, taint }`. The machine uses
`TaintedFailure { failure, taint }` for errors, while `LinkedExecution` and hosted
Executor entry points return `ExecutionOutput { outcome, taint }`. The taint
covers the complete outcome, including success/failure selection. Catch preserves
it when turning a failure into a diagnostic value; branch selection, joins and
cleanup preserve their relevant control dependencies. Final taint does not
automatically union every streamed chunk.

`ExecutionOutput::into_result` returns `Result<TaintedValue, TaintedFailure>`;
`TaintedFailure::into_value` retains provenance when a diagnostic is passed to a
later program. `DriverOutput::into_result` follows the same rule for invocations.
Drivers must report provenance alongside data-derived values and failures.
Invocation usage and cache origin stay at the invocation boundary: a cached call
may report `CachedOutcome` while its enclosing Gateway program is a new
`CurrentAttempt`. Whole-request Gateway replay has its own `CachedOutcome`.

An embedding supplies task, frame, binding and `PendingCall` arrays, a
`LinkedProgram` and a handle table. `RequestDriver` and `Cooperate` use associated
future types, so immediate calls can use `Ready` without a box, `Send`, threads
or Tokio. A driver with a `!Unpin` future can explicitly choose `Pin<Box<F>>`.
Authorization is checked before dispatch and before each pending call is polled,
including calls suspended at a write-ahead barrier.

The trusted request adapter maps imports and context entries. External effect
drivers implement `InvocationDriver` and receive only admitted operations.
`invocation::invoke` uses the shared method contract, `Billing`, `Reservation`
and Fact builders. `Account` acquires scope access only while reserving or
settling, and holds no exclusive scope borrow across an I/O wait. Tree adapters
reserve the caller and ancestors atomically and roll back only their own failed
admission. `NoFacts` rejects required recording before dispatch.

To cancel, the embedding first closes `Scope` admission, then calls
`LinkedExecution::cancel` and keeps polling cleanup. Driver futures are dropped
before cancellation completion and `Finally`. Drop releases resources but cannot
finish asynchronous cleanup. Identity changes, waits and device I/O require
explicit host adapters; the example uses a fixed identity and rejects unsupported
context changes. Durable recovery and dynamic module loading use the optional
hosted adapter.

The same example library executes `no_std + alloc` code on a desktop host and
compiles for Cortex-M:

```sh
cargo run --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo test --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo check --manifest-path examples/portable-runtime/Cargo.toml --no-default-features --target thumbv7em-none-eabi --lib --locked
```

It runs equivalent Rust and JSON programs, joins scalar and string results,
settles scope usage and releases handles. A board still supplies its entry point,
allocator, interrupts and I/O. Target compilation does not measure hardware
latency or the complete runtime's memory footprint.

## One Portable Language

Rust `Program` / `Expression` and `Program::from_json` use the same source model
and compiler. JSON is versioned and rejects unknown fields. Composition includes
input, constants, lexical `Let` / `Use`, sequences, conditionals, bounded loops,
recursive calls, parallel joins, races, catch/finally, waits and acting scopes.
Higher-level behavior should compose these or add host operations.

```rust,ignore
use xolotl_sdk::{Expression as E, Program, Transform};

let source = Program::new(E::literal(3).then(E::Transform {
    operation: Transform::Add { value: 4 },
}));
let compiled = source.compile()?;
```

Equivalent JSON:

```json
{"version":1,"body":{"kind":"sequence","steps":[{"kind":"literal","value":3},{"kind":"transform","operation":{"op":"add","value":4}}]}}
```

`Literal` uses plain JSON. `Constant` and operation `literal_input` use tagged
values preserving bytes, blobs, tensors, frames, stream markers and exact float
bits. Ordinary maps remain maps, including those with a `type` key. Program
identity covers canonical source, compiler version and instruction version;
it identifies an artifact, not its permission to run.

Prepare once with `PreparedProgram::new`, then call `Xolotl::run_prepared` with
identity, resource allowlist and a `TaintedValue` input. SDK execution helpers
return `Result<ExecutionOutput, XolotlError>`; keep the output's taint when composing
another request. Each call receives an attenuated request
process. Instructions are borrowed; mutable execution storage is independent.
Cloning `PreparedProgram` shares instructions, constants and cached resource
analysis through a reference count.
Repeated runs can supply `ExecutionBuffers` to `run_prepared_with_buffers` or
`Executor::eval_prepared_with_buffers`; graphs also have `eval_graph_with_buffers`.
`reserve_for` allocates capacity ahead of time, `retained_bytes` reports retained
capacity, and `release` returns it to the allocator. Each concurrent execution
exclusively borrows its buffers. Success, failure and dropping the Future release
all values in them. Buffer reuse does not cover payload, I/O future or process
record allocations, and dropping a Future cannot run asynchronous `Finally`.
`run_program` prepares per call. Run the complete Rust/JSON composition example:

```sh
cargo run -p xolotl-sdk --features host --example portable
```

The protobuf `PortableProgram` envelope transports bounded JSON plus identity
through checked conversions. It adds neither execution authority nor an
unrestricted gateway endpoint. Native `StepRef` closures remain part of the
hosted graph frontend; they cannot be serialized as portable functions.

Portable source can explicitly load a continuation with
`Expression::Module { module: StepRef::new("increment") }`, encoded as
`{"kind":"module","module":{"name":"increment"}}`. Bind it with
`StepModule::program(name, revision, loader)` or `StepBinding::program` and combine it with
native functions through `StepModule::compose`. `ProgramLoader` receives borrowed
input and an optional argument and returns a `PreparedProgram`. Loaders are
synchronous and effect-free; obtain external source through an Operation first.
`LoaderRevision::from_bytes([u8; 32])` identifies the loader implementation and its
captured configuration. The host must change it when either changes; it is separate
from the identity of each returned program. Recovery compares this host declaration
and cannot detect implementation changes that reuse the same declared revision.
The kernel retains the loader, not every returned image. Source positions stay
module-local; execution tickets keep repeated calls distinct. Run the mixed
native/portable example with:

```sh
cargo run -p xolotl-sdk --features host --example native_modules
```

## Resource And Cancellation Bounds

Core storage never grows. Capacity exhaustion returns a fault. Loop iterations,
optional cumulative transitions and cleanup transitions have separate limits.
`CompileLimits` defaults to expression nesting 128, 65,536 instructions and
1 MiB source bytes for one module. `compile_with_limits` and
`from_json_with_limits` accept explicit host admission settings. Larger accepted
sources produce the same image regardless of the selected limits. JSON decoding
has its own recursion bound, and instruction addresses remain `u32`.

Hosted `ExecutionConfig` defaults to 65 task slots, a depth of 256 per task, 1,024 shared frames, 1,024
bindings per task, 65,536 instructions, 16 MiB of shallow execution storage,
4,096 cleanup transitions and a 256-transition scheduling quantum. `max_steps`
defaults to `None`; hosts can set `Some(quota)` independently of that quantum.
Exhausting a quantum yields, without cancelling a long-running task. Static programs use smaller derived layouts; recursive
programs use configured ceilings where a static estimate is insufficient.
The shared pool is bounded by `max_frames`, independently of task count times
per-task depth.
A fork retains its suspended parent and consumes two child slots.

Native Step and portable module imports start with the current image's derived layout. After an import
produces a subprogram, the host analyzes it and combines the original image's
bounds with those of still-active native invocations. Completed invocations no
longer contribute, so 64 sequential scalar Steps need only one task and one
continuation frame. The estimates are conservative; all configured task, frame,
binding, instruction and byte ceilings continue to apply.

The host grows containers only when necessary. It reserves replacement capacity
before moving live values, keeping pending I/O and tickets intact. The byte budget
includes both existing and replacement containers during this handoff. A rejected
expansion or failed reservation rolls back its image changes and follows ordinary
error recovery. Empty capacity can be retained for later runs through
`ExecutionBuffers`.

Loaded subprograms are lowered and analyzed independently, then linked into
reusable instruction, import and binding ranges. At host boundaries the executor
uses active continuation frames to find retired fragments, releases their
constants and imports, and clears their binding values across all task rows.
Live addresses stay fixed, including nested calls and concurrent waits. Adjacent
free ranges coalesce; a completed earlier fragment can be reused while a later
one is still waiting. A 64-call sequence with one local variable needs only one
binding slot and space for the original graph plus one two-instruction fragment.

Free container capacity is retained until execution ends. Variable-sized live
fragments can leave gaps too small for a new fragment, so the configured limits
bound the address range including holes, not only the sum of live instructions.
There is no moving compactor. Source positions remain module-local; invocation
tickets distinguish repeated calls independently of reused addresses. Ticket
exhaustion returns an error instead of reusing a recorded identity. There is no
cumulative source-position limit on module loading. Compilation scratch, code containers and value
payloads remain outside `max_storage_bytes`.

The core itself never grows storage. `Execution::suspend` releases its borrows and
returns metadata; a host may grow its arrays and remap binding rows, then call
`Execution::resume` to validate and resume them without cloning values. This is
an in-memory handoff, not a durable commit or redispatch. `continuation_entries`
reports active host-supplied subprograms without allocation.
`clear_bindings` releases a host-selected retired binding range without cloning
values; the host must first prove that no live code or scope still references it.

`ProgramImage::resource_requirements` analyzes reachable control flow in the core,
using one caller-owned `AnalysisSlot` per instruction. Time and scratch space are
linear; analysis uses neither recursive native calls nor heap allocation.
Sequences and exclusive branches share capacities. Concurrent branches add task
usage, while child stacks are independent of their suspended parent's stack.
Nonrecursive calls have static bounds. A dimension with no established finite
bound returns `None` and requires a host-selected capacity. Analysis covers the
current image, excluding native expansions returned by the host.

The compiler reuses bindings after lexical scopes end, preserving restoration
across calls, failures and concurrent branches. Hosted preparation caches the
analysis; `PreparedProgram::layout(&config)` reports task count, total frames,
per-task depth, binding count and container bytes before execution. A sequence of 2,048 single-variable
scopes needs one binding slot; 64 sequential binary forks need three task slots;
flat input or transform chains need no continuation frames.
If only one of two branches needs 64 frames, the parent and its two children
share 64 frames instead of reserving a stack of that size for every task.
Retained buffer capacity also obeys the current byte budget. Empty buffers release
old allocations before replacement when necessary. Growing live buffers also
accounts for the temporarily overlapping containers described above.

Checkpoint recovery keeps the saved layout and checks it against every current
host capacity and the byte ceiling. Raising ceilings does not force a restored
execution to change layout; lowering them below its saved layout rejects recovery.
Core checkpoints use the independent `CHECKPOINT_VERSION = 1`, validating
stack ownership, native subprogram entries, free links, counts and unused slots on restore.
Unknown checkpoint formats are rejected; instruction and checkpoint versions evolve separately.

The byte ceiling counts task/frame/binding containers, excluding value payloads,
compiled images, driver buffers, Fact retention and process history. Hosts needing
a total memory cap must bound those separately. Transition limits do not preempt
synchronous drivers or native Steps; isolate blocking work and set operation
deadlines in the host.

`cancel_process` wakes waiting execution. The host drops cancelled request futures
before acknowledging completion, releases reserved concurrency capacity and
retains uncertain spending. `Finally` runs with a separate transition budget,
receives the body's original input and preserves a body failure. A cleanup failure
replaces a successful body result; otherwise the body value is returned. The
selected result retains both body and cleanup control dependencies. Race returns
the first result after cancelling and cleaning up the loser.

`Executor::with_deadline(tokio::time::Instant)` supplies an absolute monotonic
deadline. The host checks it while advancing and waiting for I/O; expiry returns
`Failure::Timeout` with the machine's currently live provenance and drops pending
calls. This is a hard stop and cannot continue lexical `Finally` bodies. The
request owner must still finish the process and its process finalizers.
Synchronous drivers and native Steps remain non-preemptible.

Dropping a bare Executor future releases execution storage but does not own the
Process lifecycle. `Bootstrap::request_under` returns a `RequestProcess` with
explicit ownership: call `executor` to run work, then `finish(&output)` with the
complete `ExecutionOutput`. Process finalization retains the provenance of the
body's terminal status as well as its own finalizer results.
For independently owned tasks, `Arc<Bootstrap>::request_under_owned` keeps the
host alive through the same `RequestProcess` without cloning its internal fields.
Gateway requests retain this owner from creation through receipt admission,
execution and finalization; accepted input streams carry it across calls.
SDK graph runs and ordinary prepared runs use this scope automatically. Dropping
an unfinished scope closes its request tree, cancels execution, aborts attached
tasks and revokes existing handles immediately. On Tokio it schedules one
asynchronous process cleanup attempt; successful requests spawn no cleanup task.
`Bootstrap::drain_cleanup` / `Xolotl::drain_cleanup` await pending cleanup, including
work left by a runtime shutdown or backend failure. They report failed trees
for a later retry without an unbounded retry loop.

Normal completion finishes only the specified process. Independently started
Actors and async result tasks may continue; explicit tree finalization reaches
them even through a finished ancestor. Forced closure cancels live processes
without a prior terminal intent and waits for managed body futures to drop.
Self-joining bodies or finalizers receive `ProcessBusy` instead of waiting on
their own execution. Actor directories and async outcomes use retained terminal
publications, so backend failures do not discard results or complete cleanup early.

Process finalizers are separate from a program's lexical `Finally`. Unstarted
process finalizers survive interrupted cleanup. Attempted finalizers are not
replayed automatically; interruption is recorded because external effects may
be incomplete. Lifecycle retries retain the original record, including its
timestamp, terminal intent and revoked-handle count. Completion releases modules,
attached grants and finalizer storage outside the process table lock.

Dropping the execution future, aborting a Tokio task, process exit and
`finalize_process` cannot continue the program's asynchronous `Finally` bodies.
For graceful shutdown, cancel, await the executor, then finish the request.
Process cleanup I/O still needs host deadlines. Terminal process entries, state
markers and Facts are retained; cleanup does not establish a total memory bound
or automatically reap process history.

Hosted process storage has an independent opt-in capacity:

```rust,ignore
use std::num::NonZeroUsize;
use xolotl_sdk::{DoNode, IdentityRef, Value, XolotlBuilder};

let host = XolotlBuilder::new()
    .with_process_capacity(NonZeroUsize::new(64).ok_or("invalid capacity")?)
    .build_bootstrap();
let request = host.request_under(host.root, IdentityRef::ROOT, &[])?;
let output = request.executor().eval(&DoNode::pure(Value::null())).await;
request.finish(&output).await?;
let reaped = host.kernel.processes.reap_finalized(16);
```

The root consumes one entry. Admission fails at capacity, including when terminal
records or failed cleanup occupy the slots; there is no implicit eviction. Only
committed terminal leaves whose task and finalizer owners have exited are eligible.
An ancestor stays retained while it has any children. A batch may reclaim newly
eligible parents, up to the requested limit. Shared tables accept `set_capacity`
updates, but reject limits smaller than their current length. Table allocations
are kept for reuse; the count ceiling is not a byte or RSS limit. Reaping removes
neither Facts nor state markers, async outputs or checkpoints. Those stores need
separate retention and payload budgets.

Process IDs remain monotonic and fail on exhaustion. The first actual reap closes
checkpoint import into this table, avoiding reuse of an old scope through a
retained Executor or request. This restriction still applies to arbitrary snapshot
imports. `checkpoint_recovery()` loads current active rows under retained exclusive
leases and can continue in the same Kernel after earlier processes are reaped.
An empty reap or a zero batch does not close arbitrary snapshot import.

## Bounded Fact Reads

Automatic reconciliation no longer materializes retained Fact history. The host
can choose a smaller read budget independently of execution and process capacity:

```rust,ignore
use std::num::NonZeroUsize;
use xolotl_sdk::RecoveryLimits;

let report = host.recover_all_with_limits(RecoveryLimits {
    page_limit: NonZeroUsize::new(32).ok_or("invalid record budget")?,
    max_encoded_bytes: NonZeroUsize::new(64 * 1024).ok_or("invalid byte budget")?,
}).await?;
```

The default is 256 records and 1 MiB of JSON-encoded input per page. Quarantine
entries are persisted individually, pages are released before the next read, and
recovery yields between pages. Errors propagate after any earlier quarantine
writes. An individual record exceeding the byte budget requires an explicit
larger budget; it is never truncated or skipped.

Custom storage adapters implement `FactStore::scan(FactQuery)` and indexed
`lookup(FactLookup)`. Point reads filter the current caller and check bytes in one
storage view, distinguishing a missing operation from a nonmatching caller.
`get_bounded` is an unfiltered, byte-bounded convenience. Page queries select forward or reverse append
order and independent record, candidate-examination and encoded-byte budgets.
`FactQuery::new` defaults to forward order and a candidate budget equal to the
record limit. Memory charges unrelated caller slots against that candidate budget;
an indexed backend can avoid visiting them. An empty filtered page can still have
a continuation. The budget bounds candidate visits, not per-value processing time.

Diagnostic callers can use `FactSink::scan`, process filters and
`classify_recovery` on each page. Continue with `query.next_page(&page)` until
it returns `None`; this preserves all filters and budgets in either direction.
Each page's `end` is its captured upper bound, which shrinks for reverse pages.
Pagination excludes later appends but does not freeze outcomes updated in existing
slots. Quiesce writers for a stable recovery result; after subscription lag,
rescan old slots as well as new appends.

Byte limits charge stored JSON for redb and current JSON serialization for memory.
They do not measure decoded heap size, quarantine output, backend caches or total
RSS. `get`, `all_facts`, `facts_of` and `recover_process` remain explicit unbounded
convenience reads. Fact retention and checkpoint directory scans are separate concerns.
Completed Facts cannot be automatically evicted while unfinished checkpoints may
still depend on them to reconcile external effects or lifecycle completion.

## Optional Durability

Set `Program::durable = true` and install a `CheckpointStore` through Kernel or
the SDK builder. Unsupported hosts reject admission. An exclusive journal lease
atomically persists image, tasks, frames, bindings, execution scope, pending invocation
tickets, lifecycle scope, authority and budget at dispatch/completion boundaries.
redb uses immediate durability. Fact classification provides diagnostics;
execution restoration requires a full machine checkpoint.

`OperationId` has five components. The first-release Fact and hosted journal
formats preserve complete Values and provenance, including failures held by
cleanup or recovery frames. Each checkpoint shares one node table across its
constants, tasks, frames, imports and bindings. Unknown formats are rejected;
absent taint is not pristine, and missing scopes are not inferred from history. Custom Fact and
checkpoint adapters implement `ExecutionIdSource` as well as their storage trait.
Use `with_execution_ids` to retain one source independently of both adapters;
the source must outlive every retained checkpoint or externally visible identity.
See [Execution Identity](architecture.md#execution-identity) for assembly constraints.

Completed effects are not repeated after interruption. Pending requests resume
only under their replay contract. Pending non-idempotent effects or changed
replay classifications are quarantined for reconciliation. Checkpoints do not
guarantee exactly-once execution against arbitrary external services.

Durable programs can load portable modules. A checkpoint stores their exact code,
module identities, relocated node/import/binding ranges and active continuations.
Recovery rebuilds allocator gaps and analysis from validated module ranges, using
scratch proportional to the largest module. It resumes the stored linked image,
including when the caller supplies the original root preparation. Retired modules
release their imports and values; load count is not a cumulative storage limit.

Durable admission freezes loader names and revisions in the retained imports.
Loader arguments and pending inputs share the checkpoint's value table. Closures
are supplied by the host: reattach them with `Executor::with_steps` for direct
recovery, or `checkpoint_recovery()?.with_steps(module)` for automatic recovery.
`ExecutionSnapshot::loader_dependencies()` exposes the required declarations.
Missing or changed bindings hold the existing journal before invoking a loader.
A load interrupted before its code and continuation commit may run again with the
same input and argument. After that commit the stored code resumes without calling
its loader again. A module requiring durability needs a durable caller. Native
Steps remain available to volatile programs and are rejected by durable admission.

Idempotency caching reuses completed results;
concurrent retries still rely on the method's declared idempotency. Cache failure
cannot replace a known driver result. Reaching an explicit `Collect` limit while
the driver is pending cancels collection, leaves its Fact pending and retains
uncertain spending; it does not publish a completed cache entry.

Recovery spending includes estimates for pending calls. An uncertain call may
be overcounted when a prior reservation cannot be reconciled; it is never
automatically refunded solely because the execution future disappeared.

Startup restoration supports root-owned request processes with attached grants
and no native finalizers or actor directory. Admission rejects other contexts
and detached `AsyncProcess` / raw `Stream` results; use unary, bounded collect
or sink-only results. Restoration rechecks constraints, rights and expiry.
Missing provider imports leave checkpoints held for a later recovery call.

Call `reserve_checkpoint_process_ids` before spawning application work. It reserves
the persisted process high water without decoding programs. After installing
authority and providers, create an `Arc<Bootstrap>::checkpoint_recovery()` session
and call `advance()` from the host's background loop. `resume_checkpointed_processes`
performs one bounded advance. A `complete` report means the captured key range was
examined, independently of task completion. The daemon advances recovery in the
background, so programs waiting for external signals do not block gateway startup.

`DurableRecoveryConfig` defaults to 64 metadata entries per page, 16 in-flight
recoveries per Kernel and `reap_batch = 0`. Sessions share the concurrency budget.
Capacity and an exclusive lease are acquired before loading a record; the same
lease transfers into execution and remains owned through lifecycle cleanup.
Capacity exhaustion reports `deferred` and retains the current cursor. Bounded
hosts can explicitly select `reap_batch` or run their own process retention policy.
Quarantined low-numbered records remain on disk for a new sweep after repair;
recovery does not retain a growing in-memory set of skipped identifiers.

`ExecutionConfig::max_checkpoint_bytes` defaults to 64 MiB for both bounded
serialization and encoded length checks before decoding. `scan(CheckpointQuery)`
reads keys and encoded sizes only. Loads recheck the size and canonical owner.
Before process admission, recovery borrows the checkpoint to validate core layout,
terminal state and pending tickets. Encoded bytes are not a decoded heap budget;
payload objects, interpreter storage and drivers retain their own memory costs.
`CheckpointStore::snapshots()` remains an explicit exhaustive inspection API;
recovery never calls it.

Lifecycle completion commits the Fact, terminal marker and result publication,
then retires the checkpoint before making the process reapable. Failures retain
cleanup state for retry. Retirement deletes the active row but permanently keeps
the process high water and rejects further commits on the same lease. A valid
committed lifecycle Fact permits cleanup without the original providers, including
explicit cancellation of an unfinished machine. Cleanup never replays pending
effects. An imported snapshot cannot start a fresh execution when its journal is
missing, and a retained executor cannot recreate a retired program.
Checkpoints also retain the chosen `terminal_intent`. A retained `Finalizing` row
needs an explicit outcome from that intent, a committed lifecycle Fact or a
retained process decision. With none available it is held for reconciliation;
recovery does not guess whether it should complete, fail or cancel.

One live host currently owns each process identifier namespace and must reserve
its high water before application admission. Per-process leases do not coordinate
fresh `ProcessId` allocation across independent Kernels; multiple hosts require
an additional process identity protocol. A session freezes a key range, not row
revisions. Overwrites may yield newer payloads, and late insertions below its
cursor appear in the next sweep.

Durable SDK execution transfers
request ownership to recovery with `RequestProcess::detach`. Dropping its Future
releases the journal lease and retains unfinished checkpoints without queuing
request cancellation. A host using `detach` must eventually finish the Process;
recovery from a checkpoint is explicit. Unfinished and quarantined checkpoints,
Facts and state history still need host retention policies. Recovery of actor
trees or external stream sessions is not implemented.

## Verification And Measurement

```sh
cargo check -p xolotl-sdk --no-default-features --target thumbv7em-none-eabi --lib
cargo check -p xolotl-sdk --features serde --target thumbv7em-none-eabi --lib
cargo tree -p xolotl-sdk --no-default-features --edges normal
cargo run -p xolotl-core --release --example core_footprint
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- kernel/prepared
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- process_reaping
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- kernel/payload
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- kernel/native
```

Install the Cortex-M target through rustup before target checks. The `core_footprint`
example measures scalar storage and 1,000-operation batch means including
admission/reset; its p99 is a percentile of batch means, not request tail latency.
The prepared benchmark includes host execution allocation and scheduler entry,
excluding compilation, request-process creation, I/O and inference. Compare
measurements only for the same workload, features, build and hardware.

The `benchmarks/runtime` package measures control, resident values, portable
and hosted execution, stream cancellation, file objects, State/Fact restoration
and provider parsing. Its runner separates timing from heap instrumentation,
checks outputs and resource release, and scales cumulative work with a fixed
active window. Run from the repository root:

```sh
python3 benchmarks/runtime/measure.py build --output target/runtime-measurements
python3 benchmarks/runtime/measure.py smoke time heap scaling --output target/runtime-measurements
```

See `benchmarks/runtime/README.md` for workload parameters, environment recording
and measurement scope. Heap reports count allocations after fixtures and warmup;
they do not measure process RSS or device memory. Timing reports describe complete
workloads, including validation and owner release.
