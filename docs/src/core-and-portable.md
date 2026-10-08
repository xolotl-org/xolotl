# Core And Portable Programs

Xolotl separates control flow from model execution and host services. Agent, retrieval, tool-use and workflow patterns compose ordinary programs and capability-checked imports. The core does not contain a model inference engine.

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
      portable LinkedExecution OR optional hosted execution
       shared invocation, value, scope and stream contracts
                                |
           chosen I/O, scheduling and storage adapters
                                |
              models, tools, state and connectors
```

`xolotl-core` always builds with `no_std`, forbids unsafe and has no dependencies by default. The host supplies value semantics through `Values`; scalar or fixed-capacity values keep execution allocation-free. An allocating `Clone` or custom host implementation is outside this guarantee.

Sequential continuations and completed parallel branches transfer owned results. Hosts with provenance-bearing errors override `Values::influence_result` to attach controls to both success and failure. `retain_result` obtains a control snapshot from either branch. `retain_control` defaults to cloning the input; shared `RuntimeValues` retains only taint and does not render failure diagnostics for snapshots. Snapshots only influence results; they never replace program payloads or replayed inputs. Waiting requests and scope authorization keep full inputs. Branch fan-out, lexical bindings, original inputs needed by conditions or cleanup, and the result returned by `Advance::Done` retain shared ownership with `RuntimeValues`. Custom `Values` implementations determine their own cloning costs.

`ProgramImage` borrows instructions. `Execution` borrows task, frame and binding arrays. `advance` takes a work quantum and returns `Request`, `Waiting`, `Yielded`, `Cancel` or `Done`. The host drives I/O and calls `complete(task, ticket, event, &image, &mut values)` with the matching task and ticket. Valid responses attach their provenance before implicit continuations or capacity errors can select another result. Stale responses do not change task provenance. `Execution::retain_control` captures current live dependencies for a host failure that prevents further execution. It does not collect operation or chunk history. The core starts no threads, timers or background work. Task stacks share one caller-owned bounded frame pool. Push, pop and reclamation are constant-time operations. The frame slice length bounds total capacity; `ExecutionLimits::frames_per_task` independently bounds each task's stack depth.

Minimal hosts can use `LinkedProgram` and the core `HandleTable` to validate import ownership, generations, method rights and delegated ancestry before dispatch. Revoking an ancestor invalidates descendants. The fixed-capacity `Channel` returns rejected items with `Full` or `Closed`; it does not silently discard data. Synchronization and wakeups belong to the host.

## Feature Selection

| SDK feature | Components |
| --- | --- |
| none, the default | `xolotl_sdk::core`; no allocator or runtime required |
| `serde` | Optional generic core serialization, still `no_std` |
| `program` | Shared values and portable compilation with `no_std + alloc`; no Tokio or storage |
| `runtime` | Cooperative execution, shared invocation and scope accounting, State and stream ports; `no_std + alloc` |
| `host` | Hosted values, compiler, configurable clock/task spawner, default Tokio adapter, host-selected State and optional Fact observation |
| `memory` | Optional in-memory State adapter and `in_memory` constructors |
| `multi-thread` | `host` plus Tokio multi-thread runtime support |
| `plan` | `host` plus the existing Plan frontend |
| `standard` | `host` plus standard providers |

Features are additive. Compiling components, installing resources and granting authority are separate host actions. `Xolotl` and `KernelBuilder` require `host`; the default SDK exposes only the core. `KernelBuilder::new(state)` and `Xolotl::new(state)` require a selected State backend; ordinary request cleanup needs no State write capability. Actor directory and asynchronous-result publication require their selected business write ports. Enable `memory` for `in_memory` constructors. `KernelBuilder::with_host_runtime` installs a `HostRuntime` with host-defined `HostClock`, `TaskSpawner`, and `BlockingSpawner`; the default uses Tokio.

Hosted method installation requires an explicit `MethodAuthority` in `MethodSpec`. Authority, purity and output support are separate contracts. Registry interface descriptors are immutable: install a new interface id and relink a resource to change its contract. Admission checks each method authority, unique method names/ids and a maximum of 64 methods across the resource's interfaces. Callable method authority is independent of the Resource scheme. `ResourceDescriptor.addressing` explicitly selects exact or prefix resolution; `Bootstrap::register_resource` lets embedded hosts install either form and choose the descriptive kind. A pure method that reads external state must use `MethodSpec::observes_external()`. Open requests and Handles number method bits in that combined order; method ids are dispatch keys and may be reused across resources. Source Grants select stable method names instead of retaining these positions. Opening a handle resolves every requested bit to its method name and declared capability verb; the verb check still applies to a source Grant that explicitly selects `all`. An Executor keeps the binding/interface contract used when resolving each method. Existing handles keep their frozen plans; reopening against a changed contract fails and requires a new execution. Handle-plan compilation also checks a registry revision before publishing, so concurrent configuration changes cannot restore a stale cache entry. Graph `lint` and `lint_actor` accept a host contract resolver and report unresolved methods instead of inferring permissions from names.

## Portable Runtime

The `runtime` feature supplies `LinkedExecution` over the same core machine. `program.compile()?.with_provenance()` consumes the compiled artifact and moves constant payloads into `TaintedValue` and static failures into `TaintedFailure`; both portable and Tokio execution use `RuntimeValues`. Hosted `PreparedProgram::from_compiled` uses this same conversion.

Program inputs are `TaintedValue { value, taint }`. The machine uses `TaintedFailure { failure, taint }` for errors, while `LinkedExecution` and hosted Executor entry points return `ExecutionOutput { outcome, taint, unresolved_operations }`. The taint covers the complete outcome, including success/failure selection. Catch preserves it when turning a failure into a diagnostic value; branch selection, joins and cleanup preserve their relevant control dependencies. Final taint does not automatically union every streamed chunk. `unresolved_operations` is separate from the program outcome: hosted execution records uncertain effects even if `Race` selects a successful branch or `Catch` handles an `OutcomeUnknown` failure. Portable `RequestDriver::collect_evidence` is a mandatory synchronous trusted hook. `LinkedExecution` borrows a caller-owned `UnresolvedOperations`, collects before consuming completions or dropping calls, and moves evidence into normal output; dropping execution leaves evidence with the caller. Pure adapters explicitly do nothing. Only real host-classified identities and dispatch stages count, not remote error text.

`ExecutionOutput::into_parts()` returns both `Result<TaintedValue, TaintedFailure>` and `UnresolvedOperations`; callers composing a second execution boundary must carry both. `TaintedFailure::into_value` retains provenance when a diagnostic is passed to a later program. `DriverOutput::into_result` preserves provenance for one invocation. Drivers must report provenance alongside data-derived values and failures. Invocation usage and cache origin stay at the invocation boundary: a cached call may report `CachedOutcome` while its enclosing Gateway program is a new `CurrentAttempt`. Whole-request Gateway replay has its own `CachedOutcome`.

An embedding supplies task, frame, binding and `PendingCall` arrays, a `LinkedProgram` and a handle table. `RequestDriver` and `Cooperate` use associated future types, so immediate calls can use `Ready` without a box, `Send`, threads or Tokio. A driver with a `!Unpin` future can explicitly choose `Pin<Box<F>>`. Authorization is checked before dispatch and before each pending call is polled, including calls suspended at a write-ahead barrier.

The trusted request adapter maps imports and context entries. External effect drivers implement `InvocationDriver` and receive only admitted operations. `invocation::invoke` uses the shared method contract, `Billing`, `Reservation` and Fact builders. `Account` acquires scope access only while reserving or settling, and holds no exclusive scope borrow across an I/O wait. Tree adapters reserve the caller and ancestors atomically and roll back only their own failed admission. `AccountRequest` exposes the full admitted `OperationId` and trusted `CallContext`, so receipt identities distinguish executions, repeated calls and explicit retries. `NoFacts` rejects required recording before dispatch.

`Account::reserve` is a short synchronous admission step. A permit's `Commit` future can await external storage without borrowing a scope across I/O. No `Send` bound or boxing is required; memory adapters return `Ready`. A commit owns its transaction state and cannot borrow the permit or temporary completion view. An asynchronous adapter encodes or retains its required data before returning the future. Hosted process accounts reserve and settle within the live runtime.

`AccountPermit` owns three explicit transitions. `dispatch` confirms the account's reservation before the driver future is constructed; the future must succeed before the driver can start. Failure prevents the effect. Fact observation is selected separately from account admission.

`settle` receives an `AccountCompletion` that binds the full `OperationId`, reserved and actual charges, and the final `DriverOutput`. It borrows the output without requiring a clone, allocation or storage-specific driver result. External account adapters can persist that result and affected account changes in their own transaction. The reservation stays owned while settlement waits.

The result contains the delivered outcome, source order, usage (including custom units and explicit zero), and completion origin. Billing uses the original result before projection; the completion presented to storage already applies `SinkOnly`, so its discarded response payload is not retained by the accounting port. `SinkOnly` preserves success/failure and short-circuit semantics on both hosted and portable invocation paths.

`settle` can fail after execution; `InvocationResult` preserves the real outcome, taint, usage and cache origin alongside `CompletionError::Settlement`. An explicitly selected Fact write can fail separately with `CompletionError::Fact`. Neither error proves the effect was rolled back or authorizes retry. Billing precedes `SinkOnly` payload removal.

`abandon` provides bounded synchronous cleanup when an invocation is dropped or a commit fails. Cancellation before dispatch refunds the reservation; cancellation after dispatch retains the estimate. Failed or cancelled settlement retains the greater of estimated and reported usage in each dimension. Cleanup releases concurrency. External account adapters own uncertain commits and balance reconciliation; losing a local future does not prove a refund. Driver and commit futures drop before abandonment, and successful settlement is never followed by abandonment. Portable memory permits declare `Error = Infallible`; fallible adapters expose errors convertible to `Failure`. Accounts, application data and external effects have separate commit domains.

Hosted `DataPlane::execute` and `execute_with_stream` return the same `InvocationResult`. Unconfirmed external effects retain their original operation identity for application reconciliation; cancellation or a lost local result does not prove the effect never happened. Optional Facts provide observation, not authority, account settlement or program recovery.

The streaming invocation owns its terminal until the sink accepts it. Cancelling before a conclusion is acquired can publish cancellation; cancelling while terminal delivery waits, or rejecting that delivery, preserves the acquired terminal status, provenance and completion origin through synchronous closure. A closed receiver or an already accepted terminal does not guarantee another delivery. Delivery errors remain separate from the real invocation outcome, and unconfirmed required settlement still follows its own uncertainty contract. This handoff retains one terminal, not historical chunks or restart state.

An optional Fact failure cannot mask a required stream-delivery failure: `completion_error` reports the required boundary error and the optional observation failure goes to diagnostics. An earlier required settlement or uncertain dispatch error remains primary. The actual Driver output is unchanged.

The portable `RequestDriver` returns `RequestCompletion`. `Ok(HostEvent)` advances the machine, including ordinary failures that `Catch` may handle. `Err(TaintedFailure)` interrupts the whole run, releases pending futures and retains control provenance; it acknowledges no request and runs no further `Catch` or `Finally` effects. The embedding owns subsequent reconciliation and lifecycle cleanup. Invocation adapters use `InvocationCall::operation()` to identify an unconfirmed required settlement or output handoff, and map that error to the interruption branch. Optional Fact failure preserves a known Driver result; definite pre-dispatch rejection remains its actual failure. The portable example follows these rules even though its memory account commits are infallible.

To cancel, the embedding first closes `Scope` admission, then calls `LinkedExecution::cancel` and keeps polling cleanup. Driver futures are dropped before cancellation completion and `Finally`. Drop releases resources but cannot finish asynchronous cleanup. Identity changes, waits and device I/O require explicit host adapters; the example uses a fixed identity and rejects unsupported context changes. Dynamic module loading uses the hosted adapter.

The same example library executes `no_std + alloc` code on a desktop host and compiles for Cortex-M:

```sh
cargo run --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo test --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo check --manifest-path examples/portable-runtime/Cargo.toml --no-default-features --target thumbv7em-none-eabi --lib --locked
```

It runs equivalent Rust and JSON programs, joins scalar and string results, settles scope usage and releases handles. A board still supplies its entry point, allocator, interrupts and I/O. Target compilation does not measure hardware latency or the complete runtime's memory footprint.

## One Portable Language

Native `DoNode` compilation preflights node count and the source-position namespace before allocating graph storage or cloning payloads, then lowers with explicit frames. Actor body/finalizer binding also preflights before cloning and uses explicit stacks for cloning and path binding. Nesting has no separate recursion-only 256-level cap; finite graph capacity still applies, and execution frame limits are independent of compilation. Deterministic source positions and lexical binding restoration remain part of the graph contract.

Portable structural admission counts a conservative compact-encoding lower bound before lowering. Each distinct resident value node is inspected once per embedded value, while every List/Map reference edge is charged before collection descent. Strings, bytes, map keys, Blob hashes/media types, Tensor dimensions, Frame blob metadata and StreamEnd error text contribute; referenced object contents are not fetched or charged as inline source. Hosts accepting Rust-built programs must separately measure exact compact encoded size. Every emitted instruction, including control wrappers and an empty sequence's synthetic Input, reserves capacity before constant conversion, payload copying or import registration. Rejection returns no partial image or uncharged import.

Borrowed Plan compilation remains borrowed. `PlanCompileLimits` defaults to 1 MiB of compact source encoding, 65,536 lowered nodes and depth 128; explicit limits apply before materialization, using iterative validation, lowering and JSON literal conversion. Output admission includes synthetic sequence, binding and bracket nodes, not just source steps. Unbound sequence segments are balanced without reordering stages: modifiers still wrap the whole preceding segment, lexical bindings retain their scope, successful outputs feed later stages, and failures stop them. Raw parsing also checks input byte size. These bounds do not cover the caller's AST construction, cloning, serialization or destruction, nor guarantee an arbitrary-small-stack lifecycle for those activities.

Rust `Program` / `Expression` and `Program::from_json` use the same source model and compiler. JSON is versioned and rejects unknown fields. Composition includes input, constants, lexical `Let` / `Use`, sequences, conditionals, bounded loops, recursive calls, parallel joins, races, catch/finally, waits and acting scopes. Higher-level behavior should compose these or add host operations.

Source ASTs (`DoNode` and `Expression`, including their JSON literals) are released iteratively on normal drop, admission rejection and panic unwinding. Inspect them by borrowing, such as `match &source.body` or `match &node`, rather than moving fields out of these enums, which implement `Drop`. Use builders to compose owned nodes; a compiled program does not borrow its source AST.

Portable lowering uses borrowed source nodes and explicit frames, so raising `CompileLimits.expression_depth` does not require a deeper native call stack. Sequences link cached entry/tail addresses rather than rescanning instruction chains. JSON decoding, source serialization and literal conversion retain independent depth boundaries; a higher compile limit does not remove them. AST release reuses owned sequence and JSON container iterators instead of duplicating wide branch storage, releases terminal siblings before descent and promptly frees exhausted containers. Pending branches and retained container capacity still contribute to peak heap usage; source-byte limits are not process memory limits.

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

`Literal` uses plain JSON. `Constant` and operation `literal_input` use tagged values preserving bytes, blobs, tensors, frames, stream markers and exact float bits. Ordinary maps remain maps, including those with a `type` key. Program identity covers the instruction format version, lowered instructions, entry, binding count and effective imports; distinct source forms that lower to the same image can share an identity. It identifies an artifact, not its permission to run.

Hosts can bind imports with `CompiledProgram::map_imports` before preparing an artifact. This preserves instruction positions and lexical slots, rejects request/scope kind changes, and recalculates the executable fingerprint. Signal waits need no Console-side rewrite: Kernel preparation lowers them to unary `subscribe` Operations on their exact resources. They use ordinary Handle admission, residual policy and Facts; the installed method supplies the wait. Conditional predicates inspect the value entering Wait, not a later signal value.

Prepare a program once with `PreparedProgram::new`, then call `Xolotl::run_prepared` with identity, resource allowlist and a `TaintedValue` input. SDK helpers delegate the allowlisted resource's installed methods, grouped by each method's declared authority; they do not grant arbitrary verbs or propagation flags. They return `Result<ExecutionCompletion, XolotlError>`; explicitly access `completion.output` for the body's outcome, taint and unresolved identities, and `completion.finalization` for immutable cleanup evidence. Keep the body's taint and reconciliation evidence when composing another request. Each call receives an attenuated request process. Instructions are borrowed; mutable execution storage is independent.

`PreparedProgram::new(&compiled)` retains the caller's compiled artifact by cloning its containers and owned metadata during preparation. Use `PreparedProgram::from_compiled(compiled)` when transferring ownership, avoiding that clone. Cloning an already prepared `PreparedProgram` instead shares instructions, constants and cached resource analysis through a reference count.

Repeated runs can supply `ExecutionBuffers` to `run_prepared_with_buffers` or `Executor::eval_prepared_with_buffers`; graphs also have `eval_graph_with_buffers`. `reserve_for` allocates capacity ahead of time, `retained_bytes` reports retained capacity, and `release` returns it to the allocator. Each concurrent execution exclusively borrows its buffers. Success, failure and dropping the Future release all values in them.

Buffer reuse does not cover payload, I/O future or process record allocations, and dropping a Future cannot run asynchronous `Finally`. `run_program` prepares per call.

Run the complete Rust/JSON composition example:

```sh
cargo run -p xolotl-sdk --features memory --example portable
```

The protobuf `PortableProgram` envelope transports bounded JSON plus identity through checked conversions. It adds neither execution authority nor an unrestricted gateway endpoint. Native `StepRef` closures remain part of the hosted graph frontend; they cannot be serialized as portable functions.

Portable source can explicitly load a continuation with `Expression::Module { module: StepRef::new("increment") }`, encoded as `{"kind":"module","module":{"name":"increment"}}`. Bind it with `StepModule::program(name, revision, loader)` or `StepBinding::program` and combine it with native functions through `StepModule::compose`. `ProgramLoader` receives borrowed input and an optional argument and returns a `PreparedProgram`. Loaders are synchronous and effect-free; obtain external source through an Operation first. `LoaderRevision::from_bytes([u8; 32])` identifies the loader implementation and its captured configuration. The host must change it when either changes; it is separate from the identity of each returned program. The kernel retains the loader, not every returned image. Source positions stay module-local; execution tickets keep repeated calls distinct. Run the mixed native/portable example with:

```sh
cargo run -p xolotl-sdk --features memory --example native_modules
```

## Resource And Cancellation Bounds

The standard Context assembly driver validates known layers and memoizes rendered byte lengths by resident identity before selecting prompt material. It renders only selected layers into the final buffer, without intermediate per-layer text copies. Persona and environment remain anchors even when they exceed the token estimate; malformed known layers still fail even if they would be excluded. Prompt sizing and buffer reservation are checked separately, so preserving anchors does not waive materialization failure or make the token estimate an RSS limit.

Core storage never grows. Capacity exhaustion returns a fault. Loop iterations, optional cumulative transitions and cleanup transitions have separate limits. `CompileLimits` defaults to expression nesting 128, 65,536 instructions and 1 MiB source bytes for one module. `compile_with_limits` and `from_json_with_limits` accept explicit host admission settings. Larger accepted sources produce the same image regardless of the selected limits. JSON decoding has its own recursion bound, and instruction addresses remain `u32`.

Hosted `ExecutionConfig` defaults to 65 task slots, a depth of 256 per task, 1,024 shared frames, 1,024 bindings per task, 65,536 instructions, 16 MiB of shallow execution storage, 4,096 cleanup transitions and a 256-transition scheduling quantum. `max_steps` defaults to `None`; hosts can set `Some(quota)` independently of that quantum. Exhausting a quantum yields, without cancelling a long-running task. Static programs use smaller derived layouts; recursive programs use configured ceilings where a static estimate is insufficient. The shared pool is bounded by `max_frames`, independently of task count times per-task depth. A fork retains its suspended parent and consumes two child slots.

Registered Process finalizers share one `ExecutionConfig::cleanup_timeout`, defaulting to 30 seconds for the entire sequence. This wall-time bound complements `cleanup_steps`; it does not preempt synchronous native code or stop an already accepted storage write. Derived resource executions, including finalizers, inherit the request authorizer. Denial or timeout records a live cleanup failure while local Handle disposal and terminal publication continue.

Native Step and portable module imports start with the current image's derived layout. After an import produces a subprogram, the host analyzes it and combines the original image's bounds with those of still-active native invocations. Completed invocations no longer contribute, so 64 sequential scalar Steps need only one task and one continuation frame. The estimates are conservative; all configured task, frame, binding, instruction and byte ceilings continue to apply.

The host grows containers only when necessary. It reserves replacement capacity before moving live values, keeping pending I/O and tickets intact. The byte budget includes both existing and replacement containers during this handoff. A rejected expansion or failed reservation rolls back its image changes and follows ordinary error recovery. Empty capacity can be retained for later runs through `ExecutionBuffers`.

Loaded subprograms are lowered and analyzed independently, then linked into reusable instruction, import and binding ranges. At host boundaries the executor uses active continuation frames to find retired fragments, releases their constants and imports, and clears their binding values across all task rows. Live addresses stay fixed, including nested calls and concurrent waits. Adjacent free ranges coalesce; a completed earlier fragment can be reused while a later one is still waiting. A 64-call sequence with one local variable needs only one binding slot and space for the original graph plus one two-instruction fragment.

Free container capacity is retained until execution ends. Variable-sized live fragments can leave gaps too small for a new fragment, so the configured limits bound the address range including holes, not only the sum of live instructions. There is no moving compactor. Source positions remain module-local; invocation tickets distinguish repeated calls independently of reused addresses. Ticket exhaustion returns an error instead of reusing a recorded identity. There is no cumulative source-position limit on module loading. Compilation scratch, code containers and value payloads remain outside `max_storage_bytes`.

The core itself never grows storage. `Execution::suspend` releases its borrows and returns metadata; a host may grow its arrays and remap binding rows, then call `Execution::resume` to validate and resume them without cloning values. This is an in-memory handoff, not a durable commit or redispatch. `continuation_entries` reports active host-supplied subprograms without allocation. `clear_bindings` releases a host-selected retired binding range without cloning values; the host must first prove that no live code or scope still references it.

`ProgramImage::resource_requirements` analyzes reachable control flow in the core, using one caller-owned `AnalysisSlot` per instruction. Time and scratch space are linear; analysis uses neither recursive native calls nor heap allocation. Sequences and exclusive branches share capacities. Concurrent branches add task usage, while child stacks are independent of their suspended parent's stack. Nonrecursive calls have static bounds. A dimension with no established finite bound returns `None` and requires a host-selected capacity. Analysis covers the current image, excluding native expansions returned by the host.

The compiler reuses bindings after lexical scopes end, preserving restoration across calls, failures and concurrent branches. Hosted preparation caches the analysis; `PreparedProgram::layout(&config)` reports task count, total frames, per-task depth, binding count and container bytes before execution. A sequence of 2,048 single-variable scopes needs one binding slot; 64 sequential binary forks need three task slots; flat input or transform chains need no continuation frames. If only one of two branches needs 64 frames, the parent and its two children share 64 frames instead of reserving a stack of that size for every task. Retained buffer capacity also obeys the current byte budget. Empty buffers release old allocations before replacement when necessary. Growing live buffers also accounts for the temporarily overlapping containers described above.

The byte ceiling counts task/frame/binding containers, excluding value payloads, compiled images, driver buffers, Fact retention and process history. Hosts needing a total memory cap must bound those separately. Transition limits do not preempt synchronous drivers or native Steps; isolate blocking work and set operation deadlines in the host.

`cancel_process` wakes waiting execution. Cancellation remains `Failure::Cancelled` even when a pending effect may have started; that result does not prove rollback. A completed hosted `ExecutionOutput` retains observed unresolved identities separately; dropping the execution future can prevent their delivery. The host drops cancelled request futures before acknowledging completion, releases reserved concurrency capacity and retains uncertain spending. `Finally` runs with a separate transition budget, receives the body's original input and preserves a body failure. A cleanup failure replaces a successful body result; otherwise the body value is returned. The selected result retains both body and cleanup control dependencies. Race returns the first result after cancelling and cleaning up the loser; its winning value does not erase an unresolved losing effect.

Native `DoNode::finally` and portable `Expression::Finally` lower to this same core instruction. `DoNode::bracket` and Plan `bracket` bind the acquired value and pass it to the release step; release runs after success, ordinary failure or cooperative cancellation, while the body result remains the program result. Dropping the execution future or forcing a timeout cannot run lexical cleanup; the request owner must still complete process cleanup.

`Executor::with_deadline(HostDeadline)` accepts an absolute monotonic deadline created by the Kernel's `HostRuntime`. The host checks it while advancing and waiting for I/O. If the deadline interrupts an unresolved operation that may have produced an external effect, it returns `Failure::OutcomeUnknown` with reason `deadline_exceeded`; otherwise it returns `Failure::Timeout`. `Deterministic` and `Observation` replay classes do not by themselves imply an unresolved effect. Either result keeps the machine's currently live provenance and drops pending calls. This is a hard stop and cannot continue lexical `Finally` bodies. The request owner must still finish the process and its process finalizers. A deadline `OutcomeUnknown` carries sorted, deduplicated `operation_ids` for effectful imports whose futures were polled and remained pending. The result's bounded `unresolved_operations` retains these identities and earlier host-observed uncertainty independently of the final outcome. `identities_incomplete` means some identities are unavailable, including when its ID list is empty. These IDs guide reconciliation, not a complete audit of earlier effects. Synchronous drivers and native Steps remain non-preemptible.

`with_deadline` returns an error if the deadline belongs to another `HostRuntime` clock domain. Cloning a runtime preserves its domain. When translating an application-owned absolute expiration into a runtime deadline, the host uses that runtime's clock; a monotonic instant cannot be transferred between clock domains.

Dropping a bare Executor future releases execution storage but does not own the Process lifecycle. `Bootstrap::request_under` returns a `RequestProcess` with explicit ownership: call `executor` to run work, then `finish(&output)` with the complete `ExecutionOutput`. Process finalization retains the provenance of the body's terminal status as well as its own finalizer results. For independently owned tasks, `Arc<Bootstrap>::request_under_owned` keeps the host alive through the same `RequestProcess` without cloning its internal fields. Gateway requests retain this owner from creation through receipt admission, execution and finalization; accepted input streams carry it across calls. SDK graph runs and ordinary prepared runs use this scope automatically. Dropping an unfinished scope closes its request tree, cancels execution, aborts attached tasks and revokes existing handles immediately. If the installed `TaskSpawner` accepts the task, it schedules one asynchronous process cleanup attempt; successful requests spawn no cleanup task. `Bootstrap::drain_cleanup` / `Xolotl::drain_cleanup` attempt pending cleanup, including work left by a scheduler shutdown or backend failure, and wait for detached cleanup tasks to release their Kernel captures. Stop creating request scopes before using this as a shutdown barrier. They report failed trees for a later retry without an unbounded retry loop; unrelated host blocking jobs have their own lifecycle.

Normal completion finishes only the specified process. Independently started Actors and async result tasks may continue; explicit tree finalization reaches them even through a finished ancestor. Forced closure cancels live processes without a prior terminal intent and waits for managed body futures to drop. Self-joining bodies or finalizers receive `ProcessBusy` instead of waiting on their own execution. Actor directories and async outcomes use retained terminal publications, so backend failures do not discard results or complete cleanup early.

When a completed body still has output to drain, call `RequestProcess::complete_body(&output)` before awaiting delivery. This synchronous handoff selects the existing first-terminal/Local-cleanup contract and retains body provenance and bounded unresolved identities, not the payload. It neither runs finalizers nor confirms cleanup, and cannot replace prior cancellation or Tree cleanup. Keep the owned output in the service, then call `finish(&output)` even if delivery fails. Dropping the owner after this handoff preserves the selected body conclusion; a finalized process rejects new body evidence.

Process finalizers are separate from a program's lexical `Finally`. Unstarted process finalizers survive interrupted cleanup. Attempted finalizers are not replayed automatically; interruption is recorded because external effects may be incomplete. Lifecycle retries retain the original record, including its timestamp, terminal intent and revoked-handle count. Completion releases modules, attached grants and finalizer storage outside the process table lock.

Dropping the execution future, aborting a Tokio task, process exit and `finalize_process` cannot continue the program's asynchronous `Finally` bodies. For graceful shutdown, cancel, await the executor, then finish the request. Process cleanup I/O still needs host deadlines. Terminal entries are eligible for admission-triggered reclamation only after cleanup and all custody end; explicitly selected Facts have independent retention. Cleanup does not establish a total memory bound.

Hosted process storage has an independent opt-in capacity:

```rust,ignore
use std::num::NonZeroUsize;
use xolotl_sdk::{Bootstrap, DoNode, IdentityRef, KernelBuilder, Value};

let kernel = KernelBuilder::in_memory()
    .with_process_capacity(NonZeroUsize::new(64).ok_or("invalid capacity")?)
    .build();
let host = Bootstrap::from_kernel(kernel);
let request = host.request_under(host.root(), IdentityRef::ROOT, &[])?;
let output = request.executor().eval(&DoNode::pure(Value::null())).await;
let report = request.finish(&output).await?;
let examined_limit = 16;
let reaped = host.kernel().processes().reap_finalized(examined_limit);
```

The root consumes one entry. Common child admission automatically examines the queued retirement candidates before rejecting a full table. Only cleanup-complete terminal leaves with no task, finalizer, native capture, reserved Operation or cleanup pin are eligible; an ancestor remains while it has children. Reclamation never evicts pending cleanup or custody. Each lock-held batch examines at most 32 candidates; at full capacity an admission can examine the queue length captured at its start, so total work is O(that snapshot), not constant time. New candidates do not extend that examination budget indefinitely. `reap_finalized(limit)` remains available for explicit maintenance: `limit` bounds candidates examined, including stale or pinned candidates, and the return value counts entries actually removed. Dropping a pin only queues eligibility; it does not reap immediately. The retained `report` above survives removal without pinning the Process. Tree cleanup pins its selections across waits. Shared tables accept `set_capacity` updates, but reject limits smaller than their current length. Table allocations are kept for reuse; the count ceiling is not a byte or RSS limit. Reaping does not delete explicitly recorded Facts or published asynchronous outputs. Those stores need separate retention and payload budgets.

Process IDs remain monotonic and fail on exhaustion. A process identity locates work in the current Kernel; reopening application data does not recreate its process or execution position.

## Bounded Fact Reads

Custom stores implement `FactStore::scan(FactQuery)` and identity-indexed `lookup(FactLookup)`. Point reads filter the current caller in one storage view before charging bytes. Pages independently limit returned records, inspected candidates and encoded bytes. Continue with `query.next_page(&page)`; an empty filtered page can still have a continuation. Each page's `end` captures its read upper bound without freezing completion updates in old slots.

Encoded bytes do not bound decoded heap, backend caches or RSS. Hosts select Fact recording, backend and retention. Quiesce writers when a stable diagnostic view is needed; after subscription lag, rescan old slots that may have changed. Facts cannot resume control flow or prove authority or external-effect commit.

## Live Suspension And Data Persistence

`Execution::view()` borrows the current machine state and storage for inspection. `suspend()` consumes the machine and returns a `SuspendedExecution`, releasing its borrow of caller-owned arrays. The host can grow those buffers and continue the same execution with `resume(image, token, tasks, frames, bindings)`. Tasks, frames and bindings remain host-owned; the suspension token is not a persisted program snapshot. Kernel uses this path to grow machine storage for dynamic steps.

The runtime owns requests, authority, budgets and cleanup in the current host lifecycle. Console [service-owned submissions](console-runtime.md#service-owned-submissions-and-retained-results) transfer execution responsibility to the live service with bounded result retention. After host exit, applications reopen State, objects, credentials and business call records and decide subsequent work from committed data and external-system state. Applications choose business idempotency keys and reconcile unknown effects before deciding to retry.

## Verification And Measurement

```sh
cargo check -p xolotl-sdk --no-default-features --target thumbv7em-none-eabi --lib
cargo check -p xolotl-sdk --features serde --target thumbv7em-none-eabi --lib
cargo tree -p xolotl-sdk --no-default-features --edges normal
cargo run -p xolotl-core --release --example core_footprint
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- kernel/prepared
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- process_reaping
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- kernel/payload
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- kernel/native
```

Install the Cortex-M target through rustup before target checks. The `core_footprint` example measures scalar storage and 1,000-operation batch means including admission/reset; its p99 is a percentile of batch means, not request tail latency. The prepared benchmark includes host execution allocation and scheduler entry, excluding compilation, request-process creation, I/O and inference. Compare measurements only for the same workload, features, build and hardware.

The `benchmarks/runtime` package measures control, resident values, portable and hosted execution, stream cancellation, file objects, State/Fact data reopening and provider parsing. Its runner separates timing from heap instrumentation, checks outputs and resource release, and scales cumulative work with a fixed active window. Run from the repository root:

```sh
python3 benchmarks/runtime/measure.py build --output target/runtime-measurements
python3 benchmarks/runtime/measure.py smoke time heap scaling --output target/runtime-measurements
```

See `benchmarks/runtime/README.md` for workload parameters, environment recording and measurement scope. Heap reports count allocations after fixtures and warmup; they do not measure process RSS or device memory. Timing reports describe complete workloads, including validation and owner release.
