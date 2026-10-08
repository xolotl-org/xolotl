# Runtime Model

A `Process` is the active execution and authority owner. It opens Resources into Handles, issues Operations and receives Outcomes. Hosts may explicitly record Facts for observation. Model inference, tools, State, files and external systems all use this model.

## Process

A Process has an identity, lifecycle status, grants, Handles, budget and optional finalizers. Parent/child links record spawned work. A child receives attenuated authority; naming the parent's identity or Resource does not grant access. An `Actor` is a named, long-lived Process, while a request Process has an owner responsible for its end-of-request cleanup.

`BudgetSpec` can limit lifetime cost (`max_micro_usd`), inference tokens (`max_inference_tokens`) and concurrent reserved Operations (`max_inflight_ops`). An omitted limit adds no ceiling; zero is a real ceiling. An Operation reserves estimated usage against its Process and every ancestor before Driver dispatch. Measured usage settles the reservation and can exceed an inaccurate estimate. `restrict_budget` intersects limits without resetting spending. Process budgets have no calendar reset or account-wide billing semantics.

Normal request completion finishes the request Process. Explicit tree finalization closes descendant admission, stops attached tasks, finishes descendants before parents, runs finalizers in reverse order and revokes Handles. A failed cleanup leaves work pending for a later attempt. Finalizers may use only methods marked finalizer-safe and their Process-local State subtree. Independently accepted Actors and asynchronous children can continue after the initiating body completes.

`ProcessTable::finalization_report` shares the completed live cleanup report: terminal status, provenance, unresolved operation identities, typed finalizer failures and handle-release counts. It is independent of Fact recording. Reaping releases the table's report ownership; existing observers own their retained reports separately. Reports do not restore execution or retain a full call history.

`RequestProcess::finish(&output)` returns an immutable `Arc<ProcessFinalizationReport>` before releasing the request's cleanup pin. A `RequestFinishError` retains the typed `source` and original `cleanup: CleanupTicket`; keep that ticket and use `Bootstrap::resume_cleanup` to retry cleanup, not the body. A ticket can observe a later committed report. Its report or provisional unresolved identities do not by themselves prove cleanup completion. `CleanupWaitExpired` means the caller's observation deadline expired, not that cleanup stopped or effects rolled back.

SDK `run*` helpers return `ExecutionCompletion`: access the body through `output` and cleanup evidence through `finalization`. The latter is `None` only for preparation rejection before Process admission. A retained report does not pin the Process or keep its table entry alive.

Common child admission automatically reclaims eligible terminal entries. Roots, cleanup still in custody, live tasks/finalizers, reserved Operations, pinned records and parents with children remain retained. Tree cleanup pins its selected members before waiting. There is no background reaper or eager reaping on pin drop; idle terminal records may remain until another admission. See [Core And Portable Programs](core-and-portable.md#resource-and-cancellation-bounds) for examination cost and capacity behavior.

Ordinary cleanup does not write persistent lifecycle markers or require State write capability. Actor directory and asynchronous-result publication use their business data ports; failed publication retains the known result and pending publication responsibility for a live retry.

An owned `RequestProcess` handles abandonment: dropping it cancels the tree and revokes Handles immediately, while asynchronous finalization remains the host's responsibility. `drain_cleanup` retries pending cleanup. A bare Executor future does not own Process finalization. See [Core And Portable Programs](core-and-portable.md#resource-and-cancellation-bounds) for capacity, cancellation and ownership APIs.

The runtime owns processes within one running host lifecycle. Applications can reopen persistent data and decide subsequent work from actual data and external-effect state. Unknown effects retain their original operation identity and are not automatically redispatched.

An `ActorSpec` declares a named body, capability ceiling, budget and finalizers. Actor admission checks those declarations, attenuates the parent's grants and publishes `state://agents/<identity>/<name>`. Process-local `StepRef` functions come from a host-installed `StepModule`. The structured `state://process/self/...` placeholder is bound to the actual Process before capability planning and execution.

`AsyncProcess` needs a host-installed `AsyncProcessHost`. The host reserves child custody and returns a reference before the child Driver runs. Method rights and `SPAWN_WITH` propagation rights are checked separately. The host owns quotas, acceptance receipts, results and cleanup; a kernel method cache stores a body result, never a child Process reference. The child inherits its parent's deadline unless the host narrows it.

## Resource and Interface

A Resource is a passive, addressable target. Its Interface declares methods, authority, output modes and execution properties. A Binding selects the Driver implementation. Resource paths identify targets; they do not confer rights. See [Capability Model](capability-model.md) for path syntax and `open()`.

## Driver

A Driver implements declared methods. It receives the admitted method, input, output mode and a restricted `DriverContext`, then returns an Outcome with provenance and usage. The context provides permitted State, stream and provenance operations. Driver code does not choose the caller's authority.

Invocation completion retains the Driver's source order and appends new input sources for both success and failure. A Fact has its own audit ordering. Source order records lineage; it does not grant authority.

## Handle

A Handle is the process-owned result of `open()`: concrete Resource, permitted method rights, frozen Driver plan, residual policy and generation. Release closes local use while preserving previously derived descendants; revocation invalidates a delegation subtree. Stale generations fail before slot reuse.

## Operation and Fact

An Operation names the Process, selected acting identity, Handle, method, input, output mode and full operation identity. It is the admission boundary for effects, including signal subscriptions. The Kernel checks the live Handle and policy before dispatch.

A Fact records an Operation attempt. Its first begin assigns an append slot; repeated begins under the same `OperationId` reuse that slot, and completion updates it. Facts preserve input and outcome provenance; large media uses external references. `caller_identity` records the Process's ordinary identity at admission, separately from the selected acting identity. A cached result used by a new invocation still records that new caller. See [State And Facts](state-and-facts.md#facts) for storage, queries and v1 fields.

`DataPlane::execute` retains the Driver result and completion errors separately. A completion error does not undo the effect. Unconfirmed effects report `OutcomeUnknown` with their original operation identities for application reconciliation. Fact recording is an explicitly selected observation, separate from authorization and budget ownership.
