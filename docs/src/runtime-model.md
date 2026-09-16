# Runtime Model

Xolotl has one active entity: `Process`.

A Process owns compiled Handles, issues Operations against Resources, receives
Outcomes, and records Facts. Files, terminal commands, inference, memory, state,
remote devices, and external tools all enter through the same Resource,
Interface, Driver, and Binding model.

## Process

A Process carries:

- an identity;
- a lifecycle status;
- grants and compiled handles;
- budget state;
- optional finalizers;
- parent/child links when spawned by another Process.

Spawning attenuates authority. A child Process receives rights limited by the
parent grant.

`finalize_process` closes child admission throughout the tree, aborts attached
tasks and waits for body futures to drop before cleanup. It finishes descendants before their
parents, runs finalizers in reverse order, revokes handles, records a
`ProcessFinalized` Fact, and writes a state marker for quick lookup. A failed
descendant does not prevent sibling cleanup, but leaves its parent pending.
Finished ancestors still close their descendants. Live processes without an
existing terminal intent become cancelled.
`finish_request_process` / `finish_process_as` finish the specified Process after
its own program returns; the latter accepts only terminal statuses.
Independently started Actors and async result tasks may continue. A body or
finalizer trying to await itself, or its containing tree, receives `ProcessBusy`;
it must request cancellation and return control to its owner.
Finalization context includes process-table identity and the nested call chain,
so identical local ids in separate Kernels remain independent. Finalizers can
finish idle processes but never wait for another finalization owner, preventing
cyclic waits across Kernels.
If a finalizer fails, the lifecycle Fact records the failure count and details
while cleanup continues.
Request Processes created by SDK, Console, or Gateway entry points are finalized
after their program returns, including failure and cancellation outcomes.
During finalization, operations are limited to the current Process subtree
`state://process/<process-id>/...` and methods whose interface metadata marks
them as finalizer-safe.

An owned `RequestProcess`, created by `Bootstrap::request_under`, also handles
abandonment. Dropping it immediately cancels its tree and revokes existing
handles; on Tokio it schedules one cleanup attempt. Without a runtime, or if
that attempt is interrupted or fails, `drain_cleanup` finishes pending work.
SDK ordinary graph and prepared runs use owned requests. Bare Executor futures
leave lifecycle ownership with their host. Durable SDK runs explicitly transfer
ownership to checkpoint recovery and preserve interrupted requests.

Each finalization attempt has one owner. Dropping that owner releases the claim
and wakes other callers. Unstarted finalizers remain in the process table;
completed or interrupted attempts are not replayed, and interruptions are
recorded as failures. Retries reuse the same lifecycle Fact. Process finalizers
can resume independently of a dropped executor, whose lexical `Finally` bodies
cannot run after its Future disappears. Tasks start only after attachment, and
aborted body exit is acknowledged after captured resources drop. Normal body
completion retains the result, intent and pending publication before releasing
ownership. Actor directory and async result errors remain retryable through
`drain_cleanup`, without rerunning drivers or prematurely completing cleanup.
Retries preserve the original single-process or tree scope; a failed completion
does not cancel independently running children.
Finished processes release native modules, attached grants, publication objects
and finalizer storage, but retain terminal entries,
state markers and Facts. Hosts still need a history retention policy.

An Actor is a named long-lived Process. `ActorSpec` is the declaration shape:
body, declared capabilities, budget, and finalizers. Spawning an actor checks
the body and finalizers, creates a normal
Process with attenuated grants, runs the body through the same Executor, and
publishes a directory entry under `state://agents/<identity>/<name>` for
discovery. Process-local native functions are supplied as a shared immutable
`StepModule` at spawn time when the body or finalizers reference `StepRef`s.
Ordinary requests can attach the same modules without creating an Actor. Actor declarations may use
`state://process/self/...` in body, finalizers, and declared capabilities; the
placeholder is bound to the concrete Process id before linting, grant planning,
and execution. Step references themselves contain only names and arguments.
Request grant templates also bind this placeholder before capability attenuation.
Dynamically returned Step subgraphs bind structured operation and signal paths
to the invoking Process before compilation, including nested recovery and cleanup.

Directory admission also runs inside the managed task. Dropping the spawn call
or closing its parent stops admission. Terminal CAS updates only records with
the same process and execution owner. A cancelled admission may retain a terminal
reservation to block late initial writes; an existing conflicting Actor is not
modified.

`AsyncProcess` returns a pollable `proc://async/<process>/<execution>` reference.
Status and outcome are stored at
`state://kernel/async/<process>/<execution>/status` and `outcome`. Each async task
owns a derived handle and shares managed task ownership, cancellation, lifecycle
Facts and terminal publication. Initial status failure prevents driver dispatch;
the result and taint survive terminal publication failures for later retry.

## Resource And Interface

A Resource is a passive object that can be operated on, authorized, audited, and
bound to a Driver. Its Interface describes the available methods, output modes,
purity, cost model, modality support, and batching support.

The data path normally uses Resource ids and Method ids.

## Driver

A Driver implements interface methods. It receives a restricted
`DriverContext`, the method id, an input Value, the requested output mode, and
returns an Outcome.

Driver authority comes through the restricted `DriverContext`. If a driver
needs to touch state, emit streaming chunks, derive provenance, or record output
taint, it uses the runtime APIs exposed in its context.

Invocation completion preserves the driver's reported source order and appends
input sources that are not already present, for both success and failure. Portable
and hosted execution, cached completion and asynchronous child results use this
same rule. A Fact maintains its audit sequence separately: input sources precede
new output observations. Source order does not grant authority.

## Handle

A Handle is the compiled product of `open()`: Resource, rights, fast-path mode,
DriverPlan, optional residual policy, owner Process, and generation.

Revocation bumps the generation so stale Handle ids fail before reuse.

## Operation And Fact

An Operation is the single path through which side effects occur. It contains
the caller, acting identity, handle id, method id, full operation identity, input
Value, output mode, and input taint. Facts share the complete immutable input
and successful output Values, including media metadata.

A Fact records one operation attempt. Its first begin assigns an append slot;
repeated begins with the same full ID reuse that slot, and completion updates it
in place. Media payloads use external references. Inline strings, lists, bytes
and retained Fact history need separate host limits.
