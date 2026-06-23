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

Finalization cancels descendants, runs finalizers in reverse order, revokes the
Process handles, records a `ProcessFinalized` Fact, and writes a state marker
for quick lookup. If a finalizer fails, the lifecycle Fact records the failure
count and details while cleanup continues.
Request Processes created by SDK, Console, or Gateway entry points are finalized
after their program returns, including failure and cancellation outcomes.
During finalization, operations are limited to the current Process subtree
`state://process/<process-id>/...` and methods whose interface metadata marks
them as finalizer-safe.

An Actor is a named long-lived Process. `ActorSpec` is the declaration shape:
body, declared capabilities, budget, and finalizers. Spawning an actor checks
the body and finalizers, creates a normal
Process with attenuated grants, runs the body through the same Executor, and
publishes a directory entry under `state://agents/<identity>/<name>` for
discovery. Process-local steps are host functions installed at spawn time when
the body or finalizers reference `StepRef`s. Actor declarations may use
`state://process/self/...` in body, finalizers, and declared capabilities; the
placeholder is bound to the concrete Process id before linting, grant planning,
and execution.

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

## Handle

A Handle is the compiled product of `open()`: Resource, rights, fast-path mode,
DriverPlan, optional residual policy, owner Process, and generation.

Revocation bumps the generation so stale Handle ids fail before reuse.

## Operation And Fact

An Operation is the single path through which side effects occur. It contains
the caller, acting identity, handle id, method id, causal position, input
Value, output mode, and input taint. When the data path records a Fact, it
projects the input and outcome into `ValueRef` / `OutcomeRef`.

A Fact is the durable record of an operation attempt. It is append-only and
fixed-size in the hot path; large payloads are represented by references.
