# Runtime Model

Nexus has one active entity: `Process`.

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
for quick lookup.

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
