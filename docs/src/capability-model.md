# Capability Model

Authority starts as a Grant and is compiled into a Handle before execution.

## Paths

Resource paths use:

```text
path://[cluster/]<scheme>/<segment>[/<segment>...]
```

Examples:

```text
effect://inference/infer
state://memory/alice/thread
process://alice
```

The path grammar contains the scheme, optional cluster, and path segments.
Operation options belong in structured input Values, explicit resource
segments, or policy/config state.

## Capability Literals

Capability literals use verb schemes:

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
perform://effect/events/subscribe
act-as://process/alice
```

The verb is separate from the Resource path scheme. A Resource path describes
what is being operated on; a capability literal describes what operation class
is authorized.

## Grants And Rights

A Grant has a holder Process, a selector, rights, constraints, and expiry.
Rights combine a method bitmap with propagation flags such as delegation.

Selectors can match exact paths or wildcard path segments. Requested rights must
be a subset of the parent rights when deriving or attenuating authority.

## `open()`

`open()` is the control-plane compiler. It resolves a Resource, selects a
covering Grant, checks open-time constraints, resolves the Binding, builds a
DriverPlan, compiles residual policy, and installs a process-owned Handle.

After that point, the data plane executes against the compiled Handle.

## Policy Snapshots

Policy sources compile into `PolicySnapshot`. Anything decidable at open time is
eliminated. Checks that depend on operation input, budget, rate limits, command
matching, approval, or other runtime state stay as residual checks.

If no residual checks remain, the Handle is marked `Unconditional` and the data
plane skips policy evaluation for that Handle.
