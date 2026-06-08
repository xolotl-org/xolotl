# State And Facts

Nexus separates mutable state from the Fact stream.

## State Plane

The `state://` plane is served by a `StateBackend`. Data-plane state access is
exposed through state-driver Operations: `read`, `write`, `append`, `delete`,
and `list`.

Because state access goes through Operations, capability checks, residual
policy, taint propagation, and audit apply to state reads and writes just like
they apply to other effects.

Subscriptions are currently exposed through the event bus facade
`effect://events/subscribe`, which uses the same state backend subscription
channel underneath. Executor `Wait(Signal)` nodes also wait on that backend
subscription channel.

## Tainted Values

State stores a `TaintedValue`: value plus provenance. A write carries the input
taint into the backend envelope. Reads return the stored taint, preserving
protected or low-trust provenance across the state boundary.

## Facts

Facts are append-only records of operation attempts. Recovery, audit
projection, trace projection, billing projection, and `why_not` explanations
are built from those records.

The hot path keeps Facts compact by storing refs and lightweight tags. Large
content is represented with blob, tensor, or frame references.

## Storage Backends

`nexus-state` provides the backend trait and in-memory implementation.
`nexus-storage-redb` provides persistent redb-backed state and FactStore
adapters.

`nexus.toml` chooses storage at bootstrap time. Runtime state managed by the
console is stored in Nexus state.
