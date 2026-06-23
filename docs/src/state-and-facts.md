# State And Facts

Xolotl separates mutable state from the Fact stream.

## State Path

The `state://` path is served by a `StateBackend`. State access is
exposed through state-driver Operations: `read`, `write`, `append`, `delete`,
and `list`.

Because state access goes through Operations, capability checks, residual
policy, taint propagation, and audit apply to state reads and writes just like
they apply to other effects.

Subscriptions use the event bus facade `effect://events/subscribe`, backed by
the same state backend subscription channel. Executor `Wait(Signal)` nodes also
wait on that backend subscription channel.

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

`xolotl-state` provides the backend trait and in-memory implementation.
`xolotl-storage-redb` provides persistent redb-backed state and FactStore
adapters.

`xolotl.toml` chooses storage at bootstrap time. Runtime state managed by the
console is stored in Xolotl state.
