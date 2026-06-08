# Programs And Replay

Nexus represents durable work as a graph.

## Program Front Ends

The main Rust front end is `DoNode`. It supports pure values, operations, named
Steps, branches, joins, identity switches, waits, failures, and structured
composition.

Plan documents are parsed by `nexus-plan` and lowered to the same `DoNode`
shape. gRPC submissions use the structured protobuf `Program` type in
`nexus-proto`, which converts losslessly to `DoNode`.

## ExecutionGraph

The executor compiles `DoNode` programs to `ExecutionGraph`. Node ids are
stable within the compiled graph and serve as causal positions for Operations.
This is what lets concurrent branches, replay, and recovery refer to the same
operation boundary without a central counter.

## Steps

Steps are named, pure continuations registered per Process. A `StepRef` names
the Process and step name. The Executor looks up the step, calls it with the
piped value, and splices the returned subgraph into the current cursor.

Steps are named pure continuations. IO and other effects go through Operation
nodes.

## Replay Classes

Method purity derives the replay class the kernel enforces:

| Purity | Replay behavior |
| --- | --- |
| `Pure` / `Deterministic` | May be recomputed or reread when safe. |
| `Observation` | Records observed external/durable value when consumed. |
| `IdempotentEffect` | May dedupe by an effective idempotency key. |
| `NonIdempotentEffect` | Must write ahead before issuing the effect. |

The Fact stream is the replay record. Recovery classifies those records, builds
a replay map for completed outcomes, and quarantines unsafe pending
non-idempotent effects.

## Simulation

`nexus-sim` provides deterministic testing helpers: virtual time, crash-after-N
drivers, `why_not` projections, and process replay helpers. Use it to check that
programs and drivers behave predictably across crash and replay boundaries.
