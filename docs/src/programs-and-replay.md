# Programs And Replay

Xolotl executes portable programs and existing graphs through one core machine.
This page describes native composition and Fact recovery diagnostics. Full portable checkpoint
restoration is covered in [Core And Portable Programs](core-and-portable.md).

## Program Front Ends

The existing graph front end is `DoNode`. It supports pure values, operations, named
Steps, branches, joins, identity switches, waits, failures, and structured
composition.

Plan documents are parsed by `xolotl-plan` and lowered to the same `DoNode`
shape. The structured protobuf `Program` type in `xolotl-proto` is a wire-safe
representation of the same executable shape and converts losslessly to `DoNode`.

## ExecutionGraph

The executor compiles `DoNode` programs to `ExecutionGraph`. Node ids are
stable within the compiled graph and serve as source positions for Operations.
They do not identify a dynamic call on their own. Each `OperationId` combines
`process/execution/invocation/position/attempt`; invocation uses the core's
64-bit request ticket. Independent evaluations and finalizers get fresh execution
scopes. Checkpoint recovery retains the original scope and ticket.

## Steps

Steps are named, pure continuations assembled into a `StepModule`.
`StepRef::new(name)` carries a name and an optional argument, with no process id.
The Executor resolves the name only in its immutable module, calls the function with
the piped value and argument, and appends its returned subgraph to the core image.
Missing names fail locally; lookup does not fall back to a parent or another Process.

`StepModule::single` defines one function; `StepModule::new` accepts a set of
`StepBinding`s. `StepModule::compose` combines modules in one namespace and rejects
duplicate names. Blank names are rejected during assembly. Module clones share
the name table and functions; an empty module allocates nothing. Runtime function
lookup borrows the function without a registry lock or reference-count update.

One module can be reused by standalone executors, requests and Actors:

| Host | Entry point |
| --- | --- |
| Explicit caller and host adapters | `Executor::new(...).with_steps(module)` |
| SDK graph request | `Xolotl::run_with_steps(resources, program, module)` |
| SDK Plan request | `Xolotl::run_plan_with_steps(resources, plan, module)` |
| Request under an existing process | `Bootstrap::spawn_request_process_under_with_steps(...)` |
| Actor body and finalizers | `Xolotl::spawn_actor_with_steps(..., module)` |

An executor holds a fixed module snapshot. `with_steps` overrides only that
executor. Process finalization releases the process's module after its finalizers
finish; other module owners remain valid. An executor attached to that process
stops executing after the process terminates. Standalone executors require
`with_processes` when the host wants process lifecycle checks. Modules carry no
grants: each Operation uses the invoking request's authority.
The SDK's one-shot request helpers keep the module in the evaluation future, so
dropping that future releases its native functions. Ordinary requests immediately
cancel their tree and schedule one cleanup attempt when a runtime is available;
`drain_cleanup` retries retained process finalizers and lifecycle records.
Dropping an execution cannot continue its asynchronous program `Finally` bodies.

Returned subgraphs use the same name resolution, including
nested continuations, recovery and finalizers. Structured operation targets and
signal paths under `state://process/self/...` are bound to the invoking Process
before the returned subgraph is compiled. Binding consumes the subgraph and
updates its paths in place, preserving payload and AST allocations. Literal
strings and step arguments are not interpreted as paths.
Request grant templates resolve the same `self` placeholder before checking
the parent's capability ceiling, preserving predicates and method restrictions.

`xolotl_plan::compile(&plan)` likewise produces a graph without choosing a Process;
the SDK exports this as `compile_plan` with its `plan` feature. Actor admission
checks names in the static body and finalizers. Functions referenced only by a
dynamic subgraph must also be installed by the host; their names are resolved
when that subgraph runs.

IO and other effects go through Operation nodes. Run the module composition example:

```sh
cargo run -p xolotl-sdk --features host --example native_modules
```

## Replay Classes

Method purity derives the replay class the kernel enforces:

| Purity | Replay behavior |
| --- | --- |
| `Pure` / `Deterministic` | May be recomputed or reread when safe. |
| `Observation` | Records observed external/durable value when consumed. |
| `IdempotentEffect` | May dedupe by an effective idempotency key. |
| `NonIdempotentEffect` | Must write ahead before issuing the effect. |

The Fact stream records effect history. `recover_process` classifies completed
and pending records and returns diagnostics and quarantine entries; it does not
execute a program. Facts cannot reconstruct native continuations, race winners,
external payloads or exact output provenance. `ReplayMap` and `with_replay` have
been removed. Resume execution from a complete portable checkpoint.

Default idempotency keys include the complete operation identity. A business
`_idem_key` deliberately spans executions and explicit retries within its
acting-identity and source-position namespace. Hosts must use application-specific
business keys to distinguish unrelated programs or operations at the same position.

## Simulation

`xolotl-sim` provides deterministic testing helpers: virtual time, crash-after-N
drivers, `why_not` projections, and process replay helpers. Use it to check that
programs and drivers behave predictably across crash and replay boundaries.
