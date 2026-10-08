# Programs And Replay

Xolotl executes portable programs and existing graphs through one core machine. This page describes native composition, effect classes and business idempotency. See [Core And Portable Programs](core-and-portable.md) for portable execution.

## Program Front Ends

The graph front end is `DoNode`. It supports pure values, operations, named Steps, branches, joins, identity switches, waits, failures, and structured composition.

Plan documents are parsed by `xolotl-plan` and lowered to the same `DoNode` shape. The structured protobuf `Program` type in `xolotl-proto` is a wire-safe representation of the same executable shape and converts losslessly to `DoNode`.

Plan step lists execute in document order; only explicit `Parallel` and `Race` steps introduce concurrency. `Let` and `Read.as` bind the preceding value computation for the remaining steps in that list. Later bindings may shadow earlier names. Branches, `Acting` bodies, and `Bracket` bodies inherit outer bindings but do not export their local names; sibling branches cannot see each other's bindings. `Bracket` exposes its acquired value as `_resource` in its body and passes that value to release even when the body shadows the name.

`Then` and `OnFail` modify the preceding computation, not the following steps. Modifiers immediately following `Let` or `Read` belong to the binding's producer, so its successful or recovered result is what subsequent `Use` steps receive. A modifier cannot start a list. Unbound `Use` names are rejected during lowering. JSON inputs, values, and arguments are literal data: strings such as `${name}` are not interpolated or treated as dependencies.

Native graph compilation uses explicit frames and preflights node count and source-position bounds before graph allocation or payload cloning; there is no separate recursion-only 256-level nesting cap. Plan and portable source-depth limits and decoder limits remain independent admission contracts. The protobuf tree admits at most 48 nested `DoNode`s because each level adds wrapper messages under Prost's 100-level decode limit. `program_to_pb` and `program_from_pb` also count nested values against the remaining message budget and reject a tree that could not be decoded. Local Plan and SDK execution compile `DoNode` directly and do not pass through protobuf, so the wire limit does not restrict local composition.

## ExecutionGraph

The executor compiles `DoNode` programs to `ExecutionGraph`. Node ids are stable within the compiled graph and serve as source positions for Operations. They do not identify a dynamic call on their own. Each `OperationId` combines `process/execution/invocation/position/attempt`; invocation uses the core's 64-bit request ticket. Independent evaluations and finalizers get fresh execution scopes.

## Steps

Steps are named, pure continuations assembled into a `StepModule`. `StepRef::new(name)` carries a name and an optional argument, with no process id. The Executor resolves the name only in its immutable module, calls the function with the piped value and argument, and appends its returned subgraph to the core image. Missing names fail locally; lookup does not fall back to a parent or another Process.

`StepModule::single` defines one function; `StepModule::new` accepts a set of `StepBinding`s. `StepModule::compose` combines modules in one namespace and rejects duplicate names. Blank names are rejected during assembly. Module clones share the name table and functions; an empty module allocates nothing. Runtime function lookup borrows the function without a registry lock or reference-count update.

One module can be reused by standalone executors, requests and Actors:

| Host | Entry point |
| --- | --- |
| Explicit caller identity and host adapters | `Executor::new(process, identity, data_plane, registry)?.with_steps(module)` |
| Identity from a Kernel-owned ProcessTable | `Executor::from_process_table(process, processes, data_plane, registry)?.with_steps(module)` |
| SDK graph request | `Xolotl::run_with_steps(identity, resources, program, module)` |
| SDK Plan request | `Xolotl::run_plan_with_steps(identity, resources, plan, module)` |
| Request under an existing process | `Bootstrap::spawn_request_process_under_with_steps(...)` |
| Actor body and finalizers | `Xolotl::spawn_actor_with_steps(..., module)` |

An executor holds a fixed module snapshot. `with_steps` overrides only that executor. Process finalization releases the process's module after its finalizers finish; other module owners remain valid. An executor attached to that process stops executing after the process terminates. Standalone executors receive an explicit identity; `from_process_table` rejects a missing Process. Modules carry no grants: each Operation uses the invoking request's authority. The SDK's one-shot request helpers keep the module in the evaluation future, so dropping that future releases its native functions. Ordinary requests immediately cancel their tree and schedule one cleanup attempt when a runtime is available; `drain_cleanup` retries retained process finalizers and lifecycle records. Dropping an execution cannot continue its asynchronous program `Finally` bodies.

Returned subgraphs use the same name resolution, including nested continuations and finalizers. Structured operation targets and signal paths under `state://process/self/...` are bound to the invoking Process before the returned subgraph is compiled. Binding consumes the subgraph and updates its paths in place, preserving payload and AST allocations. Literal strings and step arguments are not interpreted as paths. Request grant templates resolve the same `self` placeholder before checking the parent's capability ceiling, preserving predicates and method restrictions.

`xolotl_plan::compile(&plan)` likewise produces a graph without choosing a Process; the SDK exports this as `compile_plan` with its `plan` feature. Actor admission checks names in the static body and finalizers. Functions referenced only by a dynamic subgraph must also be installed by the host; their names are resolved when that subgraph runs.

IO and other effects go through Operation nodes. Run the module composition example:

```sh
cargo run -p xolotl-sdk --features memory --example native_modules
```

## Replay Classes

Method purity describes effects so hosts can assess unknown results and retry risk:

| Purity | Meaning |
| --- | --- |
| `Pure` / `Deterministic` | Pure or deterministic work; the caller decides whether recomputation is appropriate. |
| `Observation` | Reads external state; rereading can observe a different value. |
| `IdempotentEffect` | Can deduplicate within the method's declared idempotency-key contract. |
| `NonIdempotentEffect` | Redispatch can create a second effect; reconcile an unknown original call first. |

These classes neither automatically retry nor require an audit commit before dispatch. Facts are optional diagnostic data; authority, budgets and application data commits retain their own contracts.

Default idempotency keys include the complete operation identity. A business `_idem_key` deliberately spans executions and explicit retries within its acting-identity and source-position namespace. Applications must distinguish unrelated business operations with their keys.

## Simulation

`xolotl-sim` provides virtual time, fault-injection drivers and `why_not` projections. Use it to verify observable program, authority and Driver behavior under controlled scheduling and failures. `Sim::new` is an in-memory host with observations disabled; recorded simulations explicitly configure `Sim::boot` with a Fact sink and select recording on their Executor. Installing storage alone does not enable recording.
