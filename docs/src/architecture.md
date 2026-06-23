# Architecture

Andrias keeps the execution hot path small:

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

The runtime is split into four code paths.

The rest of the manual follows this split. Concept chapters explain Process,
Resource, Capability, Operation, Fact, and replay. Gateway chapters explain how
outside clients enter the runtime. Configuration chapters explain which
listeners, features, and runtime declarations expose those pieces in a host.

## Control Path

The control path parses, validates, resolves, and compiles. It owns registries,
resource naming, admission checks, policy compilation, binding resolution, and
`open()` handle compilation.

The key rule is that parsing and registry walking happen before execution.
Once a Process owns a Handle, execution can use compiled ids,
rights bitmaps, driver plans, and policy snapshots.

## Data Path

The data path executes one Operation through a compiled Handle. It checks
ownership, handle liveness, rights, residual policy if needed, dispatches the
DriverPlan, and records a Fact when the operation must be durable.

The data path receives compiled ids, rights bitmaps, driver plans, and policy
snapshots.

## External Adapters

External adapters project outside systems into the same runtime model.
Providers expose `effect://...` resources through Drivers or remote bindings.
Sources write inbound events into declared state streams. gRPC and WebSocket
are transport implementations for the same Provider/Source gateway.

## Program Execution

Program execution represents durable work. `DoNode` is the executable program
shape; Plan documents and structured protobuf `Program` values lower to
`DoNode`. The Executor compiles `DoNode` into `ExecutionGraph`, advances graph
nodes, issues Operations, runs named pure Steps, and resumes from recorded Facts
during recovery.

## Workspace Map

| Crate | Role |
| --- | --- |
| `andrias-types` | Core ids, paths, values, capabilities, operations, audit, trace, external access, and process data. |
| `andrias-graph` | `DoNode`, `ExecutionGraph`, graph compiler, cursor, and `ActorSpec` linting. |
| `andrias-state` | State backend trait and in-memory implementation. |
| `andrias-kernel` | Registry, policy, handle table, execution path, executor, process table, recovery, and bootstrap. |
| `andrias-storage-redb` | redb-backed state and fact storage. |
| `andrias-standard` | Standard in-process Provider and Source implementations. |
| `andrias-gateway` | Shared session admission, flow-control, taint, and audit code for external protocol adapters. |
| `andrias-gateway-grpc` | External Provider/Source gRPC adapter. |
| `andrias-gateway-websocket` | External Provider/Source WebSocket adapter. |
| `andrias-gateway-mcp` | MCP server-side adapter for selected Gateway publication kinds. |
| `andrias-proto` | Protobuf schema and vendored Rust bindings. |
| `andrias-console` | Gateway for Web Console management actions. |
| `andrias-daemon` | `andriasd`, the long-running host process. |
| `andrias-sdk` | Minimal embedded facade for in-process kernel use. |
| `andrias-plan` | Plan document parsing and lowering. |
| `andrias-sim` | Deterministic simulation and replay helpers. |

## Embedded Hosts

`andrias-sdk` builds a minimal in-memory kernel by default. `AndriasBuilder` lets
embedded hosts provide their own state backend and fact sink before the
`Bootstrap` is seeded. The SDK `standard` feature exposes the standard package
installation API for hosts that include the standard in-process providers.
Embedders can still provide their own policy sources, drivers, and host
assembly.

`ActorSpec` is a declaration for a named long-lived Process. It carries a
serializable `DoNode` body, declared capabilities, budget, and finalizers.
`Bootstrap::spawn_actor_under` checks the body and finalizers
against the declared capability ceiling, derives process-attached grants from
the parent Process, writes `state://agents/<identity>/<name>`, and runs the body
with the ordinary Executor. If the body or finalizers use process-local
`StepRef`s, the host passes those step functions to
`Bootstrap::spawn_actor_under_with_steps` so they are installed before execution
starts.

## Standard Package Features

`andrias-standard` contains the standard in-process Provider and Source
implementations. A binary can compile only the modules it needs, and compiled
code is separate from installed Resources.

High-risk in-process implementations such as `fetch`, `fs`, and `terminal`
must stay behind separate `andrias-standard` features. A daemon or embedded host may
expose them only through kernel-state declarations admitted by `config.*`.

Optional in-process projection declarations are runtime state under
`state://kernel/projections/in-process/<id>`. They use generic `config.*`
Console actions, shared kernel state admission, and host-side reconciliation
into ordinary Resource, Interface, Driver, and Binding registry entries.
Reconcile results are stored under
`state://kernel/projection-status/in-process/<id>` and read through
`projection.in_process.status.*`.

For deployment-level feature choices and runtime declaration paths, use
[Configuration](configuration.md). For HTTP model-provider dialects, use
[HTTP Inference Providers](http-inference-providers.md). For embedding APIs,
use [API Reference](api-reference.md).
