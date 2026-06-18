# Architecture

Nexus keeps the execution hot path small:

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

The runtime is split into four code paths.

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
| `nexus-types` | Core ids, paths, values, capabilities, operations, audit, trace, external access, and process data. |
| `nexus-graph` | `DoNode`, `ExecutionGraph`, graph compiler, cursor, and `ActorSpec` linting. |
| `nexus-state` | State backend trait and in-memory implementation. |
| `nexus-kernel` | Registry, policy, handle table, execution path, executor, process table, recovery, and bootstrap. |
| `nexus-storage-redb` | redb-backed state and fact storage. |
| `nexus-standard` | Standard in-process Provider and Source implementations. |
| `nexus-gateway` | Shared session admission, flow-control, taint, and audit code for external protocol adapters. |
| `nexus-gateway-grpc` | External Provider/Source gRPC adapter. |
| `nexus-gateway-websocket` | External Provider/Source WebSocket adapter. |
| `nexus-gateway-mcp` | MCP server-side adapter for selected Gateway publication kinds. |
| `nexus-proto` | Protobuf schema and vendored Rust bindings. |
| `nexus-console` | Gateway for Web Console management actions. |
| `nexus-daemon` | `nexusd`, the long-running host process. |
| `nexus-sdk` | Embedded facade for in-process kernel use. |
| `nexus-plan` | Plan document parsing and lowering. |
| `nexus-sim` | Deterministic simulation and replay helpers. |

## Standard Package Features

`nexus-standard` contains the standard in-process Provider and Source
implementations. A binary can compile only the modules it needs.

The default `standard` feature builds the core standard in-process
implementations. `standard-core` builds that core set and the pairing management
effects. `fetch`, `fs`, and `terminal` each require their own feature. External
Provider/Source session handling and `SecureEnvelope` code live in
`nexus-gateway`.

HTTP inference provider features are opt-in. `http-inference` enables all HTTP
inference dialects. The individual dialect features are `openai-responses`,
`openai-chat`, `anthropic-messages`, and `gemini-generate-content`.
`nexus-daemon` forwards those feature names to `nexus-standard`.

High-risk in-process implementations such as `fetch`, `fs`, and `terminal`
must stay behind separate `nexus-standard` features. A daemon or embedded host may
expose them only through kernel-state declarations and fixed Console actions.
Runtime in-process projection declarations are stored in Nexus state.

Optional in-process projection declarations are runtime state under
`state://kernel/projections/in-process/<id>`. They use `projection.in_process.*`
Console actions, kernel state admission, and host-side reconciliation into
ordinary Resource, Interface, Driver, and Binding registry entries.
