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
| `nexus-graph` | `DoNode`, `ExecutionGraph`, graph compiler, cursor, and actor linting. |
| `nexus-state` | State backend trait and in-memory implementation. |
| `nexus-kernel` | Registry, policy, handle table, execution path, executor, process table, recovery, and bootstrap. |
| `nexus-storage-redb` | redb-backed state and fact storage. |
| `nexus-actors` | Standard in-process Drivers and Providers. |
| `nexus-gateway` | Shared session admission, flow-control, taint, and audit code for external protocol adapters. |
| `nexus-gateway-grpc` | External Provider/Source gRPC adapter. |
| `nexus-gateway-websocket` | External Provider/Source WebSocket adapter. |
| `nexus-gateway-mcp` | MCP server-side adapter for selected Nexus effects. |
| `nexus-proto` | Protobuf schema and vendored Rust bindings. |
| `nexus-console` | Gateway for Web Console management actions. |
| `nexus-daemon` | `nexusd`, the long-running host process. |
| `nexus-sdk` | Embedded facade and public re-exports. |
| `nexus-plan` | Plan document parsing and lowering. |
| `nexus-sim` | Deterministic simulation and replay helpers. |

## Actor Cargo Features

`nexus-actors` contains the standard in-process Drivers and Providers. A binary
can compile only the modules it needs.

The default `standard` feature builds the standard in-process Drivers and
Providers. `standard-core` builds the core standard Drivers and Providers plus
external session code; it does not build `fetch`, `fs`, `terminal`, or `mcp`.
`external-session` builds only the session handling and `SecureEnvelope` code
used by gateway adapters for external Provider and Source endpoints.

Enable `fetch`, `fs`, `terminal`, or `mcp` when the binary should register those
in-process effects. Changing these features changes which implementations are
compiled and registered. It does not change Resource, Interface, Binding, or
Operation semantics.
