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

The runtime is split into four planes.

## Control Plane

The control plane parses, validates, resolves, and compiles. It owns registries,
resource naming, admission checks, policy compilation, binding resolution, and
`open()` handle compilation.

The key rule is that parsing and registry walking happen before the data plane.
Once a Process owns a Handle, the data plane can execute against compiled ids,
rights bitmaps, driver plans, and policy snapshots.

## Data Plane

The data plane executes one Operation through a compiled Handle. It checks
ownership, handle liveness, rights, residual policy if needed, dispatches the
DriverPlan, and records a Fact when the operation must be durable.

The data plane receives compiled ids, rights bitmaps, driver plans, and policy
snapshots.

## Extension Plane

The extension plane projects outside systems into the same runtime model.
Providers expose `effect://...` resources through Drivers or remote bindings.
Sources write inbound events into declared state streams. Protocol-specific
adapters stay thin and translate their transport into the shared runtime model.

## Program Plane

The program plane represents durable work. `DoNode` is the executable program
shape; Plan documents and structured protobuf `Program` submissions lower to
`DoNode`. The Executor compiles `DoNode` into `ExecutionGraph`, advances graph
nodes, issues Operations, runs named pure Steps, and resumes from recorded Facts
during recovery.

## Workspace Map

| Crate | Role |
| --- | --- |
| `nexus-types` | Core ids, paths, values, capabilities, operations, audit, trace, extension, and process data. |
| `nexus-graph` | `DoNode`, `ExecutionGraph`, graph compiler, cursor, and actor linting. |
| `nexus-state` | State backend trait and in-memory implementation. |
| `nexus-kernel` | Registry, policy, handle table, data plane, executor, process table, recovery, and bootstrap. |
| `nexus-storage-redb` | redb-backed state and fact storage. |
| `nexus-actors` | Standard in-process Drivers and Providers. |
| `nexus-gateway` | Shared gateway trait and in-process request gateway. |
| `nexus-gateway-grpc` | gRPC adapter over the shared gateway. |
| `nexus-gateway-websocket` | Program-submission WebSocket adapter. |
| `nexus-gateway-mcp` | MCP server-side gateway adapter. |
| `nexus-proto` | Protobuf schema and vendored Rust bindings. |
| `nexus-console` | Management-domain gateway for the web console backend. |
| `nexus-daemon` | `nexusd`, the long-running host process. |
| `nexus-sdk` | Embedded facade and public re-exports. |
| `nexus-plan` | Plan document parsing and lowering. |
| `nexus-sim` | Deterministic simulation and replay helpers. |
