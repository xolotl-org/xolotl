# Nexus

Nexus is an AI identity runtime: a microkernel for capability-bound effects,
durable program execution, and audited external integrations.

The kernel has one active entity, `Process`. A process holds compiled
capability handles, issues operations against resources, runs them through
drivers under policy, and records the result as facts. Files, terminal actions,
models, memory, remote devices, long-lived state, and external tools are all
projected through the same `Resource / Interface / Driver` model.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md)

## Status

This repository is an early Rust workspace for the Nexus runtime and gateways.
The implementation intentionally tracks the current design only. Old path
parameters and older wire shortcuts are not compatibility surfaces:

- resource paths do not support `@param` suffixes such as
  `effect://memory/recall@scope=user`;
- gRPC `GatewayService.Submit` accepts a structured protobuf `Program`, not a
  JSON string;
- capability literals use the verb form, such as
  `perform://effect/inference/infer`, rather than resource paths.

## Architecture

The hot path is deliberately small:

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

The design separates the runtime into four planes:

- Control plane: registry, naming, admission, policy compilation, binding
  resolution, and `open()` handle compilation.
- Data plane: fixed-cost execution over `Process`, `Handle`, `Operation`, and
  `Fact`.
- Extension plane: external providers, sources, drivers, and protocol adapters.
- Program plane: durable `Do<A>` programs and the execution graph.

The control plane handles parsing and compilation. The data plane only executes
compiled objects.

## Workspace

| Crate | Purpose |
| --- | --- |
| `nexus-types` | Core IDs, paths, values, capabilities, operations, audit types. |
| `nexus-graph` | Durable `Do<A>` program IR and execution graph compiler. |
| `nexus-state` | State backend traits and in-memory implementation. |
| `nexus-kernel` | Process, handle, registry, policy, executor, recovery, facts. |
| `nexus-storage-redb` | Persistent redb-backed state and FactStore. |
| `nexus-actors` | Standard in-process drivers and providers. |
| `nexus-gateway` | Shared gateway abstraction over submitted programs. |
| `nexus-gateway-grpc` | gRPC `GatewayService` adapter using `nexus-proto`. |
| `nexus-gateway-websocket` | WebSocket gateway adapter. |
| `nexus-gateway-mcp` | MCP server-side gateway adapter. |
| `nexus-proto` | Protobuf schema and hand-vendored prost/tonic bindings. |
| `nexus-console` | HTTP management gateway for the web console backend. |
| `nexus-daemon` | `nexusd`, the long-running host process. |
| `nexus-sdk` | Convenience exports for embedding and tests. |
| `nexus-plan`, `nexus-sim` | Planning and simulation scaffolding. |

## Requirements

- Rust 1.95 or newer.
- Cargo from the matching stable toolchain.
- No local `protoc` installation is required. `nexus-proto` ships vendored
  prost/tonic Rust bindings.

Check the local toolchain:

```sh
cargo --version
```

## Build And Test

```sh
cargo fmt --all
cargo check --workspace
cargo test --workspace
```

Build the daemon:

```sh
cargo build -p nexus-daemon
```

## Run `nexusd`

Create a local config:

```sh
cp nexus.toml.example nexus.toml
```

Start the daemon:

```sh
cargo run -p nexus-daemon -- up
```

`nexusd` is a launcher only. Runtime management is handled by the console
gateway, not by daemon subcommands.

Default addresses from `nexus.toml.example`:

- Console HTTP: `127.0.0.1:9000`
- gRPC gateway: `127.0.0.1:9100`
- WebSocket gateway: `127.0.0.1:9200`

On first boot, if no console root account exists and no bootstrap credentials
are configured, `nexusd` prints a one-time root password to stderr.

## Configuration

`nexus.toml` is bootstrap-only configuration. It controls storage and gateway
listen addresses:

- `[storage]`: `redb` persistent storage or in-memory storage.
- `[server]`: console, gRPC, and WebSocket bind addresses.
- `[console.root]`: optional preseeded root credentials.

Runtime configuration, provider setup, model routing, groups, bindings, and
policy-managed state belong in Nexus state and are managed through the console
gateway.

## External Interfaces

### Console

`nexus-console` exposes the management-domain HTTP gateway:

- `GET /health`
- `POST /api/auth/login`
- `POST /api/auth/key/challenge`
- `POST /api/auth/key/login`
- `POST /api/auth/logout`
- `GET /api/inspect?path=...`
- `GET /api/inspect?path=...&prefix=true`
- `POST /api/config`

Console operations still go through capability-bound management paths. The
console is not a privileged side channel.

### gRPC And Proto

The primary external program submission API is `GatewayService` in
`crates/nexus-proto/proto/nexus/v1/gateway.proto`.

```proto
service GatewayService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

`SubmitRequest.program` is a structured protobuf `Program`. It is not a JSON
blob and there is no `program_json` compatibility field.

`nexus-proto` is the wire schema source for Rust gateway code and for generated
clients such as mobile Kotlin/Swift packages.

### WebSocket

`nexus-gateway-websocket` serves `/ws` and adapts WebSocket frames to the shared
gateway abstraction. It is a protocol adapter over the same request process,
taint, policy, fact, and handle path.

### MCP

`nexus-gateway-mcp` exposes selected Nexus effects as MCP tools only when each
tool is bound to an explicit required capability. MCP calls are translated into
ordinary gateway submissions.

## Path And Capability Rules

Resource paths use this shape:

```text
path://[cluster/]<scheme>/<segment>[/<segment>...]
```

Examples:

```text
effect://inference/infer
state://memory/alice/thread
process://alice
```

Capability literals use verb schemes:

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
```

Path parameters are rejected. Use structured values, explicit resource
segments, or policy/config state instead of `@param` suffixes.

## Development Notes

- Keep parsing, discovery, policy source handling, and schema work in the
  control plane.
- Keep the data plane limited to compiled IDs, handles, driver plans, policy
  snapshots, operations, outcomes, and facts.
- External protocol crates should remain thin adapters over `nexus-gateway` or
  kernel extension primitives.
- Breaking design changes should update proto, vendored bindings, conversions,
  tests, and docs in the same change.

## License

MIT. See [LICENSE](LICENSE).
