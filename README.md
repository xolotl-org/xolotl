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
The implementation tracks the current design:

- resource paths do not support `@param` suffixes such as
  `effect://memory/recall@scope=user`;
- gRPC `GatewayService.Submit` accepts a structured protobuf `Program`;
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
| `nexus-console` | Management-domain gateway for the web console backend. HTTP covers bootstrap/auth only; Console WS is the post-login management path. |
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

- Console listener: `127.0.0.1:9000`
- gRPC gateway: `127.0.0.1:9100`
- Program WebSocket gateway: `127.0.0.1:9200`

On first boot, if no console root account exists and no bootstrap credentials
are configured, `nexusd` prints a one-time root password to stderr.

## Configuration

`nexus.toml` is bootstrap-only configuration. It controls storage, gateway
listen addresses, root bootstrap credentials, and bounded console resource
limits:

- `[storage]`: `redb` persistent storage or in-memory storage.
- `[server]`: console, gRPC, and WebSocket bind addresses.
- `[console.root]`: optional preseeded root credentials.
- `[console.auth]`: session TTL, session count, and Argon2 verification
  concurrency limits.
- `[console.ws]`: Console WebSocket frame, connection, idle, rate,
  subscription, result-size, and event backpressure limits.

Runtime configuration, provider setup, model routing, groups, bindings, and
policy-managed state belong in Nexus state and are managed through the console
gateway. The console auth/WS settings are deployment capacity knobs only; they
do not disable capability checks, step-up gates, Origin/Host validation,
path-specific admission, action registry validation, or secret redaction.

## External Interfaces

### Console

`nexus-console` is the management-domain gateway for Web Console. It is not a
privileged side channel: management actions still become capability-bound
Operations with admission, authorization, CAS, and audit.

The current interface shape is:

- HTTP: `GET /health`, `POST /api/auth/login`,
  `POST /api/auth/key/challenge`, `POST /api/auth/key/login`, and
  `POST /api/auth/step-up`.
- Console WebSocket: the post-login management path for snapshot, config
  read/write/CAS, runtime inspect, subscriptions, trace/fact streams,
  `ExtensionInstallation*` lifecycle actions, pairing actions, logout, and
  console user/role/session management.

Post-login management features belong on Console WebSocket, not HTTP.

### Extension Protocol

Extensions are described as one `ExtensionInstallationDef` plus one or more
single-role `ExtensionProjectionDef`s. The installation is the lifecycle,
transport, pairing, credential, and shared-config unit. Each projection is
either a Provider, which exposes `effect://...` capabilities through remote
Bindings, or a Source, which emits inbound events into a declared state stream.

Control state uses these prefixes:

```text
state://kernel/extension-installations/<installation_id>
state://kernel/extension-projections/<installation_id>/<projection_id>
state://kernel/extension-pairings/<pairing_id>
state://kernel/extension-sessions/<installation_id>/<role>
state://kernel/extension-revocations/<installation_id>
```

Out-of-process extensions connect with the extension gRPC/WebSocket protocol:
`RoleSessionClientHello { installation_id, projection_id, ... }`,
daemon-selected `SessionContext`, `RoleReady`, AEAD-protected business/control
frames, and Provider `Invoke` / Source `InboundEvent` frames. Pairing inputs use
`installation_id`; secrets stay on the one-shot display edge and do not enter
Operation input, state, Facts, or traces.

### gRPC And Proto

The primary external program submission API is `GatewayService` in
`crates/nexus-proto/proto/nexus/v1/gateway.proto`.

```proto
service GatewayService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

`SubmitRequest.program` is a structured protobuf `Program`.

`nexus-proto` is the wire schema source for Rust gateway code and for generated
clients such as mobile Kotlin/Swift packages.

### WebSocket

`nexus-gateway-websocket` serves the program-submission WebSocket gateway and
adapts WebSocket frames to the shared gateway abstraction. It is separate from
the Console WebSocket described above, and it uses the same request process,
taint, policy, fact, and handle path as other program gateways.

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
