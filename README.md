# Nexus

Nexus is a capability runtime for model-backed applications. It maps model
inference, tool calls, memory, state, and outside systems into `effect://` and
`state://` resources so programs access them through handles compiled by
`open()`. Model backends, tool processes, state stores, and external programs
remain behind resource bindings, drivers, or Provider/Source projections.

Nexus supplies the execution boundary between model calls, tool execution,
long-lived state, and external protocols. Model training, application UI, and
business logic stay outside this runtime. Every access goes through the same
`Resource / Interface / Driver`, `open()` handle, and capability-check path.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md)

## Implemented Features

- Model execution: `effect://inference/*` supports infer, embed, rerank, and
  plan. Model routing selects backends by capability, modality, group policy,
  retry, and fallback.
- Tool access: MCP tools, files, terminal commands, fetch, time, events, locks,
  blobs, tensors, approvals, and compression are registered as effect resources.
- Memory and context: the memory driver combines the state backend, vector
  index, and ranker; context assembly and compression are separate effects.
- External programs: external programs connect as Provider or Source
  projections through the external gateway.
- Capability boundary: `open()` compiles resource paths, grants, policies, and
  bindings into process-owned handles; spawned processes receive attenuated
  rights.
- Program execution: Rust `DoNode`, Plan documents, and the protobuf `Program`
  AST lower to one execution graph and one executor.

## Status

The core runtime and the external Provider/Source gateway are implemented.
Nexus has not shipped a first release, and the current gateway/config/protobuf
contract is defined by the external Provider/Source model.

External access has one role model:

- Provider projections expose remote effect handlers.
- Source projections emit inbound events and can receive outbound commands.
- gRPC and WebSocket are transport implementations for the same external
  Provider/Source gateway.

MCP publishes selected Gateway publications as tools, resources, resource
templates, and prompts. MCP requests are submitted through the same Gateway
surfaces as other protocol adapters.

## Documentation

Public manuals:

```sh
cargo install mdbook
mdbook build docs
mdbook build docs/zh-CN
```

- English: [docs/src/README.md](docs/src/README.md)
- Chinese: [docs/zh-CN/src/README.md](docs/zh-CN/src/README.md)

For a local browser preview, run `mdbook serve docs` or
`mdbook serve docs/zh-CN`.

Generate Rust API documentation:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Rustdoc output is written to `target/doc/index.html`.

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

Nexus separates the runtime into four code paths:

- Control path: registry, naming, admission, policy compilation, binding
  resolution, and `open()` handle compilation.
- Data path: fixed-cost execution over `Process`, `Handle`, `Operation`, and
  `Fact`.
- External adapters: Providers, Sources, drivers, and protocol adapters.
- Program execution: durable `Do<A>` programs and the execution graph.

## Workspace

| Crate | Purpose |
| --- | --- |
| `nexus-types` | Core IDs, paths, values, capabilities, operations, audit types, and external Provider/Source data. |
| `nexus-graph` | Durable `Do<A>` program IR and execution graph compiler. |
| `nexus-state` | State backend traits and in-memory implementation. |
| `nexus-kernel` | Process, handle, registry, policy, executor, recovery, facts. |
| `nexus-storage-redb` | Persistent redb-backed state and FactStore. |
| `nexus-standard` | Standard in-process Provider and Source implementations. |
| `nexus-gateway` | Shared session admission, flow-control, taint, and audit code for external protocol adapters. |
| `nexus-gateway-grpc` | External Provider/Source gRPC adapter using `nexus-proto`. |
| `nexus-gateway-websocket` | External Provider/Source WebSocket adapter. |
| `nexus-gateway-mcp` | MCP server-side adapter for selected Gateway publications. |
| `nexus-proto` | Protobuf schema and hand-vendored prost/tonic bindings. |
| `nexus-console` | Gateway for Web Console management actions. |
| `nexus-daemon` | `nexusd`, the long-running host process. |
| `nexus-sdk` | Convenience exports for embedding and tests. |
| `nexus-plan`, `nexus-sim` | Planning and simulation crates. |

`nexus-standard` uses Cargo features to choose which modules are built. The
default `standard` feature builds the standard in-process implementations.
Gateway crates use only `external-session`, which contains session
handling for external Provider and Source endpoints.

## Requirements

- Rust 1.95 or newer.
- Cargo from the matching stable toolchain.
- No local `protoc` installation is required. `nexus-proto` includes vendored
  prost/tonic Rust bindings.

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

`nexusd` launches the host process. Runtime management goes through Console
WebSocket.

Default addresses from `nexus.toml.example`:

- Console listener: `127.0.0.1:9000`
- External gRPC gateway: `127.0.0.1:9444`
- External WebSocket gateway: `127.0.0.1:9200`

`nexus-daemon` enables `external-grpc` and `external-websocket` by default.
Each transport can be built on its own with `--no-default-features --features
external-grpc` or `--no-default-features --features external-websocket`.

On first boot, if no console root account exists and no bootstrap credentials
are configured, `nexusd` prints a one-time root password to stderr.

## Configuration

`nexus.toml` is bootstrap configuration. It controls storage, listener bind
addresses, root bootstrap credentials, external gateway limits, gateway
transport-security settings, and Console resource limits.

- `[server]`: Console, external gRPC, and external WebSocket bind addresses.
- `[external_gateway.grpc]`: Provider/Source session limits for external gRPC.
- `[external_gateway.grpc.transport_security]`: external gRPC transport
  boundary.
- `[external_gateway.websocket]`: Provider/Source session limits for external
  WebSocket.
- `[external_gateway.websocket.transport]`: WebSocket frame, idle, first-frame,
  and connection limits.
- `[external_gateway.websocket.transport_security]`: external WebSocket plain
  listener boundary.
- `[console.*]`: console root credentials, auth/session limits, WebSocket
  limits, and transport security.

Runtime configuration, provider setup, model routing, groups, bindings, external
program installations, Provider projections, Source projections, and
policy-managed state belong in Nexus state and are managed through Console
WebSocket.

## External Interfaces

Detailed connection docs are in [Gateways](docs/src/gateways.md), [External
Gateway](docs/src/external-gateway.md), and [Console Protocol](docs/src/console-protocol.md).

### Console

`nexus-console` is the gateway for Web Console management actions. HTTP covers
health and authentication. Console WebSocket handles snapshots, config
read/write/CAS, runtime inspect, subscriptions, trace/fact streams, external
program lifecycle actions, pairing actions, logout, and console
user/role/session management after login.

### External Gateway

External programs connect as Provider or Source projections. The daemon owns
session admission, generation checks, flow control, dedupe, command
idempotency, and inbound taint stamping.

External gRPC serves the Provider/Source session stream on
`[server].external_grpc_addr` or `NEXUS_EXTERNAL_GRPC_ADDR`.

External WebSocket serves the same Provider/Source session frames on
`[server].external_websocket_addr` or `NEXUS_EXTERNAL_WEBSOCKET_ADDR`.

Control state uses these prefixes:

```text
state://kernel/external-installations/<installation_id>
state://kernel/external-pairings/<pairing_id>
state://kernel/external-sessions/<installation_id>/<role>
state://kernel/external-credential-revocations/<installation_id>
```

Provider/Source projections are embedded in each external installation
declaration.

### MCP

`nexus-gateway-mcp` exposes selected Gateway publications as MCP tools,
resources, resource templates, and prompts. Each publication references a
Gateway surface; the surface must have an explicit publish capability, and MCP
calls, reads, and prompt requests are translated into standard
capability-scoped operations. The adapter negotiates `2025-11-25` first,
supports completions from publication properties, and validates native MCP
content blocks before returning them.

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

Path parameters are rejected. Put options in structured values, explicit
resource segments, or policy/config state.

## Development Notes

- Keep parsing, discovery, policy source handling, and schema work in the
  control path.
- Keep the data path limited to compiled IDs, handles, driver plans, policy
  snapshots, operations, outcomes, and facts.
- External protocol crates should remain thin adapters over the gateway,
  console, or kernel runtime APIs.
- Protocol changes should update proto, vendored bindings, conversions, tests,
  examples, and public docs in the same change.

## License

MIT. See [LICENSE](LICENSE).
