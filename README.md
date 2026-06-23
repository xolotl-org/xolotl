# Xolotl

> [!WARNING]
> Xolotl is pre-v1. Runtime behavior, configuration paths, protobuf schemas,
> and gateway protocols may change without compatibility guarantees.

Xolotl is a Rust runtime for programs that need to call models, tools, state,
and external connectors without handing every caller raw access.

A caller runs as a `Process`. It opens a `Resource` such as
`effect://inference/infer` or `state://memory/alice/thread` and receives a
process-owned `Handle`. The kernel checks grants and policy, dispatches through
a `Driver` or an external Provider/Source session, and records `Fact`s for
audit, replay, and recovery.

Use `xolotld` when you want a daemon with Console, external gRPC, and external
WebSocket listeners. Use `xolotl-sdk` when another Rust program should embed the
kernel. In both cases, the application layer keeps model selection policy,
user-facing UI, and business logic outside the runtime and calls Xolotl through
resources and operations.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md)

## Features

- Resources and process-owned Handles are the access boundary for model calls,
  tools, memory, state, and external systems.
- `open()` compiles grants, policy, bindings, and driver plans before
  execution; operations run on ids and rights bitmaps.
- Child Processes receive attenuated grants. Named long-running work uses
  `ActorSpec` while remaining a Process.
- External programs enter as Provider or Source projections over gRPC or
  WebSocket, with one gateway session model for both transports.
- `xolotld` and `xolotl-sdk` use the same kernel. Hosts can replace state,
  facts, drivers, policy sources, and model backends.
- Durable programs compile to `ExecutionGraph` with shared operation boundaries
  for replay, recovery, audit, and simulation.

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

An operation follows this path:

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

The runtime has four code paths:

- Control path: registry, naming, admission, policy compilation, binding
  resolution, and `open()` handle compilation.
- Data path: fixed-cost execution over `Process`, `Handle`, `Operation`, and
  `Fact`.
- External adapters: Providers, Sources, drivers, and protocol adapters.
- Program execution: durable `Do<A>` programs and the execution graph.

## Workspace

| Crate | Purpose |
| --- | --- |
| `xolotl-types` | Core IDs, paths, values, capabilities, operations, audit types, and external Provider/Source data. |
| `xolotl-graph` | Durable `Do<A>` program IR and execution graph compiler. |
| `xolotl-state` | State backend traits and in-memory implementation. |
| `xolotl-kernel` | Process, handle, registry, policy, executor, recovery, facts. |
| `xolotl-storage-redb` | Persistent redb-backed state and FactStore. |
| `xolotl-standard` | Standard in-process Provider and Source implementations. |
| `xolotl-gateway` | Shared session admission, flow-control, taint, and audit code for external protocol adapters. |
| `xolotl-gateway-grpc` | External Provider/Source gRPC adapter using `xolotl-proto`. |
| `xolotl-gateway-websocket` | External Provider/Source WebSocket adapter. |
| `xolotl-gateway-mcp` | MCP server-side adapter for selected Gateway publications. |
| `xolotl-proto` | Protobuf schema and hand-vendored prost/tonic bindings. |
| `xolotl-console` | Gateway for Web Console management actions. |
| `xolotl-daemon` | `xolotld`, the long-running host process. |
| `xolotl-sdk` | Minimal embedded runtime facade and convenience exports. |
| `xolotl-plan`, `xolotl-sim` | Planning and simulation crates. |

`xolotl-standard` uses Cargo features to choose which modules are built. The
default `standard` feature enables the standard in-process implementations.
Embedded hosts can install a smaller module set with
`StandardConfig::with_modules` and can provide a model backend with
`StandardConfig::with_inference_backend`. Gateway crates use only
`external-session`, the shared session code for external Provider and Source
endpoints.

`xolotl-sdk` starts with a minimal in-memory kernel. Embedded hosts provide
state and facts through `XolotlBuilder`. Standard providers are opt-in through
the SDK `standard` feature or direct `xolotl-standard` installation.
`ActorSpec` is available through `xolotl-graph` and `xolotl-sdk`; the kernel can
spawn it as a named long-lived Process through `Bootstrap::spawn_actor_under` or
`Xolotl::spawn_actor`. If the body or finalizers reference process-local
`StepRef`s, pass their host functions at spawn time with
`Bootstrap::spawn_actor_under_with_steps` or `Xolotl::spawn_actor_with_steps`.
Actor declarations may use `state://process/self/...`; spawn binds it to the
concrete Process id before linting and execution.

## Build And Test

```sh
cargo fmt --all
cargo check --workspace
cargo test --workspace
```

Build the daemon:

```sh
cargo build -p xolotl-daemon
```

## Run `xolotld`

Create a local config:

```sh
cp xolotl.toml.example xolotl.toml
```

Start the daemon:

```sh
cargo run -p xolotl-daemon -- up
```

`xolotld` launches the host process. Runtime management goes through Console
WebSocket.

Default addresses from `xolotl.toml.example`:

- Console listener: `127.0.0.1:9000`
- External gRPC gateway: `127.0.0.1:9444`
- External WebSocket gateway: `127.0.0.1:9200`

`xolotl-daemon` enables `external-grpc` and `external-websocket` by default.
Each transport can be built on its own with `--no-default-features --features
external-grpc` or `--no-default-features --features external-websocket`.

On first boot, if no console root account exists and no bootstrap credentials
are configured, `xolotld` prints a one-time root password to stderr.

## Configuration

`xolotl.toml` is bootstrap configuration. It controls storage, listener bind
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
policy-managed state belong in Xolotl state and are managed through Console
WebSocket.

## External Interfaces

Detailed connection docs are in [Gateways](docs/src/gateways.md), [External
Gateway](docs/src/external-gateway.md), and [Console Protocol](docs/src/console-protocol.md).

### Console

`xolotl-console` is the gateway for Web Console management actions. HTTP covers
health and authentication. Console WebSocket handles snapshots, config
read/write/CAS, runtime inspect, subscriptions, trace/fact streams, external
program lifecycle actions, pairing actions, logout, and console
user/role/session management after login.

### External Gateway

External programs connect as Provider or Source projections. The daemon owns
session admission, generation checks, flow control, dedupe, command
idempotency, and inbound taint stamping.

External gRPC serves the Provider/Source session stream on
`[server].external_grpc_addr` or `XOLOTL_EXTERNAL_GRPC_ADDR`.

External WebSocket serves the same Provider/Source session frames on
`[server].external_websocket_addr` or `XOLOTL_EXTERNAL_WEBSOCKET_ADDR`.

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

`xolotl-gateway-mcp` exposes selected Gateway publications as MCP tools,
resources, resource templates, and prompts. Each publication references a
Gateway surface; the surface must have an explicit publish capability, and MCP
calls, reads, and prompt requests are translated into standard
capability-scoped operations. The adapter negotiates `2025-11-25` first,
keeps supported published MCP revisions available, declares completions only
for revisions that define them, and validates native MCP content blocks before
returning them.

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

## License

MIT. See [LICENSE](LICENSE).
