# Nexus

Nexus is a capability runtime for model-backed applications. It maps model
inference, tool calls, memory, state, and outside systems into `effect://` and
`state://` resources so programs access them through handles compiled by
`open()`. Model backends, tool processes, and state stores remain behind
resource bindings and drivers.

Nexus supplies the execution boundary between model calls, tool execution,
long-lived state, and external protocols. Model training, application UI, and
business logic stay outside this runtime. Infer, embed, rerank, and plan are
effect resources; MCP, file, terminal, and fetch-style tools are effect
resources; extensions connect as providers or sources; program front ends lower
to execution graphs. Every access goes through the same `Resource / Interface /
Driver`, `open()` handle, and capability-check path.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md)

## Implemented Surface

- Model execution: `effect://inference/*` supports infer, embed, rerank, and
  plan; the router selects backends by capability, modality, group policy,
  retry, and fallback.
- Tool access: MCP tools, files, terminal commands, fetch, time, events, locks,
  blobs, tensors, approvals, and compression are registered as effect
  resources.
- Memory and context: the memory driver combines the state backend, vector
  index, and ranker; context assembly and compression are separate effects.
- Extensions: installed extensions project remote effects as providers or
  inbound event streams as sources.
- Capability boundary: `open()` compiles resource paths, grants, policies, and
  bindings into process-owned handles; spawned processes receive attenuated
  rights.
- Program front ends: Rust `DoNode`, Plan documents, and structured protobuf
  `Program` submissions lower to one execution graph and one executor.

## Status

This repository is an early Rust workspace for the Nexus capability runtime and
gateways. The implementation currently enforces these public compatibility
rules:

- resource path grammar rejects `@param` suffixes such as
  `effect://memory/recall@scope=user`;
- gRPC `GatewayService.Submit` accepts a structured protobuf `Program`;
- capability literals use the verb form, such as
  `perform://effect/inference/infer`; resource paths keep the `effect://...`
  shape.

## Documentation

Public manuals:

Install mdBook when needed:

```sh
cargo install mdbook
```

- English: read [docs/src/README.md](docs/src/README.md), or build with:

```sh
mdbook build docs
```

- Chinese: read [docs/zh-CN/src/README.md](docs/zh-CN/src/README.md), or build
  with:

```sh
mdbook build docs/zh-CN
```

For a local browser preview, run `mdbook serve docs` or
`mdbook serve docs/zh-CN`. The Chinese book declares `language = "zh-CN"` and
loads `docs/zh-CN/theme/cjk.css` for CJK fonts and line height.

Generate and check Rust API documentation:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Then open `target/doc/index.html` in a browser. Crate pages are under
`target/doc/<crate_name>/index.html`, with hyphens converted to underscores;
for example, `nexus-sdk` is available at `target/doc/nexus_sdk/index.html`.

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

Nexus separates the runtime into four planes:

- Control plane: registry, naming, admission, policy compilation, binding
  resolution, and `open()` handle compilation.
- Data plane: fixed-cost execution over `Process`, `Handle`, `Operation`, and
  `Fact`.
- Extension plane: external providers, sources, drivers, and protocol adapters.
- Program plane: durable `Do<A>` programs and the execution graph.

The control plane handles parsing and compilation. The data plane executes
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

`nexusd` launches the host process. Runtime management goes through the console
gateway.

Default addresses from `nexus.toml.example`:

- Console listener: `127.0.0.1:9000`
- gRPC gateway: `127.0.0.1:9100`
- Program WebSocket gateway: `127.0.0.1:9200`

On first boot, if no console root account exists and no bootstrap credentials
are configured, `nexusd` prints a one-time root password to stderr.

## Configuration

`nexus.toml` is bootstrap configuration. It controls storage, gateway listen
addresses, root bootstrap credentials, and bounded console resource limits:

- `[storage]`: `redb` persistent storage or in-memory storage.
- `[server]`: console, gRPC, and WebSocket bind addresses.
- `[console.root]`: optional preseeded root credentials.
- `[console.auth]`: session TTL, session count, and Argon2 verification
  concurrency limits.
- `[console.ws]`: Console WebSocket frame, connection, idle, rate,
  subscription, result-size, and event backpressure limits.

Runtime configuration, provider setup, model routing, groups, bindings, and
policy-managed state belong in Nexus state and are managed through the console
gateway. The console auth/WS settings are deployment capacity knobs. Capability
checks, step-up gates, Origin/Host validation, path-specific admission, action
registry validation, and secret redaction remain enforced by runtime paths.

## External Interfaces

Detailed connection docs are in the manual: [Gateways](docs/src/gateways.md),
[Program Gateways](docs/src/program-gateways.md), and
[Console Protocol](docs/src/console-protocol.md).

### Console

`nexus-console` is the management-domain gateway for Web Console. Management
actions use the same authorization, state, CAS, and audit surfaces as the rest
of the runtime. When a management action invokes a runtime effect, that effect
is a standard capability-scoped Operation.

The current interface shape is:

- HTTP: `GET /health`, `POST /api/auth/login`,
  `POST /api/auth/key/challenge`, `POST /api/auth/key/login`, and
  `POST /api/auth/step-up`.
- Console WebSocket: the post-login management path for snapshot, config
  read/write/CAS, runtime inspect, subscriptions, trace/fact streams,
  `ExtensionInstallation*` lifecycle actions, pairing actions, logout, and
  console user/role/session management.

Post-login management runs on Console WebSocket. HTTP remains the health and
authentication entry point.

### Extension Protocol

Extensions are described as one `ExtensionInstallationDef` plus one or more
single-role `ExtensionProjectionDef`s. The installation is the lifecycle,
transport, pairing, credential, and shared-config unit. Projection roles are
Provider, which exposes `effect://...` capabilities through remote Bindings,
and Source, which emits inbound events into a declared state stream.

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
`installation_id`; secrets stay on the one-shot display edge. Operation input,
state, Facts, and traces receive only redacted metadata or references.

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
standard gateway submissions.

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
  control plane.
- Keep the data plane limited to compiled IDs, handles, driver plans, policy
  snapshots, operations, outcomes, and facts.
- External protocol crates should remain thin adapters over `nexus-gateway` or
  the kernel extension registration/runtime surfaces.
- Breaking runtime or protocol changes should update proto, vendored bindings, conversions,
  tests, and docs in the same change.

## License

MIT. See [LICENSE](LICENSE).
