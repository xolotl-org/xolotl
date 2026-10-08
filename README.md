# Xolotl

Xolotl is an embeddable Rust capability runtime for composing programs that call host-authorized tools, models, data and external services. Applications own their UI and business policy; hosts choose resources, storage, scheduling and exposure.

[中文 README](README.zh-CN.md)

> [!WARNING]
> Xolotl has not had a stable release. Its own protocols and formats currently use v1; APIs, configuration and formats may change without backward compatibility.

## Features

- **Composable programs:** write Rust graphs or portable Rust/JSON expressions with sequencing, branches, loops, parallel joins, races and lexical cleanup. An optional Plan front end accepts YAML/JSON workflow documents.
- **Reusable modules:** host-installed named continuations build subprograms from intermediate results. Native continuations and prepared portable programs can share a module; effects still go through authorized resource calls.
- **Capability-controlled resources:** install Drivers for tools, models, State or external services. Kernel checks Process grants and owned Handles, and tracks call outcome, provenance and usage.
- **Selectable execution layers:** use the allocation-free `no_std` Core, `no_std` + `alloc` portable execution or a hosted runtime. Prepared programs share immutable instructions; independent executions can reuse empty buffers.
- **Optional remote access:** expose application or Console services, connect external Providers/Sources, or enable node federation. Hosts select the exposed capabilities, routes and grants.

## Get started

The repository pins its Rust toolchain in [rust-toolchain.toml](rust-toolchain.toml).

### Embed in Rust

Run the hosted examples:

```sh
cargo run -p xolotl-sdk --features memory --example portable
cargo run -p xolotl-sdk --features memory --example native_modules
```

The [portable example](crates/xolotl-sdk/examples/portable.rs) composes a bounded loop and parallel branch, round-trips the program through JSON, then runs it with two inputs using shared instructions and reusable buffers. The [module example](crates/xolotl-sdk/examples/native_modules.rs) combines native continuations with a prepared portable program.

The SDK defaults to the allocation-free `no_std` Core. Enable `program` for portable compilation, `runtime` for cooperative execution, or `host` for hosted execution; `memory` adds an in-memory State adapter and convenience constructors. Embedding requires no daemon, listener or Console. See [Core And Portable Programs](docs/src/core-and-portable.md) for features and host ports.

For a host-supplied portable driver and scheduler without the hosted runtime, see the [`no_std` + `alloc` example](examples/portable-runtime/README.md).

### Run a configured host

`xolotld` assembles a host with Console and external gateways. Start with the example configuration:

```sh
cp xolotl.toml.example xolotl.toml
```

Before starting its redb-backed configuration:

1. Create two independent private raw 32-byte key files, with file permissions `0600`: one for Console credentials and one for external pairing credentials.
2. Replace the example paths in `console.credentials.active_key_file` and `external_credentials.key_file` with their absolute paths. Keep the keys with the database backups.
3. For non-interactive root initialization, provision credentials through `console.root.password_hash`, `console.root.password` or `console.root.pubkeys`. See [Configuration](docs/src/configuration.md) for key-file requirements and root authentication setup.

Then start the host:

```sh
cargo run -p xolotl-daemon -- up
```

The example listeners use loopback addresses. When initializing an empty Console without preseeded credentials, the daemon displays a random initial root password only when stderr is a TTY; change it after login. Listener settings and authentication details belong to [Configuration](docs/src/configuration.md) and [Console Protocol](docs/src/console-protocol.md).

### Connect a client or external service

- Application clients use profile-bound surfaces through [Application Gateway](docs/src/application-gateway.md). The daemon's gRPC entry requires the `application-grpc` feature, a profile and a listener address.
- Console clients use [Console](docs/src/console-protocol.md) for administration and optional resource execution. The example disables runtime execution; enabling it requires explicit exposure, caller authority and level-2 MFA.
- External effect handlers and event producers connect as [Providers or Sources](docs/src/external-gateway.md).
- MCP clients access explicitly published Gateway surfaces through the [MCP server adapter](docs/src/api-reference.md#mcp-publications); the host supplies its transport.

Remote clients use the exposed protocols without local Rust bindings. Swift/Kotlin **in-process embedding** needs language bindings and mobile lifecycle integration, which this repository does not yet provide. See [Gateways](docs/src/gateways.md) for available transports and listener settings.

## How it fits together

| Component | Responsibility |
| --- | --- |
| Core | Advance program control flow, cancellation and lexical cleanup using caller-owned bounded storage. |
| Kernel | Manage Process authority and owned Handles, authorize resource calls and settle resource budgets. |
| Driver | Perform admitted effects and return outcome, provenance and usage. |
| Host | Install resources, select storage and scheduling, and own task lifecycles and optional diagnostics. |
| Services and adapters | Admit clients, expose selected capabilities, and check current delivery authority at transport handoff. |

Execution belongs to one live host lifecycle. Application data can persist independently; reopening data does not restart a program. A successful program may still leave external effects unresolved: execution reports known identities separately, and unknown effects are not automatically repeated. Local capacity limits do not alone bound total host memory.

Cancellation is cooperative, not an effect rollback. Lexical cleanup runs while execution is being driven; dropping a future cannot finish asynchronous cleanup. Native Drivers and continuations are trusted host code, not sandboxed plugins.

Optional Federation connects authenticated nodes for authorized stream delivery, object reads and remote resource calls with business request/result records. Hosts supply routes, grants and application projections or merge rules. See the [architecture](docs/src/architecture.md) for ownership and composition boundaries and the [capability model](docs/src/capability-model.md) for resources and delegation.

## Documentation

- [English manual](docs/src/README.md) · [中文手册](docs/zh-CN/src/README.md): concepts and task-based guides.
- [Architecture](docs/src/architecture.md) · [Security And Boundaries](docs/src/security-and-boundaries.md): framework responsibilities and security policy.
- [Rust API Reference](docs/src/api-reference.md): public contracts, feature selection and rustdoc commands.
- [Gateways](docs/src/gateways.md) · [Console Protocol](docs/src/console-protocol.md): application, Provider/Source, management and runtime entry points.

## Development

```sh
cargo check --workspace
cargo test --workspace
```

These commands cover the default configuration; optional features need additional checks. Follow [AGENTS.md](AGENTS.md) for design ownership and validation, and [API Reference](docs/src/api-reference.md) for feature and documentation commands.

## License

MIT. See [LICENSE](LICENSE).
