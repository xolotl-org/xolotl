# Configuration

`nexus.toml` is bootstrap configuration. It controls storage, listener
addresses, root bootstrap credentials, and bounded console resource limits.

Create a local config:

```sh
cp nexus.toml.example nexus.toml
```

Start the daemon:

```sh
cargo run -p nexus-daemon -- up
```

## Main Sections

`[storage]` selects redb persistent storage or in-memory storage.

`[server]` sets console, gRPC, and WebSocket bind addresses. `nexusd` also
reads `NEXUS_CONSOLE_ADDR`, `NEXUS_GRPC_ADDR`, and `NEXUS_WS_ADDR` when the
matching config field is absent. A listener stays disabled when both the config
field and environment variable are absent. The gRPC listener is available in
the default build through the `grpc` feature.

`[console.root]` can preseed root credentials.

`[console.auth]` sets session TTL, session count, and Argon2 verification
concurrency limits.

`[console.ws]` sets Console WebSocket frame, connection, idle, rate,
subscription, result-size, and event backpressure limits.

## Runtime Configuration

Runtime provider setup, model routing, groups, bindings, and policy-managed
state belong in Nexus state and are managed through the console gateway.

Console auth and WebSocket settings are deployment capacity knobs. Capability
checks, step-up gates, Origin/Host validation, path-specific admission, action
registry validation, and secret redaction remain enforced by runtime paths.
