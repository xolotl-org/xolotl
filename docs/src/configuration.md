# Configuration

`nexus.toml` is bootstrap configuration. It controls storage, listener
addresses, root bootstrap credentials, external gateway limits, console
resource limits, and transport-security settings.

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

`[server]` sets listener bind addresses:

- `console_addr`
- `external_grpc_addr`
- `external_websocket_addr`

`nexusd` also reads `NEXUS_CONSOLE_ADDR`, `NEXUS_EXTERNAL_GRPC_ADDR`,
and `NEXUS_EXTERNAL_WEBSOCKET_ADDR` when the matching config field is absent. A
listener stays disabled when both the config field and environment variable are
absent.

`[external_gateway.grpc]` configures Provider/Source session limits for the
external gRPC listener.

`[external_gateway.websocket]` configures the same Provider/Source session
limits for the external WebSocket listener.

`[external_gateway.websocket.transport]` configures WebSocket frame size,
first-frame timeout, idle timeout, and total connection count.

`[console.root]` can preseed root credentials.

`[console.auth]` sets session TTL, session count, and Argon2 verification
concurrency limits.

`[console.ws]` sets Console WebSocket frame, connection, idle, rate,
subscription, result-size, and event backpressure limits.

## External Gateway

External gRPC and external WebSocket serve the same Provider/Source session
protocol:

```toml
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway.grpc]
source_dedupe_window_ms = 86400000
provider_max_in_flight_invocations = 1024
provider_max_in_flight_per_identity = 256
provider_max_in_flight_per_effect = 256
source_max_in_flight_commands = 1024
source_command_rate_limit_window_ms = 60000
source_command_rate_limit_max = 600

[external_gateway.websocket]
source_dedupe_window_ms = 86400000
provider_max_in_flight_invocations = 1024
provider_max_in_flight_per_identity = 256
provider_max_in_flight_per_effect = 256
source_max_in_flight_commands = 1024
source_command_rate_limit_window_ms = 60000
source_command_rate_limit_max = 600

[external_gateway.websocket.transport]
max_frame_bytes = 1048576
first_frame_timeout_ms = 10000
idle_timeout_ms = 300000
max_connections = 256
```

`source_dedupe_window_ms` bounds Source event id dedupe retention and Source
outbound command idempotency retention after result, deadline, or session
drain.

`provider_max_in_flight_invocations`,
`provider_max_in_flight_per_identity`, and
`provider_max_in_flight_per_effect` bound pending Provider invokes per ready
Provider session.

`source_max_in_flight_commands`,
`source_command_rate_limit_window_ms`, and
`source_command_rate_limit_max` bound outbound command dispatch per ready
Source session and per Source projection.

Source event payload-size limits, stream capacity, overflow behavior, and
event-ingress rate limits are declared on each Source projection.

## Transport Security

External gRPC transport security:

```toml
[external_gateway.grpc.transport_security]
mode = "local_trusted"
# trusted_proxy_peers = ["127.0.0.1"]
# honor_x_forwarded_proto = true
# honor_x_forwarded_host = true
# honor_x_forwarded_for = true
# certificate_chain_path = "/etc/nexus/external-grpc-cert.pem"
# private_key_path = "/etc/nexus/external-grpc-key.pem"
# client_trust_roots = ["/etc/nexus/external-client-ca.pem"]
# unsafe_relaxations = ["ignore_origin_port"]
```

External gRPC supports `production_tls`, `mtls`, `trusted_reverse_proxy`,
`local_trusted`, `unsafe_plaintext`, and `disabled_for_test`.
`production_tls` requires `certificate_chain_path` and `private_key_path`.
`mtls` additionally requires `client_trust_roots`.
`trusted_reverse_proxy` requires `trusted_proxy_peers`; forwarded headers are
used only when the direct peer is trusted.

External WebSocket transport security:

```toml
[external_gateway.websocket.transport_security]
mode = "local_trusted"
# trusted_proxy_peers = ["127.0.0.1"]
# honor_x_forwarded_proto = true
# honor_x_forwarded_host = true
# honor_x_forwarded_for = true
# unsafe_relaxations = ["ignore_origin_port"]
```

External WebSocket is a plain listener. Use `trusted_reverse_proxy` for
external TLS termination, `local_trusted` for loopback-only deployments, or
explicit `unsafe_plaintext`. `production_tls` and `mtls` fail closed for this
listener.

Console transport security is configured separately:

```toml
[console.transport_security]
mode = "local_trusted"
```

The daemon console listener is currently a plain listener. Use `local_trusted`
only with a loopback `console_addr`, or use `trusted_reverse_proxy` when TLS
terminates at a trusted front proxy and `trusted_proxy_peers` lists the direct
proxy peer addresses. `production_tls` fails closed for this listener until
daemon-owned console TLS material is configured.

## Runtime Configuration

Runtime provider setup, model routing, groups, bindings, in-process Provider or
Source projection declarations, external Provider/Source installation declarations, and
policy-managed state belong in Nexus state and are managed through Console
WebSocket actions.
External projections are part of each installation declaration. External
declarations use `external.*`; inference declarations use `inference.*`;
in-process projection declarations use `config.*` under
`state://kernel/projections/in-process/<id>`. Generic `config.*` actions reject
runtime config paths that have a dedicated action family.

`nexus-standard` Cargo features decide which in-process implementations are
compiled into the host binary. Optional in-process projection declarations live under
`state://kernel/projections/in-process/<id>`. Reconcile status is written under
`state://kernel/projection-status/in-process/<id>` and is read through
`projection.in_process.status.*`; it separates the desired declaration version
from the active registry version.
Embedded hosts can also choose which compiled standard-core modules are
installed with `StandardConfig::with_modules`; compiled code is not exposed as a
Resource until the host installs it.

HTTP inference providers are compiled only when the host binary enables the
matching `nexus-standard` feature. Runtime declarations live under
`state://kernel/inference/*` and `state://kernel/routing/inference`; backend
records store secret references such as
`state://vault/inference/<backend>/api_key`, not raw API keys.

Console auth, WebSocket, and transport-security fields are deployment settings.
Capability checks, step-up gates, path-specific admission, action registry
validation, and secret redaction remain enforced by runtime paths.
