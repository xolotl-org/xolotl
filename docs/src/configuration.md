# Configuration

`xolotl.toml` is bootstrap configuration. It controls storage, listener
addresses, root bootstrap credentials, external gateway limits, console
resource limits, and transport-security settings.

Create a local config:

```sh
cp xolotl.toml.example xolotl.toml
```

Start the daemon:

```sh
cargo run -p xolotl-daemon -- up
```

## Main Sections

| Section | Purpose |
| --- | --- |
| `[storage]` | Select redb persistent storage or in-memory storage. |
| `[server]` | Bind listeners with `console_addr`, `application_grpc_addr`, `external_grpc_addr`, and `external_websocket_addr`. |
| `[application_gateway]` | Select the State profile and application gRPC frame, upload/output concurrency, resident output and wait windows. |
| `[external_gateway.grpc]` | Set Provider/Source session limits for the external gRPC listener. |
| `[external_gateway.websocket]` | Set the same Provider/Source session limits for the external WebSocket listener. |
| `[external_gateway.websocket.transport]` | Set WebSocket frame size, first-frame timeout, idle timeout, and connection count. |
| `[console.root]` | Preseed root credentials. |
| `[console.auth]` | Set session TTL, session count, and Argon2 verification concurrency. |
| `[console.ws]` | Set Console WebSocket frame, connection, idle, rate, subscription, result-size, encoded event queue, and all-frame send limits. |

`xolotld` also reads `XOLOTL_CONSOLE_ADDR`, `XOLOTL_EXTERNAL_GRPC_ADDR`, and
`XOLOTL_EXTERNAL_WEBSOCKET_ADDR`, plus `XOLOTL_APPLICATION_GRPC_ADDR`, when the matching `[server]` field is absent. A
listener stays disabled when both the config field and environment variable are
absent.

The application listener requires the optional `application-grpc` feature.
Provision its profile through Console before enabling the address; see
[Application Gateway](application-gateway.md) for the complete configuration and
upload protocol.

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
provider_max_inline_result_bytes = 65536
source_max_in_flight_commands = 1024
source_command_max_inline_result_bytes = 65536
source_command_rate_limit_window_ms = 60000
source_command_rate_limit_max = 600

[external_gateway.websocket]
source_dedupe_window_ms = 86400000
provider_max_in_flight_invocations = 1024
provider_max_in_flight_per_identity = 256
provider_max_in_flight_per_effect = 256
provider_max_inline_result_bytes = 65536
source_max_in_flight_commands = 1024
source_command_max_inline_result_bytes = 65536
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
`provider_max_inline_result_bytes` bounds inline Provider success and error
results.

`source_max_in_flight_commands`,
`source_command_rate_limit_window_ms`, and
`source_command_rate_limit_max` bound outbound command dispatch per ready
Source session and per Source projection.
`source_command_max_inline_result_bytes` bounds inline Source command success
and error results.

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
# certificate_chain_path = "/etc/xolotl/external-grpc-cert.pem"
# private_key_path = "/etc/xolotl/external-grpc-key.pem"
# client_trust_roots = ["/etc/xolotl/external-client-ca.pem"]
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
policy-managed state belong in Xolotl state and are managed through Console
WebSocket actions.
External projections are part of each installation declaration. External
declarations use `external.*`; inference declarations use `inference.*`;
in-process projection declarations use `config.*` under
`state://kernel/projections/in-process/<id>`. Generic `config.*` actions reject
runtime config paths that have a dedicated action family.

`xolotl-standard` Cargo features decide which in-process implementations are
compiled into the host binary. Optional in-process projection declarations live under
`state://kernel/projections/in-process/<id>`. Reconcile status is written under
`state://kernel/projection-status/in-process/<id>` and is read through
`projection.in_process.status.*`; it separates the desired declaration version
from the active registry version.
Embedded hosts can also choose which compiled standard-core modules are
installed with `StandardConfig::with_modules`; compiled code is not exposed as a
Resource until the host installs it.

HTTP inference providers are compiled only when the host binary enables the
matching `xolotl-standard` feature. Runtime declarations live under
`state://kernel/inference/*` and `state://kernel/routing/inference`; backend
records store secret references such as
`state://vault/inference/<backend>/api_key`, not raw API keys.

`InferenceBackendDef.io_window_bytes` selects the encoded request and parsing
work window; it defaults to 16,384 bytes and accepts any positive value. One-byte
windows support split UTF-8 scalars and JSON escapes. This window does not limit
request size, response size or SSE event size. Output channel windows remain a
separate `StreamWindow` setting, and the HTTP library owns its transport buffers.
After record validation, selected text is emitted in chunks up to this window,
preserving complete UTF-8 scalars (up to four bytes even with a smaller window).
The output channel charges the encoded chunk and its provenance metadata.

`response_limits` makes result materialization policy explicit:

- `max_materialized_bytes`: simultaneously retained selected text and numeric
  token bytes in one unary response or atomic SSE record.
- `max_materialized_nodes`: retained selected value nodes, including empty values.
- `max_json_frames`: simultaneously open JSON containers, including skipped data.

Every limit is optional; unset fields impose no corresponding quota. The byte
and node counts are logical admission units, not an allocator or process RSS
bound. Known control tags and schema keys add fixed storage outside the selected
token-byte count. Unary output and each atomic selected SSE delta still need resident
storage; applications can admit those results explicitly without imposing a
cumulative task-size limit. Unused provider fields are validated incrementally
and never collected into a complete JSON envelope. In particular, OpenAI
Responses completion snapshots do not retain the repeated output text.

SSE dispatch requires a complete record and valid JSON before any selected delta
from that record is emitted. A late error or malformed suffix cannot publish an
earlier prefix from the same record. The parser removes exactly one initial
UTF-8 BOM and validates skipped data as well as selected data. The adapters keep
their declared delta semantics; repeated text is not guessed to be a cumulative
snapshot.
HTTP error diagnostics use a fixed 8 KiB read prefix and at most 512 redacted
display characters, independent of successful response admission. Reaching the
prefix bound stops reading without waiting for the server to close its body.
A server that stalls before that point still requires request cancellation or
a client timeout; a byte bound does not impose a response-duration policy.

Embedded hosts install object capabilities explicitly with
`StandardConfig::with_object_store`. `ObjectStore` accepts independent read,
write, and delete adapters; `xolotl-storage-fs::FileObjectStore::open(root)`
provides a file-backed implementation. Large unary Fetch and filesystem outputs,
Blob writes, and Tensor writes require an object writer. Blob reads and deletes
require their corresponding ports. Streamed Fetch and filesystem reads can run
without object storage.

Console auth, WebSocket, and transport-security fields are deployment settings.
Capability checks, step-up gates, path-specific admission, action registry
validation, and secret redaction remain enforced by runtime paths.
