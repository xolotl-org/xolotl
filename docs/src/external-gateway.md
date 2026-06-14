# External Gateway

The external gateway connects out-of-process programs to Nexus as Provider or
Source projections. gRPC and WebSocket are transport implementations for the
same session protocol.

## Roles

Provider sessions expose remote effect handlers. A ready Provider reports the
projected effects it can serve; the daemon registers those bindings for that
ready session and dispatches invocations only for registered effects.

Source sessions emit inbound events and can receive outbound commands from the
daemon. Source events enter the same schema, policy, capacity, dedupe, and taint
paths regardless of whether they arrive over gRPC or WebSocket.

Provider and Source are the only external projection roles.

## Transports

External gRPC listens on `[server].external_grpc_addr` or
`NEXUS_EXTERNAL_GRPC_ADDR` and serves
`nexus.v1.external.ExternalService.Session`.

External WebSocket listens on `[server].external_websocket_addr` or
`NEXUS_EXTERNAL_WEBSOCKET_ADDR` and serves the same logical session frames over
`/ws`.

Both transports use the same daemon-side session handler and the same
Provider/Source admission state.

## Configuration

`[external_gateway.grpc]` and `[external_gateway.websocket]` share the same
Provider/Source limit keys:

```toml
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
```

`source_dedupe_window_ms` bounds Source event id dedupe retention and Source
outbound command idempotency retention after result, deadline, or session drain.

Provider in-flight caps apply per ready Provider session, per acting identity
inside that session, and per effect path inside that session.

Source command caps apply per ready Source session. The command rate limit
applies per Source projection.

Source event payload-size limits, stream capacity, overflow behavior, and
event-ingress rate limits are declared on each Source projection.

## WebSocket Transport Limits

External WebSocket has transport-level limits:

```toml
[external_gateway.websocket.transport]
max_frame_bytes = 1048576
first_frame_timeout_ms = 10000
idle_timeout_ms = 300000
max_connections = 256
```

These values are clamped by `nexus-gateway-websocket` before the listener
starts.

## Transport Security

External gRPC supports `production_tls`, `mtls`, `trusted_reverse_proxy`,
`local_trusted`, `unsafe_plaintext`, and `disabled_for_test`.

External WebSocket is a plain listener. Use `trusted_reverse_proxy` for external
TLS termination, `local_trusted` for loopback-only deployments, or
`unsafe_plaintext` only when the deployment explicitly accepts plaintext.
`production_tls` and `mtls` fail closed for the WebSocket listener.

## Session State

Approved session state is read from:

```text
state://kernel/external-sessions/<installation_id>/<role>
```

The session record must match the connecting installation id and role. The
daemon rejects missing, mismatched, revoked, or non-ready session records before
business frames can flow.

## Provider Flow

Provider invokes are sent only for projected effects reported by the ready
session, and invoke input must match the Provider projection's `input_schema`.
Provider results are accepted only for daemon-registered in-flight invocations.
The result must arrive on the same ready Provider session generation before the
invocation deadline and within the registered result size limit.

When an invocation deadline expires, the daemon sends a best-effort
`ProviderCancel` control frame before releasing the pending invocation locally.
This is cooperative cancellation; it does not promise to undo external effects
that already happened.

## Source Flow

Source events are admitted only after the session is ready and generation fields
match the daemon-selected context. Event ids are deduped in state with a fixed
retention window.

Events that carry both `stream_id` and `seq` are appended only in stream-local
sequence order. Duplicate event ids return duplicate acknowledgements only
after the first append has committed. A retry that arrives while the original
event is still pending is rejected as backpressured.

Source projections that enable outbound commands must declare command action
and successful result schemas. The daemon validates the command action before
sending it and validates successful command results before resolving the
registered command.

## Secure Envelopes

The session protocol carries AEAD-protected business/control frames in
`SecureEnvelope`. Authenticated data binds projection, role, session,
transcript hash, key epoch, frame type, sequence number, binding generation,
and credential generation.

Receivers maintain a fixed-size replay window per envelope stream. Duplicate,
expired-window, and too-far-ahead sequence numbers are rejected before the frame
body is decoded.
