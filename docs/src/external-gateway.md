# External Gateway

The external gateway connects out-of-process programs to Andrias as Provider or
Source projections. gRPC and WebSocket are transport implementations for the
same session protocol.

## Roles

Provider sessions expose remote effect handlers declared by the selected
installation projection. After `RoleReady` confirms the daemon-selected session
context, the daemon registers those projection bindings for the ready session
and dispatches invocations only for registered effects.

Source sessions emit inbound events and can receive outbound commands from the
daemon. Source events enter the same schema, policy, capacity, dedupe, and taint
paths regardless of whether they arrive over gRPC or WebSocket.

Provider and Source are the only external projection roles.

## Transports

External gRPC listens on `[server].external_grpc_addr` or
`ANDRIAS_EXTERNAL_GRPC_ADDR` and serves
`andrias.v1.external.ExternalService.Session`.

External WebSocket listens on `[server].external_websocket_addr` or
`ANDRIAS_EXTERNAL_WEBSOCKET_ADDR` and serves the same logical session frames over
`/ws`.

Both transports use the same daemon-side session handler and the same
Provider/Source admission state.

## Configuration

Listener addresses, transport security, WebSocket transport caps, and
Provider/Source numeric limits are owned by [Configuration](configuration.md).
This page does not repeat the key list or default TOML block.

After a session is admitted, those settings bound Provider dispatch, Provider
result resolution, Source command dispatch, Source command result resolution,
Source event ingress, and Source event or command idempotency retention. Source
event payload-size limits, stream capacity, overflow behavior, and event-ingress
rate limits are declared on each Source projection.

## Transport Security

Transport-security modes and their required certificate or proxy fields are
documented in [Configuration](configuration.md). A listener that rejects its
transport-security mode fails before accepting external sessions.

## Session State

Approved session state is read from:

```text
state://kernel/external-sessions/<installation_id>/<role>
```

The session record must match the connecting installation id and role. The
daemon rejects missing, mismatched, revoked, or non-ready session records before
business frames can flow.

## Provider Flow

Provider invokes are sent only for projected effects declared by the
installation projection and registered for the ready session. Invoke input must
match the Provider projection's `input_schema`.
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
