# Console Protocol

`nexus-console` hosts the management protocol used by console clients.
It exposes HTTP routes for health and authentication, then uses Console
WebSocket for logged-in management actions and streams.

Management actions are descriptor-named calls. They use the runtime state,
authorization, CAS, visibility checks, and audit records; actions that invoke runtime
effects do so as capability-scoped Operations.

## Listener

Console HTTP and Console WebSocket share `[server].console_addr`, with
`NEXUS_CONSOLE_ADDR` as the environment fallback.

| Channel | Route | Encoding |
| --- | --- | --- |
| HTTP | `/health`, `/api/auth/*` | HTTP JSON |
| WebSocket | `/ws` | Binary MessagePack, `msgpack+nexus-console-v1` |

## HTTP Routes

Console HTTP routes are provided by `nexus-console::router`:

| Path | Method | Purpose |
| --- | --- | --- |
| `/health` | `GET` | Health check. |
| `/api/auth/login` | `POST` | Username/password login with optional TOTP. |
| `/api/auth/key/challenge` | `POST` | Create a public-key login challenge. |
| `/api/auth/key/login` | `POST` | Submit the public-key signature and finish login. |
| `/api/auth/step-up` | `POST` | Raise MFA level for an existing bearer session. |

Authentication routes require `Origin` and `Host` headers. The origin host,
port, and trusted forwarded scheme must match the externally visible host for
the console listener. Public-key login additionally requires the JSON `origin`
field to exactly match the request `Origin` header; that value is bound into the
signed transcript.

Password login request:

```json
{"username":"root","password":"...","totp_code":null}
```

Public-key challenge request:

```json
{"username":"root","origin":"https://console.example"}
```

Public-key login request:

```json
{"username":"root","challenge_id":"...","signature":"...","origin":"https://console.example","key":null}
```

Step-up request body:

```json
{"password":"...","totp_code":null}
```

`/api/auth/step-up` takes the existing session through:

```text
Authorization: Bearer <token>
```

Login, key login, and step-up return `LoginResponse`:

| Field | Meaning |
| --- | --- |
| `sid` | Session id. |
| `token` | Bearer token in `sid.secret` form. |
| `expires_at` | Absolute expiry, Unix milliseconds. |
| `idle_expires_at` | Idle expiry, Unix milliseconds. |
| `mfa_level` | Session MFA level. |

HTTP auth error mapping:

| Condition | Status |
| --- | --- |
| Missing bearer, invalid session, invalid challenge, or invalid credentials | `401 Unauthorized` |
| Account unavailable or permission denied | `403 Forbidden` |
| Rate limit exceeded | `429 Too Many Requests` |
| Invalid username | `400 Bad Request` |
| Internal auth state or crypto failure | `500 Internal Server Error` with a redacted message |

## WebSocket Upgrade

Console WebSocket is mounted at `/ws` on the console listener. The upgrade path
checks:

- `Origin` header is present and parseable;
- `Host` header is present;
- origin host and port match the externally visible host;
- `:path`, when present, is `/ws`;
- source-level connection limits have capacity.

The endpoint accepts binary MessagePack frames. Text frames return
`ConsoleErrorCode::BadFrame`. The configured frame limit is capped at 4 MiB by
the backend.

## Encoding

The wire encoding name is `msgpack+nexus-console-v1`, and the protocol version
is `1`.

Frames are serde-compatible MessagePack values. Server frames are encoded with
named fields. `ActionCall.input`, `ActionResult.output`, stream inputs, and
events wrap Nexus `Value` payloads in `JsonBytes`, a JSON string inside the
outer MessagePack frame.

## Session Sequence

Required client sequence:

1. Log in through HTTP and keep `LoginResponse.token`.
2. Open the console WebSocket at `/ws`.
3. Send `ClientFrame::Hello { hello }` with `protocol_version = 1` and
   `accepted_encodings` containing `msgpack+nexus-console-v1`.
4. Receive `ServerFrame::HelloAccepted { metadata }`.
5. Send `ClientFrame::Auth { token }`.
6. Receive `ServerFrame::Authenticated { principal, metadata }`.
7. Send `ClientFrame::Call { id, call }` for actions, or
   `ClientFrame::Subscribe { id, stream }` for streams.

`Auth`, calls, subscriptions, and unsubscriptions require an accepted `Hello`.
Calls, subscriptions, and unsubscriptions also require successful `Auth`. Each
later request revalidates the session id before dispatch.

## Client Frames

| Frame | Payload | Purpose |
| --- | --- | --- |
| `Hello` | `ClientHello` | Negotiate protocol version and accepted encodings. |
| `Auth` | `token` | Present a bearer session token. |
| `Call` | `id`, `ActionCall` | Invoke one descriptor-named action. |
| `Subscribe` | `id`, `StreamCall` | Subscribe to one descriptor-named stream. |
| `Unsubscribe` | `id` | Cancel one subscription. |
| `Ping` | `nonce` | Keepalive; the server replies with `Pong`. |

`ClientHello`:

| Field | Meaning |
| --- | --- |
| `protocol_version` | Client-supported major wire version. |
| `client_name` | Optional client application name for audit and diagnostics. |
| `accepted_encodings` | Encodings accepted by the client, in preference order. |

`ActionCall`:

| Field | Meaning |
| --- | --- |
| `action` | Action id, such as `config.read` or `state.snapshot`. |
| `input` | JSON string for a Nexus `Value`, wrapped in `JsonBytes`. |
| `scope` | Optional visibility or high-risk access scope. |
| `justification` | Optional operator justification. |
| `ttl_ms` | Optional temporary authority duration. |

`StreamCall`:

| Field | Meaning |
| --- | --- |
| `stream` | Stream id, such as `state.watch` or `audit.facts.stream`. |
| `input` | JSON string for stream filters. |
| `scope`, `justification`, `ttl_ms` | Visibility metadata required by protected streams. |
| `since_rev` | Reserved cursor; current console streams are live-only and reject it. |

## Server Frames

| Frame | Payload | Purpose |
| --- | --- | --- |
| `HelloAccepted` | `ProtocolMetadata` | Protocol metadata, registry revision, actions, streams, visibility tiers, and secret classes. |
| `Authenticated` | `PrincipalSummary`, `ProtocolMetadata` | Auth result and refreshed protocol metadata. |
| `Reply` | `id`, `ActionResult` | Action reply or subscription acknowledgement. |
| `Event` | `stream`, `ConsoleEvent` | Stream event delivery. |
| `Pong` | `nonce` | Keepalive response. |
| `Error` | optional `id`, `ConsoleErrorCode`, message | Protocol, auth, validation, authorization, rate-limit, or internal error. |

`ConsoleErrorCode` values are `BadFrame`, `NotAuthenticated`, `Unauthorized`,
`Forbidden`, `Conflict`, `BadRequest`, `RateLimited`, and `Internal`.

## Actions And Streams

Available actions and streams are advertised through `ProtocolMetadata` and can
also be fetched with `protocol.describe` or `protocol.registry.snapshot`. Those
metadata responses include the listener's actual transport-security mode and
unsafe relaxations.

Implemented action families include:

| Family | Examples |
| --- | --- |
| Protocol and registry | `protocol.describe`, `protocol.registry.snapshot`, `protocol.action_descriptor.get`, `protocol.schema.get` compatibility alias, `registry.coverage.report` |
| Resource and edit descriptors | `resource.type.list`, `resource.type.describe`, `resource.view.describe`, `graph.type.describe` |
| Authority and visibility | `authority.principal.effective`, `authority.action.matrix`, `visibility.authority.describe`, `visibility.state.read`, `visibility.state.list` |
| Secret custody | `secret.catalog`, `secret.reveal` |
| State and config | `state.snapshot`, `config.read`, `config.list`, `config.write_cas` |
| Console access | `access.user.*`, `access.role.*`, `access.session.*`, `access.session.current.logout` |
| Runtime, audit, and lineage | `runtime.process.inspect`, `audit.facts.recent`, `lineage.trace.read`, `lineage.fact.read`, `lineage.fact.by_operation`, `health.summary` |
| External programs and pairing | `external.installation.*`, `pairing.create`, `pairing.approve`, `pairing.deny`, `pairing.replace` |

Resource and graph descriptors provide shape-independent semantic metadata:
resource types, fields, views, revisions, relationships, graph node types, ports,
edges, and validation hooks. They do not name UI widgets or bypass the fixed
action descriptors used for validation, authorization, CAS, and audit.

The registry may advertise planned actions. Current planned edit-envelope
actions include `change_set.create`, `change_set.update`,
`change_set.validate`, `change_set.diff`, `change_set.dry_run`,
`change_set.apply`, and `change_set.discard`; planned actions are discoverable
but not executable.

Streams:

| Stream | Event source |
| --- | --- |
| `state.watch` | State backend watch events. |
| `audit.facts.stream` | Audit Fact events. |

Frame, connection, idle, rate, subscription, result-size, and event-send limits
come from `[console.ws]`; values are clamped by backend hard bounds.
