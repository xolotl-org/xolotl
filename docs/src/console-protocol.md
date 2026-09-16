# Console Protocol

`xolotl-console` hosts the management protocol used by console clients.
It exposes HTTP routes for health and authentication, then uses Console
WebSocket for logged-in management actions and streams.

Management actions are descriptor-named calls. They use the runtime state,
authorization, CAS, visibility checks, and audit records; actions that invoke runtime
effects do so as capability-scoped Operations.

## Listener

Console HTTP and Console WebSocket share `[server].console_addr`, with
`XOLOTL_CONSOLE_ADDR` as the environment fallback.

| Channel | Route | Encoding |
| --- | --- | --- |
| HTTP | `/health`, `/api/auth/*` | HTTP JSON |
| WebSocket | `/ws` | Binary protobuf `ConsoleFrame`, `protobuf+xolotl-console-v1` |

## HTTP Routes

Console HTTP routes are provided by `xolotl-console::router`:

| Path | Method | Purpose |
| --- | --- | --- |
| `/health` | `GET` | Health check. |
| `/api/auth/login` | `POST` | Username/password login with optional TOTP. |
| `/api/auth/key/challenge` | `POST` | Create a public-key login challenge. |
| `/api/auth/key/login` | `POST` | Submit the public-key signature and finish login. |
| `/api/auth/passkey/register/begin` | `POST` | Begin passkey registration for an elevated bearer session. |
| `/api/auth/passkey/register/finish` | `POST` | Finish passkey registration and store the credential. |
| `/api/auth/passkey/login/begin` | `POST` | Begin passkey login for a username. |
| `/api/auth/passkey/login/finish` | `POST` | Verify the passkey assertion and issue a session. |
| `/api/auth/step-up` | `POST` | Raise MFA level for an existing bearer session. |
| `/api/auth/refresh` | `POST` | Rotate the bearer token for an existing session. |

Authentication routes require `Origin` and `Host` headers. The origin host,
port, and trusted forwarded scheme must match the externally visible host for
the console listener. Public-key login additionally requires the JSON `origin`
field to exactly match the request `Origin` header; that value is bound into the
signed transcript. Passkey routes use the configured WebAuthn relying-party id
and origin, and do not prescribe any frontend layout or UI framework.

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

Passkey registration begin request:

```json
{"display_name":"Root Operator"}
```

Passkey registration begin and finish require:

```text
Authorization: Bearer <token>
```

Passkey login begin request:

```json
{"username":"root"}
```

Passkey finish requests carry the browser credential response returned by
`navigator.credentials.create` or `navigator.credentials.get`.

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

The endpoint accepts binary protobuf `ConsoleFrame` frames under the
`xolotl-console-v1` WebSocket subprotocol. Text frames return
`ConsoleErrorCode::BadFrame`. The configured frame limit is capped at 4 MiB by
the backend.

## Encoding

The wire encoding name is `protobuf+xolotl-console-v1`, the WebSocket
subprotocol is `xolotl-console-v1`, and the protocol version is `1`.

Frames are protobuf `xolotl.v1.console.ConsoleFrame` messages. `ActionCall.input`,
`ActionResult.output`, stream inputs, and events carry native `xolotl.v1.Value`
messages, so console clients share the same `Value` and `Path` protobuf shapes as
the external gateway.

## Session Sequence

Required client sequence:

1. Log in through HTTP and keep `LoginResponse.token`.
2. Open the console WebSocket at `/ws`.
3. Send `ClientFrame::Hello { hello }` with `protocol_version = 1` and
   `accepted_encodings` containing `protobuf+xolotl-console-v1`.
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
| `accepted_encodings` | Encodings accepted by the client; currently must include `protobuf+xolotl-console-v1`. |

`ActionCall`:

| Field | Meaning |
| --- | --- |
| `action` | Action id, such as `config.read` or `state.snapshot`. |
| `input` | Native `xolotl.v1.Value` protobuf message. |
| `scope` | Optional visibility or high-risk access scope. |
| `justification` | Optional operator justification. |
| `ttl_ms` | Optional temporary authority duration. |

`StreamCall`:

| Field | Meaning |
| --- | --- |
| `stream` | Stream id, such as `state.watch` or `audit.facts.stream`. |
| `input` | Native `xolotl.v1.Value` stream filter. |
| `scope`, `justification`, `ttl_ms` | Visibility metadata required by protected streams. |
| `since_rev` | Reserved; clients must omit it. Current streams are live-only and reject it. |

## Server Frames

| Frame | Payload | Purpose |
| --- | --- | --- |
| `HelloAccepted` | `ProtocolMetadata` | Protocol metadata, registry revision, actions, streams, visibility tiers, and secret classes. |
| `Authenticated` | `PrincipalSummary`, `ProtocolMetadata` | Auth result and refreshed protocol metadata. |
| `Reply` | `id`, `ActionResult` | Action reply or subscription acknowledgement. |
| `Event` | `stream`, `ConsoleEvent` | Stream event delivery. |
| `Pong` | `nonce` | Keepalive response. |
| `Error` | optional `id`, `ConsoleErrorCode`, message | Protocol, auth, validation, authorization, rate-limit, or internal error. |

`ConsoleErrorCode` values are carried on the protobuf `ConsoleError` frame. The
server maps protocol, authentication, authorization, validation, conflict,
rate-limit, and internal failures to the canonical console error enum.

## Actions And Streams

Available actions and streams are advertised through `ProtocolMetadata` and can
also be fetched with `protocol.describe` or `protocol.registry.snapshot`. Those
metadata responses include the listener's actual transport-security mode and
unsafe relaxations.

Implemented action families include:

| Family | Examples |
| --- | --- |
| Protocol and registry | `protocol.describe`, `protocol.registry.snapshot`, `protocol.action_descriptor.get`, `registry.coverage.report` |
| Resource and edit descriptors | `resource.type.list`, `resource.type.describe`, `resource.view.describe` |
| Authority and visibility | `authority.principal.effective`, `authority.action.matrix`, `visibility.authority.describe`, `visibility.state.read`, `visibility.state.list` |
| Secret custody | `secret.catalog`, `secret.reveal` |
| State and config | `state.snapshot`, `config.read`, `config.list`, `config.write_cas` for config without a dedicated action |
| Console access | `access.user.*`, `access.role.*`, `access.session.*`, `access.session.current.logout` |
| Runtime, audit, and lineage | `runtime.process.inspect`, `audit.facts.recent`, `lineage.trace.read`, `lineage.fact.read`, `health.summary` |
| External programs and pairing | `external.manifest.*`, `external.installation.*`, `pairing.create`, `pairing.approve`, `pairing.deny`, `pairing.replace` |
| In-process projection status | `projection.in_process.status.list`, `projection.in_process.status.read` |
| Inference routing | `inference.backend.*`, `inference.model.*`, `inference.group.*`, `inference.routing.*` |

The table lists executable action families. Action descriptors also carry
`implementation_status`; descriptors with `planned` or `blocked_by_custody`
status are discoverable for coverage and authority explanation, and direct
`Call` execution returns an error.

Generic `config.*` actions reject runtime config paths that have dedicated
action families. Use `access.*`, `external.*`, `inference.*`, and `pairing.*`
for those paths so validation, authorization, CAS, and audit stay tied to the
declared resource type. In-process Provider/Source projection declarations use
`config.*` under `state://kernel/projections/in-process/<id>` and shared kernel
config admission. Projection status is read-only through
`projection.in_process.status.*`.
External projections remain part of their external installation declaration and
are managed through `external.installation.*`.

Resource and graph descriptors provide shape-independent semantic metadata:
resource types, fields, views, revisions, relationships, graph node types, ports,
edges, and validation hooks. They do not name UI widgets or bypass the fixed
action descriptors used for validation, authorization, CAS, and audit.

Streams:

| Stream | Event source |
| --- | --- |
| `state.watch` | State backend watch events. |
| `audit.facts.stream` | Audit Fact events. |

Frame, connection, idle, rate, subscription, result-size, queue, and send limits
come from `[console.ws]`; values are clamped by backend hard bounds.

## Outbound Limits

`max_frame_bytes` applies to incoming and outgoing protobuf frames (default 1 MiB,
range 16 KiB to 4 MiB). Before cloning wire payloads, conversion checks cumulative
inline bytes, at most 16,384 Value nodes and 30 Value nesting levels, and at most
256 path segments. The completed protobuf message must also fit the exact frame
byte limit before its output buffer is allocated. Values are never truncated.

`send_timeout_ms` applies to every outgoing frame, including replies and errors
(default 5 seconds, range 100 ms to 60 seconds). It replaces
`event_send_timeout_ms`. If a reply cannot be encoded within the limits, the server
sends a small `Internal` error carrying the original request ID. The action may
already have completed; this error does not indicate rollback or a safe retry.
A transport error or send timeout closes the connection.

Live subscriptions share a 256-entry queue per connection.
`max_pending_event_bytes` bounds encoded subscription data bytes queued or being sent
(default 1 MiB, range 16 KiB to 16 MiB). A worker prepares at most one bounded frame
before attempting queue admission and never waits while retaining an unaccounted
frame. Exhausting either queue limit closes that subscription. The queue budget
excludes the independent control path: at most `max_subscriptions` pending closure
reasons (1 KiB each) and one closure frame being sent. It also excludes
source broadcast storage, native action outputs, temporary wire
conversion structures, socket buffers, or total process memory.

Both State and Fact workers have one session owner. Lag, source closure, a failed
projection or encoding, and worker failure release the subscription slot and
emit `SubscriptionClosed`. Closure invalidates any unsent tail for that
subscription generation; old queued events and closures cannot affect a replacement
using the same ID. Closing or cancelling the session aborts its workers. Shutdown
uses one 250 ms deadline for all workers; failure to finish closes the session.
This bounds asynchronous waits. Tokio cannot forcibly preempt synchronous adapter
work or a blocking destructor; host adapters must cooperate with cancellation.

Subscription visibility lasts for the requested `ttl_ms`, at most ten minutes.
Expiry discards pending data and emits `SubscriptionClosed`. Successful `Auth`
clears previous subscriptions before accepting the new session. Each event
reauthenticates the SID; a changed identity, effective grant set or MFA level
closes the connection and requires new authorization and subscriptions.
Data sends use the earlier of the visibility deadline and send timeout, and check
expiry after the socket becomes writable. Data already accepted by the socket
cannot be retracted. Stale generations retain queue credits until dequeued and
discarded, so an immediate replacement can still encounter queue pressure.

## Fact Queries

`audit.facts.recent` returns one reverse append-order page, defaulting to 64 records.
`lineage.trace.read` requires `process` and returns one forward append-order page,
defaulting to 128 records. Both accept `from`, `before`, `limit`, `max_bytes` and
`max_examined`; recent also accepts an optional `process`. Cursor and process inputs
accept nonnegative integers or decimal `u64` strings. Cursors and numeric identifier
fields are projected as decimal strings, preserving the full range in clients;
`op_id` retains its composite OperationId string format. `from` is a physical global append
position, including for a process-filtered trace, rather than an offset into its
matching rows. Order is fixed by the action.

Page output has the following fields:

| Field | Meaning |
| --- | --- |
| `items` | Projected Facts in append order; `completed` reflects the current outcome. |
| `from`, `end` | Inclusive lower and exclusive upper append bounds for this page. |
| `next` | Decimal continuation cursor, or `null` when the interval is exhausted. |
| `order` | `forward` or `reverse`. |
| `complete` | Whether this page exhausted its append interval. |
| `examined` | Storage candidates visited, including filtered or byte-rejected candidates. |
| `encoded_bytes` | Sum of returned Fact JSON encoding lengths before projection. |
| `process` | Selected process, when supplied. |

Continue recent with `before=next` and the same `from`; continue trace with
`from=next` and `before=end`. Preserve filters and budgets. Empty pages may have
continuations. Reverse pages shrink their upper bound. A fixed append interval
excludes later appends but does not freeze in-place completion updates.
Trace additionally returns `partial=true` and `partial_reason` for omitted
materialized lineage indexes; these fields are independent of pagination
completion. No all-history trace count is returned.

The record limit is capped by the listener's Fact or trace limit. JSON bytes are
capped at `min(max_frame_bytes / 8, 256 KiB)`, reserving room for projection and
framing. Outbound conversion and exact frame limits are checked separately. Candidate examination
defaults to `max(limit, 4096)` and is capped at 65,536. Zero budgets are invalid;
larger requests are clamped. A first matching record that exceeds the byte budget
fails the read. `lineage.fact.read` uses an indexed, byte-bounded lookup and also
accepts `max_bytes` and an optional `process`, defaulting to `op_id.process`. It
requires read authority for that process and only returns a record whose current
caller matches it. A different caller is reported as unknown, without exposing
the record. These limits do not measure decoded heap or total memory.

`runtime.process.inspect` and the `runtime` section of `state.snapshot` default to
metadata only. `include_recent_facts=true` requires an explicit `process`, Fact-read
authority for `state://fact/<process>`, and the action's visibility metadata.
`recent_facts` is one bounded reverse page; there is no full-history `fact_count`.
A snapshot accepts at most one runtime section. Process rows and children remain
independent, currently unpaged collections.

`health.summary.fact_sample` contains `sampled_facts`, `decisions`, and the same
page metadata. These counts describe only the recent sample; the old global
`fact_count` and `fact_decisions` fields are removed. Top-level `fact_cursor` is a
decimal append-head string, observed separately from the sample, and does not
track completion updates. Process counts still enumerate the process table.

## Live Audit

`audit.facts.stream` starts with future notifications and does not replay history.
Its optional `process` filters the current record before checking its byte budget;
unrelated oversized records are ignored. Appends and outcome updates both trigger
a bounded indexed reread; each event is an upsert keyed by `op_id`.
Notifications may arrive out of commit order or yield repeated current values.
Clients should replace their record for that identity rather than count every
notification as a distinct Fact.

Lag, a missing record or a bounded-read failure emits `SubscriptionClosed` and
releases the subscription slot. The shared lifecycle and queue limits above also apply.
After closure, resubscribe and reconcile retained Facts with explicit bounded
pages, including old slots whose outcomes may have changed. Establish the live
subscription before reading pages to reduce the gap, and restart reconciliation
after any further lag; this is not an atomic snapshot or a durable update log.

`StreamCall.since_rev` is reserved and rejected. Wire `ConsoleEvent.state_rev` and
`fact_cursor` remain zero; `SubscriptionClosed.last_rev` is absent. Append cursors
cannot resume outcome updates in old slots. The protobuf envelope is unchanged;
the paged action outputs and exact identifier projections replace the previous
Value payload shapes.
