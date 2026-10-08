# Console Actions and Streams

The v1 WebSocket framing below carries the same authenticated actions as the Rust service and HTTP `/calls` endpoint. Live streams use the shared Console subscription service. See [Console Protocol](console-protocol.md) for admission and [Console HTTP and Credentials](console-http-and-credentials.md) for HTTP routes.

## WebSocket Upgrade

The daemon mounts Console WebSocket at `/api/console/v1/ws`. An embedded host may mount the selected `/ws` endpoint under another prefix or omit it. The endpoint path is relative to the host's mount; `HttpApi::manifest` describes it when the host publishes that manifest. The upgrade path checks:

- `Origin` header is present, parseable and unambiguous;
- `Host` header is present and unambiguous, including behind a trusted proxy;
- origin host and port match the externally visible host;
- source-level connection limits have capacity.

The endpoint accepts binary protobuf `ConsoleFrame` frames under the `xolotl-console-v1` WebSocket subprotocol. Text frames return `ConsoleErrorCode::BadFrame`. The configured frame limit is capped at 4 MiB by the backend.

## Encoding

The wire encoding name is `protobuf+xolotl-console-v1`, the WebSocket subprotocol is `xolotl-console-v1`, and the protocol version is `1`. `ProtocolGreeting` reports this encoding; Hello does not negotiate alternatives.

Frames are protobuf `xolotl.v1.console.ConsoleFrame` messages. `ActionCall.input`, `ActionResult.output`, stream inputs, and events carry native `xolotl.v1.Value` messages, so console clients share the same `Value` and `Path` protobuf shapes as the external gateway. The shared `value_from_pb` decoder rejects malformed nested values and unknown null enum numbers instead of replacing them with `Null`. An empty outer `Value` oneof continues to represent `Null` in v1.

Custom adapters can call `wire::decode_client_frame(bytes, max_frame_bytes)` and `wire::encode_server_frame(frame, max_frame_bytes)` without enabling the `http` feature. After verifying connection and source provenance, reserve shared call capacity with `ConsoleService::admit_call()` before collecting or decoding a call-bearing frame; consume the reservation with `ConsoleCallAdmission::call` after decoding, or drop it on failure. The HTTP `/calls` adapter follows this order. The adapter must impose its own byte ceiling and collection deadline. Before Prost allocates a client frame, the decoder checks its byte ceiling and scans every encoded call or subscription input, including fields later replaced by a repeated oneof. The scan allows at most 16,384 `Value` nodes and 30 nesting levels across the frame; a map entry without an explicit value counts as one node. The byte ceiling bounds inline wire payloads. These are protobuf conversion-work limits, separate from runtime input and Kernel process budgets, and do not claim a process-memory limit. `wire::delivery_failure` preserves known execution references when a completed response cannot be encoded.

## Session Sequence

Required client sequence:

1. Obtain an authenticated session `token` through an authentication adapter over the same `ConsoleState`, completing any required continuations. The daemon uses HTTP authentication.
2. Open the selected Console WebSocket endpoint at the host's mount point plus `/ws` (the daemon default is `/api/console/v1/ws`).
3. Send `ClientFrame::Hello { hello }` with `protocol_version = 1` and an optional `client_name`.
4. Receive `ServerFrame::HelloAccepted { metadata, transport }`.
5. Send `ClientFrame::Auth { token }`.
6. Receive `ServerFrame::Authenticated { principal, metadata }`.
7. Send `ClientFrame::Call { id, call }` for actions, or `ClientFrame::Subscribe { id, stream }` for streams.

`Auth`, calls, subscriptions, and unsubscriptions require an accepted `Hello`. Calls, subscriptions, and unsubscriptions also require successful `Auth`. Each later request revalidates the session id before dispatch.

## Client Frames

| Frame | Payload | Purpose |
| --- | --- | --- |
| `Hello` | `ClientHello` | Confirm the fixed v1 protocol version. |
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

`ActionCall`:

| Field | Meaning |
| --- | --- |
| `action` | Action id, such as `config.read` or `state.snapshot`. |
| `registry_rev` | Optional descriptor revision precondition; refresh metadata after a mismatch. |
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
| `registry_rev` | Optional discovered registry revision; stale values return `registry_changed` before execution. |

## Server Frames

| Frame | Payload | Purpose |
| --- | --- | --- |
| `HelloAccepted` | `ProtocolGreeting`, `TransportSecuritySummary` | Compact service metadata and the connected adapter’s configured transport policy. |
| `Authenticated` | `PrincipalSummary`, `ProtocolGreeting` | Auth result and refreshed compact metadata. |
| `Reply` | `id`, `ActionResult` | Action reply or subscription acknowledgement. |
| `Event` | `stream`, `ConsoleEvent` | Stream event delivery. |
| `Pong` | `nonce` | Keepalive response. |
| `Error` | optional `id`, `ConsoleFailure` | Safe error category, message, and known recovery facts. |

`ConsoleErrorCode` values are carried on the protobuf `ConsoleError` frame. The server maps protocol, authentication, authorization, validation, conflict, rate-limit, and internal failures to the canonical console error enum. Every `ActionResult`, including empty mutation results and subscription acknowledgements, includes the `registry_rev` used for that response. `server_rev` is the observed Fact append cursor when observation storage is installed, otherwise zero. Disabled observation actions and streams are omitted from discovery; zero does not certify an empty history. Use the record's own version for concurrent State edits.

When observation storage is absent, `state.snapshot.fact_cursor`, `health.summary.fact_cursor` and `health.summary.fact_sample` are `null`; State and runtime observations remain available. Explicit recent-Fact requests require an installed sink.

## Descriptor validation and failures

Action and stream descriptors define their input schemas and step-up gates. The service rejects unknown fields, missing required fields and wrong types before dispatch; handlers then authorize concrete paths. Named types resolve through enclosing `definitions`. `list<T>` validates each item; `T|null` allows null; `max_items` bounds a list. A `snapshot_section` uses its `kind` discriminator and declared `variants` to select a schema. Omitted input is accepted for maps with no required fields; no-input actions declare `null`.

Input `string` is nonempty. Integer types `u8`, `u32`, `u64`, `usize` and `positive_usize` use bounded Xolotl integers; `decimal_u64` also accepts digit-only strings through the full `u64` range. `path`, `path-pattern` and `operation_id` check syntax before domain admission.

Resource views advertise their actual query and output schemas. They expose implemented cursor pagination, with no server-side text search or client-selected sorting. `registry_rev` covers actions, streams, resource types, summaries and views. Revision admission precedes action-name lookup, so a renamed action under a stale revision returns `REGISTRY_CHANGED`. Refresh descriptors on that error.

Clients can branch on codes instead of parsing messages: `UNAUTHENTICATED` means missing or invalid credentials, `FORBIDDEN` means insufficient authority, `STEP_UP_REQUIRED` identifies an MFA gate, `REGISTRY_CHANGED` a stale catalog, `VERSION_CONFLICT` a CAS conflict, `ADMISSION_REJECTED` invalid domain input, and `OUTCOME_UNKNOWN` an effect whose completion cannot be established. The Rust service and adapters preserve one `ConsoleFailure` with a sanitized `message` and only facts known at failure:

| Field | Meaning |
| --- | --- |
| `retry_after_ms` | Known rate-limit delay; absent when no release time is known. |
| `required_mfa_level` | Level required by the failed check. |
| `mfa` | Account factors and recovery-code availability, disclosed only after primary or bearer authentication; absent for generic action gates. |
| `current_registry_rev` | Revision observed when rejecting a stale catalog. |
| `current_version` | Record version observed by a failed CAS; absence does not imply the record is absent. |
| `execution` | Allocated `process_id`, `program_id` and optional service-owned `execution_id`, retained through execution and cleanup errors. |
| `outcome_unknown` | Host-authored `operation_ids` and controlled `reason` when an effect may have executed but no result can be established. The list contains only identities known to need reconciliation and can include several concurrent calls; it is not a complete ledger of effects. An empty list does not prove that no effect ran. Unrecognized host reasons become `unclassified`; the field is absent for other failures. |

`ActionResult` carries an optional execution reference and unresolved effect identities. Encoding failures preserve known references. An execution reference requires fresh authorization for observation and is neither a result bearer nor a deduplication token. For a Source command, `operation_ids` contains its one outbound command ID, derived from the invoking Kernel OperationId. A Source-supplied error with the same text cannot set this field. HTTP `/calls` uses status 500 for this code. Failed handlers can have partial effects; this status does not establish rollback or permit retry without reconciliation. A started Kernel evaluation that cannot settle within Console's bounded wait returns `OUTCOME_UNKNOWN` with `operation_ids: []` and `reason: "settlement_timeout"`; the empty list means identities were unavailable, so inspect process and Fact evidence where available. Kernel-produced deadline uncertainty lists its unresolved Operation IDs. Admission timeouts, cancellation, and missing subscription terminal events also do not prove that no effect ran. A settled Kernel cancellation may report observed unresolved IDs; a lost response or bounded settlement timeout may leave them unavailable.

## Actions And Streams

`runtime.operation.submit` and `runtime.program.submit` optionally accept a `submission_identity` map with required `registry_instance`, canonical unsigned decimal string `retry_epoch`, and `nonce`. Without it, distinct submit calls remain nonidempotent. `runtime.describe` publishes the current instance and epoch as `submission_retry_scope`; guarded retries retain the original execution reference and deadline, without recompilation. `runtime.submission.lookup` requires that identity and returns only `evidence` and a nullable `execution`, never output or side effects. `preparing` is not accepted and `unproven` is not proof of no effects. Shared logical quotas and trusted-host epoch closure are described in [service-owned submissions](console-runtime.md#service-owned-submissions-and-retained-results); restart rejects old-instance identities.

`protocol.describe` returns `ProtocolGreeting`: protocol version, server name, encoding, Fact cursor, registry revision and observation time. Hello and authentication frames carry the same compact service information; their size is independent of the catalog. Hello separately carries `transport`, using the same `TransportSecuritySummary` as the HTTP manifest: `mode`, `unsafe_transport`, and `relaxations`. These fields describe configured admission, not proof of end-to-end TLS. Authentication does not repeat the connection's transport summary.

After authentication, fetch `protocol.registry.snapshot` for `RegistrySnapshot`. It includes the greeting fields plus action and stream schemas, root visibility invariants, visibility tiers, and the two secret custody classes `non_recoverable_secret` and `one_time_secret`. Descriptors are serialized as Console `Value` using the server's authoritative native schemas, with no separate Protobuf descriptor model. Cache the catalog by `registry_rev`, which depends on contracts and host runtime configuration, not the clock or Fact cursor.

Implemented action families include:

| Family | Examples |
| --- | --- |
| Protocol and registry | `protocol.describe`, `protocol.registry.snapshot`, `protocol.action_descriptor.get` |
| Resource and edit descriptors | `resource.type.list`, `resource.type.describe`, `resource.view.describe` |
| Authority and visibility | `authority.principal.effective`, `authority.action.matrix`, `visibility.authority.describe`, `visibility.state.read`, `visibility.state.list` |
| Secret catalog | `secret.catalog` |
| State and config | `state.snapshot`, `config.read`, `config.list`, `config.write_cas` for config without a dedicated action |
| Console access | `access.user.*`, `access.role.*`, `access.session.*`, `access.session.current.logout` |
| Runtime, audit, and lineage | `runtime.process.inspect`, `audit.facts.recent`, `lineage.trace.read`, `lineage.fact.read`, `health.summary` |
| External programs and pairing | `external.manifest.*`, `external.installation.*`, `external.source.claim.inspect`, `external.source.event.decision.inspect`, `pairing.create`, `pairing.approve`, `pairing.deny` |
| Federation catalog | `federation.peer.read/list/write_cas`, `federation.peer_admission.read/write_cas`, `federation.export.read/list/write_cas`; available only with an installed local management port |
| In-process projection status | `projection.in_process.status.list`, `projection.in_process.status.read` |
| Inference routing | `inference.backend.*`, `inference.model.*`, `inference.group.*`, `inference.routing.*` |

The `pairing.create` action input has required top-level `pairing_id` and `installation_id` fields; `allowed_roles`, `expires_at`, and `reveal_display_secret` are optional. There is no nested `input` field. For example, the action input may be:

```json
{"pairing_id":"pair-sensor-1","installation_id":"sensor-hub","reveal_display_secret":true}
```

Choose and retain the pairing ID before the request. When requested, the result can carry a one-time `display_secret`: 64 hexadecimal characters encoding the 32-byte external session key. Store it in the external program's credential custody before continuing the pairing ceremony; the Console edge consumes it when returned and cannot list or recover it later. The operation and Fact record contain only hash/checksum metadata. This is an external Provider/Source credential, separate from Console account credentials and Source event-commit receipts. The session wire rules are in [External Gateway](external-gateway.md).

To abandon a `created` pairing intent and start another, call `pairing.deny` for the old ID, then `pairing.create` with a new, caller-retained ID. These are two separate operations, not one atomic replacement. Inspect each pairing record after an uncertain response, then retry only the unfinished step; `pairing.deny` cannot deny an already approved intent. If a new intent was created but its one-time display secret was not safely received, retry the same normalized create intent and ID only while the current daemon process may still hold its undelivered one-time display value. The vault key alone cannot reconstruct a display result after restart or after it was consumed by the Console edge. If the secret is unavailable, deny that new intent and create another ID.

The table lists executable action families. `secret.catalog` lists metadata only; generic visibility reads and streams reject vault paths. Secret material is returned only by the specific authorized ceremony that owns it, such as the one-time pairing display edge. Credential lifecycle uses the typed Rust service and advertised JSON endpoints.

Generic `config.*` actions reject management paths that have dedicated action families. Use `access.*`, `external.*`, `inference.*`, and `pairing.*` for those paths so validation, authorization, CAS, and audit stay tied to the declared resource type. In-process Provider/Source projection declarations use `config.*` under `state://kernel/projections/in-process/<id>`; the host-installed namespace validator checks their paths and values. Projection status is read-only through `projection.in_process.status.*`. External projections remain part of their external installation declaration and are managed through `external.installation.*`.

`external.installation.read` and `.list` return a record with `definition`, `installation_epoch`, and Source `scope_epochs`. To update or uninstall it, pass the record's `definition.version` as `expected_version` and `installation_epoch` as `expected_installation_epoch`. Both fields are required together. A retired id may be reinstalled at version 1, but its new epoch prevents an old update or uninstall from affecting it.

Action descriptors expose identity, risk, visibility, step-up, authority templates, and input/output schemas; stream descriptors expose corresponding subscription metadata and input/event schemas. Resource type lists derive from full resource descriptors and contain usable types. Each `resource.type.list` summary has `resource_type`, `title`, `default_view`, `read_action`, and `update_action`. Full resource descriptors add semantic fields, views and fixed action bindings. `revision_field` names the update action's CAS argument, or is null if the action does not expose CAS. These descriptors do not name UI widgets or bypass action validation, authorization and audit.

Action and stream descriptors expose `authority_templates`, including optional targets. `authority.action.matrix` and `authority.action.explain` report advisory templates and known gates. Each row has `templates_covered` and per-template `coverage` (`unconditional`, `predicate_bound`, `uncovered`, or `invalid_template`). An uncovered template is not a denial: a narrow grant may cover the concrete target, and some templates describe optional sections. Such rows report `input_required` when no earlier step-up or visibility gate applies. `preconditions_met` is also advisory; it reports known current gates, not implementation status. Use `authority.resource.access` for a concrete target and verb; the actual action still authorizes its inputs and evaluates current policy. The check accepts concrete method authority verbs (including `append` and `publish`) and the `spawn-with`, `act-as`, and `delegate` scope verbs. It does not accept a wildcard as the queried verb.

Streams:

| Stream | Event source |
| --- | --- |
| `state.watch` | State backend watch events. |
| `audit.facts.stream` | Audit Fact events. |
| `runtime.operation.stream` | Execute one installed method, stream its output and final result. |
| `runtime.program.stream` | Execute a portable Program with independently identified output ports. |

Each `state.watch` Set, Append, DropPrefixAppend, and Delete event includes a `source` summary with the fixed boolean fields `tainted`, `author_constant`, `model_output`, `inbound`, `fetched`, and `protected`. Set reports the replacement's lineage; Append reports the appended item's lineage combined with the existing sequence; DropPrefixAppend drops `removed` entries from the front of an existing list and appends `item`, while retaining the sequence's conservative lineage; Delete reports the deleted record's lineage. Source `DropOldest` emits the exact removed count, which can exceed one when the existing sink exceeds its current capacity. These deltas require a known prior value; on stream lag, reread current State because the stream cannot replay missed events. All source-summary fields are false for pristine data. This is a source summary, not a lossless `TaintSet`: ingress source and channel, fetched host, and protected source paths are omitted even when the subscribed business path is visible. The event's source categories do not grant access to those underlying sources. Runtime output `taint` remains a separate lossless execution envelope, subject to its own authorization and delivery limits.

Frame, connection, idle, rate, subscription, result-size, queue, and send limits come from `[console.ws]`; values are clamped by backend hard bounds.

## Source commit evidence inspection

`external.source.claim.inspect` and `external.source.event.decision.inspect` use the existing `Call` entry point, including HTTP `/calls`. The host must install `ConsoleConfig.source_management: Some(Arc<dyn SourceManagement>)`; it is absent by default. This single port combines declaration admission, the typed installation catalog, and private inspection without granting Console event commit or maintenance. The daemon installs it from the same storage owner as Source ingress, including builds without external listeners. An uninstalled port returns `BAD_REQUEST`, never `unproven` or a State fallback.

| Input field | Constraint |
| --- | --- |
| `installation_id` | Literal identity segment, 1–256 bytes. |
| `projection_id` | Literal identity segment, 1–256 bytes. |
| `scope_epoch` | Positive decimal storage incarnation of the Source projection. |
| `stream_epoch` | Required positive decimal stream incarnation for ordered events; omitted for unordered events. |
| `event_id` | Literal event identity segment, 1–256 bytes. |
| `claim_id` | Required only for exact claim inspection; exactly 32 lowercase hexadecimal digits from a trusted host incident log. |

`ActionCall.justification` must be at most 1024 bytes and nonempty after trimming. The shared service requires a valid session with MFA level at least 2. Its current grants must cover `perform` on the exact target `effect://external/source/{installation_id}/{projection_id}/claims/inspect`. For example, a role can grant `perform://effect/external/source/chat/inbox/claims/inspect` for one projection. State visibility and Source session credentials do not grant this permission. This action adds no authentication freshness requirement. Identity and justification are checked at the Console disclosure boundary, not encoded as a private Source audit record.

`external.source.event.decision.inspect` takes the installation, projection, scope incarnation, optional stream incarnation, and event ID, but no `claim_id`. Ordered event IDs are deduplicated within a stream incarnation, so a retired and reopened stream can reuse one; callers must supply the incarnation rather than infer it from the ID. This action separately requires `perform` on the concrete target `effect://external/source/{installation_id}/{projection_id}/events/inspect`. It reads the currently retained accepted event decision and its exact receipt. It cannot enumerate events, reconstruct cleaned decisions, or prove that an unknown attempt did not commit. If the same event ID is accepted again after the earlier window, the lookup returns only the current decision and cannot identify it as the earlier attempt. Within the window, reusing an ID with a different payload or ordered stream position is a deterministic conflict; the original accepted decision and receipt remain, and inspection does not report the rejected attempt. Both actions recheck current authority on every call.

The result is either `{"status":"unproven"}` or `{"status":"committed","receipt":{...}}`. The receipt contains `installation_id`, `projection_id`, `scope_epoch`, optional `stream_epoch`, `event_id`, hexadecimal `claim_id`, `sink`, and `received_at_ms`; it never contains the event payload. The storage port reads the exact identity from one consistent, read-only view; it does not write a private inspection audit. Observation auditing belongs to the host disclosure boundary, not a mandatory Console-plus-Source transaction. Current account authority, MFA, concrete-target authorization, justification and final delivery checks remain required. A receipt for a different identity is rejected without disclosure. Uncertain storage rejects reconciliation until its recovery owner reopens it. See the [Source inspection contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs). The action can inspect retained evidence after an installation is removed; it does not modify the sink, maintain dedup rows, delete claims, or replay events.

The Gateway logs the exact claim identity, including `stream_epoch` for an ordered event, only when a Source commit returns an indeterminate result. Source ACKs do not expose `claim_id`. If that log is lost, event-decision inspection can still recover a currently retained accepted claim for a known identity. For an ordered event, the operator must retain its `stream_epoch` from the Source Open response or control log; the event ID alone cannot locate a retired stream's decision. It cannot reconstruct a cleaned decision, including when only ACK delivery failed and the retention window elapsed. `unproven` can mean evidence expired or is unavailable; neither that result nor an error proves rollback or authorizes compensation. See [External gateway](external-gateway.md) for the commit and retention boundary.

## Federation catalog management

Catalog CAS responses describe local storage decisions, not remote delivery. A structured `OUTCOME_UNKNOWN` for an indeterminate catalog commit requires reading the exact row before deciding whether to retry; a missing reply is not a rejection. Federation Session errors use their own `SyncFailure.commit_verdict`, not Console's error code or message. Preserve that structured remote verdict when embedding a federation client, and do not infer non-commit from an unavailable transport or sanitized text; see the [Federation client failure contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation-grpc/src/delivery.rs).

A host can inject the same storage owner's `FederationManagement` port used by its federation Session through `ConsoleConfig.federation_management`. These actions only change the local catalog; they do not grant a remote node Console authority. Hosts without the port do not advertise the actions. With federation enabled, the stock daemon installs its redb catalog. Peer, online-admission, and export rows owned by the startup manifest can only be changed through that manifest; Console CAS creates or updates application-owned rows. The store enforces ownership in the write transaction.

Every action takes a 96-character lowercase hexadecimal `peer_node`. `federation.peer.write_cas` supplies `enabled`; `federation.peer_admission.write_cas` supplies a positive `minimum_online_generation` and `allowed_authorization_digests`, a list of at most eight 96-character lowercase hexadecimal SHA-384 digests. An empty list revokes online admission. `federation.export.read/write_cas` additionally take a literal `export`; writes supply both `serve` and `receive`. All three mutations accept an optional `expected_revision`: omitted or null means create-only, while an update requires the current positive revision. Results encode revisions and minimum online generations as decimal strings and identify the `owner` as `application` or `manifest`. If a commit result is unknown, read the exact row before deciding whether to retry.

Peer reads and writes require the corresponding `read` or `write` authority on `state://kernel/federation/peers/{peer_node}`; online admission uses its `/online-admission` child, and exports use `/exports`. Every mutation requires MFA level 2 and concrete target authorization. `federation.peer.list` requires unconditional read authority over the full `state://kernel/federation/peers` subtree; `federation.export.list` requires unconditional read authority over that peer's `/exports` subtree. The two lists use exclusive literal node ID and export name cursors, respectively, with a page `limit` from 1 to 255 (default 64). Results contain `entries` and nullable `next_cursor`. Pages observe live catalog state, not a transaction-wide snapshot; these literal cursors and limits are separate from the generic State pagination below. Generic `config.*` cannot write this catalog; enabling a peer alone does not bypass online-key admission. Subject grants, invitations, public policies, routes and replica membership still require their own host ports or stock manifests.

## Management pages, snapshots, and concurrent edits

`config.list`, `access.user.list`, `access.role.list`, `external.installation.list`, `external.manifest.list`, `projection.in_process.status.list`, `inference.backend.list`, `inference.model.list`, `inference.group.list`, `visibility.state.list`, and `access.session.list` accept optional `limit`, `max_bytes`, and `cursor` inputs. State lists require `prefix`. State-list output is:

```json
{"entries":[{"path":"state://kernel/...","value":{}}],"next_cursor":"..."}
```

Return `next_cursor` unchanged as `cursor` for the same query. A null cursor ends iteration; an empty page may still have a continuation. Cursors are opaque base64url strings bound to their exact prefix and backend position. Each request issues one bounded backend query. Later pages observe live state, not a transaction spanning all pages.

State-backed lists, including `config.list`, `visibility.state.list`, and the `kernel_config` snapshot section, require one unconditional `read` grant covering the requested prefix and all its descendants (for example, `read://state/kernel/inference/**`). An exact-path grant permits a direct read of that path, not a descendant scan. The service checks subtree authority before querying because a backend cursor can reveal a scanned key, then rechecks each returned path. To list only a narrower area, request a narrower prefix covered by its own subtree grant.

The default entry limit is 256, capped by `console.queries.max_state_list_limit`. The byte budget defaults to and is capped by `console.queries.max_page_bytes`. Both budgets must be positive. Backend record bytes and final outbound frame bytes are separate budgets. An oversized management record returns `BadRequest`; it is never silently skipped. Increase the budget or use the corresponding single-record read action. Business State reads use Operations; driver failures retain the generic sanitized `Internal` projection.

`state.snapshot` defaults to `sessions` and `runtime`. An explicit `kernel_config` section requires a manageable prefix and accepts these same pagination inputs. Every section returns an `entries/next_cursor` page, including sessions and runtime. Top-level `truncated` lists section keys with continuations. At most 16 sections are accepted, duplicates are rejected, and all sections share the snapshot byte budget. Snapshots are full live observations without a delta cursor. `server_rev` is a Fact cursor, not a transactional State revision. `registry_rev` includes action, stream, resource type and view contracts.

`expected_version = null` means create only if absent. Unversioned bootstrap records start at revision zero and require `expected_version = 0`. Successful writes advance the version. MFA enrollment, replay counters and recovery-code consumption use a separate vault aggregate with CAS. Authentication revalidates the account and policy epoch before issuing a session, without rewriting user permissions. Session activity merges timestamps through CAS without recreating revoked records; token rotation compares the old hash as well.

For local accounts, `access.user.write_cas` creates a user from `status`, `roles`, `grants`, and `authority_ceiling`. Console generates `account_id`, `identity_path` (`identity://console/accounts/<account_id>`), `bootstrap_owner`, `created_by`, and `created_at`. An update may omit these server-owned fields; if supplied, they must match the stored values. The username `root` is reserved for bootstrap. Reusing another username after deletion creates a distinct account identity. With a host `AccountAuthority`, local user and role management actions are omitted from discovery and rejected at dispatch; the host authority owns those account facts.

Calls are not deduplicated. Streams deliver one event per frame and do not offer history resumption or batching controls.

## Shared admission and query limits

`console.max_concurrent_calls` defaults to 64 (range 1–4096) and caps active management calls across Rust, HTTP and WebSocket, starting before bearer State lookup. `console.max_concurrent_authentications` separately defaults to 64 (range 1–4096) and caps credential and session checks. Saturation rejects without an unbounded waiting queue. Password hashing and external verifiers have their own narrower limits.

`console.queries` bounds State lists (512 rows), Fact pages (256), traces (512), Process pages (256) and their management query page bytes (131072) by default. Execution output reads use the separate `console.executions.max_output_page_bytes` limit. These service budgets are independent of `console.ws` connection, frame and delivery limits. A response must fit both its service and transport budgets.

## Outbound Limits

The bounded WebSocket event queue must charge retained payload bytes and entry permits until an event is sent or discarded. Cancelling a subscription must discard its queued data and release those charges without reordering surviving events or moving them into an independently unbounded queue. This differs from cancelling one pending service receive, which retains an already acquired event for the next receive; neither cancellation changes an accepted effect's commit status.

Subscription reception is a local observation, not permission to disclose a frame after queueing. Adapters obtain `delivery_authority()` once per stream and retain shared guard clones with queued frames. WebSocket validates that original authority after socket readiness, immediately before the data handoff; a grant/session change or expired original deadline can therefore suppress an already queued event. Withholding a frame does not reverse its source commit or an execution effect. Queue credits remain owned until the frame is sent or discarded. Custom transports must implement the same final-handoff check; see [Service boundary](console-protocol.md#service-boundary).

`max_frame_bytes` applies to incoming and outgoing protobuf frames (default 1 MiB, range 16 KiB to 4 MiB). Outbound conversion checks cumulative inline bytes, at most 16,384 Value nodes and 30 Value nesting levels, and at most 256 path segments before cloning payloads. The completed protobuf message must also fit the exact frame byte limit before its output buffer is allocated. Values are never truncated.

`send_timeout_ms` applies to every outgoing frame, including replies and errors (default 5 seconds, range 100 ms to 60 seconds). It replaces `event_send_timeout_ms`. If a reply cannot be encoded within the limits, the server sends a small `Internal` error carrying the original request ID. The action may already have completed; this error does not indicate rollback or a safe retry. A transport error or send timeout closes the connection.

Live subscriptions share a 256-entry queue per connection. `max_pending_event_bytes` bounds encoded subscription data bytes queued or being sent (default 1 MiB, range 16 KiB to 16 MiB). A worker prepares at most one bounded frame before attempting queue admission and never waits while retaining an unaccounted frame. Exhausting either queue limit closes that subscription. The queue budget excludes the independent control path: at most `max_subscriptions` pending closure reasons (1 KiB each) and one closure frame being sent. It also excludes source broadcast storage, native action outputs, temporary wire conversion structures, socket buffers, or total process memory.

WebSocket delivery workers own their shared service subscriptions. Lag, source closure, a failed projection or encoding, and worker failure release the subscription slot and emit `SubscriptionClosed`; these failures invalidate the unsent tail of that subscription generation. A structured failure returned by the shared service drains previously accepted queued events before `SubscriptionClosed.failure`, while the visibility deadline still permits delivery. Normal completion also drains queued events before closure. An active subscription ID cannot be reused: unsubscribe first. Old events and closures cannot affect a later subscription using the same ID. Closing or cancelling the session aborts its workers. Shutdown uses one 250 ms deadline for all workers; failure to finish closes the session. This bounds asynchronous waits. Tokio cannot forcibly preempt synchronous adapter work or a blocking destructor; host adapters must cooperate with cancellation.

Subscription visibility lasts for the requested `ttl_ms`, at most ten minutes. Expiry discards pending data and emits `SubscriptionClosed`. Successful `Auth` clears previous subscriptions before accepting the new session. Each event reauthenticates the SID; a changed identity, effective grant set or MFA level closes the connection and requires new authorization and subscriptions. Data sends use the earlier of the visibility deadline and send timeout, and check expiry at the actual socket handoff, after any adapter-owned buffering/readiness waits. Data already accepted by the socket cannot be retracted. Cancelling a generation discards its queued frames and releases their byte/entry permits; remaining generations retain their original event order and charges.

## Fact Queries

`audit.facts.recent` returns one reverse append-order page, defaulting to 64 records. `lineage.trace.read` requires `process` and returns one forward append-order page, defaulting to 128 records. Both accept `from`, `before`, `limit`, `max_bytes` and `max_examined`; recent also accepts an optional `process`. Cursor and process inputs accept nonnegative integers or decimal `u64` strings. Cursors and numeric identifier fields are projected as decimal strings, preserving the full range in clients; `op_id` retains its composite OperationId string format. `from` is a physical global append position, including for a process-filtered trace, rather than an offset into its matching rows. Order is fixed by the action.

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

Continue recent with `before=next` and the same `from`; continue trace with `from=next` and `before=end`. Preserve filters and budgets. Empty pages may have continuations. Reverse pages shrink their upper bound. A fixed append interval excludes later appends but does not freeze in-place completion updates. Trace additionally returns `partial=true` and `partial_reason` for omitted materialized lineage indexes; these fields are independent of pagination completion. No all-history trace count is returned.

The record limit is capped by `console.queries.max_fact_limit` or `max_trace_limit`. JSON bytes are capped by `console.queries.max_page_bytes` (at most 256 KiB), independently of transport. Outbound conversion and exact frame limits are checked separately. Candidate examination defaults to `max(limit, 4096)` and is capped at 65,536. Zero budgets are invalid; larger requests are clamped. A first matching record that exceeds the byte budget fails the read. `lineage.fact.read` uses an indexed, byte-bounded lookup and also accepts `max_bytes` and an optional `process`, defaulting to `op_id.process`. It requires read authority for that process and only returns a record whose current caller matches it. A different caller is reported as unknown, without exposing the record. These limits do not measure decoded heap or total memory.

`runtime.process.inspect` and the `runtime` section of `state.snapshot` default to metadata only. `include_recent_facts=true` requires an explicit `process`, Fact-read authority for `state://fact/<process>`, and the action's visibility metadata. `recent_facts` is one bounded reverse page; there is no full-history `fact_count`. `limit` bounds process rows, `cursor` continues in ascending process ID order, and `max_bytes` bounds projected process metadata. `fact_limit` separately bounds the optional embedded fact page. `process` and `cursor` are mutually exclusive. Metadata-only reads require the process-inspect capability, as with runtime snapshot sections. Sensitive expansions additionally require MFA level 2 and visibility metadata. Results use `entries/next_cursor`; rows contain `parent` and `child_count`. Clients can assemble their own tree from pages. An explicit process absent from the retained table has status `Unknown` and can still be used to read authorized retained facts. A snapshot accepts at most one runtime section. `health.summary.process_count` uses the table's constant-time retained count.

Session pages are ordered by their storage keys and contain session summaries. They filter expired records within the examined page without deleting them; a page may therefore be empty while still carrying a continuation.

`health.summary.fact_sample` contains `sampled_facts`, `decisions`, and the same page metadata. These counts describe only the recent sample. Top-level `fact_cursor` is a decimal append-head string, observed separately from the sample, and does not track completion updates. Process counts still enumerate the process table.

## Mutation Results

Mutation actions run after schema, step-up and concrete target authorization checks, then return the handler result directly. The service does not write per-mutation started/completion audits or return ActionReceipt. Diagnostic history is not a commit barrier. A failed or lost response still does not prove rollback; inspect the actual data or external effect before repeating a mutation.

Console owns this authentication summary. It describes the session validated for the request or a successfully issued session, not a new authentication performed by every audited action. Failed or incomplete authentication has no summary. Connection-level `console_ws` events, the SID-only `console_credential` logout record and independent execution events retain only known attribution; a cached principal or an account owner does not establish current authentication. Gateway audit Facts have no top-level `mfa_level`. The level is derived from complete session evidence; it is not an independently writable authentication fact.

## Live Audit

Host event labels come from a complete administrative gateway Fact envelope, recognized by `xolotl_types::audit::gateway_audit_event`. They are not restricted to `console_` names. Ordinary Operation output containing an `event` field cannot acquire that event's `Custom` audit tag. The kernel does not interpret application details as authentication or authority; see [Facts](state-and-facts.md#facts).

`audit.facts.stream` starts with future notifications and does not replay history. Its optional `process` filters the current record before checking its byte budget; unrelated oversized records are ignored. Appends and outcome updates both trigger a bounded indexed reread; each event is an upsert keyed by `op_id`. Notifications may arrive out of commit order or yield repeated current values. Clients should replace their record for that identity rather than count every notification as a distinct Fact.

Lag, a missing record or a bounded-read failure emits `SubscriptionClosed` and releases the subscription slot. The shared lifecycle and queue limits above also apply. After closure, resubscribe and reconcile retained Facts with explicit bounded pages, including old slots whose outcomes may have changed. Establish the live subscription before reading pages to reduce the gap, and restart reconciliation after any further lag; this is not an atomic snapshot or a durable update log.

The live event envelope contains no revision or resume cursor. Append cursors cannot resume outcome updates in old slots. `SubscriptionClosed.failure` preserves a structured service error when one is known, including any execution reference; ordinary completion has no failure.
