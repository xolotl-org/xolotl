# External Gateway

The external gateway connects out-of-process programs to Xolotl as Provider or Source projections. gRPC and WebSocket are transport implementations for the same session protocol.

## Roles

Provider sessions expose remote effect handlers declared by the selected installation projection. After `RoleReady` confirms the daemon-selected session context, the daemon registers those projection bindings for the ready session and dispatches invocations only for registered effects.

Source sessions emit inbound events and can receive host-issued outbound commands. A ready Source projection that declares commands publishes one callable Effect resource; the daemon routes it through the shared Source command hub to a current session. Source events enter the same schema, policy, capacity, dedupe, and taint paths over gRPC and WebSocket.

Provider and Source are the only external projection roles.

## Transports

External gRPC listens on `[server].external_grpc_addr` or `XOLOTL_EXTERNAL_GRPC_ADDR` and serves `xolotl.v1.external.ExternalService.Session`.

External WebSocket listens on `[server].external_websocket_addr` or `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` and serves the same logical session frames over `/ws`.

Both transports use the same daemon-side handler implementation and Provider/Source admission rules. The stock daemon constructs a handler per listener and shares Source command routing and publication across them.

For embedding, `xolotl-gateway-websocket` accepts any `ExternalSessionHandler` and has no tonic dependency. The handler keeps its own associated error types; service constructors take a `fn(OutboundQueueError) -> H::OutboundError` to map `Full`, `Closed`, `InvalidFrame`, and `SequenceExhausted` into the host's error type.

Outbound admission never waits for queue capacity: a full queue rejects only the submitted frame and preserves already queued frames. An accepted enqueue does not prove remote delivery. Handler errors need `Debug` for local diagnostics and close the session without becoming a wire status. The daemon chooses a shared handler whose errors use tonic; standalone WebSocket hosts do not need that choice.

`session_route(service)` returns an Axum `MethodRouter` with its service state already attached. Hosts can mount it with `.route("/external/session", session_route(service))` and compose their own routers and middleware. Supply `ConnectInfo<SocketAddr>` when serving the router, for example through `into_make_service_with_connect_info::<SocketAddr>()`. Custom mounts use the same upgrade handling, transport-security checks, and shared service limits as the default `serve` helper on `/ws`.

## Configuration

The daemon shares one `ExternalSessionScope` across gRPC and WebSocket, admitting at most 256 aggregate live sessions including handshakes. Embedded services own a scope unless the host injects a shared one. Closing rejects admission and interrupts owned readers, writers and notification workers; asynchronous shutdown joins them and remains resumable if its waiter is dropped. Dropping a gRPC response interrupts even a pending inbound read. `on_closed` releases local registrations synchronously, including partial handshake and cancellation paths.

Incoming messages default to 1 MiB, with a 10-second first-frame and 300-second idle deadline. WebSocket limits apply before fragmented message assembly. Provider cancellation enqueues best-effort notification synchronously; one worker per session accepts at most 32 queued notifications, with a one-second deadline from enqueue including queue wait. Saturation may discard this signal without delaying local release; enqueue or send success does not prove remote rollback.

Listener addresses, transport security, WebSocket transport caps, and Provider/Source numeric limits are owned by [Configuration](configuration.md). This page does not repeat the key list or default TOML block.

After a session is admitted, those settings bound Provider dispatch and result resolution, Source event ingress, Source command dispatch, and event idempotency retention. Source event payload-size limits, stream capacity, overflow behavior, and event-ingress rate limits are declared on each Source projection.

## Transport Security

Transport-security modes and their required certificate or proxy fields are documented in [Configuration](configuration.md). A listener that rejects its transport-security mode fails before accepting external sessions.

For a trusted reverse proxy, remove client-supplied forwarding headers and overwrite the adopted `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`, or `Forwarded` field with a single value. The gRPC listener rejects duplicate headers and appended forwarding chains; the WebSocket listener requires one `X-Forwarded-Proto` header. In local-trusted WebSocket mode, a supplied browser `Origin` must be one valid local origin; duplicate `Origin` headers are rejected.

## Session State

External installation declarations live in the storage owner's typed catalog. Console `external.installation.read` and `.list` return the storage-owned record, including `definition` and `installation_epoch`. `.install` requires an absent record; `.update` and `.uninstall` compare both `expected_installation_epoch` and `expected_version` from that record. State values under `state://kernel/external-installations/*` grant no admission authority.

The storage-issued `installation_epoch` remains stable across declaration updates and changes after retirement and reinstallation. Every install or update assigns a new `scope_epoch` to each Source projection. The daemon selects both in `SessionContext` and checks them against the catalog for Ready and subsequent work. A config version change also invalidates an older active session context. A Provider context has `scope_epoch = 0`.

Approved session state is read from:

```text
state://kernel/external-sessions/<installation_id>/<role>
```

The session record must match the connecting installation id, role, and `installation_epoch`. The daemon rejects missing, mismatched, revoked, or non-ready session records before business frames can flow. It also verifies that the referenced pairing is approved for this role and installation incarnation and carries the same credential generation; a partially published session record cannot authenticate on its own. A declaration update can keep an approved pairing valid while requiring a fresh active session context for the new config version.

`SessionContext.key_epoch` is the current AEAD epoch selected from that role's session record. The client uses this value in its encrypted Ready; an old connection may use only the immediately preceding epoch for a `control.config_ack` drain frame. Older epochs are rejected. New business frames use the current epoch or establish a fresh session.

`pairing.create` requires a caller-chosen `pairing_id` retained before the request, so an uncertain result can be checked against that record. Pairing creates a 32-byte session key and exposes its 64-character hexadecimal form only through the one-time `display_secret` edge requested by Console `pairing.create`. Pairing State records retain the hash, checksum, status, and credential generation; session projections retain their status and credential generation. Neither contains the key.

The stock daemon holds pending and issued keys in a separate credential vault. With redb storage, its path is derived from `storage.path` by replacing the extension with `.external-credentials` (for example, `xolotl.db` becomes `xolotl.external-credentials`). It is encrypted with an independent host key supplied by `[external_credentials] key_file`; plaintext, wrong-key and damaged files are rejected. Memory storage uses an in-memory vault. The daemon refuses a credential that does not match the installation incarnation and generation.

With redb, back up and restrict access to the vault, its independent key, and the corresponding State installation and session records. These are separate stores; pairing State writes and vault updates do not form one transaction.

Approval persists the vault key before publishing role-session State and the approved pairing status. If approval stops while the pairing remains `created`, retry the same pairing ID: the vault reuses the already issued credential generation after matching the original key and installation. If the status is already `approved` after a lost response, inspect it before initiating another pairing.

A vault write whose durability becomes uncertain after replacement blocks further key issuance and session authentication in that daemon process; restart reloads the on-disk vault and normal admission checks decide again.

To abandon an unapproved `created` intent, deny its pairing ID and then create a fresh pairing ID. Denial and creation commit separately; there is no atomic pairing replacement. After an uncertain response, inspect each record and resolve the unfinished step. An approved pairing cannot be denied through this intent workflow.

An exact same-ID create retry in the current daemon process may deliver a display secret that has not yet been consumed by the Console edge. The durable vault never reconstructs that one-time display after a restart or after consumption; if it is unavailable, deny the new intent and create another ID.

## Provider Flow

Provider invokes are sent only for projected effects declared by the installation projection and registered for the ready session. Invoke input must match the Provider projection's `input_schema`. Provider results are accepted only for daemon-registered in-flight invocations. The result must arrive on the same ready Provider session generation before the invocation deadline and within the registered result size limit.

The original invocation deadline is converted once to a monotonic deadline covering outgoing queue wait and result wait. Both deadlines are checked before sending; an already accepted result is not replaced by a later timeout. Rejection before sending an Invoke is definite. Once sending starts, a send failure, invocation deadline, or session disconnect has an unknown outcome: the host reports `Failure::OutcomeUnknown` with the original invocation ID (the Kernel OperationId) and reason `delivery_or_session_lost` or `deadline_exceeded`. These reasons are host-classified, not Provider-supplied. Do not automatically retry an effectful invocation with an unknown outcome. After a sent invocation times out or is cancelled, the daemon removes its owned local registration and waiter, then asynchronously attempts a `ProviderCancel` frame with a one-second send ceiling. This frame may not be delivered; local release does not wait for it. This is cooperative cancellation; it does not promise to undo external effects that already happened.

## Source Flow

Source events are admitted only after the session is ready and generation fields match the daemon-selected context. Before deduplication or sink append, the backend checks the active `scope_epoch` and current declaration in the same commit domain; a queued old event cannot recreate a retired scope. Each accepted event records an expiry fixed from daemon receipt time and that admission's deduplication window; later configuration changes affect only new decisions.

The declared State sink, event decision, optional stream sequence, rate state, and private receipt are updated in one backend commit. An accepted acknowledgement means they committed together. A failed `seq=1` does not let `seq=2` skip ahead.

### Ordered Streams

An ordered Source stream has an explicit lifecycle on a ready Source session:

1. Send `SourceStreamRequest { Inspect }` with a stream ID to read the scope's control revision and the stream's current state, if open.
2. Send `Open { expected_revision }` using that revision. Storage reserves one active-stream slot, issues a never-reused `stream_epoch`, and sets `last_seq = 0`. The request ID is the stable Open identity. A lost response can be retried with the same request ID and revision to recover the same active epoch. If another control operation changed the scope revision, inspect again before making a new Open request.
3. Send ordered `InboundEvent` frames with `stream_id`, the next positive `seq`, and that positive `stream_epoch`. All three fields are required; data frames cannot open a stream. After reconnection, Inspect returns the active epoch and last accepted sequence so the Source can continue.
4. Send `Retire { stream_epoch }` when this logical stream is finished. Storage fences later events from the old epoch and returns its slot in the same commit. The same stream ID can then be opened with a new epoch. Disconnecting a session does not retire its streams.

`SourceStreamResult` echoes request ID and stream ID and returns a snapshot, retirement revision, or typed rejection. Open and Retire are conditional on the current scope; an old session cannot mutate a retired scope.

The built-in stores bound active ordered streams across all scopes with `[storage].source_stream_limit` (default 4096, configurable from 1 through 65536). A full quota rejects Open without changing the sink or event decisions; existing streams can still advance. Scope retirement also fences commits, but its remaining positions return quota through bounded maintenance. A lost Retire response can be investigated with Inspect; its current snapshot does not prove that a past event or external effect never happened.

For ordered events, event-ID decisions and receipts are scoped by `stream_epoch`; unordered events use no stream epoch. Reopening a name may reuse an old event ID without being mistaken for the prior stream's Duplicate.

Within a retained decision's window, the same ID is a Duplicate only when the lossless tagged Value payload and, for an ordered event, `stream_id` and `seq` match the accepted event. Reusing the ID for different content or position is a deterministic `event_id_conflict` rejected ACK; it does not change the original decision, sink, sequence, or rate state. Event ACKs echo the event ID and optional stream epoch so old and new lives can be distinguished. A retired event is rejected before deduplication even if its earlier decision is still retained.

### Event Capacity And Storage

At installation, the selected Source storage owner validates the declaration's budgets. The built-in memory and redb stores allow up to 1 MiB per tagged Value encoding, 65,536 entries in the resulting Source sink, a 64 MiB product of declared entry count and inline byte limit, and 65,536 hits per rate window. Installation and projection identities are each limited to 256 bytes; the canonical sink path is limited to 4096 bytes. Ordinary State writes have separate limits; DropOldest checks the sink after pruning and appending, so it can recover a List that previously exceeded Source capacity.

Console rejects any external installation when no `source_management` port is installed; a Provider-only declaration skips Source budget validation. A custom store may define its own limits.

The built-in stores measure `max_inline_payload_bytes` from the exact tagged Value encoding, including `Null` and escaped strings. The gateway does not encode the payload separately just to measure it; the store combines size measurement with the event-ID fingerprint during commit. The daemon rechecks the installed store's limits when it loads a Source session declaration.

Current entry count and the encoded sink representation have separate limits. Provenance and representation overhead can cause a deterministic capacity rejection before `capacity.max_events` is reached. Such a rejection does not record an event decision or advance a stream. Source admission and charging follow the [Source storage contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs).

The declared sink remains an ordinary State path whose logical value is a List. Redb uses State's shared top-level List representation for both ordinary State writes and Source commits; there is no Source-specific conversion. Representation and mutation rules belong to the [State backend](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-storage-redb/src/state.rs). If another writer replaces the sink with a non-list value, the next Source commit returns a deterministic `sink_type_mismatch` rejection without reserving event, sequence, or rate state. Hosts should give a Source sink one writer; an installation-time type check cannot prevent a later concurrent replacement.

Source denotes the external event service; provenance denotes a value's data lineage, represented by `TaintSet`. Neither a Source identity nor provenance grants access; the [types contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-types/src/taint.rs) owns lineage representation.

Embedding hosts supply a trusted `SourceClock` to event admission and maintenance. The store samples it once after acquiring serialization; decision time governs deduplication, rate windows, expiry and cleanup, while `received_at_ms` is documentary only. A regression below the affected scope's committed floor is rejected, not clamped into new allowance. See the [Source clock contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs); it is not a global runtime clock or an outbox.

### Uncertain Commits And Inspection

If the backend cannot determine whether a commit completed, both transports return an event acknowledgement with status `outcome_unknown` and no `reject_reason`. This status does not assert that the event was rejected before commit. The Source should promptly retry the same event ID and payload and, for an ordered event, the same stream ID, sequence, and stream epoch. It is observed as a duplicate only while the prior decision remains retained at the backend serialization point and the stream is still active.

An event can arrive before expiry but wait through asynchronous policy work until cleanup has removed the old decision. A retired stream's old event is rejected before deduplication; inspection of its retained receipt is the way to investigate the earlier attempt.

A Source data frame cannot inspect receipts or alter the declared sink or taint. The current sink stores only payloads, so a missing payload, especially after DropOldest, does not prove that an event was never committed.

An authorized operator can call the Console action `external.source.claim.inspect` with `installation_id`, `projection_id`, `scope_epoch`, `event_id`, and `claim_id`, plus `stream_epoch` for an ordered event. Epochs are positive decimal u64 values and may refer to retired scopes or streams. Omit `stream_epoch` for an unordered event. The three textual identities are nonempty literal segments of at most 256 UTF-8 bytes; the claim is exactly 32 lowercase hexadecimal digits.

The action requires MFA level of at least 2, `perform` permission on `effect://external/source/{installation_id}/{projection_id}/claims/inspect`, and `ActionCall.justification` of at most 1024 UTF-8 bytes that is nonempty after trimming. Console owns the authenticated disclosure boundary; see [inspection admission](console-actions-and-streams.md). The Source port performs an exact, read-only lookup from one consistent storage view, without a private audit write.

`external.source.event.decision.inspect` accepts installation, projection, scope epoch, event ID, and the stream epoch for an ordered event. It separately requires `perform` on `effect://external/source/{installation_id}/{projection_id}/events/inspect`, with the same MFA, justification, and current disclosure requirements. It recovers a currently retained accepted decision and its claim receipt within that stream epoch; it does not enumerate events or past attempts. If the same event ID is accepted again after the earlier window within one epoch, the lookup returns only the newer decision and cannot establish the earlier attempt's outcome.

The response is `status: committed` with a `receipt`, or `status: unproven` without one. The receipt includes the scope epoch, optional stream epoch, four claim identifiers, original `sink`, and `received_at_ms`; it contains no event payload. `Unproven` means no retained receipt was found, not that the attempt never committed. Neither this result nor an inspection error authorizes automatic compensation or replay. Inspection does not modify the sink or provide claim enumeration, deletion, or maintenance.

Claim identifiers come from the Gateway's structured host incident log when a Source commit returns `Indeterminate`; Source ACKs do not disclose them. For ordered events the log also records the stream epoch. Protect and retain those logs if operators need exact-claim diagnosis. If the log is lost, the process exits before logging, or only the network ACK is lost, event-decision inspection can still recover a retained accepted record when the operator knows the stream epoch from the Source Open response or control log. Once the decision expires or is cleaned, absence cannot prove rollback. Inspection can still read retained evidence after its installation has been removed; current installation presence is not required.

An embedding host installs one `ConsoleConfig.source_management` object for declaration validation, typed catalog access, and evidence inspection. It gives Console no event-commit, stream-control, or maintenance access. The stock daemon derives this object and its Standard and external-ingress ports from the same Source store. Embedding hosts must preserve that owner relationship across separately assembled services. The management port defaults to absent; the daemon installs it when constructing Console, even if no external listener is enabled. All messages remain v1.

### Maintenance And Outbound Commands

The shared command hub has a global unit budget across both transports, configured by [`[external_gateway].source_command_limit`](configuration.md#external-gateway). Pending commands, retained terminal IDs, and installation/projection rate rows count against it. A pending command already reserves its terminal ID slot; a new rate row needs a separate unit. Capacity rejection occurs before send or rate consumption and never evicts valid unexpired IDs. An embedding registry with a zero dedupe window frees the ID at terminal transition, but retains its rate row until that window expires; a zero daemon dedupe setting selects the default instead. Registration and periodic Source maintenance examine at most 64 retained ID and rate rows per cleanup, including for an idle hub. An earliest-expiry hint skips unnecessary traversal, and an in-memory cursor resumes each sweep. This bounds units, not bytes or RSS; command state is not persisted.

Embedding hosts can choose a positive budget with `SourceCommandRegistry::with_capacity(NonZeroUsize)`; `Default` uses `DEFAULT_SOURCE_COMMAND_LIMIT`. `occupied()` reports charged units. Each `expire_retained(now)` call returns `SourceCommandMaintenanceReport { examined, removed, reached_end }`; completion means that the current sweep ended or no sweep is due, not that future insertions have been examined. Hosts must also call it during idle maintenance. The registry reuses its primary tables without a per-ID expiry index; zero released units do not imply completion. Command metadata remains local to the running host.

Periodic cleanup shares `max_batches_per_tick` across the command registry and Source-private event decisions, rate records, and stream positions. Busy owners alternate batches, with the turn preserved across ticks even when the budget is one. Each charged batch examines at most 64 rows; an owner that finishes without examining rows yields its unused budget. The hub lock is released between batches and tasks can run before the next batch. Source-store cleanup removes expired decisions and receipts, idle rate records, and retired-scope stream positions, returning stream quota; its cursor survives a redb restart, unlike the in-memory command cursor. Rows inserted before a cursor are revisited after wraparound. Active streams are retired explicitly, and State history has its own retention policy.

Source projections that declare outbound commands must provide command action and successful result schemas. When such a projection becomes Ready, the daemon publishes `effect://external-source/{installation_id}/{projection_id}/command` with the `dispatch` method (`perform`, effectful; unary or AsyncProcess). Kernel Operations invoke it with the command action as input. Console can use `runtime.operation.invoke` or `.submit` after the host exposes the exact resource and the account holds a matching `perform` grant; this namespace is not exposed automatically. Kernel grant, policy, Fact, and taint checks still apply. The host-managed binding can route over either gRPC or WebSocket. Dispatch requires exactly one current eligible Ready session, validates the declared schemas and command limits, and correlates `CommandResult` by command ID.

A call without a shorter deadline has a 60-second daemon ceiling. The deadline is converted once at registration to a monotonic deadline shared by send and result waiting. Before send, both the original wall-clock deadline and that monotonic deadline must still be valid. Pre-send expiry releases the command registration without retaining its ID; an already admitted rate hit remains charged. Rejection before send is definite. Once sending starts, a timeout, disconnect, or transport error yields the host-authored `Failure::OutcomeUnknown { operation_ids, reason }`; this command contributes one outbound command ID to `operation_ids`. The outbound ID is the invoking Kernel OperationId, so a Kernel deadline that interrupts the command reports the same identity. The endpoint classifies its failures as `deadline_exceeded`, `delivery_or_session_lost`, or `result_identity_mismatch`; Kernel deadline uncertainty also uses `deadline_exceeded`. None of these reasons comes from Source-supplied text. When this failure reaches Console, its error has code `OUTCOME_UNKNOWN` and an `outcome_unknown` object with `operation_ids` and `reason` across the Rust service, HTTP `/calls`, and WebSocket. A Source-returned error cannot claim that host-authored outcome. Cancellation may leave the caller without a response, while the pending ID remains fenced for the dedupe window. An accepted enqueue does not prove execution. Do not automatically retry an effectful command whose outcome is unknown. v1 has no Source command cancellation frame, durable outbox, or durable command receipt; a daemon restart cannot resolve an in-flight command.

## Secure Envelopes

External gRPC and WebSocket use the same v1 handshake. The endpoint first sends a plaintext `RoleSessionClientHello`; the daemon returns a plaintext, authoritative `SessionContext`. Both sides compute the transcript hash from those validated typed v1 messages: SHA-256 over the domain bytes `xolotl/external/session-transcript/v1\0`, followed by each message's big-endian u64 byte length and canonical typed-protobuf encoding, in Hello-then-Context order. Unknown protobuf wire fields are excluded by the typed conversion.

The endpoint then sends `RoleReady`, echoing the entire selected context, inside a `SecureEnvelope` with AAD frame type `role_ready` and direction `client_to_daemon`. A plaintext Ready is rejected; the daemon does not register Provider bindings or admit Source events until it has authenticated this envelope and checked the echoed context.

After Ready, every client business/control frame must be sealed: `InboundEvent`, `SourceStreamRequest`, `CommandResult`, `InvokeResult`, and `ControlFrame`. Every daemon business/control response is sealed too: `Invoke`, `OutboundCommand`, `EventAck`, `SourceStreamResult`, and `ControlFrame`. Transport stream errors and connection closure remain transport events, not business frames.

An external client must decode the inner `ExternalFrame` only after opening the envelope, and verify that its kind matches the authenticated AAD `frame_type`. It must also verify `daemon_to_client`, the selected installation/projection/role/session and generations, the transcript hash, the key epoch allowed by its session policy, and its receive-side replay window. Frame types use the lower-case snake-case variant name (`inbound_event`, `event_ack`, and so on); controls use `control.<kind>`, such as `control.config_ack`. AAD role is `provider` or `source`.

The 32-byte pairing key is the PSK for v1 HKDF/ChaCha20-Poly1305 envelopes. AAD binds the installation credential generation, projection, role, session, canonical Hello/Context transcript hash, key epoch, frame type, sequence number, binding generation, and a required direction domain: `client_to_daemon` or `daemon_to_client`. The daemon rejects reflected daemon-to-client envelopes as inbound requests.

AAD context and key generation must match the selected session and current authority; possession of an old pairing secret alone does not reopen a retired installation or revoked session. The Ready envelope uses exactly the key epoch in the plaintext Context; that field is protected by the transcript hash, so changing the Context in transit cannot create a valid Ready.

Each sender uses its own monotonically increasing sequence, starting at zero, and never reuses it across a rekey on the same connection. The stock daemon retains one bounded inbound replay window per session rather than one per key epoch; closing the session releases it. The first authenticated sequence may establish an empty window at any value. Subsequent duplicate, too-old, and too-far-ahead sequences are rejected before decoding the frame body.

For independent v1 clients, serialize the inner typed `ExternalFrame` as protobuf. Form the authenticated byte string by length-prefixing the domain `xolotl-secure-external-envelope-v1`, installation ID, credential generation, AAD version, projection ID, role, session ID, sequence, frame type, binding generation, credential generation, transcript hash, key epoch, and direction, in that order. Every prefix is an unsigned 64-bit little-endian byte length; AAD version uses four little-endian bytes and the other numeric values use eight little-endian bytes.

Derive a 32-byte key with HKDF-SHA256 using the 32-byte pairing PSK, salt `xolotl/external/session-envelope/chacha20poly1305/v1`, and that same authenticated byte string as HKDF info. Draw a fresh 12-byte random `nonce_prefix` for each envelope and XOR its last eight bytes with the big-endian sequence to obtain the ChaCha20-Poly1305 nonce. Authenticate the byte string as AEAD AAD.

The protobuf `EnvelopeAad` carries these fields on the wire; its field order is not the cryptographic byte encoding.

Embedding hosts implement both `open_secure_envelope` and `seal_secure_envelope` in `ExternalSessionHandler`. The shared adapters own framing, the canonical session transcript, direction, outbound sequence, and queueing; the handler owns credential lookup, current key-epoch policy, AEAD verification/sealing, and revocation checks.

The stock daemon resolves the key from its private vault and rechecks installation and session authority on incoming and outgoing frames. Inbound business and open callbacks borrow the selected `&SessionContext`; Ready and Closed callbacks receive owned contexts because they may retain them across the session lifecycle.
