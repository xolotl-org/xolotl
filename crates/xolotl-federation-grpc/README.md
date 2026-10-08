# Federation gRPC transport

`FederationGrpcPublisherServer` serves a node's published streams over a
TLS 1.3 connection admitted by `federation_tls_incoming`.
`FederationGrpcSubscriberClient` dials a pinned peer and owns one bidirectional
`Session`. Each side proves its root-authorized online key against both Hello
frames and the exporter from that exact TLS connection. The client refuses an
implicit tonic reconnect; call `connect` again to establish a new TLS channel
and Session proof.

The host supplies `FederationLocalCredentials`, an authoritative
`FederationPeerPolicy`, and a `FederationService` backed by its local store.
`PeerDialConfig` contains the peer's node ID, URI, TLS server name, trust root,
and client certificate/key. The URI uses `http://host:port` because the custom
connector establishes TLS before tonic sends HTTP/2. The connector accepts only
TLS 1.3 with the security policy's hybrid key exchange and h2 ALPN, and disables resumption
and early data. The peer's Hello node ID must match `expected_peer` and its
current signed proof must pass local policy before any application request.

Use `connect_bidirectional(route, local, policy, runtime, service, call_store)`
when the dialing node also publishes streams. The listener can obtain the
authenticated peer's outbound handle with
`server.connected_peer(peer, ServedCapability::Publication)` and
issue Open/Read/ACK on the existing connection. `closed().await` lets a dial
supervisor detect disconnects and create a fresh TLS Session. Both directions
have independent request correlation and recheck current peer policy for each
business frame.

Protocol v1 Hello advertises the installed Publication, Invoke, Object and
Snapshot service groups and binds them into the authenticated transcript.
Ordinary `connect` advertises no reverse services. Selection filters by the
required group; the advertisement grants no authority, and unknown groups or
unsupported protocol versions reject. All connections for a host share its transport
runtime, including object receivers.

Call clients expose `prepare_call_as`, `invoke_call_as`, `inspect_call_as`, and
`cancel_call_as`. A server installs a durable `FederationCallStore` for call
authority and state, plus a `FederationCallInvoker` for execution. Its Prepare
gate verifies the exact current executable contract before reserving a CallRef. Its Invoke
path coordinates the original Kernel work identity and checked acceptance
receipt. Without the bridge, Prepare and Invoke return Unavailable before
changing target call state. A Preparing status never proves Kernel
acceptance or execution. A caller must persist its own intent, input and
CallRef before using Invoke or retrying an indeterminate result.
Persistent call records retain business evidence, not restartable programs.
After restart, accepted calls without terminal evidence remain unknown; do not
replay their effects. See the [Kernel call bridge contract](../xolotl-federation-kernel/src/lib.rs).
For production source ordering, use `prepare_call_persisted` with a durable
`FederationOutboundCallStore`, followed by `invoke_call_persisted` and
`inspect_call_persisted`. These methods commit each source transition before
the next wire frame. An indeterminate Invoke still requires reconciliation
against its original CallRef; no new target call is allocated automatically.

For a receiver, call `open_and_install(open, &service)` to install the verified
Open result under current local authority. Then call
`read_accept_ack(read, stream, &service)` with the expected stream and the
persisted inbox cursor. It verifies the Batch identity, record digests, bounds,
and sequence continuity, accepts each record through the local store, and
ACKs the publisher only after acceptance succeeds. A partial acceptance can
be retried from the persisted cursor; an indeterminate Open or Close uses its
same stable control request ID. The lower-level `open`, `read`, `acknowledge`,
`inspect_subscription`, and `close_subscription` methods allow a host to own
those steps itself.

The client limits decoded protobuf frames, negotiated batch sizes, pending
requests, command queue size, TLS handshake time, and each response deadline.
Every response must match a pending request number and its expected variant and
business identity. An unknown, replayed, malformed, or late response closes
the Session and fails its outstanding requests.
