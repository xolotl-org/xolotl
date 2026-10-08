# Configuration

`xolotl.toml` is bootstrap configuration. It controls storage, listener addresses, root bootstrap credentials, external gateway limits, console resource limits, and transport-security settings. The default `xolotl.toml` is optional; set `XOLOTL_CONFIG` to load a specific file. An explicit path must exist and be readable, or the daemon fails startup. Relative paths inside the file, including storage and TLS material paths, are resolved from the daemon's working directory, independent of the config file's location. Use absolute paths when launching it from different directories.

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
| `[storage]` | Select `redb` or `memory`, State history, and the global retained Source stream-position quota. Unknown values fail configuration parsing. |
| `[storage.history_maintenance]` | Opt into a time-window policy for `full` State history, with bounded trim attempts and transactions. Omit it to retain all history until the host trims manually. |
| `[server]` | Bind listeners with `console_addr`, `application_grpc_addr`, `external_grpc_addr`, and `external_websocket_addr`. |
| `[storage.observations]` | Opt into observation history with required positive `max_records`, `max_encoded_bytes`, and `max_record_bytes`; the single-record budget cannot exceed the aggregate byte budget. Absent by default. Selected recording rejects at capacity instead of silently evicting evidence; encoded bytes do not bound RSS. Execution identities and business persistence remain independent. |
| `[application_gateway]` | Select the State profile and application gRPC frame, upload/output concurrency, resident output and wait windows. |
| `[application_gateway.request_storage]` | Bound request evidence with `max_records`, `max_bytes`, and `max_record_bytes`. `retry_epoch_ms` independently schedules host retry-range closure: default 900000 ms, accepted 1–86400000 without clamping. Eligible settled evidence is reclaimed; pending and unknown work remains charged. See [Application Gateway](application-gateway.md#retry-ranges). |
| `[external_gateway]` | Set the global Source command capacity shared by external transports. |
| `[external_gateway.source_maintenance]` | Set the Source cleanup interval and shared command/store batch budget. |
| `[external_gateway.grpc]` | Set Provider/Source session limits for the external gRPC listener. |
| `[external_gateway.websocket]` | Set the same Provider/Source session limits for the external WebSocket listener. |
| `[external_gateway.websocket.transport]` | Set WebSocket frame size, first-frame timeout, idle timeout, and connection count. |
| `[console.root]` | Preseed root credentials. |
| `[console.credentials]` | Provide the host-owned key for encrypted Console credential records. Required with redb. |
| `[external_credentials]` | Provide an independent host key for the encrypted external pairing vault. Required with redb. |
| `[console.auth]` | Set session TTL, session count, Argon2 hashing/verification concurrency, and `max_external_verifications` (default 32, clamped to 1–256). Password work runs on the blocking pool; full capacity rejects immediately and canceled work retains its slot until it exits. An external preparation retains its permit through verification, account lookup and session or bounded continuation admission; account-authority reads keep their own timeout. |
| `[console.auth.challenges]` | Shared persisted limits for public-key, Passkey and MFA authentication: global 256, per user 8, per verified source 32, and 1 MiB encoded storage, including in-flight reservations. Counts clamp to 1–1024; storage clamps to 1 KiB–4 MiB. |
| `[console.auth.mfa]` | `install_totp` selects built-in TOTP (default `true`); also sets issuer, enrollment and recent-authentication windows, authentication lifetime, provider-call budget and minimum polling interval. Defaults and bounds appear below. |
| `[console.auth.mfa.totp]` | RFC 6238 SHA1/SHA256/SHA512, 6/8 digits, 15–120 second periods, and 0–2 steps of clock skew. Parameter compatibility is checked when built-in TOTP is installed. |
| `[console.runtime]` | Enable generic resource calls and portable programs, declare unconditional capability exposure, and bound source, outer-input Value, imports, execution, collection and output ports. Input limits count logical nodes, depth and inline bytes, not RSS. Disabled by default; never grants authority. |
| `[console.runtime.budget]` | Per-execution process-tree ceilings: `max_micro_usd`, `max_inflight_ops`, `max_inference_tokens`. Omitted dimensions add no ceiling; zero is valid. Calls, subscriptions and submissions can tighten them. Spending has no calendar reset. |
| `[console.runtime.executions]` | Explicit service-owned submissions, global/account quotas, result, authority and Stream log bytes, retention, cancellation cleanup and reauthorization polling. Disabled by default; submissions belong to the current host lifecycle. |
| `[console]` | Set shared action and attached-execution concurrency with `max_concurrent_calls`, and shared credential/session request concurrency with `max_concurrent_authentications` (both default 64; values outside 1–4096 are rejected). `request_body_timeout_ms` limits HTTP JSON/protobuf body collection (default 30000; effective range 1000–300000). `submission_retry_epoch_ms` selects the daemon's monotonic retry-range closure cadence (default 900000; accepted range 1–86400000, not clamped), independently of result retention. |
| `[console.streams]` | Shared subscription counts and canonical v1 event byte limits across Rust and WebSocket. |
| `[console.queries]` | Bound state, session, process, Fact and trace page rows and bytes independently of transport. |
| `[console.ws]` | Set Console WebSocket frame, connection, idle, rate, subscription, encoded event queue, and all-frame send limits. |

`xolotld` also reads `XOLOTL_CONSOLE_ADDR`, `XOLOTL_EXTERNAL_GRPC_ADDR`, and `XOLOTL_EXTERNAL_WEBSOCKET_ADDR`, plus `XOLOTL_APPLICATION_GRPC_ADDR`, when the matching `[server]` field is absent. A listener stays disabled when both the config field and environment variable are absent.

The application listener requires the optional `application-grpc` feature. Provision its profile through Console before enabling the address; see [Application Gateway](application-gateway.md) for the complete configuration and upload protocol.

`[storage].state_history` defaults to `"current_only"` for both `redb` and `memory`. It retains current State values and provenance, but does not provide historical queries. Select `"full"` to retain State mutations outside the protected `state://vault/**` namespace; this grows with writes, including Source sink updates and Gateway ticket changes. The redb choice is stored when the database is created; reopening it with another choice fails. Source claims, Facts and private service records have separate retention rules; current-only State does not bound total storage. The redb database also owns the two-way `identity://...` directory and its allocation high water. Startup validates that directory before execution; keep it with the persistent records that reference its identity numbers. Reopening business data does not resume programs; see the [storage contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-storage-redb/src/lib.rs).

With redb storage, external pairing keys are kept in an encrypted host-private vault obtained by replacing the extension of `storage.path` with `.external-credentials` (`xolotl.db` → `xolotl.external-credentials`). Configure `[external_credentials] key_file` with an independent 32-byte raw random key at an absolute path; it must be a private regular file on Unix. The daemon opens the key and vault without following final symlinks, checks their permissions, and rejects a missing key, old plaintext vault, wrong key or damaged ciphertext. It also rejects a vault key identical to any active or previous Console credential key. The AES-256-GCM-SIV vault is capped at 64 MiB. New writes use a private temporary file and atomic rename. Memory storage keeps pairing keys only in memory. Back up the redb database, vault and separate key as a matched set: installation/session State and issued keys do not share a transaction, and a missing or mismatched key fails session authentication. Pairing mutations rewrite and sync the whole vault; ready-session key lookup is by installation ID. The active-key map has no independent count limit, so measure file size and pairing latency for large installations. Replacing the vault key without resealing the file is rejected at startup; no automatic key rotation is provided.

Built-in backends never put Console credential vault updates into logical State history. Historical point reads of vault paths explicitly fail. Console credential records in redb are encrypted with a host-owned AES-256-GCM-SIV key; the key never enters redb. Old plaintext rows are rejected. Copy-on-write pages and backups may still contain older ciphertext or plaintext from deployments before this format; encryption does not erase them. Advance the explicit history retention floor when the host no longer needs older non-vault changes. The stock daemon schedules this only when its time-window policy is configured.

Persistent Console storage requires `[console.credentials]` with `active_key_id` and `active_key_file`. The file contains exactly 32 raw random bytes, uses an absolute path, and on Unix must be a regular file inaccessible to group and other users; the daemon opens it without following the final symlink and checks the opened file before reading. The daemon rejects persistent startup without a key. Memory storage without this section creates a process-local key. An embedded Rust host supplies the same `CredentialSealer` to root bootstrap and `ConsoleConfig.auth.credential_sealer`.

To rotate, set a new active key and list the old key as `[[console.credentials.previous]]` with `key_id` and `key_file`. Previous keys only decrypt. A record is sealed with the active key when a credential update writes it; there is no automatic bulk rekey. Keep each old key until every record encrypted under it has been re-sealed, or reads of remaining records fail closed. Hosts sharing one State backend must use the same key IDs and active key. Protect and back up the key files with the matching redb database; old database pages and backups remain the host's responsibility.

## State History Maintenance

`full` history without `[storage.history_maintenance]` retains all non-vault mutations until an embedding host trims them explicitly. To authorize the daemon to advance the global history floor on both `redb` and `memory` storage:

```toml
[storage]
state_history = "full"

[storage.history_maintenance]
retain_for_ms = 86400000 # retain at least a 24-hour timestamp window
```

The policy computes `target = now_millis - retain_for_ms` on each tick and only tries a positive target above the committed floor. Mutations strictly before the committed floor become path baselines; historical reads before that floor fail with `HistoryTrimmed`. The history clock can run ahead of wall time under high write rates. This policy does **not** discover active history readers, audit/replay requirements, or their earliest needed timestamps. Configure a window only after the host has established those retention promises; otherwise leave automatic maintenance disabled and choose manual floors. `current_only` with this section is rejected, and `retain_for_ms` is required and nonzero.

| Field | Default | Accepted range |
| --- | ---: | ---: |
| `retain_for_ms` | Required | `1`–`i64::MAX` |
| `interval_ms` | `10000` | `1000`–`3600000` |
| `max_attempts_per_tick` | `16` | `1`–`64` |
| `max_batches_per_tick` | `4` | `1`–`16`, and no more than `max_attempts_per_tick` |
| `events_per_batch` | `4096` | `1`–`4096` |
| `encoded_bytes_per_batch` | `16777216` | `1`–`16777216` (16 MiB) |

Invalid values are rejected rather than clamped. Every trim is atomic under its event and encoded-byte limits. If the target exceeds one transaction's budget, the daemon probes smaller floors between the committed floor and the failed target, within the per-tick attempt and successful-batch limits. An individual event or baseline too large for one batch can stall progress; the daemon logs that condition and does not skip it. A failed batch leaves the last committed floor in place, including earlier successful batches in that tick. The redb adapter runs each synchronous trim transaction through the bounded blocking port shared with Kernel jobs. Progress, lag, stalls and errors are logged; this does not provide a hard bound on redb file size or process RSS. The policy is independent of Source-private maintenance, Facts and Console audit retention.

## Kernel and root bootstrap

`[kernel].max_handle_slots` defaults to 65,536 allocated slot indices shared by the daemon's executors. Vacant and permanently retired indices count; this ceiling does not limit captured driver payloads or total process memory.

Root provisioning first claims a non-authenticating `provisioning` account, then writes credentials and conditionally activates that exact account incarnation. Interrupted provisioning can be replaced on restart; a displaced attempt cannot overwrite its successor. Existing active, disabled or locked accounts are never reprovisioned. Random-password bootstrap requires stderr to be a TTY; non-interactive deployments must set `console.root.password_hash`, `console.root.password`, or `console.root.pubkeys` first.

## MFA Provider Installation

`console.auth.mfa.install_totp = false` omits the built-in implementation. Its parameter compatibility checks no longer apply, but configuration must still use valid field types and algorithm names. Existing factors and their stored parameters remain; removing their provider does not remove the account's MFA requirement. Unused account recovery codes remain available.

Rust hosts install native implementations through `ConsoleConfig.auth.mfa.providers`; TOML cannot load provider code. The host validates and freezes each declaration during assembly, then uses it for discovery and enrollment admission. At most 32 providers may be installed: 31 extensions with built-in TOTP, or 32 without it. Duplicate installed IDs reject assembly. With built-in TOTP disabled, a Rust host may explicitly install a compatible implementation under `totp`; it must understand that ID's existing verifiers. See [second-factor contracts](console-http-and-credentials.md#second-factors-and-credential-lifecycle).

Each declaration separates enrollment schemas (`begin_schema`, `setup_schema`, optional `pending_schema`) from `authentication.proof_schema` and `authentication.interaction.challenge_schema`. Each enrollment or authentication challenge carries the response schema for that round. An omitted capability is unavailable; operations do not implicitly fall back to another schema. Interactive challenges or external approval require a host-installed native provider; daemon TOML does not install a push service.

Installation and permitted use are separate. Per-provider overrides apply to both native calls and every adapter:

```toml
[console.auth.mfa.provider_usage.totp]
allow_enrollment = false
allow_authentication = true
```

This stops new enrollment, including confirmation of pending setup, while retaining existing TOTP authentication. Each field defaults to `true`; omitted providers permit both uses. IDs must be syntactically valid, but may name a currently uninstalled provider. Configuration never installs code or enables an operation absent from its descriptor. The host validates and freezes usage with the installed implementation.

Authentication permission covers direct proofs and every interactive round for login and step-up. A policy rejection preserves the continuation and does not count as a credential failure. Cancel and factor management retain their existing authorization; recovery codes and Passkey primary authentication are separate. Disabling use does not rotate epochs, rewrite existing evidence or lower the account's second-factor requirement. Allowing enrollment while disabling authentication is valid, but the newly enrolled factor cannot authenticate on that host. Discovery exposes both capability and usage.

The following fields belong to `[console.auth.mfa]`; durations use integer milliseconds. The host clamps each value to the bounds shown:

| Field | Default | Effective bounds and meaning |
| --- | --- | --- |
| `enrollment_ttl_ms` | `300000` | 30 seconds–15 minutes for pending registration. |
| `recent_auth_ttl_ms` | `300000` | 30 seconds–15 minutes for credential-management freshness. |
| `authentication_ttl_ms` | `120000` | 30 seconds–5 minutes for the entire authentication continuation; never renewed. |
| `max_authentication_steps` | `16` | 1–32 actual provider calls, including authentication begin. |
| `max_enrollment_steps` | `16` | 2–32 actual provider calls, including enrollment begin and final verification. |
| `min_poll_interval_ms` | `500` | 100–30000 ms; provider waits can be longer but must fit the original deadline. |

Factor selection and in-flight provider work share the challenge ledger's count and byte limits. After current provider-usage and account admission checks, early polls return the remaining wait without calling the provider or consuming the continuation. Canceling an in-flight round retains its quota until that call exits and retires the entry, or the original deadline permits reclamation. A crashed Future is not resumed or retried. These limits bound storage, concurrency and each ceremony's calls; they are not a global calls-per-second budget. Every instance applies its own frozen usage policy before claiming a shared continuation. A rejected request may return to an allowing instance; cluster-wide restrictions require consistent host configuration. Resuming an interaction still requires a provider compatible with its stored verifier and private state.

## Federation publisher

Federation Sessions accept only protocol version 1. `Hello.served_capabilities`
is a finite bitmap authenticated by the v1 session transcript together with the
protocol version. It advertises served groups, not caller grants or TLS evidence:
`Publication = 1`, `Invoke = 2`, `Object = 4`, `Snapshot = 8`. Ordinary client
connections advertise no served groups. Hosts select a compatible authenticated
peer Session for each operation; an arbitrary live connection is insufficient.
See [Federation API](api-reference.md) for shared transport ownership.

The stock daemon accepts inbound federation Sessions when `server.federation_grpc_addr` is explicitly set, and can initiate outbound Sessions without a listener. It requires the explicitly selected `federation-grpc` build feature, redb storage, a valid ML-DSA-65 online signer authorized by the configured root, and daemon-owned `production_tls` or `mtls`. The default build excludes federation; selecting it does not enable generic durable execution. Plaintext, proxy trust, TLS resumption and classical fallback are rejected. The TLS certificate and federation root are separate identities; the current peer policy is checked against the verified root and online authorization on every request.

```toml
[storage]
kind = "redb"
path = "xolotl.db"
state_history = "full"

[server]
federation_grpc_addr = "127.0.0.1:9446"

[federation]
root_descriptor_path = "/etc/xolotl/federation/root.bin"
online_key_path = "/etc/xolotl/federation/online.pk8"
online_authorization_path = "/etc/xolotl/federation/online-authorization.bin"
online_authorization_signature_path = "/etc/xolotl/federation/online-authorization.sig"

[[federation.peers]]
node_id = "<96 hex digits of the peer root node ID>"
enabled = true
minimum_online_generation = 1
allowed_authorization_digests = ["<96 hex digits of SHA-384(online authorization bytes)>"]

[[federation.peers.exports]]
name = "notes"
serve = true
receive = false

[[federation.streams]]
id = "<32 hex digits of a stable stream ID>"
export = "notes"

[[federation.state_history_publications]]
prefix = "state://federation/public/notes"
stream_id = "<same 32 hex digits>"

# Optional: let any authenticated federation node read this exact stream.
[[federation.public_streams]]
stream_id = "<same 32 hex digits>"
enabled = true
max_read_records = 8
max_read_bytes = 524288

[federation.grpc.transport_security]
mode = "production_tls"
certificate_chain_path = "/etc/xolotl/federation/tls-cert.pem"
private_key_path = "/etc/xolotl/federation/tls-key.pem"
```

The four federation identity files are raw binary data at absolute paths, mode 0600, with no symlinks. `root.bin` is `FederationRoot::encode()`, `online.pk8` is `FederationOnlineKey::to_pkcs8()`, `online-authorization.bin` is `FederationOnlineKeyAuthorization::encode()`, and the signature file contains `FederationRootKey::sign(OnlineKeyAuthorization, authorization_bytes)`. Keep the root private key offline. Obtain the peer node ID from its verified root descriptor; its online digest is SHA-384 of its exact canonical authorization bytes. `mtls` also requires `client_trust_roots` as in the external gRPC TLS configuration.

Provision the identity on a Linux machine that keeps the root key offline:

```sh
cargo run -p xolotl-federation-key -- init-root --out-dir /secure/offline/xolotl-root
cargo run -p xolotl-federation-key -- issue-online --root-dir /secure/offline/xolotl-root --out-dir /secure/offline/online-1 --generation 1 --not-before-ms 1800000000000 --expires-ms 1900000000000
cargo run -p xolotl-federation-key -- inspect --dir /secure/offline/online-1
```

Both output directories must be new absolute paths. `init-root` creates a 0700 directory containing `root.pk8` and `root.bin`; `issue-online` reads and verifies both, then creates a separate 0700 directory containing only the four 0600 files configured above. It never puts `root.pk8` in the online directory or replaces an existing path. Transfer only that four-file online directory to a new private directory on the daemon host, and adjust the four config paths to its location. Keep `root.pk8` offline. `not-before-ms` is inclusive and `expires-ms` exclusive, both Unix time in milliseconds; choose a current validity window and an increasing generation. `inspect` verifies the root signature and online private key, then prints `node_id`, `authorization_sha384`, generation and validity fields as `key=value` lines. A peer config uses the printed `node_id` and places `authorization_sha384` in `allowed_authorization_digests`; `inspect` does not decide whether that peer's local policy admits the authorization.

Peer enablement, exact online digests, generation floor and export rights are persisted in the same redb database before binding. No peer is admitted by default. On a policy change, set `expected_revision` for the peer or export row and `admission_expected_revision` for the online rule to their current persisted revisions; stale revisions reject startup. A new enabled peer starts at peer revision 2 because it is created disabled and enabled only after its other rules are installed. Removing a peer stanza disables its persisted peer row at the next startup. Removing an export stanza disables both directions of that persisted export; an older config cannot restore it without its new revision. Setting `enabled = false` or clearing `allowed_authorization_digests` revokes access. Online generation floors cannot decrease.

Federated resource calls use an exact method manifest and a separate grant. Programs execute only within the current host lifecycle, without restart continuation. The program file must be an absolute, private (0600), nonsymlink JSON `Program`; `{"version":1,"body":{"kind":"input"}}` is a minimal byte echo program. Stock loading rejects native `Module` imports; embedding hosts can supply live step catalogs. `program_id` is `Program::from_json(file)?.compile()?.id()`. Its `contract_digest` is the stock loader's BLAKE3 digest of the exact export, path, method, compiled program ID, stable `identity://` acting path, codec and normalized request grants; see [the digest function](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-daemon/src/federation_catalog.rs). The loader reports its calculated values when a configured digest mismatches, so an operator can inspect and pin both values before enabling a method. A change to any bound component requires a new digest. The configured ID and digest must match at startup. Retained business results keep their original codec contract; unknown work is not re-executed. `bytes_v1` accepts raw bytes and returns raw bytes; other result types need an embedding host's codec and catalog.

```toml
[[federation.methods]]
export = "tools"
path = "/echo"
method = "echo"
program_path = "/etc/xolotl/federation/echo.json"
program_id = "<64 hex digits of the compiled portable program ID>"
contract_digest = "<64 hex digits of the bound method contract>"
identity_path = "identity://federation/echo"
codec = "bytes_v1"

[[federation.methods.grants]]
selector = "perform://effect/echo"
methods = ["invoke"]
flags = []

[[federation.call_authorities]]
presenter = "<96 hex digits of the authenticated peer node ID>"
subject = { kind = "node" }
export = "tools"
path = "/echo"
method = "echo"
contract_digest = "<same 64 hex digits as the method>"
enabled = true
expires_ms = 1900000000000
max_input_bytes = 65536
max_prepare_window_ms = 30000
max_result_retention_ms = 86400000
```

The peer also needs a `tools` export with `serve = true`. A declared method never grants access by itself. Each call rule binds one presenter, subject and exact target, with its own expiry and bounds; changes to an existing rule require `expected_revision`. Removing a rule disables its persisted entry before the listener binds. Prepare checks both the live rule and the executable catalog before allocating a CallRef; Invoke and cancellation use the checked Kernel bridge. The same bridge accepts reverse calls over an outbound Session. Persistent call records retain business request/result evidence, not restartable execution state. Accepted work without a terminal result remains unknown after restart; do not replay unknown effects. See the [Kernel call bridge contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation-kernel/src/lib.rs).

To expose a remote method as a local Kernel effect, configure an exact outbound binding on the calling node and a pinned dial route for that peer:

```toml
[[federation.outbound_calls]]
local_path = "effect://federation/peer-echo"
local_method = "invoke"
binding_generation = 1
peer_node = "<96 hex digits of the target node ID>"
export = "tools"
path = "/echo"
method = "echo"
contract_digest = "<same 64 hex digits as the target method>"
allowed_acting = ["root"]
codec = "bytes_v1"
```

The local Kernel grant remains necessary to open and invoke this Resource. `allowed_acting` selects stable local identities that act as the node; a request body cannot choose them. The target, codec and generation are fixed before execution. The stock `bytes_v1` mapping exchanges raw byte Values with the target's `bytes_v1` method. The source stores a stable operation namespace alongside its durable execution IDs and binds each operation to its target before sending; after reconnect it inspects the original CallRef. After restart, committed business results remain readable, while accepted work without a terminal stays unknown; neither its program nor unknown effects are replayed. The target must grant this node `serve = true` on the export and an exact `call_authorities` rule. After a truthful terminal source receipt and completion of its business responsibilities, maintenance can remove the call payload while retaining a compact operation marker that rejects replay. This marker covers normal restart, not restoration of an older backup; see the recovery rule below.

To let one stable local acting identity call as a Hosted subject, configure host-held credentials and name them in the exact outbound method binding:

```toml
[[federation.outbound_hosted_subjects]]
name = "alice"
acting = "identity://people/alice"
peer_node = "<96 hex digits of the target node ID>"
issuer = "<96 hex digits of the subject issuer ID>"
namespace = "app"
subject = "alice"
issuer_descriptor_path = "/etc/xolotl/federation/alice-issuer.bin"
assertion_path = "/etc/xolotl/federation/alice-assertion.bin"
issuer_signature_path = "/etc/xolotl/federation/alice-assertion.sig"
holder_key_path = "/etc/xolotl/federation/alice-holder.pk8"

# Add to the matching [[federation.outbound_calls]] entry:
# allowed_hosted = ["alice"]
```

All four credential files must be private (0600), nonsymlink regular files at absolute paths. The signed assertion must match the declared issuer, namespace and subject, name this node as presenter and the target as audience, restrict purpose to `invoke`, and bind the supplied holder public key. `allowed_hosted` admits only the named credentials for that method; `allowed_acting` remains the node-principal list. The target separately needs an issuer policy for this presenter and `invoke` purpose and a Hosted `call_authorities` rule. The daemon holds the holder private key and signs each request; when the user keeps that key, an embedding host supplies `FederationCallPrincipal` and `FederationCallSessionProvider` instead. Retained business call control obtains the same Hosted context for Prepare, Inspect and Cancel from the recorded call subject. Keep that holder credential valid while a call remains unresolved: if it is removed or expires, or the target revokes its issuer, the pending cancellation and inspection remain held for repair and never fall back to the node principal.

For a hosted subject, set `subject = { kind = "hosted", issuer = "<96 hex digits>", namespace = "app", subject = "alice" }` and explicitly allow its issuer, namespace, presenter and `invoke` purpose with `[[federation.subject_issuers]]`. The verified issuer assertion and holder's per-request ML-DSA-65 proof remain mandatory; a node-level grant does not imply hosted-user authority. The issuer rule's audience is always this local node. Other allowed purposes are `discover`, `sync` and `object_read`.

Hosted stream access uses a separate exact grant, with an explicit `sync` issuer rule for the presenter:

```toml
[[federation.subject_issuers]]
issuer = "<96 hex digits of the issuer ID>"
namespace = "app"
presenter = "<96 hex digits of the enabled peer node ID>"
purposes = ["sync"]

[[federation.subject_grants]]
issuer = "<same issuer ID>"
namespace = "app"
subject = "alice"
presenter = "<same peer node ID>"
stream_id = "<32 hex digits of a local declared stream ID>"
not_before_ms = 1800000000000
expires_ms = 1900000000000
history = "from_grant"
enabled = true
# expected_revision = 1  # Set to the current revision when changing this row.
```

`history = "all"` permits existing records; `from_grant` begins at the grant's committed stream frontier. An enabled stock grant requires a configured, enabled peer and the matching `sync` issuer rule. `expected_revision` is absent on creation and must match the persisted row when changing it. If `subject_grants` is omitted, an embedding host owns grants; setting `subject_grants = []` under `[federation]` makes the daemon own an empty manifest and disable previously enabled grants at startup. A present manifest disables omitted rows before serving; unchanged rows keep their revision.

An unconfigured node may instead enter a Guest Session when its exact presenter, issuer, namespace and `sync` or `object_read` purpose are explicitly listed under `subject_issuers`. The host-managed invitation store can then redeem a named or bearer invitation through a holder-signed `RedeemInvitation` frame. The redemption creates an invitation-origin grant for one Hosted subject, presenter and stream; Guest Open/Read/Inspect/Close/Acknowledge require that current grant and never create peer authority. Revoking or expiring the invitation stops new redemptions, while an existing guest grant remains active until its own expiry or exact revocation. Bearer invitations can be transferred only among holders whose issuer and presenter are already trusted by these explicit rules. Open bearer invitations to a wholly unknown presenter or issuer are not supported by this stock host. The daemon exposes Session redemption and optional complete stock-owned manifests through `invitation_issuer_authorities` and `invitations`. Omitted manifests leave host-managed rows alone; present manifests reconcile only stock-owned rows, revoke omitted entries and require exact revisions for changes. Bearer entries store only a precomputed secret digest.

The stock publication source copies only pristine State history mutations beneath configured `state://federation/public/<namespace>` prefixes into their streams, as `xolotl.state.mutation.v1` JSON records. It requires `state_history = "full"`, not permanently untrimmed history. Each round shares one committed high watermark and rotates bounded pages through the commit-time index. A tick admits at most eight storage jobs; completed prefixes leave the queue, and blocking-worker AtCapacity preserves progress. A publication identity-capacity rejection without receipts preserves that page and rotates to the other pending publishers, allowing their original accepted identities to settle and return quota. A full rotation without publication progress returns Capacity rather than spinning or dropping evidence. Startup finishes the initial round before FromGrant invitations or readiness.

Before append, a page persists its fixed high, exclusive continuation and native retry epoch. Settlement atomically validates exact receipts, closes the epoch, retires only confirmed identities and advances the source-history pin. A definite identity-capacity rejection after some appends can settle their leading prefix, returning quota without requiring concurrent publishers to finish whole pages. Omitted events remain pinned; settlement requires their identities to be absent in that epoch. Unknown attempts retain their original window and epoch. After database commit uncertainty, release database users and reopen before reconciliation. This is business replication state, not restart execution.

At most 64 publishers hold persisted pins, each with at most a 4 MiB continuation plus 16 KiB metadata; trim scans at most 64 rows and fails closed on invalid metadata. Registration and trim check the current floor under the same write lock; a new publisher cannot reconstruct missing history. Removing configuration retains the pin. A trusted host must settle pending pages, then call `release_publication` with the exact prefix and completed cursor; pending or unknown pages cannot expire or be released. A released stream cannot re-register as a complete-prefix publisher; a new stream requires intact initial history. Each stream has one non-overlapping prefix, with canonical UTF-8 path at most 4096 bytes; other State paths are not published. A public exposure policy requires a listener; local publication and explicit retirement may run without one. Stock records are at most 512 KiB; set `federation.grpc.max_batch_bytes` to at least 512 KiB and `max_frame_bytes` to at least 516 KiB. Keep publication namespaces narrow to bound initial work.

To retire a State publication, remove its active `state_history_publications` stanza and explicitly declare its exact terminal cursor:

```toml
[[federation.state_history_publication_retirements]]
stream_id = "<32 hex digits of the existing local stream>"
prefix = "state://federation/public/notes"
expected_cursor = 1800000000000 # exact completed cursor or persisted pending high
```

At most 64 distinct retirements are accepted. A stream cannot also have an active State source. It may retain its `streams` declaration and access/replica policies to serve existing records. Retirement requires redb with full State history and the existing federation identity/security configuration, but needs no listener. Startup checks existing pins before stream declaration or listener binding. `expected_cursor` must match either the completed cursor with no pending window, or the exact high of the saved window. The read-only native `publication_status` port exposes those values; mismatch errors report them without creating work. Wrong prefix, unknown stream, capacity failure or uncertain commit rejects startup rather than waiving responsibility.

The daemon settles only saved windows using their original append identities and bounded storage workers, then conditionally releases the explicitly retired pins. Before settlement, it validates all retirement declarations and includes already pending windows of configured active publishers in the same fair rotation, so their accepted identities can release shared capacity. Each window keeps its own saved high; recovery neither opens a new window nor publishes later State changes. A full rotation without progress rejects startup. Published records, replica commitments and access policies have separate owners; removing their configuration has its own policy effects. Completed releases survive reopen and reject full-prefix re-registration of that stream. Keeping an applied retirement stanza is harmless: an absent pin is reported as absence, not proof that the supplied prefix or cursor was ever published. Removing configuration without this declaration still retains the pin. Each page and release is a separate commit; startup failure or cancellation does not undo earlier confirmed settlement or release, and unknown outcomes require reopening the storage owner before reconciliation.

The State path's `public` segment does not itself grant network access. Without `[[federation.public_streams]]`, a reader needs a configured peer and `serve` export grant, or an exact invitation-backed Guest grant. A public stream policy grants stateless `InspectPublic` and `ReadPublic` to a node whose root and current online key passed the TLS-bound proof; no publisher-side peer or subscription row is created for these reads. An unknown node may also use `ReadObject` under an exact node-self object grant, or the scoped Guest operations described above. An explicitly disabled peer cannot fall back to public or Guest access. A public policy must first be enabled while its stream is empty, so the daemon commits it before scanning State history. Policy changes require the exact persisted `expected_revision`; removing the stanza disables it. A disabled stream ID cannot be made public again—use a new stream ID. Set positive `max_read_records` (at most 256) and `max_read_bytes` (at most 4 MiB), within the configured gRPC batch limits. Public reads fence pages by the policy revision and recheck revocation on every request. A publisher with only public streams needs a listener but no `[[federation.peers]]` entries.

An exact object grant is separate from stream and peer export rights. The host verifies the object exists before issuing a durable grant; the `ReadObject` request repeats its complete content identity, grant ID and revision. The receiver keeps one nonzero 16-byte transfer ID across chunk requests and fresh Sessions, verifies the full SHA-384 digest, then commits the complete object. A PublicOnly node may use only a node-self grant; a Guest may also use a Hosted grant after registering an issuer explicitly trusted for `object_read`. A configured private peer may use either kind of exact object grant. Revocation, expiry, range and disclosure budget are checked around each chunk read.

```toml
[[federation.object_grants]]
presenter = "<96 hex digits of the reader node ID>"
subject = { kind = "node" }
hash = "<96 lowercase hex digits of the object's SHA-384>"
size = 1048576
mime = "application/octet-stream"
range_start = 0
range_end = 1048576
expires_at_ms = 1900000000000
max_total_bytes = 4194304
max_chunk_bytes = 262144
```

The grant covers only this exact object and half-open byte range. `max_total_bytes` includes retries and must cover the range; `max_chunk_bytes` is at most 1 MiB and must fit the gRPC batch and frame limits. The first startup allocates a durable grant ID and logs it for the receiver. Repeating the same manifest reuses that grant; removing an entry revokes it before listening. A revoked grant cannot be reissued from a stale manifest. Omitting `object_grants` entirely leaves grants managed by an embedding host untouched; an empty list revokes all grants previously managed by this manifest.

An enabled private peer with a pinned dial route can fetch an exact granted object into the local object store:

```toml
[[federation.object_receives]]
provider_node = "<96 hex digits of the provider node ID>"
grant_id = 1
grant_revision = 1
hash = "<96 lowercase hex digits of the object's SHA-384>"
size = 1048576
mime = "application/octet-stream"
owner_digest = "<96 hex digits of the local event or result owning the reference>"
max_chunk_bytes = 262144
```

The provider grant must authorize this node as its node subject. Stock reception is limited to 64 entries, 64 MiB per object, at most two concurrent downloads, and chunks no larger than 512 KiB or the configured transport batch. The receiver persists a stable transfer ID, verifies the entire object, and records `Verified`; an application must durably publish its own reference before marking the receipt `Bound`. A Hosted recipient or application reference binding needs an embedding host.

An outbound-only node omits `server.federation_grpc_addr` and sets a pinned route under its approved peer:

```toml
[[federation.peers.subscriptions]]
stream_id = "<32 hex digits of the remote stream ID>"
generation = 0
# Opt in only to application snapshot schemas this receiver can archive.
# snapshot_schema_revisions = ["<64 hex digits of a schema revision>"]

[federation.peers.dial]
uri = "http://peer.example:9446"
server_name = "peer.example"
trust_root_path = "/etc/xolotl/federation/peer-ca.pem"
```

The URI is an h2 authority; the connector always uses full-handshake hybrid TLS and pins both the TLS trust root and the signed federation node ID. A subscription requires `receive = true` on its export. The daemon accepts records into its redb inbox, acknowledges only accepted records, and reconnects with a fresh TLS-bound Session using the same stable Open identity. Bump the subscription `generation` when intentionally replacing its durable delivery contract after an authority change. A listening node can configure `[[federation.peers.subscriptions]]` without a dial route to read a peer's stream over that peer's inbound Session, so the peer does not need a listener. The same Session carries requests in both directions.

Snapshot offers with only `action = "retire"` require neither a listener nor a
dial route; retirement settles local retained obligations without requiring
network access. Any `action = "publish"` still requires a network path (listener
or dial route) and the compatible served group. This distinction applies to
snapshot offers, not to all local State-history publication.

For a private node-self history gap, stock can archive an application-sealed snapshot when the subscription names its accepted `snapshot_schema_revisions` (at most 16) and the publisher offers that exact subscription. Empty means fail closed on a gap. The application or operator must attest that the content covers the committed position and contains no excluded history; stock checks the file digest, size, exact log position and current authority, but cannot establish application meaning from bytes or install an application projection. A publisher declares this proof explicitly:

```toml
[[federation.snapshot_offers]]
action = "publish"
subscriber_node = "<96 hex digits of the receiver node ID>"
stream_id = "<32 hex digits of the local stream ID>"
subscription_generation = 0
snapshot_id = "<32 hex digits of a never-reused application snapshot ID>"
position_sequence = 42
position_digest = "<96 hex digits of the covered record digest>"
schema_revision = "<64 hex digits of the application snapshot schema>"
content_path = "/var/lib/xolotl/sealed/snapshot.bin"
content_digest = "<96 hex digits of the complete content SHA-384>"
content_bytes = 1048576
publication_digest = "<96 hex digits of durable application publication evidence>"
```

Stock copies and verifies at most 64 MiB per offer into a private publisher pin before disclosure; it accepts at most 64 declared offers and 64 pinned files. The offer appears after the exact private Open exists, including over a reverse Session, and its log pin remains until explicitly retired. To retire it, replace the declaration with `action = "retire"` and only `subscriber_node`, `stream_id`, `subscription_generation`. Removing a stanza does not claim authority to retire a persisted offer. The receiver downloads bounded chunks into a separate private archive beside `[storage].path`, verifies and syncs the whole content, then commits only an `Archived` delivery baseline. It rechecks the bytes on restart and can accept the bounded post-snapshot inbox suffix. This baseline is not an application projection. An embedding host must durably install the application state and bind its completion to the same install ID before reporting projection progress or cleaning old inbox generations. Only after its old readers and workers have stopped may the application declare a release for the resulting `Projected` anchor:

The archive receipt binds the exact subscription, install/archive digests and nonzero Federation generation. After durable contiguous suffix acceptance, the receiver sends native coverage from the archive baseline or last confirmed suffix frontier, with an exact through-position digest; the publisher validates every newly covered log record in bounded pages before advancing replica snapshot coverage. Gaps, stale generations and mismatched receipts reject. Archived ordinary event ACK remains absent: coverage never claims the missing prefix events were accepted, never installs application state, and queued receipts still recheck final delivery authority.

```toml
[[federation.snapshot_reader_releases]]
publisher_node = "<96 hex digits of the publisher node ID>"
stream_id = "<32 hex digits of its stream ID>"
subscription_generation = 0
install_id = "<32 hex digits of the active install ID>"
federation_generation = 1
application_generation = 1
completion_digest = "<96 hex digits of the active completion digest>"
release_digest = "<96 hex digits of the durable application reader-release decision>"
```

Stock requires the nonzero application and federation generations to match and checks the derived subscription against its persisted `Projected` anchor, exact install ID and completion digest. A release declared while only `Archived` exists is rejected; stock does not manufacture application completion evidence. A valid release can remain configured after the peer is removed or the local receiver is closed; cleanup then removes covered old inbox rows in bounded transactions and at most four old archive files per step. The release digest records the trusted application or operator's durable decision; it does not cryptographically prove that readers stopped. Leave the declaration in place while cleanup continues across restarts. Without one, old generations remain; the archive limits `.part` and `.sealed` files together to 64. Public and Guest follows do not use this private snapshot contract.

Publisher-side retention for a private replica is a separate commitment. Declare the receiver's exact node ID and the same `generation` it uses for its `[[federation.peers.subscriptions]]`; an embedding host can instead supply an exact 16-byte `subscription_id`. Set exactly one of these identifiers on an enabled row:

```toml
[[federation.replica_members]]
stream_id = "<32 hex digits of a local stream ID>"
member_node = "<96 hex digits of the receiver node ID>"
stock_generation = 0
enabled = true
# lease_until_ms = 1900000000000  # Omit for a permanent commitment.

[federation.replica_history_maintenance]
stream_ids = ["<32 hex digits of a local stream ID>"]
interval_ms = 10000
max_batches_per_tick = 8
records_per_batch = 256
```

The publisher joins the member only after its live node-self subscription has opened; until then, stock automatic trim skips its stream. Open history must still be available when the join commits. A normal subscription or ACK does not create this commitment. Omission of a member row never retires an existing commitment. To retire it, use a disabled row naming only `stream_id`, `member_node`, `enabled = false` and its current `expected_revision`; the daemon commits the retirement before serving. A term extension or re-enrollment also requires that revision. Re-enrollment requires a new subscription ID, usually by incrementing the receiver's `generation`. A lease lasts at most 30 days and is never silently renewed; after its deadline, a bounded retention transaction commits expiry. An enabled row with an expired lease does not restore that commitment.

Automatic history maintenance is opt-in per local stream. Select at most 64 streams; each tick has a global budget of eight round-robin transactions, at most 256 records and 64 MiB of payload per transaction. `interval_ms` must be 1 second to 1 day. At most 64 members per stream and 1024 configured members are accepted. The redb transaction checks all active commitments, confirmed publisher ACKs and snapshot pins before deleting a prefix. A pending configured member blocks stock automatic trim for its stream. Errors stop the current attempt and are logged; restart does not infer ACK or retire a missing member. Application projection and receiver inbox retention remain separate decisions.

To follow an unknown node's explicitly public stream, configure a separate public follower. It creates no private peer or subscription on the publisher. This node can dial without opening a federation listener:

```toml
[[federation.public_follows]]
publisher_node = "<96 hexadecimal digits of the publisher's root node ID>"
stream_id = "<32 hexadecimal digits of the public stream ID>"
minimum_online_generation = 1
allowed_authorization_digests = ["<96 hexadecimal digits of the publisher's canonical online authorization SHA-384>"]
max_inbox_records = 1024
max_inbox_bytes = 8388608

[federation.public_follows.dial]
uri = "http://public.example:9446"
server_name = "public.example"
trust_root_path = "/etc/xolotl/federation/public-ca.pem"
```

Each rule pins the publisher's root identity, online authorization digest, TLS trust root and exact stream. The same publisher cannot also have a private peer row; a disabled persisted peer row cannot fall through to this public path. At most 64 public follows are accepted. Per local redb inbox, `max_inbox_records` must be 1–4096, while `max_inbox_bytes` must be 512 KiB–64 MiB and at least the configured gRPC batch size. After reconnecting, the follower resumes from its durable digest position and atomically accepts a page while pruning the oldest local records. This rolling inbox does not guarantee that an application has projected old records, nor does it establish a publisher-side replica retention obligation. A publisher history gap returns `ResyncRequired`; atomic snapshot resynchronization is not implemented. Applications must read and project their local inbox and define gap handling.

An invitation-only Guest follower uses an explicitly trusted Hosted subject without creating a private peer row. The publisher must already permit that issuer and presenter for `sync` and issue the exact invitation. The example uses a named invitation; add `invitation_secret_path` for a bearer invitation whose raw 32-byte secret is in a private file.

```toml
[[federation.guest_follows]]
publisher_node = "<96 hexadecimal digits of the publisher's root node ID>"
stream_id = "<32 hexadecimal digits of the invited stream ID>"
minimum_online_generation = 1
allowed_authorization_digests = ["<96 hexadecimal digits of the publisher's online authorization SHA-384>"]
generation = 1
invitation_id = "<32 hexadecimal digits of the invitation ID>"
invitation_revision = 1
issuer = "<96 hexadecimal digits of the Hosted issuer ID>"
namespace = "app"
subject = "visitor"
issuer_descriptor_path = "/etc/xolotl/federation/guest-issuer.bin"
assertion_path = "/etc/xolotl/federation/guest-assertion.bin"
issuer_signature_path = "/etc/xolotl/federation/guest-assertion.sig"
holder_key_path = "/etc/xolotl/federation/guest-holder.pk8"
max_inbox_records = 1024
max_inbox_bytes = 8388608

[federation.guest_follows.dial]
uri = "http://friend.example:9446"
server_name = "friend.example"
trust_root_path = "/etc/xolotl/federation/friend-ca.pem"
```

The assertion must name this local node as presenter, the pinned publisher as audience, and `sync` as purpose; the daemon verifies its issuer signature and holder key at startup. At most 64 Guest follows are configured, with the same per-inbox bounds as public follows. The follower persists invitation redemption, Open, accepted pages and rolling inbox state; after reconnecting it replays an ACK only for a durable accepted position. Increment `generation` to replace the local relationship. Revocation stops new reads, and a history gap remains `ResyncRequired`; the inbox is not an application projection or replica retention promise.

Remote stores carry the verified online proof and a host-owned decision clock into the actual local authorization decision. Current peer/key policy and business rows are checked in one lock or transaction, including queued Kernel admission and resource calls, staged object disclosure, snapshot commit and receiver acceptance. Public and Guest follows retain their publisher pin and reject configured peer rows. Revocation fences new local decisions; it does not undo an already admitted physical Driver effect or create a transaction across stores or nodes.

Back up the federation redb database, online authorization, objects, and keys as one recovery generation. The stock daemon has no trusted high-water mark outside redb. Reconnecting an old database backup under the original federation identity can reuse publication sequences and outbound operation identities, and lose revocations or deduplication tombstones. Isolate and reconcile an old backup first, then pair it under a new federation root with new stream and subscription identities. Quarantine pending unknown calls until their external effects are reconciled; changing identity alone does not make replay safe. Reopening the same database after an ordinary crash does not have this rollback hazard.

## Sourced absence storage

`[storage].absence_record_limit` and `absence_encoded_byte_limit` default to 65536 and 67108864 on both memory and redb. Each accepts a nonnegative integer or explicit TOML string `"unlimited"`; zero forbids new charge. They count retained sourced-absence records and backend encoding plus key, not current values, history or RSS. Lowered quotas preserve evidence and allow non-growing commits. Redb requires initialized retained counters and rejects missing metadata.

## External Gateway

The daemon shares an aggregate 256-session External lifecycle scope across both transports. External gRPC enforces 1 MiB message decoding, a 10-second first-frame deadline and 300-second idle deadline. WebSocket retains bounded configurable transport limits and also charges the aggregate scope. Close service admission before stopping listeners, then drain the scope before blocking storage work; see [External Gateway](external-gateway.md).

External gRPC and external WebSocket serve the same Provider/Source session protocol:

```toml
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway]
source_command_limit = 65536

[external_gateway.source_maintenance]
interval_ms = 10000
max_batches_per_tick = 64

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

`[storage].source_stream_limit` bounds active ordered Source stream positions across all installations and projections in the built-in store. The default is 4096; values from 1 through 65536 are accepted. An explicit Open reserves one slot and issues a stream epoch before any event; an event frame cannot create a position. At capacity, Open rejects without changing the sink or private event decisions, while existing streams can advance. Retire atomically closes that incarnation and returns its slot; positions left by a retired scope are reclaimed by bounded maintenance. redb persists the count with each mutation. Lowering the limit on restart does not delete existing positions, but new Open requests wait until occupancy falls below the limit. Long-lived scopes can therefore reuse stream names without accumulating active positions; each event's retained decision and State history still have separate limits.

`[storage].source_retention_limit` bounds retained Source event-decision/receipt pairs plus rate records across the entire built-in memory or redb storage owner, including retired scopes. The default is 65536; the value must be positive. Each decision/receipt pair and each rate record charges one slot. Duplicate events replay without a new slot; replacing an expired decision or updating an existing rate record reuses its slot. A growing commit above the limit is rejected atomically with `retention_capacity_exceeded`, without evicting valid evidence or consuming a sequence number. Maintenance returns slots when it deletes expired decisions/receipts or idle rate records. Lowering the limit on reopen preserves old records and permits non-growing commits. Stream positions, installation records, State values and history remain separate domains. This record limit and the individual row bounds do not specify process RSS or physical database size; size the limit, deduplication window and maintenance throughput together for the workload.

`[storage].federation_publish_id_limit` bounds retained accepted publish identities across every stream in the built-in Federation store. The default is 65536; the value must be positive. New identities at capacity fail with `Capacity` before changing the stream or log. Publish requests bind an explicit per-stream retry epoch; closing it permanently rejects old appends before execution, including previously known IDs, but permits inspection of retained evidence. Only exact confirmed receipts from closed epochs authorize identity retirement and return slots; unknown identities remain charged. Trimming log bodies returns no identity slots, and a pruned active-epoch retry remains `Indeterminate`. Lowering the limit on redb reopen preserves evidence. Stock State page commits close their fixed epoch and reclaim confirmed page IDs atomically with the publication cursor, so normal long-lived publication reuses this budget. Neither new heads nor new pages upgrade an old unknown attempt to a newer epoch. The limit is not a payload, RSS or physical-file bound.

`[external_gateway].source_command_limit` is a positive global capacity for the shared in-memory Source command registry, not a per-transport setting. It defaults to 65536 and counts pending commands, retained terminal IDs, and installation/projection rate rows across gRPC and WebSocket together. A pending command reserves its eventual terminal ID slot; a new rate row needs another unit. At capacity, dispatch rejects before sending or consuming rate allowance. Valid unexpired IDs are never evicted. This bounds units, not bytes or process RSS, and is separate from Source event storage limits.

`source_dedupe_window_ms` bounds Source event ID dedupe retention. The Source command registry also uses the normalized value to fence a command ID after a result, deadline, or session drain. A zero daemon setting selects the existing default rather than disabling deduplication. Embedding hosts can pass a zero `SourceCommandRegister::idempotency_window_ms` to release the command ID at terminal transition; the rate row has an independent lifetime and remains until its rate window expires.

Command registration performs bounded expiry cleanup. Periodic Source maintenance also cleans the shared command hub when it is idle or disconnected. Each batch examines at most 64 ID and rate rows; unreclaimed expired rows remain charged. `SourceCommandMaintenanceReport` separates examined rows, released units, and sweep completion: zero releases do not mean completion. An earliest-expiry hint skips unnecessary traversal, without a per-ID expiry index. Command metadata belongs only to the current host lifecycle. Maintenance controls reclamation speed after expiry; it does not shorten valid dedupe windows.

`source_maintenance` runs at startup and every `interval_ms` while the daemon is running, including when no Source session is connected. Each tick shares one `max_batches_per_tick` budget between command-registry cleanup and Source-private accepted decisions, rate records, and retired-scope stream positions. Busy owners alternate batches, preserving their turn across ticks even for a budget of one; a finished owner yields unused budget. Each charged batch examines at most 64 rows. Batches use one tick timestamp, release the command hub lock, and yield to other tasks between batches. A backend-owned cursor resumes across ticks and redb restarts and resets at the end of the private key space. The defaults are 10 seconds and 64 batches. Zero uses the default; values above one hour or 1024 batches are capped.

The retention deadline is fixed for each accepted event from its own transport's bounded `source_dedupe_window_ms`. Changing that setting affects new decisions only; maintenance does not reinterpret stored deadlines. It removes expired accepted decisions and their receipts even after an installation or projection is removed. The atomic commit path creates no pending claims. Unknown outcomes may be retried with the same event ID and payload and, for an ordered event, the same stream ID, sequence, and active stream epoch; a Duplicate requires the old decision to remain retained when the backend decides. A retired stream rejects its old event before deduplication; an authorized evidence inspection can still examine a retained decision. Retries do not release a pending reservation, and expiry does not prove the first attempt aborted.

Idle rate records expire after their last accepted hit leaves the window recorded with that row. Changing the window starts a new rate accounting period on the next accepted event; changing only the event limit takes effect against retained hits. A window change can briefly relax admission.

Active stream positions are never removed by elapsed time. Scope retirement fences their commits, after which maintenance removes the obsolete positions and returns their quota; individual Retire closes an active position immediately. Rows inserted before the cursor are revisited after wraparound; sustained ingress faster than maintenance is not bounded by the per-tick budget. Retained event decisions and State history have separate residency requirements.

`provider_max_in_flight_invocations`, `provider_max_in_flight_per_identity`, and `provider_max_in_flight_per_effect` bound pending Provider invokes per ready Provider session. `provider_max_inline_result_bytes` bounds inline Provider success and error results.

`source_max_in_flight_commands`, `source_command_rate_limit_window_ms`, and `source_command_rate_limit_max` configure Source command dispatch limits; `source_command_max_inline_result_bytes` bounds inline results. A projection must declare commands, become Ready, and be invoked through an authorized Kernel Operation before these limits apply. Rate admission does not promise sustained throughput: select the shared capacity and dedupe window together for cumulative new IDs in that window, pending commands, and rate rows. Cleanup controls how quickly expired capacity returns, not whether valid IDs may be evicted.

Source event payload-size limits, stream capacity, overflow behavior, and event-ingress rate limits are declared on each Source projection.

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

External gRPC supports `production_tls`, `mtls`, `trusted_reverse_proxy`, `local_trusted`, `unsafe_plaintext`, and `disabled_for_test`. `production_tls` requires `certificate_chain_path` and `private_key_path`. `mtls` additionally requires `client_trust_roots`. The daemon's TLS modes accept only TLS 1.3 with `X25519MLKEM768`, AES-256-GCM or ChaCha20-Poly1305, and ML-DSA-65 certificate chains; session tickets and 0-RTT are disabled. `trusted_reverse_proxy` requires `trusted_proxy_peers`; forwarded headers are used only when the direct peer is trusted. Proxy TLS policy is enforced by that deployment, not by the daemon.

`private_key_path` must be absolute and name a regular file of at most 64 KiB, with no group or other permissions. The daemon refuses a symlink at the final path component and erases its in-memory PEM buffer when the listener configuration is dropped. Protect parent directories and backups separately.

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

External WebSocket is a plain listener. Use `trusted_reverse_proxy` for external TLS termination, `local_trusted` for loopback-only deployments, or explicit `unsafe_plaintext`. `production_tls` and `mtls` fail closed for this listener.

Console transport security is configured separately:

```toml
[console.transport_security]
mode = "local_trusted"
```

The daemon console listener is currently a plain listener. Use `local_trusted` only with a loopback `console_addr`, or use `trusted_reverse_proxy` when TLS terminates at a trusted front proxy and `trusted_proxy_peers` lists the direct proxy peer addresses. `production_tls` fails closed for this listener until daemon-owned console TLS material is configured.

Console uses forwarded source addresses only when the socket peer is trusted and `honor_x_forwarded_for` is enabled. Otherwise it ignores both `X-Forwarded-For` and `X-Real-IP` and uses the socket peer. The trusted peer list also identifies proxy hops within a forwarded chain:

- All `X-Forwarded-For` header values form one chain in header order. Console scans from right to left, skips trusted proxy IPs, and uses the first untrusted IP. If every hop is trusted, it uses the leftmost IP. Earlier client-supplied entries do not override the first untrusted hop.
- An empty, malformed or non-IP entry encountered while scanning the trusted suffix makes Console fall back to the socket peer. It does not then try `X-Real-IP`. That header is considered only when `X-Forwarded-For` is absent; it must contain one IP address, with no duplicate header or comma-separated values. Accepted IPs use their normalized textual form for audit and limits. A proxy using the `X-Real-IP` fallback must overwrite or remove any client-supplied value; validating one IP does not establish who supplied it.
- Trusted, enabled `X-Forwarded-Host` and `X-Forwarded-Proto` must each contain a single header value without commas. Duplicate or combined values reject origin admission. The trusted proxy must overwrite incoming client values for these headers instead of appending to them. Untrusted or disabled forwarded headers do not override the request host or scheme checks.

## Runtime Configuration

Terminal installation requires a host-owned shared runtime, not a caller
approval flag or a `high_risk` pseudo-approval configuration. The daemon's host
assembly owns its command lifecycle; embedded hosts install their owner
explicitly. Capacity, rejection and draining are described once in
[Terminal installation](api-reference.md#terminal-installation). Standard Fetch
has no implicit environment-proxy or internal-network mode; use a host custom
Driver for those deployments under [Driver boundaries](security-and-boundaries.md#driver-boundaries).

Embedded Rust hosts configure an Executor through `ExecutionConfig`, separately from `xolotl.toml`. Its three retained caches each default to 4,096 entries: `max_method_metadata`, `max_resource_bindings`, and `max_method_bindings`. Newly retained keys also have defaults of 1,024 canonical UTF-8 path bytes (`max_cache_path_bytes`) and 256 UTF-8 method-name bytes (`max_cache_method_name_bytes`); a newly frozen resource contract retains at most 64 interface IDs (`max_cache_interfaces`). A cache hit or same-key replacement remains usable when a limit is reached. Lowering limits after entries exist does not evict them. These are entry and selected content limits, not an exact allocator-byte, native-handle, or whole-Executor memory ceiling.

An embedded host can set `KernelBuilder::with_handle_slot_limit(limit)` for the shared `HandleTable`, or construct a standalone table with `HandleTable::with_slot_limit(limit)`. The default has no slot limit; zero admits no handles. The limit counts allocated slot indices, including retained ancestors, reusable vacant indices and permanently retired generations. `allocated_slots()` reports charged indices; `len()` reports live payloads. Neither is a byte limit on Drivers or policy captures.

Runtime provider setup, model routing, groups, bindings, in-process Provider or Source projection declarations, external Provider/Source installation declarations, and policy-managed state belong in Xolotl state and are managed through Console actions over Rust, HTTP or WebSocket. External projections are part of each installation declaration. External declarations use `external.*`; inference declarations use `inference.*`; in-process projection declarations use `config.*` under `state://kernel/projections/in-process/<id>`. Generic `config.*` actions reject management paths that have a dedicated action family.

`xolotl-standard` Cargo features decide which in-process implementations are compiled into the host binary. Optional in-process projection declarations live under `state://kernel/projections/in-process/<id>`. Reconcile status is written under `state://kernel/projection-status/in-process/<id>` and is read through `projection.in_process.status.*`; it separates the desired declaration version from the active registry version. Embedded hosts can also choose which compiled standard-core modules are installed with `StandardConfig::with_modules`; compiled code is not exposed as a Resource until the host installs it.

HTTP inference providers are compiled only when the host binary enables the matching `xolotl-standard` feature. Runtime declarations live under `state://kernel/inference/*` and `state://kernel/routing/inference`; backend records store secret references such as `state://vault/inference/<backend>/api_key`, not raw API keys.

Each standard `fetch` or HTTP inference client selects its restricted post-quantum rustls provider explicitly, including single-provider feature builds. Client construction neither installs nor relies on the process-default provider; the same policy applies in embedded hosts. Public HTTPS services with classical certificate chains or without the hybrid exchange may therefore be unreachable; these clients do not silently fall back to classical TLS. Hosts own the transport policy of separately supplied Drivers. See [Security And Boundaries](security-and-boundaries.md).

`InferenceBackendDef.io_window_bytes` selects the encoded request and parsing work window; it defaults to 16,384 bytes and accepts any positive value. It is separate from output `StreamWindow` capacity and does not limit total request or response size.

`response_limits` makes result materialization policy explicit:

- `max_materialized_bytes`: simultaneously retained selected text and numeric token bytes in one unary response or atomic SSE record.
- `max_materialized_nodes`: retained selected value nodes, including empty values.
- `max_json_frames`: simultaneously open JSON containers, including skipped data.

Every limit is optional. These are logical result-admission units, not a bound on allocator bytes, transport buffers or total RSS. See [HTTP Inference Providers](http-inference-providers.md#incremental-http-data) for parser, streaming and error behavior.

Embedded hosts install object capabilities explicitly with `StandardConfig::with_object_store`. `ObjectStore` accepts independent read, write, and delete adapters; `xolotl-storage-fs::FileObjectStore::open(root)` provides a file-backed implementation. Large unary Fetch and filesystem outputs, Blob writes, and Tensor writes require an object writer. Blob reads and deletes require their corresponding ports. Streamed Fetch and filesystem reads can run without object storage.

`FileObjectStore::with_options(root, FileObjectOptions)` configures nonzero limits; `open(root)` uses these defaults:

| Option | Default | Charged resource |
| --- | --- | --- |
| `chunk_bytes` | 64 KiB | Bytes accepted or returned by one chunk request |
| `max_uploads` | 64 | Upload responsibilities: creating, live, lost-receipt, and deferred cleanup |
| `max_io_tasks` | 8 | Concurrent foreground filesystem jobs and their resident chunk buffers |
| `max_metadata_bytes` | 1 MiB | Encoded metadata per object, including provenance |

Clones share the owner's upload and I/O limits; independently opened instances have independent budgets, even at the same root. Upload capacity is reserved without waiting before staging creation; exhaustion rejects the upload before that filesystem effect. Cleanup has one separate worker and does not consume foreground I/O permits; its queued and running work still occupies upload slots. These limits do not cap total object bytes, disk garbage, or process RSS. For cleanup, receipt retries, and platform durability, see [API Reference](api-reference.md) and the owning [object-storage contract](architecture.md).

Console auth, WebSocket, and transport-security fields are deployment settings. Capability checks, step-up gates, path-specific admission, action registry validation, and secret redaction remain enforced by runtime paths.
