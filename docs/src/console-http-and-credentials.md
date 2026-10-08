# Console HTTP and Credentials

This page lists the HTTP mount, authentication and credential endpoints. They use the shared [Console service](console-protocol.md); runtime calls and submissions are described in [Console Runtime Calls and Submissions](console-runtime.md).

## HTTP Routes

`http::serve()` mounts all endpoints at `/api/console/v1`. `http::router(adapter)` returns routes relative to the mount point; the paths below are relative to it.

`HttpApi` assembles selected groups or individual `HttpEndpoint`s from one catalog of 20 operational endpoints; the manifest is additional. `HttpApi::new()` starts empty and `HttpApi::all()` selects everything. `.router(adapter)` installs the selected routes and serves their manifest at GET `/`; with `.nest("/admin", ...)`, read it at `/admin`. `.routes(adapter)` installs the same selected routes without occupying the host's root or publishing a manifest.

The host may publish `HttpApi::manifest(&adapter)` at another path with `Cache-Control: no-store`. Its method/path pairs are relative to the mount of those routes, not absolute URLs; a host using a different prefix must account for it. The manifest describes the selected route set, not unrelated host routes or other mounts.

Hosts select groups with `HttpApi::with_group(HttpGroup::...)` and individual routes with `HttpApi::with_endpoint(HttpEndpoint::...)`; `without_group` and `without_endpoint` narrow an assembled set. They then mount the selected routes. Each group preserves its namespace from the table.

Assemble `HttpState` from an `Arc<ConsoleState>` and `HttpConfig`. All adapters over the same service share credentials, registry, call/subscription capacity and execution budgets. Each `HttpState` owns its origin/proxy and originless automation policy, plus WebSocket connection, frame and delivery limits. Reusing its `Arc` across mounts or listeners shares these connection limits; separate instances count their connections independently. Hosts supply tracing, CORS and application layers; Console enforces origin and bearer checks.

TCP hosts use `into_make_service_with_connect_info::<SocketAddr>()` for ordinary connection provenance, or `HttpTcpConnection` when a connection-bound automation verdict is needed. For a Unix-domain or other non-TCP listener, the host verifies the peer at its connection boundary, constructs `HttpPeer::verified_source(name)`, and attaches it as an Axum `Extension` to requests on that connection. A plain HTTP client cannot supply an Axum extension; the host must never construct it from a client-controlled header. The source name is a bounded audit and rate-limit key, not an account identity or an authority grant.

By default POST requests and WebSocket upgrades still need `Origin`; the three read-only GET endpoints below may omit it. To admit a non-browser automation client that does not send `Origin` on POST, set `HttpConfig.originless_clients` to `OriginlessClientPolicy::AllowVerifiedAutomation` and serve with `into_make_service_with_connect_info::<HttpTcpConnection>()` so Axum issues one `ConnectInfo<HttpTcpConnection>` per accepted TCP connection, then attach `VerifiedAutomationClient::for_tcp_connection(&tcp_connection)` as an Axum `Extension` after independently verifying that connection. Non-TCP hosts attach `VerifiedAutomationClient::for_host_peer(&verified_http_peer)`.

Console compares the verdict to its actual connection provenance. Reusing a socket address does not reuse a TCP connection proof; for non-TCP peers, inject the same `HttpPeer` instance (or a clone), since a new peer with the same source name is also a different connection proof. Do not derive this extension from a bearer, request header, forwarded address, source IP alone or an unverified shared listener. The policy changes only HTTP `Origin` omission; it does not authenticate the account or grant an action capability.

Authentication, credential, call and WebSocket endpoints reject requests with no source, or with more than one of `HttpPeer`, `ConnectInfo<SocketAddr>`, and `ConnectInfo<HttpTcpConnection>`. They never convert absent provenance into `unknown`. The public HTTP manifest and health endpoint do not use connection provenance.

Interactive step-up also needs the shared `/auth/continue` and `/auth/cancel` endpoints from the authentication group, or another adapter over the same service. Selecting the session group does not implicitly mount them.

JSON request bodies are limited to 64 KiB; `/auth/external` alone permits 96 KiB to carry a 64 KiB assertion after base64url and JSON encoding; individual factor inputs, setup, verifier and interaction payloads to 16 KiB.

The manifest includes this adapter's `transport` policy summary and `originless_clients` setting, plus the effective `request_body_timeout_ms`. These settings describe configured admission, not whether any particular client has been verified. `websocket` limits are present only when its WebSocket endpoint is selected; `idle_timeout_ms` and `send_timeout_ms` are integer milliseconds. `HttpApi::manifest(&adapter)` returns the same description before mounting. Service discovery and `health.summary` do not infer a listener or report WebSocket configuration.

```rust,ignore
use xolotl_console::http::{self, HttpConfig, HttpState};
let adapter = HttpState::new(console_state, HttpConfig::default());
let app = axum::Router::new()
    .nest("/admin", http::router(adapter.clone()));
// Reuse the same adapter's admission for a separate mount:
let app = axum::Router::new()
    .nest("/automation", http::HttpApi::new()
        .with_endpoint(http::HttpEndpoint::Calls)
        .routes(adapter.clone()));
// If the host already owns GET /, merge a selected route set without a root manifest:
let api = http::HttpApi::new().with_endpoint(http::HttpEndpoint::Health);
let manifest = api.manifest(&adapter);
let app = axum::Router::new()
    .route("/", axum::routing::get(|| async { "host root" }))
    .merge(api.routes(adapter));
// The host can publish `manifest` at its chosen discovery path.
```

| Relative path | Method | Purpose |
| --- | --- | --- |
| `/health` | `GET` | Health check (plain text). |
| `/auth/password/login` | `POST` | Verify a password and any supplied `second_factor`, or return factor selection. |
| `/auth/external` | `POST` | Verify an opaque assertion and resolve its account through the installed host authority. |
| `/auth/keys/challenges` | `POST` | Create a public-key login challenge. |
| `/auth/keys/login` | `POST` | Verify the signature and any required second factor. |
| `/auth/passkeys/challenges` | `POST` | Begin passkey login. |
| `/auth/passkeys/login` | `POST` | Finish a user-verified passkey assertion. |
| `/auth/factor-providers` | `GET` | Discover installed factor providers and their enrollment/authentication schemas. |
| `/auth/continue` | `POST` | Continue login or step-up with its opaque continuation. |
| `/auth/cancel` | `POST` | Cancel that authentication; returns JSON `null` on success. |
| `/session/step-up` | `POST` | Verify a fresh factor, or omit `proof` to choose one; requires an existing bearer. |
| `/session/refresh` | `POST` | Rotate the bearer secret; preserve session authentication time. |
| `/credentials` | `GET` | Read primary credential metadata for the current account. |
| `/credentials` | `POST` | Manage primary credentials; optional target account requires administrative authority. |
| `/credentials/passkeys/registration` | `POST` | Begin passkey registration after recent authentication. |
| `/credentials/passkeys/registration/confirm` | `POST` | Confirm and store a passkey credential. |
| `/credentials/factors` | `GET` | Read the caller’s enrolled methods and recovery-code count. |
| `/credentials/factors` | `POST` | Run a tagged MFA lifecycle operation. |
| `/calls` | `POST` | Execute one authenticated [protobuf v1 action](#single-call-protobuf). |
| `/ws` | `GET` | Upgrade to protobuf v1 calls and live subscriptions. |

Logout and administrative revocation use the descriptor actions `access.session.current.logout`, `access.session.revoke`, and `access.session.revoke_user` through Rust `call`, `/calls`, or WebSocket, sharing one authorization and audit path.

Browser POST authentication and call requests require `Origin` and `Host` headers. Same-origin browser GET requests often omit `Origin`, which JavaScript cannot set manually. `GET /auth/factor-providers`, `GET /credentials`, and `GET /credentials/factors` therefore accept a missing `Origin` after verifying connection provenance and one valid `Host`; the two private reads still require their bearer. If a GET supplies `Origin`, it must pass the same strict check.

Only a matching host-verified automation connection under the explicit policy may omit `Origin` on HTTP POST authentication, credential and call routes. `Host` is always required. A supplied `Origin` always undergoes the full check. Public-key challenge and login and every WebSocket upgrade always require an actual `Origin`, including for verified automation connections.

The origin host, port, and trusted forwarded scheme must match the externally visible host for the console listener. Each header must contain one unambiguous value; duplicate or comma-combined values are rejected even behind a trusted proxy. Default HTTP(S) ports are equivalent to an omitted port, and equivalent IPv6 spellings match.

Public-key login additionally requires the JSON `origin` field to exactly match the request `Origin` header; that value is bound into the signed transcript. Passkey routes use the configured WebAuthn relying-party id and origin, and do not prescribe any frontend layout or UI framework.

The two continuation endpoints advertise `authentication: "continuation"`. Login needs the continuation; step-up additionally needs the current bearer for its initiating SID. Both endpoints apply the same origin checks. A missing Authorization header is passed as `None`; a present but malformed, empty, repeated or combined bearer header is rejected, not treated as absent. The service owns validation of the bound step-up session.

Forwarded source headers affect audit and admission limits only for a trusted socket peer with `honor_x_forwarded_for` enabled. Console combines repeated `X-Forwarded-For` fields in header order and scans from right to left past trusted proxy IPs to the first untrusted IP; an entirely trusted chain uses its leftmost IP. An empty, malformed or non-IP entry in the scanned suffix falls back to the socket peer without trying `X-Real-IP`.

Only when XFF is absent may one `X-Real-IP` field supply a single normalized IP; duplicate or comma-separated values fall back to the socket peer. Untrusted peers and disabled forwarding use the socket peer. The trusted proxy must overwrite or remove client-supplied `X-Real-IP` before using that fallback; a valid single IP does not establish its provenance.

Host-verified non-TCP peers have no proxy IP. Their bounded source key is used directly, and `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and `X-Forwarded-Proto` cannot override it or the external origin check. `Host` remains mandatory. The explicit automation policy above can waive only the absent HTTP `Origin` on eligible routes; it does not make forwarded headers trusted or waive `Host`.

When trusted and enabled, `X-Forwarded-Host` and `X-Forwarded-Proto` each accept one header without commas. The proxy must overwrite client-supplied values; duplicates or combined values reject origin admission. These rules apply to HTTP calls/authentication and WebSocket upgrades. See [Console transport configuration](configuration.md) for deployment settings.

Password login request:

```json
{"username":"root","password":"...","second_factor":null}
```

External primary authentication is installed on `ConsoleConfig.external_authentication` as an `ExternalPrimaryAuthentication` implementation. `ConsoleService::exchange_external` accepts opaque assertion bytes; HTTP `/auth/external` accepts `{"assertion":"<unpadded-base64url-assertion>"}`. It uses the same HTTP Origin policy, `Host`, verified peer, bounded body, audit, account and MFA admission as other authentication routes.

The host's external preparation permit spans verification, account lookup and admission to a session or bounded continuation. A slow account authority cannot create an uncharged queue after verification. Completion and cancellation release the permit; a returned continuation is charged to the challenge ledger instead.

The verifier must check signature, issuer, audience, expiry and replay policy before returning `(provider, issuer, subject)`, assertion verification time, optional proven user authentication time, absolute assertion expiry and assessed assurance.

A separately installed `ConsoleConfig.account_authority` resolves these verified facts to a stable `AccountKey` and reads its current status, local `identity://...` path, grants and revocation epoch. Console rejects disabled, replaced or changed accounts and credential epochs.

This crate does not ship an OIDC verifier. A forwarded header, `HttpPeer` label, application Gateway principal or client-supplied username is never an identity assertion.

At issuance, Console freezes the current account grants as the session ceiling. Issuance rejects a ceiling above 128 capabilities, 8 KiB of capability text, or 2 KiB for one capability. Each request and subscription delivery takes the provable intersection of that ceiling with fresh account grants, retaining the narrower path and predicate; incomparable conditions are denied. The verifier supplies no resource authority.

Installing a host account authority disables local password, public-key and Passkey primary login; Console still owns its bearer sessions and account-keyed second-factor ledger. Every external primary is Console MFA level 1, even when the verifier reports `multi_factor` assurance; enrolled Console factors still require the ordinary continuation. An explicit local policy for treating a particular external assurance as Console level 2 is not implemented.

External `valid_until` caps the MFA continuation and the session's hard and idle deadlines. Factor completion, step-up and credential replacement reissue cannot extend it; refresh retains the hard deadline.

Each bearer call and subscription delivery rechecks the session deadline, account key, current revocation epoch, identity path and Console credential epoch. Account-authority revocation is observed on those reads; revocation known only to the assertion issuer needs host integration or waits for assertion expiry. Accepted work retains its original deadline and is checked against current account authority independently of bearer lifetime.

HTTP and WebSocket use the exchanged ordinary Console bearer for subsequent calls. This bearer does not prove mTLS private-key possession on another connection.

Public-key, Passkey and MFA authentication continuations share one bounded CAS ledger at `state://vault/console/challenges`. `console.auth.challenges` defaults to 256 pending ceremonies globally, 8 per account and 32 per verified source, with a 1 MiB encoded ledger limit. A single ceremony is limited to 64 KiB. Source keys are hashed. Concurrent admissions cannot exceed capacity.

For public-key and Passkey, before deleting a challenge, the consumption CAS matches its purpose and owner: public-key login binds username and origin; Passkey registration binds username and the initiating SID; Passkey login binds username. A wrong binding leaves the challenge usable. A matching request consumes it once before proof verification, even if the proof is invalid. Source addresses affect quotas and audit, not this binding; switching networks does not invalidate the challenge.

Expired entries are reclaimed on admission; abandoned responses occupy capacity until expiry. Hosts sharing State share the ledger and must use the same limits. Capacity saturation returns `RateLimited` without inventing a retry delay.

Public-key challenge request:

```json
{"username":"root","origin":"https://console.example"}
```

Public-key login request:

```json
{"username":"root","challenge_id":"...","signature":"...","origin":"https://console.example","key":"ml-dsa-65:<base64url-public-key>","second_factor":null}
```

Passkey registration begin request:

```json
{"label":"Operator passkey","display_name":"Root Operator"}
```

Passkey registration begin and finish require:

```text
Authorization: Bearer <token>
```

Passkey login begin request:

```json
{"username":"root"}
```

Passkey finish requests carry the browser credential response returned by `navigator.credentials.create` or `navigator.credentials.get`.

Step-up request body:

```json
{"proof":{"kind":"factor","factor_id":"<enrolled-factor-id>","response":{"code":"123456"}}}
```

An empty object, or `"proof": null`, requests factor selection instead of verifying a direct proof. It does not refresh the session's authentication time.

`/session/step-up` takes the existing session through:

```text
Authorization: Bearer <token>
```

Password login, key login and step-up return `AuthenticationResponse`:

| `result` | Fields and meaning |
| --- | --- |
| `authenticated` | `session: LoginResponse`; all required verification has committed. |
| `continue` | `continuation`, `expires_at`, `step`; authentication is still incomplete. |

Both are HTTP 200 responses. Rust clients match the enum or use `into_session()`, which returns the session or retains `AuthenticationContinuation` in its `Err` branch. A login continuation binds the verified primary proof for this authentication; step-up binds the original complete session evidence and a separate SID purpose. A continuation only authorizes continuation or cancellation of that authentication. It cannot authorize calls, credential management or WebSocket authentication. Passwords and key signatures need not be resubmitted to choose a factor. An incorrect supplied proof still fails authentication.

Passkey login and refresh return `LoginResponse` directly. Credential management embeds replacement sessions in its existing result types. `LoginResponse` has these fields:

| Field | Meaning |
| --- | --- |
| `sid` | Session id. |
| `token` | Bearer token in `sid.secret` form. |
| `expires_at` | Absolute expiry, Unix milliseconds. |
| `idle_expires_at` | Idle expiry, Unix milliseconds. |
| `authentication` | Complete `AuthenticationEvidence`, described below. |

`authentication` has a required `primary` object and a required nullable `secondary`. Each non-null proof carries its actual `verified_at` in Unix milliseconds:

| Proof | `method` | Credential reference |
| --- | --- | --- |
| Primary | `password` | The account's unique password slot; no credential ID or password hash. |
| Primary | `public_key` | `credential_key`: the canonical ML-DSA-65 descriptor actually verified. |
| Primary | `passkey_uv` | `credential_id`: the verified base64url WebAuthn credential ID; UV succeeded. |
| Primary | `external` | Verified `provider`, `issuer`, stable `subject`, optional user `authenticated_at`, assertion `valid_until`, and descriptive `assurance`; no assertion secret. |
| Secondary | `factor` | `factor_id` and the `provider_id` resolved from the stored instance. |
| Secondary | `recovery_code` | No code, digest or recovery-list position. |

The service fixes each time when verification succeeds, before later asynchronous storage or issuance. Account key, revocation epoch and Console credential epoch remain in the session envelope. References describe historical verification and may refer to a credential removed by subsequent authorized management. Step-up retains the original primary proof and replaces the secondary proof; its SID binding is separate from both. Credential management and refresh preserve all evidence. Persisted sessions require evidence; records missing it are rejected.

Rust clients can call `authentication.mfa_level()` and `authenticated_at()` (which returns `Option<i64>`). Greeting, session-list, authority and audit projections expose derived summaries where useful. Password/public-key alone gives level 1; an independent secondary proof or `passkey_uv` gives the current level 2. This number does not assert phishing resistance or exclude recovery: consumers with such requirements must inspect the proof kind. Recency uses the latest proven user authentication or locally verified secondary time. External assertion `verified_at`, token issue time and exchange time cannot create a recent authentication window; an absent user time produces `null` in audit and session-list summaries until a local factor is verified.

The public continuation has a fixed absolute `expires_at` in Unix milliseconds. Its `step.kind` determines the accepted `AuthenticationInput`:

| `step.kind` | Public fields | Accepted `input.kind` |
| --- | --- | --- |
| `choose_factor` | `options` contains account `factors` and `recovery_code_available`. | `proof` with `proof: MfaProof`, or `select_factor` with `factor_id` for an interactive provider. |
| `challenge` | `factor_id`, `provider_id`, provider `challenge`. | `response` with provider-specific `response`. |
| `pending` | `factor_id`, `provider_id`, provider `status`, `retry_after_ms`. | `poll` after the advertised delay. |

`POST /auth/continue` accepts `ContinueAuthenticationRequest`. For example, a client can finish factor selection with a direct TOTP proof:

```json
{"continuation":"...","input":{"kind":"proof","proof":{"kind":"factor","factor_id":"<enrolled-factor-id>","response":{"code":"123456"}}}}
```

The same `proof` field accepts `{"kind":"recovery_code","code":"..."}`. To start a provider's interactive path instead:

```json
{"continuation":"...","input":{"kind":"select_factor","factor_id":"<enrolled-factor-id>"}}
```

Subsequent input is `{"kind":"response","response":...}` for a challenge, or `{"kind":"poll"}` while pending; response content follows that provider's declared schema. Each consumed step returns a session or a new continuation; replace the saved token. After current policy and account admission checks, an early poll returns the same token and remaining wait without invoking the provider. Account, purpose, selected factor and original step-up SID are fixed by the host; input cannot replace them. Changing networks does not change ownership.

`POST /auth/cancel` accepts `CancelAuthenticationRequest`:

```json
{"continuation":"..."}
```

Success is HTTP 200 with JSON `null` and `Cache-Control: no-store`. Step-up continues to require the original SID's current bearer for both continue and cancel. A login continuation needs no ordinary session. Switching a selected interactive factor requires canceling and restarting authentication.

`POST /session/refresh` takes the existing bearer in `Authorization`. It checks the session and active account before changing credentials, rotates only the secret, and preserves the SID, complete authentication evidence and hard expiration while extending idle activity. The shared service audits the result and verified source. Rotation and audit are not a cross-record transaction: if the response is lost or an audit write fails after rotation, the caller may need to log in again.

The session and its bearer verifier form one private aggregate owned by `ConsoleSessionStore`, separate from State and its history. The store atomically admits sessions against its shared account and domain capacities; expired rows still count until deleted. Hosts must schedule bounded maintenance. Concurrent refreshes using the same bearer have at most one winner, and stale activity cannot restore an old verifier. `state://kernel/console/sessions` is the management authorization target, not a stored State copy: session listing projects authorized summaries without the verifier, credential epoch or grant ceiling. Session commits do not form a joint transaction with account or audit updates. Storage, eviction, conditional updates and uncertain-commit rules are owned by the [session-store rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-console/src/session_store.rs).

Read-only SID validation rereads the private session after asynchronous account and credential checks and requires unchanged immutable authority and live hard/idle deadlines. Concurrent activity or bearer rotation alone does not revoke the SID; validation never renews activity or emits session writes. Active authentication and refresh anchor idle renewal at the original valid admission time, not completion time, and check liveness before and after committing. Issuance also checks the committed session before returning credentials. A delayed operation cannot deliver an expired session or renew indefinitely through waiting. These final observations do not lock out later revocation or make account, credential and session checks atomic.

Authentication responses use `Cache-Control: no-store`. Errors, including JSON parsing and body-limit failures, return a JSON `ConsoleFailure` with snake_case codes (for example `not_authenticated` or `rate_limited`); optional recovery fields are omitted when unknown. Invalid input diagnostics never echo credential values.

HTTP auth error mapping:

| Condition | Status |
| --- | --- |
| Missing bearer, invalid session, invalid challenge, or invalid credentials | `401 Unauthorized` |
| Operation requires stronger authentication | `403 Forbidden`, `step_up_required`; ordinary action gates omit account factors |
| Account unavailable or permission denied | `403 Forbidden` |
| Host forbids the selected factor provider's use | `403 Forbidden`, `forbidden`; no credential-failure count |
| Factor provider not installed, or permitted operation not declared | `422 Unprocessable Entity`, `admission_rejected`; no credential-failure count |
| Rate limit exceeded | `429 Too Many Requests` |
| Invalid username | `400 Bad Request` |
| Concurrent credential mutation | `409 Conflict`; no current revision is inferred. |
| Removal of the last primary credential | `422 Unprocessable Entity`, `admission_rejected`. |
| Malformed JSON / wrong JSON shape / unsupported content type / oversized body | `400` / `422` / `415` / `413` with `bad_request` |
| Internal auth state or crypto failure | `500 Internal Server Error` with a redacted message |

## Single-call protobuf

`POST /calls` accepts one protobuf `ConsoleFrame.call`. Send `Authorization: Bearer <token>`, `Content-Type: application/protobuf`, and the `Host` and `Origin` headers required above. It needs no WebSocket Hello or Auth frame. The response is a `ConsoleFrame.reply` or `ConsoleFrame.error` with `Cache-Control: no-store`; errors after frame decoding preserve the request ID. Admission errors before the body is read have no request ID. Live streams use WebSocket or `ConsoleService::subscribe`.

Protobuf preserves bytes, large identifiers and typed Xolotl values. Public authentication request and response DTOs implement both `Serialize` and `Deserialize`, so custom adapters can reuse the same service types.

```sh
curl https://console.example/api/console/v1/calls \
  -H 'Origin: https://console.example' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/protobuf' \
  --data-binary @request.pb --output reply.pb
```

Console error categories map to HTTP 400/401/403/409/422/429/500. Unsupported media types return 415; bodies over 4 MiB return 413. The encoded response has its own 4 MiB limit, in addition to Value conversion budgets. HTTP emits `Retry-After` only when the service knows a delay, rounded up to seconds; the protobuf failure retains millisecond precision. Neither field proves a retry is safe. On `VERSION_CONFLICT`, reread the record and reconcile the edit; the observed version can already be stale. See [failure fields](console-actions-and-streams.md#descriptor-validation-and-failures).

`HttpConfig.request_body_timeout` defaults to 30 seconds (allowed: 1 second–5 minutes); the daemon exposes it as `console.request_body_timeout_ms`. It bounds JSON authentication and protobuf `/calls` body collection, returning HTTP 408 on timeout. Connection provenance, Origin and required bearer-header syntax are checked before reading a body or taking shared admission capacity; public-key login requires a real Origin even for verified automation. Bearer validity remains a service decision after decoding. The timeout does not cover service execution after receipt.

Body collection transfers the same shared reservation into service dispatch, retaining it through verification or credential mutation. Return, including a continuation, releases admission; malformed input, timeout, rejected handler checks and cancellation also release it. Account authority and persisted challenge quotas remain independent. Native hosts can reserve with `ConsoleService::admit_authentication` and consume `ConsoleAuthenticationAdmission`; ordinary service methods acquire the same reservation automatically. See [shared limits](console-actions-and-streams.md#shared-admission-and-query-limits).

Password verification runs on Tokio's blocking pool under the shared `argon2_concurrency` limit. Saturation returns `RATE_LIMITED` (HTTP 429) without an invented retry delay or unbounded waiter queue. Cancellation holds the slot until hashing finishes.

## Primary credential management

This section applies to Console-managed local accounts. A host `AccountAuthority` owns its primary-account lifecycle; Console rejects these local primary-credential operations in host-authority mode. Account-keyed second factors remain managed by Console.

`ConsoleService::credentials` and `POST /credentials` accept `CredentialRequest`. Omit `username` to address the authenticated account. `GET /credentials` reads the same account's metadata without requiring a new proof. The JSON operation is nested:

```json
{"operation":{"action":"set_password","password":"..."}}
```

| `operation.action` | Other operation fields | Effect |
| --- | --- | --- |
| `status` | None | Password enabled/changed time, public-key descriptors, Passkey labels/IDs/last-use times and limits. |
| `set_password` | `password` | Set or replace a password under the built-in strength policy. |
| `disable_password` | None | Disable password login while retaining another primary credential. |
| `add_public_key` | `key` | Add a canonical `ml-dsa-65:<base64url>` descriptor for a 1,952-byte raw public key. |
| `remove_public_key` | `key` | Revoke the exact public-key descriptor. |
| `rename_passkey` | `credential_id`, `label` | Change a 1–128-byte label without invalidating sessions. |
| `revoke_passkey` | `credential_id` | Remove the Passkey, invalidate old sessions and pending login challenges. |
| `reset_second_factors` | None | Administrative recovery for another account: clear enrolled factors, pending setup and recovery codes. |

Status returns `status: "current"`; mutations return `status: "updated"`, `sessions_invalidated`, and an optional replacement `session`. Every change to credential authority rotates the same vault epoch as MFA. Changes to the caller's own credentials return a replacement session; use it immediately. Credential-only changes preserve the original authentication time, so repeated mutations cannot extend the recent-authentication window. Labels alone do not rotate the epoch. The per-account limits are 32 public keys and 32 Passkeys. Removing the last primary credential is rejected: TOTP and recovery codes are second factors, not replacements for primary login. Password hashing and verification share bounded blocking capacity.

To initialize or reset another account, supply `username`. This requires recent level-2 authentication, `perform://effect/kernel/console/users`, write authority over the target account, and authority covering that account's effective grants and ceiling. Only root may manage root credentials. A change to another account never issues a session for that account. First create account metadata with `access.user.write_cas`, then provision a password or public key through this service. An account with no primary credential cannot log in; provisioning failure does not make it usable.

Account metadata excludes credential verifiers and authentication evidence. The host generates immutable `account_id` on creation; clients omit it on create and may omit it on update. Updates cannot substitute a different ID. Credentials are bound to that account ID; recreating a username does not reuse its vault credentials. Local sessions additionally bind the account metadata version as a revocation epoch, so updating or disabling and re-enabling an account requires fresh login. Current grants are re-evaluated on each access.

Passkey registration begins with `label` and optional authenticator `display_name`. Its challenge binds the account credential epoch and initiating SID. Confirmation returns `credential_id` and a replacement `session`. Registration, password/public-key changes and revocation atomically update the credential aggregate; stale login-counter or factor updates cannot resurrect a revoked credential. Public-key and Passkey login challenges bind the credential epoch, so removal and re-addition cannot revive a challenge. WebAuthn validates the configured RP/origin and requires user verification for level 2. A concurrent credential CAS returns a conflict; an invalidated token requires fresh login. A committed change, subsequent session issuance and audit delivery are separate operations. After a lost response, authenticate with the current credential and inspect status.

## Second factors and credential lifecycle

Password and public-key login produce level 1 when no independent factor is enrolled. Once a factor is enrolled, correct primary credentials without `second_factor` return `result: "continue"` with `step.kind: "choose_factor"`. An incorrect password does not disclose enrollment. Direct TOTP or recovery proofs may instead accompany the initial request, keeping authentication within one request. A user-verified Passkey assertion supplies level 2 through WebAuthn. Password rechecks alone never supply level 2. An existing bearer can submit a fresh factor to `/session/step-up`.

```json
{"username":"root","password":"...","second_factor":{"kind":"factor","factor_id":"<enrolled-factor-id>","response":{"code":"123456"}}}
```

`GET /auth/factor-providers` returns installed providers as `{descriptor, usage}` records, without account enrollment. `usage` contains independent `allow_enrollment` and `allow_authentication` host decisions. Each descriptor contains `provider_id`, `label`, optional `enrollment` with optional `begin_schema`, required `setup_schema`, and optional `pending_schema`, plus `authentication` with optional `proof_schema` and optional `interaction` containing `challenge_schema`. Each challenge step supplies its own `response_schema`, so successive rounds can require different inputs. At least one authentication path must be declared. Missing capabilities are unavailable; enrollment responses never implicitly use the authentication proof schema. The host checks declaration schemas for an object or boolean top-level shape and byte/depth limits during assembly, then fixes them for that host. It checks each response schema when the provider returns a challenge. Discovery and enrollment admission use the same declaration. The Console does not validate full JSON Schema syntax or evaluate request values against it. Providers publish coherent schemas and validate the shape and meaning of received input and proofs.

`GET /credentials/factors` requires a bearer and returns `result: "status"`, `providers`, `factors`, `max_factors`, and `recovery_codes_remaining`. Each factor summary contains its opaque `factor_id`, `provider_id`, user label, `created_at`, optional `last_used_at`, and `availability`. Times are Unix milliseconds; `last_used_at` records committed login or step-up use, excluding enrollment activation. Availability is `provider_not_installed`, `authentication_disabled`, or `available`; the last value permits the installed provider's declared authentication paths on this host. Clients still inspect the descriptor to choose direct proof or interaction; availability does not predict external dependency health. JSON, HTTP protobuf and WebSocket protobuf retain these distinct states. Recovery codes are an account-owned proof type; the host generates them when the first factor is activated.

Provider dispatch requires installation, a declared operation and host permission. Enrollment permission is checked at begin and every continuation; authentication permission covers direct proofs, login, step-up and every interactive round, including early polls. Policy rejection returns HTTP 403 with JSON code `forbidden`; missing implementations or permitted operations without declarations return HTTP 422 with `admission_rejected`. For an installed provider, host permission is checked before operation support. Neither rejection is counted as an invalid credential proof. The service checks these conditions before claiming a round, so another instance's rejection does not consume it. The original deadline and SID remain binding.

Disabling new use does not change stored factors, credential epochs or historical session evidence, and cannot remove the account's second-factor requirement. Listing, canceling, renaming, deleting and recovery-code use retain their existing authorization rules. Passkey primary authentication is separate from provider usage policy. See [provider configuration](configuration.md#mfa-provider-installation).

All paths in this section are relative to the selected routes' mount; the daemon's `http::serve()` uses `/api/console/v1` by default. `POST /credentials/factors` takes the same tagged `MfaRequest` as `ConsoleService::mfa`:

| Operation | Additional fields | Result |
| --- | --- | --- |
| `status` | None | Same status as GET. |
| `current` | None | This SID’s pending `enrollment`, including its current public step, or `no_enrollment`; requires recent credential-management authentication. |
| `begin` | `provider_id`, `label`, optional `replace_factor_id`, and `input` when the provider declares `begin_schema` | `enrollment` with `challenge_id`, new `factor_id`, `provider_id`, `label`, `expires_at`, and a `step`. |
| `continue` | `challenge_id`, `input` (`response` for a challenge or `poll` while pending) | Another `enrollment` step or `updated` with a new `session` and optional `recovery_codes`. |
| `cancel` | `challenge_id` | `canceled`. |
| `rename` | `factor_id`, `label` | `renamed` with the current factor summary; sessions remain valid. |
| `remove` | `factor_id` | `updated`; preserves session authentication evidence; removing the last factor clears recovery codes. |
| `regenerate_recovery_codes` | None | `updated` with a new session and replacement recovery codes. |

Enrollment begins with a recent authenticated bearer. `begin_schema: null` means the provider accepts no `input`; an advertised JSON Schema requires the `input` field. An explicit `input: null` is present input and can be valid if the provider's schema allows it. The host rejects missing, extra, oversized (over 16 KiB encoded) or deeply nested (over 32 levels) begin input before provider dispatch. A provider can reject the value's semantics with `MfaProviderError::InvalidInput`, reported as a bad request; that result promises no external enrollment was accepted, so the host restores any earlier ready round. The host borrows begin input only for that call; pending enrollment stores the current public step and provider-private round state, not the original input. The verifier is stored only after a final verified step. TOTP declares no begin input. Its setup returns a Base32 `secret`, an encoded `otpauth_uri`, `algorithm`, `digits`, and `period_seconds`. Clients can render a QR code or use the secret for manual setup. The host does not choose a frontend, renderer or authenticator application. Continue the TOTP challenge with:

```json
{"operation":"continue","challenge_id":"...","input":{"kind":"response","response":{"code":"123456"}}}
```

Enrollment is an account-writing ceremony separate from login continuation. `begin_enrollment` returns a challenge or pending status; each `continue_enrollment` returns another challenge, a pending status, or a final verified step. The `enrollment.step` has `kind: "challenge"` with provider-specific `setup` and that round's `response_schema`, or `kind: "pending"` with `status` and `retry_after_ms`. Poll with `{"operation":"continue","challenge_id":"...","input":{"kind":"poll"}}`. Each successful non-final round rotates `challenge_id`; the host permits at most 16 provider calls by default, including begin and the final verification. Polling before `retry_after_ms` returns the remaining wait with the same ID and does not call the provider. Begin first reserves an internal starting claim in the account vault with CAS; `current` reports `step.kind: "starting"` while that call is in flight. Only the winner of a live claim calls the provider. A definite Begin failure before dispatch or after a known provider result rolls back that exact claim, restoring a displaced unexpired ready step when it still fits; a competing CAS or cancellation takes precedence. Each continuation likewise claims its round before provider work. Provider results require a second CAS to publish the next step; a concurrent credential change, cancellation, expiry or session revocation may discard the result. External reservations need their own expiry and may use the stable host-generated `factor_id` for correlation. Providers must make intermediate work safe to abandon; only the final account CAS activates a factor.

There is one pending enrollment per account, bound to the initiating SID and a 5-minute default expiry. Starting another replaces a ready or expired round; it never changes an active factor. Omit `replace_factor_id` to add a separate instance; multiple instances may use the same provider. Explicit replacement requires an existing factor from the same account and provider. Its old verifier stays active until the final round atomically installs the new ID and removes the old one. An account can enroll at most 8 factors; replacement is permitted at capacity. Labels must be nonblank, contain no control characters, and occupy at most 128 UTF-8 bytes. Rename changes only the label, retaining factor identity, sessions and any ready enrollment.

Each continuation first claims the current round with an account vault CAS, before calling the provider. The same ID cannot dispatch twice. An incorrect response is retryable only when the provider guarantees that no enrollment completed and the private round state remains usable. A timeout or uncertain provider error retains the `starting` or `in_flight` claim and is never replayed automatically. While that claim is live, a new `begin` or another MFA management change returns a credential conflict. `cancel` explicitly abandons the claim, including a running provider call; an expired claim can also be replaced by a new `begin`. Neither path can activate a late provider result. If a Begin or non-final response is lost, the same SID can call `current` to recover the active ID and public challenge/status while that enrollment remains current; `current` also exposes an in-flight ID for cancellation. It returns `no_enrollment` for another SID, an expired round or a completed enrollment. The old ID cannot be replayed after a successful non-final round. If the final response is lost, authenticate again using current credentials and inspect factor status.

Final enrollment activation, removal and recovery-code regeneration rotate the account's policy epoch. All previous tokens, refresh attempts and WebSocket SIDs then fail revalidation; clients must use the returned session and authenticate a new WebSocket connection.

All credential changes require authentication within the last 5 minutes by default. If any independent factor is enrolled, level 2 is also required. The first factor can be enrolled with a recent primary login, which avoids a bootstrap dead end. Refreshing a token never resets this authentication time. Expired freshness requires a new login or a fresh enrolled factor through step-up. Passkey registration uses the same recent-authentication check.

Final enrollment activation, factor removal and recovery-code regeneration preserve the complete original evidence in the replacement session. Session metadata separates `issued_at` (this session's creation time) from the derived `authenticated_at` (the latest actual verification); session eviction orders by `issued_at`. First-factor activation does not upgrade the session: a level-1 session needs an actual factor proof or recovery code through step-up before level-2 operations. Removing the last factor does not downgrade historical evidence.

After asynchronous provider work, the service revalidates the bearer, account binding and recent-authentication window before committing. Passkey registration repeats that check at its final write boundary; Passkey registration/login and final factor activation also rechecks its original enrollment deadline before writing credentials.

TOTP follows RFC 6238: SHA1/256/512, 6 or 8 digits, configurable period and bounded clock skew. New enrollments default to HMAC-SHA-256 with a random 32-byte secret. Enrollment settings are stored with the factor, so configuration changes only affect future enrollment. Accepted time steps are persisted; the same or earlier step is rejected. Ten random 32-byte recovery codes are returned on the first factor activation, and stored only as hashes. Use `{"kind":"recovery_code","code":"..."}` for login or step-up. Each code is consumed once; regenerating invalidates all old codes.

A bounded vault aggregate stores password hashes, public keys, Passkey verifier state, factors, pending setup, replay state and recovery hashes at `state://vault/console/credentials/<authority_id>/<instance_id>`. CAS commits consumption before a session can be issued. The same TOTP step or recovery code can commit at most once; custom providers must satisfy their own freshness and replay contract. Session issuance rechecks the active account and policy epoch. Invalid proofs contribute to source/account/global backoff and persistent account lockout.

Both private rows use exact-path bounded State reads and bounded conditional CAS writes. An embedded Console host must install `StateBoundedRead` and `StateBoundedWrite` over the same current-value commit domain; missing ports fail authentication operations instead of falling back to unrestricted State I/O. The credential JSON is capped at 256 KiB and sealed with a host-provided AES-256-GCM-SIV key. Its versioned envelope is stored as canonical base64url in a State string; authenticated data binds purpose, version, authority, account instance and key ID. The host supplies the same `CredentialSealer` to root bootstrap and `ConsoleConfig.auth.credential_sealer`. Missing keys, old plaintext and malformed ciphertext fail closed. The challenge ledger JSON is capped at 4 MiB. Encoded State-row budgets are 397,312 bytes for credentials and 8,392,704 bytes for the challenge ledger. A concurrent oversized replacement is rejected inside the CAS transaction; these per-row bounds do not limit retained State history.

Proofs, enrollment inputs, setup secrets, recovery codes, continuation tokens, interaction payloads and bearer credentials are redacted from DTO Debug output, audit records and safe failure projections.

Rust hosts add `Arc<dyn MfaProvider>` through `ConsoleConfig.auth.mfa.providers`. A provider's `descriptor()` is read and validated once per host assembly, then retained with that implementation. Its stable `provider_id`, declared schemas and capabilities remain fixed for that host; challenge response schemas are supplied and validated per round. The provider port separates these operations:

| Method | Contract |
| --- | --- |
| `begin_enrollment` | Receive borrowed provider-specific input and return `MfaEnrollmentStep::Challenge` or `Pending`, each with public progress and private round state. External preparation must be safe to abandon before the first result is published. |
| `continue_enrollment` | Apply `MfaInteractionInput::Response` or `Poll` to the authorized round; return another step or `Verified` with the verifier to activate. |
| `verify_proof` | Validate one direct authentication proof and return the next verifier. |
| `begin_authentication` | Begin an interaction against the selected active verifier. |
| `continue_authentication` | Apply `MfaInteractionInput::Response` or `Poll` to the retained private state. |

Default trait methods return `MfaProviderError::Unavailable`; providers should advertise only implemented capabilities. Console rejects undeclared operations before calling the provider. A declared method returning `Unavailable` during execution is a provider failure, separate from installation, capability or usage admission. The host supplies `MfaContext` with immutable `account_id`, `factor_id`, username, display label, `purpose` (`Enrollment`, `Login`, or `StepUp`), issuer and time. Labels are mutable display data, not security identities. The shared host owns enrollment, CAS, recovery and session policy. Provider calls have a 10-second timeout; providers must enforce independent possession, freshness and replay protection and handle cancellation. Each instance has separate replay state; a successful CAS cannot make an unchanged verifier replay-safe. Interactive calls additionally receive `MfaInteractionContext`: verified factor context, stable `ceremony_id`, invocation `round` starting at one, and the original `expires_at`. These facts never come from client JSON. Enrollment calls instead receive `MfaEnrollmentContext` with the same stable ceremony identity, round number and deadline.

An interactive provider returns `MfaInteractionStep::Challenge { private_state, challenge, response_schema }`, `Pending { private_state, status, retry_after_ms }`, or `Verified { next_verifier }`. The public `AuthenticationStep::Challenge` includes the challenge and its round-specific `response_schema`; pending status is also public. Private state stays in the challenge ledger. Challenge accepts a response and Pending accepts a poll. `Verified` is not a session: the service must first win final continuation consumption and commit the account verifier CAS. The selected verifier must still match; another authentication's replay-state update cannot be overwritten. Provider JSON is bounded to 16 KiB and depth 32; schema describes interoperability, while the provider validates protocol semantics. The host does not fetch schemas or execute provider-supplied client code.

Selection and provider rounds share the challenge ledger's count and byte limits. Claiming a continuation atomically marks its entry in flight while retaining capacity; concurrent calls cannot fork it. A successor rotates the opaque token, keeps the original deadline and remains subject to ledger size limits. Default authentication lifetime is 120 seconds, with at most 16 provider calls including begin and a minimum poll interval of 500 ms; see [MFA configuration](configuration.md#mfa-provider-installation) for bounds. Every provider call is limited by both the 10-second timeout and remaining ceremony time. An admitted early poll spends no step and creates no invalid-proof failure. Current provider usage, ordinary admission and account lockout checks still apply before returning the wait result.

Cancellation can use the current token while its round is in flight. It competes with successor publication or final consumption in the same ledger CAS. If cancellation wins, that result cannot publish or commit credentials. The entry keeps its quota until the provider call exits and retires it, or the original deadline permits reclamation. Once final consumption wins, cancellation cannot undo credential/session commits or remote effects. Crashed in-flight Futures are not resumed or retried; their reservations expire at the original deadline. A lost successor response requires restarting authentication.

`ConsoleConfig.auth.mfa.install_totp` defaults to `true`. Set it to `false` for an empty installation or one supplied entirely by the Rust host. Disabled built-in parameters do not undergo TOTP compatibility checks; configuration still requires valid field types and algorithm names. The limit of 32 providers counts only installed implementations, independently of the per-account factor limit. Duplicate installed IDs reject assembly. With built-in TOTP disabled, a host may explicitly install a compatible implementation under `totp`; reusing any stored provider ID requires understanding its existing verifier format.

Provider names do not select the account recovery path. `MfaProof::Factor` resolves an installed provider through the saved factor, while `MfaProof::RecoveryCode` consumes the account's code directly; even a provider named `recovery_code` cannot intercept that separate proof branch. Removing a provider retains its enrolled factors as unavailable and does not downgrade the account's factor requirement. Existing recovery codes remain usable independently of installation. Provider code is trusted host code, not supplied in a request or loaded from daemon TOML. Custom providers can implement hardware challenges, multiple response rounds or external approval using the separate enrollment and authentication interaction ports. This is an extension contract, not a built-in push service or device integration. TOTP and recovery codes remain direct proofs; Passkey primary authentication keeps its dedicated WebAuthn RP/origin and user-verification path.

Provider work, vault CAS, session writes and audit writes are not one distributed transaction. A lost response can leave a proof consumed or enrollment committed. After an uncertain result, check status or authenticate again; do not assume a proof is reusable. Account recovery outside the returned codes and configured Passkeys is an explicit host provisioning concern, not an unauthenticated reset endpoint.
