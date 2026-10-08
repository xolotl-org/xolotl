# Console Protocol

Console exposes host-selected management and runtime functions through one authenticated service. Rust callers, HTTP single calls and WebSocket calls share action admission, authorization, audit and execution. The Kernel checks each admitted Operation. Clients choose their own workflows from descriptors; discovery does not grant authority.

| Need | Read |
| --- | --- |
| Call installed resources, run portable programs, submit retained work or subscribe | [Runtime Calls and Submissions](console-runtime.md) |
| Mount HTTP routes, authenticate or manage credentials and second factors | [HTTP and Credentials](console-http-and-credentials.md) |
| Use protobuf frames, action descriptors, State/Fact queries or audit streams | [Actions and Streams](console-actions-and-streams.md) |
| Select a daemon listener or transport | [Gateways](gateways.md) |

## Service boundary

Validation belongs at the actual transport handoff, including any adapter-owned buffering. Checking before a buffer's later readiness or flush wait is insufficient. The production WebSocket session owns the full socket rather than a split sink, so a split adapter cannot insert another unchecked readiness wait between validation and underlying acceptance. Custom adapters must preserve the same ordering.

If revision metadata lookup fails after an accepted self-revoking action, the original error and session-invalidated disposition survive; the service must not install a delivery guard for the revoked SID. Withholding a protected failure preserves `OutcomeUnknown` classification, known execution/unresolved identities and native cleanup custody, without exposing its protected `runtime_completion`. A delivery denial is neither rollback nor cleanup confirmation.

`ConsoleService::call` and `ConsoleCallAdmission::call` are local-observation conveniences: they execute the action and validate the result's current delivery authority before returning it to the Rust caller. Network adapters instead use `prepare_call`, which returns an opaque `PreparedConsoleResult` containing either the action result or its structured failure. `into_parts` separates the local result from its optional `ConsoleDelivery`; retain that guard through encoding, queueing and socket-readiness waits, then call `ConsoleDelivery::validate` immediately before handing bytes to transport. `deliver` performs local validation but does not authorize a later delayed send. Validation neither repeats the action nor renews its session or visibility deadline. Explicit self-revoking session-control acknowledgments are guard-free; this exception does not authorize ordinary protected results after revocation.

`ConsoleState::with_config(boot, ConsoleConfig)` constructs shared service state without starting a listener. `ConsoleService::new(state)` exposes authentication, calls and subscriptions. Callers supply bearer credentials; the service revalidates sessions and applies descriptor and path-specific checks. Hosts supply verified source provenance for audit and transport policy, not a pre-authorized principal. Owned Rust `RuntimeRequest` values can enter through `run_runtime`, `submit_runtime` and `subscribe_runtime`; see [Rust runtime requests](console-runtime.md#rust-runtime-requests).

```rust,ignore
use xolotl_console::{ConsoleConfig, ConsoleService, ConsoleState};
use xolotl_console::session_store::{ConsoleSessionPolicy, MemoryConsoleSessionStore};
use std::sync::Arc;

let sessions = Arc::new(MemoryConsoleSessionStore::new(ConsoleSessionPolicy::default()));
let state = ConsoleState::with_config(boot, ConsoleConfig {
    session_store: Some(sessions),
    ..ConsoleConfig::default()
})?;
let service = ConsoleService::new(state);
```

`ConsoleConfig::default()` installs no host configuration validators. An embedding host may register `ConfigNamespaceAdmission` for the existing declaration spaces or a custom `state://kernel/config/<owner>` namespace; the stock daemon installs its Gateway, manifest, projection and inference validators during assembly. Console retains authorization, version checks and CAS. Host-owned configuration writes without a matching admission rule fail, and overlapping or reserved namespace claims fail assembly.

The default crate features provide the embedded service and bounded public wire codec without Axum. Enable `http` for HTTP/WebSocket adapters. An HTTP adapter adds origin, proxy and connection policy through its own `HttpState`. Adapters over one `ConsoleState` share authentication, registry, call and subscription admission, and submitted execution custody. WebSocket owns frame delivery and its connection queue. Custom adapters verify their connection and source, then use `ConsoleService::admit_call()` before collecting or decoding a call frame. The returned `ConsoleCallAdmission` borrows its issuing service, cannot be cloned, and releases capacity when dropped on a malformed frame or cancelled request. After decoding, `admission.call(bearer, source, action)` consumes the reservation. The reservation also offers `run_runtime` and `submit_runtime` for owned Rust requests; direct service methods use the same admission and dispatch path. Adapters still own frame limits, body deadlines and source-provenance checks; see [v1 encoding](console-actions-and-streams.md#encoding).

A Rust host can install `ExternalPrimaryAuthentication` and `AccountAuthority` in `ConsoleConfig`; the verifier establishes the primary proof, the authority supplies the current account, and Console issues its own bearer. In host-authority mode, local primary login is disabled.

The daemon mounts Console under `/api/console/v1`. Rust hosts can mount a selected set of relative HTTP routes elsewhere; see [HTTP routes](console-http-and-credentials.md#http-routes).

Runtime replies and sanitized errors can carry `unresolved_operations` independently of their value or failure category. It contains bounded, sorted `operation_ids` observed by the host and `identities_incomplete` when some identities could not be retained. A successful result can therefore still require external reconciliation. The same fields cross the v1 protobuf reply/error frames; callers should inspect them before deciding whether to repeat an effect. See [runtime result custody](console-runtime.md#service-owned-submissions-and-retained-results) for retained executions.

Sanitized failures can also carry `runtime_completion` in JSON and v1 protobuf errors: bounded known body evidence plus a separate finalization projection after lifecycle or delivery failure. `body_retention_failure` distinguishes an omitted body from an unknown effect. Native `ConsoleFailure.finalization_error` is not encoded; it retains a typed cause and cleanup ticket only for a trusted Rust host. See [runtime result custody](console-runtime.md#service-owned-submissions-and-retained-results) for projection states, byte limits and retry obligations.
