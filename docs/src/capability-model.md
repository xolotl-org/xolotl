# Capability Model

Authority starts as a Grant and is compiled into a Handle before execution.

## Paths

Resource paths use:

```text
<scheme>://[<segment>[/<segment>...]]
path://<cluster>/<scheme>[/<segment>...]
```

Examples:

```text
effect://inference/infer
state://memory/alice/thread
process://alice
path://phone/effect/inference/infer
```

The `path://` form explicitly names a cluster; an unqualified path is local. Cluster identity is part of a path's equality, prefix, and pattern matching. The scheme can be application-defined in either form; `path` itself is reserved as the cluster-qualified prefix. Cluster names may equal scheme names; their positions in `path://<cluster>/<scheme>/...` are unambiguous. Both local and clustered root paths may omit segments. Parsing requires the explicit `://` delimiter; slash-only shorthand is invalid.

Resource installation declares `ResourceAddressing::Exact` or `Prefix`. Exact matches only the registered path; Prefix also serves descendant paths in the same scheme and cluster, unless a nearer registration wins. The Resource kind and path scheme do not choose this behavior. Authorization always checks the complete requested path.

Operation options belong in structured input Values, explicit resource segments, or policy/config state.

## Capability Literals

Capability literals use verb schemes:

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
perform://effect/events/subscribe
act-as://identity/alice
perform://path://phone/effect/inference/infer
read://path://*/state/memory/alice/**
read://device/lab/thermostat#sample
```

The verb is separate from the Resource path scheme. A Resource path describes what is being operated on; a capability literal describes what operation class is authorized. Callable method verbs (`perform`, `read`, `write`, `append`, `subscribe`, `publish`) may target application-defined schemes; the installed method declares which verb it requires. `act-as` addresses an `identity://...` identity, and `spawn` addresses a `process://...` resource. Acting identities use concrete local paths; a process path does not identify an acting principal.

An unqualified capability selects **only local paths**, even when its scheme or segments use wildcards. Within a capability literal, the `path://phone/` prefix selects that cluster, while `path://*/` selects any clustered path but no local path. The canonical root capability `*://**` is the sole form spanning both local and clustered paths. A host may still restrict access to clustered targets independently.

Append `#<method>` to select one exact, stable resource method name, before any `@` predicate: `perform://effect/app/echo#invoke` or `read://state/app/profile#load@account=alice`. Without `#`, a capability covers every method in that verb and path scope; it does not bypass the method's declared authority class. Method names use canonical UTF-8 percent encoding: ASCII letters, digits, `-`, `_`, `.`, and `~` remain literal; every other byte uses uppercase `%HH` (for example, `#read%2Fdetail`). Method selectors have no wildcards. A method-scoped capability cannot authorize a check that has no method context, such as `act-as`.

## Grants And Rights

A Grant has a holder Process, a selector, rights, constraints, and expiry. Its selector predicate and inherited constraints both apply to the same operation input and clock. A source Grant records `GrantMethods` by stable method name (or explicitly `all`) and propagation flags such as delegation. Open requests and Handles use a resource-local method bitmap. Resource relinking may reorder methods without turning a named grant into authority for another method; `all` deliberately includes newly installed methods.

Selectors can match exact paths or wildcard path segments. Requested rights must be a subset of the parent rights when deriving or attenuating authority.

Capability-set attenuation checks cluster scope, the path language, and the input predicate. A local parent cannot derive a clustered child, and a grant for one cluster cannot derive a grant for another or for all clusters. A cluster-wildcard parent may derive an exact-cluster child, never a local child. `*` matches one segment; `**` matches zero or more, so a parent `read://state/memory/*` cannot derive a child `read://state/memory/**`.

A child of a method-scoped capability must retain the same method; a capability without `#` may derive one exact method. A child of a parent with an input predicate such as `@account=alice` must retain that same predicate. An unpredicated parent may derive a more restrictive predicated child. `CapSet::intersect` uses the complete `Capability::covers_cap` check; it cannot gain authority by dropping a parent's predicate.

Structural coverage is conservative and may reject some patterns that are in fact contained; use a more direct parent selector when needed. `Capability::covers_cap_pattern` checks structure only: Bootstrap separately carries the parent's predicate into the derived constraints, and Console discovery reports such authority as `predicate_bound`. Structural coverage alone never authorizes a call.

An `@until=<i64 Unix milliseconds>` predicate bounds the capability by the current wall clock, including the stated millisecond. It accepts only `=` and an exact signed 64-bit integer; malformed or dynamically constructed `until` predicates deny authorization.

For input fields, integer values compare with integer literals exactly, including values above `2^53`. A fractional or out-of-range threshold cannot authorize an integer field. Float fields use finite `f64` comparisons; `NaN` and infinity cannot form numeric authorization bounds. Missing fields and type mismatches also deny authorization.

## `open()`

`open()` is the control-path compiler. It resolves a Resource, selects a covering Grant, checks open-time constraints, resolves the Binding, builds a DriverPlan, compiles residual policy, and installs a process-owned Handle.

After that point, the data path executes against the compiled Handle.

An opened `DriverPlan` retains every original method declaration alongside its dispatch rules, including methods outside the requested rights. `methods()` and `entry(id).declaration()` inspect that frozen interface without consulting the current registry. Low-level hosts may use `insert` for native entries without declarations; `insert_declared` retains a full declaration and derives its dispatch rules. Undeclared native entries cannot be captured as portable authority.

Embedded hosts can separate these phases with `prepare_open(&registry, request, attached_grants) -> PreparedOpen`. Preparation borrows no handle table. Its immutable result exposes the owner, acting identity, concrete path, rights, driver contracts and optional residual policy. A host can validate or capture policy recovery recipes before allocating a slot; discarding the plan creates no handle.

The requested path must be concrete and resolve to the selected resource. Wildcard targets fail with `OpenError::NonConcretePath` before grant selection, policy callbacks or cache insertion; selectors may still use patterns.

`prepared.install(&handles)` borrows the plan, checks the source registry's revision and installs under a short revision guard. A grant, policy or resource update invalidates an uninstalled plan. Installation never recompiles or evaluates residual checks. Static policy uses the time supplied during preparation; prepare close to installation. Each successful installation creates a fresh slot.

Low-level hosts manage process lifetime and attached grants. Bootstrap and Executor compile outside the shared handle-table lock, then recheck process admission while installing. Trusted finalizer and machine cleanup scopes retain their existing admission rules.

The hosted `HandleTable` is shared: cloning it keeps the same slots, and its public operations manage synchronization. `get(id)` returns an owned snapshot; changing it cannot rewrite live rights, dispatch contracts or policy. Each invocation resolves its own authority at admission; keeping a snapshot cannot authorize new calls after revocation.

Lifecycle state belongs to the slots, not the snapshots: `release` removes local use while preserving existing descendants, and `revoke` invalidates the whole delegation subtree. There is no separate `close` state retaining an unusable driver payload. `HandleTable::derive` checks the parent and installs its attenuated child atomically.

Release, revocation and owner cleanup drop retired native captures after unlocking, including failed installation and batch rollback. Drivers and policy objects can retain a `WeakHandleTable` from `downgrade()` without creating a table ownership cycle.

The data plane also releases the table lock before recording admission failures. A custom Fact backend may inspect or revoke handles while recording a rejected call; both outcome recording and its durability barrier run outside the lock.

`Registry::new()` retains at most 1,024 simple open plans; `Registry::with_open_cache_capacity(entries)` selects the capacity, and zero disables caching. Constrained grants and installed policy sources bypass the cache. Eviction does not invalidate prepared or installed plans. Cache validity, charging and release rules belong to the [Registry rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-kernel/src/registry.rs).

## Policy Snapshots

Policy sources compile into `PolicySnapshot`. Anything decidable at open time is eliminated. Checks that depend on operation input, budget, rate limits, command matching, approval, or other runtime state stay as residual checks.

If no residual checks remain, the Handle is marked `Unconditional` and the data path skips policy evaluation for that Handle.

Residual checks run in their frozen order, preserving repeated stateful checks. Authority, residual policy and budgets are checked on the live admission path; Facts do not replace those checks. Handles and native checks belong to the current host lifecycle. A new host opens Handles against its installed resources, policy and grants.

## Persistent Rate Limits

`RateLimitCheck::new(scope, maximum, window_millis, state)` uses an explicit, stable host-selected account scope plus the acting identity. A policy source can use `OpenContext::resource_path` for per-target accounts, or choose a tenant or API scope to share a limit across targets. Local Resource IDs never select persistent accounts. Scopes must be nonblank and at most 512 UTF-8 bytes; windows must be positive, while a zero maximum is valid. Invalid configuration is rejected.

State lives at `state://kernel/ratelimit/<scope-hash>/identity:<acting>` using a domain-separated hash of the complete scope. The v1 record retains the window length and admission timestamps. Changing a window under an existing scope is rejected to avoid forgetting history already evicted by the old window; the host must explicitly migrate that state or select a new scope.

Malformed records fail closed without being overwritten. Concurrent checks share CAS admission, and backward clocks retain future timestamps conservatively. This limit counts policy evaluations, including checks followed by another residual's denial; it is not a count of completed Operations.

## Advisory Locks

The optional Standard lock provider exposes `effect://lock/acquire` and `effect://lock/release` as `invoke` methods. Acquire accepts a lock name and returns `{ "acquired": true, "name": name, "token": token }` when it wins, or the same map with `acquired: false` and `token: null` when another acquisition holds the lock. A successful result can be passed directly to release.

Release requires the map's `name` and `token`, and returns `true` only when its atomic compare-and-delete removed that exact holder. A stale or already released token returns `false`; it cannot delete a later holder, including a later acquisition by the same Process.

Each successful acquisition uses a fresh random token. Its Operation identity also appears in the token so a retry with the **same Operation ID** can recover the token after an uncertain State commit. An uncertain acquire may have left the lock held without returning the token; a new Operation ID cannot claim that holder.

An uncertain release can be retried with the same token. A later `false` means that token no longer holds the row, whether the first release committed or another holder has since acquired it. The caller must retain the acquisition result for release; the provider has no lease or automatic expiry.

The State row is observable to callers with permission to read `state://kernel/locks/<name>`. The token is concurrency ownership evidence, not a secret authorization boundary: release still requires permission for the effect method. It is not a monotonic fencing number for external resources; those resources must enforce their own stale-owner protection.
