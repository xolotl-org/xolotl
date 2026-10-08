# Working on Xolotl

Xolotl is an embeddable, composable capability runtime. Optimize for **generality, performance, and memory efficiency**, subject to security and truthful call/data-commit semantics. Applications own business policy; hosts choose resources, storage, scheduling, and exposure.

## Build the Project Model First

Start with the [architecture](docs/src/architecture.md): program describes work, Core advances it, Kernel authorizes resource calls, and Driver performs them. Use its ownership map to find the responsible crate, public rustdoc contract, implementation, and acceptance tests. Read the [security policy](docs/src/security-and-boundaries.md) when trust, authentication, transport, secrets, or persistence is affected.

For a whole-project review, trace one real request from the service adapter through execution to its Driver. Identify the selected execution configuration, mutable-state owners, commit domains, evidence, and release points before reviewing modules. Use the architecture's [composition checks](docs/src/architecture.md#composition-checks) at handoffs; check APIs and Cargo manifests against the contracts and report concrete gaps.

The runtime owns one running host lifecycle. Persistent application data is distinct from execution state. Keep ordinary calls independent of restart checkpoints, durable task families, and mandatory audit history; retain in-memory suspension where live scheduling needs it.

## Make a Focused Change

- Locate the rule owner and identify whether the issue is an implementation deviation, missing contract, or conflicting responsibility. Fix design first for the latter two.
- Establish the affected data path, valid states, commit point, failure/recovery behavior, and resource cost. Prefer removing unnecessary work or reusing a contract before adding a mechanism.
- Update the formal architecture for cross-layer decisions and the owning public rustdoc for domain contracts; synchronize the user manuals for observable behavior. Evolve pre-release APIs and formats directly, updating affected callers together.
- Preserve existing workspace changes and keep edits scoped. Commit or create branches only on explicit request.

Security controls belong at actual trust boundaries, not every module hop. Core/Kernel/trusted Drivers pass ordinary typed values; transport and credential/storage owners provide the applicable protection. Preserve required authorization, provenance, revocation, and delivery checks. Internal encryption is not native-code isolation; cryptographic profiles are defined in the security policy, not duplicated here.

Evaluate complexity, copies/encoding, lock scope, in-flight capacity, peak working set, and retained memory. Prefer moves, justified immutable sharing, local reads, bounded pages, and incremental updates. Each limit specifies its charged object, rejection, and release; encoded bytes are not an RSS limit.

## Validate and Maintain

Tests protect observable contracts and distinguish incorrect implementations. Share backend acceptance contracts; separately cover reopen, rejection, cancellation, and uncertain commits. Remove tests for duplicated or explicitly retired mechanisms; retain acceptance tests for active contracts. Keep relevant implementation gaps beside their contract until resolved.

Start with `cargo test -p <crate>`, then related backends and independent features; use workspace tests and strict Clippy for cross-layer changes, and configured formatting checks. Performance changes require representative latency and memory measurements. Report only the scope actually checked and distinguish environment failures from product failures.

For documentation, build both mdBooks, validate source and generated links, and run `git diff --check`. Maintain one primary location per rule and synchronize user manuals; keep measurement archives, maintenance lists and round logs out of project documentation. Do not add documents or speculative interfaces merely to fill out a structure.

Pause/resume a Goal only on user instruction. Documentation work does not resume paused implementation work.
