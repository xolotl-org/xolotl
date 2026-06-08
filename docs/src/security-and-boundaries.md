# Security And Boundaries

Nexus security is enforced by runtime paths. This chapter describes the public
behavior of those paths.

## Authority

Authority starts as a `Grant`, is attenuated during spawn or request admission,
and is compiled by `open()` into a process-owned `Handle`. The data plane checks
the Handle owner, liveness, method rights, and residual policy before dispatch.

Kernel-reserved prefixes such as `state://kernel/*`, `state://vault/*`, and
`state://fact/*` accept writes from kernel paths. Console management state is
admitted per path and management actions use fixed descriptors.

## Provenance And Taint

Values carry provenance in a `TaintSet`. Taint sources include author constants,
model output, inbound events, fetched content, and protected sources. Operation
inputs propagate taint to outputs, and state stores a `TaintedValue` so
provenance survives state writes and reads.

Policies can then decide from lineage. For example, an outbound Operation can
be denied when its input lineage touched a protected source.

## Secrets

Secrets may enter Operation input, state, Facts, or traces only as redacted
metadata or references.

Console authentication writes redacted gateway audit Facts. Pairing raw secrets
are generated inside the pairing driver and leave through the one-shot display
edge; recorded Operations carry only hash/checksum metadata. The Console
Protocol declares secret custody actions, but the current host blocks raw
secret reveal and audits the attempt.

## Console Boundary

HTTP is limited to health and authentication bootstrap. Post-login management
runs over Console WebSocket using fixed action descriptors and stream
descriptors. Clients submit descriptor-named actions.

Management actions still run through authorization, state, CAS, visibility,
audit, and runtime Operation paths. Protected payload views require explicit
visibility metadata such as scope, justification, and TTL.

## Driver Boundaries

The standard terminal driver executes argv directly and never through a shell.
Commands must pass the denylist, allowlist, and high-risk approval checks.

The fetch driver rejects loopback, private-network, `.local`, `.internal`, and
non-HTTP(S) targets before issuing a request.

These checks are runtime gates. Untrusted code still needs OS/container
isolation.
