# Security And Boundaries

## Trust boundaries and cryptography

This is the pre-release security policy. Requirements do not imply that every deployment or protocol has completed interoperability testing or independent security review. Choose controls from the protected object and attacker, not from crate, function or queue boundaries.

Core, Kernel and trusted Drivers exchange ordinary typed values by move or justified sharing. Preserve identity, Handle ownership, authorization, provenance and budget checks; do not repeatedly encrypt, sign or serialize internal hops. Native-code isolation requires a process or sandbox, not encryption of values used in that same process.

Transport endpoints protect and terminate network channels. Credential/storage owners seal private persistent secrets at writes and open them at reads with host-owned keys. Applications that distrust a relay own end-to-end encryption; relay payloads remain opaque. These protect different objects and have independent key lifecycles. At-rest sealing is not an internal Value representation.

| Boundary | Pre-release default policy |
| --- | --- |
| Remote TLS | TLS 1.3, `X25519MLKEM768` hybrid exchange, AES-256-GCM or ChaCha20-Poly1305; reject classical fallback and business 0-RTT |
| Node / owned public-key identity | ML-DSA-65 with constrained purpose, audience, validity and canonical authority-chain records; bind proofs to the verified channel |
| Password / TOTP / bearer / pairing | Bounded Argon2id; high-entropy HMAC secrets; OS-generated 256-bit bearer and pairing material respectively |
| External envelope | 256-bit PSK-derived ChaCha20-Poly1305; remote sessions also require the TLS policy against recorded traffic and later PSK disclosure |
| Local secrets | Private credential owners enforce integrity, object/version binding and commit semantics; hosts protect keys, permissions, backups and recovery anchors |

Use established algorithm implementations and combinations. Exchange and authentication are separate guarantees; a verified node does not inherit user authority. Report actual exchange, authentication path, content visibility, at-rest protection and evidence, rather than a single quantum-safe flag. PQC does not fix weak passwords, malicious hosts, unauthorized calls, rollback or leaked plaintext.

Daemon gRPC listeners and standard fetch/inference HTTPS clients select explicit per-transport TLS providers, independent of the process default. HTTPS clients retain platform trust verification and require ML-DSA-65 authentication as well as the remote TLS policy; incompatible third-party services fail closed, without classical fallback. These clients disable resumption and early data; hosts need not install a global crypto provider.

Adapters supply facts from completed handshakes: actual version, exchange group, verified peer and channel binding. Headers, Hello messages and features are not handshake evidence. Identity owners validate roots, online delegation, purposes, expiry and channel proofs; user/service subjects separately validate issuer, audience and holder evidence. Services check current resource/action/scope/limits and revalidate at dispatch, commit and delivery where their contracts require it. Kernel consumes verified local identity and authority, not raw network proofs.

Reject missing evidence, unverifiable authority, expiry and downgrade; do not retry as plaintext or classical crypto. Pass minimal verified facts onward. Cache separation respects differing subjects and visibility. Bound unauthenticated work, payload size/depth, concurrency, KDF/signature costs and queues before expensive work; authentication does not remove limits.

Local SDK calls need no TLS. Loopback and OS-protected IPC may use a local host boundary; LAN, public and proxied connections require the actual termination endpoint to satisfy remote policy. A trusted-proxy setting proves neither upstream hybrid exchange nor post-quantum identity. Classical Passkeys retain their authenticator/browser guarantees and cannot be reported as post-quantum; password/TOTP limits, MFA, recovery and revocation remain independent.

Rotate root, TLS, session-ticket, bearer and content keys independently. New algorithms require versioned policy and independent interoperability evidence. Root-compromise recovery requires an independent trusted anchor or reapproval. Encryption and zeroization do not prove rollback resistance or erasure of copies, old pages, dumps and backups. Accepted effects retain real identities for reconciliation when authority stops new work or delivery.

Release validation covers actual negotiation, valid/invalid proofs, downgrade and replay rejection, revocation races, tampering and wrong binding, exhausted budgets, recovery/old backups and secret leakage. Standard libraries and unit tests are not independent security review. Report checked guarantees only; sealed Console and pairing records do not imply encrypted general State, objects or backups.

## Authority

A `Grant` is attenuated during Process admission and compiled by `open()` into a process-owned `Handle`. Invocation checks its owner, liveness, method rights and residual policy. A service also checks caller identity and host exposure before delegating authority to a Process. Discovery describes available forms; it does not authorize a later call. See [Capability Model](capability-model.md).

Kernel-reserved paths such as `state://kernel/*`, `state://vault/*` and `state://fact/*` are not general application State. Console management actions apply path-specific admission; a broad State grant does not turn reserved paths into ordinary writable data.

Selecting a Gateway retry epoch grants no account or surface authority. Closing that range is a trusted-host operation, not a client RPC, and never authorizes replay of unknown effects. Source evidence inspection still requires current Console authority, MFA, the concrete target, justification and final-delivery checks. Any observation audit is owned by that disclosure boundary; the Source lookup is read-only and adds no private audit commit. Absence of retained evidence is not proof of non-commit or permission to release responsibility or replay. Domain rules belong to the [Gateway request-store](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-gateway/src/idempotency_store.rs) and [Source inspection](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs) contracts.

## Provenance

`TaintSet` records sources of values and failures, including model output, gateway inputs, external Providers and Sources, fetched content and protected data. State retains taint with values. A policy may deny an outbound Operation based on its input lineage. Provenance explains where data came from; it does not grant authority to read, execute or export it. See [State And Facts](state-and-facts.md#tainted-values).

## Secrets and audit

Ordinary execution Operations, application State, Facts and traces carry secrets only as references or redacted metadata. Dedicated Console vault rows hold credential verifier material, including TOTP secrets, under bounded access and conditional writes; see [credential storage](console-http-and-credentials.md#second-factors-and-credential-lifecycle). Pairing secrets leave through a one-shot display edge; recorded Operations carry hash or checksum metadata. Console blocks raw secret reveal and records the attempt when observation storage is installed; recording errors after installation remain visible. Required recording barriers still use strict APIs.

Console credential vault rows and the separate external pairing credential file are encrypted with independent host-owned AES-256-GCM-SIV keys. Old plaintext, missing or wrong keys, and modified ciphertext fail closed. Hosts must protect keys and backups, including redb copy-on-write pages that may retain older plaintext. TLS does not protect data on disk. Federation Sessions bind post-quantum node proofs, and hosted-subject proofs when used, to full-handshake hybrid TLS; the system has not undergone independent end-to-end security review. See the [federation security contract](security-and-boundaries.md).

Console Rust, HTTP and WebSocket entries share authenticated admission, schema, step-up and concrete target authorization. Management actions return the actual handler result without separate mutation start/completion audits. Failure or cancellation does not imply rollback; runtime requests retain cancellation and handle cleanup ownership. See [Mutation Results](console-actions-and-streams.md#mutation-results).

Level-2 Console access requires an independent second factor or a verified Passkey with user verification. TOTP, recovery codes and host-installed MFA providers are governed by the same session evidence and credential lifecycle; factor enrollment alone does not prove recent authentication. See [second-factor contracts](console-http-and-credentials.md#second-factors-and-credential-lifecycle).

## Driver boundaries

The standard terminal Driver executes argv directly, without a shell, under Kernel authority and host command allow/deny lists. Caller-supplied `approved` flags and `high_risk` command classifications are not authentication or approval evidence; the standard Driver does not accept these pseudo-approval controls. Applications own any human-approval policy. Cleanup covers the direct child, not isolation or termination of its entire OS process tree. See [Terminal installation](api-reference.md#terminal-installation) for host custody and limits.

Standard Fetch is public-only: it admits HTTP(S) URLs, rejects local/internal names and non-public literal addresses, and validates the DNS addresses used by the actual connector before connecting. URL preflight alone cannot prevent DNS rebinding. DNS admission rejects the whole answer set if any address is non-public or there are more than 64 answers. Literal addresses and redirect targets use the same public-IP classifier, including rejection of mapped or NAT64-embedded private addresses. Environment proxy settings are not adopted implicitly. Internal-network or proxy access requires a host-supplied custom Driver with its own transport policy. These runtime checks do not replace OS or container isolation for untrusted code.
