# Incremental Values

Structured values can be encoded into immutable objects and consumed as events
without collecting their complete wire representation. Resident consumers use
the same immutable shared `Value` throughout portable and hosted execution,
State, Facts and checkpoints. Event processing and materialization are explicit
choices; an I/O window does not impose a cumulative task-size limit.

## Resident Ownership

`Value` is an opaque owner. Inspect its semantic variants with `view()`, or use
`as_list`, `as_map`, `as_str` and `as_bytes`. Clone is O(1). Moving String or Vec
buffers into a Value preserves their data allocations; `into_text` and
`into_bytes` return independently shared leaf owners. Cloning a selected child
allows the original parent and its unrelated siblings to be released.

`ValueList` and `ValueMap` have persistent typed indexes. Updates share unchanged
branches and copy one leaf plus its index path. Growth returns `CollectionError`
for representational overflow; ordinary allocator failure is not promised to be
recoverable. Final collection release is iterative and does not allocate a work
stack or recurse through nested Values.

For sequential construction, `ValueListBuilder` and `ValueMapBuilder` retain
one unfinished leaf of at most 32 members and O(log n) completed index roots.
Ordered construction takes O(n) time; `finish()` transfers those leaves into
the same persistent collections. Map `append` requires unique keys in ascending
UTF-8 byte order. Use ordinary `ValueMap::insert` when input order is arbitrary.

Exact equality, semantic digests and token estimates memoize shared subgraphs.
Digests include complete media metadata and exact float bits, without reading
external content. Equality never treats matching digests as proof. Token
estimates count each logical edge and saturate at `u64::MAX`. Debug is shallow.
`ValuePostorder` exposes the same borrowed walk to consumers; allocation keys
are temporary memo keys, never persistent identities.

Tagged persistence stores a postorder node table and root references, decoding
directly into Value. `ValueTableEncoder` and `ValueTableDecoder` share one table
across multiple roots, including checkpoint fields. Encoding preserves physical
sharing; it does not make every semantically equal sharing layout byte-identical.
Use `semantic_digest()` for semantic identity. Plain JSON and protobuf remain
tree adapters whose output size and parser depth require explicit admission.

## Selectable Components

| Component | Responsibility | Runtime dependency |
| --- | --- | --- |
| `xolotl_types::value::event` | Logical events, borrowed `ValueCursor`, pure semantic `Validator`, explicit `ValueBuilder` | `no_std + alloc`; no I/O |
| `xolotl_value_codec::validation` | `EventValidator`, GAT `KeyStore`, paged `MemoryKeyStore` | `no_std + alloc`; caller drives futures |
| `xolotl-value-codec/cbor` | Validated version 1 encoder and decoder | Optional `ciborium-ll`; no State or executor |
| `xolotl-value-object/cbor` | `ValueObjectWriter`, `ValueObjectReader`, explicit `encode_value` / `read_value` | Codec and portable State object ports |
| `xolotl-storage-fs/value-workspace` | `FileKeyStore` for keys exceeding the resident budget | Tokio file I/O; no CBOR dependency |

These components are independent of the SDK's minimal dependency tree. The
value-object crate without features exposes only explicit encoding descriptors.
Object ports can be static implementations or the optional host `ObjectStore`,
which implements the same GAT traits and forwards only its installed capabilities.

## One Logical Grammar

A document contains recorded taint followed by exactly one value. `Begin` and
`End` delimit collections and fields; `Atom` carries fixed-size values and
metadata; `Data` borrows fragments of strings, bytes and map keys. Every existing
Value variant is represented, including tensor dimensions, frame timestamps,
stream errors, and the exact bits of floating-point values. Taint source order
and duplicates are preserved as recorded data.

UTF-8 validation crosses chunk boundaries. The same incremental identifier
rules validate ordinary Paths and structured path fields. Map keys must be
unique and strictly increasing in UTF-8 byte order. The pure validator retains
only open frames and key identities; creation, prefix comparison, append and
release are explicit workspace effects. Only one event transaction is active.

`MemoryKeyOptions` selects page size and optional active-key and reserved-data
budgets. Pages avoid copying entire growing keys, and comparisons index pages
directly. Reserved bytes include unused page tails; map and directory metadata
are additional. Releasing a key frees its pages immediately. For larger keys,
`FileKeyStore` rereads fixed windows from an isolated temporary directory. Its
active-key budget is independent of key length, and each session has one async
worker with a one-request queue. Release waits for file removal; Drop closes the
queue and leaves ongoing I/O and cleanup owned by that worker. `close().await`
observes cleanup completion. Runtime shutdown or process failure can leave
unpublished workspace directories, so hosts manage retention in an isolated root.

An optional frame budget limits simultaneous nesting, not total bytes or items.
CBOR Data records are at most `u32::MAX` bytes; larger fields use multiple records.
Wire offsets and logical lengths use `u64`. Neither record sizes nor I/O windows
define a cumulative task limit.

## Explicit Materialization

`ValueBuilder` consumes events through the same Validator and the sequential
collection builders. `End(Document)` seals the candidate; consuming `finish()`
publishes it after the caller has confirmed actual source EOF. An error drops
all partial fields, collections and keys, and closes the builder. Completed
source claims remain available through `observed_taint()` as failure evidence.
Its default has no total byte, node or depth limit. A caller choosing to retain
a complete value can set independent materialization admission:

```rust
use xolotl_types::value::event::{MaterializationLimits, ValueBuilder};

let mut builder = ValueBuilder::new(MaterializationLimits {
    max_payload_bytes: Some(64 * 1024 * 1024),
    max_nodes: Some(1_000_000),
    max_frames: None,
});
// Feed validated or unvalidated events through builder.push(event)?;
// After actual source EOF, consume builder.finish()?;
```

These budgets count retained logical payload, semantic nodes and active frames;
they do not estimate allocator overhead or process RSS. Event consumers that
do not need a resident value can process and discard fragments directly.

## Owned Publication And Consumption

For a completed `TaintedValue`, `encode_value` borrows its payload and sources.
General event sources use `ValueObjectWriter::begin` with initially known
provenance and then `write(event, &event_sources)`. Actual sources are observed
before validation and I/O, including on rejected events and cancelled writes.
Consecutive events share the caller's scratch buffer. Full windows apply
backpressure through acknowledged writes, and `flush()` sends a partial window
without ending the document. `finish(&final_taint)` validates source EOF, drains
the closing envelope, acknowledges the final window, and commits with initial
and subsequently observed sources together. A returned descriptor requires
published metadata covering those sources; missing metadata labels are an error.

`ObjectWrite::commit_upload` freezes content and effective provenance after
repairable preflight checks and before publication I/O. A sealed upload rejects
further writes. Retrying a live sealed upload requires the same source set;
source order and duplicate labels do not change that set. Deduplication unions
stored sources before returning canonical metadata. Successfully delivered
upload identities may retire; callers retain the committed reference.

Errors or cancellation after the first poll close the entire owner and release
its workspace and private upload lease. Dropping unpolled write or flush futures
leaves the owner usable. A cancelled commit can have an uncertain published
outcome; the writer does not delete shared content as compensation. `WriteFailure`
and `ReadFailure` pair a structured error with observed sources. Reader and
writer owners also expose observed provenance after a cancelled polled future.

The result contains an `EncodedValueRef { blob, encoding }` and publication
taint. The encoding is explicit: MIME is descriptive and may reflect earlier
deduplicated content. A descriptor, content hash or recorded taint confers no
read authority. A host authorizes disclosure before issuing an existing Gateway
object-read grant over the backing blob.

`Decoder::decode` borrows each input window through semantic acceptance. Consume
the reported prefix, process the returned event, and offer any remaining suffix.
`DecodeStatus::End` marks the envelope boundary. Only `finish()` after actual
successful source EOF confirms a complete document. Keep derived results
unpublished until that point, and include opening object metadata and every read
chunk's actual provenance. Wire lineage alone is not trusted input provenance.

`ValueObjectReader::open` checks exact canonical metadata through an explicitly
supplied read port. `next_event()` borrows one scratch window and returns tentative
events with observed sources. Only validated object EOF produces `None` and
makes a private `ReadReceipt` available through `finish()`. The receipt proves
document validation, not disclosure authority or continued object retention.
`read_value` composes this reader with a private `ValueBuilder`, publishing only
after the receipt. Success and failure retain actual read sources and completed
wire claims; nested content references remain descriptors.

`copy_value(reader, writer)` takes both configured owners and forwards each event
with its actual sources. It obtains the reader's EOF receipt before committing
the writer. Failures preserve observations from both ports; cancellation drops
both workspaces and any unpublished staging. `encode_failure` borrows a typed
`Failure` and encodes its complete externally tagged layout through the same
cursor/writer, without formatting a diagnostic string or building a temporary map.

`EncodedValueRef::into_value` and `try_from_value` define the exact protocol map
`{ encoding: "xolotl.value.cbor.v1", blob: <typed Blob> }`. Extra fields, unknown
encodings and untyped references are rejected. A map with this shape remains an
ordinary map when encoded; no kernel path dereferences it automatically.

The independent `xolotl-standard/value-objects` feature exposes
`install_value_objects(boot, objects, config, make_keys)`. It installs
`effect://value/read` and `effect://value/write` only for supplied capabilities.
Each call owns its configured I/O window and asynchronously created key workspace;
installation starts no workers or buffers. `ValueObjectConfig` separates the I/O
window, write record policy and read materialization policy. `memory_key_factory`
provides resident key pages; a host can inject a file workspace without making
filesystem storage or the full Standard provider set mandatory. Read explicitly
materializes one validated document; consumers needing bounded payload retention
use `ValueObjectReader` events directly. All failure paths retain observed sources.

Encoding-byte hashes vary with legal chunk boundaries and do not replace semantic
value hashes. Resuming an arbitrary byte range requires parser checkpoints or an
index. Whole-document provenance accumulates for that document; independent
stream messages do not require retaining the sources of previously released
messages.
