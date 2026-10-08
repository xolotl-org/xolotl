# Runtime resource measurements

## Native Gateway evidence lookup example

`gateway_evidence_lookup` separately measures real `Gateway::lookup_request`
and `Gateway::read_retained_request_result` calls against
an explicitly selected memory or redb request-evidence store. A hosted
`Bootstrap`/`KernelBuilder` installs a unary `EchoDriver`; a bearer Profile maps
the principal to an identity, registers and validates the host authority, and
authorizes the Echo surface. The fixture submits one keyed string value using
its original discovered scope and epoch, then queries that same identity.
Every lookup must be `Settled` with unchanged original acceptance, terminal
class and unresolved effects. Each retained-result read must preserve the complete
`ExecutionOutput`, including provenance, and report a cached completion origin.
Returned summaries and results are dropped after verification; no output object
is reused between queries. Request-store usage, namespace and
epoch must remain unchanged. This is not a synthetic record-decoder benchmark.

```sh
cargo build --release --locked --offline -p xolotl-runtime-bench \
  --example gateway_evidence_lookup
artifacts=$(mktemp -d "$PWD/target/gateway-evidence-lookup.XXXXXX")
/usr/bin/time -v -o "$artifacts/memory.time" \
  target/release/examples/gateway_evidence_lookup \
  --backend memory --events 5000 --payload-bytes 1024 > "$artifacts/memory.json"
/usr/bin/time -v -o "$artifacts/redb.time" \
  target/release/examples/gateway_evidence_lookup \
  --backend redb --db "$artifacts/requests.redb" \
  --events 5000 --payload-bytes 65536 > "$artifacts/redb.json"
sha256sum target/release/examples/gateway_evidence_lookup \
  benchmarks/runtime/examples/gateway_evidence_lookup.rs
```

Both backends also rebuild the live Kernel and Gateway and verify lookup with
the original identity and scope. Memory retains the same store owner: this is
reattachment, not persistence across owner loss. Redb releases the Gateway and
all database owners before reopening the same file and verifying namespace,
scope, result, usage and epoch. Neither case resumes execution across restart.
The redb path must have an existing canonical parent under the workspace
`target`, must not resolve under `/tmp`, and is exclusively created (0600 on Unix) without
overwriting an existing file or symlink. Failed runs may leave their new file;
choose another new path rather than reusing it.

`--events` is bounded to 1..=1,000,000 and `--payload-bytes` to 1..=65,536;
defaults are 5000 and 1024. Only `u64` nanosecond samples are accumulated, at
most 16,000,000 bytes across both sample arrays (not a process RSS budget). The fixture
retains one original result for comparison and one store record. JSON reports
nearest-rank p50/p95 and the sum of durations separately for summary lookup and
retained-result reading, plus the full interleaved loop time, parameters and
verification flags. Each timing includes identity cloning
and the awaited native call, but excludes comparison, result drop, sample
sorting, JSON output, initial submission and reopen verification. Loop time
also includes comparison, result release and sample collection. `/usr/bin/time`
peak RSS covers the entire process, including setup, retained fixture, samples,
database mappings and reopen; it does not isolate lookup allocations. These
measurements establish neither a speedup nor network throughput or an RSS limit.

This unpublished package measures the runtime's control, resident values, execution, warmed Executor preparation, streams, provider parsing, objects, State/Fact representation, bounded Source fingerprints, borrowed Plan compilation, and memory consolidation. Every case checks its result and releases sample-owned data before returning. It is independent of the SDK dependency graph; `dhat` is an optional dependency of this measurement package only.

Each process runs one case in one measurement mode and emits one JSON report to stdout. Use the repository's pinned Rust toolchain. Record `rustc -Vv`, the source revision, enabled features, CPU model, operating system, and filesystem alongside the report when comparing runs. The report itself includes every workload parameter, architecture, operating system, and measurement mode.

## Build and run

The standard-library Python runner builds and preserves separate release executables, then runs each group serially. From the repository root:

```sh
python3 benchmarks/runtime/measure.py build --output target/runtime-measurements
python3 benchmarks/runtime/measure.py smoke --output target/runtime-measurements
python3 benchmarks/runtime/measure.py time --output target/runtime-measurements
python3 benchmarks/runtime/measure.py heap scaling --output target/runtime-measurements
```

`--output` defaults to `target/runtime-measurements`. The build uses `CARGO_INCREMENTAL=0`, `--release --offline --locked`, and the shared `target` directory, copying each executable before building the other mode. Complete workspace checks before building; avoid concurrent Cargo commands and CPU-heavy work while measuring. The runner requires Python 3.9 or later and a POSIX host. Build and measure in the same execution environment, including its filesystem mount namespace. The provider fixture requires local loopback sockets.

Each output directory accepts one build and one attempt per group. Choose a new directory to repeat measurements or after changing sources. `build.json` records source, runner, toolchain, configuration, commands, and binary hashes at build time. `environment.json` binds that build to the CPU, operating system, filesystem, and runner protocol. The runner verifies this identity before and after every group and refuses stale binaries or mixed sources. It never rewrites the environment while appending groups. `results.json` includes only complete, verified groups; each group's directory retains raw JSON, stderr, commands, and status, including partial output after failure or interruption.

Workload processes receive `TMPDIR=<output>/workload-tmp`, so file-object measurements use the chosen output filesystem. The environment records that directory and its `findmnt` description when available. Choose `--output` on the disk or tmpfs you intend to measure. Direct executable invocations below use the caller's temporary-directory environment instead. The runner also sets both `NO_PROXY` and `no_proxy` to `127.0.0.1,localhost,::1` for workload processes, keeping the provider fixture's HTTP requests on loopback even when the caller has configured a proxy.

Build separate binaries so an instrumented executable cannot replace the timing binary. Run Cargo commands from the repository root:

```sh
cargo build --locked --release -p xolotl-runtime-bench \
  --target-dir target/runtime-time
cargo build --locked --release -p xolotl-runtime-bench --features heap-profile \
  --target-dir target/runtime-heap

target/runtime-time/release/xolotl-runtime-bench --list
target/runtime-time/release/xolotl-runtime-bench \
  --case core --mode time --samples 20 --warmup 1 --work 1000000
target/runtime-heap/release/xolotl-runtime-bench \
  --case core --mode heap --samples 1 --warmup 1 --work 1000000
```

The timing build rejects heap mode. The heap build rejects timing mode because allocation instrumentation changes execution cost. Heap profiling uses the `dhat` allocator; this package contains no custom allocator or unsafe code.

Heap mode optionally accepts `--heap-file PATH` to save a DHAT profile with full allocation stacks, including allocations first made during fixture/runtime teardown. The default uses DHAT's testing mode and writes only the aggregate JSON report. The diagnostic option preserves all measurement boundaries and also writes the aggregate report; full stacks increase profiling overhead. Create the profile's parent directory before running. For symbolized diagnosis, build with debug information:

```sh
cargo build --locked -p xolotl-runtime-bench --features heap-profile \
  --target-dir target/runtime-heap-debug
target/runtime-heap-debug/debug/xolotl-runtime-bench \
  --case core --mode heap --samples 1 --warmup 1 --work 1000000 \
  --heap-file target/runtime-heap-debug/core-heap.json
```

The saved DHAT file spans the complete profiling interval through teardown. Its total and peak fields therefore need not equal the aggregate report's totals and peaks, which are captured immediately after the measured samples. The final live fields in the aggregate report also observe teardown.

Run each case in a fresh process. This smoke matrix validates the cases with small inputs; it does not establish representative throughput:

```sh
for case in core resident executor-prepare portable hosted stream stream-cancel object-file state-fact provider-stream; do
  target/runtime-time/release/xolotl-runtime-bench \
    --case "$case" --mode time --samples 2 --warmup 1 \
    --work 1024 --width 128 --depth 128 --window 4096
done

for case in core resident executor-prepare portable hosted stream stream-cancel object-file state-fact provider-stream; do
  target/runtime-heap/release/xolotl-runtime-bench \
    --case "$case" --mode heap --samples 2 --warmup 1 \
    --work 1024 --width 128 --depth 128 --window 4096
done
```

## Sustained State overwrite and file growth

`examples/state_growth.rs` is a separate Linux-only release workload for a fresh redb database. It uses the public `RedbStore` State adapter, commits one `Set` per write to a fixed set of keys, changes the first eight payload bytes on every write, verifies the final value of every key, closes and reopens the database, and verifies again. In `full` mode it also counts all history rows through bounded pages. It does not use DHAT or the sampling runner above.

```sh
cargo build --release --locked -p xolotl-runtime-bench --example state_growth
mkdir -p target/state-growth-sample
target/release/examples/state_growth \
  --db target/state-growth-sample/current.redb --history current_only \
  --writes 8000 --keys 64 --payload-bytes 256 --report-every 1000 \
  > target/state-growth-sample/current.jsonl
target/release/examples/state_growth \
  --db target/state-growth-sample/full.redb --history full \
  --writes 8000 --keys 64 --payload-bytes 256 --report-every 1000 \
  > target/state-growth-sample/full.jsonl
```

Each database path must be new. Run the two modes as separate processes on the same filesystem and keep their raw JSONL files. The first record states every parameter; `checkpoint` records report completed writes, cumulative write-loop time, logical payload bytes, Linux `VmRSS`/`VmHWM`, database file length, and the change in `/proc/self/io` `write_bytes` since database opening. The final `verified` record confirms reopening, current key count, and (for `full`) history row count. A failed write or validation stops the process with a nonzero exit code, preserving earlier samples in the JSONL file.

RSS includes mapped pages and the allocator; file length reports the redb file, not live logical records or disk blocks. The process I/O counter can also include report output and filesystem work outside redb; its ratio to logical payload bytes is only a coarse whole-process write-cost indicator. Sampling and value construction are part of the workload, but `write_elapsed_ms` excludes sampling, verification, startup, and reopening. A short single-writer run cannot establish a long-term RSS or file-size bound, concurrent throughput, or device-level write amplification. Record `rustc -Vv`, filesystem and mount options, CPU, source revision, feature set, and other load with the raw samples.

## Sustained Source stream churn

`examples/source_churn.rs` is a separate Linux-only workload using the public redb Source and State adapters. It creates one installation, one Source projection, and one reusable stream name. Each cycle inspects the retired stream, opens a new stream epoch, commits one accepted ordered event with a unique event and claim ID, then retires the stream. The sink is a State list with `DropOldest` capacity 16; State history uses the default current-only mode. The adapter is configured with a one-active-stream quota, so a leaked active position should stop a later open. This workload does not involve a Gateway connection, driver execution, network transport, or concurrent clients.

```sh
cargo build --release --locked -p xolotl-runtime-bench --example source_churn
mkdir -p target/source-churn-sample
target/release/examples/source_churn \
  --db target/source-churn-sample/run.redb \
  --cycles 100000 --report-every 1000 \
  > target/source-churn-sample/run.jsonl
```

The database path must be new. Put it on the filesystem being measured, and keep the complete JSONL output. At each report boundary the workload runs private Source maintenance in batches of at most 64 examined rows until it reaches the end, then checks the retired stream and bounded sink. The cumulative `churn_elapsed_ms` measures the Open/Commit/Retire loops, including their pre-open inspection and validation; `maintenance_elapsed_ms` measures only the maintenance loop. Both exclude checkpoint sampling, startup, installation, database reopening, and the final verification. Every `checkpoint` also reports removed and examined private rows, stream revision and epoch, Linux `VmRSS` and `VmHWM`, redb file length, and the change in `/proc/self/io/write_bytes` since opening. The final `verified` record follows database close and reopen, checks the sink and retired stream, then opens and retires one more epoch to verify that capacity is reusable. An error exits nonzero and leaves earlier JSONL records available for diagnosis.

RSS includes allocator and mapped pages; redb file length is not a count of live records or disk blocks. The process write counter may include unrelated process writes and may remain zero on tmpfs, so it is not device-level write amplification. The example uses a synthetic, advancing event clock and periodic maintenance; results do not describe real event arrival timing, unbounded sink payloads, a `Full` State history, concurrent ingress, crash recovery, or indefinite steady-state memory and file size. Record the exact source revision or executable hash, toolchain, CPU, filesystem, mount options, and other load with any comparison.

## Gateway request evidence

`examples/gateway_request_growth.rs` measures the memory or redb request store,
not protocol submission or Driver execution. Each event reserves, completes,
observes and retires one identity; retained fingerprints intentionally grow.
The report separates those awaited operations, logical charges and Linux RSS.
The final check verifies retained evidence, refusal to redispatch a retired
identity, and stable ledger namespace, including redb reopen. This is not a
measurement of indefinite steady-state retention or the request-scope guard.
Use `--help` for workload parameters; redb requires a new disk-backed path under
the workspace `target/` directory.

## Growing Source sink

`examples/source_sink_growth.rs` measures sequential unordered Source commits into one State List. Set `capacity >= events` to grow the list throughout the run, or a small capacity to measure steady `DropOldest` replacement. It reports each batch's commit time, current sink length, Linux RSS/high-water mark, redb file length, and process write-byte delta. It closes and reopens the database to verify the final list. Use a new database path for each run:

```sh
cargo build --release --offline --locked -p xolotl-runtime-bench --example source_sink_growth
target/release/examples/source_sink_growth \
  --db /tmp/source-sink-growth-new.redb \
  --events 2048 --capacity 2048 --payload-bytes 1024 --report-every 256
```

The loop measures payload construction and commits; it excludes checkpoint reads, reporting, installation, and reopening. The process counter is not a redb-only or device write count. Compare equal event counts at `capacity=16` and `capacity=events` to isolate the current sink size; this case does not measure concurrent ingress or full State history.

## Workloads and their boundaries

| Case | Measured work per sample | Parameters used |
| --- | --- | --- |
| `core` | Fixed stack storage, scalar values, exactly the requested ordinary control transitions, then cancellation. Heap mode fails if this case allocates. | `work` |
| `resident` | Construct a wide list sharing one 1 KiB payload; copy and update one entry; construct and clone a deep chain; encode/restore a 24-level binary shared DAG with the lossless graph codec; check sharing and release all roots. | `width`, `depth` |
| `executor-prepare` | Call `Executor::prepare_operation` exactly `work` times with the same Executor, `OperationTemplate`, and already valid handle. The fixture registers `width` real effects and prepares each once before measurement. No Driver method executes. | `work`, `width` |
| `portable` | Execute a prepared input/fork/input/projection program through `LinkedExecution`, with fixed caller-owned control buffers and a concrete immediate transform driver. | `width` |
| `hosted` | Execute the same prepared program through the hosted `Executor`; check the same resident output identity and provenance. | `width` |
| `stream` | Transfer numbered scalar chunks through one real leased credit, hold selected receive leases across a yield or delay, then validate terminal and EOF and release the channel. | `work`, `window`, `slow-every`, `delay-micros` |
| `stream-cancel` | Perform the same transfer, then fill the sole credit, verify another send is pending, drop the receiver, and verify the blocked sender wakes with failure. The two cancellation setup sends are additional work. | `work`, `window`, `slow-every`, `delay-micros` |
| `object-file` | Incrementally encode bytes into a filesystem value object, commit, decode through EOF with a reused scratch buffer, validate content, delete the object, and check no uploads remain. | `work`, `window` |
| `state-fact` | Write/read a shared value with provenance in in-memory State, losslessly encode/restore a Fact whose input and outcome share one root, write/read the restored root, and delete State data. History is disabled. | `width` |
| `provider-stream` | Invoke an HTTP Responses provider through the public Standard installation and an admitted DataPlane stream; selectively parse a response with a large ignored completion snapshot, validate selected output, provenance and usage, consume the terminal result and channel EOF, and release the request and its loopback server. | `work`, `window` |
| `source-fingerprint` | Hash the bounded tagged encoding of a list sharing one 16 KiB byte value, checking exact byte count and stable digest against the fixture reference on every call. | `work`, `width`, `window` |
| `source-fingerprint-deep-reject` | Check `None` from bounded fingerprinting of a nested single-child list chain. | `work`, `depth`, `window` |
| `source-fingerprint-wide-reject` | Check `None` from bounded fingerprinting of a wide scalar list. | `work`, `width`, `window` |
| `source-fingerprint-shared-reject` | Check `None` from bounded fingerprinting of a list sharing one 16 KiB byte value. Edges are charged even when payload ownership is shared. | `work`, `width`, `window` |
| `plan-compile` | Compile a borrowed Plan of sequential scalar literals inside identity wrappers; iteratively validate every wrapper, generated sequence name, and literal, then release the output. | `work`, `width`, `depth` |
| `plan-compile-reject` | Compile a borrowed Plan that exceeds default compiler capacity, checking `PlanError::Capacity` on every call. | `work`, `width`, `depth` |
| `memory-consolidate` | Repeat public Kernel calls into installed Standard memory consolidation, check each returned count is zero, release each output, and verify the final namespace still contains exactly its working records and no summaries. | `work`, `width`, `depth` |

### Bounded fingerprints and compilation

These cases use `work` as the number of independent calls per sample, not source nodes or encoded bytes. Fixtures and their initial acceptance/rejection checks are outside timing and DHAT sample boundaries; every measured call checks its result. The accepted fingerprint fixture separately measures its canonical tagged encoding length and obtains a reference digest before measurement. Rejection fixtures must actually reject, and admitted fixtures must actually succeed; an accidental outcome change fails the run rather than being published as a faster sample.

Source `window` is the fingerprint work/exact-encoding budget in bytes. `None` can mean either predescent work cutoff or exact writer cutoff, so these cases do not infer which stage rejected. The default rejection fixtures are a 65,536-level chain, 65,536 scalar edges, and 65,536 shared edges at a fixed 1 KiB budget. The accepted fixture is 64 references to one 16 KiB byte value at a 1 MiB budget. Source values are built once; samples measure fingerprint indexing, bounded encoding/hashing, checks, and scratch release, not Source mutation, durable storage, or payload construction.

Plan samples borrow the resident source and use fixed default `CompileLimits`: 1 MiB compact source, 65,536 output `DoNode` nodes, and nesting depth 128. The admitted fixture defaults to 64 literal steps under four identity wrappers; the rejected fixture has one literal under 129 wrappers. Output validation is iterative and allocates no validation stack. Source construction/deserialization and caller-owned AST destruction are not compiler work. Fixture teardown releases that source separately; an encoded-byte or node budget is not an RSS limit.

Default `work` is 100 for accepted fingerprints, 1000 for rejected fingerprints, and 32 for either Plan case. Smoke uses two calls per bounded sample. The scaling group repeats each fixed fixture at `work=1,16,256`, keeping its admission budget and dimensions constant. Compare cumulative allocation totals, peak live bytes, released owners, and whole-process RSS; more completed calls may increase total allocations without increasing active scratch. These workloads establish absolute costs for their stated boundaries, not an unmeasured speedup or a general process-memory guarantee.

### Public memory consolidation

`memory-consolidate` installs only Standard's public Memory module with the offline `EchoBackend` and an in-memory State backend with history disabled. Setup uses real Kernel `store` calls to seed one namespace with `width` working records. Each record contains `depth` distinct whitespace-separated tokens of the form `r<record>w<word>`; words are disjoint across records. These are nonempty eligible records, so consolidation traverses the pairwise comparisons, but no pair reaches the similarity threshold and no summaries should be written. Installation, seed embedding/indexing, initial handle opening, and initial fixture verification are outside measurement.

Defaults are `width=64`, `depth=8`, and `work=16`. Fixed public consolidation admission limits are 256 records, 1 MiB of lossless encoded records, and 64 KiB of projected text; they do not grow with `work`. Fixture admission additionally restricts `depth` to at most 32 words and rejects setup exceeding the fixed record/text limits. Timing and DHAT include operation construction and fresh execution identity allocation, input sharing, Kernel authorization/accounting, Standard namespace paging and bounded reads, encoded-record admission, text projection/tokenization, pairwise overlap comparisons and cooperative yields, per-call result checks, and output release. A final bounded namespace scan per sample verifies count, storage-key/record identity, exact seeded content, working tier, and nonsummary kind; handle and process counts must remain fixed. Fact recording is disabled, and calls return only count zero rather than retaining output history.

Smoke runs two real consolidation calls per sample. Timing/heap groups use the defaults, and scaling holds the 64-record namespace and all limits fixed while repeating `work=1,16,256`. This is an absolute end-to-end public-facade cost including validation, not an isolated text-comparison microbenchmark, model invocation cost, successful-summary write cost, or a speedup claim. Resident seeds and the installed embedding/index projection are fixtures excluded from DHAT sample allocation counts but included in the process RSS snapshot before teardown.

Every report includes Linux `process_memory` snapshots after fixture/warmup and after fixture/runtime teardown; other platforms report `null` snapshots. `resident_bytes` comes from `VmRSS` and `high_water_bytes` from `VmHWM`. Reads occur outside timed sample intervals and outside DHAT profiling. The process high-water mark includes setup, warmup, allocator retention, mapped pages, and profiling overhead; it is neither reset per sample nor an isolated compiler/fingerprint peak. DHAT sample peaks exclude already resident fixtures, whereas RSS includes them before teardown.

The portable and hosted cases create identical fresh inputs and execution storage inside each sample. Source compilation, prepared programs, and the hosted Bootstrap are fixtures created before measurement. These cases compare prepared execution; they do not include cold startup.

The `executor-prepare` fixture creates an in-memory `Bootstrap`, registers `width` effects through its public API, builds one root Executor, and prepares each effect once. Every measured sample then repeats one already prepared template on that same Executor. The sample includes method and handle cache lookup, handle ownership and rights checks, cancellation/deadline checks, and successful result validation by the case. It excludes resource registration, first metadata resolution, initial handle opening, actual invocation, Driver execution, and Fact recording. It is one defined preflight path, not an end-to-end Operation latency.

`--width` changes the number of warmed resource, method, and handle entries. The executable defaults this case to `width=1`; an explicit `--width` selects a larger fixture. The general runner also uses `width=1` and `work=10000` in its timing and heap groups. The heap profiler starts after fixture creation and warmup, so its live and peak fields **exclude the already resident cache and registry entries**. Changing width alone does not measure those entries' bytes; use a separately scoped resident-memory measurement before claiming cache footprint. This case's allocation totals measure only incremental work after warmup, including the selected preparation path and its validation.

For a focused same-build comparison, run the timing and heap executables with the same workload inputs:

```sh
target/runtime-time/release/xolotl-runtime-bench \
  --case executor-prepare --mode time --samples 20 --warmup 1 \
  --work 10000 --width 1
target/runtime-heap/release/xolotl-runtime-bench \
  --case executor-prepare --mode heap --samples 1 --warmup 1 \
  --work 10000 --width 1
```

The object case uses one upload and one filesystem job at a time, two explicit window-sized buffers, and the store's own bounded transfer buffers. Total logical bytes may be much larger than the window. This case exercises a byte value, so map-key workspace and numeric tensor semantics require separate measurements. Filesystem caching and sync behavior affect timing. The State/Fact case measures in-memory State and representation restoration; it does not measure durable checkpoint recovery, a Fact database, or disk State.

Stream samples retain one credit regardless of cumulative chunk count. The receiver explicitly checks every sequence number. A zero delay still yields while holding the lease; a positive delay includes the Tokio timer and OS scheduling cost. The `window` is the maximum inline bytes on that credit, not a cumulative stream-size bound.

The provider case uses `Bootstrap::open_for` and `Kernel::data_plane().execute_with_stream` under an attenuated request grant. The server sends the fixed text delta `ok`, usage of 5 input tokens and 7 output tokens, and `work` bytes of ignored completion snapshot data. Its declared work counts those ignored payload bytes, excluding HTTP/SSE framing and selected output. The listener, immutable State declarations, resource name, compiled request grant, and Standard module configuration are fixtures created before the samples.

Each provider sample creates and releases its own State, Bootstrap, Standard installation, provider routing, HTTP client, request, and output. Fixed host setup, a real loopback request, selective parsing, validation, and stream/socket/host release are included. Validation checks the exact text, `ModelOutput` provenance, usage, terminal result, channel EOF, recorded Fact, finalized and reaped request, and release of shared stream, handle-table and Fact-store owners. No State or Fact history is retained across samples. The parser I/O and server emission buffers use the fixed `window`, and the output channel has one credit. HTTP transport buffers have their own capacities; this window is not a complete-path heap cap. Selected output does not grow with the ignored snapshot; the response selector has budgets of 4 materialized bytes, 8 materialized nodes and 16 JSON frames. The fixture validates one fixed `prompt` request with 16 KiB header and body budgets, and each sample has a 60-second watchdog. These fixture guards define this measurement workload.

Provider heap measurements include the real client, parser, runtime, and bounded loopback fixture in the same process. They do not isolate parser allocations from HTTP or server costs. The runner scales the ignored payload through 64 KiB, 1 MiB, and 16 MiB while keeping the window at 4 KiB. These measurements exercise local processing and memory scaling; they do not measure an external API, model inference, or network service latency. `slow-every` and `delay-micros` apply only to the channel stream cases.

## Measurement semantics

All modes create a current-thread Tokio runtime and the case fixture first, then run `warmup` complete samples. Synchronous Core and resident workloads run directly; asynchronous cases pass their own future to `Runtime::block_on`. Dispatch happens before future construction, so an unrelated case cannot cause Tokio to box the selected workload's future. Core measurements do not enter Tokio. Every measured sample runs and validates its workload, then drops any sample-owned data. Fixtures persist between samples; the Executor preparation fixture's caches are populated before measurement and remain live through it.

Each timing sample measures one complete workload run. The report contains the sample count, total measured duration, throughput, and nearest-rank p50/p95/p99 in nanoseconds; individual sample durations are not retained. The runner uses 30 samples in its timing group; the executable defaults to 20. In either case, p99 is the observed maximum. These are **whole-workload latencies**; they are not per-event, per-token, or production request tail latencies. Throughput is the total declared work units divided by the sum of measured durations. Output serialization, latency sorting, and fixture/runtime teardown are outside timing.

The heap report starts `dhat` after fixture creation and warmup. Its counts are **incremental heap allocations after warmup**, excluding allocations that already belong to the fixture, runtime, or input configuration. It reports:

- `total_allocations` and `total_allocated_bytes` across the measured samples;
- `peak_live_bytes` and the number of live allocations at that byte peak;
- live allocations and bytes immediately after the measured samples;
- live allocations and bytes after dropping the fixture and runtime.

The total and peak fields stop at the end of the samples. The final live fields also observe teardown. Measurements include validation work in the case. The profiler's own bookkeeping is excluded by `dhat`. No heap report is a measurement of total process RSS, allocator fragmentation, stack usage, mapped files, or a device's complete memory footprint. A nonzero final live field warrants inspection of retained owners or library caches; the JSON does not automatically label it a leak. Semantic release checks run in both modes.

## Scaling checks

Increase cumulative work while holding the active window constant and use one sample per heap process to compare peaks. For example:

```sh
for work in 1000 100000 1000000; do
  target/runtime-heap/release/xolotl-runtime-bench \
    --case stream --mode heap --samples 1 --warmup 1 \
    --work "$work" --window 4096 --slow-every 64
done

for work in 65536 1048576 16777216; do
  target/runtime-heap/release/xolotl-runtime-bench \
    --case object-file --mode heap --samples 1 --warmup 1 \
    --work "$work" --window 4096
done

for work in 65536 1048576 16777216; do
  target/runtime-heap/release/xolotl-runtime-bench \
    --case provider-stream --mode heap --samples 1 --warmup 1 \
    --work "$work" --window 4096
done
```

Compare portable and hosted execution with equal `width`, `samples`, and `warmup`. Vary resident `width` and `depth` separately to identify directory and nesting costs. A longer stream is expected to perform more cumulative allocations where the adapter allocates per event; bounded active memory concerns the peak and released owners, not a constant lifetime allocation count.

Default parameters are `samples=20`, `warmup=1`, `work=1000000`, `width=8192`, `depth=12000`, `window=4096`, `slow-every=64`, and `delay-micros=0`, except the bounded fixtures described above. Cases only use the parameters listed in the table. Counts and dimensions must be nonzero; `warmup` and `delay-micros` may be zero. The defaults are reproducible inputs, not recommended production limits. `executor-prepare` defaults to `width=1` when `--width` is omitted.
