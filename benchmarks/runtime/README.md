# Runtime resource measurements

This unpublished package measures the runtime's control, resident values,
execution, streams, provider parsing, objects, and State/Fact representation paths.
Every case checks its output and releases its workload-owned data before returning. It is
independent of the SDK dependency graph; `dhat` is an optional dependency of this
measurement package only.

Each process runs one case in one measurement mode and emits one JSON report to
stdout. Use the repository's pinned Rust toolchain. Record `rustc -Vv`, the source
revision, enabled features, CPU model, operating system, and filesystem alongside
the report when comparing runs. The report itself includes every workload
parameter, architecture, operating system, and measurement mode.

## Build and run

The standard-library Python runner builds and preserves separate release
executables, then runs each group serially. From the repository root:

```sh
python3 benchmarks/runtime/measure.py build --output target/runtime-measurements
python3 benchmarks/runtime/measure.py smoke --output target/runtime-measurements
python3 benchmarks/runtime/measure.py time --output target/runtime-measurements
python3 benchmarks/runtime/measure.py heap scaling --output target/runtime-measurements
```

`--output` defaults to `target/runtime-measurements`. The build uses
`CARGO_INCREMENTAL=0`, `--release --offline --locked`, and the shared `target`
directory, copying each executable before building the other mode. Complete
workspace checks before building; avoid concurrent Cargo commands and CPU-heavy
work while measuring. The runner requires Python 3.9 or later and a POSIX host.
Build and measure in the same execution environment, including its filesystem
mount namespace. The provider fixture requires local loopback sockets.

Each output directory accepts one build and one attempt per group. Choose a new
directory to repeat measurements or after changing sources. `build.json` records
source, runner, toolchain, configuration, commands, and binary hashes at build
time. `environment.json` binds that build to the CPU, operating system, filesystem,
and runner protocol. The runner verifies this identity before and after every
group and refuses stale binaries or mixed sources. It never rewrites the
environment while appending groups. `results.json` includes only complete,
verified groups; each group's directory retains raw JSON, stderr, commands, and
status, including partial output after failure or interruption.

Workload processes receive `TMPDIR=<output>/workload-tmp`, so file-object
measurements use the chosen output filesystem. The environment records that
directory and its `findmnt` description when available. Choose `--output` on the
disk or tmpfs you intend to measure. Direct executable invocations below use the
caller's temporary-directory environment instead.
The runner also sets both `NO_PROXY` and `no_proxy` to
`127.0.0.1,localhost,::1` for workload processes, keeping the provider fixture's
HTTP requests on loopback even when the caller has configured a proxy.

Build separate binaries so an instrumented executable cannot replace the timing
binary. Run Cargo commands from the repository root:

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

The timing build rejects heap mode. The heap build rejects timing mode because
allocation instrumentation changes execution cost. Heap profiling uses the
`dhat` allocator; this package contains no custom allocator or unsafe code.

Heap mode optionally accepts `--heap-file PATH` to save a DHAT profile with full
allocation stacks, including allocations first made during fixture/runtime
teardown. The default uses DHAT's testing mode and writes only the aggregate JSON
report. The diagnostic option preserves all measurement boundaries and also
writes the aggregate report; full stacks increase profiling overhead. Create the
profile's parent directory before running. For symbolized diagnosis, build with
debug information:

```sh
cargo build --locked -p xolotl-runtime-bench --features heap-profile \
  --target-dir target/runtime-heap-debug
target/runtime-heap-debug/debug/xolotl-runtime-bench \
  --case core --mode heap --samples 1 --warmup 1 --work 1000000 \
  --heap-file target/runtime-heap-debug/core-heap.json
```

The saved DHAT file spans the complete profiling interval through teardown. Its
total and peak fields therefore need not equal the aggregate report's totals and
peaks, which are captured immediately after the measured samples. The final live
fields in the aggregate report also observe teardown.

Run each case in a fresh process. This smoke matrix validates the cases with
small inputs; it does not establish representative throughput:

```sh
for case in core resident portable hosted stream stream-cancel object-file state-fact provider-stream; do
  target/runtime-time/release/xolotl-runtime-bench \
    --case "$case" --mode time --samples 2 --warmup 1 \
    --work 1024 --width 128 --depth 128 --window 4096
done

for case in core resident portable hosted stream stream-cancel object-file state-fact provider-stream; do
  target/runtime-heap/release/xolotl-runtime-bench \
    --case "$case" --mode heap --samples 2 --warmup 1 \
    --work 1024 --width 128 --depth 128 --window 4096
done
```

## Workloads and their boundaries

| Case | Measured work per sample | Parameters used |
| --- | --- | --- |
| `core` | Fixed stack storage, scalar values, exactly the requested ordinary control transitions, then cancellation. Heap mode fails if this case allocates. | `work` |
| `resident` | Construct a wide list sharing one 1 KiB payload; copy and update one entry; construct and clone a deep chain; encode/restore a 24-level binary shared DAG with the lossless graph codec; check sharing and release all roots. | `width`, `depth` |
| `portable` | Execute a prepared input/fork/input/projection program through `LinkedExecution`, with fixed caller-owned control buffers and a concrete immediate transform driver. | `width` |
| `hosted` | Execute the same prepared program through the hosted `Executor`; check the same resident output identity and provenance. | `width` |
| `stream` | Transfer numbered scalar chunks through one real leased credit, hold selected receive leases across a yield or delay, then validate terminal and EOF and release the channel. | `work`, `window`, `slow-every`, `delay-micros` |
| `stream-cancel` | Perform the same transfer, then fill the sole credit, verify another send is pending, drop the receiver, and verify the blocked sender wakes with failure. The two cancellation setup sends are additional work. | `work`, `window`, `slow-every`, `delay-micros` |
| `object-file` | Incrementally encode bytes into a filesystem value object, commit, decode through EOF with a reused scratch buffer, validate content, delete the object, and check no uploads remain. | `work`, `window` |
| `state-fact` | Write/read a shared value with provenance in in-memory State, losslessly encode/restore a Fact whose input and outcome share one root, write/read the restored root, and delete State data. History is disabled. | `width` |
| `provider-stream` | Invoke an HTTP Responses provider through the public Standard installation and an admitted DataPlane stream; selectively parse a response with a large ignored completion snapshot, validate selected output, provenance and usage, consume the terminal result and channel EOF, and release the request and its loopback server. | `work`, `window` |

The portable and hosted cases create identical fresh inputs and execution storage
inside each sample. Source compilation, prepared programs, and the hosted
Bootstrap are fixtures created before measurement. These cases compare prepared
execution; they do not include cold startup.

The object case uses one upload and one filesystem job at a time, two explicit
window-sized buffers, and the store's own bounded transfer buffers. Total logical
bytes may be much larger than the window. This case exercises a byte value, so
map-key workspace and numeric tensor semantics require separate measurements.
Filesystem caching and sync behavior affect timing. The State/Fact case measures
in-memory State and representation restoration; it does not measure durable
checkpoint recovery, a Fact database, or disk State.

Stream samples retain one credit regardless of cumulative chunk count. The
receiver explicitly checks every sequence number. A zero delay still yields while
holding the lease; a positive delay includes the Tokio timer and OS scheduling
cost. The `window` is the maximum inline bytes on that credit, not a cumulative
stream-size bound.

The provider case uses `Bootstrap::open_for` and
`Kernel::data_plane().execute_with_stream` under an attenuated request grant. The
server sends the fixed text delta `ok`, usage of 5 input tokens and 7 output tokens,
and `work` bytes of ignored completion snapshot data. Its declared work counts
those ignored payload bytes, excluding HTTP/SSE framing and selected output. The
listener, immutable State declarations, resource name, compiled request grant,
and Standard module configuration are fixtures created before the samples.

Each provider sample creates and releases its own State, Bootstrap, Standard
installation, provider routing, HTTP client, request, and output. Fixed host setup,
a real loopback request, selective parsing, validation, and stream/socket/host
release are included. Validation checks the exact text, `ModelOutput` provenance,
usage, terminal result, channel EOF, recorded Fact, finalized and reaped request, and
release of shared stream, handle-table and Fact-store owners. No State or Fact
history is retained across samples. The parser I/O and server emission buffers
use the fixed `window`, and the output channel has one credit. HTTP transport
buffers have their own capacities; this window is not a complete-path heap cap. Selected output
does not grow with the ignored snapshot; the response selector has budgets of
4 materialized bytes, 8 materialized nodes and 16 JSON frames. The fixture validates
one fixed `prompt` request with 16 KiB header and body budgets, and each sample has
a 60-second watchdog. These fixture guards define this measurement workload.

Provider heap measurements include the real client, parser, runtime, and bounded
loopback fixture in the same process. They do not isolate parser allocations from
HTTP or server costs. The runner scales the ignored payload through 64 KiB, 1 MiB,
and 16 MiB while keeping the window at 4 KiB. These measurements exercise local
processing and memory scaling; they do not measure an external API, model
inference, or network service latency. `slow-every` and `delay-micros` apply only
to the channel stream cases.

## Measurement semantics

All modes create a current-thread Tokio runtime and the case fixture first, then
run `warmup` complete samples. Synchronous Core and resident workloads run directly;
asynchronous cases pass their own future to `Runtime::block_on`. Dispatch happens
before future construction, so an unrelated case cannot cause Tokio to box the
selected workload's future. Core measurements do not enter Tokio.
Every measured sample constructs, runs, validates, and drops its workload-owned
data. Immutable fixtures persist between samples.

Each timing sample measures one complete workload run. The report contains the
sample count, total measured duration, throughput, and nearest-rank p50/p95/p99
in nanoseconds; individual sample durations are not retained. The runner uses
30 samples in its timing group; the executable defaults to 20. In either case,
p99 is the observed maximum. These are **whole-workload latencies**; they are not per-event,
per-token, or production request tail latencies. Throughput
is the total declared work units divided by the sum of measured durations. Output
serialization, latency sorting, and fixture/runtime teardown are outside timing.

The heap report starts `dhat` after fixture creation and warmup. Its counts are
**incremental heap allocations after warmup**, excluding allocations that already
belong to the fixture, runtime, or input configuration. It reports:

- `total_allocations` and `total_allocated_bytes` across the measured samples;
- `peak_live_bytes` and the number of live allocations at that byte peak;
- live allocations and bytes immediately after the measured samples;
- live allocations and bytes after dropping the fixture and runtime.

The total and peak fields stop at the end of the samples. The final live fields
also observe teardown. Measurements include validation work in the case. The
profiler's own bookkeeping is excluded by `dhat`. No heap report is a measurement
of total process RSS, allocator fragmentation, stack usage, mapped files, or a
device's complete memory footprint. A nonzero final live field warrants inspection
of retained owners or library caches; the JSON does not automatically label it a
leak. Semantic release checks run in both modes.

## Scaling checks

Increase cumulative work while holding the active window constant and use one
sample per heap process to compare peaks. For example:

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

Compare portable and hosted execution with equal `width`, `samples`, and `warmup`.
Vary resident `width` and `depth` separately to identify directory and nesting
costs. A longer stream is expected to perform more cumulative allocations where
the adapter allocates per event; bounded active memory concerns the peak and
released owners, not a constant lifetime allocation count.

Default parameters are `samples=20`, `warmup=1`, `work=1000000`, `width=8192`,
`depth=12000`, `window=4096`, `slow-every=64`, and `delay-micros=0`. Cases only use
the parameters listed in the table. Counts and dimensions must be nonzero;
`warmup` and `delay-micros` may be zero. The defaults are reproducible inputs,
not recommended production limits.
