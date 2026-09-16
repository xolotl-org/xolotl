#!/usr/bin/env python3
"""Build and measure one immutable runtime-benchmark source snapshot.

Only Python's standard library is required. Each output directory belongs to one
build and at most one attempt at each measurement group. Failed attempts retain
their logs; choose another directory to rebuild or repeat a group.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RUNNER = Path(__file__).resolve()
LOADED_RUNNER_SHA256 = hashlib.sha256(RUNNER.read_bytes()).hexdigest()
PROTOCOL = "xolotl-runtime-measurements/v1"
CASES = (
    "core", "resident", "portable", "hosted", "stream", "stream-cancel",
    "object-file", "state-fact", "provider-stream",
)
GROUPS = ("smoke", "time", "heap", "scaling")
DEFAULTS = {
    "samples": 1, "warmup": 1, "work": 1_048_576, "width": 8192,
    "depth": 12000, "window": 4096, "slow_every": 64, "delay_micros": 0,
}


class MeasurementError(Exception):
    """An invalid build, environment, or workload result."""


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest_json(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    """Publish a complete manifest without truncating its previous version."""
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as out:
        temporary = Path(out.name)
        try:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path):
    try:
        with path.open() as source:
            return json.load(source)
    except (OSError, ValueError) as error:
        raise MeasurementError(f"cannot read {path}: {error}") from error


def command_text(command, optional=False):
    try:
        result = subprocess.run(
            command, cwd=REPO, capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        if optional:
            return None
        raise MeasurementError(f"metadata command {command!r} failed: {error}") from error


def source_snapshot():
    # Generated reports, build outputs, and documentation do not enter the
    # identity. Untracked Rust files and manifests do: this is a worktree hash.
    paths = {REPO / "Cargo.toml", REPO / "Cargo.lock", RUNNER}
    paths.update(path for name in ("rust-toolchain", "rust-toolchain.toml")
                 if (path := REPO / name).is_file())
    for root in (REPO / "crates", REPO / "benchmarks", REPO / "examples"):
        for directory, children, names in os.walk(root):
            children[:] = sorted(set(children) - {"target", ".git", "node_modules", "__pycache__"})
            for name in names:
                path = Path(directory) / name
                if path.suffix in (".rs", ".proto") or name in ("Cargo.toml", "Cargo.lock"):
                    paths.add(path)
    files = {str(path.relative_to(REPO)): digest_file(path) for path in sorted(paths)}
    return {"sha256": digest_json(files), "files": files}


def build_inputs():
    if digest_file(RUNNER) != LOADED_RUNNER_SHA256:
        raise MeasurementError("runner changed while running; start a new invocation")
    # Cargo also reads configuration outside the worktree. Retain its hashes,
    # not its contents, because a local configuration may contain credentials.
    config_roots = [REPO, *REPO.parents]
    config_dirs = [root / ".cargo" for root in config_roots]
    config_dirs.append(Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))))
    configs = {}
    for directory in config_dirs:
        for name in ("config", "config.toml"):
            path = directory / name
            if path.is_file():
                configs[str(path.resolve())] = digest_file(path)
    relevant = {
        key: value for key, value in os.environ.items()
        if key in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN", "CC", "CXX", "AR",
            "CFLAGS", "CXXFLAGS", "LDFLAGS",
        ) or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_"))
    }
    # The runner fixes these settings for every build, independently of the
    # invoking shell. Cargo's structured artifact report locates the binary.
    relevant["CARGO_INCREMENTAL"] = "0"
    return {
        "protocol": PROTOCOL,
        "runner_sha256": LOADED_RUNNER_SHA256,
        "source": source_snapshot(),
        "rustc": command_text(["rustc", "-Vv"]),
        "cargo": command_text(["cargo", "-V"]),
        "cargo_config_sha256": configs,
        "build_environment": relevant,
    }


def filesystem(path):
    stat = os.statvfs(path)
    return {
        "path": str(path), "block_size": stat.f_bsize,
        "mount": command_text(
            ["findmnt", "--json", "--target", str(path),
             "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"], optional=True,
        ),
    }


def host_environment(output):
    cpu = {}
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        wanted = {"vendor_id", "model name", "cpu family", "model", "stepping",
                  "microcode", "cpu cores", "siblings", "flags", "Hardware"}
        for line in cpuinfo.read_text().splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() in wanted:
                cpu.setdefault(key.strip(), set()).add(value.strip())
    policies = {}
    for path in sorted(Path("/sys/devices/system/cpu").glob("cpufreq/policy*/scaling_governor")):
        policies[str(path)] = path.read_text().strip()
    return {
        "system": platform.system(), "release": platform.release(),
        "version": platform.version(), "machine": platform.machine(),
        "os_release": Path("/etc/os-release").read_text() if Path("/etc/os-release").is_file() else None,
        "python": sys.version,
        "cpu": {key: sorted(values) for key, values in cpu.items()},
        "logical_cpus": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "cpu_governors": policies,
        "filesystems": {
            "repository": filesystem(REPO), "output": filesystem(output),
            "workload_temp": filesystem(output / "workload-tmp"),
        },
        "runtime_environment": {
            key: value for key, value in workload_environment(output).items() if key in (
                "TMPDIR", "TMP", "TEMP", "LD_PRELOAD", "LD_LIBRARY_PATH",
                "MALLOC_CONF", "MALLOC_ARENA_MAX", "GLIBC_TUNABLES",
                "NO_PROXY", "no_proxy",
            )
        },
        # Client construction can inspect proxy settings even for a bypassed
        # loopback request. Keep their identity without exposing credentials.
        "proxy_environment_sha256": {
            key: hashlib.sha256(value.encode()).hexdigest()
            for key, value in workload_environment(output).items()
            if key.lower() in ("http_proxy", "https_proxy", "all_proxy")
        },
    }


def workload_environment(output):
    # tempfile in the Rust object workload honors TMPDIR. Choosing it explicitly
    # prevents a tmpfs /tmp from silently replacing a requested disk workload.
    # The provider fixture is local even when the caller uses a system proxy.
    return dict(
        os.environ, TMPDIR=str(output / "workload-tmp"),
        NO_PROXY="127.0.0.1,localhost,::1", no_proxy="127.0.0.1,localhost,::1",
    )


def binary_hashes(output):
    return {name: digest_file(output / "bin" / name)
            for name in ("runtime-time", "runtime-heap")}


def execute_raw(directory, name, command, env=None):
    """Keep a process's exact output even when it fails or is interrupted."""
    with (directory / f"{name}.json").open("x") as stdout:
        with (directory / f"{name}.stderr").open("x") as stderr:
            return subprocess.run(command, cwd=REPO, env=env, stdout=stdout, stderr=stderr).returncode


def raw_hashes(directory, name):
    return {extension: digest_file(directory / f"{name}.{extension}")
            for extension in ("json", "stderr")}


def build(output):
    if any(path.name != ".runner.lock" for path in output.iterdir()):
        raise MeasurementError(f"build requires an empty output directory: {output}")
    (output / "bin").mkdir()
    (output / "workload-tmp").mkdir()
    logs = output / "build-logs"
    logs.mkdir()
    inputs = build_inputs()
    manifest = {
        "started_at": timestamp(), "inputs": inputs, "commands": [],
        "git_head": command_text(["git", "rev-parse", "HEAD"], optional=True),
        "git_dirty": bool(command_text(["git", "status", "--porcelain"], optional=True)),
    }
    write_json(output / "build-attempt.json", manifest)
    env = dict(os.environ, CARGO_INCREMENTAL="0")
    for mode in ("time", "heap"):
        command = [
            "cargo", "build", "--release", "--offline", "--locked",
            "-p", "xolotl-runtime-bench", "--target-dir", str(REPO / "target"),
            "--message-format=json-render-diagnostics",
        ]
        if mode == "heap":
            command.extend(["--features", "heap-profile"])
        manifest["commands"].append(command)
        write_json(output / "build-attempt.json", manifest)
        print(f"build {mode}: starting (logs in {logs})", flush=True)
        code = execute_raw(logs, mode, command, env)
        if code:
            raise MeasurementError(f"build {mode} exited {code}; see {logs / (mode + '.stderr')}")
        artifacts = []
        for line in (logs / f"{mode}.json").read_text().splitlines():
            message = json.loads(line)
            if (message.get("reason") == "compiler-artifact"
                    and message.get("target", {}).get("name") == "xolotl-runtime-bench"
                    and message.get("executable")):
                artifacts.append(Path(message["executable"]))
        if len(artifacts) != 1:
            raise MeasurementError(f"build {mode} did not report exactly one executable")
        destination = output / "bin" / f"runtime-{mode}"
        artifact_hash = digest_file(artifacts[0])
        shutil.copy2(artifacts[0], destination)
        if digest_file(destination) != artifact_hash or build_inputs() != inputs:
            raise MeasurementError(f"build {mode} changed inputs or binary while building/copying")
        print(f"build {mode}: copied and verified", flush=True)
    manifest.update(finished_at=timestamp(), binary_sha256=binary_hashes(output))
    write_json(output / "build.json", manifest)
    identity = {
        "inputs": inputs, "binary_sha256": manifest["binary_sha256"],
        "host": host_environment(output),
    }
    environment = {
        "protocol": PROTOCOL, "build_sha256": digest_file(output / "build.json"),
        "fingerprint_sha256": digest_json(identity), "identity": identity,
    }
    write_json(output / "environment.json", environment)
    write_json(output / "results.json", {
        "protocol": PROTOCOL, "environment_sha256": digest_file(output / "environment.json"),
        "groups": {},
    })
    print(f"build complete: {output}", flush=True)


def verify_environment(output):
    manifest = read_json(output / "build.json")
    environment = read_json(output / "environment.json")
    identity = {
        "inputs": build_inputs(), "binary_sha256": binary_hashes(output),
        "host": host_environment(output),
    }
    if (environment.get("protocol") != PROTOCOL
            or environment.get("build_sha256") != digest_file(output / "build.json")
            or identity["inputs"] != manifest.get("inputs")
            or identity["binary_sha256"] != manifest.get("binary_sha256")
            or identity != environment.get("identity")
            or digest_json(identity) != environment.get("fingerprint_sha256")):
        raise MeasurementError("sources, runner, binaries, toolchain, or host environment changed; use a new --output and build")
    results = read_json(output / "results.json")
    if (results.get("protocol") != PROTOCOL
            or results.get("environment_sha256") != digest_file(output / "environment.json")):
        raise MeasurementError("results do not belong to this environment")
    for group, completed in results["groups"].items():
        if group not in GROUPS:
            raise MeasurementError(f"unknown result group: {group}")
        directory = output / group
        record = read_json(directory / "group.json")
        if (digest_file(directory / "group.json") != completed["group_sha256"]
                or record.get("status") != "complete"
                or record.get("environment_sha256") != results["environment_sha256"]):
            raise MeasurementError(f"completed {group} does not match its recorded environment")
        for name, case in record["cases"].items():
            if case["raw_sha256"] != raw_hashes(directory, name):
                raise MeasurementError(f"completed {name} has modified raw output")
        for name, report in completed["reports"].items():
            if read_json(directory / f"{name}.json") != report:
                raise MeasurementError(f"completed {name} differs from its aggregated report")
    return results


def workloads(group):
    if group == "smoke":
        for mode in ("time", "heap"):
            for case in CASES:
                yield f"smoke-{mode}-{case}", mode, case, {
                    "samples": 2, "work": 1024, "width": 128, "depth": 128,
                }
    elif group in ("time", "heap"):
        for case in CASES:
            yield f"{group}-{case}", group, case, {
                "samples": 30 if group == "time" else 1,
                "warmup": 2 if group == "time" else 1,
                "work": 100_000 if case in ("stream", "stream-cancel") else 1_048_576,
            }
    else:
        for case, amounts in (
            ("stream", (1000, 100_000, 1_000_000)),
            ("stream-cancel", (1000, 100_000, 1_000_000)),
            ("object-file", (65_536, 1_048_576, 16_777_216)),
            ("provider-stream", (65_536, 1_048_576, 16_777_216)),
        ):
            for work in amounts:
                yield f"scaling-{case}-{work}", "heap", case, {"work": work}
        for mode in ("time", "heap"):
            yield f"slow-{mode}-stream", mode, "stream", {
                "samples": 3, "work": 10_000, "delay_micros": 1000,
            }


def measure(output, group):
    results = verify_environment(output)
    directory = output / group
    if directory.exists() or group in results["groups"]:
        raise MeasurementError(f"group {group} already has an attempt; choose a new --output to repeat it")
    directory.mkdir()
    record = {
        "started_at": timestamp(), "status": "running", "cases": {},
        "environment_sha256": results["environment_sha256"],
    }
    reports = {}
    write_json(directory / "group.json", record)
    failure = None
    try:
        for name, mode, case, overrides in workloads(group):
            parameters = DEFAULTS | overrides
            command = [str(output / "bin" / f"runtime-{mode}"), "--mode", mode, "--case", case]
            for key, value in parameters.items():
                command.extend(["--" + key.replace("_", "-"), str(value)])
            record["cases"][name] = {"command": command, "started_at": timestamp()}
            write_json(directory / "group.json", record)
            code = execute_raw(directory, name, command, workload_environment(output))
            record["cases"][name].update(
                returncode=code, finished_at=timestamp(), raw_sha256=raw_hashes(directory, name),
            )
            write_json(directory / "group.json", record)
            if code:
                raise MeasurementError(f"{name} exited {code}; see {directory / (name + '.stderr')}")
            report = read_json(directory / f"{name}.json")
            expected_config = parameters | {"case": case, "mode": mode, "heap_file": None}
            if (report.get("format") != 1 or report.get("config") != expected_config
                    or report.get("heap_instrumented") != (mode == "heap")):
                raise MeasurementError(f"{name} reported a different workload or measurement mode")
            reports[name] = report
            print(f"{name}: passed", flush=True)
        if group == "smoke":
            for binary, mode in (("runtime-time", "heap"), ("runtime-heap", "time")):
                name = f"reject-{binary}-{mode}"
                command = [str(output / "bin" / binary), "--mode", mode]
                record["cases"][name] = {"command": command, "started_at": timestamp()}
                write_json(directory / "group.json", record)
                code = execute_raw(directory, name, command, workload_environment(output))
                record["cases"][name].update(
                    returncode=code, finished_at=timestamp(), raw_sha256=raw_hashes(directory, name),
                )
                write_json(directory / "group.json", record)
                if code == 0 or "time mode requires" not in (directory / f"{name}.stderr").read_text():
                    raise MeasurementError(f"{name}: measurement mode separation failed")
            print("mode rejection: passed", flush=True)
    except BaseException as error:
        failure = error
    # Validate even a failed group, retaining its output without publishing it
    # as verified results. Environment metadata is never rewritten here.
    try:
        verify_environment(output)
        record["identity_after"] = "verified"
    except Exception as error:
        record["identity_after"] = str(error)
        failure = failure or error
    record.update(finished_at=timestamp(), status="failed" if failure else "complete")
    if failure:
        record["error"] = str(failure) or type(failure).__name__
    write_json(directory / "group.json", record)
    if failure:
        raise failure
    results["groups"][group] = {
        "group_sha256": digest_file(directory / "group.json"), "reports": reports,
    }
    write_json(output / "results.json", results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commands", nargs="+", choices=("build", *GROUPS))
    parser.add_argument("--output", type=Path, default=REPO / "target" / "runtime-measurements")
    args = parser.parse_args()
    if len(set(args.commands)) != len(args.commands):
        parser.error("each command may be requested only once")
    if "build" in args.commands and args.commands[0] != "build":
        parser.error("build must be the first command")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".runner.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise MeasurementError(f"another runner owns {output}") from error
        for command in args.commands:
            if command == "build":
                build(output)
            else:
                measure(output, command)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("measurement interrupted; partial logs have been preserved", file=sys.stderr)
        sys.exit(130)
    except (MeasurementError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"measurement failed: {error}", file=sys.stderr)
        sys.exit(1)
