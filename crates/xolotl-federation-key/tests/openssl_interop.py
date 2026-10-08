#!/usr/bin/env python3
"""Check v1 identity interoperability with Python and OpenSSL 3.6+.

Run on a regular host after building the key binary:

    cargo build -p xolotl-federation-key --locked
    python3 crates/xolotl-federation-key/tests/openssl_interop.py \
        target/debug/xolotl-federation-key

This checks identity files and root authorization signatures in both directions.
It does not exercise a TLS Session or the protobuf protocol.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


ROOT_PREFIX = b"xolotl.federation.root.v1\0"
NODE_PREFIX = b"xolotl.federation.node-id.v1\0"
ONLINE_PREFIX = b"xolotl.federation.online-key.v1\0"
SIGNATURE_PREFIX = b"xolotl.federation.signature.v1\0"
KEY_HEADER = struct.pack(">HHH", 1, 1, 1952)
SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309


def run(*args: object, success: bool = True) -> str:
    command = [str(arg) for arg in args]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected command result: {command!r}\n{result.stdout}{result.stderr}"
        )
    return result.stdout


def write(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def public_key(private: Path, output: Path) -> bytes:
    run(
        "openssl", "pkey", "-inform", "DER", "-in", private,
        "-pubout", "-outform", "DER", "-out", output,
    )
    spki = output.read_bytes()
    assert spki.startswith(SPKI_PREFIX)
    assert len(spki) == len(SPKI_PREFIX) + PUBLIC_KEY_BYTES
    return spki[len(SPKI_PREFIX):]


def signed_input(authorization: bytes) -> bytes:
    return (
        SIGNATURE_PREFIX
        + bytes([2])
        + struct.pack(">I", len(authorization))
        + authorization
    )


def facts(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines())


def expected_facts(descriptor: bytes, authorization: bytes) -> dict[str, str]:
    return {
        "node_id": hashlib.sha384(NODE_PREFIX + descriptor).hexdigest(),
        "authorization_sha384": hashlib.sha384(authorization).hexdigest(),
        "generation": "1",
        "not_before_ms": "1800000000000",
        "expires_ms": "1800001000000",
    }


def openssl_to_xolotl(key_binary: Path, directory: Path) -> None:
    root_key = directory / "external-root.pk8"
    online = directory / "external-online"
    online.mkdir(mode=0o700)
    online_key = online / "online.pk8"
    root_spki = directory / "external-root.spki"
    online_spki = directory / "external-online.spki"
    for key in (root_key, online_key):
        run("openssl", "genpkey", "-algorithm", "ML-DSA-65", "-outform", "DER", "-out", key)
        key.chmod(0o600)

    descriptor = ROOT_PREFIX + KEY_HEADER + public_key(root_key, root_spki)
    authorization = (
        ONLINE_PREFIX + KEY_HEADER
        + struct.pack(">QQQ", 1, 1800000000000, 1800001000000)
        + public_key(online_key, online_spki)
    )
    write(online / "root.bin", descriptor)
    write(online / "online-authorization.bin", authorization)
    message = directory / "external-signing-input.bin"
    write(message, signed_input(authorization))
    signature = online / "online-authorization.sig"
    run(
        "openssl", "pkeyutl", "-sign", "-inkey", root_key, "-keyform", "DER",
        "-rawin", "-in", message, "-out", signature,
    )
    signature.chmod(0o600)
    assert signature.stat().st_size == SIGNATURE_BYTES
    assert facts(run(key_binary, "inspect", "--dir", online)) == expected_facts(
        descriptor, authorization
    )

    valid_signature = signature.read_bytes()
    changed_signature = bytearray(valid_signature)
    changed_signature[-1] ^= 1
    write(signature, changed_signature)
    run(key_binary, "inspect", "--dir", online, success=False)
    write(signature, valid_signature)

    changed = bytearray(authorization)
    changed[-1] ^= 1
    write(online / "online-authorization.bin", changed)
    run(key_binary, "inspect", "--dir", online, success=False)


def xolotl_to_openssl(key_binary: Path, directory: Path) -> None:
    root = directory / "xolotl-root"
    online = directory / "xolotl-online"
    run(key_binary, "init-root", "--out-dir", root)
    issued = facts(run(
        key_binary, "issue-online", "--root-dir", root, "--out-dir", online,
        "--generation", 1, "--not-before-ms", 1800000000000,
        "--expires-ms", 1800001000000,
    ))
    descriptor = (online / "root.bin").read_bytes()
    authorization = (online / "online-authorization.bin").read_bytes()
    assert descriptor.startswith(ROOT_PREFIX + KEY_HEADER)
    assert authorization.startswith(ONLINE_PREFIX + KEY_HEADER)
    assert issued == expected_facts(descriptor, authorization)

    root_spki = directory / "xolotl-root.spki"
    write(root_spki, SPKI_PREFIX + descriptor[-PUBLIC_KEY_BYTES:])
    online_spki = directory / "xolotl-online.spki"
    assert public_key(online / "online.pk8", online_spki) == authorization[-PUBLIC_KEY_BYTES:]
    message = directory / "xolotl-signing-input.bin"
    write(message, signed_input(authorization))
    signature = online / "online-authorization.sig"
    run(
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", root_spki,
        "-keyform", "DER", "-rawin", "-in", message, "-sigfile", signature,
    )
    changed = bytearray(message.read_bytes())
    changed[-1] ^= 1
    write(message, changed)
    run(
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", root_spki,
        "-keyform", "DER", "-rawin", "-in", message, "-sigfile", signature,
        success=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key_binary", type=Path)
    arguments = parser.parse_args()
    key_binary = arguments.key_binary.resolve(strict=True)
    if shutil.which("openssl") is None:
        parser.error("OpenSSL is required")
    algorithms = run("openssl", "list", "-signature-algorithms")
    if "ML-DSA-65" not in algorithms:
        parser.error("OpenSSL with ML-DSA-65 support is required")
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="xolotl-openssl-interop-") as temporary:
            directory = Path(temporary)
            openssl_to_xolotl(key_binary, directory)
            xolotl_to_openssl(key_binary, directory)
    finally:
        os.umask(old_umask)
    print("v1 identity and root authorization interoperate in both directions")


if __name__ == "__main__":
    main()
