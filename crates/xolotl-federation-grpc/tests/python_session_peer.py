#!/usr/bin/env python3
"""Independent Python/OpenSSL 3.6 + h2 client for federation v1 Session.

No generated Xolotl bindings or Python gRPC/protobuf runtime are used. The
small protobuf encoder below covers only the fields exercised by this test.
"""

import argparse
import hashlib
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, TrailersReceived
from OpenSSL import SSL


ROOT = b"xolotl.federation.root.v1\0"
NODE = b"xolotl.federation.node-id.v1\0"
ONLINE = b"xolotl.federation.online-key.v1\0"
SIGNATURE = b"xolotl.federation.signature.v1\0"
CAPABILITIES = b"xolotl.federation.hello-capabilities.v1\0"
SESSION = b"xolotl.federation.online-session.v1\0"
RECORD = b"xolotl.federation.record.v1\0"
EXPORTER = b"EXPORTER-xolotl-federation-v1"
SPKI = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
KEY_HEADER = struct.pack(">HHH", 1, 1, 1952)
STREAM_ID = bytes([3]) * 16
SUBSCRIPTION_ID = bytes([4]) * 16


def run(*args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, timeout=10)
    if result.returncode:
        raise AssertionError(f"OpenSSL failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def varint(value):
    assert value >= 0
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def number(field, value):
    return varint(field << 3) + varint(value)


def blob(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value


def fields(data):
    result = {}
    offset = 0

    def read_varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            assert offset < len(data), "truncated protobuf varint"
            part = data[offset]
            offset += 1
            value |= (part & 127) << shift
            if part < 128:
                return value
        raise AssertionError("oversized protobuf varint")

    while offset < len(data):
        tag = read_varint()
        field, wire = tag >> 3, tag & 7
        assert field > 0
        if wire == 0:
            value = read_varint()
        elif wire == 2:
            length = read_varint()
            assert offset + length <= len(data), "truncated protobuf bytes"
            value = data[offset:offset + length]
            offset += length
        else:
            raise AssertionError(f"unexpected protobuf wire type {wire}")
        result.setdefault(field, []).append(value)
    return result


def one(message, field):
    values = message[field]
    assert len(values) == 1
    return values[0]


def optional(message, field, default=None):
    return one(message, field) if field in message else default


def sign(key, message, directory):
    source = directory / "signing-input.bin"
    signature = directory / "signature.bin"
    source.write_bytes(message)
    run("openssl", "pkeyutl", "-sign", "-inkey", key, "-keyform", "DER",
        "-rawin", "-in", source, "-out", signature)
    result = signature.read_bytes()
    assert len(result) == 3309
    return result


def verify(public, message, signature, directory):
    public_file = directory / "verify-public.der"
    message_file = directory / "verify-input.bin"
    signature_file = directory / "verify-signature.bin"
    public_file.write_bytes(SPKI + public)
    message_file.write_bytes(message)
    signature_file.write_bytes(signature)
    run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", public_file,
        "-keyform", "DER", "-rawin", "-in", message_file,
        "-sigfile", signature_file)


def public_key(private, directory):
    output = directory / "public.der"
    run("openssl", "pkey", "-inform", "DER", "-in", private,
        "-pubout", "-outform", "DER", "-out", output)
    encoded = output.read_bytes()
    assert encoded.startswith(SPKI) and len(encoded) == len(SPKI) + 1952
    return encoded[len(SPKI):]


def prepare(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_key = directory / "root.pk8"
    online_key = directory / "online.pk8"
    for key in (root_key, online_key):
        run("openssl", "genpkey", "-algorithm", "ML-DSA-65", "-outform", "DER", "-out", key)
        key.chmod(0o600)
    descriptor = ROOT + KEY_HEADER + public_key(root_key, directory)
    authorization = (ONLINE + KEY_HEADER + struct.pack(">QQQ", 1, 100, 200)
                     + public_key(online_key, directory))
    root_input = SIGNATURE + bytes([2]) + struct.pack(">I", len(authorization)) + authorization
    (directory / "root.bin").write_bytes(descriptor)
    (directory / "authorization.bin").write_bytes(authorization)
    (directory / "root.sig").write_bytes(sign(root_key, root_input, directory))
    node = hashlib.sha384(NODE + descriptor).hexdigest()
    (directory / "node-id.txt").write_text(node)
    print(node, flush=True)


def hello(directory):
    descriptor = (directory / "root.bin").read_bytes()
    authorization = (directory / "authorization.bin").read_bytes()
    node = bytes.fromhex((directory / "node-id.txt").read_text())
    values = {
        1: 1,
        2: node,
        3: 2 * 1024 * 1024,
        4: 16,
        5: 128,
        6: 512 * 1024,
        7: descriptor,
        8: authorization,
        9: (directory / "root.sig").read_bytes(),
        10: os.urandom(32),
    }
    return values, encode_hello(values)


def encode_hello(values):
    return b"".join(
        number(field, value) if isinstance(value, int) else blob(field, value)
        for field, value in values.items()
    )


def verify_hello(server, expected_node, directory):
    assert one(server, 1) == 1
    assert one(server, 2) == expected_node
    assert len(one(server, 10)) == 32 and any(one(server, 10))
    assert 11 not in server
    descriptor = one(server, 7)
    authorization = one(server, 8)
    assert descriptor.startswith(ROOT + KEY_HEADER) and len(descriptor) == 1984
    assert authorization.startswith(ONLINE + KEY_HEADER) and len(authorization) == 2014
    assert hashlib.sha384(NODE + descriptor).digest() == expected_node
    assert struct.unpack(">QQQ", authorization[len(ONLINE) + 6:len(ONLINE) + 30]) == (1, 100, 200)
    root_input = SIGNATURE + bytes([2]) + struct.pack(">I", len(authorization)) + authorization
    verify(descriptor[-1952:], root_input, one(server, 9), directory)


def transcript(initiator, responder, signer, exporter):
    capability = hashlib.sha384(CAPABILITIES + b"".join(
        struct.pack(">II", one(hello, 1), one(hello, 12) if 12 in hello else 0) + one(hello, 2) + struct.pack(">QIIQ", one(hello, 3), one(hello, 4),
                                     one(hello, 5), one(hello, 6))
        for hello in (initiator, responder)
    )).digest()
    return (SESSION + one(signer, 2) + one(initiator, 2) + one(responder, 2)
            + one(initiator, 10) + one(responder, 10) + exporter + capability
            + hashlib.sha384(one(signer, 8)).digest())


class GrpcSession:
    def __init__(self, connection):
        self.connection = connection
        self.h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        self.pending = bytearray()
        self.frames = []
        self.trailers = None
        self.h2.initiate_connection()
        self.h2.send_headers(1, [
            (":method", "POST"), (":scheme", "https"), (":authority", "localhost"),
            (":path", "/xolotl.v1.federation.FederationService/Session"),
            ("content-type", "application/grpc"), ("te", "trailers"),
        ])
        self.flush()

    def flush(self):
        data = self.h2.data_to_send()
        if data:
            self.connection.sendall(data)

    def send(self, field, payload):
        body = blob(field, payload)
        self.h2.send_data(1, b"\0" + struct.pack(">I", len(body)) + body)
        self.flush()

    def receive(self, expected_field):
        while not self.frames:
            data = self.connection.recv(65535)
            assert data, f"closed before response {expected_field}, trailers={self.trailers}"
            for event in self.h2.receive_data(data):
                if isinstance(event, DataReceived):
                    self.pending.extend(event.data)
                    self.h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, ResponseReceived):
                    headers = dict(event.headers)
                    assert headers.get("content-type", "").startswith("application/grpc"), headers
                elif isinstance(event, TrailersReceived):
                    self.trailers = dict(event.headers)
                elif isinstance(event, StreamEnded):
                    raise AssertionError(f"Session ended early: {self.trailers}")
            self.flush()
            while len(self.pending) >= 5:
                assert self.pending[0] == 0, "compressed gRPC message"
                length = struct.unpack(">I", self.pending[1:5])[0]
                if len(self.pending) < 5 + length:
                    break
                self.frames.append(bytes(self.pending[5:5 + length]))
                del self.pending[:5 + length]
        envelope = fields(self.frames.pop(0))
        assert expected_field in envelope, f"expected frame {expected_field}, got {envelope.keys()}"
        return fields(one(envelope, expected_field))

    def expect_unauthenticated(self):
        while self.trailers is None:
            data = self.connection.recv(65535)
            assert data, "server closed without gRPC authentication status"
            for event in self.h2.receive_data(data):
                if isinstance(event, DataReceived):
                    raise AssertionError("business frame delivered after invalid proof")
                if isinstance(event, TrailersReceived):
                    self.trailers = dict(event.headers)
            self.flush()
        assert self.trailers.get("grpc-status") == "16", self.trailers


def check_record(record, server_node):
    stream = fields(one(record, 1))
    assert one(stream, 1) == server_node and one(stream, 2) == STREAM_ID
    assert one(record, 2) == 1 and one(record, 3) == bytes([9]) * 16
    assert one(record, 4) == b"note.created"
    assert one(record, 5) == bytes([6]) * 32
    assert 6 not in record
    payload = one(record, 7)
    assert payload == b"durable Python delivery"
    digest = hashlib.sha384(
        RECORD + server_node + STREAM_ID + struct.pack(">Q", 1) + bytes([9]) * 16
        + struct.pack(">Q", len(b"note.created")) + b"note.created" + bytes([6]) * 32
        + b"\0" + struct.pack(">Q", len(payload)) + hashlib.sha384(payload).digest()
    ).digest()
    assert one(record, 8) == digest
    return digest


def tls_connect(context, address):
    host, port = address.rsplit(":", 1)
    raw = socket.create_connection((host, int(port)), timeout=8)
    # PyOpenSSL reports WantRead on a socket with a Python timeout, even for a
    # healthy in-progress TLS handshake. Use blocking I/O after connect.
    raw.settimeout(None)
    connection = SSL.Connection(context, raw)
    connection.set_connect_state()
    connection.set_tlsext_host_name(b"localhost")
    connection.do_handshake()
    return raw, connection


def client(directory, address, server_node, ca):
    own, own_encoded = hello(directory)
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_min_proto_version(SSL.TLS1_3_VERSION)
    context.set_max_proto_version(SSL.TLS1_3_VERSION)
    context.set_alpn_protos([b"h2"])
    context.load_verify_locations(str(ca))
    context.set_verify(SSL.VERIFY_PEER, lambda _conn, _cert, _error, _depth, ok: ok)
    raw, connection = tls_connect(context, address)
    try:
        assert connection.get_protocol_version_name() == "TLSv1.3"
        assert connection.get_group_name() == "X25519MLKEM768"
        assert connection.get_cipher_name() in ("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")
        assert connection.get_alpn_proto_negotiated() == b"h2"
        assert connection.get_peer_certificate().get_subject().CN == "localhost"
        exporter = connection.export_keying_material(EXPORTER, 48)
        session = GrpcSession(connection)
        session.send(1, own_encoded)
        server = session.receive(1)
        verify_hello(server, server_node, directory)
        own_parsed = fields(own_encoded)
        proof = sign(directory / "online.pk8", transcript(own_parsed, server, own_parsed, exporter), directory)
        session.send(9, blob(1, proof))
        remote_auth = session.receive(9)
        verify(one(server, 8)[-1952:], transcript(own_parsed, server, server, exporter),
               one(remote_auth, 1), directory)
        stream = blob(1, server_node) + blob(2, STREAM_ID)
        subscription = blob(1, bytes.fromhex((directory / "node-id.txt").read_text())) + blob(2, SUBSCRIPTION_ID)
        open_request = (number(1, 1) + blob(2, bytes([7]) * 16) + blob(3, subscription)
                        + blob(4, stream) + number(6, 1))
        session.send(2, open_request)
        opened = session.receive(3)
        assert one(opened, 1) == 1 and one(opened, 2) == bytes([7]) * 16
        assert fields(one(opened, 3)) == fields(subscription)
        assert fields(one(opened, 4)) == fields(stream)
        assert one(opened, 5) == b"friends" and one(opened, 8) > 0
        read = number(1, 2) + blob(2, subscription) + number(4, 8) + number(5, 1024)
        session.send(4, read)
        batch = session.receive(5)
        assert one(batch, 1) == 2 and fields(one(batch, 2)) == fields(subscription)
        assert one(batch, 5) == 1 and len(batch[3]) == 1
        digest = check_record(fields(one(batch, 3)), server_node)
        head = fields(one(batch, 4))
        assert one(head, 1) == 1 and one(head, 2) == digest
        print("python_tls_session_open_read=ok", flush=True)
    finally:
        connection.close()
        raw.close()

    for invalid in ("exporter", "root_signature"):
        own, own_encoded = hello(directory)
        if invalid == "root_signature":
            own[9] = bytes([own[9][0] ^ 1]) + own[9][1:]
            own_encoded = encode_hello(own)
        raw, connection = tls_connect(context, address)
        try:
            exporter = connection.export_keying_material(EXPORTER, 48)
            session = GrpcSession(connection)
            session.send(1, own_encoded)
            server = session.receive(1)
            verify_hello(server, server_node, directory)
            wrong_exporter = bytes([exporter[0] ^ 1]) + exporter[1:]
            signed_exporter = wrong_exporter if invalid == "exporter" else exporter
            proof = sign(directory / "online.pk8",
                         transcript(fields(own_encoded), server, fields(own_encoded), signed_exporter),
                         directory)
            session.send(9, blob(1, proof))
            node = bytes.fromhex((directory / "node-id.txt").read_text())
            denied_subscription = blob(1, node) + blob(2, bytes([5]) * 16)
            denied_stream = blob(1, server_node) + blob(2, STREAM_ID)
            session.send(2, number(1, 10) + blob(2, bytes([8]) * 16)
                         + blob(3, denied_subscription) + blob(4, denied_stream) + number(6, 1))
            remote_auth = session.receive(9)
            verify(one(server, 8)[-1952:],
                   transcript(fields(own_encoded), server, server, exporter),
                   one(remote_auth, 1), directory)
            session.expect_unauthenticated()
            print(f"python_tls_session_reject_{invalid}=ok", flush=True)
        finally:
            connection.close()
            raw.close()


def main():
    if hasattr(signal, "SIGALRM"):
        def timed_out(_signal, _frame):
            raise TimeoutError("Python federation Session exceeded 30 seconds")
        signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(30)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("directory", type=Path)
    connect = sub.add_parser("client")
    connect.add_argument("directory", type=Path)
    connect.add_argument("address")
    connect.add_argument("server_node")
    connect.add_argument("ca", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.directory)
    else:
        client(args.directory, args.address, bytes.fromhex(args.server_node), args.ca)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Python federation peer failed: {error}", file=sys.stderr)
        raise
