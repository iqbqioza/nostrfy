#!/usr/bin/env python3
"""Minimal dependency-free Nostr client used by scripts/soak_chaos.sh.

It exists only for the nightly soak/chaos job: it publishes events over the
relay's WebSocket endpoint, captures the OK frames before the relay is
SIGKILLed, and verifies after the restart that every acknowledged event is
still queryable (through the read-only REST API at /api/v1/ids/{hex}).

Everything uses the Python standard library only:

* BIP-340 Schnorr signing is implemented in pure Python. The probe signs
  only a few dozen events per chaos cycle, so the (slow) pure-Python point
  arithmetic is irrelevant here.
* The WebSocket client implements just enough of RFC 6455 for the relay:
  the HTTP upgrade handshake, masked client text frames, and unmasked
  server frames (including ping/close handling and continuation frames).

Commands:
  publish --url ws://127.0.0.1:PORT --count N --prefix P --ids-file F
  verify  --http http://127.0.0.1:PORT --ids-file F
  health  --http http://127.0.0.1:PORT
  stats   --http http://127.0.0.1:PORT
  selftest   (BIP-340 test vector 0)
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

# --- secp256k1 / BIP-340 ---------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Same fixed secret key as examples/bench.rs ([7u8; 32]).
DEFAULT_SECKEY = "07" * 32


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _jac_double(pt):
    x, y, z = pt
    if y == 0:
        return (0, 1, 0)
    a = (x * x) % P
    b = (y * y) % P
    c = (b * b) % P
    d = (2 * ((x + b) * (x + b) - a - c)) % P
    e = (3 * a) % P
    f = (e * e) % P
    x3 = (f - 2 * d) % P
    y3 = (e * (d - x3) - 8 * c) % P
    z3 = (2 * y * z) % P
    return (x3, y3, z3)


def _jac_add(p1, p2):
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1z1 = (z1 * z1) % P
    z2z2 = (z2 * z2) % P
    u1 = (x1 * z2z2) % P
    u2 = (x2 * z1z1) % P
    s1 = (y1 * z2 * z2z2) % P
    s2 = (y2 * z1 * z1z1) % P
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jac_double(p1)
    h = (u2 - u1) % P
    i = (2 * h) ** 2 % P
    j = (h * i) % P
    r = (2 * (s2 - s1)) % P
    v = (u1 * i) % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % P
    return (x3, y3, z3)


def _jac_mul(k, pt=(GX, GY, 1)):
    result = (0, 1, 0)
    addend = pt
    while k:
        if k & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(addend)
        k >>= 1
    return result


def _affine_x(pt):
    x, y, z = pt
    if z == 0:
        raise ValueError("point at infinity")
    zi = pow(z, P - 2, P)
    return x * zi * zi % P, y * zi * zi * zi % P


def pubkey_xonly(seckey: bytes) -> bytes:
    d = int.from_bytes(seckey, "big")
    if not 0 < d < N:
        raise ValueError("secret key out of range")
    return _affine_x(_jac_mul(d))[0].to_bytes(32, "big")


def sign_schnorr(seckey: bytes, msg: bytes, aux: bytes) -> bytes:
    if len(msg) != 32 or len(aux) != 32:
        raise ValueError("message and aux must be 32 bytes")
    d0 = int.from_bytes(seckey, "big")
    if not 0 < d0 < N:
        raise ValueError("secret key out of range")
    x, y = _affine_x(_jac_mul(d0))
    d = d0 if y % 2 == 0 else N - d0
    px = x.to_bytes(32, "big")
    t = d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")
    k0 = int.from_bytes(
        tagged_hash("BIP0340/nonce", t.to_bytes(32, "big") + px + msg), "big"
    ) % N
    if k0 == 0:
        raise ValueError("invalid nonce")
    rx, ry = _affine_x(_jac_mul(k0))
    k = k0 if ry % 2 == 0 else N - k0
    e = int.from_bytes(
        tagged_hash(
            "BIP0340/challenge", rx.to_bytes(32, "big") + px + msg
        ),
        "big",
    ) % N
    return rx.to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


def make_event(seckey: bytes, pubkey: bytes, kind: int, content: str, created_at: int):
    payload = [0, pubkey.hex(), created_at, kind, [], content]
    serialized = json.dumps(
        payload, separators=(",", ":"), ensure_ascii=True
    ).encode()
    event_id = hashlib.sha256(serialized).digest()
    sig = sign_schnorr(seckey, event_id, os.urandom(32))
    event = {
        "id": event_id.hex(),
        "pubkey": pubkey.hex(),
        "created_at": created_at,
        "kind": kind,
        "tags": [],
        "content": content,
        "sig": sig.hex(),
    }
    return event_id.hex(), json.dumps(event, separators=(",", ":"))


# --- WebSocket client ------------------------------------------------------


class WebSocket:
    def __init__(self, url: str, timeout: float):
        parsed = urlparse(url)
        if parsed.scheme != "ws" or not parsed.hostname:
            raise ValueError("only ws:// URLs are supported")
        self.host = parsed.hostname
        self.port = parsed.port or 80
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.sock = socket.create_connection(
            (self.host, self.port), timeout=timeout
        )
        self.buf = b""
        self._handshake(timeout)

    def _handshake(self, timeout):
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("handshake: connection closed")
            head += chunk
        header, _, self.buf = head.partition(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise ConnectionError(
                "handshake failed: " + status.decode("latin-1", "replace")
            )
        expect = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        lower = header.lower()
        if f"sec-websocket-accept: {expect.lower()}".encode() not in lower:
            raise ConnectionError("handshake: bad Sec-WebSocket-Accept")
        self.sock.settimeout(timeout)

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket: connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_frame(self):
        b1, b2 = self._read_exact(2)
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else None
        payload = self._read_exact(length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    def _send_frame(self, opcode, payload):
        mask = os.urandom(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send_text(self, text: str):
        self._send_frame(0x1, text.encode())

    def recv_text(self) -> str:
        chunks = []
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == 0x8:
                raise ConnectionError("websocket: closed by peer")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1 or opcode == 0x0:
                chunks.append(payload)
                if fin:
                    return b"".join(chunks).decode("utf-8", "replace")
            # Other opcodes (binary) are ignored: the relay never sends them.

    def close(self):
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# --- HTTP helpers ----------------------------------------------------------


def fetch_json(url: str, timeout: float):
    request = urllib.request.Request(
        url, headers={"User-Agent": "nostrfy-soak-probe"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


# --- commands --------------------------------------------------------------


def cmd_publish(args):
    seckey = bytes.fromhex(args.seckey)
    pubkey = pubkey_xonly(seckey)
    now = int(time.time())
    nonce = os.urandom(4).hex()

    ids = {}
    events = []
    for i in range(args.count):
        content = f"{args.prefix} {i} {nonce}"
        event_id, raw = make_event(
            seckey, pubkey, 1, content, now - i % 600
        )
        ids[event_id] = False
        events.append(raw)

    ws = WebSocket(args.url, args.timeout)
    try:
        for raw in events:
            ws.send_text('["EVENT",' + raw + "]")

        acked = []
        rejected = []
        seen = set()
        deadline = time.monotonic() + args.timeout
        while len(acked) + len(rejected) < len(events):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ws.sock.settimeout(remaining)
            try:
                message = ws.recv_text()
            except socket.timeout:
                break
            try:
                parsed = json.loads(message)
            except ValueError:
                continue
            if (
                not isinstance(parsed, list)
                or len(parsed) < 3
                or parsed[0] != "OK"
            ):
                continue
            event_id = parsed[1]
            if event_id not in ids or event_id in seen:
                continue
            seen.add(event_id)
            if parsed[2] is True:
                acked.append(event_id)
            else:
                reason = parsed[3] if len(parsed) > 3 else ""
                rejected.append((event_id, reason))
        if rejected:
            print(
                f"publish: relay rejected {len(rejected)} event(s): "
                f"{rejected[0][0]} {rejected[0][1]}",
                file=sys.stderr,
            )
            return 1
        if len(acked) != len(events):
            print(
                f"publish: only {len(acked)}/{len(events)} events were "
                "acknowledged before the timeout",
                file=sys.stderr,
            )
            return 1
    finally:
        ws.close()

    with open(args.ids_file, "w", encoding="utf-8") as fh:
        for event_id in acked:
            fh.write(event_id + "\n")
    print(
        f"publish: {len(acked)}/{len(events)} events acknowledged "
        f"(first id {acked[0]})"
    )
    return 0


def cmd_verify(args):
    with open(args.ids_file, encoding="utf-8") as fh:
        wanted = [line.strip() for line in fh if line.strip()]
    missing = []
    for event_id in wanted:
        try:
            body = fetch_json(
                f"{args.http.rstrip('/')}/api/v1/ids/{event_id}",
                args.timeout,
            )
            events = body.get("events") or []
            if body.get("count", 0) < 1 or not any(
                event.get("id") == event_id for event in events
            ):
                missing.append(event_id)
        except (urllib.error.URLError, ValueError, KeyError):
            missing.append(event_id)
    if missing:
        print(
            f"verify: {len(missing)}/{len(wanted)} acknowledged events are "
            f"missing after restart (first: {missing[0]})",
            file=sys.stderr,
        )
        return 1
    print(f"verify: {len(wanted)}/{len(wanted)} acknowledged events queryable")
    return 0


def cmd_health(args):
    body = fetch_json(f"{args.http.rstrip('/')}/health", args.timeout)
    if body.get("status") != "ok":
        print(f"health: relay reported {body}", file=sys.stderr)
        return 1
    return 0


def cmd_stats(args):
    body = fetch_json(f"{args.http.rstrip('/')}/relay/stats", args.timeout)
    events = body.get("events", {})
    print(
        "accepted={accepted} received={received} rejected={rejected} "
        "duplicate={duplicate} db_errors={db_errors}".format(
            accepted=events.get("accepted", 0),
            received=events.get("received", 0),
            rejected=events.get("rejected", 0),
            duplicate=events.get("duplicate", 0),
            db_errors=body.get("db_errors", 0),
        )
    )
    return 0


def cmd_selftest(_args):
    seckey = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000003"
    )
    aux = bytes(32)
    msg = bytes(32)
    expected_pub = (
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    )
    expected_sig = (
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )
    pub = pubkey_xonly(seckey).hex().upper()
    sig = sign_schnorr(seckey, msg, aux).hex().upper()
    if pub != expected_pub or sig != expected_sig:
        print(f"selftest: FAIL pub={pub} sig={sig}", file=sys.stderr)
        return 1
    print("selftest: BIP-340 vector 0 OK")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="soak_probe.py")
    sub = parser.add_subparsers(dest="command", required=True)

    publish = sub.add_parser("publish")
    publish.add_argument("--url", required=True)
    publish.add_argument("--count", type=int, required=True)
    publish.add_argument("--prefix", required=True)
    publish.add_argument("--ids-file", required=True)
    publish.add_argument("--seckey", default=DEFAULT_SECKEY)
    publish.add_argument("--timeout", type=float, default=30.0)
    publish.set_defaults(func=cmd_publish)

    verify = sub.add_parser("verify")
    verify.add_argument("--http", required=True)
    verify.add_argument("--ids-file", required=True)
    verify.add_argument("--timeout", type=float, default=10.0)
    verify.set_defaults(func=cmd_verify)

    health = sub.add_parser("health")
    health.add_argument("--http", required=True)
    health.add_argument("--timeout", type=float, default=5.0)
    health.set_defaults(func=cmd_health)

    stats = sub.add_parser("stats")
    stats.add_argument("--http", required=True)
    stats.add_argument("--timeout", type=float, default=5.0)
    stats.set_defaults(func=cmd_stats)

    selftest = sub.add_parser("selftest")
    selftest.set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
