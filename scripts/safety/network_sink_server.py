#!/usr/bin/env python3
"""ContextDroid Phase 4 Option C — custom DNS + HTTP(+HTTPS) sink.

Logs only to the vault path given by ABRG_SINK_JSONL. Fail-closed on write errors.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "extraction_pipeline"))
from safety.vault_paths import MOUNT_ROOT, assert_mounted  # noqa: E402

try:
    import ssl
except ImportError:  # pragma: no cover
    ssl = None  # type: ignore


MARKER_HTTP = "CONTEXTDROID_SINK_HTTP_MARKER"
MARKER_DNS = "CONTEXTDROID_SINK_DNS_MARKER"
HEADER_SINK = "X-CONTEXTDROID-SINK"
DNS_ANSWER = "192.0.2.1"


class SinkState:
    def __init__(
        self,
        *,
        run_id: str,
        nonce: str,
        jsonl_path: Path,
        pid_path: Path,
    ) -> None:
        self.run_id = run_id
        self.nonce = nonce
        self.jsonl_path = jsonl_path
        self.pid_path = pid_path
        self.lock = threading.Lock()
        self.closed = False

    def emit(self, event: str, **fields: Any) -> None:
        if self.closed:
            raise RuntimeError("sink closed")
        rec = {
            "ts": time.time(),
            "event": event,
            "run_id": self.run_id,
            "nonce": self.nonce,
            **fields,
        }
        line = json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n"
        with self.lock:
            try:
                with self.jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                self.closed = True
                raise RuntimeError(f"vault jsonl write failed (fail-closed): {exc}") from exc


STATE: SinkState | None = None


def _require_state() -> SinkState:
    if STATE is None:
        raise RuntimeError("sink state not initialized")
    return STATE


class DnsServer(threading.Thread):
    """Minimal UDP (+ optional TCP) DNS catch-all answering DNS_ANSWER."""

    daemon = True

    def __init__(self, host: str, port: int) -> None:
        super().__init__(name="abrg-dns")
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        state = _require_state()
        state.emit("dns_listen", host=self.host, port=self.port)
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                resp, qname = build_dns_response(data)
                sock.sendto(resp, addr)
                state.emit(
                    "dns_query",
                    qname=qname,
                    answer=DNS_ANSWER,
                    client=f"{addr[0]}:{addr[1]}",
                    transport="udp",
                )
            except Exception as exc:  # noqa: BLE001 — keep serving
                try:
                    state.emit("dns_error", error=str(exc))
                except Exception:  # noqa: BLE001
                    pass


class UdpCatchAllServer(threading.Thread):
    """UDP catch-all sink for non-53 guest ports DNATed to host :8053."""

    daemon = True
    MARKER = b"CONTEXTDROID_SINK_UDP_CATCHALL\n"

    def __init__(self, host: str, port: int) -> None:
        super().__init__(name="abrg-udp-catchall")
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        state = _require_state()
        state.emit("udp_catchall_listen", host=self.host, port=self.port)
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                nonce = state.nonce.encode("ascii")
                sock.sendto(self.MARKER + b"nonce=" + nonce + b"\n", addr)
                state.emit(
                    "udp_catchall",
                    client=f"{addr[0]}:{addr[1]}",
                    nbytes=len(data),
                    marker="CONTEXTDROID_SINK_UDP_CATCHALL",
                    transport="udp",
                    listen_port=self.port,
                )
            except Exception as exc:  # noqa: BLE001 — keep serving
                try:
                    state.emit("udp_catchall_error", error=str(exc))
                except Exception:  # noqa: BLE001
                    pass


def build_dns_response(data: bytes) -> tuple[bytes, str]:
    if len(data) < 12:
        raise ValueError("short dns packet")
    i = 12
    labels: list[str] = []
    while i < len(data):
        length = data[i]
        if length == 0:
            i += 1
            break
        if (length & 0xC0) == 0xC0:
            i += 2
            break
        labels.append(data[i + 1 : i + 1 + length].decode("ascii", "ignore"))
        i += 1 + length
    if i + 4 > len(data):
        raise ValueError("truncated question")
    i += 4  # qtype + qclass
    qname = ".".join(labels) if labels else "."
    qsection = data[12:i]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(map(int, DNS_ANSWER.split(".")))
    header = data[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0)
    return header + qsection + answer, qname


class SinkHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    def _nonce(self) -> str:
        return _require_state().nonce

    def _body_for(self, path: str) -> str:
        nonce = self._nonce()
        return (
            f"{MARKER_HTTP}\n"
            f"nonce={nonce}\n"
            f"path={path}\n"
            f"{MARKER_DNS}\n"
        )

    def _send(self, code: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header(HEADER_SINK, "1")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        state = _require_state()
        path = self.path.split("?", 1)[0]
        qs = ""
        if "?" in self.path:
            qs = self.path.split("?", 1)[1]

        if path == "/__abrg_health":
            # Gate A: require nonce query param match
            want = None
            for part in qs.split("&"):
                if part.startswith("nonce="):
                    want = part.split("=", 1)[1]
            if want != state.nonce:
                self._send(403, "nonce mismatch\n")
                state.emit("http_health_fail", path=self.path, reason="nonce_mismatch")
                return
            body = self._body_for(path)
            self._send(200, body)
            state.emit("http_health_ok", path=self.path, marker=MARKER_HTTP)
            return

        body = self._body_for(path)
        host = self.headers.get("Host", "")
        # Guest catch-all DNATs any non-80/443 TCP onto this listener; tag those hits.
        catch_all = path.startswith("/__abrg_catchall") or ":1337" in host or ":4444" in host
        self._send(200, body)
        state.emit(
            "http_fetch",
            path=path,
            host=host,
            marker=MARKER_HTTP,
            client=self.client_address[0],
            url=f"http://{host}{self.path}",
            catch_all=catch_all,
        )
        if catch_all:
            state.emit(
                "tcp_catchall",
                path=path,
                host=host,
                marker=MARKER_HTTP,
                client=self.client_address[0],
                listen_port="http",
            )

    def do_POST(self) -> None:  # noqa: N802
        # Optional control channel for guest helpers (conntrack evidence).
        state = _require_state()
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, "bad json\n")
            return
        event = str(payload.get("event", "guest_event"))
        fields = {k: v for k, v in payload.items() if k != "event"}
        state.emit(event, **fields)
        self._send(200, self._body_for("/__abrg_ingest"))


class DualStackServer(ThreadingHTTPServer):
    allow_reuse_address = True


def make_http_server(host: str, port: int) -> DualStackServer:
    return DualStackServer((host, port), SinkHTTPRequestHandler)


def make_https_server(host: str, port: int, certfile: Path, keyfile: Path) -> DualStackServer:
    if ssl is None:
        raise RuntimeError("ssl module unavailable")
    httpd = DualStackServer((host, port), SinkHTTPRequestHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def generate_self_signed(cert_dir: Path) -> tuple[Path, Path]:
    """Best-effort self-signed cert for HTTPS sink. Raises if openssl missing."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert = cert_dir / "sink.crt"
    key = cert_dir / "sink.key"
    if cert.is_file() and key.is_file():
        return cert, key
    import subprocess

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=CONTEXTDROID-SINK",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def main() -> int:
    global STATE
    ap = argparse.ArgumentParser(description="ABRG Option C network sink")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--jsonl", required=True, type=Path)
    ap.add_argument("--pidfile", required=True, type=Path)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--dns-port", type=int, default=15353)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--https-port", type=int, default=8443)
    ap.add_argument("--udp-catchall-port", type=int, default=8053)
    ap.add_argument("--enable-https", action="store_true")
    ap.add_argument("--cert-dir", type=Path, default=None)
    args = ap.parse_args()

    jsonl = args.jsonl.resolve()
    try:
        mount = assert_mounted().resolve()
    except Exception as exc:
        print(f"refusing jsonl: vault not mounted ({exc})", file=sys.stderr)
        return 2
    try:
        jsonl.relative_to(mount)
    except ValueError:
        print(
            f"refusing jsonl outside vault mount {MOUNT_ROOT}: {jsonl}",
            file=sys.stderr,
        )
        return 2
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    # Touch / prove writable before bind
    with jsonl.open("a", encoding="utf-8") as fh:
        fh.write("")
        fh.flush()

    STATE = SinkState(
        run_id=args.run_id,
        nonce=args.nonce,
        jsonl_path=jsonl,
        pid_path=args.pidfile,
    )
    args.pidfile.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    STATE.emit(
        "sink_start",
        dns_port=args.dns_port,
        http_port=args.http_port,
        udp_catchall_port=args.udp_catchall_port,
    )

    dns = DnsServer(args.bind, args.dns_port)
    dns.start()
    udp_ca = UdpCatchAllServer(args.bind, args.udp_catchall_port)
    udp_ca.start()
    httpd = make_http_server(args.bind, args.http_port)
    httpsd = None
    if args.enable_https:
        try:
            cert_dir = args.cert_dir or jsonl.parent / f".certs-{args.run_id}"
            cert, key = generate_self_signed(cert_dir)
            httpsd = make_https_server(args.bind, args.https_port, cert, key)
            STATE.emit("https_listen", port=args.https_port)
        except Exception as exc:  # noqa: BLE001
            STATE.emit("https_deferred", error=str(exc))
            httpsd = None

    stop = threading.Event()

    def _shutdown(*_a: Any) -> None:
        stop.set()
        dns.stop()
        udp_ca.stop()
        httpd.shutdown()
        if httpsd is not None:
            httpsd.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    threading.Thread(target=httpd.serve_forever, name="abrg-http", daemon=True).start()
    if httpsd is not None:
        threading.Thread(target=httpsd.serve_forever, name="abrg-https", daemon=True).start()

    STATE.emit("sink_ready")
    while not stop.is_set():
        time.sleep(0.25)
    STATE.emit("sink_stop")
    try:
        args.pidfile.unlink(missing_ok=True)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
