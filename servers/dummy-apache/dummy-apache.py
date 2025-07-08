"""
A dummy HTTP to TLS upgrade server that mimics the behavior of Apache.
It first accepts the headers of a plain HTTP request and expects to find an upgrade header.
It will then expect (and perform) the TLS handshake, to then read any request body after the handshake.
The connection is kept open until the client closes it.

This implementation logs the plaintext requests and also the boundaries of TLS records.
"""

import logging
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from threading import Semaphore, Thread, current_thread

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)10s | %(threadName)s %(message)s",
)
LOGGER = logging.getLogger(__name__)


ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# uncomment to enable keylogging - can be used with wireshark to decrypt the traffic
# ssl_context.keylog_filename = "/tmp/keylogfile"
ssl_context.load_cert_chain(
    certfile=Path(__file__).parent / "certs/server.crt",
    keyfile=Path(__file__).parent / "certs/server.key",
)


def reprB(data: bytes, max_len=120):
    if len(data) > max_len:
        return repr(data[: max_len // 2]) + "..." + repr(data[-max_len // 2 :])[1:]
    return repr(data)


def recvn(sock: socket.socket, length: int):
    """Receive a specific number of bytes from the socket."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionResetError("Connection closed")
        data += chunk
    return data


def recvuntil(sock: socket.socket, delimiter: bytes):
    """Receive data from the socket until the delimiter is found."""
    data = b""
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionResetError("Connection closed")
        data += chunk
        if data.endswith(delimiter):
            break
    return data


def recvline(sock: socket.socket):
    return recvuntil(sock, b"\n")


class InvalidRequestException(Exception):
    pass


@dataclass
class RequestHead:
    method: str
    path: str
    version: str
    headers: dict

    @staticmethod
    def parse(sock):
        try:
            req_line = recvline(sock)
            try:
                method, path, version = req_line.decode("utf-8").strip().split(" ", 2)
            except ValueError as e:
                LOGGER.warning("Invalid request line: %s", req_line)
                raise InvalidRequestException("Invalid request line", req_line) from e
            headers: dict[str, str] = {}
            while line := recvline(sock).decode("utf-8").strip():
                key, value = line.split(":", 1)
                key = key.lower().strip()
                if key in headers:
                    LOGGER.warning("HTTP Duplicate header %s", key)
                headers[key] = value.strip()

            return RequestHead(
                method=method,
                path=path,
                version=version,
                headers=headers,
            )
        except TimeoutError:
            return None

    def receive_body(self, sock: socket.socket):
        if "content-length" in self.headers:
            content_length = int(self.headers["content-length"])
            return recvn(sock, content_length)
        return None


def response(code, reason, body=b""):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return f"HTTP/1.1 {code} {reason}\r\nContent-Length: {len(body)}\r\n\r\n".encode("utf-8") + body


class IntrospectingTlsSocket:
    # this is a bit of a mess, so let's try to "draw" it
    # with the ssl module (ssllib) we have the following setup [OS](TCP socket)-ssllib-(TLS socket)[Application]
    # When we read from the TLS socket, ssllib will read from the TCP socket.
    # We are now interested in intercepting the communication just before and after ssllib, such that we can see which records we received
    # hence we emulate being a socket (simply providing recv and sendall as we do not use more APIs) and inject a thread between the TCP socket and ssllib
    # This thread (LimitedRecordForwarder) will reassemble TLS records and forward them one by one. This way we can track which application data was fragmented in TLS.

    class Forwarder(Thread):
        def __init__(self, sock_from: socket.socket, sock_to: socket.socket):
            super().__init__(daemon=True)
            self._sock_from = sock_from
            self._sock_to = sock_to

        def run(self):
            try:
                while True:
                    data = self._sock_from.recv(4096)
                    if not data:
                        break
                    self._sock_to.sendall(data)
            except OSError:
                # socket closed
                pass
            finally:
                self._sock_to.close()

    class LimitedRecordForwarder(Thread):
        def __init__(self, sock_from: socket.socket, sock_to: socket.socket):
            super().__init__(daemon=True, name=current_thread().name + "-lfw")
            self._sock_from = sock_from
            self._sock_to = sock_to
            self._limit = Semaphore(0)
            self.enforce_limit = True

        def allow_new_record(self):
            self._limit.release()

        def run(self):
            try:
                while True:
                    # reassemble TLS records and forward them one by one (as the limit allows)
                    head = recvn(self._sock_from, 5)
                    record_type = head[0]
                    version = head[1:3]
                    length = int.from_bytes(head[3:5], "big")
                    data = recvn(self._sock_from, length)
                    if self.enforce_limit and record_type == 23:
                        # only limit appdata
                        self._limit.acquire()
                    self._sock_to.sendall(head + data)
            except OSError:
                # socket closed
                pass
            finally:
                self._sock_to.close()

    def __init__(self, tcp_sock: socket.socket, plain_ssl_lib_sock: socket.socket, tls_sock: ssl.SSLSocket):
        self._buffer = b""
        self._tcp_sock = tcp_sock
        self._plain_ssl_lib_sock = plain_ssl_lib_sock
        self.tls_sock = tls_sock

        # do not limit writing
        self.write_record_limiter = IntrospectingTlsSocket.Forwarder(self._plain_ssl_lib_sock, self._tcp_sock)
        self.write_record_limiter.start()
        # limit reading such that we can track incoming records to plaintext
        self.read_record_limiter = IntrospectingTlsSocket.LimitedRecordForwarder(
            self._tcp_sock, self._plain_ssl_lib_sock
        )
        self.read_record_limiter.enforce_limit = False  # only start after handshake
        self.read_record_limiter.start()

    def __enter__(self):
        self.tls_sock.do_handshake()
        self.read_record_limiter.enforce_limit = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        LOGGER.debug("Closing TLS socket")
        self.tls_sock.close()
        self._tcp_sock.close()
        self._plain_ssl_lib_sock.close()

    def _do_read(self):
        # notify that we can read a new record
        self.read_record_limiter.allow_new_record()

        # read from the TLS socket
        data = self.tls_sock.recv(2**14)
        if not data:
            raise ConnectionResetError("TLS socket closed")
        self._buffer += data

        LOGGER.debug("TLS: Received %d bytes record: %s", len(data), reprB(data))

    def recv(self, bufsize: int = 4096):
        if len(self._buffer) == 0:
            self._do_read()
        amount = min(len(self._buffer), bufsize)
        data = self._buffer[:amount]
        self._buffer = self._buffer[amount:]
        return data

    def sendall(self, data: bytes):
        self.tls_sock.sendall(data)

    @classmethod
    def wrap(cls, plain, context, server_side=False):
        w_to_ssl_sock, _sock_for_ssl_lib = socket.socketpair()
        ssl_sock = context.wrap_socket(
            _sock_for_ssl_lib,
            server_side=server_side,
            do_handshake_on_connect=False,
        )
        return cls(plain, w_to_ssl_sock, ssl_sock)

    def keylog(self, line):
        if self.keylog_filename:
            with open(self.keylog_filename, "a") as f:
                f.write(line + "\n")
        else:
            print(line)


def _client_handler(plain_sock: socket.socket):
    head = RequestHead.parse(plain_sock)
    if head.headers.get("connection") != "Upgrade" or head.headers.get("upgrade") != "TLS/1.0":
        LOGGER.warning("Plain: No Connection/Upgrade TLS header, ignoring")
        LOGGER.debug("Plain: Headers: %s", head.headers)
        plain_sock.sendall(response(400, "Bad Request", b"Missing Connection/Upgrade TLS header\n"))
        return

    LOGGER.info("Upgrading to TLS")
    plain_sock.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
    # with ssl_context.wrap_socket(plain_sock, server_side=True) as tls_sock:
    with IntrospectingTlsSocket.wrap(plain_sock, ssl_context, server_side=True) as tls_sock:
        while True:
            LOGGER.info("Got %s %s: CL=%s", head.method, head.path, head.headers.get("content-length", "-none-"))
            body = head.receive_body(tls_sock)
            LOGGER.info("- Body: %s", reprB(body))
            tls_sock.sendall(response(200, "OK", f"Responding to {head.method} {head.path}\n"))
            # read new request
            try:
                head = RequestHead.parse(tls_sock)
            except InvalidRequestException as e:
                tls_sock.sendall(response(400, "Bad Request", "Invalid request\n" + repr(e)))
                raise


def client_handler(plain_sock: socket.socket, _addr):
    LOGGER.info("Client connected: %s:%d", *_addr)
    try:
        _client_handler(plain_sock)
    except ssl.SSLError as e:
        LOGGER.error("TLS Error: %s", e)
    except ConnectionResetError:
        LOGGER.warning("Client disconnected")
    except Exception:
        LOGGER.exception("Error handling client connection")
    finally:
        plain_sock.close()


def main(bindaddr="localhost", port=1235):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bindaddr, port))
    sock.listen(1)

    while True:
        # Wait for a connection
        connection, client_address = sock.accept()
        Thread(target=client_handler, args=(connection, client_address), name=f"{client_address}", daemon=True).start()


if __name__ == "__main__":
    main()
