#!/usr/bin/env python3
"""Fake SMTP front end for the kit-c tests (stdlib only). Test use only, inside a network namespace that has nothing but
loopback. It speaks the plaintext part of SMTP itself and, after STARTTLS, relays the raw bytes to a local
`openssl s_server` (which has no STARTTLS mode of its own), so the TLS part is a real OpenSSL server with -trace.

  fake_smtp.py LISTEN_IP LISTEN_PORT BACKEND_PORT LOG [option ...]

options: banner-delay=S   wait S seconds before the greeting
         no-banner        never send a greeting (tarpit); the connection is held open
         no-starttls      do not advertise STARTTLS in the EHLO reply
         starttls-reply=TEXT   reply to STARTTLS with TEXT (default "220 2.0.0 Ready to start TLS"); a reply that does not
                               start with 220 means no TLS: the front end stays in SMTP mode
         reject           greeting "554 5.7.1 no service here" instead of 220

LOG gets one JSON line per event: {"t", "conn", "ev", ...}. ev = accept / s2c / c2s (plaintext, "data" = the exact bytes
as latin-1 text) / tls-c2s / tls-s2c ("n" bytes relayed, "first" = first byte of the first chunk as an int) / close.
Every byte the client sends before the TLS relay starts is logged verbatim, so a test can state exactly what s_client sends.
"""
import json, socket, sys, threading, time


def main():
    host, port, backend, logp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    opts = {}
    for o in sys.argv[5:]:
        k, _, v = o.partition("=")
        opts[k] = v
    lock = threading.Lock()
    logf = open(logp, "a", buffering=1)

    def log(**kw):
        with lock:
            logf.write(json.dumps(dict(t=round(time.time(), 3), **kw)) + "\n")

    def relay(a, b, conn, ev):
        first, n = None, 0
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                if first is None:
                    first = d[0]
                n += len(d)
                b.sendall(d)
        except OSError:
            pass
        log(conn=conn, ev=ev, n=n, first=first)
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def handle(c, conn):
        log(conn=conn, ev="accept")

        def send(txt):
            c.sendall(txt.encode("latin-1"))
            log(conn=conn, ev="s2c", data=txt)
        try:
            if "no-banner" in opts:
                while c.recv(65536):            # hold the connection; log anything the client sends anyway
                    pass
                return
            if "banner-delay" in opts:
                time.sleep(float(opts["banner-delay"]))
            send("554 5.7.1 no service here\r\n" if "reject" in opts else "220-fake.test ESMTP test front end\r\n220 fake.test ready\r\n")
            buf = b""
            while True:
                d = c.recv(65536)
                if not d:
                    log(conn=conn, ev="close", by="client", pending=buf.decode("latin-1"))
                    return
                log(conn=conn, ev="c2s", data=d.decode("latin-1"))
                buf += d
                while b"\n" in buf:
                    line, _, buf = buf.partition(b"\n")
                    cmd = line.decode("latin-1").strip().upper()
                    if cmd.startswith(("EHLO", "HELO", "LHLO")):
                        send("250-fake.test\r\n250-PIPELINING\r\n" + ("" if "no-starttls" in opts else "250-STARTTLS\r\n")
                             + "250 8BITMIME\r\n")
                    elif cmd == "STARTTLS":
                        rep = opts.get("starttls-reply", "220 2.0.0 Ready to start TLS")
                        send(rep + "\r\n")
                        if rep.startswith("220"):
                            u = socket.create_connection(("127.0.0.1", backend))
                            if buf:
                                u.sendall(buf)
                            t = threading.Thread(target=relay, args=(c, u, conn, "tls-c2s"), daemon=True)
                            t.start()
                            relay(u, c, conn, "tls-s2c")
                            t.join(5)
                            return
                    elif cmd == "QUIT":
                        send("221 2.0.0 bye\r\n")
                        c.close()
                        log(conn=conn, ev="close", by="server")
                        return
                    else:
                        send("502 5.5.2 command not recognized\r\n")
        except OSError as e:
            log(conn=conn, ev="close", by="error", err=str(e))
        finally:
            try:
                c.close()
            except OSError:
                pass

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen(64)
    n = 0
    while True:
        c, _ = ls.accept()
        n += 1
        threading.Thread(target=handle, args=(c, n), daemon=True).start()


if __name__ == "__main__":
    main()
