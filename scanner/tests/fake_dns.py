#!/usr/bin/env python3
"""Fake recursive resolver for the kit-c tests (UDP and TCP, stdlib only). Test use only, inside a network namespace
that has nothing but loopback. Unlike stub_dns.py (the namespace's system resolver) it serves CNAME and MX records and
misbehaves on request, so the tests can exercise dnsclient.py.

  fake_dns.py <config.json> <query-log> [listen-ip] [port]

config.json: {"zone": {"name": [["A", "127.0.0.1"], ["AAAA", "::1"], ["CNAME", "target"], ["MX", 10, "mx.host"], ...]},
              "cname_only": ["name", ...],    # answer a CNAME at this name without following it (forces a re-query)
              "behave": {"name": "servfail" | "refused" | "tc" | "badid" | "badid-then-good" | "badq" | "ptrloop" |
                                 "drop"}}
  An answer follows CNAMEs inside the zone (at most 16 steps) unless a name is in cname_only; a chain ending at an
  unknown name gets NXDOMAIN with the CNAME records. tc: UDP replies have TC=1 and no answer, TCP replies are complete.
  badid: one reply with a different id. badid-then-good: that, then the correct reply. badq: a reply whose question
  name differs. ptrloop: a reply whose answer owner is a compression pointer to itself. drop: no reply.
Every query is appended to <query-log> as a JSON line {"t", "proto", "name", "type", "id"} before it is answered.
"""
import json, socket, struct, sys, threading, time

TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15}
TNAME = {v: k for k, v in TYPES.items()}


def enc(name):
    name = name.lower().rstrip(".")
    out = b""
    if name:
        for lab in name.split("."):
            out += bytes([len(lab)]) + lab.encode()
    return out + b"\0"


def qname(buf, off):
    labels = []
    while True:
        n = buf[off]
        off += 1
        if n == 0:
            return ".".join(labels).lower(), off
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n


def rr(owner, rec):
    t = rec[0]
    if t == "A":
        import ipaddress
        data = ipaddress.IPv4Address(rec[1]).packed
    elif t == "AAAA":
        import ipaddress
        data = ipaddress.IPv6Address(rec[1]).packed
    elif t == "CNAME":
        data = enc(rec[1])
    elif t == "MX":
        data = struct.pack("!H", rec[1]) + enc(rec[2])
    return enc(owner) + struct.pack("!HHIH", TYPES[t], 1, 60, len(data)) + data


def main():
    cfg = json.load(open(sys.argv[1]))
    zone = {k.lower().rstrip("."): v for k, v in cfg.get("zone", {}).items()}
    cname_only = {x.lower() for x in cfg.get("cname_only", [])}
    behave = {k.lower(): v for k, v in cfg.get("behave", {}).items()}
    logf = open(sys.argv[2], "a", buffering=1)
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.2"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 53
    lock = threading.Lock()

    def answer(buf, proto):
        """-> list of reply packets (possibly empty)."""
        try:
            qid, flags, qd = struct.unpack("!HHH", buf[:6])
            name, off = qname(buf, 12)
            qtype, _qc = struct.unpack("!HH", buf[off:off + 4])
            question = buf[12:off + 4]
        except Exception:
            return []
        with lock:
            logf.write(json.dumps({"t": round(time.time(), 4), "proto": proto, "name": name,
                                   "type": TNAME.get(qtype, str(qtype)), "id": qid}) + "\n")
        b = behave.get(name)
        if b == "drop":
            return []

        def hdr(i, fl, an):
            return struct.pack("!HHHHHH", i, fl, 1, an, 0, 0)
        if b == "servfail":
            return [hdr(qid, 0x8182, 0) + question]
        if b == "refused":
            return [hdr(qid, 0x8185, 0) + question]
        if b == "tc" and proto == "udp":
            return [hdr(qid, 0x8380, 0) + question]
        if b == "badq":
            return [hdr(qid, 0x8180, 0) + enc("x" + name) + question[-4:]]
        if b == "ptrloop":
            loop = struct.pack("!H", 0xC000 | (12 + len(question)))      # points at itself
            return [hdr(qid, 0x8180, 1) + question + loop + struct.pack("!HHIH", qtype, 1, 60, 4) + b"\x7f\0\0\1"]
        answers, cur, rcode = [], name, 0
        for _ in range(16):
            recs = zone.get(cur)
            if recs is None:
                rcode = 3
                break
            want = [r for r in recs if TYPES[r[0]] == qtype]
            if want:
                answers += [rr(cur, r) for r in want]
                break
            cn = [r for r in recs if r[0] == "CNAME"]
            if not cn:
                break
            answers.append(rr(cur, cn[0]))
            if cur in cname_only:
                break
            cur = cn[0][1].lower().rstrip(".")
        good = hdr(qid, 0x8180 | rcode, len(answers)) + question + b"".join(answers)
        if b == "badid":
            return [hdr(qid ^ 0x5555, 0x8180, 0) + question]
        if b == "badid-then-good":
            return [hdr(qid ^ 0x5555, 0x8180, 0) + question, good]
        return [good]

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))
        while True:
            buf, peer = s.recvfrom(4096)
            for pkt in answer(buf, "udp"):
                s.sendto(pkt, peer)

    def tcp_conn(c):
        try:
            c.settimeout(10)
            ln = struct.unpack("!H", c.recv(2))[0]
            buf = b""
            while len(buf) < ln:
                d = c.recv(ln - len(buf))
                if not d:
                    return
                buf += d
            for pkt in answer(buf, "tcp")[-1:]:
                c.sendall(struct.pack("!H", len(pkt)) + pkt)
        except Exception:
            pass
        finally:
            c.close()

    def tcp():
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((host, port))
        ls.listen(16)
        while True:
            c, _ = ls.accept()
            threading.Thread(target=tcp_conn, args=(c,), daemon=True).start()

    threading.Thread(target=tcp, daemon=True).start()
    udp()


if __name__ == "__main__":
    main()
