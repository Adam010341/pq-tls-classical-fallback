#!/usr/bin/env python3
"""dnsclient.py: minimal stub DNS client for kit-c (Python standard library only; the scan machines have no dnspython).

Used by `run.py --resolver ADDRESS` (A / AAAA) and by `mxlist.py` (MX). It sends questions to ONE recursive resolver
(an IPv4 address, port 53) and to nothing else; it never contacts an authoritative server itself.

Query: one question, RD=1, class IN, no EDNS, a random 16-bit id (secrets.randbits) from a fresh UDP socket (random
source port chosen by the kernel). The socket is connect()ed to the resolver, so the kernel drops datagrams from any
other address. A reply is accepted only if its id equals the query id, QR=1, opcode 0, QDCOUNT=1 and its question
(name, type, class) equals ours (name compared case-insensitively); anything else (wrong id, wrong question, malformed
packet, compression-pointer loop) is ignored and counted in `ignored`, and the client keeps waiting until the deadline.
TC=1 in a valid UDP reply: the same question is asked again over TCP (2-byte length prefix) and that answer is used.

resolve(name, type, timeout): follows CNAME records in the answer section starting at the queried name (owner names
compared case-insensitively; records whose owner is not on the chain are ignored). When a NOERROR answer ends the chain
at a name without records of the wanted type, that name is queried again (the resolver did not include the target).
At most MAX_CNAME CNAME steps; a name seen twice is a loop. Every packet sent (UDP, TCP, CNAME re-queries) shares one
deadline of `timeout` seconds. Outcomes (Result.status):
  ok             records of the wanted type at the end of the chain (Result.records: addresses as strings, or
                 (preference, exchange) for MX; the root "" is a null MX)
  nxdomain       RCODE 3            nodata    NOERROR without such records      servfail  RCODE 2
  refused        RCODE 5            error     other RCODE, ICMP unreachable, TCP failure, unusable name
  timeout        no acceptable reply before the deadline
  cname-loop     a CNAME chain that returns to a name already on it
  cname-too-long more than MAX_CNAME CNAME steps
DEFINITIVE = statuses that a retry would not change (nxdomain, nodata, cname-loop, cname-too-long); callers retry only
the others. A shared Limiter (optional) bounds the packets sent per second over all threads.
"""
import collections, ipaddress, secrets, socket, struct, threading, time

QTYPE = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15}
MAX_CNAME = 8
DEFINITIVE = ("nxdomain", "nodata", "cname-loop", "cname-too-long")
RCODE = {0: "nodata", 2: "servfail", 3: "nxdomain", 5: "refused"}

Result = collections.namedtuple("Result", "status records chain queries")


class Mismatch(Exception):
    """A reply that is not the answer to our question (wrong id, wrong question, not a response)."""


class Limiter:
    """Thread-safe: at most `rate` packets in any sliding 1 s window and at least 1/rate s between two packets."""
    def __init__(self, rate):
        self.iv = 1.0 / rate
        self.n = max(1, int(rate))
        self.win = collections.deque(maxlen=self.n)
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            t = max(self.next, time.monotonic())
            if len(self.win) == self.n:
                t = max(t, self.win[0] + 1.001)
            d = t - time.monotonic()
            if d > 0:
                time.sleep(d)
            now = time.monotonic()
            self.win.append(now)
            self.next = now + self.iv


def norm(name):
    return name.strip().lower().rstrip(".")


def encode_name(name):
    out = b""
    n = norm(name)
    if n:
        for lab in n.split("."):
            b = lab.encode("ascii")
            if not 0 < len(b) < 64:
                raise ValueError(f"bad label in {name!r}")
            out += bytes([len(b)]) + b
    if len(out) + 1 > 255:
        raise ValueError(f"name too long: {name!r}")
    return out + b"\0"


def build_query(qid, name, qtype):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def read_name(buf, off):
    """-> (lower-case name without trailing dot, offset after the name). Follows compression pointers (at most 32)."""
    labels, jumps, end, total = [], 0, None, 0
    while True:
        if off >= len(buf):
            raise ValueError("name runs past the end of the packet")
        n = buf[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("cut compression pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 32 or ptr >= len(buf):
                raise ValueError("compression pointer loop or out of range")
            off = ptr
            continue
        if n & 0xC0:
            raise ValueError("unknown label type")
        off += 1
        if n == 0:
            break
        if off + n > len(buf):
            raise ValueError("label runs past the end of the packet")
        labels.append(buf[off:off + n].decode("ascii", "replace").lower())
        total += n + 1
        if total > 255:
            raise ValueError("name longer than 255 octets")
        off += n
    return ".".join(labels), (end if end is not None else off)


def parse_response(buf, qid, qname, qtype):
    """-> (rcode, tc, answers [(owner, type, data)]). Raises Mismatch or ValueError for a packet that is not usable."""
    if len(buf) < 12:
        raise ValueError("short packet")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    if rid != qid:
        raise Mismatch(f"id {rid} != {qid}")
    if not flags & 0x8000 or (flags >> 11) & 0xF:
        raise Mismatch("not a standard query response")
    if qd != 1:
        raise Mismatch(f"QDCOUNT {qd}")
    name, off = read_name(buf, 12)
    if off + 4 > len(buf):
        raise ValueError("cut question")
    qt, qc = struct.unpack("!HH", buf[off:off + 4])
    off += 4
    if name != norm(qname) or qt != qtype or qc != 1:
        raise Mismatch(f"question {name!r}/{qt}/{qc} is not {norm(qname)!r}/{qtype}/1")
    tc, rcode = bool(flags & 0x0200), flags & 0xF
    if tc:
        return rcode, True, []
    answers = []
    for _ in range(an):
        owner, off = read_name(buf, off)
        if off + 10 > len(buf):
            raise ValueError("cut resource record")
        t, c, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        if off + rdlen > len(buf):
            raise ValueError("cut rdata")
        rd = buf[off:off + rdlen]
        if c == 1:
            if t == 1 and rdlen == 4:
                answers.append((owner, 1, str(ipaddress.IPv4Address(rd))))
            elif t == 28 and rdlen == 16:
                answers.append((owner, 28, str(ipaddress.IPv6Address(rd))))
            elif t == 5:
                answers.append((owner, 5, read_name(buf, off)[0]))
            elif t == 15 and rdlen >= 3:
                answers.append((owner, 15, (struct.unpack("!H", rd[:2])[0], read_name(buf, off + 2)[0])))
        off += rdlen
    return rcode, False, answers


class Client:
    def __init__(self, server, limiter=None, port=53):
        self.server = str(ipaddress.IPv4Address(server))
        self.port = port
        self.limiter = limiter
        self.lock = threading.Lock()
        self.sent = self.sent_tcp = self.ignored = 0

    def _count(self, **kw):
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)

    def _send_gate(self):
        if self.limiter is not None:
            self.limiter.wait()

    def _udp(self, wire, qid, qname, qtype, deadline):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((self.server, self.port))
            self._send_gate()
            s.send(wire)
            self._count(sent=1)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return "timeout"
                s.settimeout(left)
                try:
                    buf = s.recv(65535)
                except socket.timeout:
                    return "timeout"
                except OSError:                       # ICMP port/host unreachable on the connected socket
                    return "error"
                try:
                    return parse_response(buf, qid, qname, qtype)
                except (Mismatch, ValueError, IndexError, struct.error):
                    self._count(ignored=1)
        finally:
            s.close()

    def _tcp(self, wire, qid, qname, qtype, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            return "timeout"
        self._send_gate()
        try:
            s = socket.create_connection((self.server, self.port), timeout=left)
        except socket.timeout:
            return "timeout"
        except OSError:
            return "error"
        try:
            s.sendall(struct.pack("!H", len(wire)) + wire)
            self._count(sent=1, sent_tcp=1)

            def recv_exact(n):
                b = b""
                while len(b) < n:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise socket.timeout()
                    s.settimeout(left)
                    d = s.recv(n - len(b))
                    if not d:
                        raise ConnectionError("closed")
                    b += d
                return b
            try:
                (ln,) = struct.unpack("!H", recv_exact(2))
                buf = recv_exact(ln)
            except socket.timeout:
                return "timeout"
            except OSError:
                return "error"
            try:
                rcode, _tc, ans = parse_response(buf, qid, qname, qtype)
            except (Mismatch, ValueError, IndexError, struct.error):
                self._count(ignored=1)
                return "error"
            return rcode, False, ans
        finally:
            s.close()

    def query(self, name, qtype, deadline):
        """One question (UDP, then TCP if the reply has TC=1) -> (rcode, tc, answers) or 'timeout' / 'error'."""
        qid = secrets.randbits(16)
        try:
            wire = build_query(qid, name, qtype)
        except (ValueError, UnicodeError):
            return "error"
        r = self._udp(wire, qid, name, qtype, deadline)
        if isinstance(r, tuple) and r[1]:
            qid = secrets.randbits(16)
            r = self._tcp(build_query(qid, name, qtype), qid, name, qtype, deadline)
        return r

    def resolve(self, name, qtype_name, timeout):
        qtype = QTYPE[qtype_name]
        deadline = time.monotonic() + timeout
        cur = norm(name)
        seen, chain, queries = {cur}, [], 0
        while True:
            asked = cur
            r = self.query(cur, qtype, deadline)
            queries += 1
            if isinstance(r, str):
                return Result(r, [], chain, queries)
            rcode, _tc, ans = r
            while True:
                recs = [d for o, t, d in ans if o == cur and t == qtype]
                if recs and rcode == 0:
                    out = []
                    for d in recs:
                        if d not in out:
                            out.append(d)
                    return Result("ok", sorted(out) if qtype != 15 else sorted(out, key=lambda x: (x[0], x[1])), chain, queries)
                cn = [d for o, t, d in ans if o == cur and t == 5]
                if not cn:
                    break
                nxt = cn[0]
                if nxt in seen:
                    return Result("cname-loop", [], chain + [nxt], queries)
                if len(chain) >= MAX_CNAME:
                    return Result("cname-too-long", [], chain, queries)
                chain.append(nxt)
                seen.add(nxt)
                cur = nxt
            if rcode == 0 and cur != asked:
                continue                                  # the chain ended at a name we have not asked about yet
            return Result(RCODE.get(rcode, "error"), [], chain, queries)


def system_resolver(path="/etc/resolv.conf"):
    """First IPv4 'nameserver' in resolv.conf (for mxlist.py --resolver system), or None."""
    try:
        for line in open(path):
            p = line.split()
            if len(p) >= 2 and p[0] == "nameserver":
                try:
                    return str(ipaddress.IPv4Address(p[1]))
                except ValueError:
                    continue
    except OSError:
        pass
    return None
