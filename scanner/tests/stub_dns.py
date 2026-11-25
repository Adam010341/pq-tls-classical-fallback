#!/usr/bin/env python3
"""Tiny authoritative-style stub DNS server for the kit-c tests (UDP, stdlib only). Test use only, inside a network
namespace that has nothing but loopback.

  stub_dns.py <table.json> <query-log> [listen-ip] [port]

table.json: {"name": ["127.0.0.1", "::1", ...], ...}. A queries get the IPv4 entries, AAAA queries the IPv6 entries;
an unknown name gets NXDOMAIN, a known name without records of that type an empty NOERROR answer. Every query is
appended to <query-log> as "name<TAB>type" before it is answered, so tests can prove which names were looked up.
"""
import ipaddress, json, socket, struct, sys


def qname(buf, off):
    labels = []
    while True:
        n = buf[off]
        off += 1
        if n == 0:
            return ".".join(labels).lower(), off
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n


def main():
    table = {k.lower().rstrip("."): v for k, v in json.load(open(sys.argv[1])).items()}
    logf = open(sys.argv[2], "a", buffering=1)
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 53
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        buf, peer = s.recvfrom(4096)
        try:
            qid, flags, qd = struct.unpack("!HHH", buf[:6])
            name, off = qname(buf, 12)
            qtype, qclass = struct.unpack("!HH", buf[off:off + 4])
            question = buf[12:off + 4]
        except Exception:
            continue
        tname = {1: "A", 28: "AAAA"}.get(qtype, str(qtype))
        logf.write(f"{name}\t{tname}\n")
        answers = []
        rcode = 0
        if name not in table:
            rcode = 3
        else:
            for a in table[name]:
                ip = ipaddress.ip_address(a)
                if (qtype == 1 and ip.version == 4) or (qtype == 28 and ip.version == 6):
                    answers.append(struct.pack("!HHHIH", 0xC00C, qtype, 1, 60, len(ip.packed)) + ip.packed)
        hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0)
        s.sendto(hdr + question + b"".join(answers), peer)


if __name__ == "__main__":
    main()
