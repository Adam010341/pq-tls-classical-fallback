#!/usr/bin/env python3
"""mxlist.py: turn a domain list into a deduplicated MX host list, the --targets of `run.py --proto smtp`.

  python3 -I mxlist.py --domains FILE --out FILE [--resolver system|A.B.C.D] [--rate R] [--workers N] [--timeout S]
                       [--retries N] [--all-preferences] [--map FILE] [--exclude-file FILE] [--real]

DNS only, nothing else: one MX question per domain (plus CNAME re-queries and retries) to ONE recursive resolver, with
kit-c's stdlib client (dnsclient.py; RD=1, random id, id and question checked, TC=1 -> TCP, CNAME chains of at most 8
steps). No A/AAAA lookup, no connection to any mail server. --resolver system = the first IPv4 nameserver in
/etc/resolv.conf (MX cannot be asked through getaddrinfo).

Safety: it refuses to run (exit 6) unless it is inside a network namespace whose only interface is loopback and no host
resolver socket is visible, the same test run.py applies to an unguarded run. --real lifts that refusal for the one
real run (it is never used in the tests outside such a namespace). --rate (default and maximum 20) bounds the packets
sent per second (sliding 1 s window). Excluded domains (--exclude-file, default the kit's exclude.txt, same syntax as
run.py) are never looked up.

Input: --domains, a ranked list as run.py reads it ("name" per line or Tranco "rank,name"; '#' comments).
Selection: for each domain the MX records at the lowest preference (all preferences with --all-preferences); a null MX
(RFC 7505: one record with exchange ".") gives no host; a domain without MX gives no host (no implicit-MX fallback to
the domain's address: a web host is not assumed to be a mail server). Host names are lower-cased without the trailing
dot; names run.py would call invalid are dropped and counted.
Output: --out, one MX host name per line, each once, in the order of first appearance (domains in input order, within
a domain by preference, then name); --out.sha256 in `sha256sum` format; --map (optional) a TSV
"rank domain status preference mx" with one line per MX record (or one line with "-" when there is none).
Neither --out, --out.sha256 nor --map may exist already (nothing is overwritten). A summary goes to stderr and a
"MXLIST-JSON {...}" line to stdout. Exit 0 done, 2 usage, 6 refused (not isolated).
"""
import argparse, collections, concurrent.futures, hashlib, importlib.util, ipaddress, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
RATE_MAX = 20.0


def load(name, fn):
    sys.dont_write_bytecode = True              # no __pycache__ in the kit directory
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, fn))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class StampLimiter:
    """dnsclient.Limiter that also keeps the send times (for the summary's busiest-second figure)."""
    def __init__(self, D, rate):
        self.lim = D.Limiter(rate)
        self.stamps = []

    def wait(self):
        self.lim.wait()
        self.stamps.append(time.monotonic())


def busiest(ts):
    ts = sorted(ts)
    best = j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] >= 1.0:
            j += 1
        best = max(best, i - j + 1)
    return best


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--domains", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--map", default=None)
    ap.add_argument("--resolver", default="system")
    ap.add_argument("--rate", type=float, default=RATE_MAX, help="packets per second, at most 20")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=6.0, help="seconds per lookup attempt")
    ap.add_argument("--retries", type=int, default=3, help="attempts per domain (timeouts, SERVFAIL, REFUSED, errors)")
    ap.add_argument("--all-preferences", action="store_true")
    ap.add_argument("--exclude-file", default=os.path.join(HERE, "exclude.txt"))
    ap.add_argument("--real", action="store_true", help="allow running outside a loopback-only network namespace")
    a = ap.parse_args()
    R = load("kitc_run_for_mxlist", "run.py")
    D = load("kitc_dnsclient_for_mxlist", "dnsclient.py")
    if not 0 < a.rate <= RATE_MAX:
        ap.error(f"--rate must be in (0, {RATE_MAX:g}]")
    if not (1 <= a.workers <= 32 and 1 <= a.retries <= 5 and 0 < a.timeout <= 30):
        ap.error("--workers 1..32, --retries 1..5, --timeout (0, 30]")
    for p in (a.out, a.out + ".sha256", a.map):
        if p and os.path.lexists(p):
            ap.error(f"{p} exists; nothing is overwritten")
    isolated = R.only_loopback_interfaces() and not any(os.path.exists(p) for p in R.RESOLVED_SOCKETS)
    if not isolated and not a.real:
        print("REFUSED: mxlist.py sends real DNS queries only with --real; without it, it runs only inside a network "
              f"namespace with loopback only and no host resolver socket (interfaces "
              f"{[n for _, n in __import__('socket').if_nameindex()]}).", file=sys.stderr)
        return 6
    if a.resolver == "system":
        server = D.system_resolver()
        if server is None:
            print("REFUSED: no IPv4 nameserver in /etc/resolv.conf", file=sys.stderr)
            return 2
    else:
        try:
            server = str(ipaddress.IPv4Address(a.resolver))
            if server != a.resolver:
                raise ValueError
        except ValueError:
            ap.error(f"--resolver must be 'system' or one IPv4 address, got {a.resolver!r}")
    try:
        excl = R.Exclusions(a.exclude_file) if a.exclude_file else R.Exclusions("")
    except (OSError, ValueError) as e:
        print(f"REFUSED: exclusion file: {e}", file=sys.stderr)
        return 2
    ranked = R.read_targets(a.domains)
    lim = StampLimiter(D, a.rate)
    cl = D.Client(server, limiter=lim)

    def lookup(rd):
        rank, dom = rd
        if not R.valid_name(dom):
            return rank, dom, "invalid", []
        if excl.name_excluded(dom):
            return rank, dom, "excluded", []
        r = None
        for attempt in range(a.retries):
            r = cl.resolve(dom, "MX", a.timeout)
            if r.status == "ok" or r.status in D.DEFINITIVE:
                break
            if attempt + 1 < a.retries:
                time.sleep(1.0 + attempt)
        return rank, dom, r.status, r.records

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        res = list(ex.map(lookup, ranked))
    hosts, seen, maplines = [], set(), []
    st = collections.Counter()
    bad_mx = dup = 0
    for rank, dom, status, recs in res:
        if status == "ok":
            real = [(p, h) for p, h in recs if h != ""]
            if not real:
                status = "nullmx"
            recs = sorted(real)
        st[status] += 1
        if status != "ok":
            maplines.append(f"{rank}\t{dom}\t{status}\t-\t-")
            continue
        low = min(p for p, _ in recs)
        for p, h in recs:
            h = R.norm_name(h)
            maplines.append(f"{rank}\t{dom}\tok\t{p}\t{h}")
            if not a.all_preferences and p != low:
                continue
            if not R.valid_name(h):
                bad_mx += 1
            elif h in seen:
                dup += 1
            else:
                seen.add(h)
                hosts.append(h)
    data = "".join(h + "\n" for h in hosts).encode()
    tmp = a.out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, a.out)
    digest = hashlib.sha256(data).hexdigest()
    with open(a.out + ".sha256", "w") as f:
        f.write(f"{digest}  {os.path.basename(a.out)}\n")
    if a.map:
        with open(a.map, "w") as f:
            f.write("".join(l + "\n" for l in maplines))
    summ = {"domains": len(ranked), "status": dict(sorted(st.items())), "mx_hosts": len(hosts), "mx_duplicates": dup,
            "mx_invalid": bad_mx, "packets_sent": cl.sent, "packets_tcp": cl.sent_tcp, "replies_ignored": cl.ignored,
            "busiest_second": busiest(lim.stamps), "rate_limit": a.rate, "resolver": server, "seconds": round(time.time() - t0, 1),
            "out": a.out, "sha256": digest, "all_preferences": a.all_preferences, "real": a.real}
    print(f"mxlist: {len(ranked)} domains -> {len(hosts)} MX hosts ({dup} duplicates, {bad_mx} invalid names); lookups "
          f"{dict(sorted(st.items()))}; {cl.sent} packets to {server} (TCP {cl.sent_tcp}), busiest second "
          f"{summ['busiest_second']} (limit {a.rate:g}); {a.out} sha256 {digest}", file=sys.stderr)
    print("MXLIST-JSON " + json.dumps(summ, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
