#!/usr/bin/env python3
"""kit-c scanner: rate-limited, resumable TLS 1.3 key-share probes.

Nothing here runs by itself. A real run
(any non-loopback address) is only possible when started by guard.py after its pre-flight checks and the operator's
--go phrase; started directly, run.py connects to loopback addresses only (see "Unguarded mode" below).

Probes (every probe: one TLS 1.3 handshake with `openssl s_client`, 12 s timeout, no retry, zero bytes of
application data, close_notify; quic: --quic-timeout, CONNECTION_CLOSE):
  P1  -groups '*X25519MLKEM768:*X25519'   every target with an address        -> PQ-capable if it selects X25519MLKEM768
  P2  -groups 'X25519MLKEM768:*X25519'    PQ-capable targets only
  P3  -groups '*X25519:X25519MLKEM768'    PQ-capable targets only (all of them; no longer a 200-name sample)
  PA  -groups '*X25519:*X25519MLKEM768'   PQ-capable targets only (Fall's "Preference A")
A target is one (name, address family) in the default pinned mode, one (name, address) in --mode alladdr.
Cap: at most --cap (default and maximum 4) handshakes per target, counted in the probe function itself; there are no
retries. The count is kept per (name, address) and, in pinned mode, also per (name, family), so a target whose address
changed between two invocations still gets at most --cap in total. --max-per-name N (optional) caps the total over all
targets of one SNI name (both families / all addresses).

Protocol:
  --proto https       (default) TLS directly on port 443 with probe_one.sh, as before
  --proto smtp        SMTP STARTTLS on port 25 with probe_smtp.sh (`s_client -starttls smtp -name <--ehlo-name>`); SNI =
                      the MX host name being probed; --targets is a list of MX host names (mxlist.py); the probe set,
                      caps, kill switch, exclusions, rate limit, breaker and resume are the same. Needs --ehlo-name
                      (a host name that identifies the scanner). --smtp-timeout S (default 30, 12..60) bounds each
                      exchange including the greeting; --per-ip-cap N (default 8, 1..8) caps the handshakes per
                      address over the whole campaign (many MX names share the addresses of large providers); www add
                      and alladdr mode are refused. In https mode --per-ip-cap is 0 (off) unless given.
  --proto quic        QUIC (HTTP/3 ALPN h3) on UDP port 443 with probe_quic.sh (`s_client -quic -alpn h3`); SNI = the
                      target name; --targets is an explicit name list (quic_targets.py: the names whose P1 selected
                      X25519MLKEM768 in a finished https run); the probe set, caps, kill switch, exclusions, rate limit,
                      breaker and resume are the same. --quic-timeout S (default 8, 5..12) bounds each probe; inside it
                      probe_quic.sh also stops s_client after 40 sent datagrams or 1 MiB of trace. No per-IP cap (as
                      https: CDN addresses serve many names); www add and alladdr mode are refused.

Targets:
  --targets FILE      ranked list: one name per line (rank = line number) or "rank,name" (Tranco CSV); '#' comments
  --www off|add       add: also probe "www.<name>" as a separate target (not for names that already start with www.;
                      a derived www name that is itself on the list is probed once, as listed)
  --families 4|6|4,6  A and/or AAAA; in pinned mode each family is pinned to ONE address chosen with
                      random.Random("<seed>:<name>") for IPv4 (identical to campaign 2) and "<seed>:<name>:6" for IPv6
  --mode pinned|alladdr
                      alladdr: for the names in --targets (a sample file), every A/AAAA address is a target; P1 to each,
                      P2 to each address whose P1 selected X25519MLKEM768, never P3/PA; cap counted per address;
                      at most --max-addrs addresses per name and family (seeded sample if more)

Controls:
  --rate R            global limit on handshake starts, default 18/s, maximum 20; spacing >= 1/R and never more than R
                      starts in any sliding 1 s window
  kill switch         a file named STOP in --out stops new handshakes at once (checked before every start)
  circuit breaker     after --breaker-min-probes (400) handshakes, if fewer than --breaker-min-rate (3%) of the last
                      --breaker-window (200) completed: write STOP and stop
  --exclude-file F    exact names, "*.suffix" (the suffix itself and every name below it), IPv4/IPv6 addresses and CIDR
                      blocks; a derived www target is excluded when its listed name is. Names are checked BEFORE
                      resolution (an excluded name is never looked up) and names and addresses again before EVERY
                      probe. The file is re-read when it changes during a run; if it becomes unreadable or invalid the
                      run stops (STOP). An invalid file at start: exit 2, nothing done.
  --max-minutes M     the scanner writes STOP itself after M minutes (the guard's watchdog does the same, independently)
  non-global          addresses that are not globally routable (private, loopback, link-local, ...) are never probed in
                      a real run (row "nonglobal"); tests use --allow-nonglobal or --resolve-file
  --dry-run           reads targets and exclusions, prints the plan (targets, expected handshakes per probe, duration at
                      --rate); no DNS lookup, no connection, no file written
  --estimate N        the same plan for N names without a file
  plan assumptions    --assume-reachable r (share of targets that get P1 = have an address; default 0.84 = campaign 2
                      top 10k), --assume-pq q (share of targets that are PQ-capable; default 0.45 = campaign 2),
                      --assume-reachable6/--assume-pq6 (IPv6; default = IPv4 values), --assume-addrs (alladdr mode,
                      mean addresses per name and family, default 2)

Resolver:
  --resolver system   (default) getaddrinfo with the system resolver, as before
  --resolver A.B.C.D  kit-c's stdlib DNS client (dnsclient.py) asks that recursive resolver (RD=1, UDP, TCP after TC=1,
                      CNAME chains followed, at most 8 steps); --dns-retries attempts of at most 6 s each, at most
                      --dns-concurrency lookups at a time, retried only on timeout / SERVFAIL / REFUSED / error (NXDOMAIN,
                      no data and CNAME loops are final); every outcome without an address is the row "noaddr", as
                      today. Recorded as "resolver" in run-meta.json.

Unguarded mode (run.py started without guard.py): every address to be probed must be loopback, otherwise the run
writes STOP and exits 6 before connecting; real DNS lookups are allowed only inside a network namespace whose only
interface is loopback. --resolve-file FILE (tests): lines "name<TAB>addr[,addr...]", addr = - | IPv4[:port] | IPv6 |
[IPv6]:port; replaces DNS.

Output (DIR = --out): results.tsv, one row per target, tab-separated, no header:
  1 host  2 ip  3 n_ips  4 p1  5 p2  6 p3  7 t_start  8 t_end  9 flag  10 pa  11 family  12 variant  13 rank  14 mode
  (columns 1-9 as in campaign 2's results-final.tsv; cells "ok|ch=..|hrr=..|sh=..|grp=.." or skip / noaddr /
  nonglobal / excluded / invalid / capped / stopped); probes.log (start time, name, label, ip, port of every
  handshake); traces.jsonl.xz (raw s_client traces, one JSON line per handshake with t = start time and dur_ms = wall
  time of the probe process in ms, appended as independent xz streams of <= 256 traces; private); run-meta.json; run.log. Exit codes: 0 done, 2 usage/refusal, 6 unguarded refusal, 7 exclusion
  file became invalid during the run.

Resume: every invocation appends to the files in --out, skips targets that already have a row in results.tsv (partial
rows included) and counts every handshake in probes.log against the caps, so a target whose handshakes started but whose
row was never written is probed again only up to the remaining cap. Each probes.log line is fsync'ed before its
handshake starts. A last line cut short by a crash is repaired at start: in probes.log it is terminated (and still
counts); in results.tsv it is moved to results.torn.tsv. --resume (passed by guard.py run --resume) records
start_kind RESUME and the rows and handshakes already present in run-meta.json and run.log.
"""
import argparse, asyncio, collections, hashlib, ipaddress, json, lzma, math, os, random, re, secrets, signal, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "probe_one.sh")
PROBE_SMTP = os.path.join(HERE, "probe_smtp.sh")
PROBE_QUIC = os.path.join(HERE, "probe_quic.sh")
PORTS = {"https": 443, "smtp": 25, "quic": 443}       # quic: UDP
SMTP_TIMEOUT_DEFAULT, SMTP_TIMEOUT_MIN, SMTP_TIMEOUT_MAX = 30.0, 12.0, 60.0
QUIC_TIMEOUT_DEFAULT, QUIC_TIMEOUT_MIN, QUIC_TIMEOUT_MAX = 8.0, 5.0, 12.0
PER_IP_CAP_MAX = 8
G = {"p1": "*X25519MLKEM768:*X25519", "p2": "X25519MLKEM768:*X25519", "p3": "*X25519:X25519MLKEM768",
     "pa": "*X25519:*X25519MLKEM768"}
PQ_GROUP = "X25519MLKEM768"
PQ_FOLLOWUPS = ("p2", "p3", "pa")
FAIL = "fail|ch=0|hrr=0|sh=0|grp=-"
CAP_MAX = 4
RATE_MAX = 20.0
RATE_DEFAULT = 18.0
DEFAULT_OPENSSL = "openssl"
NAME_RE = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+")
RESOLVED_SOCKETS = ("/run/systemd/resolve/io.systemd.Resolve", "/run/nscd/socket")
DNS_ATTEMPT_SECONDS = 6.0          # one lookup attempt, as asyncio.wait_for(getaddrinfo, 6) in the system path


def load_dnsclient():
    """dnsclient.py of this kit (run.py runs with -I, so the kit directory is not on sys.path); no __pycache__ in the kit."""
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("kitc_dnsclient", os.path.join(HERE, "dnsclient.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Refusal(Exception):
    pass


def parse(tok):
    d = {"st": tok.split("|")[0]}
    for kv in tok.split("|")[1:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            d[k] = v
    return d


def is_pq(tok):
    d = parse(tok)
    return d["st"] == "ok" and d.get("grp") == PQ_GROUP


# ----------------------------------------------------------------------------------------------------------- targets
def norm_name(s):
    return s.strip().lower().rstrip(".")


def valid_name(n):
    if not NAME_RE.fullmatch(n):
        return False
    try:
        ipaddress.ip_address(n)
        return False
    except ValueError:
        pass
    return not n.replace(".", "").isdigit()


def read_targets(path):
    """Ranked list -> [(rank, name)] in file order. 'name' per line (rank = line number among entries) or 'rank,name'."""
    out, seen, i = [], set(), 0
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            i += 1
            if "," in line:
                r, _, n = line.partition(",")
                if not r.strip().isdigit():          # header line such as "rank,domain"
                    i -= 1
                    continue
                rank = int(r)
            else:
                rank, n = i, line
            n = norm_name(n)
            if n in seen:
                continue
            seen.add(n)
            out.append((rank, n))
    return out


def expand(ranked, www):
    """-> [(name, listed_name, variant, rank)]; variant 'list' or 'www'."""
    listed = {n for _, n in ranked}
    out = []
    for rank, n in ranked:
        out.append((n, n, "list", rank))
        if www == "add" and valid_name(n) and not n.startswith("www."):
            w = "www." + n
            if w not in listed:
                out.append((w, n, "www", rank))
    return out


# ----------------------------------------------------------------------------------------------------------- exclusions
def parse_exclusions(path):
    names, suffixes, nets = set(), set(), []
    with open(path) as f:
        for no, raw in enumerate(f, 1):
            l = raw.split("#", 1)[0].strip().lower()
            if not l:
                continue
            if l.startswith("*."):
                s = norm_name(l[2:])
                if not (valid_name(s) or re.fullmatch(r"[a-z0-9-]{1,63}", s)):
                    raise ValueError(f"{path}:{no}: bad suffix entry {raw.strip()!r}")
                suffixes.add(s)
                continue
            try:
                nets.append(ipaddress.ip_network(l, strict=False))
                continue
            except ValueError:
                pass
            n = norm_name(l)
            if not valid_name(n):
                raise ValueError(f"{path}:{no}: not a name, *.suffix, address or CIDR: {raw.strip()!r}")
            names.add(n)
    return names, suffixes, nets


class Exclusions:
    def __init__(self, path):
        self.path = path
        self.sig = None
        self.names, self.suffixes, self.nets = set(), set(), []
        self.reloads = 0
        if path:
            self.names, self.suffixes, self.nets = parse_exclusions(path)
            self.sig = self._sig()

    def _sig(self):
        st = os.stat(self.path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def refresh(self):
        """Re-read the file if it changed. Raises (-> run stops) if it became unreadable or invalid."""
        if not self.path:
            return False
        s = self._sig()
        if s == self.sig:
            return False
        self.names, self.suffixes, self.nets = parse_exclusions(self.path)
        self.sig = s
        self.reloads += 1
        return True

    def name_excluded(self, name, listed=None):
        for n in {norm_name(name), norm_name(listed or name)}:
            if n in self.names:
                return True
            if any(n == s or n.endswith("." + s) for s in self.suffixes):
                return True
        return False

    def ip_excluded(self, ip):
        a = ipaddress.ip_address(ip)
        return any(a.version == n.version and a in n for n in self.nets)

    def count(self):
        return len(self.names) + len(self.suffixes) + len(self.nets)


# ----------------------------------------------------------------------------------------------------------- plan
def plan(n_names, a, n_targets=None, n_excluded=0):
    """Expected handshakes. n_targets: number of (name) targets after www expansion and name exclusion; if None it is
    derived from n_names and --www with the assumption that every name gets a www variant."""
    fams = families(a.families)
    if n_targets is None:
        n_targets = n_names * (2 if a.www == "add" else 1)
    per = {}
    tot = {"p1": 0.0, "p2": 0.0, "p3": 0.0, "pa": 0.0}
    upper = 0
    for fam in fams:
        r = a.assume_reachable if fam == 4 or a.assume_reachable6 is None else a.assume_reachable6
        q = a.assume_pq if fam == 4 or a.assume_pq6 is None else a.assume_pq6
        if a.mode == "alladdr":
            k = a.assume_addrs
            d = {"p1": n_targets * r * k, "p2": n_targets * q * k, "p3": 0.0, "pa": 0.0}
            upper += n_targets * a.max_addrs * 2          # every address PQ-capable: P1 + P2 per address
        else:
            d = {"p1": n_targets * r, "p2": n_targets * q, "p3": n_targets * q, "pa": n_targets * q}
            upper += n_targets * a.cap
        per[f"ipv{fam}"] = {k2: round(v) for k2, v in d.items()} | {"reachable_share": r, "pq_share": q}
        for k2 in tot:
            tot[k2] += d[k2]
    total = sum(tot.values())
    per_name = (a.cap if a.mode == "pinned" else 2 * a.max_addrs) * len(fams) * (2 if a.www == "add" else 1)
    if a.max_per_name:
        per_name = min(per_name, a.max_per_name)
    return {"names": n_names, "names_excluded": n_excluded, "targets_per_family": n_targets, "families": fams,
            "www": a.www, "mode": a.mode, "proto": a.proto, "rate_per_s": a.rate, "per_family": per,
            "expected": {k: round(v) for k, v in tot.items()}, "expected_total": round(total),
            "expected_seconds": round(total / a.rate, 1), "upper_bound_total": round(upper),
            "upper_bound_seconds": round(upper / a.rate, 1), "max_handshakes_per_listed_name": per_name}


def hms(s):
    s = int(round(s))
    return f"{s // 3600}h{(s % 3600) // 60:02d}m{s % 60:02d}s"


def print_plan(p, title):
    print(title)
    print(f"  names: {p['names']} (targets excluded by name before resolution: {p['names_excluded']}; invalid: "
          f"{p.get('targets_invalid', 0)}); www: {p['www']}; "
          f"families: {','.join('IPv' + str(f) for f in p['families'])}; mode: {p['mode']}")
    print(f"  targets per family: {p['targets_per_family']}")
    for fam, d in p["per_family"].items():
        print(f"  {fam}: assumed reachable share {d['reachable_share']}, PQ-capable share {d['pq_share']} -> "
              f"P1 {d['p1']}, P2 {d['p2']}, P3 {d['p3']}, PA {d['pa']}")
    e = p["expected"]
    print(f"  expected handshakes: P1 {e['p1']} + P2 {e['p2']} + P3 {e['p3']} + PA {e['pa']} = {p['expected_total']}")
    print(f"  expected duration at {p['rate_per_s']:g}/s: {p['expected_seconds']} s ({hms(p['expected_seconds'])}); the rate is a "
          f"ceiling, so the real run takes at least this long")
    print(f"  upper bound (every target reachable and PQ-capable): {p['upper_bound_total']} handshakes, "
          f"{hms(p['upper_bound_seconds'])}")
    print(f"  at most {p['max_handshakes_per_listed_name']} handshakes for any one listed name over all its targets")
    if p["proto"] == "smtp":
        print("  smtp: the duration is a lower bound; slow greetings occupy workers (--workers) for up to --smtp-timeout each")
    if p["proto"] == "quic":
        print("  quic: the duration is a lower bound; a target without QUIC occupies a worker (--workers) for --quic-timeout, "
              "and every completed probe for about 0.6 s")
    print("PLAN-JSON " + json.dumps(p, sort_keys=True))


def families(s):
    out = []
    for x in str(s).split(","):
        x = x.strip()
        if x not in ("4", "6"):
            raise SystemExit(f"--families: {s!r}; use 4, 6 or 4,6")
        if int(x) not in out:
            out.append(int(x))
    return out


# ----------------------------------------------------------------------------------------------------------- environment
def only_loopback_interfaces():
    try:
        return all(n == "lo" for _, n in socket.if_nameindex())
    except OSError:
        return False


def guard_nonce_ok(out):
    n = os.environ.get("KITC_GUARD_NONCE", "")
    try:
        toks = open(os.path.join(out, ".guard.lock")).read().split()
    except OSError:
        return False
    return bool(n) and len(toks) >= 2 and secrets.compare_digest(toks[1], n)


def parse_addr(s):
    """'1.2.3.4' / '1.2.3.4:443' / '::1' / '[::1]:443' -> (ip, port)."""
    s = s.strip()
    if s.startswith("["):
        ip, _, rest = s[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else 443
    elif s.count(":") == 1:
        ip, _, p = s.partition(":")
        port = int(p)
    else:
        ip, port = s, 443
    return str(ipaddress.ip_address(ip)), port


class Limiter:
    """Global start limiter: starts at least 1/rate s apart AND never more than `rate` starts in any sliding 1 s window
    (with 1 ms margin). The sleep happens while holding the lock, so starts are strictly serialised."""
    def __init__(self, rate):
        self.iv = 1.0 / rate
        self.n = max(1, int(math.floor(rate)))
        self.next = 0.0
        self.win = collections.deque(maxlen=self.n)
        self.lock = asyncio.Lock()

    async def wait(self, stopped):
        async with self.lock:
            if stopped():
                return None
            t = max(self.next, time.monotonic())
            if len(self.win) == self.n:
                t = max(t, self.win[0] + 1.001)
            d = t - time.monotonic()
            if d > 0:
                await asyncio.sleep(d)
            if stopped():
                return None
            now = time.monotonic()
            self.win.append(now)
            self.next = now + self.iv
            return time.time()


class KeyedLimiter:
    """Per-address start spacing (1/rate s) and concurrency; both off by default."""
    def __init__(self, rate, conc):
        self.iv = 1.0 / rate if rate > 0 else 0.0
        self.conc = conc
        self.next, self.sems = {}, {}
        self.lock = asyncio.Lock()

    def sem(self, key):
        return None if self.conc <= 0 else self.sems.setdefault(key, asyncio.Semaphore(self.conc))

    async def wait(self, key):
        if self.iv <= 0:
            return
        async with self.lock:
            t = max(self.next.get(key, 0.0), time.monotonic())
            self.next[key] = t + self.iv
        d = t - time.monotonic()
        if d > 0:
            await asyncio.sleep(d)


class TraceStore:
    def __init__(self, out, mode):
        self.mode = mode
        self.tmp = os.path.join(out, ".tmp-traces")
        os.makedirs(self.tmp, exist_ok=True)
        self.dir = os.path.join(out, "traces")
        if mode == "files":
            os.makedirs(self.dir, exist_ok=True)
        self.xz = os.path.join(out, "traces.jsonl.xz")
        self.buf, self.t_flush, self.n = [], time.monotonic(), 0

    def path(self, name, ip, label):
        return os.path.join(self.tmp, f"{secrets.token_hex(8)}.{label}.trace")

    def add(self, name, ip, label, t, tf, dur=None):
        """dur: seconds from just before the probe process starts until it exits (time.monotonic), or None."""
        try:
            txt = open(tf, "rb").read().decode("utf-8", "replace")
        except OSError:
            txt = ""
        self.n += 1
        if self.mode == "files":
            if os.path.exists(tf):
                os.replace(tf, os.path.join(self.dir, f"{name[:180]}.{ip.replace(':', '_')}.{label}.trace"))
            return
        if os.path.exists(tf):
            os.remove(tf)
        if self.mode == "xz":
            rec = {"t": round(t, 3), "host": name, "ip": ip, "label": label, "trace": txt}
            if dur is not None:
                rec["dur_ms"] = round(dur * 1000, 1)   # wall time of the probe process (bash + s_client), to 0.1 ms
            self.buf.append(json.dumps(rec) + "\n")
            if len(self.buf) >= 256 or time.monotonic() - self.t_flush > 30:
                self.flush()

    def flush(self):
        if self.buf:
            with open(self.xz, "ab") as f:
                f.write(lzma.compress("".join(self.buf).encode()))
                f.flush()
                os.fsync(f.fileno())
            self.buf = []
        self.t_flush = time.monotonic()


# ----------------------------------------------------------------------------------------------------------- run
class Run:
    def __init__(self, a, excl, guarded):
        self.a = a
        self.excl = excl
        self.guarded = guarded
        self.stop = False
        self.exit_code = 0
        self.sem = asyncio.Semaphore(a.workers)
        self.lim = Limiter(a.rate)
        self.iplim = KeyedLimiter(a.per_ip_rate, a.per_ip_conc)
        self.dns_sem = asyncio.Semaphore(a.dns_concurrency)
        self.dns = None                             # --resolver system: getaddrinfo, unchanged
        self.dns_status = collections.Counter()
        if a.resolver != "system":
            self.dnsmod = load_dnsclient()
            self.dns = self.dnsmod.Client(a.resolver)
        self.recent = collections.deque(maxlen=a.breaker_window)
        self.count = collections.Counter()          # handshakes per (name, ip), including earlier invocations
        self.count_name = collections.Counter()
        self.count_fam = collections.Counter()      # handshakes per (name, family): the target in pinned mode
        self.count_ip = collections.Counter()       # handshakes per address over all names (--per-ip-cap)
        self.port = PORTS[a.proto]
        plog = os.path.join(a.out, "probes.log")
        if os.path.exists(plog):
            for l in open(plog, errors="replace"):
                p = l.rstrip("\n").split("\t")
                if len(p) >= 4:
                    self.count[(p[1], p[3])] += 1
                    self.count_name[p[1]] += 1
                    self.count_ip[p[3]] += 1
                    try:
                        self.count_fam[(p[1], ipaddress.ip_address(p[3]).version)] += 1
                    except ValueError:
                        pass
        self.handshakes_before = sum(self.count_name.values())
        self.nprobes = self.nrows = 0
        self.t_begin = time.time()
        self.t_mono = time.monotonic()
        self.stopfile = os.path.join(a.out, "STOP")
        self.traces = TraceStore(a.out, a.traces)
        self.plog = open(os.path.join(a.out, "probes.log"), "a", buffering=1)
        self.rlog = open(os.path.join(a.out, "run.log"), "a", buffering=1)
        self.out = open(os.path.join(a.out, "results.tsv"), "a", buffering=1)
        self.override = {}
        if a.resolve_file:
            for l in open(a.resolve_file):
                p = l.rstrip("\n").split("\t")
                if len(p) == 2 and p[0].strip():
                    self.override[norm_name(p[0])] = [] if p[1].strip() == "-" else [parse_addr(x) for x in p[1].split(",") if x.strip()]

    def log(self, msg):
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}"
        self.rlog.write(line + "\n")
        print(line, file=sys.stderr, flush=True)

    def halt(self, reason, code=None):
        if not self.stop:
            self.log(f"STOP: {reason}")
        self.stop = True
        if code is not None:
            self.exit_code = code
        if not os.path.exists(self.stopfile):
            with open(self.stopfile, "w") as f:
                f.write(reason + "\n")

    def should_stop(self):
        if self.stop:
            return True
        if os.path.exists(self.stopfile):
            self.stop = True
            return True
        if self.a.max_minutes and time.monotonic() - self.t_mono > self.a.max_minutes * 60:
            self.halt(f"run.py --max-minutes {self.a.max_minutes} reached")
            return True
        return False

    def excluded_now(self, name, listed, ip=None):
        try:
            if self.excl.refresh():
                self.log(f"exclusion file changed; reloaded ({self.excl.count()} entries)")
        except Exception as e:
            self.halt(f"exclusion file unreadable or invalid during the run ({type(e).__name__}: {e})", code=7)
            return True
        return self.excl.name_excluded(name, listed) or (ip is not None and self.excl.ip_excluded(ip))

    async def resolve(self, name, fam):
        """-> (list of (ip, port), source). Real DNS: getaddrinfo with the system resolver, port 443; with --resolver
        ADDRESS: resolve_direct()."""
        af = socket.AF_INET if fam == 4 else socket.AF_INET6
        if self.override:
            ent = self.override.get(name, [])
            return sorted({(ip, port) for ip, port in ent if ipaddress.ip_address(ip).version == fam}), "resolve-file"
        if self.dns is not None:
            return await self.resolve_direct(name, fam), "dns-direct"
        for attempt in range(self.a.dns_retries):
            try:
                async with self.dns_sem:
                    infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                        name, 443, family=af, type=socket.SOCK_STREAM), 6)
                ips = sorted({i[4][0] for i in infos if ipaddress.ip_address(i[4][0]).version == fam})
                if ips:
                    return [(ip, self.port) for ip in ips], "dns"
            except Exception:
                pass
            if attempt + 1 < self.a.dns_retries:
                await asyncio.sleep(1.0 + attempt)
        return [], "dns"

    async def resolve_direct(self, name, fam):
        """--resolver ADDRESS: dnsclient.Client.resolve in a worker thread, same attempts, pause and concurrency as the
        getaddrinfo path. Retries only outcomes a retry can change; every failure means no address."""
        qtype = "A" if fam == 4 else "AAAA"
        for attempt in range(self.a.dns_retries):
            async with self.dns_sem:
                r = await asyncio.get_running_loop().run_in_executor(None, self.dns.resolve, name, qtype, DNS_ATTEMPT_SECONDS)
            self.dns_status[r.status] += 1
            if r.status == "ok":
                return [(ip, self.port) for ip in sorted({x for x in r.records if ipaddress.ip_address(x).version == fam})]
            if r.status in self.dnsmod.DEFINITIVE:
                return []
            if attempt + 1 < self.a.dns_retries:
                await asyncio.sleep(1.0 + attempt)
        return []

    def capped(self, name, ip):
        if self.count[(name, ip)] >= self.a.cap:
            return True
        if self.a.per_ip_cap and self.count_ip[ip] >= self.a.per_ip_cap:
            return True
        if self.a.mode == "pinned" and self.count_fam[(name, ipaddress.ip_address(ip).version)] >= self.a.cap:
            return True
        return bool(self.a.max_per_name) and self.count_name[name] >= self.a.max_per_name

    async def probe(self, name, listed, ip, port, label):
        """One handshake. Returns the result cell, 'capped' / 'excluded', or None when the run is stopping."""
        key = (name, ip)
        if self.capped(name, ip):
            return "capped"
        if self.should_stop():
            return None
        if self.excluded_now(name, listed, ip):
            return None if self.stop else "excluded"
        if not self.guarded and not ipaddress.ip_address(ip).is_loopback:
            self.halt(f"unguarded run.py refuses non-loopback address {ip} ({name}); real runs go through guard.py", code=6)
            return None
        sem = self.iplim.sem(ip)
        if sem is None:
            return await self._probe(name, listed, ip, port, label, key)
        async with sem:
            return await self._probe(name, listed, ip, port, label, key)

    async def _probe(self, name, listed, ip, port, label, key):
        await self.iplim.wait(ip)
        t = await self.lim.wait(self.should_stop)
        if t is None:
            return None
        if self.excluded_now(name, listed, ip):       # final gate, after the (possibly long) wait for a start slot
            return None if self.stop else "excluded"
        if self.capped(name, ip):
            return "capped"
        self.count[key] += 1
        self.count_name[name] += 1
        self.count_fam[(name, ipaddress.ip_address(ip).version)] += 1
        self.count_ip[ip] += 1
        self.plog.write(f"{t:.3f}\t{name}\t{label}\t{ip}\t{port}\n")
        self.plog.flush()
        os.fsync(self.plog.fileno())        # on disk before the handshake starts: the caps survive a crash or power loss
        tf = self.traces.path(name, ip, label)
        if self.a.proto == "smtp":
            cmd = ["bash", PROBE_SMTP, name, ip, str(port), label, G[label], tf, self.a.ehlo_name, f"{self.a.smtp_timeout:g}"]
        elif self.a.proto == "quic":
            cmd = ["bash", PROBE_QUIC, name, ip, str(port), label, G[label], tf, f"{self.a.quic_timeout:g}"]
        else:
            cmd = ["bash", PROBE, name, ip, str(port), label, G[label], tf]
        t_run = time.monotonic()
        p = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, stdin=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(p.communicate(), timeout=self.a.hard_timeout)
        except asyncio.TimeoutError:
            p.kill()
            out = b""
        dur = time.monotonic() - t_run
        tok = out.decode().strip() or FAIL
        self.traces.add(name, ip, label, t, tf, dur)
        self.recent.append(tok.startswith("ok"))
        self.nprobes += 1
        w = self.a.breaker_window
        if (self.nprobes >= self.a.breaker_min_probes and len(self.recent) == w
                and sum(self.recent) / w < self.a.breaker_min_rate):
            self.halt(f"circuit breaker: fewer than {self.a.breaker_min_rate:.0%} of the last {w} handshakes completed")
        return tok

    def emit(self, name, ip, n, p1, p2, p3, pa, t0, flag, fam, variant, rank):
        self.out.write("\t".join([name, ip, str(n), p1, p2, p3, f"{t0:.0f}", f"{time.time():.0f}", flag, pa,
                                  str(fam), variant, str(rank), self.a.mode]) + "\n")
        self.nrows += 1
        if self.nrows % 500 == 0:
            el = time.time() - self.t_begin
            self.log(f"{self.nrows} rows, {self.nprobes} handshakes, {el:.0f}s, {self.nprobes / max(el, 1):.1f}/s")

    def addresses(self, ents):
        """-> (allowed [(ip, port)], reason if none allowed)."""
        if not ents:
            return [], "noaddr"
        glob = ents if self.a.allow_nonglobal or self.a.resolve_file else [e for e in ents if ipaddress.ip_address(e[0]).is_global]
        if not glob:
            return [], "nonglobal"
        allowed = [e for e in glob if not self.excl.ip_excluded(e[0])]
        if not allowed:
            return [], "excluded"
        return allowed, None

    async def do_target(self, tgt, done):
        name, listed, variant, rank = tgt
        async with self.sem:
            for fam in families(self.a.families):
                if self.should_stop():
                    return
                if (name, fam, "*") in done:
                    continue
                t0 = time.time()
                if not valid_name(name):
                    self.emit(name, "-", 0, "invalid", "skip", "skip", "skip", t0, "", fam, variant, rank)
                    continue
                if self.excluded_now(name, listed):           # before resolution: an excluded name is never looked up
                    if self.stop:
                        return
                    self.emit(name, "-", 0, "excluded", "skip", "skip", "skip", t0, "", fam, variant, rank)
                    continue
                ents, _ = await self.resolve(name, fam)
                allowed, why = self.addresses(ents)
                if why:
                    self.emit(name, "-", len(ents), why, "skip", "skip", "skip", t0, "", fam, variant, rank)
                    continue
                if self.a.mode == "pinned":
                    ips = sorted(ip for ip, _ in allowed)
                    seed = f"{self.a.seed}:{name}" if fam == 4 else f"{self.a.seed}:{name}:6"
                    ip = random.Random(seed).choice(ips)
                    port = dict(allowed)[ip]
                    if not await self.pinned(name, listed, ip, port, len(allowed), t0, fam, variant, rank):
                        return
                else:
                    ips = sorted(ip for ip, _ in allowed)
                    if len(ips) > self.a.max_addrs:
                        ips = sorted(random.Random(f"{self.a.seed}:{name}:{fam}:all").sample(ips, self.a.max_addrs))
                    ports = dict(allowed)
                    for ip in ips:
                        if (name, fam, ip) in done:
                            continue
                        if not await self.alladdr(name, listed, ip, ports[ip], len(allowed), time.time(), fam, variant, rank):
                            return
                        t0 = time.time()

    async def pinned(self, name, listed, ip, port, n, t0, fam, variant, rank):
        p1 = await self.probe(name, listed, ip, port, "p1")
        if p1 is None:
            return False
        cells, flag = {k: "skip" for k in PQ_FOLLOWUPS}, ""
        if is_pq(p1):
            for lab in PQ_FOLLOWUPS:
                r = await self.probe(name, listed, ip, port, lab)
                if r is None:
                    cells[lab], flag = "stopped", "partial"
                    break
                cells[lab] = r
        self.emit(name, ip, n, p1, cells["p2"], cells["p3"], cells["pa"], t0, flag, fam, variant, rank)
        return flag == ""

    async def alladdr(self, name, listed, ip, port, n, t0, fam, variant, rank):
        p1 = await self.probe(name, listed, ip, port, "p1")
        if p1 is None:
            return False
        p2, flag = "skip", ""
        if is_pq(p1):
            p2 = await self.probe(name, listed, ip, port, "p2")
            if p2 is None:
                p2, flag = "stopped", "partial"
        self.emit(name, ip, n, p1, p2, "skip", "skip", t0, flag, fam, variant, rank)
        return flag == ""


def load_done(res):
    """-> (set of done targets, number of malformed lines skipped)."""
    done, bad = set(), 0
    if os.path.exists(res):
        for l in open(res, errors="replace"):
            p = l.rstrip("\n").split("\t")
            try:
                if len(p) != 14:
                    raise ValueError(len(p))
                fam = int(p[10])
            except ValueError:
                bad += 1
                continue
            # partial rows count as done: a target is never started twice in one campaign
            done.add((p[0], fam, "*") if p[13] == "pinned" or p[1] == "-" else (p[0], fam, p[1]))
    return done, bad


def repair_tail(path, quarantine=None):
    """A crash or power loss can leave a last line without its newline; later appends would glue onto it. -> the fragment
    (bytes, b'' if none). quarantine None (probes.log): terminate the fragment, so it stays a line of its own (and still
    counts against the caps if it names a host and an address). Otherwise (results.tsv): append the fragment to
    `quarantine` and cut it off, so the target is probed again, within the caps."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return b""
    if size == 0:
        return b""
    with open(path, "rb+") as f:
        f.seek(-1, os.SEEK_END)
        if f.read(1) == b"\n":
            return b""
        pos, start = size, 0
        while pos > 0:
            r = max(0, pos - 65536)
            f.seek(r)
            k = f.read(pos - r).rfind(b"\n")
            if k >= 0:
                start = r + k + 1
                break
            pos = r
        f.seek(start)
        frag = f.read()
        if quarantine is None:
            f.seek(0, os.SEEK_END)
            f.write(b"\n")
        else:
            with open(quarantine, "ab") as q:
                q.write(frag + b"\n")
                q.flush()
                os.fsync(q.fileno())
            f.truncate(start)
        f.flush()
        os.fsync(f.fileno())
    return frag


def xz_tail_ok(path):
    """True if traces.jsonl.xz is absent/empty or ends with an xz stream footer ('YZ'); False after a torn last stream."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                return True
            f.seek(-2, os.SEEK_END)
            return f.read(2) == b"YZ"
    except OSError:
        return True


def validate(a, ap):
    if not (0 < a.rate <= RATE_MAX):
        ap.error(f"--rate must be in (0, {RATE_MAX:g}]")
    if not (1 <= a.cap <= CAP_MAX):
        ap.error(f"--cap must be in [1, {CAP_MAX}] (per-target cap)")
    if a.max_per_name < 0 or a.max_addrs < 1 or a.workers < 1:
        ap.error("bad --max-per-name / --max-addrs / --workers")
    if not (0 < a.breaker_window <= 100000 and 0 <= a.breaker_min_rate < 1 and a.breaker_min_probes >= a.breaker_window):
        ap.error("bad circuit-breaker parameters (window > 0, min-probes >= window, 0 <= min-rate < 1)")
    for v in (a.assume_reachable, a.assume_pq, a.assume_reachable6, a.assume_pq6):
        if v is not None and not 0 <= v <= 1:
            ap.error("--assume-* shares must be in [0, 1]")
    families(a.families)
    if a.resolver != "system":
        try:
            if str(ipaddress.IPv4Address(a.resolver)) != a.resolver:
                raise ValueError
        except ValueError:
            ap.error(f"--resolver must be 'system' or one IPv4 address (port 53), got {a.resolver!r}")
    if a.proto == "smtp":
        if not a.ehlo_name or not valid_name(norm_name(a.ehlo_name)) or norm_name(a.ehlo_name) != a.ehlo_name:
            ap.error(f"--proto smtp needs --ehlo-name: a lower-case host name that identifies the scanner, got {a.ehlo_name!r}")
        if a.www != "off" or a.mode != "pinned":
            ap.error("--proto smtp probes the listed MX host names only: --www off and --mode pinned")
        if not SMTP_TIMEOUT_MIN <= a.smtp_timeout <= SMTP_TIMEOUT_MAX or a.smtp_timeout != int(a.smtp_timeout):
            ap.error(f"--smtp-timeout must be a whole number of seconds in [{SMTP_TIMEOUT_MIN:g}, {SMTP_TIMEOUT_MAX:g}]")
        if a.per_ip_cap is None:
            a.per_ip_cap = PER_IP_CAP_MAX
        if not 1 <= a.per_ip_cap <= PER_IP_CAP_MAX:
            ap.error(f"--per-ip-cap must be in [1, {PER_IP_CAP_MAX}] in smtp mode")
        a.hard_timeout = max(a.hard_timeout, a.smtp_timeout + 6)
    else:
        if a.ehlo_name is not None:
            ap.error("--ehlo-name is for --proto smtp only")
        if a.per_ip_cap is None:
            a.per_ip_cap = 0
        if not 0 <= a.per_ip_cap <= PER_IP_CAP_MAX:
            ap.error(f"--per-ip-cap must be in [0, {PER_IP_CAP_MAX}] (0 = off)")
    if a.proto == "quic":
        if a.www != "off" or a.mode != "pinned":
            ap.error("--proto quic probes the listed names only (an explicit name list): --www off and --mode pinned")
        a.quic_timeout = QUIC_TIMEOUT_DEFAULT if a.quic_timeout is None else a.quic_timeout
        if not QUIC_TIMEOUT_MIN <= a.quic_timeout <= QUIC_TIMEOUT_MAX or a.quic_timeout != int(a.quic_timeout):
            ap.error(f"--quic-timeout must be a whole number of seconds in [{QUIC_TIMEOUT_MIN:g}, {QUIC_TIMEOUT_MAX:g}]")
        a.hard_timeout = max(a.hard_timeout, a.quic_timeout + 6)
    elif a.quic_timeout is not None:
        ap.error("--quic-timeout is for --proto quic only")


async def amain(a):
    excl = Exclusions(a.exclude_file)
    os.makedirs(a.out, exist_ok=True)
    stopfile = os.path.join(a.out, "STOP")
    if os.path.exists(stopfile) and not a.force:
        print(f"{stopfile} exists: remove it to start (kill switch, circuit breaker or watchdog was triggered)", file=sys.stderr)
        return 2
    if a.force and os.path.exists(stopfile):
        os.remove(stopfile)
    guarded = guard_nonce_ok(a.out)
    if not guarded and not a.resolve_file:
        bad = [p for p in RESOLVED_SOCKETS if os.path.exists(p)]
        if not only_loopback_interfaces() or bad:
            print("REFUSED: unguarded run.py may use real DNS only inside a network namespace with loopback only and no "
                  f"host resolver socket (interfaces {[n for _, n in socket.if_nameindex()]}, sockets {bad}). "
                  "Real runs go through guard.py.", file=sys.stderr)
            return 6
    ranked = read_targets(a.targets)
    tg = expand(ranked, a.www)
    random.Random(a.seed).shuffle(tg)
    if a.limit:
        tg = tg[:a.limit]
    res = os.path.join(a.out, "results.tsv")
    plog_path = os.path.join(a.out, "probes.log")
    torn = {"results.tsv": repair_tail(res, os.path.join(a.out, "results.torn.tsv")).decode("utf-8", "replace"),
            "probes.log": repair_tail(plog_path).decode("utf-8", "replace")}
    rows_before = 0
    if os.path.exists(res):
        with open(res, "rb") as f:
            rows_before = sum(1 for l in f if l.strip())
    done, malformed = load_done(res)
    traces_ok = xz_tail_ok(os.path.join(a.out, "traces.jsonl.xz"))
    run = Run(a, excl, guarded)
    meta = {"argv": sys.argv, "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "vantage": a.vantage,
            "guarded": guarded, "seed": a.seed, "rate_per_s": a.rate, "workers": a.workers, "cap_per_target": a.cap,
            "max_per_name": a.max_per_name, "mode": a.mode, "www": a.www, "families": a.families,
            "per_ip_rate": a.per_ip_rate, "per_ip_conc": a.per_ip_conc, "max_minutes": a.max_minutes,
            "breaker": [a.breaker_window, a.breaker_min_probes, a.breaker_min_rate], "traces": a.traces,
            "targets_file_sha256": hashlib.sha256(open(a.targets, "rb").read()).hexdigest(), "names": len(ranked),
            "targets": len(tg), "already_done_rows": len(done), "exclusion_entries": excl.count(),
            "start_kind": "RESUME" if a.resume else "FRESH", "resume": bool(a.resume), "rows_already_present": rows_before,
            "handshakes_already_present": run.handshakes_before, "malformed_rows_skipped": malformed,
            "torn_tail_repaired": {k: v for k, v in torn.items() if v}, "traces_xz_tail_ok": traces_ok,
            "tz": a.tz, "window": a.window, "resolver": a.resolver, "proto": a.proto, "port": PORTS[a.proto],
            "ehlo_name": a.ehlo_name, "smtp_timeout": a.smtp_timeout if a.proto == "smtp" else None,
            "per_ip_cap": a.per_ip_cap, "quic_timeout": a.quic_timeout,
            "groups": G, "openssl": subprocess.run([os.environ.get("OPENSSL", DEFAULT_OPENSSL), "version"],
                                                   capture_output=True, text=True).stdout.strip()}
    with open(os.path.join(a.out, "run-meta.json"), "a") as f:
        f.write(json.dumps(meta) + "\n")
    for k, v in torn.items():
        if v:
            run.log(f"repaired a last line cut short in {k}: {v[:200]!r}"
                    + (" (moved to results.torn.tsv; that target is probed again within the caps)" if k == "results.tsv" else
                       " (terminated; it still counts against the caps)"))
    if malformed:
        run.log(f"WARNING: {malformed} malformed line(s) in results.tsv ignored")
    if not traces_ok:
        run.log("WARNING: traces.jsonl.xz does not end with a complete xz stream (crash during a write); `xz -dc` stops "
                "there, so read later streams separately (see README)")
    if a.resume:
        run.log(f"RESUME: {rows_before} rows and {run.handshakes_before} handshakes already present; targets with a row are "
                f"skipped ({len(done)}), earlier handshakes count against the caps, files are appended to")
    run.log(f"start: {len(tg)} targets from {len(ranked)} names, proto {a.proto} (port {PORTS[a.proto]}), "
            f"families {a.families}, www {a.www}, mode {a.mode}, "
            f"rate <= {a.rate}/s, cap {a.cap}/target, {a.workers} workers, guarded={guarded}, vantage: {a.vantage}")
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, lambda: setattr(run, "stop", True))
    await asyncio.gather(*[asyncio.create_task(run.do_target(t, done)) for t in tg])
    run.traces.flush()
    if run.dns is not None:
        run.log(f"dns client: resolver {a.resolver}, lookups by outcome {dict(sorted(run.dns_status.items()))}, packets sent "
                f"{run.dns.sent} (TCP {run.dns.sent_tcp}), replies ignored (wrong id/question, malformed) {run.dns.ignored}")
    el = time.time() - run.t_begin
    run.log(f"finished: {run.nrows} rows recorded, {run.nprobes} handshakes in {el:.0f}s ({run.nprobes / max(el, 1):.1f}/s); "
            f"stopped={run.should_stop()}; exclusion reloads {excl.reloads}")
    try:
        os.rmdir(run.traces.tmp)
    except OSError:
        pass
    return run.exit_code


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--targets", help="ranked name list (name per line, or rank,name)")
    ap.add_argument("--out")
    ap.add_argument("--www", choices=("off", "add"), default="off")
    ap.add_argument("--families", default="4")
    ap.add_argument("--mode", choices=("pinned", "alladdr"), default="pinned")
    ap.add_argument("--max-addrs", type=int, default=16, help="alladdr: at most this many addresses per name and family")
    ap.add_argument("--rate", type=float, default=RATE_DEFAULT)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--cap", type=int, default=CAP_MAX, help="handshakes per target (at most 4)")
    ap.add_argument("--max-per-name", type=int, default=0, help="optional total cap per SNI name over all its targets (0 = off)")
    ap.add_argument("--seed", default="1")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--exclude-file", default="")
    ap.add_argument("--vantage", default="unspecified")
    ap.add_argument("--tz", default=None, help="vantage time zone, recorded in run-meta.json only (guard.py enforces it)")
    ap.add_argument("--window", default=None, help="local scan window, recorded in run-meta.json only (guard.py enforces it)")
    ap.add_argument("--max-minutes", type=float, default=0.0, help="write STOP after this many minutes (0 = off)")
    ap.add_argument("--breaker-window", type=int, default=200)
    ap.add_argument("--breaker-min-probes", type=int, default=400)
    ap.add_argument("--breaker-min-rate", type=float, default=0.03)
    ap.add_argument("--traces", choices=("xz", "files", "none"), default="xz")
    ap.add_argument("--hard-timeout", type=float, default=float(os.environ.get("PROBE_TIMEOUT", "12")) + 6)
    ap.add_argument("--dns-retries", type=int, default=3)
    ap.add_argument("--dns-concurrency", type=int, default=8)
    ap.add_argument("--resolver", default="system", help="system (getaddrinfo) or the IPv4 address of a recursive resolver")
    ap.add_argument("--proto", choices=("https", "smtp", "quic"), default="https")
    ap.add_argument("--ehlo-name", default=None, help="smtp: the EHLO name s_client sends (-name)")
    ap.add_argument("--smtp-timeout", type=float, default=SMTP_TIMEOUT_DEFAULT, help="smtp: seconds per exchange, greeting included")
    ap.add_argument("--per-ip-cap", type=int, default=None, help="handshakes per address per campaign (smtp default 8; https 0 = off)")
    ap.add_argument("--quic-timeout", type=float, default=None, help=f"quic: seconds per probe (default {QUIC_TIMEOUT_DEFAULT:g})")
    ap.add_argument("--per-ip-rate", type=float, default=0.0)
    ap.add_argument("--per-ip-conc", type=int, default=0)
    ap.add_argument("--resolve-file", default="", help="TEST ONLY: replaces DNS")
    ap.add_argument("--allow-nonglobal", action="store_true", help="TEST ONLY: probe non-global (e.g. loopback) addresses from DNS")
    ap.add_argument("--force", action="store_true", help="remove an existing STOP file first")
    ap.add_argument("--resume", action="store_true", help="record this invocation as the continuation of an interrupted run")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--estimate", type=int, default=None, metavar="N")
    ap.add_argument("--assume-reachable", type=float, default=0.84)
    ap.add_argument("--assume-pq", type=float, default=0.45)
    ap.add_argument("--assume-reachable6", type=float, default=None)
    ap.add_argument("--assume-pq6", type=float, default=None)
    ap.add_argument("--assume-addrs", type=float, default=2.0)
    a = ap.parse_args()
    validate(a, ap)
    if a.estimate is not None:
        print_plan(plan(a.estimate, a), f"ESTIMATE for {a.estimate} names (nothing is sent)")
        return 0
    if not a.targets:
        ap.error("--targets is required")
    if a.dry_run:
        try:
            excl = Exclusions(a.exclude_file)
        except (OSError, ValueError) as e:
            print(f"REFUSED: exclusion file: {e}", file=sys.stderr)
            return 2
        ranked = read_targets(a.targets)
        tg = expand(ranked, a.www)
        if a.limit:
            tg = random.Random(a.seed).sample(tg, min(a.limit, len(tg)))
        valid = [t for t in tg if valid_name(t[0])]
        keep = [t for t in valid if not excl.name_excluded(t[0], t[1])]
        p = plan(len(ranked), a, n_targets=len(keep), n_excluded=len(valid) - len(keep))
        p["targets_invalid"] = len(tg) - len(valid)
        print_plan(p,
                   f"DRY RUN: {a.targets} (nothing is resolved or sent)")
        return 0
    if not a.out:
        ap.error("--out is required")
    a.out = os.path.abspath(a.out)
    try:
        Exclusions(a.exclude_file)
    except (OSError, ValueError) as e:
        print(f"REFUSED: exclusion file: {e}", file=sys.stderr)
        return 2
    return asyncio.run(amain(a))


if __name__ == "__main__":
    sys.exit(main())
