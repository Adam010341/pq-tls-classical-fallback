#!/usr/bin/env python3
"""guard.py: pre-flight guard and watchdog for kit-c campaign scans.

NOT armed, NOT scheduled. Nothing in this file starts by itself: `run` only starts the scanner when a person types it
AND supplies the exact phrase GO-<date>-OPERATOR-APPROVED, which is given only after explicit approval for that one
run.

  python3 -I guard.py check --date D --out DIR --targets FILE --targets-sha256 HEX --allowed-dates D[,D..] \
                            --expected-egress A.B.C.D --vantage-label TEXT --max-minutes M [--families 4|6|4,6
                            --expected-egress6 PREFIX/LEN] [--www off|add] [--mode pinned|alladdr]
                            [--tz IANA_NAME --window HH:MM-HH:MM] [--resolver system|A.B.C.D]
                            [--proto smtp --ehlo-name NAME [--smtp-timeout S] [--per-ip-cap N]]
                            [--proto quic [--quic-timeout S]]
  python3 -I guard.py run   (same arguments) --go GO-<D>-OPERATOR-APPROVED

check: every pre-flight check, one PASS/FAIL line each, exit 0 only if all pass. No side effects except one HTTPS GET
       to api.ipify.org (and api6.ipify.org when IPv6 is probed) for the egress address, unless GUARD_EGRESS(6) is set.
run:   refuses unless --go is exact; runs check; only if all pass starts run.py of this kit with the fixed campaign
       parameters (rate 18/s, 24 workers, seed 1, cap 4 per target, DNS retries 3), inside systemd-inhibit if usable,
       with a watchdog that writes DIR/STOP (the scanner's kill switch) when the local clock (--tz) reaches the end of
       --window (default Asia/Taipei 08:00), the run
       exceeds --max-minutes (required, at most 360), or check (k) stops returning `yes` (polled every 60 s). run.py also
       gets --max-minutes as a second, independent stop. Check (k) runs once more immediately before run.py starts.
--resume (check and run): continue an interrupted run in the same DIR instead of refusing it. Allowed only if DIR
       exists and its name contains --date; guard-meta.json (written when a run starts) records the same --date,
       targets sha256, --expected-egress(6), --families, --www, --mode, --tz, --window, --resolver and the --proto settings
       (smtp: EHLO name, timeout, per-IP cap; quic: timeout),
       and its status is `running` (the guard
       died: crash, power cut) or `failed` (run.py died), never `stopped`/`incomplete`/`finished`; every
       run-meta.json line agrees on targets sha256, families, www, mode, tz, window, resolver and proto settings; there is
       no STOP file;
       and no live process
       holds DIR/.guard.lock (a lock left by a dead pid is stale and only noted). (e) then reports the rows and
       handshakes already present; all other checks are unchanged. run.py --resume skips targets that have a row,
       counts the handshakes in probes.log against the caps, and appends to the same files.

Exit codes: 0 ok / all checks passed / run finished cleanly; 1 a check failed (nothing started); 2 usage or refusal;
3 watchdog stopped the run (truncated); 4 run.py failed; 5 run.py ended with STOP present for another reason.

Vantage time zone and window: --tz IANA_NAME (default Asia/Taipei) and --window HH:MM-HH:MM (default 02:00-08:00,
       start < end within one local day). --tz requires an explicit --window (no silent Taipei window in another zone).
--resolver system|A.B.C.D: system (default) = run.py resolves with getaddrinfo as before; an address = run.py's stdlib
       DNS client asks that recursive resolver. A resolver comparison is a separate campaign on a separate night (the
       handshake caps are per campaign); --resume refuses a different --resolver.
--proto https|smtp: https (default) as before. smtp = SMTP STARTTLS on port 25 to the MX host names in --targets
       (mxlist.py), SNI = the MX host name, EHLO name = --ehlo-name (required); run.py also gets --smtp-timeout (default
       30 s, 12..60), --per-ip-cap (default 8, 1..8, handshakes per address per campaign) and --max-per-name 4 (at most 4
       handshakes per MX host name over both families). --www add and --mode alladdr are refused. --resume refuses a
       different --proto, --ehlo-name, --smtp-timeout or --per-ip-cap.
--proto quic: QUIC (ALPN h3) on UDP port 443 to the names in --targets (an explicit list, normally quic_targets.py's
       output: the names whose P1 selected X25519MLKEM768 in a finished https run), SNI = the name; run.py also gets
       --quic-timeout (default 8 s, 5..12) and --max-per-name 4 (at most 4 handshakes per name over both families). No
       per-IP cap (as https). --www add and --mode alladdr are refused. A QUIC campaign is a separate campaign on its own
       night (own directory, date and GO phrase). --resume refuses a different --proto or --quic-timeout.
       A key missing from a guard-meta.json/run-meta.json written before these options existed means the default.

Checks (a)..(k):
  (a) local time (--tz) in [window start, window end), local date == --date, --date in --allowed-dates (required, no
      default dates), and the zone's UTC offset does not change on --date (a daylight-saving transition day is refused)
  (b) egress: IPv4 egress (GET https://api.ipify.org, 10 s) starts with --egress-prefix (default 140.116.) AND equals
      --expected-egress (the address announced to the network operator; a different address FAILS unless
      --allow-unannounced-egress, an OVERRIDE that turns it into the old WARN). If --families includes 6: IPv6 egress
      (GET https://api6.ipify.org) must be global and inside --expected-egress6 (a prefix, because IPv6 privacy
      addresses rotate). Unknown egress = FAIL.
  (c) no Tailscale exit node in use
  (d) free disk on the output filesystem >= max(--min-free-gb, expected handshakes x 6 KiB + 0.25 GiB)
  (e) DIR/STOP absent, no earlier results / run files / lock in DIR, DIR name contains the date
      (with --resume: the resume conditions above instead)
  (f) OpenSSL 3.5.x lists X25519MLKEM768 (static listing, no socket); with --proto smtp, `s_client -help` lists -starttls
      and -name; with --proto quic, `s_client -help` lists -quic and -alpn, and `stdbuf` (used by probe_quic.sh) exists
  (g) targets file sha256 == --targets-sha256; kit files match SHA256SUMS; exclusion file parses
  (h) exclusion entries (information)
  (i) no other scanner (old or new run.py) running
  (j) load plan (run.py --dry-run): expected handshakes and duration at 18/s; WARN if it does not fit before the window
      end or within --max-minutes (the watchdog would cut the run)
  (k) system clock synchronized: `timedatectl show -p NTPSynchronized --value` prints `yes`. Missing timedatectl, an
      error, or any other output FAILS (fail closed: right after a Windows boot the clock can be 8 h off until NTP syncs)

Test hooks (loud "TEST MODE" banner; `run` then only accepts a --resolve-file whose addresses are all loopback):
  env GUARD_NOW, GUARD_EGRESS, GUARD_EGRESS6, GUARD_FREE_GB, GUARD_TAILSCALE_JSON (JSON, file, or NOT_INSTALLED),
  GUARD_RESOLV_CONF, GUARD_NTP_SYNC (the value timedatectl would print, a file holding it (re-read at every poll), or
  NOT_INSTALLED), GUARD_NTP_POLL_SECONDS (watchdog poll interval for (k)); option --extra-run-args (only --resolve-file
  and --limit). Like every GUARD_* variable, the two clock variables switch on TEST MODE, so a real run never honours
  them, and none of them is passed to run.py.
OVERRIDE banner (allowed, weaker rule): --allow-unannounced-egress (also naming --egress-prefix when that is not 140.116.,
because the prefix is then the only network rule left), --min-free-gb. A non-default --egress-prefix together with the
exact --expected-egress rule is a vantage parameter, not an override: it prints a NOTE line instead.
"""
import argparse, datetime, fcntl, hashlib, ipaddress, json, os, re, secrets, shlex, shutil, signal, subprocess, sys, time, urllib.request
import zoneinfo
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TZ = "Asia/Taipei"
DEFAULT_WINDOW = "02:00-08:00"
TZ = ZoneInfo(DEFAULT_TZ)
TZ_RE = re.compile(r"[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*")
WINDOW_RE = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])")
DEFAULT_PREFIX = "140.116."
DEFAULT_MIN_FREE = 1.5
MAX_MINUTES_CAP = 360.0
WIN_START = datetime.time(2, 0)     # the default window (DEFAULT_WINDOW); a run uses args.win_start / args.win_end
WIN_END = datetime.time(8, 0)
DEFAULT_OPENSSL = "openssl"
TEST_ENV = ("GUARD_NOW", "GUARD_EGRESS", "GUARD_EGRESS6", "GUARD_FREE_GB", "GUARD_TAILSCALE_JSON", "GUARD_RESOLV_CONF",
            "GUARD_NTP_SYNC", "GUARD_NTP_POLL_SECONDS")
NTP_POLL_SECONDS = 60.0            # watchdog: re-run check (k) this often during a run
RUN_FILES = ("results.tsv", "run-meta.json", "probes.log", "traces", "traces.jsonl.xz", ".guard.lock", "guard-meta.json")
# guard-meta.json status values --resume accepts: "running" = the guard died (crash, power cut, hard reset, SIGKILL);
# "failed" = run.py exited non-zero without a watchdog reason. "stopped" (watchdog or signal), "incomplete" (STOP) and
# "finished" are refused.
RESUMABLE_STATUS = ("running", "failed")
# value assumed for a campaign key that a guard-meta.json / run-meta.json written by an earlier kit version lacks: those
# versions could only run with these values
LEGACY_IDENT = {"tz": DEFAULT_TZ, "window": DEFAULT_WINDOW, "resolver": "system", "proto": "https", "ehlo_name": None,
                "smtp_timeout": None, "per_ip_cap": 0, "quic_timeout": None}
SMTP_TIMEOUT_DEFAULT, SMTP_TIMEOUT_MIN, SMTP_TIMEOUT_MAX = 30.0, 12.0, 60.0
PER_IP_CAP_MAX = 8
SMTP_MAX_PER_NAME = 4             # at most 4 handshakes per host name per campaign, here over both families
QUIC_TIMEOUT_DEFAULT, QUIC_TIMEOUT_MIN, QUIC_TIMEOUT_MAX = 8.0, 5.0, 12.0
QUIC_MAX_PER_NAME = 4             # the same rule for --proto quic (both families together)
EXTRA_ARGS_ALLOWED = ("--resolve-file", "--limit")
KIT_FILES = ("run.py", "probe_one.sh", "guard.py", "dnsclient.py", "probe_smtp.sh", "probe_quic.sh")
CAMPAIGN_ARGS = ["--rate", "18", "--workers", "24", "--seed", "1", "--cap", "4", "--dns-retries", "3",
                 "--dns-concurrency", "8", "--traces", "xz"]
TRACE_KIB_PER_HANDSHAKE = 6        # campaign 2: 3.8 KiB/trace with xz over whole files; 6 leaves margin for 256-trace streams


# ----------------------------------------------------------------------------------------------------------------- clock
class Clock:
    """Clock in the vantage time zone (default Asia/Taipei). With GUARD_NOW set, the clock starts at that instant and
    then ticks in real time; GUARD_NOW carries its own UTC offset, so it names one instant in any zone."""
    def __init__(self, tz=TZ):
        v = os.environ.get("GUARD_NOW")
        self.tz = tz
        self.t0 = time.monotonic()
        self.base = None
        if v:
            b = datetime.datetime.fromisoformat(v)
            if b.tzinfo is None:
                raise SystemExit("GUARD_NOW needs a UTC offset, e.g. 2026-12-15T03:00:00+08:00")
            self.base = b

    def now(self):
        if self.base is not None:
            return (self.base + datetime.timedelta(seconds=time.monotonic() - self.t0)).astimezone(self.tz)
        return datetime.datetime.now(self.tz)


def parse_window(s):
    """'HH:MM-HH:MM' -> (start, end) as datetime.time; start < end within one local day, else ValueError."""
    m = WINDOW_RE.fullmatch(s or "")
    if not m:
        raise ValueError(f"--window must be HH:MM-HH:MM (24 h), got {s!r}")
    a, b = datetime.time(int(m[1]), int(m[2])), datetime.time(int(m[3]), int(m[4]))
    if not a < b:
        raise ValueError(f"--window {s}: the start must be before the end within one local day (no window across midnight)")
    return a, b


def place(tzname):
    """Short label for messages: 'Taipei' for the default zone (the texts stay as before), else the IANA name."""
    return "Taipei" if tzname == DEFAULT_TZ else tzname


def utc_offset_changes(date, zone):
    """True if the zone's UTC offset is not the same all day on date (a daylight-saving transition)."""
    d = datetime.date.fromisoformat(date)
    offs = {datetime.datetime.combine(d, datetime.time(h, m), tzinfo=zone).utcoffset()
            for h in range(24) for m in (0, 30)} | {datetime.datetime.combine(d, datetime.time(23, 59), tzinfo=zone).utcoffset()}
    return len(offs) > 1


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def families(s):
    return [int(x) for x in s.split(",") if x]


# ----------------------------------------------------------------------------------------------------------------- checks
def check_time(clock, date, allowed, tzname=DEFAULT_TZ, window=DEFAULT_WINDOW):
    ws, we = parse_window(window)
    now = clock.now()
    tod = now.time()
    probs = []
    if not (ws <= tod < we):
        probs.append(f"outside the {window} window")
    if now.date().isoformat() != date:
        probs.append(f"{place(tzname)} date is {now.date().isoformat()}, not --date {date}")
    if date not in allowed:
        probs.append(f"--date {date} is not one of --allowed-dates {','.join(allowed)}")
    if utc_offset_changes(date, clock.tz):
        probs.append(f"the UTC offset of {tzname} changes on {date} (daylight-saving transition): the window and the "
                     f"watchdog use wall-clock time, so choose another date")
    txt = f"{tzname} now {now.strftime('%Y-%m-%d %H:%M:%S')}, window {window}, --date {date}, allowed {','.join(allowed)}"
    if probs:
        return False, txt + " -> " + "; ".join(probs)
    return True, txt


def minutes_left(clock, win_end=WIN_END):
    """Minutes from now to the window end today (computed in UTC, so it is also right on a day with an offset change)."""
    now = clock.now()
    end = datetime.datetime.combine(now.date(), win_end, tzinfo=clock.tz)
    return (end.astimezone(datetime.timezone.utc) - now.astimezone(datetime.timezone.utc)).total_seconds() / 60


def get_egress(v6=False):
    v = os.environ.get("GUARD_EGRESS6" if v6 else "GUARD_EGRESS")
    if v is not None:
        return v.strip(), ("GUARD_EGRESS6" if v6 else "GUARD_EGRESS") + " (fake)"
    url = "https://api6.ipify.org" if v6 else "https://api.ipify.org"
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(url, timeout=10) as r:
        return r.read(200).decode("ascii", "replace").strip(), url.split("//")[1]


def check_egress(prefix, expected, allow_other, fams, expected6):
    parts, ok, addrs = [], True, {}
    try:
        addr, src = get_egress()
    except Exception as e:
        return False, f"could not determine the IPv4 egress address ({type(e).__name__}: {e}); never start without knowing it", None
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False, f"IPv4 egress reply is not an IPv4 address: {addr!r} (source {src})", None
    addrs[4] = str(ip)
    parts.append(f"IPv4 egress {ip} (source {src}), required prefix {prefix}, expected {expected}")
    if not str(ip).startswith(prefix):
        ok = False
        parts.append("-> wrong network")
    elif not ip.is_global:
        ok = False
        parts.append("-> not a public address")
    elif str(ip) != expected:
        if allow_other:
            parts.append(f"(WARN: not the expected address {expected}; tell the network operator before running)")
        else:
            ok = False
            parts.append(f"-> not the expected (announced) address {expected}")
    if 6 in fams:
        try:
            a6, src6 = get_egress(v6=True)
            ip6 = ipaddress.IPv6Address(a6)
        except Exception as e:
            return False, "; ".join(parts) + f"; could not determine the IPv6 egress address ({type(e).__name__}: {e})", None
        net6 = ipaddress.IPv6Network(expected6, strict=False)
        addrs[6] = str(ip6)
        parts.append(f"IPv6 egress {ip6} (source {src6}), expected inside {net6}")
        if not ip6.is_global:
            ok = False
            parts.append("-> IPv6 egress not global")
        elif ip6 not in net6:
            ok = False
            parts.append("-> IPv6 egress outside the expected prefix")
    return ok, " ".join(parts), addrs


def check_tailscale():
    v = os.environ.get("GUARD_TAILSCALE_JSON")
    if v is not None:
        if v == "NOT_INSTALLED":
            return True, "tailscale not installed (fake)"
        raw = open(v).read() if not v.lstrip().startswith("{") else v
        src = "fake JSON"
    else:
        exe = shutil.which("tailscale")
        if not exe:
            return True, "tailscale not installed"
        try:
            p = subprocess.run([exe, "status", "--json"], capture_output=True, text=True, timeout=10)
        except Exception as e:
            return False, f"`tailscale status --json` failed ({type(e).__name__}); cannot rule out an exit node"
        if p.returncode != 0:
            msg = (p.stdout + p.stderr).strip().replace("\n", " ")[:160]
            if re.search(r"doesn't appear to be running|failed to connect to local tailscaled|is not running", msg, re.I):
                return True, f"tailscaled not running ({msg})"
            return False, f"`tailscale status --json` exit {p.returncode}: {msg}; cannot rule out an exit node"
        raw, src = p.stdout, "tailscale status --json"
    try:
        j = json.loads(raw)
    except Exception as e:
        return False, f"unparseable tailscale status ({e})"
    ens = j.get("ExitNodeStatus")
    peers = [p.get("HostName", "?") for p in (j.get("Peer") or {}).values() if p.get("ExitNode")]
    if ens or peers:
        return False, f"an exit node is in use ({src}): ExitNodeStatus={json.dumps(ens)[:120]} peers={peers}"
    return True, f"no exit node in use ({src}; BackendState {j.get('BackendState', '?')})"


def check_clock_sync():
    """(k) `timedatectl show -p NTPSynchronized --value` must print exactly `yes`; anything else FAILS (fail closed)."""
    v = os.environ.get("GUARD_NTP_SYNC")
    if v is not None:
        if v == "NOT_INSTALLED":
            return False, "timedatectl not installed (fake); cannot confirm the clock is synchronized (fail closed)"
        if os.path.isfile(v):
            try:
                val = open(v).read().strip()
            except OSError as e:
                return False, f"GUARD_NTP_SYNC file unreadable ({e}) (fake); fail closed"
            src = f"GUARD_NTP_SYNC file {v} (fake)"
        else:
            val, src = v.strip(), "GUARD_NTP_SYNC (fake)"
    else:
        exe = shutil.which("timedatectl")
        if not exe:
            return False, "timedatectl not found; cannot confirm the clock is synchronized (fail closed)"
        try:
            p = subprocess.run([exe, "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=10)
        except Exception as e:
            return False, f"`timedatectl show -p NTPSynchronized --value` failed ({type(e).__name__}: {e}); fail closed"
        if p.returncode != 0:
            msg = (p.stdout + p.stderr).strip().replace("\n", " ")[:160]
            return False, f"`timedatectl show -p NTPSynchronized --value` exit {p.returncode}: {msg!r}; fail closed"
        val, src = p.stdout.strip(), "timedatectl show -p NTPSynchronized --value"
    if val == "yes":
        return True, f"NTPSynchronized=yes ({src})"
    return False, (f"NTPSynchronized={val[:40]!r} ({src}), need 'yes': the clock may be wrong (e.g. 8 h off right after "
                   f"a Windows boot); wait until NTP has synchronized")


def existing_ancestor(p):
    p = os.path.abspath(p)
    while not os.path.exists(p):
        p = os.path.dirname(p)
    return p


def check_disk(out, min_gb, plan):
    v = os.environ.get("GUARD_FREE_GB")
    if v is not None:
        free, src = float(v), "GUARD_FREE_GB (fake)"
    else:
        anc = existing_ancestor(out)
        free, src = shutil.disk_usage(anc).free / 2 ** 30, f"filesystem of {anc}"
    need_plan = (plan["expected_total"] * TRACE_KIB_PER_HANDSHAKE / 2 ** 20 + 0.25) if plan else 0.0
    need = max(min_gb, need_plan)
    ok = free >= need
    return ok, (f"free {free:.2f} GiB ({src}), required >= {need:.2f} GiB (max of --min-free-gb {min_gb} and "
                f"{plan['expected_total'] if plan else '?'} expected handshakes x {TRACE_KIB_PER_HANDSHAKE} KiB + 0.25 GiB)")


def check_outdir(out, date):
    probs, notes = [], []
    if date not in os.path.basename(os.path.abspath(out)):
        probs.append(f"directory name {os.path.basename(os.path.abspath(out))!r} does not contain the date {date}")
    if os.path.exists(os.path.join(out, "STOP")):
        probs.append("STOP file exists (kill switch, circuit breaker or watchdog was triggered; remove it deliberately)")
    for n in RUN_FILES:
        if os.path.exists(os.path.join(out, n)):
            probs.append(f"earlier run file {n} exists (results are never overwritten; --resume continues an interrupted run)")
    if not os.path.exists(out):
        anc = existing_ancestor(out)
        if not os.access(anc, os.W_OK):
            probs.append(f"cannot create {out}: {anc} not writable")
        notes.append("directory will be created")
    txt = f"{out}: " + ("; ".join(probs) if probs else "no STOP, no earlier results" + (f" ({'; '.join(notes)})" if notes else ""))
    return not probs, txt


def campaign_ident(args):
    """The parameters a resumed run must share with the interrupted one (recorded in guard-meta.json)."""
    return {"date": args.date, "targets_sha256": args.targets_sha256.lower(), "expected_egress": args.expected_egress,
            "expected_egress6": args.expected_egress6 if 6 in families(args.families) else None,
            "families": args.families, "www": args.www, "mode": args.mode, "tz": args.tz, "window": args.window,
            "resolver": args.resolver, "proto": args.proto, "ehlo_name": args.ehlo_name, "smtp_timeout": args.smtp_timeout,
            "per_ip_cap": args.per_ip_cap, "quic_timeout": args.quic_timeout}


def runmeta_ident(args):
    """(run-meta.json key, value this run passes to run.py) pairs that every earlier part must share."""
    return (("targets_file_sha256", args.targets_sha256.lower()), ("families", args.families), ("www", args.www),
            ("mode", args.mode), ("tz", args.tz), ("window", args.window), ("resolver", args.resolver), ("proto", args.proto),
            ("ehlo_name", args.ehlo_name), ("smtp_timeout", args.smtp_timeout), ("per_ip_cap", args.per_ip_cap),
            ("quic_timeout", args.quic_timeout))


def count_lines(p):
    try:
        with open(p, "rb") as f:
            return sum(1 for l in f if l.strip())
    except OSError:
        return 0


def pid_is_guard(pid):
    """True if pid is a live (non-zombie) `guard.py run` process."""
    try:
        toks = [t.decode("utf-8", "replace") for t in open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") if t]
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[-1].split()[0]
    except (OSError, IndexError):
        return False
    return st != "Z" and any(os.path.basename(t) == "guard.py" for t in toks) and "run" in toks


def lock_state(out):
    """-> ("none" | "stale" | "live", text). Live = some process holds a flock on DIR/.guard.lock (every guard run
    holds one for its lifetime) or the pid written in it is a live `guard.py run`."""
    p = os.path.join(out, ".guard.lock")
    if not os.path.lexists(p):
        return "none", "no .guard.lock"
    try:
        fd = os.open(p, os.O_RDONLY)
    except OSError as e:
        return "live", f".guard.lock unreadable ({e}); treated as held"
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return "live", ".guard.lock is held (flock) by a live process"
        fcntl.flock(fd, fcntl.LOCK_UN)
        toks = os.read(fd, 200).decode("ascii", "replace").split()
    finally:
        os.close(fd)
    pid = int(toks[0]) if toks and toks[0].isdigit() else None
    if pid is not None and pid_is_guard(pid):
        return "live", f".guard.lock names pid {pid}, a live guard.py run"
    if pid is not None and os.path.exists(f"/proc/{pid}"):
        return "stale", f"stale .guard.lock (pid {pid} is alive but is not a guard.py run: pid reused)"
    return "stale", f"stale .guard.lock (pid {pid} not running)"


def check_resume(args):
    """(e) with --resume: may this interrupted run be continued in DIR?"""
    out, date = args.out, args.date
    if not os.path.isdir(out):
        return False, f"{out}: --resume needs the directory of an interrupted run, and it does not exist"
    probs, notes = [], []
    if date not in os.path.basename(out):
        probs.append(f"directory name {os.path.basename(out)!r} does not contain the date {date}")
    if os.path.exists(os.path.join(out, "STOP")):
        probs.append("STOP file exists (kill switch, circuit breaker or watchdog): a stopped run is never resumed")
    want = campaign_ident(args)
    gm = None
    try:
        with open(os.path.join(out, "guard-meta.json")) as f:
            gm = json.load(f)
        if not isinstance(gm, dict):
            raise ValueError("not a JSON object")
    except FileNotFoundError:
        probs.append("no guard-meta.json: cannot verify that DIR belongs to this campaign")
        gm = None
    except Exception as e:
        probs.append(f"guard-meta.json unreadable ({type(e).__name__}: {e})")
        gm = None
    if gm is not None:
        for k, v in want.items():
            got = gm.get(k, LEGACY_IDENT.get(k))
            if got != v:
                probs.append(f"guard-meta.json {k}={got!r} differs from this run's {v!r}")
        if gm.get("status") == "finished":
            probs.append("guard-meta.json says the run finished cleanly; nothing to resume")
        elif gm.get("status") not in RESUMABLE_STATUS:
            probs.append(f"guard-meta.json status={gm.get('status')!r}: only an interrupted run (status "
                         f"{' or '.join(RESUMABLE_STATUS)}) is resumed; a run stopped by the watchdog or a signal is not")
    rm = os.path.join(out, "run-meta.json")
    if os.path.exists(rm):
        try:
            lines = [json.loads(l) for l in open(rm) if l.strip()]
        except Exception as e:
            probs.append(f"run-meta.json unreadable ({type(e).__name__}: {e})")
            lines = []
        for i, m in enumerate(lines, 1):
            for k, v in runmeta_ident(args):
                got = m.get(k, LEGACY_IDENT.get(k))
                if got != v:
                    probs.append(f"run-meta.json line {i}: {k}={got!r} differs from this run's {v!r}")
    else:
        notes.append("no run-meta.json (run.py had not started)")
    st, ltxt = lock_state(out)
    (probs if st == "live" else notes).append(ltxt)
    notes.insert(0, f"RESUME: {count_lines(os.path.join(out, 'results.tsv'))} rows and "
                    f"{count_lines(os.path.join(out, 'probes.log'))} handshakes already present")
    if probs:
        return False, f"{out}: resume refused: " + "; ".join(probs)
    return True, (f"{out}: resume allowed: same date, targets, egress, families, www, mode, tz, window, resolver and "
                  f"proto settings; no STOP; "
                  + "; ".join(notes))


def run_cmd(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def check_openssl(path, proto="https"):
    try:
        v = run_cmd([path, "version"])
    except Exception as e:
        return False, f"cannot run {path} ({type(e).__name__}: {e})"
    m = re.match(r"OpenSSL (3\.5\.\d+)\b", v.stdout.strip())
    if not m:
        return False, f"{path}: {v.stdout.strip()!r}, need OpenSSL 3.5.x"
    try:
        kem = run_cmd([path, "list", "-kem-algorithms"])
        grp = run_cmd([path, "list", "-tls1_3", "-tls-groups"])
    except Exception as e:
        return False, f"{path} {m.group(1)}: listing algorithms failed ({e})"
    in_kem, in_grp = "X25519MLKEM768" in kem.stdout, "X25519MLKEM768" in grp.stdout
    txt = (f"{path} {m.group(1)}; X25519MLKEM768 in `list -kem-algorithms`: {in_kem}, "
           f"in `list -tls1_3 -tls-groups`: {in_grp} (static listing, no socket)")
    if proto not in ("smtp", "quic"):
        return (in_kem and in_grp), txt
    try:
        h = run_cmd([path, "s_client", "-help"])
    except Exception as e:
        return False, txt + f"; `s_client -help` failed ({e})"
    hl = h.stdout + h.stderr
    if proto == "quic":
        q = bool(re.search(r"^\s*-quic\b", hl, re.M)) and bool(re.search(r"^\s*-alpn\b", hl, re.M))
        sb = shutil.which("stdbuf")
        return (in_kem and in_grp and q and bool(sb)), txt + f"; s_client -quic and -alpn: {q}; stdbuf: {sb or 'NOT FOUND'}"
    st = bool(re.search(r"^\s*-starttls\b", hl, re.M)) and bool(re.search(r"^\s*-name\b", hl, re.M))
    return (in_kem and in_grp and st), txt + f"; s_client -starttls and -name: {st}"


def read_sums(kit):
    d = {}
    with open(os.path.join(kit, "SHA256SUMS")) as f:
        for l in f:
            if l.strip():
                h, n = l.strip().split(None, 1)
                d[n.lstrip("*")] = h
    return d


def parse_exclusions(path):
    sys.path.insert(0, HERE)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("kitc_run", os.path.join(HERE, "run.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m.parse_exclusions(path)
    finally:
        sys.path.pop(0)


def check_kit(args):
    probs, info = [], []
    try:
        got = sha256_file(args.targets)
        if got != args.targets_sha256.lower():
            probs.append(f"targets sha256 {got[:12]}... != --targets-sha256 {args.targets_sha256[:12]}...")
        else:
            info.append(f"targets sha256 {got[:12]}... as approved")
    except Exception as e:
        probs.append(f"cannot read targets {args.targets}: {e}")
    try:
        sums = read_sums(HERE)
        for need in KIT_FILES:
            if need not in sums:
                probs.append(f"{need} not listed in SHA256SUMS")
        for n, h in sums.items():
            p = os.path.join(HERE, n)
            if not os.path.isfile(p):
                probs.append(f"{n} missing")
            elif sha256_file(p) != h:
                probs.append(f"{n} does not match SHA256SUMS")
        if not probs:
            info.append(f"{len(sums)} kit files match SHA256SUMS")
    except Exception as e:
        probs.append(f"SHA256SUMS unusable ({e})")
    try:
        parse_exclusions(args.exclude_file)
        info.append(f"exclusion file {args.exclude_file} parses")
    except Exception as e:
        probs.append(f"exclusion file unusable: {e}")
    return not probs, "; ".join(probs) if probs else "; ".join(info)


def exclude_count(path):
    n, s, nets = parse_exclusions(path)
    return f"{len(n)} exact name(s), {len(s)} *.suffix, {len(nets)} address block(s) in {path}"


def get_plan(args):
    cmd = [sys.executable, "-I", os.path.join(HERE, "run.py"), "--dry-run", "--targets", args.targets, "--www", args.www,
           "--families", args.families, "--mode", args.mode, "--rate", "18", "--exclude-file", args.exclude_file,
           "--assume-reachable", str(args.assume_reachable), "--assume-pq", str(args.assume_pq)] + proto_args(args)
    p = run_cmd(cmd, timeout=120)
    for l in p.stdout.splitlines():
        if l.startswith("PLAN-JSON "):
            return json.loads(l[len("PLAN-JSON "):])
    raise RuntimeError(f"run.py --dry-run gave no plan (exit {p.returncode}): {(p.stdout + p.stderr)[-300:]}")


def proto_args(args):
    """run.py arguments that follow from --proto (fixed campaign values in smtp and quic mode)."""
    if args.proto == "quic":
        return ["--proto", "quic", "--quic-timeout", f"{args.quic_timeout:g}", "--max-per-name", str(QUIC_MAX_PER_NAME)]
    if args.proto != "smtp":
        return ["--proto", "https"]
    return ["--proto", "smtp", "--ehlo-name", args.ehlo_name, "--smtp-timeout", f"{args.smtp_timeout:g}",
            "--per-ip-cap", str(args.per_ip_cap), "--max-per-name", str(SMTP_MAX_PER_NAME)]


def check_plan(plan, clock, max_minutes, win_end=WIN_END):
    if plan is None:
        return False, "no load plan (run.py --dry-run failed)"
    mins = plan["expected_seconds"] / 60
    left = minutes_left(clock, win_end)
    txt = (f"{plan['targets_per_family']} targets x {len(plan['families'])} famil(ies), expected {plan['expected_total']} handshakes "
           f"(P1 {plan['expected']['p1']}, P2 {plan['expected']['p2']}, P3 {plan['expected']['p3']}, PA {plan['expected']['pa']}), "
           f"{mins:.0f} min at 18/s; upper bound {plan['upper_bound_total']}; at most {plan['max_handshakes_per_listed_name']} per listed name")
    if mins > min(left, max_minutes):
        txt += (f" (WARN: does not fit in {min(left, max_minutes):.0f} min (window left {left:.0f}, --max-minutes {max_minutes:g}); "
                f"the watchdog will truncate the run)")
    return True, txt


def other_scanners():
    found = []
    me = os.getpid()
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == me:
            continue
        try:
            toks = open(f"/proc/{d}/cmdline", "rb").read().split(b"\0")
        except OSError:
            continue
        toks = [t.decode("utf-8", "replace") for t in toks if t]
        if any(os.path.basename(t) == "run.py" for t in toks) and ("--hosts" in toks or "--targets" in toks) and "--dry-run" not in toks:
            found.append(int(d))
    return found


def check_others():
    f = other_scanners()
    return (not f), ("no other run.py scanner process" if not f else f"another scanner process is running: pid {f}")


def active_overrides(args):
    test, ovr = [], []
    for k in TEST_ENV:
        if os.environ.get(k) is not None:
            test.append(f"env {k}")
    if getattr(args, "extra_run_args", ""):
        test.append("--extra-run-args")
    if args.allow_unannounced_egress:
        # the exact --expected-egress rule is off: the prefix is then the only network rule, so name it if not the default
        ovr += (["--egress-prefix"] if args.egress_prefix != DEFAULT_PREFIX else []) + ["--allow-unannounced-egress"]
    if args.min_free_gb != DEFAULT_MIN_FREE:
        ovr.append("--min-free-gb")
    return test, ovr


def run_checks(args, clock):
    openssl = os.environ.get("OPENSSL", DEFAULT_OPENSSL)
    res = []

    def add(i, name, fn):
        try:
            out = fn()
        except Exception as e:
            out = (False, f"check crashed: {type(e).__name__}: {e}")
        res.append((i, name, out[0], out[1], out[2] if len(out) > 2 else None))

    try:
        plan = get_plan(args)
    except Exception as e:
        plan, plan_err = None, str(e)
    allowed = tuple(x for x in args.allowed_dates.split(",") if x)
    add("a", "time window / date", lambda: check_time(clock, args.date, allowed, args.tz, args.window))
    add("b", "egress address", lambda: check_egress(args.egress_prefix, args.expected_egress, args.allow_unannounced_egress,
                                                     families(args.families), args.expected_egress6))
    add("c", "no Tailscale exit node", check_tailscale)
    add("d", "free disk", lambda: check_disk(args.out, args.min_free_gb, plan))
    add("e", "output directory", lambda: check_resume(args) if args.resume else check_outdir(args.out, args.date))
    add("f", "OpenSSL 3.5 with X25519MLKEM768", lambda: check_openssl(openssl, args.proto))
    add("g", "targets hash, kit integrity, exclusion file", lambda: check_kit(args))
    add("h", "exclusion entries (information)", lambda: (True, exclude_count(args.exclude_file)))
    add("i", "no other scanner running", check_others)
    add("j", "load plan", lambda: check_plan(plan, clock, args.max_minutes, args.win_end) if plan else (False, f"no load plan: {plan_err}"))
    add("k", "system clock synchronized", check_clock_sync)
    return res


def format_checks(res):
    lines = [f"{'PASS' if ok else 'FAIL'} ({i}) {name}: {txt}" for i, name, ok, txt, _ in res]
    bad = [i for i, _, ok, _, _ in res if not ok]
    lines.append("RESULT: all checks passed" if not bad else f"RESULT: {len(bad)} check(s) FAILED ({','.join(bad)}); do not start")
    return lines, not bad


def banners(args):
    test, ovr = active_overrides(args)
    out = []
    if test:
        out.append("!!!! TEST MODE: fake or replaced inputs in use (" + ", ".join(test) + "). This is NOT a real pre-flight. !!!!")
    if ovr:
        out.append("!!!! OVERRIDE in use: " + ", ".join(ovr) + " (a weaker rule than the default) !!!!")
    if args.egress_prefix != DEFAULT_PREFIX and not args.allow_unannounced_egress:
        out.append(f"NOTE: egress prefix {args.egress_prefix} (a vantage outside {DEFAULT_PREFIX}); the egress must still equal "
                   f"--expected-egress {args.expected_egress} exactly")
    if args.resolver != "system":
        out.append(f"NOTE: names are resolved by kit-c's DNS client at {args.resolver}, not by the system resolver")
    if args.proto == "smtp":
        out.append(f"NOTE: SMTP STARTTLS mode: port 25, EHLO {args.ehlo_name}, timeout {args.smtp_timeout:g} s per exchange, "
                   f"at most {args.per_ip_cap} handshakes per address and {SMTP_MAX_PER_NAME} per MX host name")
    if args.proto == "quic":
        out.append(f"NOTE: QUIC mode: UDP port 443, ALPN h3, timeout {args.quic_timeout:g} s per probe, at most "
                   f"{QUIC_MAX_PER_NAME} handshakes per name; no per-address cap")
    if (args.tz, args.window) != (DEFAULT_TZ, DEFAULT_WINDOW):
        out.append(f"NOTE: vantage time zone {args.tz}, window {args.window} local time")
    return out, bool(test)


# ----------------------------------------------------------------------------------------------------------------- commands
def usage(msg):
    print(f"usage error: {msg}", file=sys.stderr)
    sys.exit(2)


def validate_common(args):
    try:
        datetime.date.fromisoformat(args.date)
        for d in args.allowed_dates.split(","):
            if d:
                datetime.date.fromisoformat(d)
    except ValueError:
        usage("--date and --allowed-dates must be YYYY-MM-DD")
    try:
        ipaddress.IPv4Address(args.expected_egress)
    except ValueError:
        usage(f"--expected-egress must be one IPv4 address, got {args.expected_egress!r}")
    if not args.expected_egress.startswith(args.egress_prefix):
        usage(f"--expected-egress {args.expected_egress} does not start with --egress-prefix {args.egress_prefix}")
    if args.tz is not None and args.window is None:
        usage("--tz needs an explicit --window HH:MM-HH:MM (the default window 02:00-08:00 is for Asia/Taipei only)")
    tzname = DEFAULT_TZ if args.tz is None else args.tz
    if not TZ_RE.fullmatch(tzname) or tzname not in zoneinfo.available_timezones():
        usage(f"--tz must be an IANA time zone name such as Asia/Taipei or America/New_York, got {tzname!r}")
    try:
        args.zone = ZoneInfo(tzname)
        args.win_start, args.win_end = parse_window(DEFAULT_WINDOW if args.window is None else args.window)
    except Exception as e:
        usage(str(e))
    args.tz = tzname
    if args.proto == "smtp":
        en = args.ehlo_name or ""
        if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+", en):
            usage(f"--proto smtp needs --ehlo-name: a lower-case host name that identifies the scanner (ideally the PTR "
                  f"name of the egress address), got {args.ehlo_name!r}")
        if args.www != "off" or args.mode != "pinned":
            usage("--proto smtp probes the listed MX host names only: --www off and --mode pinned")
        args.smtp_timeout = SMTP_TIMEOUT_DEFAULT if args.smtp_timeout is None else args.smtp_timeout
        if not SMTP_TIMEOUT_MIN <= args.smtp_timeout <= SMTP_TIMEOUT_MAX or args.smtp_timeout != int(args.smtp_timeout):
            usage(f"--smtp-timeout must be a whole number of seconds in [{SMTP_TIMEOUT_MIN:g}, {SMTP_TIMEOUT_MAX:g}]")
        args.per_ip_cap = PER_IP_CAP_MAX if args.per_ip_cap is None else args.per_ip_cap
        if not 1 <= args.per_ip_cap <= PER_IP_CAP_MAX:
            usage(f"--per-ip-cap must be in [1, {PER_IP_CAP_MAX}] (it may only lower the default)")
    else:
        if args.ehlo_name is not None or args.smtp_timeout is not None or args.per_ip_cap is not None:
            usage("--ehlo-name, --smtp-timeout and --per-ip-cap are for --proto smtp only")
        args.per_ip_cap = 0
    if args.proto == "quic":
        if args.www != "off" or args.mode != "pinned":
            usage("--proto quic probes the listed names only (an explicit name list): --www off and --mode pinned")
        args.quic_timeout = QUIC_TIMEOUT_DEFAULT if args.quic_timeout is None else args.quic_timeout
        if not QUIC_TIMEOUT_MIN <= args.quic_timeout <= QUIC_TIMEOUT_MAX or args.quic_timeout != int(args.quic_timeout):
            usage(f"--quic-timeout must be a whole number of seconds in [{QUIC_TIMEOUT_MIN:g}, {QUIC_TIMEOUT_MAX:g}]")
    elif args.quic_timeout is not None:
        usage("--quic-timeout is for --proto quic only")
    if args.resolver != "system":
        try:
            if str(ipaddress.IPv4Address(args.resolver)) != args.resolver:
                raise ValueError
        except ValueError:
            usage(f"--resolver must be 'system' or one IPv4 address (port 53), got {args.resolver!r}")
    args.window = f"{args.win_start.strftime('%H:%M')}-{args.win_end.strftime('%H:%M')}"
    fams = families(args.families)
    if not fams or any(f not in (4, 6) for f in fams):
        usage("--families must be 4, 6 or 4,6")
    if 6 in fams:
        if not args.expected_egress6:
            usage("--families includes 6: --expected-egress6 PREFIX/LEN (announced IPv6 source prefix) is required")
        try:
            ipaddress.IPv6Network(args.expected_egress6, strict=False)
        except ValueError:
            usage(f"--expected-egress6 must be an IPv6 prefix, got {args.expected_egress6!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.targets_sha256 or ""):
        usage("--targets-sha256 must be 64 hex characters")
    if not args.vantage_label.strip():
        usage("--vantage-label is required")
    if not (0 < args.max_minutes <= MAX_MINUTES_CAP):
        usage(f"--max-minutes must be in (0, {MAX_MINUTES_CAP:g}]")
    args.out = os.path.abspath(args.out)
    args.targets = os.path.abspath(args.targets)
    args.exclude_file = os.path.abspath(args.exclude_file)


def cmd_check(args):
    validate_common(args)
    clock = Clock(args.zone)
    bl, _ = banners(args)
    for b in bl:
        print(b)
    lines, ok = format_checks(run_checks(args, clock))
    print("\n".join(lines))
    return 0 if ok else 1


def resolvers(path):
    ns = []
    try:
        for l in open(path):
            p = l.split()
            if len(p) >= 2 and p[0] == "nameserver":
                ns.append(p[1])
    except OSError:
        return "unknown"
    if ns == ["127.0.0.53"] and "GUARD_RESOLV_CONF" not in os.environ:
        up = []
        try:
            for l in open("/run/systemd/resolve/resolv.conf"):
                p = l.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    up.append(p[1])
        except OSError:
            pass
        return "127.0.0.53 (systemd-resolved stub; upstream " + (",".join(up) or "unknown") + ")"
    return ",".join(ns) or "unknown"


def parse_extra(extra):
    toks = shlex.split(extra) if extra else []
    i, resolve = 0, None
    while i < len(toks):
        if toks[i] not in EXTRA_ARGS_ALLOWED:
            usage(f"--extra-run-args: {toks[i]!r} not allowed (only {', '.join(EXTRA_ARGS_ALLOWED)})")
        if toks[i] == "--resolve-file":
            resolve = toks[i + 1] if i + 1 < len(toks) else None
        i += 2
    return toks, resolve


def resolve_file_is_loopback(path):
    """kit-c format: name<TAB>addr[,addr...]; addr = - | IPv4[:port] | IPv6 | [IPv6]:port."""
    if not path or not os.path.isfile(path):
        return False
    for l in open(path):
        p = l.rstrip("\n").split("\t")
        if len(p) != 2 or p[1].strip() == "-":
            continue
        for a in p[1].split(","):
            a = a.strip()
            if not a:
                continue
            if a.startswith("["):
                ip = a[1:].partition("]")[0]
            elif a.count(":") == 1:
                ip = a.partition(":")[0]
            else:
                ip = a
            try:
                if not ipaddress.ip_address(ip).is_loopback:
                    return False
            except ValueError:
                return False
    return True


class Log:
    def __init__(self, path, clock, label="taipei"):
        self.f = open(path, "a", buffering=1)
        self.clock = clock
        self.label = label

    def __call__(self, msg):
        line = (f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"[{self.label} {self.clock.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")
        self.f.write(line + "\n")
        print(line, flush=True)


def max_per_second(plog):
    try:
        t = sorted(float(l.split("\t")[0]) for l in open(plog) if l.strip())
    except OSError:
        return 0
    best, j = 0, 0
    for i in range(len(t)):
        while t[i] - t[j] >= 1.0:
            j += 1
        best = max(best, i - j + 1)
    return best


def inhibit_prefix():
    exe = shutil.which("systemd-inhibit")
    if not exe:
        return [], "systemd-inhibit not installed"
    base = [exe, "--what=sleep:idle", "--who=kitc_guard", "--why=TLS campaign scan running", "--mode=block"]
    try:
        p = subprocess.run(base + ["true"], capture_output=True, text=True, timeout=10)
    except Exception as e:
        return [], f"systemd-inhibit unusable ({type(e).__name__})"
    if p.returncode != 0:
        return [], f"systemd-inhibit unusable (exit {p.returncode}: {p.stderr.strip()[:100]})"
    return base, "systemd-inhibit --what=sleep:idle active for the run"


def kill_group(pid, sig):
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def take_lock(out, resume):
    """Open DIR/.guard.lock and hold an exclusive flock on it for the guard's lifetime (released by the kernel when the
    guard dies, so a lock file left by a dead guard is stale). Fresh run: the file must not exist. -> (fd, note) or
    (None, reason)."""
    p = os.path.join(out, ".guard.lock")
    try:
        fd = os.open(p, os.O_RDWR | os.O_CREAT | (0 if resume else os.O_EXCL), 0o600)
    except FileExistsError:
        return None, ".guard.lock exists (another guard run in this directory)"
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None, ".guard.lock is held by a live process"
    toks = os.read(fd, 200).decode("ascii", "replace").split()
    if toks and toks[0].isdigit() and int(toks[0]) != os.getpid() and pid_is_guard(int(toks[0])):
        os.close(fd)
        return None, f".guard.lock names pid {toks[0]}, a live guard.py run"
    return fd, (f"stale lock of pid {toks[0]} taken over" if toks else "lock created")


def cmd_run(args):
    validate_common(args)
    want = f"GO-{args.date}-OPERATOR-APPROVED"
    if args.go is None:
        print(f"REFUSED: --go is required. It must be exactly {want}, typed by hand after the operator's explicit approval for this run.")
        return 2
    if args.go != want:
        print(f"REFUSED: --go does not equal {want}. Nothing was started.")
        return 2
    poll = NTP_POLL_SECONDS
    if os.environ.get("GUARD_NTP_POLL_SECONDS") is not None:          # test hook (TEST MODE)
        try:
            poll = float(os.environ["GUARD_NTP_POLL_SECONDS"])
        except ValueError:
            usage("GUARD_NTP_POLL_SECONDS must be a number")
        if not 0 < poll <= NTP_POLL_SECONDS:
            usage(f"GUARD_NTP_POLL_SECONDS must be in (0, {NTP_POLL_SECONDS:g}]")
    clock = Clock(args.zone)
    bl, is_test = banners(args)
    for b in bl:
        print(b)
    res = run_checks(args, clock)
    lines, ok = format_checks(res)
    print("\n".join(lines))
    if not ok:
        print("REFUSED: pre-flight failed. Nothing was started.")
        return 1
    extra_toks, resolve = parse_extra(getattr(args, "extra_run_args", ""))
    if is_test and not resolve_file_is_loopback(resolve):
        print("REFUSED: TEST MODE may only run with --extra-run-args '--resolve-file FILE' whose addresses are all loopback. Nothing was started.")
        return 2
    egress = next(r[4] for r in res if r[0] == "b")
    openssl = os.environ.get("OPENSSL", DEFAULT_OPENSSL)
    out = args.out
    os.makedirs(out, exist_ok=True)
    nonce = secrets.token_hex(16)
    lock_path = os.path.join(out, ".guard.lock")
    lock_fd, lock_note = take_lock(out, args.resume)
    if lock_fd is None:
        print(f"REFUSED: {lock_note}. Nothing was started.")
        return 1
    os.ftruncate(lock_fd, 0)
    os.lseek(lock_fd, 0, os.SEEK_SET)
    os.write(lock_fd, f"{os.getpid()} {nonce}\n".encode())
    os.fsync(lock_fd)
    log = Log(os.path.join(out, "guard.log"), clock, "taipei" if args.tz == DEFAULT_TZ else f"local {args.tz}")
    for b in bl:
        log(b)
    for l in lines:
        log("preflight " + l)
    rp, pp, gp = os.path.join(out, "results.tsv"), os.path.join(out, "probes.log"), os.path.join(out, "guard-meta.json")
    rows0, shakes0, prev = count_lines(rp), count_lines(pp), None
    if args.resume:
        try:
            prev = json.load(open(gp))
        except Exception:
            prev = None
        log(f"RESUME: {rows0} rows and {shakes0} handshakes already present in {out}; {lock_note}; run.py gets --resume "
            f"(skips targets with a row, counts the {shakes0} handshakes against the caps, appends to the same files)")
    now = clock.now()
    rtxt = (resolvers(os.environ.get('GUARD_RESOLV_CONF', '/etc/resolv.conf')) if args.resolver == "system" else
            f"{args.resolver} (kit-c dnsclient.py, RD=1)")
    vantage = (f"{args.vantage_label.strip()}; egress {egress}; run {args.date} {now.strftime('%H:%M')} {place(args.tz)} via kit-c guard.py; "
               f"resolver {rtxt}" + (f"; SMTP STARTTLS port 25, EHLO {args.ehlo_name}" if args.proto == "smtp" else "")
               + ("; QUIC UDP port 443, ALPN h3" if args.proto == "quic" else "")
               + ("; resumed" if args.resume else ""))
    cmd = [sys.executable, "-I", os.path.join(HERE, "run.py"), "--targets", args.targets, "--out", out] + CAMPAIGN_ARGS + [
           "--www", args.www, "--families", args.families, "--mode", args.mode, "--exclude-file", args.exclude_file,
           "--max-minutes", f"{args.max_minutes:g}", "--tz", args.tz, "--window", args.window, "--resolver", args.resolver,
           ] + proto_args(args) + ["--vantage", vantage
           ] + (["--resume"] if args.resume else []) + extra_toks
    pre, why = inhibit_prefix()
    log(why if pre else f"WARNING: {why}; the machine may sleep during the run")
    full = pre + cmd
    env = {k: v for k, v in os.environ.items() if not k.startswith("GUARD_") and k != "KITC_GUARD_NONCE"}
    env["OPENSSL"] = openssl
    env["KITC_GUARD_NONCE"] = nonce
    # check (k) once more, immediately before run.py starts
    ok_k, txt_k = check_clock_sync()
    log(f"pre-start {'PASS' if ok_k else 'FAIL'} (k) system clock synchronized: {txt_k}")
    if not ok_k:
        log("REFUSED: check (k) failed immediately before start. Nothing was started (exit 1)")
        os.unlink(lock_path)
        os.close(lock_fd)
        return 1
    # signal handlers before guard-meta.json says "running": from here on a SIGINT/SIGTERM always ends in STOP
    stop_path = os.path.join(out, "STOP")
    sig_flag = {"sig": None}
    signal.signal(signal.SIGINT, lambda s, f: sig_flag.__setitem__("sig", "SIGINT"))
    signal.signal(signal.SIGTERM, lambda s, f: sig_flag.__setitem__("sig", "SIGTERM"))
    meta = dict(campaign_ident(args), status="running", egress=egress, vantage=vantage, command=full, test_mode=is_test,
                taipei_start=now.astimezone(TZ).isoformat(), local_start=now.isoformat(), openssl=openssl,
                resume=bool(args.resume), rows_before=rows0,
                handshakes_before=shakes0,
                parts=(prev.get("parts", []) + [{k: v for k, v in prev.items() if k != "parts"}]) if isinstance(prev, dict) else [])
    write_json_atomic(gp, meta)
    log("command: " + " ".join(shlex.quote(c) for c in full))
    so = open(os.path.join(out, "stdout.log"), "a")
    t_start = time.monotonic()
    proc = subprocess.Popen(full, stdout=so, stderr=so, env=env, start_new_session=True)
    log(f"started run.py chain, pid {proc.pid}, max {args.max_minutes:g} min, watchdog stops at "
        f"{args.win_end.strftime('%H:%M')} {place(args.tz)} or when "
        f"check (k) fails (polled every {poll:g} s)")
    reason, t_stop, phase, t_ntp = None, None, 0, time.monotonic()
    while True:
        rc = proc.poll()
        if rc is not None:
            break
        n = clock.now()
        if reason is None:
            if n.time() >= args.win_end or n.time() < args.win_start or n.date().isoformat() != args.date:
                reason = (f"{place(args.tz)} clock reached {n.strftime('%Y-%m-%d %H:%M:%S')} (outside {args.window} of "
                          f"{args.date})")
            elif time.monotonic() - t_start > args.max_minutes * 60:
                reason = f"run exceeded {args.max_minutes:g} min"
            elif sig_flag["sig"]:
                reason = f"guard received {sig_flag['sig']}"
            elif time.monotonic() - t_ntp >= poll:
                t_ntp = time.monotonic()
                ok_k, txt_k = check_clock_sync()
                if not ok_k:
                    reason = f"system clock no longer synchronized, check (k) failed: {txt_k}"
            if reason:
                with open(stop_path, "w") as f:
                    f.write(f"guard watchdog: {reason}\n")
                t_stop = time.monotonic()
                log(f"WATCHDOG: {reason}; created {stop_path}")
        elif phase == 0 and time.monotonic() - t_stop > args.grace_seconds:
            log(f"WATCHDOG: run still alive {args.grace_seconds:g} s after STOP; sending SIGTERM to its process group")
            kill_group(proc.pid, signal.SIGTERM)
            phase, t_stop = 1, time.monotonic()
        elif phase == 1 and time.monotonic() - t_stop > 10:
            log("WATCHDOG: run still alive 10 s after SIGTERM; sending SIGKILL")
            kill_group(proc.pid, signal.SIGKILL)
            phase = 2
        time.sleep(0.25)
    if reason is None and sig_flag["sig"]:
        # e.g. at shutdown the signal reaches the guard and the run.py chain together, and the chain (systemd-inhibit)
        # dies before the loop sees the flag: write STOP here too, so a signal always ends in STOP (no resume)
        reason = f"guard received {sig_flag['sig']}"
        with open(stop_path, "w") as f:
            f.write(f"guard watchdog: {reason} (run.py chain had already ended)\n")
        log(f"WATCHDOG: {reason} (run.py ended with it); created {stop_path}")
    kill_group(proc.pid, signal.SIGKILL)   # nothing may outlive the guard
    rows = count_lines(rp)
    shakes = count_lines(pp)
    mx = max_per_second(pp)
    elapsed = time.monotonic() - t_start
    stop_now = os.path.exists(stop_path)
    log(f"run.py exited with {rc} after {elapsed:.0f} s; results.tsv rows {rows}, handshakes started {shakes}"
        + (f" (of which {rows0} rows and {shakes0} handshakes from earlier parts)" if args.resume else "")
        + f", max in any 1 s window {mx}, STOP present: {stop_now}")
    status = "stopped" if reason else "failed" if rc != 0 else "incomplete" if stop_now else "finished"
    meta.update(status=status, watchdog_reason=reason, exit_code=rc, rows=rows, handshakes=shakes, max_per_second=mx,
                elapsed_s=round(elapsed), taipei_end=clock.now().astimezone(TZ).isoformat(), local_end=clock.now().isoformat())
    write_json_atomic(gp, meta)
    if reason:
        log("RESULT: stopped by the watchdog; the run is truncated (exit 3)")
        return 3
    if rc != 0:
        log(f"RESULT: run.py failed with exit {rc} (exit 4)")
        return 4
    if stop_now:
        log("RESULT: run.py ended while STOP is present (circuit breaker, max-minutes in run.py or manual STOP); incomplete (exit 5)")
        return 5
    log("RESULT: run finished cleanly. Next: compress nothing (traces are already xz); see README.md 'After a run'")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="guard.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "run"):
        p = sub.add_parser(name)
        p.add_argument("--date", required=True, help="local date (in --tz) of this run, YYYY-MM-DD")
        p.add_argument("--allowed-dates", required=True, help="comma-separated dates on which a run is approved (no default)")
        p.add_argument("--out", required=True, help="new output directory; its name must contain the date")
        p.add_argument("--targets", required=True, help="ranked name list (or the all-addresses sample file)")
        p.add_argument("--targets-sha256", required=True, help="sha256 of the approved targets file")
        p.add_argument("--expected-egress", required=True, help="IPv4 source address announced to the network operator")
        p.add_argument("--expected-egress6", default=None, help="IPv6 source prefix (required with --families 4,6 or 6)")
        p.add_argument("--egress-prefix", default=DEFAULT_PREFIX)
        p.add_argument("--allow-unannounced-egress", action="store_true", help="OVERRIDE: mismatch with --expected-egress is a WARN")
        p.add_argument("--vantage-label", required=True, help='e.g. "University campus, AS64500, City"')
        p.add_argument("--max-minutes", type=float, required=True, help=f"watchdog limit, at most {MAX_MINUTES_CAP:g}")
        p.add_argument("--families", default="4")
        p.add_argument("--www", choices=("off", "add"), default="off")
        p.add_argument("--mode", choices=("pinned", "alladdr"), default="pinned")
        p.add_argument("--exclude-file", default=os.path.join(HERE, "exclude.txt"))
        p.add_argument("--assume-reachable", type=float, default=0.84, help="load plan only")
        p.add_argument("--assume-pq", type=float, default=0.45, help="load plan only")
        p.add_argument("--min-free-gb", type=float, default=DEFAULT_MIN_FREE)
        p.add_argument("--resume", action="store_true", help="continue an interrupted run in the existing --out (see (e))")
        p.add_argument("--tz", default=None, help=f"IANA time zone of the vantage (default {DEFAULT_TZ}); needs --window")
        p.add_argument("--window", default=None, help=f"local scan window HH:MM-HH:MM, start < end (default {DEFAULT_WINDOW})")
        p.add_argument("--resolver", default="system", help="system (getaddrinfo) or the IPv4 address of a recursive resolver")
        p.add_argument("--proto", choices=("https", "smtp", "quic"), default="https")
        p.add_argument("--ehlo-name", default=None, help="smtp: EHLO name (required with --proto smtp)")
        p.add_argument("--smtp-timeout", type=float, default=None, help=f"smtp: seconds per exchange (default {SMTP_TIMEOUT_DEFAULT:g})")
        p.add_argument("--per-ip-cap", type=int, default=None, help=f"smtp: handshakes per address per campaign (default {PER_IP_CAP_MAX})")
        p.add_argument("--quic-timeout", type=float, default=None, help=f"quic: seconds per probe (default {QUIC_TIMEOUT_DEFAULT:g})")
        if name == "run":
            p.add_argument("--go", default=None, help="must equal GO-<date>-OPERATOR-APPROVED")
            p.add_argument("--grace-seconds", type=float, default=45.0, help="wait this long after STOP before signalling the process group")
            p.add_argument("--extra-run-args", default="", help="TEST ONLY: --resolve-file FILE [--limit N]")
    args = ap.parse_args()
    sys.exit({"check": cmd_check, "run": cmd_run}[args.cmd](args))


if __name__ == "__main__":
    main()
