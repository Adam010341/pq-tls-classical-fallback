#!/usr/bin/env python3
"""Offline tests for kit-c (run.py, probe_one.sh, guard.py).  Run via ../run_tests.sh, or:  python3 -I tests/test_kit.py

The script re-executes itself inside `unshare -Urnm` (new user, network and mount namespaces). Inside:
  * the network namespace has only loopback; the test asserts this before doing anything;
  * /run is replaced by an empty tmpfs (hides the host's systemd-resolved, avahi and D-Bus sockets, which would
    otherwise be reachable through the file system), /etc/resolv.conf points to 127.0.0.1 and nsswitch to
    "files dns", so every DNS lookup goes to tests/stub_dns.py on 127.0.0.1:53 and is logged;
  * the work directory tests/.work is a tmpfs: nothing a test writes reaches the disk, and it vanishes at exit.
Servers are local `openssl s_server` instances. Expected values come from how the fixtures are built (which server
answers which name, which fake time or address is injected), never from the code under test.
"""
import os, sys, subprocess

TESTS = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(TESTS)
WORK = os.path.join(TESTS, ".work")
if os.environ.get("KITC_TEST_INNER") != "1":
    os.makedirs(WORK, exist_ok=True)
    env = dict(os.environ, KITC_TEST_INNER="1", OPENSSL=os.environ.get("OPENSSL", "openssl"))
    sh = ('set -e; ip link set lo up; mount -t tmpfs -o size=512m none "$1"; mount -t tmpfs none /run; '
          'shift; exec python3 -I "$0" "$@"')
    r = subprocess.run(["unshare", "-Urnm", "bash", "-c", sh, os.path.abspath(__file__), WORK] + sys.argv[1:], env=env)
    try:
        os.rmdir(WORK)
    except OSError:
        pass
    sys.exit(r.returncode)

import collections, hashlib, ipaddress, json, lzma, random, re, shutil, signal, socket, threading, time, traceback

OPENSSL = os.environ["OPENSSL"]
RUNPY = os.path.join(KIT, "run.py")
PROBE = os.path.join(KIT, "probe_one.sh")
PROBE_SMTP = os.path.join(KIT, "probe_smtp.sh")
PROBE_QUIC = os.path.join(KIT, "probe_quic.sh")
QUIC_TARGETS = os.path.join(KIT, "quic_targets.py")
QSRV_C = os.path.join(TESTS, "qsrv.c")
MXLIST = os.path.join(KIT, "mxlist.py")
STUB = os.path.join(TESTS, "stub_dns.py")
FAKE_DNS = os.path.join(TESTS, "fake_dns.py")
FAKE_SMTP = os.path.join(TESTS, "fake_smtp.py")
FDNS_IP = "127.0.0.2"                     # fake recursive resolver for --resolver (the system resolver is the stub on .1)
G = {"p1": "*X25519MLKEM768:*X25519", "p2": "X25519MLKEM768:*X25519", "p3": "*X25519:X25519MLKEM768", "pa": "*X25519:*X25519MLKEM768"}
P_HYB, P_DEF, P_CLS, P_DEAD, P_HANG = 4532, 4533, 4534, 4539, 4538     # HYB: groups X25519MLKEM768:X25519 (one tuple)
# SMTP: fake_smtp.py front ends (plaintext SMTP, then a raw relay) in front of s_server back ends
P_SB_DEF, P_SB_HYB = 4541, 4542                                          # back ends: default groups / X25519MLKEM768:X25519
S_DEF, S_HYB, S_454 = 2501, 2502, 2504                                   # front ends on 0.0.0.0 (any 127.x address), and :25
SHARED_IP = "127.0.0.5"
# QUIC: tests/qsrv.c servers (UDP, built into the tmpfs work dir); WAIT = seconds a server waits for the client's close
Q_DEF, Q_COL, Q_NV, Q_P256 = 4801, 4802, 4803, 4805                   # evidence servers (default+Retry, colon list, no Retry,
Q_SINK, Q_CLOSED = 4806, 4807                                           # P-256 only); count-and-drop; nobody listens
Q_HYB = (4804, 4808, 4809)                  # hybrid-only servers, started fresh in q02 (the PING storm needs a new server)
Q_SDEF, Q_SCOL = 4811, 4812                                             # scan servers (WAIT 0.2): default, colon list
QWAIT = "1.5"
EHLO = "probe.kitc.test"
CELL = re.compile(r"^(ok|fail)\|ch=\d+\|hrr=[01]\|sh=\d+\|grp=[A-Za-z0-9_-]+$")
GDATE = "2026-01-15"                      # a past date: test GO phrases can never match a real future run
GO = f"GO-{GDATE}-OPERATOR-APPROVED"
IN_WIN = f"{GDATE}T03:00:00+08:00"
EGR = "140.116.1.2"
procs, results, failures = [], {"pass": 0, "fail": 0}, []
DNSLOG = os.path.join(WORK, "dns-queries.log")
FDNSLOG = os.path.join(WORK, "fake-dns-queries.log")
FDNS_ZONE = {
    "zone": {"a.dns.test": [["A", "127.0.0.1"], ["AAAA", "::1"]], "v4.dns.test": [["A", "127.0.0.1"]],
             "c1.dns.test": [["CNAME", "c2.dns.test"]], "c2.dns.test": [["CNAME", "a.dns.test"]],
             "r1.dns.test": [["CNAME", "r2.dns.test"]], "r2.dns.test": [["CNAME", "a.dns.test"]],
             "l1.dns.test": [["CNAME", "l2.dns.test"]], "l2.dns.test": [["CNAME", "l1.dns.test"]],
             "l3.dns.test": [["CNAME", "l4.dns.test"]], "l4.dns.test": [["CNAME", "l3.dns.test"]],
             "dangling.dns.test": [["CNAME", "gone.dns.test"]],
             **{f"k{i}.dns.test": [["CNAME", f"k{i + 1}.dns.test" if i < 9 else "a.dns.test"]] for i in range(10)},
             "tc.dns.test": [["A", "127.0.0.1"]], "badid.dns.test": [["A", "127.0.0.1"]],
             "badidok.dns.test": [["A", "127.0.0.1"]], "badq.dns.test": [["A", "127.0.0.1"]],
             "ptr.dns.test": [["A", "127.0.0.1"]], "drop.dns.test": [["A", "127.0.0.1"]],
             "mail.test": [["MX", 20, "mx2.mail.test"], ["MX", 10, "mx1.mail.test"]],
             "shared1.test": [["MX", 10, "mx.shared.test"]], "shared2.test": [["MX", 10, "MX.Shared.Test"]],
             "nullmx.test": [["MX", 0, ""]], "nomx.test": [["A", "127.0.0.1"]], "cnamemx.test": [["CNAME", "mail.test"]],
             "badmx.test": [["MX", 10, "bad_name!.test"]],
             "multi.test": [["MX", 10, "b.multi.test"], ["MX", 10, "a.multi.test"], ["MX", 30, "c.multi.test"]],
             "skip.excl-mx.test": [["MX", 10, "mx.excl.test"]], "mx.smtp.test": [["A", "127.0.0.1"]]},
    "cname_only": ["r1.dns.test", "r2.dns.test", "l3.dns.test", "l4.dns.test"] + [f"k{i}.dns.test" for i in range(10)],
    "behave": {"tc.dns.test": "tc", "badid.dns.test": "badid", "badidok.dns.test": "badid-then-good", "badq.dns.test": "badq",
               "ptr.dns.test": "ptrloop", "drop.dns.test": "drop", "sf.dns.test": "servfail", "ref.dns.test": "refused",
               "sfmx.test": "servfail"}}


# ------------------------------------------------------------------------------------------------- helpers
def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def runpy(*args, env=None, timeout=180, script=RUNPY):
    e = dict(os.environ) if env is None else env
    e.pop("KITC_GUARD_NONCE", None)
    p = subprocess.run([sys.executable, "-I", script, *args], capture_output=True, text=True, env=e, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def bg_runpy(*args, env=None):
    e = dict(os.environ) if env is None else env
    return subprocess.Popen([sys.executable, "-I", RUNPY, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=e)


def rows(out):
    p = os.path.join(out, "results.tsv")
    return [l.rstrip("\n").split("\t") for l in open(p)] if os.path.exists(p) else []


def plog(out):
    p = os.path.join(out, "probes.log")
    return [l.rstrip("\n").split("\t") for l in open(p) if l.strip()] if os.path.exists(p) else []


def max_in_window(ts):
    ts = sorted(ts)
    best, j = 0, 0
    for i in range(len(ts)):
        while ts[i] - ts[j] >= 1.0:
            j += 1
        best = max(best, i - j + 1)
    return best


def resolve_file(name, mapping):
    """mapping: {name: "addr[,addr]" or "-"}"""
    return w(os.path.join(WORK, name), "".join(f"{h}\t{a}\n" for h, a in mapping.items()))


def targets_file(name, names):
    return w(os.path.join(WORK, name), "".join(n + "\n" for n in names))


def dns_queries():
    try:
        return [l.rstrip("\n").split("\t") for l in open(DNSLOG)]
    except OSError:
        return []


def wait_gone(substr, timeout=30):
    t = time.time() + timeout
    while time.time() < t:
        if not procs_mentioning(substr):
            return True
        time.sleep(0.2)
    return False


def procs_mentioning(s):
    found = []
    for d in os.listdir("/proc"):
        if d.isdigit() and int(d) != os.getpid():
            try:
                cl = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
                st = open(f"/proc/{d}/stat").read().split(")")[-1].split()[0]
            except OSError:
                continue
            if s in cl and st != "Z":
                found.append((int(d), cl[:120]))
    return found


def test(fn):
    name = fn.__name__
    t0 = time.time()
    try:
        fn()
        results["pass"] += 1
        print(f"  ok   {name} ({time.time() - t0:.1f}s)", flush=True)
    except Exception as e:
        results["fail"] += 1
        failures.append(name)
        msg = str(e)
        print(f"  FAIL {name}: {type(e).__name__}: {msg if len(msg) < 2500 else msg[:800] + ' ... ' + msg[-1500:]}", flush=True)
        if not isinstance(e, AssertionError):
            traceback.print_exc()


def start(cmd, out=subprocess.DEVNULL):
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    procs.append(p)
    return p


CERT = os.path.join(WORK, "certs")


def sserver(accept, groups=None, trace=None, naccept=None):
    cmd = [OPENSSL, "s_server", "-cert", f"{CERT}/c.pem", "-key", f"{CERT}/k.pem", "-tls1_3", "-www", "-accept", str(accept)]
    cmd += ["-groups", groups] if groups else []
    cmd += ["-naccept", str(naccept)] if naccept else []
    if trace:
        return start(cmd + ["-trace"], out=open(trace, "w"))
    return start(cmd + ["-quiet"])


def wait_port(host, port, timeout=5):
    t = time.time() + timeout
    while time.time() < t:
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server on {host}:{port} did not come up")


def wait_listen(port, timeout=5):
    """Wait until something listens on the port (without connecting: one-shot -naccept servers must not be used up)."""
    t = time.time() + timeout
    hexport = f"{port:04X}"
    while time.time() < t:
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                for l in open(f).readlines()[1:]:
                    p = l.split()
                    if p[1].endswith(":" + hexport) and p[3] == "0A":
                        return
            except OSError:
                pass
        time.sleep(0.05)
    raise RuntimeError(f"nothing listening on {port}")


# ------------------------------------------------------------------------------------------------- setup
def setup():
    # isolation: loopback only, host resolver sockets hidden, DNS -> local stub
    ifs = [n for _, n in socket.if_nameindex()]
    assert ifs == ["lo"], f"network namespace must have loopback only, has {ifs}"
    for s in ("/run/systemd/resolve/io.systemd.Resolve", "/run/dbus/system_bus_socket", "/run/avahi-daemon/socket"):
        assert not os.path.exists(s), s
    rc = os.path.realpath("/etc/resolv.conf")
    conf = "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"
    if rc.startswith("/run/"):
        w(rc, conf)
    else:
        subprocess.run(["mount", "--bind", w(os.path.join(WORK, "resolv.conf"), conf), "/etc/resolv.conf"], check=True)
    subprocess.run(["mount", "--bind", w(os.path.join(WORK, "nsswitch.conf"), "hosts: files dns\n"), "/etc/nsswitch.conf"], check=True)
    assert open("/etc/resolv.conf").read() == conf
    print(f"isolation: interfaces {ifs}; /run is an empty tmpfs; resolver = stub on 127.0.0.1:53; work dir {WORK} is tmpfs", flush=True)
    os.makedirs(CERT)
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{CERT}/k.pem",
                    "-out", f"{CERT}/c.pem", "-subj", "/CN=localhost", "-days", "2"], capture_output=True, check=True)
    sserver(P_HYB, "X25519MLKEM768:X25519")
    sserver(P_DEF)
    sserver(P_CLS, "X25519")
    sserver(443, "X25519MLKEM768:X25519")        # for the stub-DNS tests (real port 443, all local addresses, v4 and v6)
    w(os.path.join(WORK, "hang.py"), "import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
      f"s.bind(('127.0.0.1',{P_HANG}));s.listen(100)\nc=[]\nwhile True:\n    c.append(s.accept()[0])\n")
    start([sys.executable, "-I", os.path.join(WORK, "hang.py")])
    table = {"d1.test": ["127.0.0.1", "::1"], "www.d1.test": ["127.0.0.1"], "excl-dns.test": ["127.0.0.1"],
             "www.excl-dns.test": ["127.0.0.1"], "q.zone-ex.test": ["127.0.0.1"], "v4only.test": ["127.0.0.1"],
             "far.test": ["192.0.2.10"], "mx25.test": ["127.0.0.1"], "quic443.test": ["127.0.0.1"]}
    w(os.path.join(WORK, "dns.json"), json.dumps(table))
    start([sys.executable, "-I", STUB, os.path.join(WORK, "dns.json"), DNSLOG])
    w(os.path.join(WORK, "fake-dns.json"), json.dumps(FDNS_ZONE))
    start([sys.executable, "-I", FAKE_DNS, os.path.join(WORK, "fake-dns.json"), FDNSLOG, FDNS_IP, "53"])
    sserver(P_SB_DEF)
    sserver(P_SB_HYB, "X25519MLKEM768:X25519")
    for port, back, opts in ((S_DEF, P_SB_DEF, ()), (S_HYB, P_SB_HYB, ()),
                             (S_454, P_SB_HYB, ("starttls-reply=454 4.7.0 TLS not available",)), (25, P_SB_HYB, ())):
        start([sys.executable, "-I", FAKE_SMTP, "0.0.0.0", str(port), str(back), os.path.join(WORK, f"smtp-front-{port}.log"), *opts])
    for port in (P_HYB, P_DEF, P_CLS, 443, P_HANG, P_SB_DEF, P_SB_HYB):
        wait_port("127.0.0.1", port)
    for port in (S_DEF, S_HYB, S_454, 25):
        wait_listen(port)
    quic_setup()
    wait_port("::1", P_HYB)
    wait_port(FDNS_IP, 53)
    time.sleep(0.3)
    # stub sanity: the system resolver really goes to the stub
    assert socket.getaddrinfo("d1.test", 443, socket.AF_INET)[0][4][0] == "127.0.0.1"
    assert ["d1.test", "A"] in dns_queries(), dns_queries()


# ------------------------------------------------------------------------------------------------- 1. no application data
def server_view(trace_path):
    """Parse an s_server -trace log -> (received inner content types, client close_notify seen)."""
    recv, cur, cn = [], None, False
    for l in open(trace_path, errors="replace"):
        if re.match(r"Received (TLS )?Record", l):
            cur = "R"
        elif re.match(r"Sent (TLS )?Record", l):
            cur = "S"
        m = re.search(r"Inner Content Type = (\w+)", l)
        if m and cur == "R":
            recv.append(m.group(1))
        if cur == "R" and "description=close notify" in l:
            cn = True
    return recv, cn


def client_sent_appdata(trace_path):
    cur, n = None, 0
    for l in open(trace_path, errors="replace"):
        if re.search(r"Sent (TLS )?Record", l):
            cur = "S"
        elif re.search(r"Received (TLS )?Record", l):
            cur = "R"
        if cur == "S" and "Inner Content Type = ApplicationData" in l:
            n += 1
    return n


def one_probe_against_traced_server(port, groups_srv, label, ip, tag):
    tr = os.path.join(WORK, f"srv-{tag}.trace")
    srv = sserver(port, groups_srv, trace=tr, naccept=1)
    wait_listen(port)
    ctr = os.path.join(WORK, f"cli-{tag}.trace")
    tok = subprocess.run(["bash", PROBE, "x.test", ip, str(port), label, G[label], ctr], capture_output=True, text=True,
                         timeout=30, stdin=subprocess.DEVNULL).stdout.strip()
    srv.wait(timeout=10)
    return tok, tr, ctr


def p01_no_application_data_server_trace():
    cases = [("p1", "X25519MLKEM768:X25519", "127.0.0.1", "grp=X25519MLKEM768", "hrr=0"),
             ("p2", None, "::1", "grp=X25519MLKEM768", "hrr=1"),           # default server: HelloRetryRequest path
             ("p3", "X25519MLKEM768:X25519", "127.0.0.1", "grp=ecdh_x25519", "hrr=0"),
             ("pa", None, "::1", "grp=X25519MLKEM768", "hrr=0")]
    for i, (lab, gs, ip, grp, hrr) in enumerate(cases):
        tok, tr, ctr = one_probe_against_traced_server(4600 + i, gs, lab, ip, f"new{i}")
        assert tok.startswith("ok|") and grp in tok and hrr in tok, (lab, tok)
        recv, cn = server_view(tr)
        assert "Handshake" in recv, (lab, recv)                      # the server did decrypt the client's Finished
        assert "ApplicationData" not in recv, f"{lab}: server received application data from the client: {recv}"
        assert cn, f"{lab}: no close_notify from the client in the server trace"
        assert client_sent_appdata(ctr) == 0, f"{lab}: client trace shows sent application data"
    # positive control: the old pipeline (`echo | s_client`) IS detected by the same parser
    tr = os.path.join(WORK, "srv-old.trace")
    srv = sserver(4610, "X25519MLKEM768:X25519", trace=tr, naccept=1)
    wait_listen(4610)
    subprocess.run(f"echo | timeout 12 {OPENSSL} s_client -connect 127.0.0.1:4610 -servername x.test -tls1_3 "
                   f"-groups '{G['p1']}' -trace > {WORK}/cli-old.trace 2>&1", shell=True, timeout=30)
    srv.wait(timeout=10)
    recv, _ = server_view(tr)
    assert recv.count("ApplicationData") == 1, f"control: old pipeline should show exactly one client data record: {recv}"
    assert client_sent_appdata(os.path.join(WORK, "cli-old.trace")) == 1


def p02_slow_server_still_completes_without_data():
    """stdin is at EOF from the start; s_client must still wait for a slow handshake (relay delays the server 1.5 s)."""
    tr = os.path.join(WORK, "srv-slow.trace")
    srv = sserver(4620, "X25519MLKEM768:X25519", trace=tr, naccept=1)
    wait_listen(4620)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 4621))
    ls.listen(1)

    def pump(a, b, delay):
        first = True
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                if first and delay:
                    time.sleep(delay)
                first = False
                b.sendall(d)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def relay():
        c, _ = ls.accept()
        u = socket.create_connection(("127.0.0.1", 4620))
        threading.Thread(target=pump, args=(c, u, 0), daemon=True).start()
        pump(u, c, 1.5)

    threading.Thread(target=relay, daemon=True).start()
    t0 = time.time()
    tok = subprocess.run(["bash", PROBE, "x.test", "127.0.0.1", "4621", "p1", G["p1"], os.path.join(WORK, "cli-slow.trace")],
                         capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL).stdout.strip()
    el = time.time() - t0
    srv.wait(timeout=10)
    ls.close()
    assert el >= 1.4 and tok.startswith("ok|") and "grp=X25519MLKEM768" in tok, (el, tok)
    recv, cn = server_view(tr)
    assert "ApplicationData" not in recv and cn, recv


# ------------------------------------------------------------------------------------------------- 2. probe set
EXP = {  # server -> expected (hrr, grp) per probe, from the server configuration (see setup)
    "ex": {"p1": ("0", "X25519MLKEM768"), "p2": ("0", "ecdh_x25519"), "p3": ("0", "ecdh_x25519"), "pa": ("0", "ecdh_x25519")},
    "pf": {"p1": ("0", "X25519MLKEM768"), "p2": ("1", "X25519MLKEM768"), "p3": ("1", "X25519MLKEM768"), "pa": ("0", "X25519MLKEM768")},
}


def r01_probe_set_and_cells():
    m = {}
    for i in range(1, 4):
        m[f"ex{i}.test"] = f"127.0.0.1:{P_HYB}"
        m[f"pf{i}.test"] = f"127.0.0.1:{P_DEF}"
        m[f"cl{i}.test"] = f"127.0.0.1:{P_CLS}"
    m.update({"dead1.test": f"127.0.0.1:{P_DEAD}", "hang1.test": f"127.0.0.1:{P_HANG}", "noaddr1.test": "-"})
    names = list(m)
    rf = resolve_file("r01.tsv", m)
    tf = targets_file("r01-targets.txt", names)
    o = os.path.join(WORK, "r01")
    env = dict(os.environ, PROBE_TIMEOUT="3")
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--workers", "8", env=env)
    assert rc == 0, out
    rs = {r[0]: r for r in rows(o)}
    assert sorted(rs) == sorted(names), sorted(rs)
    for r in rs.values():
        assert len(r) == 14 and r[10] == "4" and r[11] == "list" and r[13] == "pinned", r
        assert int(r[12]) == names.index(r[0]) + 1, r                     # rank = position in the list
    for h, r in rs.items():
        kind = h[:2]
        cells = {"p1": r[3], "p2": r[4], "p3": r[5], "pa": r[9]}
        if kind in EXP:
            for lab, (hrr, grp) in EXP[kind].items():
                c = cells[lab]
                assert CELL.match(c) and c.startswith("ok|") and f"hrr={hrr}" in c and c.endswith(f"grp={grp}"), (h, lab, c)
        elif kind == "cl":
            assert cells["p1"].startswith("ok|") and cells["p1"].endswith("grp=ecdh_x25519"), r
            assert cells["p2"] == cells["p3"] == cells["pa"] == "skip", r
        elif h in ("dead1.test", "hang1.test"):
            assert cells["p1"].startswith("fail|") and CELL.match(cells["p1"]), r
            assert cells["p2"] == cells["p3"] == cells["pa"] == "skip", r
        elif h == "noaddr1.test":
            assert r[1] == "-" and cells["p1"] == "noaddr", r
    seq = {}
    for p in plog(o):
        seq.setdefault(p[1], []).append(p[2])
    for h in names:
        want = ["p1", "p2", "p3", "pa"] if h[:2] in EXP else ([] if h == "noaddr1.test" else ["p1"])
        assert seq.get(h, []) == want, (h, seq.get(h))
    n = len(plog(o))
    assert n == 6 * 4 + 5, n
    # raw traces: one JSON line per handshake in traces.jsonl.xz, no temporary files left
    lines = lzma.decompress(open(os.path.join(o, "traces.jsonl.xz"), "rb").read()).decode().splitlines()
    assert len(lines) == n, (len(lines), n)
    recs = [json.loads(l) for l in lines]
    assert all("ClientHello" in x["trace"] for x in recs if x["host"].startswith(("ex", "pf", "cl")))
    # every record carries the probe's wall time in ms: short for loopback handshakes, >= PROBE_TIMEOUT (3 s) for the hang
    assert all(isinstance(x.get("dur_ms"), float) and x["dur_ms"] > 0 for x in recs), [x.get("dur_ms") for x in recs]
    assert all(x["dur_ms"] < 2500 for x in recs if x["host"].startswith(("ex", "pf", "cl"))), [(x["host"], x["dur_ms"]) for x in recs]
    assert all(x["dur_ms"] >= 2900 for x in recs if x["host"] == "hang1.test"), [(x["host"], x["dur_ms"]) for x in recs]
    assert not os.path.exists(os.path.join(o, ".tmp-traces"))
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    assert meta["rate_per_s"] == 18.0 and meta["cap_per_target"] == 4 and meta["guarded"] is False and meta["groups"] == G
    assert (meta["proto"], meta["port"], meta["ehlo_name"], meta["smtp_timeout"], meta["per_ip_cap"]) == ("https", 443, None, None, 0), meta


def r02_cap_and_limits():
    rf = resolve_file("r02.tsv", {f"ex{i}.test": f"127.0.0.1:{P_HYB}" for i in range(1, 4)})
    tf = targets_file("r02-targets.txt", [f"ex{i}.test" for i in range(1, 4)])
    o = os.path.join(WORK, "r02")
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--cap", "2")
    assert rc == 0, out
    for r in rows(o):
        assert r[3].startswith("ok|") and r[4].startswith("ok|") and r[5] == "capped" and r[9] == "capped", r
    cnt = {}
    for p in plog(o):
        cnt[(p[1], p[3])] = cnt.get((p[1], p[3]), 0) + 1
    assert set(cnt.values()) == {2}, cnt
    for bad in (("--cap", "5"), ("--rate", "21"), ("--rate", "0")):
        rc, out = runpy("--targets", tf, "--out", os.path.join(WORK, "r02-bad"), "--resolve-file", rf, *bad)
        assert rc == 2 and not os.path.exists(os.path.join(WORK, "r02-bad")), (bad, rc, out)
    # retries included: handshakes from an earlier, interrupted invocation count against the cap of 4
    o2 = os.path.join(WORK, "r02-resume")
    os.makedirs(o2)
    t = time.time()
    w(os.path.join(o2, "probes.log"), "".join(f"{t - 100 + k:.3f}\tex1.test\tp1\t127.0.0.1\t{P_HYB}\n" for k in range(3)))
    rc, out = runpy("--targets", tf, "--out", o2, "--resolve-file", rf)
    assert rc == 0, out
    rs = {r[0]: r for r in rows(o2)}
    assert rs["ex1.test"][3].startswith("ok|") and rs["ex1.test"][4] == rs["ex1.test"][5] == rs["ex1.test"][9] == "capped", rs["ex1.test"]
    assert rs["ex2.test"][9].startswith("ok|"), rs["ex2.test"]
    assert sum(1 for p in plog(o2) if p[1] == "ex1.test") == 4


# ------------------------------------------------------------------------------------------------- 3. targets
def r03_www_variants_and_csv():
    tf = w(os.path.join(WORK, "r03.csv"), "rank,domain\n1,a.test\n2,www.b.test\n3,c.test\n4,ex-excl.test\n5,www.c.test\n6,bad_name!\n")
    ex = w(os.path.join(WORK, "r03-ex.txt"), "ex-excl.test\n")
    rf = resolve_file("r03.tsv", {n: f"127.0.0.1:{P_CLS}" for n in
                                  ("a.test", "www.a.test", "www.b.test", "c.test", "www.c.test", "ex-excl.test", "www.ex-excl.test")})
    o = os.path.join(WORK, "r03")
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--www", "add", "--exclude-file", ex)
    assert rc == 0, out
    got = {(r[0], r[11], r[12], r[3].split("|")[0]) for r in rows(o)}
    want = {("a.test", "list", "1", "ok"), ("www.a.test", "www", "1", "ok"), ("www.b.test", "list", "2", "ok"),
            ("c.test", "list", "3", "ok"), ("www.c.test", "list", "5", "ok"), ("ex-excl.test", "list", "4", "excluded"),
            ("www.ex-excl.test", "www", "4", "excluded"), ("bad_name!", "list", "6", "invalid")}
    assert got == want, sorted(got ^ want)
    assert not any("excl" in p[1] for p in plog(o)), plog(o)
    assert len(plog(o)) == 5


def r04_families_and_pinning():
    names = [f"m{i:02d}.test" for i in range(20)]
    v4 = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
    rf = resolve_file("r04.tsv", {n: ",".join(f"{a}:{P_CLS}" for a in v4) + f",[::1]:{P_CLS}" for n in names})
    tf = targets_file("r04-targets.txt", names)
    pins = {}
    for tag, seed in (("a", "1"), ("b", "1"), ("c", "2")):
        o = os.path.join(WORK, f"r04{tag}")
        rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--families", "4,6", "--seed", seed)
        assert rc == 0, out
        rs = rows(o)
        assert len(rs) == 40 and all(r[3].startswith("ok|") for r in rs), rs
        pins[tag] = {(r[0], r[10]): r[1] for r in rs}
        for r in rs:
            assert r[2] == ("3" if r[10] == "4" else "1"), r
            if r[10] == "6":
                assert r[1] == "::1", r
            else:
                assert r[1] == random.Random(f"{seed}:{r[0]}").choice(sorted(v4)), r      # campaign-2 formula
        assert {(p[1], p[3]) for p in plog(o)} == {(k[0], v) for k, v in pins[tag].items()}
    assert pins["a"] == pins["b"]
    assert pins["a"] != pins["c"]


def r05_all_addresses_mode():
    names = [f"aa{i}.test" for i in range(1, 4)]
    addrs = f"127.0.0.1:{P_HYB},127.0.0.2:{P_CLS},127.0.0.3:{P_DEF},127.0.0.4:{P_HYB},[::1]:{P_HYB}"
    rf = resolve_file("r05.tsv", {n: addrs for n in names})
    tf = targets_file("r05-sample.txt", names)
    o = os.path.join(WORK, "r05")
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--families", "4,6", "--mode", "alladdr")
    assert rc == 0, out
    rs = rows(o)
    assert len(rs) == 3 * 5, len(rs)
    for r in rs:
        assert r[13] == "alladdr" and r[5] == "skip" and r[9] == "skip", r
        if r[1] == "127.0.0.2":
            assert r[3].endswith("grp=ecdh_x25519") and r[4] == "skip", r
        else:
            assert r[3].endswith("grp=X25519MLKEM768") and r[4].startswith("ok|"), r
        assert r[2] == ("4" if r[10] == "4" else "1"), r
    assert {p[2] for p in plog(o)} == {"p1", "p2"}
    cnt = {}
    for p in plog(o):
        cnt[(p[1], p[3])] = cnt.get((p[1], p[3]), 0) + 1
    assert len(cnt) == 15 and max(cnt.values()) == 2, cnt
    o2 = os.path.join(WORK, "r05b")
    rc, out = runpy("--targets", tf, "--out", o2, "--resolve-file", rf, "--families", "4", "--mode", "alladdr", "--max-addrs", "2")
    assert rc == 0, out
    per = {}
    for r in rows(o2):
        per[r[0]] = per.get(r[0], 0) + 1
    assert per == {n: 2 for n in names}, per


# ------------------------------------------------------------------------------------------------- 4. controls
def r06_global_rate_default_18():
    names = [f"rt{i:03d}.test" for i in range(60)]
    rf = resolve_file("r06.tsv", {n: f"127.0.0.1:{P_HYB}" for n in names})
    o = os.path.join(WORK, "r06")
    rc, out = runpy("--targets", targets_file("r06-t.txt", names), "--out", o, "--resolve-file", rf)   # default --rate
    assert rc == 0, out
    ts = [float(p[0]) for p in plog(o)]
    assert len(ts) == 240, len(ts)
    mx = max_in_window(ts)
    mean = (len(ts) - 1) / (max(ts) - min(ts))
    assert mx <= 18 and mean <= 18.05, (mx, mean)
    print(f"       240 handshakes: max {mx} in any 1 s window, mean {mean:.2f}/s", flush=True)


def r07_kill_switch_and_resume():
    names = [f"ks{i:03d}.test" for i in range(150)]
    rf = resolve_file("r07.tsv", {n: f"127.0.0.1:{P_CLS}" for n in names})
    tf = targets_file("r07-t.txt", names)
    o = os.path.join(WORK, "r07")
    p = bg_runpy("--targets", tf, "--out", o, "--resolve-file", rf)
    time.sleep(2.0)
    t_stop = time.time()
    w(os.path.join(o, "STOP"), "test\n")
    p.communicate(timeout=30)
    t_exit = time.time()
    last = max(float(x[0]) for x in plog(o))
    n1 = len(rows(o))
    assert last <= t_stop + 0.1, f"handshake started {last - t_stop:.3f}s after STOP"
    assert t_exit - t_stop < 15 and 10 < n1 < 150, (t_exit - t_stop, n1)
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf)
    assert rc == 2 and "STOP" in out and len(rows(o)) == n1, out
    os.remove(os.path.join(o, "STOP"))
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf)
    assert rc == 0, out
    keys = [r[0] for r in rows(o)]
    assert sorted(keys) == sorted(names), (len(keys), len(set(keys)))
    assert len(plog(o)) == 150


def r08_circuit_breaker():
    names = [f"cb{i:03d}.test" for i in range(150)]
    rf = resolve_file("r08.tsv", {n: f"127.0.0.1:{P_DEAD}" for n in names})
    o = os.path.join(WORK, "r08")
    rc, out = runpy("--targets", targets_file("r08-t.txt", names), "--out", o, "--resolve-file", rf,
                    "--breaker-window", "30", "--breaker-min-probes", "40")
    s = open(os.path.join(o, "STOP")).read()
    assert "circuit breaker" in s, s
    n = len(plog(o))
    assert 40 <= n <= 40 + 24 + 2, n


def r09_max_minutes_in_runpy():
    names = [f"mm{i:03d}.test" for i in range(150)]
    rf = resolve_file("r09.tsv", {n: f"127.0.0.1:{P_CLS}" for n in names})
    o = os.path.join(WORK, "r09")
    t0 = time.time()
    rc, out = runpy("--targets", targets_file("r09-t.txt", names), "--out", o, "--resolve-file", rf, "--max-minutes", "0.05")
    el = time.time() - t0
    assert "max-minutes" in open(os.path.join(o, "STOP")).read()
    n = len(plog(o))
    assert el < 12 and n <= 3 * 18 + 19, (el, n)


def r10_exclusions_names_suffixes_cidrs():
    ex = w(os.path.join(WORK, "r10-ex.txt"), "# test\nexcl.test\n*.sfx.test\n127.0.0.9\n::1/128   # IPv6 block\n")
    m = {"excl.test": f"127.0.0.1:{P_CLS}", "sub.excl.test": f"127.0.0.1:{P_CLS}", "sfx.test": f"127.0.0.1:{P_CLS}",
         "a.sfx.test": f"127.0.0.1:{P_CLS}", "ip9.test": f"127.0.0.9:{P_CLS}",
         "mix.test": f"127.0.0.9:{P_CLS},127.0.0.1:{P_CLS},[::1]:{P_CLS}", "ok.test": f"127.0.0.1:{P_CLS}"}
    rf = resolve_file("r10.tsv", m)
    o = os.path.join(WORK, "r10")
    rc, out = runpy("--targets", targets_file("r10-t.txt", list(m)), "--out", o, "--resolve-file", rf, "--exclude-file", ex,
                    "--families", "4,6")
    assert rc == 0, out
    rs = {(r[0], r[10]): r for r in rows(o)}
    for n in ("excl.test", "sfx.test", "a.sfx.test"):
        assert rs[(n, "4")][3] == "excluded" and rs[(n, "6")][3] == "excluded", n
    assert rs[("ip9.test", "4")][3] == "excluded"
    assert rs[("mix.test", "4")][1] == "127.0.0.1" and rs[("mix.test", "4")][2] == "1", rs[("mix.test", "4")]
    assert rs[("mix.test", "6")][3] == "excluded", rs[("mix.test", "6")]
    assert rs[("sub.excl.test", "4")][3].startswith("ok|")       # exact entry does not cover subdomains
    assert {p[1] for p in plog(o)} == {"sub.excl.test", "mix.test", "ok.test"}
    assert not any(p[3] in ("127.0.0.9", "::1") for p in plog(o))
    bad = w(os.path.join(WORK, "r10-bad.txt"), "ok.test\nthis is not valid\n")
    o2 = os.path.join(WORK, "r10-bad")
    rc, out = runpy("--targets", targets_file("r10-t.txt", list(m)), "--out", o2, "--resolve-file", rf, "--exclude-file", bad)
    assert rc == 2 and not os.path.exists(o2), (rc, out)


def r11_exclusion_reload_during_run():
    names = [f"n{i:03d}.test" for i in range(60)] + [f"x{i:03d}.late.test" for i in range(60)]
    rf = resolve_file("r11.tsv", {n: f"127.0.0.1:{P_CLS}" for n in names})
    tf = targets_file("r11-t.txt", names)
    ex = w(os.path.join(WORK, "r11-ex.txt"), "# empty at start\n")
    o = os.path.join(WORK, "r11")
    p = bg_runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--exclude-file", ex)
    time.sleep(2.0)
    t_add = time.time()
    with open(ex, "a") as f:
        f.write("*.late.test\n")
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 0, out
    late_after = [x for x in plog(o) if x[1].endswith(".late.test") and float(x[0]) > t_add]
    assert not late_after, late_after[:3]
    assert any(x[1].endswith(".late.test") for x in plog(o)), "fixture: some late names should have been probed before the reload"
    rs = rows(o)
    assert len(rs) == 120 and sum(1 for r in rs if r[3] == "excluded") >= 20, len(rs)
    assert "reloaded" in open(os.path.join(o, "run.log")).read()
    # an invalid line appearing mid-run stops the run (exit 7) instead of running on a stale list
    ex2 = w(os.path.join(WORK, "r11-ex2.txt"), "\n")
    o2 = os.path.join(WORK, "r11b")
    p = bg_runpy("--targets", tf, "--out", o2, "--resolve-file", rf, "--exclude-file", ex2)
    time.sleep(1.5)
    t_bad = time.time()
    with open(ex2, "a") as f:
        f.write("not a valid entry\n")
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 7, (p.returncode, out[-500:])
    assert "exclusion file" in open(os.path.join(o2, "STOP")).read()
    assert all(float(x[0]) <= t_bad + 0.1 for x in plog(o2))


def r12_real_resolver_path_with_stub_dns():
    tf = targets_file("r12-t.txt", ["d1.test", "excl-dns.test", "q.zone-ex.test", "nx.test", "v4only.test"])
    ex = w(os.path.join(WORK, "r12-ex.txt"), "excl-dns.test\n*.zone-ex.test\n")
    before = len(dns_queries())
    o = os.path.join(WORK, "r12")
    rc, out = runpy("--targets", tf, "--out", o, "--exclude-file", ex, "--www", "add", "--families", "4,6",
                    "--allow-nonglobal", "--dns-retries", "1")
    assert rc == 0, out
    q = {n for n, _ in dns_queries()[before:]}
    qt = set(tuple(x) for x in dns_queries()[before:])
    assert {("d1.test", "A"), ("d1.test", "AAAA"), ("www.d1.test", "A"), ("nx.test", "A")} <= qt, qt
    for never in ("excl-dns.test", "www.excl-dns.test", "q.zone-ex.test", "www.q.zone-ex.test"):
        assert never not in q, f"excluded name {never} was looked up"
    rs = {(r[0], r[10]): r for r in rows(o)}
    assert rs[("d1.test", "4")][1] == "127.0.0.1" and rs[("d1.test", "4")][9].startswith("ok|"), rs[("d1.test", "4")]
    assert rs[("d1.test", "6")][1] == "::1" and rs[("d1.test", "6")][3].endswith("grp=X25519MLKEM768")
    assert rs[("nx.test", "4")][3] == "noaddr" and rs[("v4only.test", "6")][3] == "noaddr"
    assert rs[("excl-dns.test", "4")][3] == "excluded" and rs[("www.excl-dns.test", "6")][3] == "excluded"
    assert json.loads(open(os.path.join(o, "run-meta.json")).readline())["resolver"] == "system"
    assert "dns client" not in open(os.path.join(o, "run.log")).read()
    # without --allow-nonglobal a real run never probes non-global addresses (here: loopback from DNS)
    o2 = os.path.join(WORK, "r12b")
    rc, out = runpy("--targets", tf, "--out", o2, "--exclude-file", ex, "--families", "4,6", "--dns-retries", "1")
    assert rc == 0, out
    assert rows(o2) and all(r[3] in ("nonglobal", "noaddr", "excluded") for r in rows(o2)), rows(o2)
    assert plog(o2) == []


def r13_unguarded_refusals():
    subprocess.run(["ip", "addr", "add", "192.0.2.10/32", "dev", "lo"], check=True)
    try:
        tr = os.path.join(WORK, "srv-far.trace")
        srv = sserver("192.0.2.10:4560", "X25519MLKEM768:X25519", trace=tr)
        wait_listen(4560)
        rf = resolve_file("r13.tsv", {"far.test": "192.0.2.10:4560"})
        tf = targets_file("r13-t.txt", ["far.test"])
        o = os.path.join(WORK, "r13")
        os.makedirs(o)
        w(os.path.join(o, ".guard.lock"), "1 forged-nonce\n")                 # a lock file without the guard's env nonce
        rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, env=dict(os.environ, KITC_GUARD_NONCE="other"))
        assert rc == 6, (rc, out)
        assert "non-loopback" in open(os.path.join(o, "STOP")).read() and plog(o) == []
        time.sleep(0.3)
        assert "ClientHello" not in open(tr).read(), "the non-loopback server was contacted"
        srv.kill()
        # real DNS from an unguarded run.py is refused when the namespace has any interface besides loopback
        subprocess.run(["ip", "link", "add", "kd0", "type", "dummy"], check=True)
        before = len(dns_queries())
        o2 = os.path.join(WORK, "r13b")
        rc, out = runpy("--targets", targets_file("r13-t2.txt", ["d1.test"]), "--out", o2, "--allow-nonglobal")
        assert rc == 6 and "REFUSED" in out, (rc, out)
        assert len(dns_queries()) == before and plog(o2) == []
    finally:
        subprocess.run(["ip", "link", "del", "kd0"], capture_output=True)
        subprocess.run(["ip", "addr", "del", "192.0.2.10/32", "dev", "lo"], capture_output=True)


def r14_dry_run_sends_nothing():
    names = [f"d{i:04d}.test" for i in range(950)] + [f"k{i:02d}.ex.test" for i in range(50)] + ["1.2.3.4", "bad_name!", "d1.test"]
    tf = targets_file("r14-t.txt", names)
    ex = w(os.path.join(WORK, "r14-ex.txt"), "*.ex.test\n")
    before = len(dns_queries())
    o = os.path.join(WORK, "r14")
    rc, out = runpy("--targets", tf, "--out", o, "--exclude-file", ex, "--dry-run", "--www", "add", "--families", "4,6",
                    "--assume-reachable", "0.5", "--assume-pq", "0.2")
    assert rc == 0, out
    pj = json.loads([l for l in out.splitlines() if l.startswith("PLAN-JSON ")][0][10:])
    kept = (950 + 1) * 2                          # valid, not excluded, apex + www
    assert pj["names"] == 1003 and pj["targets_per_family"] == kept and pj["names_excluded"] == 100 and pj["targets_invalid"] == 2, pj
    per_fam = kept * 0.5 + 3 * kept * 0.2
    assert pj["expected_total"] == round(2 * per_fam) and pj["expected"]["p1"] == round(2 * kept * 0.5), pj
    assert pj["expected_seconds"] == round(2 * per_fam / 18, 1), pj
    assert pj["upper_bound_total"] == kept * 4 * 2 and pj["max_handshakes_per_listed_name"] == 16, pj
    assert "DRY RUN" in out and str(pj["expected_total"]) in out
    assert len(dns_queries()) == before, "dry run looked up names"
    assert not os.path.exists(o), "dry run wrote files"
    assert not procs_mentioning("s_client")


def r15_load_estimate():
    rc, out = runpy("--estimate", "100000", "--assume-reachable", "0.85", "--assume-pq", "0.35")
    pj = json.loads([l for l in out.splitlines() if l.startswith("PLAN-JSON ")][0][10:])
    assert rc == 0 and pj["expected"] == {"p1": 85000, "p2": 35000, "p3": 35000, "pa": 35000}, pj
    assert pj["expected_total"] == 190000 and pj["expected_seconds"] == round(190000 / 18, 1), pj
    assert "2h55m56s" in out, out
    rc, out = runpy("--estimate", "1000", "--www", "add", "--families", "4,6")
    pj = json.loads([l for l in out.splitlines() if l.startswith("PLAN-JSON ")][0][10:])
    assert pj["expected_total"] == round(2 * (2000 * 0.84 + 3 * 2000 * 0.45)) and pj["upper_bound_total"] == 16000, pj
    rc, out = runpy("--estimate", "200", "--mode", "alladdr", "--assume-addrs", "3", "--assume-reachable", "0.8", "--assume-pq", "0.5")
    pj = json.loads([l for l in out.splitlines() if l.startswith("PLAN-JSON ")][0][10:])
    assert pj["expected"] == {"p1": 480, "p2": 300, "p3": 0, "pa": 0}, pj


def r16_trace_modes():
    names = ["tm1.test", "tm2.test"]
    rf = resolve_file("r16.tsv", {n: f"127.0.0.1:{P_CLS}" for n in names})
    tf = targets_file("r16-t.txt", names)
    for mode in ("files", "none"):
        o = os.path.join(WORK, f"r16-{mode}")
        rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--traces", mode)
        assert rc == 0, out
        assert not os.path.exists(os.path.join(o, "traces.jsonl.xz")) and not os.path.exists(os.path.join(o, ".tmp-traces"))
        if mode == "files":
            assert len(os.listdir(os.path.join(o, "traces"))) == 2
        else:
            assert not os.path.exists(os.path.join(o, "traces"))


def _counts(pl):
    by_ip, by_fam, by_name = {}, {}, {}
    for x in pl:
        if len(x) < 4:
            continue
        by_ip[(x[1], x[3])] = by_ip.get((x[1], x[3]), 0) + 1
        fam = ipaddress.ip_address(x[3]).version
        by_fam[(x[1], fam)] = by_fam.get((x[1], fam), 0) + 1
        by_name[x[1]] = by_name.get(x[1], 0) + 1
    return by_ip, by_fam, by_name


# ------------------------------------------------------------------------------------------------- 4b. --resolver
def fdns_log():
    try:
        return [json.loads(l) for l in open(FDNSLOG) if l.strip()]
    except OSError:
        return []


def dnsclient_module():
    import importlib.util
    sys.dont_write_bytecode = True                  # no __pycache__ in the kit directory
    spec = importlib.util.spec_from_file_location("kitc_dnsclient_t", os.path.join(KIT, "dnsclient.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def d01_dns_client_against_fake_resolver():
    D = dnsclient_module()
    c = D.Client(FDNS_IP)
    n0 = len(fdns_log())

    def res(name, t="A", timeout=3.0):
        return c.resolve(name, t, timeout)
    r = res("a.dns.test")
    assert r.status == "ok" and r.records == ["127.0.0.1"] and r.chain == [] and r.queries == 1, r
    assert res("a.dns.test", "AAAA").records == ["::1"]
    r = res("C1.Dns.Test.")                                              # case and trailing dot do not matter
    assert r.status == "ok" and r.records == ["127.0.0.1"] and r.chain == ["c2.dns.test", "a.dns.test"] and r.queries == 1, r
    k = len(fdns_log())
    r = res("r1.dns.test")                                               # chain ends without an address: re-query
    assert r.status == "ok" and r.records == ["127.0.0.1"] and r.queries == 3, r
    assert [x["name"] for x in fdns_log()[k:]] == ["r1.dns.test", "r2.dns.test", "a.dns.test"], fdns_log()[k:]
    r = res("l1.dns.test")
    assert r.status == "cname-loop" and r.queries == 1, r                # loop inside one answer
    r = res("l3.dns.test")
    assert r.status == "cname-loop" and r.queries == 2 and r.chain == ["l4.dns.test", "l3.dns.test"], r
    r = res("k0.dns.test")
    assert r.status == "cname-too-long" and r.queries == D.MAX_CNAME + 1 and len(r.chain) == D.MAX_CNAME, r
    assert res("dangling.dns.test").status == "nxdomain"
    assert res("nx.dns.test").status == "nxdomain" and res("v4.dns.test", "AAAA").status == "nodata"
    assert res("sf.dns.test").status == "servfail" and res("ref.dns.test").status == "refused"
    k = len(fdns_log())
    r = res("tc.dns.test")                                               # TC=1 over UDP -> the same question over TCP
    assert r.status == "ok" and r.records == ["127.0.0.1"], r
    assert [(x["proto"], x["name"]) for x in fdns_log()[k:]] == [("udp", "tc.dns.test"), ("tcp", "tc.dns.test")], fdns_log()[k:]
    assert c.sent_tcp == 1
    # replies that do not answer our question are ignored: wrong id, wrong question name, compression-pointer loop
    for name in ("badid.dns.test", "badq.dns.test", "ptr.dns.test", "drop.dns.test"):
        ig = c.ignored
        t0 = time.time()
        r = res(name, timeout=1.0)
        assert r.status == "timeout" and r.records == [] and 0.9 < time.time() - t0 < 2.5, (name, r)
        assert c.ignored == ig + (0 if name == "drop.dns.test" else 1), (name, c.ignored, ig)
    ig = c.ignored
    r = res("badidok.dns.test")                                          # a wrong id first, then the real answer
    assert r.status == "ok" and r.records == ["127.0.0.1"] and c.ignored == ig + 1, r
    r = res("mail.test", "MX")
    assert r.status == "ok" and r.records == [(10, "mx1.mail.test"), (20, "mx2.mail.test")], r
    # query ids are random
    ids = [x["id"] for x in fdns_log()[n0:]]
    assert len(set(ids)) > len(ids) * 0.9, ids
    # a resolver that does not listen: error or timeout, never an address
    r = D.Client("127.0.0.3").resolve("a.dns.test", "A", 1.0)
    assert r.status in ("error", "timeout") and r.records == [], r
    # shared limiter: at most `rate` packets in any 1 s window, over threads
    k = len(fdns_log())
    lim = D.Limiter(20)
    cl = D.Client(FDNS_IP, limiter=lim)
    ths = [threading.Thread(target=cl.resolve, args=("a.dns.test", "A", 10.0)) for _ in range(50)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    ts = [x["t"] for x in fdns_log()[k:]]
    assert len(ts) == 50 and max_in_window(ts) <= 20, (len(ts), max_in_window(ts))
    print(f"       50 lookups with Limiter(20): max {max_in_window(ts)} queries in any 1 s window", flush=True)


def r18_resolver_option():
    names = ["a.dns.test", "v4.dns.test", "c1.dns.test", "r1.dns.test", "l1.dns.test", "l3.dns.test", "dangling.dns.test",
             "tc.dns.test", "badidok.dns.test", "sf.dns.test", "nx.dns.test"]
    tf = targets_file("r18-t.txt", names)
    o = os.path.join(WORK, "r18")
    sys0, f0 = len(dns_queries()), len(fdns_log())
    rc, out = runpy("--targets", tf, "--out", o, "--families", "4,6", "--allow-nonglobal", "--resolver", FDNS_IP,
                    "--dns-retries", "2")
    assert rc == 0, out
    rs = {(r[0], r[10]): r for r in rows(o)}
    want_ok = {("a.dns.test", "4"): "127.0.0.1", ("a.dns.test", "6"): "::1", ("v4.dns.test", "4"): "127.0.0.1",
               ("c1.dns.test", "4"): "127.0.0.1", ("c1.dns.test", "6"): "::1", ("r1.dns.test", "4"): "127.0.0.1",
               ("r1.dns.test", "6"): "::1", ("tc.dns.test", "4"): "127.0.0.1", ("badidok.dns.test", "4"): "127.0.0.1"}
    assert len(rs) == 22, sorted(rs)
    for k, r in rs.items():
        if k in want_ok:
            assert r[1] == want_ok[k] and r[3].startswith("ok|") and r[3].endswith("grp=X25519MLKEM768"), r
        else:
            assert r[1] == "-" and r[3] == "noaddr", r
    assert all(p[4] == "443" for p in plog(o))
    # every lookup went to the fake resolver, none to the system resolver
    assert not [q for q in dns_queries()[sys0:] if q[0].endswith(".dns.test")], dns_queries()[sys0:]
    q = collections.Counter((x["name"], x["type"]) for x in fdns_log()[f0:])
    assert q[("sf.dns.test", "A")] == 2 and q[("sf.dns.test", "AAAA")] == 2, q          # retried (--dns-retries 2)
    assert q[("nx.dns.test", "A")] == 1 and q[("dangling.dns.test", "AAAA")] == 1, q     # final answers: not retried
    assert q[("l3.dns.test", "A")] == 1 and q[("l4.dns.test", "A")] == 1, q              # loop found after 2 questions
    assert ("tcp", "tc.dns.test") in {(x["proto"], x["name"]) for x in fdns_log()[f0:]}
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    assert meta["resolver"] == FDNS_IP, meta
    lg = open(os.path.join(o, "run.log")).read()
    assert f"dns client: resolver {FDNS_IP}" in lg and "'cname-loop': 4" in lg and "'servfail': 4" in lg, lg
    # bad values are refused before anything happens
    for bad in ("dns.google", "::1", "1.1.1", "1.1.1.1:53", "001.1.1.1", "", "8.8.8.8 "):
        rc, out = runpy("--targets", tf, "--out", os.path.join(WORK, "r18-bad"), "--resolver", bad)
        assert rc == 2 and "--resolver" in out and not os.path.exists(os.path.join(WORK, "r18-bad")), (bad, rc, out)
    # unguarded run.py with --resolver outside a loopback-only namespace: refused, no query
    subprocess.run(["ip", "link", "add", "kd1", "type", "dummy"], check=True)
    try:
        f1 = len(fdns_log())
        o2 = os.path.join(WORK, "r18b")
        rc, out = runpy("--targets", tf, "--out", o2, "--allow-nonglobal", "--resolver", FDNS_IP)
        assert rc == 6 and "REFUSED" in out and len(fdns_log()) == f1 and plog(o2) == [], (rc, out)
    finally:
        subprocess.run(["ip", "link", "del", "kd1"], capture_output=True)


# ------------------------------------------------------------------------------------------------- 4c. SMTP STARTTLS
SMTP_CMDS = ("MAIL", "RCPT", "DATA", "QUIT", "RSET", "VRFY", "EXPN", "AUTH", "BDAT")


def front_log(path):
    return [json.loads(l) for l in open(path) if l.strip()] if os.path.exists(path) else []


def client_text(evs, conn=None):
    """Everything the client sent in plaintext (before the TLS relay), per connection."""
    out = collections.defaultdict(str)
    for e in evs:
        if e["ev"] == "c2s" and (conn is None or e["conn"] == conn):
            out[e["conn"]] += e["data"]
    return dict(out)


def no_smtp_transaction(txt):
    lines = [l.strip().upper() for l in txt.replace("\r", "\n").split("\n")]
    return not any(l.startswith(SMTP_CMDS) for l in lines)


def smtp_probe(port, label, timeout="30", host="mx.test", ip="127.0.0.1", tag=None):
    tf = os.path.join(WORK, f"smtp-cli-{tag or port}-{label}.trace")
    t0 = time.time()
    tok = subprocess.run(["bash", PROBE_SMTP, host, ip, str(port), label, G[label], tf, EHLO, timeout], capture_output=True,
                         text=True, timeout=120, stdin=subprocess.DEVNULL).stdout.strip()
    return tok, tf, time.time() - t0


def smtp_front(tag, port, backend, opts=()):
    lg = os.path.join(WORK, f"smtp-front-{tag}.log")
    start([sys.executable, "-I", FAKE_SMTP, "127.0.0.1", str(port), str(backend), lg, *opts])
    wait_listen(port)
    return lg


def s01_smtp_client_bytes_and_hrr_on_starttls():
    """What s_client -starttls smtp sends, recorded by a fake SMTP server; the TLS part is a real s_server -trace."""
    want = f"EHLO {EHLO}\r\nSTARTTLS\r\n"
    # (port, label, server groups, expected hrr, expected group)
    for i, (lab, gs, hrr, grp) in enumerate((("p1", "X25519MLKEM768:X25519", "0", "X25519MLKEM768"),
                                             ("p2", None, "1", "X25519MLKEM768"),          # default server: HRR to hybrid
                                             ("p2", "X25519MLKEM768:X25519", "0", "ecdh_x25519"),
                                             ("pa", None, "0", "X25519MLKEM768"))):
        port, bport = 4710 + i, 4730 + i
        tr = os.path.join(WORK, f"smtp-srv-{i}.trace")
        sserver(bport, gs, trace=tr, naccept=1)
        wait_listen(bport)
        lg = smtp_front(f"s01-{i}", port, bport)
        tok, tf, _ = smtp_probe(port, lab, tag=f"s01-{i}")
        assert CELL.match(tok) and tok.startswith("ok|") and f"hrr={hrr}" in tok and tok.endswith(f"grp={grp}"), (lab, gs, tok)
        time.sleep(0.3)
        evs = front_log(lg)
        assert client_text(evs) == {1: want}, client_text(evs)                       # exactly these bytes in plaintext
        relay = [e for e in evs if e["ev"] == "tls-c2s"]
        assert len(relay) == 1 and relay[0]["first"] == 22, relay                   # then a TLS handshake record
        recv, cn = server_view(tr)
        assert "Handshake" in recv and "ApplicationData" not in recv and cn, (lab, recv, cn)   # no data, close_notify
        assert client_sent_appdata(tf) == 0
        assert "250 8BITMIME" in open(tf).read()            # s_client echoes the last EHLO line into its trace (README)
    # the server does not offer STARTTLS: s_client says so, sends STARTTLS anyway (this front end then accepts it)
    lg = smtp_front("s01-nost", 4720, P_SB_HYB, ("no-starttls",))
    tok, tf, _ = smtp_probe(4720, "p1", tag="s01-nost")
    time.sleep(0.3)
    assert tok.startswith("ok|") and "Didn't find STARTTLS" in open(tf).read() and client_text(front_log(lg)) == {1: want}, tok
    # a 554 greeting: s_client still sends EHLO and STARTTLS
    lg = smtp_front("s01-rej", 4721, P_SB_HYB, ("reject",))
    tok, tf, _ = smtp_probe(4721, "p1", tag="s01-rej")
    time.sleep(0.3)
    assert client_text(front_log(lg)) == {1: want}, front_log(lg)
    # STARTTLS refused (454): s_client sends its ClientHello anyway, in plaintext; the probe fails; still no transaction
    lg = smtp_front("s01-454", 4722, 4799, ("starttls-reply=454 4.7.0 TLS not available",))
    tok, tf, _ = smtp_probe(4722, "p2", tag="s01-454")
    time.sleep(0.3)
    txt = client_text(front_log(lg))[1]
    assert tok.startswith("fail|") and txt.startswith(want + "\x16\x03\x01"), (tok, txt[:80])
    assert no_smtp_transaction(txt) and "wrong version number" in open(tf).read(), txt[:200]
    # a slow greeting (4 s) is waited for; a server that never greets gets nothing and the probe ends at the timeout
    lg = smtp_front("s01-slow", 4723, P_SB_HYB, ("banner-delay=4",))
    tok, tf, el = smtp_probe(4723, "p1", timeout="12", tag="s01-slow")
    assert tok.startswith("ok|") and el >= 4.0, (tok, el)
    lg = smtp_front("s01-tarpit", 4724, P_SB_HYB, ("no-banner",))
    tok, tf, el = smtp_probe(4724, "p1", timeout="12", tag="s01-tarpit")
    time.sleep(0.3)
    evs = front_log(lg)
    assert tok == "fail|ch=0|hrr=0|sh=0|grp=-" and 11.5 <= el < 16 and client_text(evs) == {}, (tok, el, evs)
    assert [e["ev"] for e in evs] == ["accept"], evs
    print(f"       client bytes before TLS: {want!r}; tarpit: nothing sent, probe ended after {el:.1f} s", flush=True)


def s02_smtp_scan_caps_and_refusals():
    m = {"mxdef1.test": f"127.0.0.21:{S_DEF}", "mxdef2.test": f"127.0.0.22:{S_DEF}", "mxhyb1.test": f"127.0.0.23:{S_HYB}",
         "mxhyb2.test": f"127.0.0.24:{S_HYB}", "mx454.test": f"127.0.0.25:{S_454}", "mxexcl.test": f"127.0.0.26:{S_HYB}"}
    m.update({f"share{i}.test": f"{SHARED_IP}:{S_HYB}" for i in range(7)})
    rf = resolve_file("s02.tsv", m)
    names = [n for n in m if n not in ("share5.test", "share6.test")]
    tf = targets_file("s02-t.txt", names)
    ex = w(os.path.join(WORK, "s02-ex.txt"), "mxexcl.test\n")
    o = os.path.join(WORK, "s02")
    fronts = [os.path.join(WORK, f"smtp-front-{p}.log") for p in (S_DEF, S_HYB, S_454)]
    n0 = {f: len(front_log(f)) for f in fronts}
    rc, out = runpy("--targets", tf, "--out", o, "--resolve-file", rf, "--exclude-file", ex, "--proto", "smtp",
                    "--ehlo-name", EHLO)
    assert rc == 0, out
    rs = {r[0]: r for r in rows(o)}
    assert sorted(rs) == sorted(names), sorted(rs)
    for h in ("mxdef1.test", "mxdef2.test", "mxhyb1.test", "mxhyb2.test"):
        r, kind = rs[h], ("pf" if "def" in h else "ex")
        for lab, (hrr, grp) in EXP[kind].items():
            c = {"p1": r[3], "p2": r[4], "p3": r[5], "pa": r[9]}[lab]
            assert c.startswith("ok|") and f"hrr={hrr}" in c and c.endswith(f"grp={grp}"), (h, lab, c)
    assert rs["mx454.test"][3].startswith("fail|") and rs["mxexcl.test"][3] == "excluded", (rs["mx454.test"], rs["mxexcl.test"])
    pl = plog(o)
    assert not any(p[1] == "mxexcl.test" for p in pl)
    assert {p[4] for p in pl} == {str(S_DEF), str(S_HYB), str(S_454)}, {p[4] for p in pl}
    by_ip, by_fam, by_name = _counts(pl)
    assert max(by_name.values()) <= 4
    shared = [p for p in pl if p[3] == SHARED_IP]
    assert len(shared) == 8, len(shared)                                   # --per-ip-cap default 8 over 5 MX names
    cells = [c for h in rs if h.startswith("share") for c in (rs[h][3], rs[h][4], rs[h][5], rs[h][9])]
    assert all(c.startswith("ok|") or c in ("capped", "skip") for c in cells) and "capped" in cells, cells
    # every connection of this run sent exactly EHLO and STARTTLS in plaintext (the 454 one: then its ClientHello)
    for f in fronts:
        for conn, txt in client_text(front_log(f)[n0[f]:]).items():
            if f.endswith(f"-{S_454}.log"):
                assert txt.startswith(f"EHLO {EHLO}\r\nSTARTTLS\r\n\x16") and no_smtp_transaction(txt), txt[:60]
            else:
                assert txt == f"EHLO {EHLO}\r\nSTARTTLS\r\n", (f, conn, txt)
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    assert (meta["proto"], meta["port"], meta["ehlo_name"], meta["smtp_timeout"], meta["per_ip_cap"]) == ("smtp", 25, EHLO, 30.0, 8), meta
    recs = [json.loads(l) for l in lzma.decompress(open(os.path.join(o, "traces.jsonl.xz"), "rb").read()).decode().splitlines()]
    assert len(recs) == len(pl) and all("CONNECTED" in x["trace"] for x in recs if x["host"].startswith("mxhyb")), len(recs)
    # resume: earlier handshakes count against the per-IP cap (two more names on the same address get none)
    tf2 = targets_file("s02-t2.txt", names + ["share5.test", "share6.test"])
    rc, out = runpy("--targets", tf2, "--out", o, "--resolve-file", rf, "--exclude-file", ex, "--proto", "smtp",
                    "--ehlo-name", EHLO, "--resume")
    assert rc == 0, out
    rs = {r[0]: r for r in rows(o)}
    assert rs["share5.test"][3] == rs["share6.test"][3] == "capped" and len([p for p in plog(o) if p[3] == SHARED_IP]) == 8, rs
    assert len(plog(o)) == len(pl)
    # a lower per-IP cap
    o3 = os.path.join(WORK, "s02-cap3")
    rc, out = runpy("--targets", tf, "--out", o3, "--resolve-file", rf, "--exclude-file", ex, "--proto", "smtp",
                    "--ehlo-name", EHLO, "--per-ip-cap", "3")
    assert rc == 0 and len([p for p in plog(o3) if p[3] == SHARED_IP]) == 3, out
    assert len([p for p in plog(o3) if p[1] == "mxdef1.test"]) == 3                 # its own address: 3 of its 4 probes
    # refusals: nothing created
    bad_args = [(), ("--ehlo-name", "Bad Name"), ("--ehlo-name", "Probe.Kitc.Test"), ("--ehlo-name", f"{EHLO}\r\nMAIL FROM:<x@y>"),
                ("--ehlo-name", EHLO, "--www", "add"), ("--ehlo-name", EHLO, "--mode", "alladdr"),
                ("--ehlo-name", EHLO, "--per-ip-cap", "9"), ("--ehlo-name", EHLO, "--per-ip-cap", "0"),
                ("--ehlo-name", EHLO, "--smtp-timeout", "11"), ("--ehlo-name", EHLO, "--smtp-timeout", "61"),
                ("--ehlo-name", EHLO, "--smtp-timeout", "30.5")]
    for extra in bad_args:
        rc, out = runpy("--targets", tf, "--out", os.path.join(WORK, "s02-bad"), "--resolve-file", rf, "--proto", "smtp", *extra)
        assert rc == 2 and not os.path.exists(os.path.join(WORK, "s02-bad")), (extra, rc, out)
    for extra in (("--ehlo-name", EHLO), ("--per-ip-cap", "9")):                     # https mode
        rc, out = runpy("--targets", tf, "--out", os.path.join(WORK, "s02-bad"), "--resolve-file", rf, *extra)
        assert rc == 2 and not os.path.exists(os.path.join(WORK, "s02-bad")), (extra, rc, out)


def s03_smtp_port_25_from_dns():
    tf = targets_file("s03-t.txt", ["mx25.test", "mx.smtp.test"])
    f = os.path.join(WORK, "smtp-front-25.log")
    for tag, extra, name in (("sys", (), "mx25.test"), ("direct", ("--resolver", FDNS_IP), "mx.smtp.test")):
        o = os.path.join(WORK, f"s03-{tag}")
        n0 = len(front_log(f))
        rc, out = runpy("--targets", tf, "--out", o, "--allow-nonglobal", "--proto", "smtp", "--ehlo-name", EHLO, *extra)
        assert rc == 0, out
        rs = {r[0]: r for r in rows(o)}
        assert rs[name][1] == "127.0.0.1" and rs[name][3].startswith("ok|") and rs[name][4].startswith("ok|"), rs
        assert {p[4] for p in plog(o)} == {"25"} and {p[1] for p in plog(o)} == {name}, plog(o)
        assert set(client_text(front_log(f)[n0:]).values()) == {f"EHLO {EHLO}\r\nSTARTTLS\r\n"}


def m01_mxlist():
    doms = w(os.path.join(WORK, "m01-domains.csv"), "rank,domain\n1,mail.test\n2,shared1.test\n3,shared2.test\n4,nullmx.test\n"
             "5,nomx.test\n6,nx-mx.test\n7,cnamemx.test\n8,badmx.test\n9,multi.test\n10,sfmx.test\n11,skip.excl-mx.test\n"
             "12,bad_domain!\n")
    ex = w(os.path.join(WORK, "m01-ex.txt"), "*.excl-mx.test\n")
    out, mp = os.path.join(WORK, "m01-mx.txt"), os.path.join(WORK, "m01-map.tsv")
    f0, s0 = len(fdns_log()), len(dns_queries())
    rc, o = runpy("--domains", doms, "--out", out, "--map", mp, "--resolver", FDNS_IP, "--exclude-file", ex, "--retries", "2",
                  script=MXLIST)
    assert rc == 0, o
    assert open(out).read() == "mx1.mail.test\nmx.shared.test\na.multi.test\nb.multi.test\n", open(out).read()
    assert open(out + ".sha256").read() == f"{sha(out)}  m01-mx.txt\n"
    j = json.loads([l for l in o.splitlines() if l.startswith("MXLIST-JSON ")][0][12:])
    assert j["status"] == {"excluded": 1, "invalid": 1, "nodata": 1, "nullmx": 1, "nxdomain": 1, "ok": 6, "servfail": 1}, j
    assert j["mx_hosts"] == 4 and j["mx_duplicates"] == 2 and j["mx_invalid"] == 1 and j["sha256"] == sha(out), j
    ql = fdns_log()[f0:]
    assert {x["type"] for x in ql} == {"MX"}, ql                              # MX questions only: no A/AAAA, no mail server
    qn = collections.Counter(x["name"] for x in ql)
    assert "skip.excl-mx.test" not in qn and not any("bad_domain" in n for n in qn), qn   # excluded / invalid: never asked
    assert qn["sfmx.test"] == 2 and qn["nx-mx.test"] == 1 and qn["cnamemx.test"] == 1, qn
    assert len(dns_queries()) == s0                                            # nothing to the system resolver
    ml = [l.split("\t") for l in open(mp).read().splitlines()]
    assert ["9", "multi.test", "ok", "30", "c.multi.test"] in ml and ["4", "nullmx.test", "nullmx", "-", "-"] in ml, ml
    # nothing is overwritten
    rc, o = runpy("--domains", doms, "--out", out, "--resolver", FDNS_IP, "--exclude-file", ex, script=MXLIST)
    assert rc == 2 and "exists" in o, o
    out2 = os.path.join(WORK, "m01-mx-all.txt")
    rc, o = runpy("--domains", doms, "--out", out2, "--resolver", FDNS_IP, "--exclude-file", ex, "--all-preferences", script=MXLIST)
    assert rc == 0 and open(out2).read().split() == ["mx1.mail.test", "mx2.mail.test", "mx.shared.test", "a.multi.test",
                                                    "b.multi.test", "c.multi.test"], open(out2).read()
    # rate: at most 20 queries in any 1 s window (sent and as received)
    bulk = targets_file("m01-bulk.txt", [f"bulk{i:03d}.test" for i in range(120)])
    f1 = len(fdns_log())
    t0 = time.time()
    rc, o = runpy("--domains", bulk, "--out", os.path.join(WORK, "m01-bulk-mx.txt"), "--resolver", FDNS_IP, "--workers", "16",
                  script=MXLIST)
    el = time.time() - t0
    j = json.loads([l for l in o.splitlines() if l.startswith("MXLIST-JSON ")][0][12:])
    ts = [x["t"] for x in fdns_log()[f1:]]
    assert rc == 0 and len(ts) == 120 and j["packets_sent"] == 120, (rc, len(ts), o)
    assert j["busiest_second"] <= 20 and max_in_window(ts) <= 20 and 5.9 <= el < 12, (j["busiest_second"], max_in_window(ts), el)
    print(f"       120 MX lookups: busiest second {max_in_window(ts)} at the resolver, {el:.1f} s", flush=True)
    # system resolver = the nameserver in /etc/resolv.conf (the namespace's stub)
    rc, o = runpy("--domains", targets_file("m01-sys.txt", ["d1.test"]), "--out", os.path.join(WORK, "m01-sys-mx.txt"), script=MXLIST)
    assert rc == 0 and ["d1.test", "15"] in dns_queries()[s0:], (o, dns_queries()[s0:])
    # refusals
    for extra in (("--rate", "21"), ("--resolver", "dns.google"), ("--resolver", "1.1.1.1:53")):
        rc, o = runpy("--domains", doms, "--out", os.path.join(WORK, "m01-bad.txt"), *extra, script=MXLIST)
        assert rc == 2 and not os.path.exists(os.path.join(WORK, "m01-bad.txt")), (extra, o)
    subprocess.run(["ip", "link", "add", "kd2", "type", "dummy"], check=True)
    try:
        f2 = len(fdns_log())
        rc, o = runpy("--domains", doms, "--out", os.path.join(WORK, "m01-ns.txt"), "--resolver", FDNS_IP, script=MXLIST)
        assert rc == 6 and "REFUSED" in o and len(fdns_log()) == f2 and not os.path.exists(os.path.join(WORK, "m01-ns.txt")), o
        rc, o = runpy("--domains", doms, "--out", os.path.join(WORK, "m01-ns.txt"), "--resolver", FDNS_IP, "--exclude-file", ex,
                      "--real", script=MXLIST)                  # the flag lifts the refusal (here: still only loopback reachable)
        assert rc == 0 and len(fdns_log()) > f2 and json.loads(o.split("MXLIST-JSON ")[1].splitlines()[0])["real"] is True, o
    finally:
        subprocess.run(["ip", "link", "del", "kd2"], capture_output=True)


# ------------------------------------------------------------------------------------------------- 4d. QUIC
QSRV = os.path.join(WORK, "qsrv")
QLOG = {}                                   # port -> qsrv log path
EVID = []                                   # evidence lines (KITC_QUIC_EVIDENCE=FILE writes them; see main)


def quic_setup():
    """Build tests/qsrv.c against the OpenSSL of $OPENSSL (into the tmpfs work dir) and start the QUIC test servers."""
    pre = os.path.dirname(os.path.dirname(os.path.realpath(OPENSSL)))
    subprocess.run(["gcc", "-O1", "-Wall", "-o", QSRV, QSRV_C, f"-I{pre}/include", f"-L{pre}/lib", f"-Wl,-rpath,{pre}/lib",
                    "-lssl", "-lcrypto"], check=True, capture_output=True)
    for port, groups, val, wait, addr in ((Q_DEF, "-", "validate", QWAIT, "127.0.0.1"),
                                          (Q_COL, "X25519MLKEM768:X25519", "validate", QWAIT, "127.0.0.1"),
                                          (Q_NV, "-", "novalidate", QWAIT, "127.0.0.1"),
                                          (Q_P256, "P-256", "validate", QWAIT, "127.0.0.1"),
                                          (Q_SDEF, "-", "validate", "0.2", "127.0.0.1"),
                                          (Q_SCOL, "X25519MLKEM768:X25519", "validate", "0.2", "127.0.0.1"),
                                          (Q_SDEF, "-", "validate", "0.2", "::1"),
                                          (443, "X25519MLKEM768:X25519", "validate", "0.2", "127.0.0.1")):
        lg = os.path.join(WORK, f"qsrv-{port}-{addr.replace(':', '')}.log")
        QLOG.setdefault(port, lg)
        start([QSRV, str(port), f"{CERT}/c.pem", f"{CERT}/k.pem", groups, val, wait, addr], out=open(lg, "w"))
    t = time.time() + 5
    while time.time() < t and not all("listening" in open(f).read() for f in glob_qlogs()):
        time.sleep(0.05)
    assert all("listening" in open(f).read() for f in glob_qlogs()), [open(f).read() for f in glob_qlogs()]


def fresh_qsrv(port, groups):
    lg = os.path.join(WORK, f"qsrv-{port}-127001.log")
    QLOG[port] = lg
    start([QSRV, str(port), f"{CERT}/c.pem", f"{CERT}/k.pem", groups, "validate", QWAIT, "127.0.0.1"], out=open(lg, "w"))
    t = time.time() + 5
    while time.time() < t and "listening" not in open(lg).read():
        time.sleep(0.05)
    assert "listening" in open(lg).read(), open(lg).read()


def glob_qlogs():
    return [os.path.join(WORK, f) for f in os.listdir(WORK) if f.startswith("qsrv-") and f.endswith(".log")]


def quic_types(d):
    """QUIC packet types in one UDP datagram, from the header fields that header protection leaves in clear (RFC 9000
    17.2: long-header type bits and Length; a short-header packet runs to the end of the datagram)."""
    out, i = [], 0
    while i < len(d):
        f = d[i]
        if not f & 0x40:
            out.append("pad" if not any(d[i:]) else "junk")
            break
        if not f & 0x80:
            out.append("1rtt")
            break
        if d[i + 1:i + 5] == b"\0\0\0\0":
            out.append("vneg")
            break
        t = ("initial", "0rtt", "handshake", "retry")[(f >> 4) & 3]
        if t == "retry":
            out.append(t)
            break
        j = i + 5
        j += 1 + d[j]
        j += 1 + d[j]

        def vint(k):
            n = 1 << (d[k] >> 6)
            v = d[k] & 0x3f
            for x in range(1, n):
                v = (v << 8) | d[k + x]
            return v, k + n
        if t == "initial":
            tl, j = vint(j)
            j += tl
        ln, j = vint(j)
        out.append(t)
        i = j + ln
    return out


class UdpCounter:
    """Every UDP datagram to or from one port on lo, seen by an AF_PACKET socket (the namespace's root may open one; the
    host's interfaces are not in this namespace). Records (time, 'c2s'|'s2c', payload bytes, QUIC packet types)."""
    def __init__(self, port):
        self.port, self.ev, self.run = port, [], True
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
        try:
            self.s.setsockopt(socket.SOL_SOCKET, 33, 32 << 20)          # SO_RCVBUFFORCE (namespace root): no drops in a storm
        except OSError:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 << 20)
        self.s.bind(("lo", 0))
        self.s.settimeout(0.05)
        self.th = threading.Thread(target=self._loop, daemon=True)
        self.th.start()

    def _loop(self):
        while self.run:
            try:
                d, a = self.s.recvfrom(65535)
            except socket.timeout:
                continue
            if a[2] != 0 or len(d) < 28 or d[0] >> 4 != 4 and d[0] >> 4 != 6:
                continue                                                  # PACKET_HOST copy only (lo shows each packet twice)
            if d[0] >> 4 == 4:
                if d[9] != 17:
                    continue
                o = (d[0] & 15) * 4
            else:
                if d[6] != 17:
                    continue
                o = 40
            sp, dp = int.from_bytes(d[o:o + 2], "big"), int.from_bytes(d[o + 2:o + 4], "big")
            if self.port in (sp, dp):
                p = d[o + 8:]
                self.ev.append((time.time(), "c2s" if dp == self.port else "s2c", len(p), quic_types(p)))

    def stop(self, linger=0.3):
        time.sleep(linger)
        self.run = False
        self.th.join()
        st = self.s.getsockopt(263, 6, 8)                                   # SOL_PACKET, PACKET_STATISTICS
        self.s.close()
        drops = int.from_bytes(st[4:8], sys.byteorder)
        assert drops == 0, f"packet counter dropped {drops} packets"
        return self.ev

    @staticmethod
    def c2s(ev):
        return [e for e in ev if e[1] == "c2s"]


def quic_probe(port, label, groups=None, ip="127.0.0.1", host="q.test", timeout="8", tag="", script=PROBE_QUIC):
    tf = os.path.join(WORK, f"quic-cli-{tag or port}-{label}.trace")
    cnt = UdpCounter(port)
    t0 = time.time()
    tok = subprocess.run(["bash", script, host, ip, str(port), label, groups or G[label], tf, timeout], capture_output=True,
                         text=True, timeout=60, stdin=subprocess.DEVNULL).stdout.strip()
    el = time.time() - t0
    ev = cnt.stop()
    return tok, tf, el, ev, t0


def sent_frames(tf):
    return collections.Counter(l.strip() for l in open(tf, errors="replace") if l.startswith("Sent Frame: "))


def sent_datagram_lines(tf):
    return sum(1 for l in open(tf, errors="replace") if l.startswith("Sent Datagram"))


def qsrv_conns(port, n, timeout=20):
    """The first n finished connection records of a qsrv log: [{'hs': line, 'streams': [...], 'end': line}]."""
    lg = QLOG[port]
    t = time.time() + timeout
    while time.time() < t:
        txt = open(lg).read()
        if txt.count(" done\n") >= n:
            break
        time.sleep(0.1)
    conns = {}
    for l in open(lg).read().splitlines():
        m = re.match(r"qsrv: conn (\d+) (.*)", l)
        if m:
            c = conns.setdefault(int(m[1]), {"lines": []})
            c["lines"].append(m[2])
    assert len(conns) >= n, (n, open(lg).read()[-2000:])
    return [conns[k] for k in sorted(conns)][:n]


SENT_FRAMES_OK = {"Sent Frame: Crypto", "Sent Frame: Padding", "Sent Frame: Ack  (without ECN)", "Sent Frame: Ping",
                  "Sent Frame: Connection close (transport)", "Sent Frame: Connection close (app)"}
CLOSE_T, CLOSE_A = "Sent Frame: Connection close (transport)", "Sent Frame: Connection close (app)"


def quic_end(types, fr):
    """How a completed probe ended, or None if it broke a rule. Rules: no 0-RTT packet; only Crypto, Padding, Ack, Ping
    and exactly one Connection close frame. The packets differ from run to run (a race inside s_client between stdin's
    end-of-file and the server's first 1-RTT packets): usually only Initial and Handshake packets and a transport close
    in a Handshake packet, which the server never reads; sometimes also small 1-RTT packets (ACK, and maybe an
    application close, which the server then reads)."""
    if not set(types) <= {"initial", "handshake", "1rtt"} or not set(fr) <= SENT_FRAMES_OK or fr[CLOSE_T] + fr[CLOSE_A] != 1:
        return None
    return f"{'with 1-RTT' if types['1rtt'] else 'no 1-RTT'}, close {'app' if fr[CLOSE_A] else 'transport'}"


SERVER_END = ("not closed by the client within", "closed_by=client application error=0x0 ", "closed_by=client transport error=0xc ")


def q01_quic_handshake_sends_no_stream_data():
    """(a) and (c): completed QUIC probes; what the client sends, seen three ways (datagram counter on lo with the packet
    types, the server's stream log, the client's own -trace); tokens equal the TCP expectations (EXP)."""
    cases = [(Q_DEF, lab, "pf", "default groups, Retry") for lab in ("p1", "p2", "p3", "pa")] + \
            [(Q_COL, lab, "ex", "X25519MLKEM768:X25519, Retry") for lab in ("p1", "p2", "p3", "pa")] + \
            [(Q_NV, "p2", "pf", "default groups, no Retry")]
    seen, mx, branch, srv_end = collections.Counter(), 0, collections.defaultdict(list), collections.Counter()
    EVID.append("== (a) and (c): completed probes (probe_quic.sh, timeout 8 s) against tests/qsrv.c")
    for port, lab, kind, desc in cases:
        tok, tf, el, ev, t0 = quic_probe(port, lab, tag="q01")
        seen[port] += 1
        hrr, grp = EXP[kind][lab]
        assert CELL.match(tok) and tok.startswith("ok|") and f"hrr={hrr}" in tok and tok.endswith(f"grp={grp}"), (port, lab, tok)
        c = UdpCounter.c2s(ev)
        types = collections.Counter(t for e in c for t in e[3])
        fr = sent_frames(tf)
        b = quic_end(types, fr)
        assert b, (port, lab, types, fr)                                    # never 0-RTT, never a Stream frame
        assert 4 <= len(c) <= 16 and sent_datagram_lines(tf) == len(c), (port, lab, len(c), sent_datagram_lines(tf))
        assert el < 2.5 and "s_client stopped" not in open(tf).read(), (el, tok)
        branch[port].append(b)
        mx = max(mx, len(c))
        EVID.append(f"server {desc} (udp {port}), probe {lab}: token {tok}; client datagrams {len(c)} "
                    f"({sum(e[2] for e in c)} bytes), packet types {dict(sorted(types.items()))}; client frames "
                    f"{dict(sorted((k[12:], v) for k, v in fr.items()))}; {b}; probe ended after {el:.2f} s")
    for port, n in seen.items():
        for k, conn in enumerate(qsrv_conns(port, n)):
            txt = "\n".join(conn["lines"])
            assert "handshake=1" in txt and "streams=0" in txt and "client opened stream" not in txt, (port, k, txt)
            ends = [e for e in SERVER_END if e in txt]
            assert len(ends) == 1 and "closed_by=server" not in txt, (port, k, branch[port][k], txt)
            if branch[port][k] == "no 1-RTT, close transport":
                assert ends[0] == SERVER_END[0], (port, k, txt)       # a close in a Handshake packet is never read
            srv_end[ends[0].strip()] += 1
    nb = collections.Counter(b for v in branch.values() for b in v)
    EVID.append(f"server logs (qsrv, every connection above): handshake=1, streams=0 (no stream opened by the client); "
                f"how they ended: {dict(srv_end)}")
    EVID.append(f"client ends: {dict(nb)}")
    # control for the 1-RTT end, made certain: stdin stays open (empty) for 0.3 s, so the server's 1-RTT packets come first
    cnt = UdpCounter(Q_DEF)
    late = os.path.join(WORK, "quic-late-eof.trace")
    subprocess.run(f"sleep 0.3 | timeout 8 {OPENSSL} s_client -quic -alpn h3 -connect 127.0.0.1:{Q_DEF} -servername q.test "
                   f"-groups '{G['p1']}' -trace > {late} 2>/dev/null", shell=True, timeout=30)
    c = UdpCounter.c2s(cnt.stop())
    types = collections.Counter(t for e in c for t in e[3])
    fr = sent_frames(late)
    conn = "\n".join(qsrv_conns(Q_DEF, seen[Q_DEF] + 1)[-1]["lines"])
    small = [e[2] for e in c if "1rtt" in e[3]]
    assert quic_end(types, fr) == "with 1-RTT, close app" and all(n <= 64 for n in small), (types, fr, small)
    assert "streams=0" in conn and "closed_by=client application error=0x0" in conn, conn
    EVID.append(f"control for the 1-RTT end (sleep 0.3 | s_client -quic ..., stdin empty but open for 0.3 s): packet types "
                f"{dict(sorted(types.items()))}, the 1-RTT datagrams are {small} bytes; client frames "
                f"{dict(sorted((k[12:], v) for k, v in fr.items()))}; server: streams=0, closed_by=client application error=0x0")
    # positive control: one line on stdin. Each detector sees it: a client stream with 6 bytes in the server log,
    # 1-RTT packets on the wire, a Stream frame in the client trace
    cnt = UdpCounter(Q_DEF)
    ctl = os.path.join(WORK, "quic-control.trace")
    subprocess.run(f"printf 'hello\\n' | timeout 8 {OPENSSL} s_client -quic -alpn h3 -connect 127.0.0.1:{Q_DEF} -servername q.test "
                   f"-groups '{G['p1']}' -trace > {ctl} 2>&1", shell=True, timeout=30)
    c = UdpCounter.c2s(cnt.stop())
    conn = "\n".join(qsrv_conns(Q_DEF, seen[Q_DEF] + 2)[-1]["lines"])
    assert "client opened stream id=0" in conn and "bytes=6" in conn and "closed_by=client application" in conn, conn
    assert any("1rtt" in e[3] for e in c) and sent_frames(ctl)["Sent Frame: Stream"] >= 1, (c, sent_frames(ctl))
    EVID.append("positive control (printf 'hello\\n' | s_client -quic ...): server log '" +
                [l for l in conn.split("\n") if "stream id=0 type" in l and "bytes=" in l][0] + "'; client packet types "
                f"{dict(collections.Counter(t for e in c for t in e[3]))}; client trace has 'Sent Frame: Stream'")
    print(f"       {len(cases)} completed QUIC probes {dict(nb)}: no stream, no Stream frame, at most {mx} datagrams",
          flush=True)


def q02_quic_unanswered_and_failed_handshakes():
    """(b) datagrams to a port where nobody answers; (d) the datagram and trace caps when the handshake fails."""
    EVID.append("== (b): no answer (P1, the only probe a host without QUIC gets)")
    sink, sev, srun = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), [], [True]
    sink.bind(("127.0.0.1", Q_SINK))
    sink.settimeout(0.05)

    def drain():
        while srun[0]:
            try:
                sev.append((time.time(), len(sink.recv(65535))))
            except socket.timeout:
                pass
    th = threading.Thread(target=drain, daemon=True)
    th.start()
    try:
        for port, T, want, what in ((Q_SINK, "8", 5, "UDP socket that counts and drops"), (Q_SINK, "5", 4, "UDP socket that counts and drops"),
                                    (Q_CLOSED, "12", 5, "no socket (ICMP port unreachable)")):
            n0 = len(sev)
            tok, tf, el, ev, t0 = quic_probe(port, "p1", timeout=T, tag=f"q02-{T}")
            c = UdpCounter.c2s(ev)
            rel = [round(e[0] - t0, 1) for e in c]
            assert tok == "fail|ch=1|hrr=0|sh=0|grp=-" and float(T) - 0.2 <= el < float(T) + 2.5, (tok, el)
            assert len(c) == want and {t for e in c for t in e[3]} == {"initial"} and all(e[2] == 1200 for e in c), c
            assert all(abs(a - b) <= 0.4 for a, b in zip(rel, (0, 0, 1, 3, 7))) and sent_datagram_lines(tf) == want, (rel, tf)
            if port == Q_SINK:
                assert len(sev) - n0 == want, (len(sev) - n0, want)
            EVID.append(f"{what}, udp {port}, timeout {T} s: token {tok}; {len(c)} datagrams of 1200 bytes at {rel} s"
                        + (f" (the socket counted {len(sev) - n0})" if port == Q_SINK else "") + f"; probe ended after {el:.2f} s")
    finally:
        srun[0] = False
        th.join()
        sink.close()
    EVID.append("== (d): failed handshakes")
    # no common group, server answers with CONNECTION_CLOSE: ends at once
    tok, tf, el, ev, _ = quic_probe(Q_P256, "p1", tag="q02-p256")
    c = UdpCounter.c2s(ev)
    assert tok.startswith("fail|") and el < 2.5 and len(c) <= 10 and "s_client stopped" not in open(tf).read(), (tok, el, len(c))
    conn = "\n".join(qsrv_conns(Q_P256, 1)[0]["lines"])
    assert "closed_by=server transport error=0x128" in conn, conn
    EVID.append(f"P-256-only server, P1: token {tok}; {len(c)} client datagrams; ended after {el:.2f} s; server: "
                f"{[l for l in conn.split(chr(10)) if 'closed_by' in l][0]}")
    # hybrid-only server, client offers X25519 only (lab-B11's P0): the client and a fresh OpenSSL server answer each
    # other's PINGs without end (only on the first connection of a new server process); probe_quic.sh kills s_client at 40
    for port in Q_HYB:
        fresh_qsrv(port, "X25519MLKEM768")
    tok, tf, el, ev, _ = quic_probe(Q_HYB[0], "p0", groups="X25519", tag="q02-hyb")
    c, txt = UdpCounter.c2s(ev), open(tf, errors="replace").read()
    storm = len(c)
    assert tok.startswith("fail|") and "---- probe_quic.sh: s_client stopped: 40 datagrams sent ----" in txt, (tok, el, len(c), txt[-300:])
    assert 40 <= len(c) <= 100 and el < 3 and len(txt) < 200000, (len(c), el, len(txt))   # 52-59 seen: the kill lags ~1 ms
    assert not procs_mentioning(f"127.0.0.1:{Q_HYB[0]}"), procs_mentioning(f"127.0.0.1:{Q_HYB[0]}")
    EVID.append(f"hybrid-only server, client groups X25519 (lab-B11 P0), shipped probe_quic.sh: token {tok}; marker "
                f"'s_client stopped: 40 datagrams sent'; {len(c)} client datagrams in total (counter); trace {len(txt)} "
                f"bytes; ended after {el:.2f} s")
    # the same with the datagram stop switched off in a test copy: the trace cap (1 MiB) stops it
    src = open(PROBE_QUIC).read()
    cp = w(os.path.join(WORK, "probe_quic_nodg.sh"), src.replace("MAX_DATAGRAMS=40\n", "MAX_DATAGRAMS=100000000\n"))
    assert [l for l in open(cp).read().splitlines() if l not in src.splitlines()] == ["MAX_DATAGRAMS=100000000"]
    tok, tf, el, ev, _ = quic_probe(Q_HYB[1], "p0", groups="X25519", tag="q02-cap", script=cp)
    c, sz = UdpCounter.c2s(ev), os.path.getsize(tf)
    txt = open(tf, errors="replace").read()
    assert tok.startswith("fail|") and "---- probe_quic.sh: s_client stopped: trace reached 1048576 bytes ----" in txt, (tok, el, len(c), txt[-300:])
    assert sz <= 1048576 + 100 + 65536 + 20 and el < 8 and len(c) < 20000, (sz, el, len(c))
    assert not procs_mentioning(f"127.0.0.1:{Q_HYB[1]}")
    EVID.append(f"same, test copy with MAX_DATAGRAMS=100000000 (only the trace cap left): marker 's_client stopped: trace "
                f"reached 1048576 bytes'; trace file {sz} bytes; {len(c)} client datagrams; ended after {el:.2f} s")
    # control: cutting the output alone (head -c, as lab-B11) does not stop s_client: it ignores SIGPIPE
    cnt = UdpCounter(Q_HYB[2])
    t0 = time.time()
    subprocess.run(f"timeout 2 {OPENSSL} s_client -quic -alpn h3 -connect 127.0.0.1:{Q_HYB[2]} -servername q.test -groups X25519 "
                   f"-trace < /dev/null 2>/dev/null | head -c 65536 > /dev/null", shell=True, timeout=30)
    el = time.time() - t0
    c = UdpCounter.c2s(cnt.stop())
    assert len(c) > 2000 and el >= 1.9, (len(c), el)
    EVID.append(f"control: `timeout 2 s_client ... -groups X25519 -trace | head -c 65536` (output cut, no kill): s_client "
                f"ran until the timeout ({el:.2f} s) and sent {len(c)} datagrams")
    print(f"       no answer: 5 datagrams in 8 s; PING storm stopped after {storm} client datagrams; output cut only: "
          f"{len(c)} datagrams in 2 s", flush=True)


def q03_quic_scan_probe_set_caps_and_refusals():
    m = {f"qd{i}.test": f"127.0.0.1:{Q_SDEF}" for i in range(1, 4)}
    m.update({f"qc{i}.test": f"127.0.0.1:{Q_SCOL}" for i in range(1, 4)})
    m.update({"qsilent.test": f"127.0.0.1:{Q_SINK}", "qnoaddr.test": "-", "qexcl.test": f"127.0.0.1:{Q_SCOL}",
              "qboth.test": f"127.0.0.1:{Q_SDEF},[::1]:{Q_SDEF}"})
    rf = resolve_file("q03.tsv", m)
    tf = targets_file("q03-t.txt", list(m))
    ex = w(os.path.join(WORK, "q03-ex.txt"), "qexcl.test\n")
    o = os.path.join(WORK, "q03")
    common = ("--targets", tf, "--out", o, "--resolve-file", rf, "--exclude-file", ex, "--proto", "quic", "--families", "4,6",
              "--quic-timeout", "5", "--max-per-name", "4")
    t0 = time.time()
    rc, out = runpy(*common)
    assert rc == 0, out
    rs = {(r[0], r[10]): r for r in rows(o)}
    for h in [f"qd{i}.test" for i in range(1, 4)] + [f"qc{i}.test" for i in range(1, 4)] + ["qboth.test"]:
        r, kind = rs[(h, "4")], ("pf" if h.startswith(("qd", "qboth")) else "ex")
        for lab, (hrr, grp) in EXP[kind].items():
            c = {"p1": r[3], "p2": r[4], "p3": r[5], "pa": r[9]}[lab]
            assert CELL.match(c) and c.startswith("ok|") and f"hrr={hrr}" in c and c.endswith(f"grp={grp}"), (h, lab, c)
    assert rs[("qboth.test", "6")][3] == "capped", rs[("qboth.test", "6")]             # --max-per-name 4 over both families
    assert rs[("qsilent.test", "4")][3] == "fail|ch=1|hrr=0|sh=0|grp=-" and rs[("qnoaddr.test", "4")][3] == "noaddr"
    assert rs[("qexcl.test", "4")][3] == "excluded" and rs[("qd1.test", "6")][3] == "noaddr", rs
    pl = plog(o)
    by_ip, by_fam, by_name = _counts(pl)
    assert max(by_name.values()) <= 4 and not any(p[1] == "qexcl.test" for p in pl), by_name
    assert len([p for p in pl if p[3] == "127.0.0.1" and p[4] == str(Q_SDEF)]) == 16           # no per-IP cap: 4 names x 4
    assert {p[4] for p in pl} == {str(Q_SDEF), str(Q_SCOL), str(Q_SINK)}, {p[4] for p in pl}
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    assert (meta["proto"], meta["port"], meta["quic_timeout"], meta["per_ip_cap"], meta["smtp_timeout"]) == ("quic", 443, 5.0, 0, None), meta
    recs = [json.loads(l) for l in lzma.decompress(open(os.path.join(o, "traces.jsonl.xz"), "rb").read()).decode().splitlines()]
    assert len(recs) == len(pl) and all("Packet Type: Initial" in x["trace"] for x in recs), len(recs)
    assert "proto quic (port 443)" in open(os.path.join(o, "run.log")).read()
    el = time.time() - t0
    # resume: nothing is probed again
    rc, out = runpy(*common, "--resume")
    assert rc == 0 and len(plog(o)) == len(pl) and len(rows(o)) == len(rs), out
    # refusals: nothing created
    for extra in (("--www", "add"), ("--mode", "alladdr"), ("--quic-timeout", "4"), ("--quic-timeout", "13"),
                  ("--quic-timeout", "8.5"), ("--quic-timeout", "nan"), ("--ehlo-name", EHLO)):
        rc, out = runpy("--targets", tf, "--out", os.path.join(WORK, "q03-bad"), "--resolve-file", rf, "--proto", "quic", *extra)
        assert rc == 2 and not os.path.exists(os.path.join(WORK, "q03-bad")), (extra, rc, out)
    for extra in (("--quic-timeout", "8"), ("--proto", "smtp", "--ehlo-name", EHLO, "--quic-timeout", "8")):
        rc, out = runpy("--targets", tf, "--out", os.path.join(WORK, "q03-bad"), "--resolve-file", rf, *extra)
        assert rc == 2 and "--quic-timeout is for --proto quic only" in out and not os.path.exists(os.path.join(WORK, "q03-bad")), out
    rc, out = runpy("--estimate", "1000", "--proto", "quic")
    assert rc == 0 and "quic: the duration is a lower bound" in out and '"proto": "quic"' in out, out
    print(f"       {len(pl)} QUIC handshakes over {len(rs)} rows in {el:.1f} s", flush=True)


def q04_quic_port_443_from_dns_and_targets_helper():
    # the system resolver path (stub DNS) with UDP port 443
    tf = targets_file("q04-t.txt", ["quic443.test"])
    o = os.path.join(WORK, "q04")
    rc, out = runpy("--targets", tf, "--out", o, "--allow-nonglobal", "--proto", "quic")
    assert rc == 0, out
    r = rows(o)[0]
    assert r[1] == "127.0.0.1" and r[3].startswith("ok|") and r[4].endswith("grp=ecdh_x25519"), r
    assert {p[4] for p in plog(o)} == {"443"} and len(plog(o)) == 4, plog(o)
    assert json.loads(open(os.path.join(o, "run-meta.json")).readline())["quic_timeout"] == 8.0
    # quic_targets.py on a finished https run directory (fixture)
    d = os.path.join(WORK, "q04-https")
    os.makedirs(d)
    PQ = "ok|ch=1|hrr=0|sh=1|grp=X25519MLKEM768"
    X = "ok|ch=1|hrr=0|sh=1|grp=ecdh_x25519"

    def row(h, fam, var, rank, p1, ip="192.0.2.1"):
        return "\t".join([h, ip, "1", p1, "skip", "skip", "0", "0", "", "skip", str(fam), var, str(rank), "pinned"]) + "\n"
    w(os.path.join(d, "results.tsv"), "".join([
        row("b.test", 4, "list", 2, PQ), row("www.b.test", 4, "www", 2, PQ), row("b.test", 6, "list", 2, PQ, "2001:db8::1"),
        row("a.test", 4, "list", 1, X), row("www.a.test", 4, "www", 1, PQ), row("c.test", 4, "list", 3, "fail|ch=1|hrr=0|sh=0|grp=-"),
        row("d.test", 6, "list", 4, PQ, "2001:db8::2"), row("d.test", 4, "list", 4, "noaddr", "-"), row("e.test", 4, "list", 5, "capped"),
        row("f.test", 4, "list", 6, "excluded", "-"), row("g.test", 4, "list", 7, "ok|ch=2|hrr=1|sh=2|grp=X25519MLKEM768"),
        "torn\tline\n"]))
    w(os.path.join(d, "run-meta.json"), json.dumps({"start_kind": "FRESH"}) + "\n" + json.dumps({"proto": "https"}) + "\n")
    w(os.path.join(d, "guard-meta.json"), json.dumps({"status": "finished"}))
    out_f = os.path.join(WORK, "q04-quic-targets.txt")
    rc, out = runpy("--run", d, "--out", out_f, script=QUIC_TARGETS)
    assert rc == 0, out
    want = "1,www.a.test\n2,b.test\n2,www.b.test\n4,d.test\n7,g.test\n"     # P1 on the hybrid in any family; rank kept
    assert open(out_f).read() == want, open(out_f).read()
    assert open(out_f + ".sha256").read() == f"{sha(out_f)}  q04-quic-targets.txt\n"
    j = json.loads(out.split("QUICTARGETS-JSON ")[1].splitlines()[0])
    assert (j["rows"], j["pq_rows"], j["names"], j["malformed_or_invalid"], j["complete"]) == (11, 6, 5, 1, True), j
    rc, out = runpy("--dry-run", "--targets", out_f, "--proto", "quic")
    assert rc == 0 and "names: 5 " in out and "targets per family: 5" in out, out
    # refusals: nothing written
    rc, out = runpy("--run", d, "--out", out_f, script=QUIC_TARGETS)
    assert rc == 2 and "exists" in out, out
    bad = os.path.join(WORK, "q04-bad.txt")
    for what, fix in (("smtp run", lambda: w(os.path.join(d, "run-meta.json"), json.dumps({"proto": "smtp"}) + "\n")),
                      ("quic run", lambda: w(os.path.join(d, "run-meta.json"), json.dumps({"proto": "quic"}) + "\n")),
                      ("running", lambda: (w(os.path.join(d, "run-meta.json"), "{}\n"), w(os.path.join(d, "guard-meta.json"), '{"status": "running"}'))),
                      ("STOP", lambda: (w(os.path.join(d, "guard-meta.json"), '{"status": "finished"}'), w(os.path.join(d, "STOP"), "x\n")))):
        fix()
        rc, out = runpy("--run", d, "--out", bad, script=QUIC_TARGETS)
        assert rc == 2 and not os.path.exists(bad) and not os.path.exists(bad + ".sha256"), (what, out)
    rc, out = runpy("--run", d, "--out", bad, "--allow-incomplete", script=QUIC_TARGETS)
    assert rc == 0 and "WARNING" in out and '"complete": false' in out and open(bad).read() == want, out
    rc, out = runpy("--run", os.path.join(WORK, "q04-none"), "--out", os.path.join(WORK, "q04-none.txt"), script=QUIC_TARGETS)
    assert rc == 2 and "not found" in out, out


def write_quic_evidence(path):
    v = subprocess.run([OPENSSL, "version"], capture_output=True, text=True).stdout.strip()
    head = f"""What `openssl s_client -quic` sends: kit-c probe_quic.sh on loopback (written by tests/test_kit.py q01-q02)

Recorded on the laptop inside `unshare -Urnm` (network namespace with loopback only; nothing left the machine) by
  KITC_QUIC_EVIDENCE={os.path.relpath(path, KIT)} bash run_tests.sh q01 q02
Client: kit-c/probe_quic.sh q.test 127.0.0.1 PORT LABEL GROUPS TRACE TIMEOUT, i.e.
  timeout -k 2 TIMEOUT stdbuf -oL {OPENSSL} s_client -quic -alpn h3 -connect 127.0.0.1:PORT -servername q.test
          -groups GROUPS -trace < /dev/null       ({v})
  with probe_quic.sh's two stops: s_client is killed at its 40th sent datagram or at 1 MiB of trace.
Servers: kit-c/tests/qsrv.c (built from source by the test; OpenSSL server-side QUIC API, ALPN h3; accepts and logs
every stream the client opens, waits {QWAIT} s for the client to close, logs the client's CONNECTION_CLOSE).
Observers: (1) a datagram counter on lo (AF_PACKET socket): every UDP datagram, split into QUIC packets by the header
fields that header protection leaves in clear; STREAM frames can only travel in 0-RTT and 1-RTT packets (RFC 9000
12.4), so a client that sends only Initial and Handshake packets sends no stream data; (2) the server's stream log;
(3) the client's own -trace ("Sent Frame:" and "Sent Datagram" lines; the counts are checked against (1)).
The same facts are asserted by tests q01 and q02 at every run of the suite.
Timestamps differ between runs; counts are checked against fixed bounds by the tests.

Summary
- (a) A completed probe sends the ClientHello (two datagrams when it carries an X25519MLKEM768 share), a second
  ClientHello after a Retry or a HelloRetryRequest, ACKs, the client Finished, a few PINGs and one CONNECTION_CLOSE,
  7 to 13 datagrams (asserted: 4 to 16). It never sends a STREAM frame: no HTTP/3 request, no SETTINGS, no stream
  opened (every server log: streams=0; the client trace lists only Crypto, Padding, Ack, Ping and Connection close
  frames, and its "Sent Datagram" count equals the counter's). The packets differ between runs (a race inside
  s_client between stdin's end-of-file and the server's first 1-RTT packets):
  usually only Initial and Handshake packets, with the CONNECTION_CLOSE (transport) in a Handshake packet, which the
  server never reads ("not closed by the client"; inference: by then it has dropped its Handshake keys, RFC 9001
  4.9.2), so a real server keeps the connection until its idle timeout. Without any 1-RTT packet no STREAM frame can be
  sent at all (RFC 9000 12.4), which the counter checks independently of the trace.
  Sometimes the client also sends one or two small 1-RTT packets: an ACK, and, when it has processed the server's
  1-RTT packets before stdin's end-of-file, an application CONNECTION_CLOSE with error 0 that the server reads
  ("closed_by=client application error=0x0", streams=0). Seen in earlier runs of q01 (1 of 9 probes, twice); made
  certain by the control that keeps stdin open, empty, for 0.3 s (two 1-RTT datagrams of 32 and 34 bytes). These
  packets carry no stream: the server log and the client's frame list say so for every probe.
  s_client exits about 0.6 s after it started.
- (c) Tokens equal the TCP expectations (test EXP): default server -> P2 and P3 get a HelloRetryRequest and end on
  X25519MLKEM768; colon list X25519MLKEM768:X25519 -> P2, P3, PA end on X25519 without HRR; P1 on the hybrid in both.
  A QUIC Retry does not change the token (the trace prints the ClientHello once; ch counts TLS messages).
- (b) A host that does not answer gets 5 datagrams of 1200 bytes in 8 s (0, 0, 1, 3, 7 s), 4 in 5 s, and 5 in 12 s
  (the next would be at 15 s); a closed port (ICMP port unreachable) gets the same.
- (d) No common group with an answering server (P-256 only): the server closes, the probe ends in 0.6 s. Hybrid-only
  server with a client that offers X25519 only: client and a fresh OpenSSL server answer each other's PINGs without
  end; probe_quic.sh kills s_client at its 40th datagram (52 to 59 sent in all in our runs, asserted at most 100,
  under 1 s; the kill lags the 40th datagram by about 1 ms, in which the PING exchange goes on). With that stop switched
  off, the 1 MiB trace cap kills it (about 1,100 datagrams). With neither (output only cut by head -c, as in lab-B11),
  s_client ignores SIGPIPE and keeps going (over 2,000 datagrams asserted; about 30,000 in 2 s observed).

"""
    with open(path, "w") as f:
        f.write(head + "\n".join(EVID) + "\n")


def r17_resume_after_kill_caps_across_parts():
    # part A: run.py killed with SIGKILL mid-run, then `--resume`: no duplicate rows, every cap holds over both parts
    names = [f"rs{i:03d}.test" for i in range(60)]
    rf = resolve_file("r17.tsv", {n: f"127.0.0.1:{P_HYB},[::1]:{P_HYB}" for n in names})
    tf = targets_file("r17-t.txt", names)
    o = os.path.join(WORK, "r17")
    common = ("--targets", tf, "--out", o, "--resolve-file", rf, "--families", "4,6", "--max-per-name", "6")
    p = bg_runpy(*common)
    deadline = time.time() + 40
    while len(plog(o)) < 160 and time.time() < deadline:     # of about 360; rows appear only after ~100 handshakes
        time.sleep(0.05)
    p.kill()
    p.communicate(timeout=10)
    time.sleep(0.5)
    rows1, pl1 = rows(o), plog(o)
    rowed = {(r[0], int(r[10])) for r in rows1}
    _, fam1, _ = _counts(pl1)
    in_flight = [k for k in fam1 if k not in rowed]          # handshakes started, row never written
    assert 0 < len(rows1) < 120 and in_flight, (len(rows1), in_flight)
    rc, out = runpy(*common, "--resume")
    assert rc == 0, out
    rs = rows(o)
    keys = [(r[0], r[10]) for r in rs]
    assert len(keys) == len(set(keys)) == 120, (len(keys), len(set(keys)))
    by_ip, by_fam, by_name = _counts(plog(o))
    assert max(by_ip.values()) <= 4 and max(by_fam.values()) <= 4 and max(by_name.values()) <= 6, (by_ip, by_name)
    for k in in_flight:                                        # re-probed only up to the remaining cap
        assert by_fam[k] <= 4, (k, fam1[k], by_fam[k])
    metas = [json.loads(l) for l in open(os.path.join(o, "run-meta.json"))]
    assert [m["start_kind"] for m in metas] == ["FRESH", "RESUME"], metas
    assert metas[1]["rows_already_present"] == len(rows1) and metas[1]["handshakes_already_present"] == len(pl1), metas[1]
    assert "RESUME:" in open(os.path.join(o, "run.log")).read()
    print(f"       part 1: {len(rows1)} rows, {len(pl1)} handshakes, {len(in_flight)} targets in flight at the kill; "
          f"after resume: {len(rs)} rows, {sum(by_ip.values())} handshakes, max per (name, family) {max(by_fam.values())}, "
          f"max per name {max(by_name.values())}", flush=True)
    # part B (fixture): the pinned address changed between the parts, and a crash cut the last line of both files
    o2 = os.path.join(WORK, "r17b")
    os.makedirs(o2)
    t = time.time()
    w(os.path.join(o2, "probes.log"), "".join(f"{t - 100 + k:.3f}\tipchg.test\t{lab}\t127.0.0.2\t{P_HYB}\n"
                                             for k, lab in enumerate(("p1", "p2", "p3"))) + f"{t - 50:.3f}\tipchg.te")
    done_row = "\t".join(["done.test", "127.0.0.1", "1", "ok|ch=1|hrr=0|sh=1|grp=ecdh_x25519", "skip", "skip", "0", "0", "",
                          "skip", "4", "list", "2", "pinned"])
    w(os.path.join(o2, "results.tsv"), done_row + "\ntorn.test\t127.0.0.1\t1\tok|ch=1")
    rf2 = resolve_file("r17b.tsv", {n: f"127.0.0.1:{P_HYB}" for n in ("ipchg.test", "done.test", "torn.test")})
    tf2 = targets_file("r17b-t.txt", ["ipchg.test", "done.test", "torn.test"])
    rc, out = runpy("--targets", tf2, "--out", o2, "--resolve-file", rf2, "--resume")
    assert rc == 0, out
    rs = {r[0]: r for r in rows(o2)}
    assert len(rows(o2)) == 3 and all(len(r) == 14 for r in rows(o2)), rows(o2)
    assert rs["done.test"] == done_row.split("\t"), rs["done.test"]
    ip = rs["ipchg.test"]
    assert ip[1] == "127.0.0.1" and ip[3].startswith("ok|") and ip[4] == ip[5] == ip[9] == "capped", ip
    _, by_fam, _ = _counts(plog(o2))
    assert by_fam[("ipchg.test", 4)] == 4 and ("done.test", 4) not in by_fam and by_fam[("torn.test", 4)] == 4, by_fam
    assert open(os.path.join(o2, "results.torn.tsv")).read() == "torn.test\t127.0.0.1\t1\tok|ch=1\n"
    lines = open(os.path.join(o2, "probes.log")).read().split("\n")
    assert f"{t - 50:.3f}\tipchg.te" in lines, lines[:6]
    m = json.loads(open(os.path.join(o2, "run-meta.json")).readline())
    assert set(m["torn_tail_repaired"]) == {"results.tsv", "probes.log"} and m["rows_already_present"] == 1, m
    assert m["handshakes_already_present"] == 3, m           # the terminated fragment has 2 fields: not a handshake


# ------------------------------------------------------------------------------------------------- 5. guard
GKIT = os.path.join(WORK, "gkit")
GUARD = os.path.join(GKIT, "guard.py")
GT = GR = GSHA = None


def gsetup():
    global GT, GR, GSHA
    shutil.copytree(KIT, GKIT, ignore=shutil.ignore_patterns(".work", "__pycache__", "*.log"))
    names = [f"g{i:02d}.test" for i in range(1, 11)]
    GT = targets_file("g-targets.txt", names)
    GSHA = sha(GT)
    GR = resolve_file("g.tsv", {n: f"127.0.0.1:{P_HYB if i < 5 else P_CLS}" for i, n in enumerate(names)})


def genv(**kw):
    e = {k: v for k, v in os.environ.items() if not k.startswith("GUARD_")}
    e.update(GUARD_NOW=IN_WIN, GUARD_EGRESS=EGR, GUARD_FREE_GB="50", GUARD_TAILSCALE_JSON="NOT_INSTALLED",
             GUARD_RESOLV_CONF="/etc/resolv.conf", GUARD_NTP_SYNC="yes", OPENSSL=OPENSSL)
    for k, v in kw.items():
        if v is None:
            e.pop(k, None)
        else:
            e[k] = v
    return e


def gout(name):
    return os.path.join(WORK, f"g-{name}", f"run-{GDATE}")


def gargs(out, targets=None, tsha=None, extra=()):
    return ["--date", GDATE, "--allowed-dates", GDATE, "--out", out, "--targets", targets or GT, "--targets-sha256", tsha or GSHA,
            "--expected-egress", EGR, "--vantage-label", "test vantage", "--max-minutes", "30", *extra]


def guard(sub, args, env=None, timeout=180, script=None):
    p = subprocess.run([sys.executable, "-I", script or GUARD, sub, *args], capture_output=True, text=True, env=env or genv(), timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def verdicts(out):
    return {l[6]: l[:4] for l in out.splitlines() if l.startswith(("PASS (", "FAIL ("))}


def expect_fail_only(out, ids, rc=None):
    v = verdicts(out)
    assert set(v) == set("abcdefghijk"), f"missing check lines: {sorted(v)}\n{out}"
    got = {k for k, x in v.items() if x == "FAIL"}
    assert got == set(ids), f"expected exactly {sorted(ids)} to FAIL, got {sorted(got)}\n{out}"
    if rc is not None:
        assert rc == (1 if ids else 0), f"rc {rc}\n{out}"


def chk(extra=(), env=None, out=None, **kw):
    return guard("check", gargs(out or gout("chk"), extra=extra, **kw), env=env)


def g01_baseline_all_pass():
    rc, out = chk()
    expect_fail_only(out, [], rc)
    assert "TEST MODE" in out and "RESULT: all checks passed" in out, out


def g02_window_boundaries():
    for t, ok in (("01:59:59", False), ("02:00:00", True), ("07:59:30", True), ("08:00:00", False), ("12:30:00", False)):
        rc, out = chk(env=genv(GUARD_NOW=f"{GDATE}T{t}+08:00"))
        expect_fail_only(out, [] if ok else ["a"], rc)
    rc, out = chk(env=genv(GUARD_NOW="2026-01-14T21:00:00+00:00"))           # = 05:00 Taipei on GDATE
    expect_fail_only(out, [], rc)


def g03_dates():
    rc, out = chk(env=genv(GUARD_NOW="2026-01-16T03:00:00+08:00"))
    expect_fail_only(out, ["a"], rc)
    a = gargs(gout("d"))
    a[a.index("--allowed-dates") + 1] = "2026-01-16"
    rc, out = guard("check", a)
    expect_fail_only(out, ["a"], rc)
    a = gargs(gout("d"))
    i = a.index("--allowed-dates")
    del a[i:i + 2]
    rc, out = guard("check", a)
    assert rc == 2 and "--allowed-dates" in out, out


def g04_egress_parameter():
    rc, out = chk(env=genv(GUARD_EGRESS="140.116.9.9"))
    expect_fail_only(out, ["b"], rc)
    assert "not the expected" in out
    rc, out = chk(extra=("--allow-unannounced-egress",), env=genv(GUARD_EGRESS="140.116.9.9"))
    expect_fail_only(out, [], rc)
    assert "OVERRIDE" in out and "WARN: not the expected address" in out, out
    for bad in ("8.8.8.8", "garbage", "2001:288::1"):
        rc, out = chk(env=genv(GUARD_EGRESS=bad))
        expect_fail_only(out, ["b"], rc)
    a = gargs(gout("e"))
    a[a.index("--expected-egress") + 1] = "10.1.2.3"
    rc, out = guard("check", a + ["--egress-prefix", "10."], env=genv(GUARD_EGRESS="10.1.2.3"))
    expect_fail_only(out, ["b"], rc)
    assert "not a public address" in out
    t0 = time.time()
    rc, out = chk(env=genv(GUARD_EGRESS=None))           # real lookup path: fails inside the namespace (DNS -> stub, NXDOMAIN)
    expect_fail_only(out, ["b"], rc)
    assert "could not determine" in out and time.time() - t0 < 30
    rc, out = guard("check", [x if x != EGR else "140.116.1.300" for x in gargs(gout("e"))])
    assert rc == 2, out


def g05_ipv6_egress():
    rc, out = chk(extra=("--families", "4,6"))
    assert rc == 2 and "--expected-egress6" in out, out
    ok6 = ("--families", "4,6", "--expected-egress6", "2001:288:1234::/48")
    rc, out = chk(extra=ok6, env=genv(GUARD_EGRESS6="2001:288:1234::5"))
    expect_fail_only(out, [], rc)
    rc, out = chk(extra=ok6, env=genv(GUARD_EGRESS6="2001:288:9999::5"))
    expect_fail_only(out, ["b"], rc)
    rc, out = chk(extra=ok6, env=genv(GUARD_EGRESS6=None))
    expect_fail_only(out, ["b"], rc)


def g06_exit_node():
    for js in ('{"BackendState":"Running","ExitNodeStatus":{"ID":"n1","Online":true}}',
               '{"BackendState":"Running","ExitNodeStatus":null,"Peer":{"k":{"HostName":"hk","ExitNode":true}}}'):
        rc, out = chk(env=genv(GUARD_TAILSCALE_JSON=js))
        expect_fail_only(out, ["c"], rc)
    rc, out = chk(env=genv(GUARD_TAILSCALE_JSON='{"BackendState":"Running","ExitNodeStatus":null,"Peer":{}}'))
    expect_fail_only(out, [], rc)


def g07_disk():
    rc, out = chk(env=genv(GUARD_FREE_GB="1.0"))
    expect_fail_only(out, ["d"], rc)
    big = targets_file("g-big.txt", [f"b{i:06d}.test" for i in range(200000)])
    rc, out = chk(env=genv(GUARD_FREE_GB="2.0"), targets=big, tsha=sha(big))   # plan: ~438k handshakes -> ~2.76 GiB needed
    expect_fail_only(out, ["d"], rc)
    rc, out = chk(env=genv(GUARD_FREE_GB="3.0"), targets=big, tsha=sha(big))
    expect_fail_only(out, [], rc)


def g08_output_directory():
    for name, prep in (("stop", "STOP"), ("res", "results.tsv"), ("xz", "traces.jsonl.xz")):
        o = gout(name)
        w(os.path.join(o, prep), "x\n")
        rc, out = chk(out=o)
        expect_fail_only(out, ["e"], rc)
    rc, out = chk(out=os.path.join(WORK, "g-nodate", "run"))
    expect_fail_only(out, ["e"], rc)


def g09_targets_hash_and_kit_integrity():
    rc, out = chk(tsha="0" * 64)
    expect_fail_only(out, ["g"], rc)
    k2 = os.path.join(WORK, "gkit-tampered")
    shutil.copytree(GKIT, k2)
    with open(os.path.join(k2, "run.py"), "a") as f:
        f.write("# tampered\n")
    rc, out = guard("check", gargs(gout("t")), script=os.path.join(k2, "guard.py"))
    expect_fail_only(out, ["g"], rc)
    assert "run.py does not match" in out, out


def g10_exclusion_file_invalid():
    bad = w(os.path.join(WORK, "g-bad-ex.txt"), "good.test\n?? bad\n")
    rc, out = chk(extra=("--exclude-file", bad))
    v = verdicts(out)
    assert rc == 1 and v["g"] == "FAIL" and v["j"] == "FAIL", out


def g11_openssl():
    fake = w(os.path.join(WORK, "fake-openssl"), "#!/bin/sh\necho 'OpenSSL 3.0.13 30 Jan 2024'\n")
    os.chmod(fake, 0o755)
    rc, out = chk(env=genv(OPENSSL=fake))
    expect_fail_only(out, ["f"], rc)


def g12_other_scanner():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "/x/run.py", "--targets", "x"])
    try:
        time.sleep(0.3)
        rc, out = chk()
        expect_fail_only(out, ["i"], rc)
    finally:
        p.kill()
        p.wait()


def g13_run_refusals():
    o = gout("ref")
    rc, out = guard("run", gargs(o) + ["--extra-run-args", f"--resolve-file {GR}"])
    assert rc == 2 and "REFUSED" in out and not os.path.exists(o), out
    for go in ("GO-2026-01-15-OPERATOR-APPROVE", "go-2026-01-15-operator-approved", "GO-2026-01-16-OPERATOR-APPROVED", " " + GO):
        rc, out = guard("run", gargs(o) + ["--go", go, "--extra-run-args", f"--resolve-file {GR}"])
        assert rc == 2 and not os.path.exists(o), (go, out)
    rc, out = guard("run", gargs(o) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"],
                    env=genv(GUARD_NOW=f"{GDATE}T12:00:00+08:00"))
    assert rc == 1 and "pre-flight failed" in out and not os.path.exists(o), out


def g14_test_mode_loopback_only():
    o = gout("tm")
    far = resolve_file("g-far.tsv", {"g01.test": "192.0.2.10:443"})
    for extra in ([], ["--extra-run-args", f"--resolve-file {far}"], ["--extra-run-args", "--rate 50"]):
        rc, out = guard("run", gargs(o) + ["--go", GO] + extra)
        assert rc == 2 and not os.path.exists(os.path.join(o, "results.tsv")), (extra, out)


def g15_max_minutes_required_and_capped():
    a = gargs(gout("mm"))
    i = a.index("--max-minutes")
    rc, out = guard("check", a[:i] + a[i + 2:])
    assert rc == 2, out
    for v in ("361", "0", "-1"):
        b = list(a)
        b[i + 1] = v
        rc, out = guard("check", b)
        assert rc == 2, (v, out)


def g16_happy_path():
    o = gout("happy")
    rc, out = guard("run", gargs(o) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"], timeout=180)
    assert rc == 0, out
    rs = rows(o)
    assert len(rs) == 10, rs
    assert len(plog(o)) == 5 * 4 + 5, len(plog(o))
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    a = meta["argv"]

    def val(flag):
        return a[a.index(flag) + 1]
    for flag, v in (("--rate", "18"), ("--workers", "24"), ("--seed", "1"), ("--cap", "4"), ("--max-minutes", "30"),
                    ("--families", "4"), ("--www", "off"), ("--mode", "pinned"), ("--traces", "xz")):
        assert val(flag) == v, (flag, a)
    assert meta["guarded"] is True and EGR in meta["vantage"] and "test vantage" in meta["vantage"], meta
    for forbidden in ("--force", "--allow-nonglobal", "--per-ip-rate"):
        assert forbidden not in a
    assert val("--tz") == "Asia/Taipei" and val("--window") == "02:00-08:00", a
    assert meta["tz"] == "Asia/Taipei" and meta["window"] == "02:00-08:00", meta
    gm = json.load(open(os.path.join(o, "guard-meta.json")))
    assert gm["exit_code"] == 0 and gm["max_per_second"] <= 18 and gm["handshakes"] == 25, gm
    assert gm["tz"] == "Asia/Taipei" and gm["window"] == "02:00-08:00" and gm["local_start"].endswith("+08:00"), gm
    assert "RESULT: run finished cleanly" in open(os.path.join(o, "guard.log")).read()
    assert not procs_mentioning(o)
    rc2, out2 = guard("run", gargs(o) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"])
    assert rc2 == 1 and "REFUSED" in out2 and len(rows(o)) == 10


def _bigrun(tag, n=300):
    names = [f"{tag}{i:03d}.test" for i in range(n)]
    t = targets_file(f"g-{tag}.txt", names)
    r = resolve_file(f"g-{tag}.tsv", {x: f"127.0.0.1:{P_CLS}" for x in names})
    return t, sha(t), r


def g17_watchdog_at_0800():
    t, s, r = _bigrun("wd")
    o = gout("wd")
    t0 = time.time()
    rc, out = guard("run", gargs(o, targets=t, tsha=s) + ["--go", GO, "--grace-seconds", "5", "--extra-run-args", f"--resolve-file {r}"],
                    env=genv(GUARD_NOW=f"{GDATE}T07:59:56+08:00"))
    assert rc == 3, out
    assert "08:00" in open(os.path.join(o, "STOP")).read() and time.time() - t0 < 20
    n = len(plog(o))
    assert 30 <= n <= 6 * 18 + 19, n
    assert wait_gone(o, 10)


def g18_watchdog_max_minutes():
    t, s, r = _bigrun("wm")
    o = gout("wm")
    a = gargs(o, targets=t, tsha=s)
    a[a.index("--max-minutes") + 1] = "0.05"
    t0 = time.time()
    rc, out = guard("run", a + ["--go", GO, "--grace-seconds", "5", "--extra-run-args", f"--resolve-file {r}"])
    assert rc in (3, 5) and os.path.exists(os.path.join(o, "STOP")), out          # guard watchdog or run.py's own stop
    assert time.time() - t0 < 20 and len(plog(o)) <= 4 * 18 + 19
    assert wait_gone(o, 10)


def g19_sigterm_to_guard():
    t, s, r = _bigrun("st")
    o = gout("st")
    p = subprocess.Popen([sys.executable, "-I", GUARD, "run", *gargs(o, targets=t, tsha=s), "--go", GO, "--grace-seconds", "5",
                          "--extra-run-args", f"--resolve-file {r}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=genv())
    deadline = time.time() + 30
    while not plog(o) and time.time() < deadline:
        time.sleep(0.2)
    time.sleep(1.0)
    p.send_signal(signal.SIGTERM)
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 3, out
    assert "SIGTERM" in open(os.path.join(o, "STOP")).read()
    assert wait_gone(o, 10), procs_mentioning(o)


def g20_plan_line_and_warning():
    rc, out = chk()
    j = [l for l in out.splitlines() if l.startswith("PASS (j)")][0]
    assert "expected" in j and "WARN" not in j, j
    t, s, _ = _bigrun("pl", 3000)
    a = gargs(gout("pl"), targets=t, tsha=s)
    a[a.index("--max-minutes") + 1] = "1"
    rc, out = guard("check", a)
    j = [l for l in out.splitlines() if "(j)" in l][0]
    assert j.startswith("PASS") and "WARN: does not fit" in j, j


def kline(out):
    return [l for l in out.splitlines() if l.startswith(("PASS (k)", "FAIL (k)"))][0]


def eline(out):
    return [l for l in out.splitlines() if l.startswith(("PASS (e)", "FAIL (e)"))][0]


def stub_exe(path, body):
    w(path, "#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return path


def g21_clock_check_pass_fail_missing():
    # real code path (GUARD_NTP_SYNC unset): a stub timedatectl first on PATH; it answers only the exact invocation
    sd = os.path.join(WORK, "g21-bin")
    exact = '[ "$*" = "show -p NTPSynchronized --value" ] || { echo "unexpected arguments: $*" >&2; exit 64; }\n'
    for body, ok, frag in ((exact + "echo yes\n", True, "NTPSynchronized=yes (timedatectl"),
                           (exact + "echo no\n", False, "NTPSynchronized='no'"),
                           (exact + "echo YES\n", False, "NTPSynchronized='YES'"),
                           (exact + "echo\n", False, "NTPSynchronized=''"),
                           (exact + "echo 'System has not been booted with systemd' >&2; exit 1\n", False, "exit 1")):
        stub_exe(os.path.join(sd, "timedatectl"), body)
        rc, out = chk(env=genv(GUARD_NTP_SYNC=None, PATH=sd))
        expect_fail_only(out, [] if ok else ["k"], rc)
        assert frag in kline(out), (body, kline(out))
    empty = os.path.join(WORK, "g21-empty")
    os.makedirs(empty)
    rc, out = chk(env=genv(GUARD_NTP_SYNC=None, PATH=empty))                  # timedatectl missing: fail closed
    expect_fail_only(out, ["k"], rc)
    assert "timedatectl not found" in kline(out), kline(out)
    # the real timedatectl inside the test namespace (no D-Bus, /run is empty): an error, so FAIL
    rc, out = chk(env=genv(GUARD_NTP_SYNC=None))
    expect_fail_only(out, ["k"], rc)
    # test override: a value, a file (re-read every time), NOT_INSTALLED
    for v, ok in (("yes", True), ("no", False), ("NOT_INSTALLED", False), ("", False)):
        rc, out = chk(env=genv(GUARD_NTP_SYNC=v))
        expect_fail_only(out, [] if ok else ["k"], rc)
    f = w(os.path.join(WORK, "g21-ntp"), "no\n")
    rc, out = chk(env=genv(GUARD_NTP_SYNC=f))
    expect_fail_only(out, ["k"], rc)
    w(f, "yes\n")
    rc, out = chk(env=genv(GUARD_NTP_SYNC=f))
    expect_fail_only(out, [], rc)


def g22_clock_override_only_in_test_mode():
    # GUARD_NTP_SYNC / GUARD_NTP_POLL_SECONDS alone (no other GUARD_* variable) switch on TEST MODE, like GUARD_NOW
    for var, val in (("GUARD_NTP_SYNC", "yes"), ("GUARD_NTP_POLL_SECONDS", "1"), ("GUARD_NOW", IN_WIN)):
        e = {k: v for k, v in os.environ.items() if not k.startswith("GUARD_")}
        e.update({"OPENSSL": OPENSSL, var: val})
        rc, out = chk(env=e)
        banner = [l for l in out.splitlines() if "TEST MODE" in l]
        assert banner and f"env {var}" in banner[0], (var, out)
    # in TEST MODE `run` refuses anything but loopback: the override can never reach a real run
    far = resolve_file("g22-far.tsv", {f"g{i:02d}.test": "192.0.2.10:443" for i in range(1, 11)})
    o = gout("g22")
    for extra in ([], ["--extra-run-args", f"--resolve-file {far}"]):
        for env in (genv(), genv(GUARD_NOW=None, GUARD_NTP_SYNC="yes")):
            rc, out = guard("run", gargs(o) + ["--go", GO] + extra, env=env)
            assert rc in (1, 2) and "REFUSED" in out and not os.path.exists(os.path.join(o, "probes.log")), (extra, rc, out)
    # without the override the real clock check is used; it fails inside the test namespace, so nothing starts
    rc, out = guard("run", gargs(o) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"], env=genv(GUARD_NTP_SYNC=None))
    assert rc == 1 and "FAIL (k)" in out and "pre-flight failed" in out and not os.path.exists(o), out


def g23_clock_recheck_immediately_before_start():
    # stub timedatectl: `yes` for the pre-flight call, `no` from the second call on (the pre-start re-check)
    sd = os.path.join(WORK, "g23-bin")
    cnt = os.path.join(WORK, "g23-count")
    stub_exe(os.path.join(sd, "timedatectl"),
             f'n=$(cat {cnt} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {cnt}\n[ $n -le 1 ] && echo yes || echo no\n')
    o = gout("g23")
    a = gargs(o) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"]
    rc, out = guard("run", a, env=genv(GUARD_NTP_SYNC=None, PATH=sd + ":/usr/bin:/bin"))
    assert rc == 1, out
    assert open(cnt).read().strip() == "2", open(cnt).read()
    gl = open(os.path.join(o, "guard.log")).read()
    assert "preflight PASS (k)" in gl and "pre-start FAIL (k)" in gl and "Nothing was started" in gl, gl
    for f in ("probes.log", "results.tsv", "run-meta.json", "guard-meta.json", ".guard.lock", "stdout.log"):
        assert not os.path.exists(os.path.join(o, f)), f
    # the refusal leaves the directory usable for the next attempt (fresh run, no --resume needed)
    rc, out = guard("run", a)
    assert rc == 0 and len(rows(o)) == 10, out


def _runpy_pids(o):
    found = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                toks = [t.decode() for t in open(f"/proc/{d}/cmdline", "rb").read().split(b"\0") if t]
            except OSError:
                continue
            if any(t.endswith("/run.py") for t in toks) and o in toks:
                found.append(int(d))
    return found


def g24_watchdog_stops_when_clock_unsynchronized():
    t, s, r = _bigrun("nt")
    o = gout("nt")
    f = w(os.path.join(WORK, "g24-ntp"), "yes\n")
    p = subprocess.Popen([sys.executable, "-I", GUARD, "run", *gargs(o, targets=t, tsha=s), "--go", GO, "--grace-seconds", "5",
                          "--extra-run-args", f"--resolve-file {r}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         env=genv(GUARD_NTP_SYNC=f, GUARD_NTP_POLL_SECONDS="1"))
    deadline = time.time() + 30
    while len(plog(o)) < 20 and time.time() < deadline:
        time.sleep(0.1)
    pids = _runpy_pids(o)
    assert pids, "run.py not found"
    env = open(f"/proc/{pids[0]}/environ", "rb").read().split(b"\0")
    assert not any(x.startswith(b"GUARD_") for x in env), [x for x in env if x.startswith(b"GUARD_")]
    time.sleep(1.5)                                  # at least one poll that still sees `yes`
    assert p.poll() is None, p.communicate()[0]
    t_change = time.time()
    w(f, "no\n")
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 3, out
    stop = open(os.path.join(o, "STOP")).read()
    assert "check (k) failed" in stop and "NTPSynchronized='no'" in stop, stop
    last = max(float(x[0]) for x in plog(o))
    assert last <= t_change + 2.5, f"handshake started {last - t_change:.2f}s after the clock lost sync"
    assert "WATCHDOG: system clock no longer synchronized" in open(os.path.join(o, "guard.log")).read()
    assert json.load(open(os.path.join(o, "guard-meta.json")))["status"] == "stopped"
    assert wait_gone(o, 10)


def _dead_pid():
    q = subprocess.Popen(["true"])
    q.wait()
    return q.pid


def _resume_fixture(path, gm_over=None, rm_over=None, lock=True):
    os.makedirs(path)
    gm = {"date": GDATE, "targets_sha256": GSHA, "expected_egress": EGR, "expected_egress6": None, "families": "4",
          "www": "off", "mode": "pinned", "status": "running"}
    gm.update(gm_over or {})
    w(os.path.join(path, "guard-meta.json"), json.dumps(gm))
    rm = {"targets_file_sha256": GSHA, "families": "4", "www": "off", "mode": "pinned", "start_kind": "FRESH"}
    rm.update(rm_over or {})
    w(os.path.join(path, "run-meta.json"), json.dumps(rm) + "\n")
    w(os.path.join(path, "results.tsv"), "\t".join(["g05.test", "127.0.0.1", "1", "ok|ch=1|hrr=0|sh=1|grp=ecdh_x25519", "skip",
                                                    "skip", "0", "0", "", "skip", "4", "list", "5", "pinned"]) + "\n")
    w(os.path.join(path, "probes.log"), f"{time.time() - 60:.3f}\tg05.test\tp1\t127.0.0.1\t{P_CLS}\n")
    if lock:
        w(os.path.join(path, ".guard.lock"), f"{_dead_pid()} 0123abcd\n")
    return path


SMTP_G = ("--proto", "smtp", "--ehlo-name", "scan.example.test")
SMTP_META = {"proto": "smtp", "ehlo_name": "scan.example.test", "smtp_timeout": 30.0, "per_ip_cap": 8}


def g25_resume_refusals():
    n = [0]

    def fx(**kw):
        n[0] += 1
        return _resume_fixture(os.path.join(WORK, f"g25-{n[0]}", f"run-{GDATE}"), **kw)

    R = ("--resume",)
    o = fx()
    rc, out = chk(extra=R, out=o)                                      # the unchanged campaign may resume
    expect_fail_only(out, [], rc)
    assert "stale .guard.lock" in eline(out) and "RESUME: 1 rows and 1 handshakes" in eline(out), eline(out)
    rc, out = chk(out=o)                                               # without --resume: refused as before
    expect_fail_only(out, ["e"], rc)
    os.remove(os.path.join(o, ".guard.lock"))                          # no lock at all is fine too
    rc, out = chk(extra=R, out=o)
    expect_fail_only(out, [], rc)
    o = fx(gm_over=SMTP_META, rm_over=SMTP_META)                       # an smtp campaign resumes with the same settings
    rc, out = chk(extra=R + SMTP_G, out=o)
    expect_fail_only(out, [], rc)
    cases = [
        ("date in guard-meta", dict(o=fx(gm_over={"date": "2026-01-14"})), "date="),
        ("date not in the directory name", dict(o=_resume_fixture(os.path.join(WORK, "g25-nodate", "run"))), "does not contain"),
        ("targets hash", dict(o=fx(), targets=targets_file("g25-t2.txt", ["g01.test", "g02.test"]), tsha=None), "targets_sha256="),
        ("expected egress", dict(o=fx(), args=("--expected-egress", "140.116.1.3"), env=genv(GUARD_EGRESS="140.116.1.3")),
         "expected_egress="),
        ("families", dict(o=fx(), extra=("--families", "4,6", "--expected-egress6", "2001:288:1234::/48"),
                          env=genv(GUARD_EGRESS6="2001:288:1234::5")), "families="),
        ("www", dict(o=fx(), extra=("--www", "add")), "www="),
        ("mode", dict(o=fx(), extra=("--mode", "alladdr")), "mode="),
        ("run-meta families", dict(o=fx(rm_over={"families": "4,6"})), "run-meta.json line 1: families="),
        ("tz in guard-meta", dict(o=fx(gm_over={"tz": "America/New_York", "window": "02:00-08:00"})), "tz='America/New_York'"),
        ("tz of this run (meta from before the option: Asia/Taipei)",
         dict(o=fx(), extra=("--tz", "America/New_York", "--window", "02:00-08:00"), env=genv(GUARD_NOW=f"{GDATE}T03:00:00-05:00")),
         "tz='Asia/Taipei' differs from this run's 'America/New_York'"),
        ("window of this run", dict(o=fx(), extra=("--window", "02:00-07:00")), "window='02:00-08:00' differs"),
        ("run-meta window", dict(o=fx(rm_over={"window": "02:00-07:00"})), "run-meta.json line 1: window="),
        ("resolver of this run", dict(o=fx(), extra=("--resolver", "1.1.1.1")), "resolver='system' differs from this run's '1.1.1.1'"),
        ("resolver in guard-meta", dict(o=fx(gm_over={"resolver": "8.8.8.8"})), "guard-meta.json resolver='8.8.8.8'"),
        ("run-meta resolver", dict(o=fx(rm_over={"resolver": "8.8.8.8"})), "run-meta.json line 1: resolver='8.8.8.8'"),
        ("proto of this run", dict(o=fx(), extra=SMTP_G), "proto='https' differs from this run's 'smtp'"),
        ("proto in guard-meta", dict(o=fx(gm_over=SMTP_META, rm_over=SMTP_META)), "guard-meta.json proto='smtp'"),
        ("ehlo name", dict(o=fx(gm_over=SMTP_META, rm_over=SMTP_META), extra=SMTP_G[:3] + ("other.example.test",)),
         "ehlo_name='scan.example.test' differs"),
        ("per-ip cap", dict(o=fx(gm_over=SMTP_META, rm_over=SMTP_META), extra=SMTP_G + ("--per-ip-cap", "4")),
         "per_ip_cap=8 differs from this run's 4"),
        ("smtp timeout in run-meta", dict(o=fx(gm_over=SMTP_META, rm_over=dict(SMTP_META, smtp_timeout=45.0)), extra=SMTP_G),
         "run-meta.json line 1: smtp_timeout=45.0"),
        ("finished run", dict(o=fx(gm_over={"status": "finished"})), "finished cleanly"),
        ("stopped run without STOP", dict(o=fx(gm_over={"status": "stopped"})), "status='stopped'"),
        ("incomplete run without STOP", dict(o=fx(gm_over={"status": "incomplete"})), "status='incomplete'"),
        ("unknown status", dict(o=fx(gm_over={"status": None})), "status=None"),
        ("no guard-meta", dict(o=fx(), rm=["guard-meta.json"]), "no guard-meta.json"),
        ("STOP", dict(o=fx(), add={"STOP": "manual\n"}), "STOP file exists"),
        ("missing directory", dict(o=os.path.join(WORK, "g25-none", f"run-{GDATE}")), "does not exist"),
    ]
    for label, c, frag in cases:
        oo = c["o"]
        for f in c.get("rm", []):
            os.remove(os.path.join(oo, f))
        for f, txt in c.get("add", {}).items():
            w(os.path.join(oo, f), txt)
        tg = c.get("targets")
        a = gargs(oo, targets=tg, tsha=sha(tg) if tg else None, extra=tuple(c.get("extra", ())) + R)
        if "args" in c:
            a[a.index(c["args"][0]) + 1] = c["args"][1]
        rc, out = guard("check", a, env=c.get("env"))
        expect_fail_only(out, ["e"], rc)
        assert frag in eline(out), (label, eline(out))
    # live lock (1): a process holds the flock, as every running guard does
    o = fx()
    lk = os.path.join(o, ".guard.lock")
    holder = subprocess.Popen([sys.executable, "-c", "import fcntl,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR)\n"
                               "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('locked',flush=True)\ntime.sleep(60)", lk], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        rc, out = chk(extra=R, out=o)
        expect_fail_only(out, ["e"], rc)
        assert "held (flock)" in eline(out), eline(out)
        before = open(os.path.join(o, "probes.log")).read()
        rc, out = guard("run", gargs(o, extra=R) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"])
        assert rc == 1 and "REFUSED" in out and open(os.path.join(o, "probes.log")).read() == before, out
    finally:
        holder.kill()
        holder.wait()
    # live lock (2): the pid in the lock is a live `guard.py run` (no flock, e.g. a guard from before this change)
    o = fx()
    fake = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "/x/guard.py", "run"])
    try:
        time.sleep(0.3)
        w(os.path.join(o, ".guard.lock"), f"{fake.pid} 0123abcd\n")
        rc, out = chk(extra=R, out=o)
        expect_fail_only(out, ["e"], rc)
        assert f"pid {fake.pid}, a live guard.py run" in eline(out), eline(out)
    finally:
        fake.kill()
        fake.wait()
    # a pid that is alive but is not a guard (pid reused after a reboot): stale, resume allowed
    o = fx()
    w(os.path.join(o, ".guard.lock"), f"{os.getpid()} 0123abcd\n")
    rc, out = chk(extra=R, out=o)
    expect_fail_only(out, [], rc)
    assert "pid reused" in eline(out), eline(out)
    # `run --resume` on a refused directory changes nothing
    o = fx(gm_over={"date": "2026-01-14"})
    before = {f: open(os.path.join(o, f)).read() for f in ("probes.log", "results.tsv", "guard-meta.json", "run-meta.json")}
    rc, out = guard("run", gargs(o, extra=R) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"])
    assert rc == 1 and "pre-flight failed" in out, out
    assert {f: open(os.path.join(o, f)).read() for f in before} == before and not os.path.exists(os.path.join(o, "guard.log"))


def _kill_mentioning(o):
    for d in os.listdir("/proc"):
        if d.isdigit() and int(d) != os.getpid():
            try:
                cl = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
            except OSError:
                continue
            if o in cl:
                try:
                    os.kill(int(d), signal.SIGKILL)
                except ProcessLookupError:
                    pass


def _resume_scenario(tag, kill_guard):
    names = [f"{tag}{i:03d}.test" for i in range(120)]
    hyb = {n for i, n in enumerate(names) if i % 3}
    t = targets_file(f"g-{tag}.txt", names)
    s = sha(t)
    r = resolve_file(f"g-{tag}.tsv", {n: f"127.0.0.1:{P_HYB if n in hyb else P_CLS}" for n in names})
    o = gout(tag)
    a = gargs(o, targets=t, tsha=s) + ["--go", GO, "--grace-seconds", "5", "--extra-run-args", f"--resolve-file {r}"]
    p = subprocess.Popen([sys.executable, "-I", GUARD, "run", *a], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=genv())
    deadline = time.time() + 30
    while len(plog(o)) < 60 and time.time() < deadline:
        time.sleep(0.05)
    if kill_guard:                                  # like a crash or power cut: the guard and everything it started die
        p.kill()
        _kill_mentioning(o)
        p.communicate(timeout=10)
    else:                                           # only run.py dies; the guard notices and exits 4
        for pid in _runpy_pids(o):
            os.kill(pid, signal.SIGKILL)
        out1, _ = p.communicate(timeout=60)
        assert p.returncode == 4 and "RESULT: run.py failed" in out1, out1
    assert wait_gone(o, 10), procs_mentioning(o)
    rows1, pl1 = rows(o), plog(o)
    rowed = {r[0] for r in rows1}
    started = {x[1] for x in pl1}
    in_flight = started - rowed
    assert 0 < len(rows1) < 120 and in_flight, (len(rows1), in_flight)
    gm1 = json.load(open(os.path.join(o, "guard-meta.json")))
    assert gm1["status"] == ("running" if kill_guard else "failed"), gm1
    assert not os.path.exists(os.path.join(o, "STOP"))
    rc, out = guard("check", gargs(o, targets=t, tsha=s))                       # without --resume: refused
    expect_fail_only(out, ["e"], rc)
    rc, out = guard("check", gargs(o, targets=t, tsha=s, extra=("--resume",)))
    expect_fail_only(out, [], rc)
    assert "stale .guard.lock" in eline(out), eline(out)
    rc, out = guard("run", a + ["--resume"], timeout=180)
    assert rc == 0, out
    rs = rows(o)
    assert sorted(x[0] for x in rs) == sorted(names), (len(rs), len({x[0] for x in rs}))         # no duplicate, none missing
    by_ip, by_fam, by_name = _counts(plog(o))
    assert max(by_ip.values()) <= 4 and max(by_name.values()) <= 4, (by_ip, by_name)
    for nme in names:
        if nme not in started:                                                  # untouched in part 1: full probe set once
            assert by_name[nme] == (4 if nme in hyb else 1), (nme, by_name[nme])
    gl = open(os.path.join(o, "guard.log")).read()
    assert f"RESUME: {len(rows1)} rows and {len(pl1)} handshakes already present" in gl, gl[-2000:]
    metas = [json.loads(l) for l in open(os.path.join(o, "run-meta.json"))]
    assert metas[-1]["start_kind"] == "RESUME" and metas[-1]["rows_already_present"] == len(rows1), metas[-1]
    assert metas[-1]["handshakes_already_present"] == len(pl1) and "--resume" in metas[-1]["argv"], metas[-1]
    gm = json.load(open(os.path.join(o, "guard-meta.json")))
    assert gm["status"] == "finished" and gm["resume"] is True and gm["rows_before"] == len(rows1), gm
    assert gm["handshakes_before"] == len(pl1) and len(gm["parts"]) == 1 and gm["parts"][0]["status"] == gm1["status"], gm
    assert gm["max_per_second"] <= 18 and gm["handshakes"] == len(plog(o)), gm
    rc, out = guard("check", gargs(o, targets=t, tsha=s, extra=("--resume",)))   # a finished run is not resumed again
    expect_fail_only(out, ["e"], rc)
    print(f"       part 1: {len(rows1)} rows, {len(pl1)} handshakes, {len(in_flight)} names in flight at the kill; "
          f"after resume: {len(rs)} rows, {len(plog(o))} handshakes, max per (name, address) {max(by_ip.values())}", flush=True)


def g26_resume_after_guard_and_runpy_killed():
    _resume_scenario("kr", kill_guard=True)


def g27_resume_after_runpy_killed():
    _resume_scenario("kp", kill_guard=False)


def g28_sigterm_when_runpy_chain_already_ended():
    # shutdown: SIGTERM reaches the guard and the run.py chain together, and the chain dies at once (systemd-inhibit has
    # no handler). STOP must exist anyway, guard-meta says "stopped", and --resume refuses the directory.
    t, s, r = _bigrun("sd")
    o = gout("sd")
    a = gargs(o, targets=t, tsha=s) + ["--go", GO, "--grace-seconds", "5", "--extra-run-args", f"--resolve-file {r}"]
    p = subprocess.Popen([sys.executable, "-I", GUARD, "run", *a], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, env=genv())
    deadline = time.time() + 30
    while len(plog(o)) < 20 and time.time() < deadline:
        time.sleep(0.1)
    pids = _runpy_pids(o)
    assert pids, "run.py not found"
    p.send_signal(signal.SIGTERM)                   # guard: handler sets the flag, its 0.25 s sleep goes on
    for pid in pids:
        os.kill(pid, signal.SIGKILL)                # chain gone before the guard's next poll
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 3, out
    assert "SIGTERM" in open(os.path.join(o, "STOP")).read()
    gl = open(os.path.join(o, "guard.log")).read()
    path = "after the loop" if "run.py ended with it); created" in gl else "inside the loop"
    assert "WATCHDOG: guard received SIGTERM" in gl and "created" in gl, gl[-1500:]
    assert json.load(open(os.path.join(o, "guard-meta.json")))["status"] == "stopped"
    assert wait_gone(o, 10), procs_mentioning(o)
    rc, out = guard("check", gargs(o, targets=t, tsha=s, extra=("--resume",)))
    expect_fail_only(out, ["e"], rc)
    assert "STOP file exists" in eline(out) and "status='stopped'" in eline(out), eline(out)
    print(f"       STOP written {path} (the case this test is for: after the loop)", flush=True)


# ------------------------------------------------------------------------------------------------- 5b. vantage time zone
NY = ("--tz", "America/New_York", "--window", "01:00-06:00")


def aline(out):
    return [l for l in out.splitlines() if l.startswith(("PASS (a)", "FAIL (a)"))][0]


def g29_tz_and_window_options():
    # defaults: the same text as before the option existed
    rc, out = chk()
    expect_fail_only(out, [], rc)
    assert "Asia/Taipei now 2026-01-15 03:00:" in aline(out) and "window 02:00-08:00" in aline(out), aline(out)
    assert "NOTE" not in out, out
    # refusals (usage, exit 2, nothing checked)
    for extra, frag in ((("--tz", "America/New_York"), "--tz needs an explicit --window"),
                        (("--tz", "Mars/Olympus_Mons", "--window", "01:00-06:00"), "IANA time zone"),
                        (("--tz", "../../etc/passwd", "--window", "01:00-06:00"), "IANA time zone"),
                        (("--tz", "/etc/localtime", "--window", "01:00-06:00"), "IANA time zone"),
                        (("--window", "22:00-04:00"), "no window across midnight"),
                        (("--window", "03:00-03:00"), "start must be before the end"),
                        (("--window", "3:00-6:00"), "HH:MM-HH:MM"),
                        (("--window", "02:00-24:00"), "HH:MM-HH:MM"),
                        (("--tz", "America/New_York", "--window", "05:00-01:00"), "no window across midnight")):
        rc, out = chk(extra=extra)
        assert rc == 2 and frag in out and "PASS (" not in out, (extra, out)
    # another zone: local time and local date decide; GUARD_NOW carries its own offset
    for now, ok in (("2026-01-15T00:59:59-05:00", False), ("2026-01-15T01:00:00-05:00", True),
                    ("2026-01-15T05:59:30-05:00", True), ("2026-01-15T06:00:00-05:00", False),
                    (IN_WIN, False)):                                   # 03:00 Taipei = 14:00 on 2026-01-14 in New York
        rc, out = chk(extra=NY, env=genv(GUARD_NOW=now))
        expect_fail_only(out, [] if ok else ["a"], rc)
        assert "America/New_York now" in aline(out) and "window 01:00-06:00" in aline(out), aline(out)
    assert "America/New_York date is 2026-01-14, not --date 2026-01-15" in aline(out), aline(out)
    assert "NOTE: vantage time zone America/New_York, window 01:00-06:00 local time" in out and "OVERRIDE" not in out, out
    # the local date counts, not Taipei's: 21:00 in New York on GDATE is already 2026-01-16 in Taipei
    rc, out = chk(extra=("--tz", "America/New_York", "--window", "20:00-23:30"), env=genv(GUARD_NOW=f"{GDATE}T21:00:00-05:00"))
    expect_fail_only(out, [], rc)
    # a daylight-saving transition day is refused (wall-clock window); Asia/Taipei has none
    d = "2026-03-08"                                                    # US clocks go forward at 02:00
    a = gargs(os.path.join(WORK, "g29-dst", f"run-{d}"), extra=NY)
    a[a.index("--date") + 1] = d
    a[a.index("--allowed-dates") + 1] = d
    rc, out = guard("check", a, env=genv(GUARD_NOW=f"{d}T04:00:00-04:00"))
    expect_fail_only(out, ["a"], rc)
    assert "daylight-saving transition" in aline(out), aline(out)
    # (j) uses the end of this window: a plan of about 6 min does not fit at 03:59:30 in a window ending 04:00 ...
    t, s_, _ = _bigrun("tzpl", 3000)
    a = gargs(gout("tzpl"), targets=t, tsha=s_, extra=("--tz", "America/New_York", "--window", "01:00-04:00"))
    rc, out = guard("check", a, env=genv(GUARD_NOW=f"{GDATE}T03:59:30-05:00"))
    j = [l for l in out.splitlines() if "(j)" in l][0]
    assert j.startswith("PASS") and "WARN: does not fit in 0 min (window left 0" in j, j
    # ... and fits in a window ending at 23:00 (only --max-minutes 30 limits it)
    a = gargs(gout("tzpl"), targets=t, tsha=s_, extra=("--tz", "America/New_York", "--window", "01:00-23:00"))
    rc, out = guard("check", a, env=genv(GUARD_NOW=f"{GDATE}T03:59:30-05:00"))
    j = [l for l in out.splitlines() if "(j)" in l][0]
    assert j.startswith("PASS") and "WARN" not in j, j
    # egress at another vantage: an exact --expected-egress with its own prefix is a NOTE, not an OVERRIDE
    us = ("--egress-prefix", "128.210.")
    a = gargs(gout("eg"), extra=us)
    a[a.index("--expected-egress") + 1] = "128.210.1.2"
    rc, out = guard("check", a, env=genv(GUARD_EGRESS="128.210.1.2"))
    expect_fail_only(out, [], rc)
    assert "OVERRIDE" not in out and "NOTE: egress prefix 128.210." in out and "equal --expected-egress 128.210.1.2" in out, out
    rc, out = guard("check", a, env=genv(GUARD_EGRESS="128.210.9.9"))           # the exact rule still applies
    expect_fail_only(out, ["b"], rc)
    rc, out = guard("check", a + ["--allow-unannounced-egress"], env=genv(GUARD_EGRESS="128.210.9.9"))
    expect_fail_only(out, [], rc)
    assert "OVERRIDE in use: --egress-prefix, --allow-unannounced-egress" in out, out
    rc, out = guard("check", a, env=genv(GUARD_EGRESS="140.116.1.2"))           # wrong network
    expect_fail_only(out, ["b"], rc)
    b = list(a)
    b[b.index("--expected-egress") + 1] = EGR                                       # announced address outside the prefix
    rc, out = guard("check", b, env=genv(GUARD_EGRESS=EGR))
    assert rc == 2 and "does not start with --egress-prefix" in out, out


def g30_watchdog_at_window_end_in_other_zone():
    t, s, r = _bigrun("wz")
    o = gout("wz")
    t0 = time.time()
    rc, out = guard("run", gargs(o, targets=t, tsha=s, extra=NY) + ["--go", GO, "--grace-seconds", "5", "--extra-run-args",
                    f"--resolve-file {r}"], env=genv(GUARD_NOW=f"{GDATE}T05:59:56-05:00"))
    assert rc == 3, out
    stop = open(os.path.join(o, "STOP")).read()
    assert "America/New_York clock reached 2026-01-15 06:00" in stop and "outside 01:00-06:00 of 2026-01-15" in stop, stop
    assert time.time() - t0 < 20 and 30 <= len(plog(o)) <= 6 * 18 + 19, len(plog(o))
    gl = open(os.path.join(o, "guard.log")).read()
    assert "[local America/New_York 2026-01-15 05:59:" in gl and "watchdog stops at 06:00 America/New_York" in gl, gl[:1500]
    gm = json.load(open(os.path.join(o, "guard-meta.json")))
    assert gm["tz"] == "America/New_York" and gm["window"] == "01:00-06:00" and gm["status"] == "stopped", gm
    assert gm["local_start"].startswith("2026-01-15T05:59:5") and gm["local_start"].endswith("-05:00"), gm
    assert gm["taipei_start"].startswith("2026-01-15T18:59:5") and gm["taipei_start"].endswith("+08:00"), gm
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    assert meta["tz"] == "America/New_York" and meta["window"] == "01:00-06:00" and "America/New_York" in meta["vantage"], meta
    assert wait_gone(o, 10)


def g31_resolver_option():
    rc, out = chk(extra=("--resolver", "1.1.1.1"))
    expect_fail_only(out, [], rc)
    assert "NOTE: names are resolved by kit-c's DNS client at 1.1.1.1" in out and "OVERRIDE" not in out, out
    for bad in ("dns.google", "2606:4700:4700::1111", "1.1.1.1:53"):
        rc, out = chk(extra=("--resolver", bad))
        assert rc == 2 and "--resolver must be" in out, (bad, out)
    o = gout("rsv")
    rc, out = guard("run", gargs(o, extra=("--resolver", FDNS_IP)) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"])
    assert rc == 0, out
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    a = meta["argv"]
    assert a[a.index("--resolver") + 1] == FDNS_IP and meta["resolver"] == FDNS_IP, meta
    assert f"resolver {FDNS_IP} (kit-c dnsclient.py, RD=1)" in meta["vantage"], meta["vantage"]
    gm = json.load(open(os.path.join(o, "guard-meta.json")))
    assert gm["resolver"] == FDNS_IP and gm["status"] == "finished", gm
    # the default passes --resolver system and records it
    o = gout("rsv-sys")
    rc, out = guard("run", gargs(o) + ["--go", GO, "--extra-run-args", f"--resolve-file {GR}"])
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    assert rc == 0 and meta["resolver"] == "system" and json.load(open(os.path.join(o, "guard-meta.json")))["resolver"] == "system"


def g32_smtp_mode_in_guard():
    for extra, frag in (((("--proto", "smtp")), "needs --ehlo-name"), (SMTP_G[:3] + ("Scan.Example.Test",), "needs --ehlo-name"),
                        (SMTP_G[:3] + ("scan_x.example.test",), "needs --ehlo-name"),
                        (SMTP_G + ("--www", "add"), "MX host names only"), (SMTP_G + ("--mode", "alladdr"), "MX host names only"),
                        (SMTP_G + ("--per-ip-cap", "9"), "may only lower"), (SMTP_G + ("--per-ip-cap", "0"), "may only lower"),
                        (SMTP_G + ("--smtp-timeout", "90"), "--smtp-timeout"), (("--per-ip-cap", "4"), "for --proto smtp only"),
                        (("--ehlo-name", "scan.example.test"), "for --proto smtp only")):
        rc, out = chk(extra=extra)
        assert rc == 2 and frag in out, (extra, out)
    rc, out = chk(extra=SMTP_G)
    expect_fail_only(out, [], rc)
    assert "s_client -starttls and -name: True" in [l for l in out.splitlines() if l.startswith("PASS (f)")][0], out
    assert "NOTE: SMTP STARTTLS mode: port 25, EHLO scan.example.test, timeout 30 s per exchange, at most 8 handshakes per " \
           "address and 4 per MX host name" in out, out
    # an OpenSSL whose s_client lacks -starttls fails (f) in smtp mode only
    fake = w(os.path.join(WORK, "g32-openssl"), f'#!/bin/sh\n[ "$1" = s_client ] && {{ echo " -connect val"; exit 0; }}\nexec {OPENSSL} "$@"\n')
    os.chmod(fake, 0o755)
    rc, out = chk(extra=SMTP_G, env=genv(OPENSSL=fake))
    expect_fail_only(out, ["f"], rc)
    rc, out = chk(env=genv(OPENSSL=fake))
    expect_fail_only(out, [], rc)
    # a test-mode run: every g name points at the SMTP front end on 127.0.0.1; the per-IP cap (8) stops after 8 handshakes
    rf = resolve_file("g32.tsv", {f"g{i:02d}.test": f"127.0.0.1:{S_HYB}" for i in range(1, 11)})
    o = gout("smtp")
    rc, out = guard("run", gargs(o, extra=SMTP_G) + ["--go", GO, "--extra-run-args", f"--resolve-file {rf}"])
    assert rc == 0, out
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    a = meta["argv"]

    def val(flag):
        return a[a.index(flag) + 1]
    for flag, v in (("--proto", "smtp"), ("--ehlo-name", "scan.example.test"), ("--smtp-timeout", "30"), ("--per-ip-cap", "8"),
                    ("--max-per-name", "4"), ("--rate", "18"), ("--cap", "4"), ("--www", "off"), ("--mode", "pinned")):
        assert val(flag) == v, (flag, a)
    assert (meta["proto"], meta["port"], meta["ehlo_name"], meta["per_ip_cap"]) == ("smtp", 25, "scan.example.test", 8), meta
    assert "SMTP STARTTLS port 25, EHLO scan.example.test" in meta["vantage"], meta["vantage"]
    assert len(plog(o)) == 8 and len(rows(o)) == 10 and {p[4] for p in plog(o)} == {str(S_HYB)}, (len(plog(o)), len(rows(o)))
    gm = json.load(open(os.path.join(o, "guard-meta.json")))
    assert {k: gm[k] for k in SMTP_META} == SMTP_META and gm["status"] == "finished", gm


QUIC_G = ("--proto", "quic")
QUIC_META = {"proto": "quic", "quic_timeout": 8.0}


def g33_quic_mode_in_guard():
    for extra, frag in ((QUIC_G + ("--www", "add"), "listed names only"), (QUIC_G + ("--mode", "alladdr"), "listed names only"),
                        (QUIC_G + ("--quic-timeout", "4"), "--quic-timeout must be"), (QUIC_G + ("--quic-timeout", "13"), "--quic-timeout must be"),
                        (QUIC_G + ("--quic-timeout", "8.5"), "--quic-timeout must be"), (("--quic-timeout", "8"), "for --proto quic only"),
                        (SMTP_G + ("--quic-timeout", "8"), "for --proto quic only"), (QUIC_G + ("--per-ip-cap", "4"), "for --proto smtp only"),
                        (QUIC_G + ("--ehlo-name", "scan.example.test"), "for --proto smtp only")):
        rc, out = chk(extra=extra)
        assert rc == 2 and frag in out and "PASS (" not in out, (extra, out)
    rc, out = chk(extra=QUIC_G)
    expect_fail_only(out, [], rc)
    f = [l for l in out.splitlines() if l.startswith("PASS (f)")][0]
    assert "s_client -quic and -alpn: True; stdbuf: " in f and "NOT FOUND" not in f, f
    assert "NOTE: QUIC mode: UDP port 443, ALPN h3, timeout 8 s per probe, at most 4 handshakes per name; no per-address cap" in out, out
    # (f) fails in quic mode only: an s_client without -quic, or no stdbuf on PATH
    fake = w(os.path.join(WORK, "g33-openssl"), f'#!/bin/sh\n[ "$1" = s_client ] && {{ echo " -alpn val"; exit 0; }}\nexec {OPENSSL} "$@"\n')
    os.chmod(fake, 0o755)
    rc, out = chk(extra=QUIC_G, env=genv(OPENSSL=fake))
    expect_fail_only(out, ["f"], rc)
    rc, out = chk(env=genv(OPENSSL=fake))
    expect_fail_only(out, [], rc)
    os.makedirs(os.path.join(WORK, "g33-emptybin"), exist_ok=True)
    rc, out = chk(extra=QUIC_G, env=genv(PATH=os.path.join(WORK, "g33-emptybin")))
    expect_fail_only(out, ["f"], rc)
    assert "stdbuf: NOT FOUND" in out, out
    # a test-mode run: every g name points at the colon-list QUIC server; P1 on the hybrid, then P2/P3/PA (4 per name)
    rf = resolve_file("g33.tsv", {f"g{i:02d}.test": f"127.0.0.1:{Q_SCOL}" for i in range(1, 11)})
    o = gout("quic")
    rc, out = guard("run", gargs(o, extra=QUIC_G) + ["--go", GO, "--extra-run-args", f"--resolve-file {rf}"])
    assert rc == 0, out
    meta = json.loads(open(os.path.join(o, "run-meta.json")).readline())
    a = meta["argv"]

    def val(flag):
        return a[a.index(flag) + 1]
    for flag, v in (("--proto", "quic"), ("--quic-timeout", "8"), ("--max-per-name", "4"), ("--rate", "18"), ("--cap", "4"),
                    ("--www", "off"), ("--mode", "pinned")):
        assert val(flag) == v, (flag, a)
    assert "--per-ip-cap" not in a and "--ehlo-name" not in a, a
    assert (meta["proto"], meta["port"], meta["quic_timeout"], meta["per_ip_cap"]) == ("quic", 443, 8.0, 0), meta
    assert "QUIC UDP port 443, ALPN h3" in meta["vantage"], meta["vantage"]
    assert len(plog(o)) == 40 and len(rows(o)) == 10 and {p[4] for p in plog(o)} == {str(Q_SCOL)}, (len(plog(o)), len(rows(o)))
    assert all(r[4].endswith("grp=ecdh_x25519") and r[4].startswith("ok|") for r in rows(o)), rows(o)
    gm = json.load(open(os.path.join(o, "guard-meta.json")))
    assert {k: gm[k] for k in QUIC_META} == QUIC_META and gm["status"] == "finished" and gm["max_per_second"] <= 18, gm
    # resume: same quic settings only
    n = [0]

    def fx(**kw):
        n[0] += 1
        return _resume_fixture(os.path.join(WORK, f"g33-{n[0]}", f"run-{GDATE}"), **kw)
    rc, out = chk(extra=("--resume",) + QUIC_G, out=fx(gm_over=QUIC_META, rm_over=QUIC_META))
    expect_fail_only(out, [], rc)
    for label, kw, extra, frag in (
            ("timeout of this run", dict(gm_over=QUIC_META, rm_over=QUIC_META), QUIC_G + ("--quic-timeout", "10"),
             "quic_timeout=8.0 differs from this run's 10.0"),
            ("https run resumed as quic", {}, QUIC_G, "proto='https' differs from this run's 'quic'"),
            ("quic run resumed as https", dict(gm_over=QUIC_META, rm_over=QUIC_META), (), "guard-meta.json proto='quic'"),
            ("run-meta timeout", dict(gm_over=QUIC_META, rm_over=dict(QUIC_META, quic_timeout=5.0)), QUIC_G,
             "run-meta.json line 1: quic_timeout=5.0")):
        rc, out = chk(extra=("--resume",) + extra, out=fx(**kw))
        expect_fail_only(out, ["e"], rc)
        assert frag in eline(out), (label, eline(out))


# ------------------------------------------------------------------------------------------------- 6. cron launcher
LAUNCH = os.path.join(KIT, "launch", "launch-cron.sh")
BEGIN, END = "# ---- BEGIN SETTINGS", "# ---- END SETTINGS"


def l01_launcher_decisions():
    base = os.path.join(WORK, "l01")
    bin_, kit, runs = (os.path.join(base, x) for x in ("bin", "kit", "runs"))
    for d in (bin_, kit, runs):
        os.makedirs(d)
    calls = os.path.join(base, "calls.log")
    D = os.path.join(runs, f"c1-{GDATE}")
    w(os.path.join(bin_, "date"), f'#!/bin/bash\nexec /usr/bin/date -d "$(cat {base}/now)" "$@"\n')
    w(os.path.join(bin_, "timedatectl"), f'#!/bin/bash\necho "timedatectl $*" >> {calls}\ncat {base}/ntp\n')
    w(os.path.join(bin_, "lab"), f'#!/bin/bash\necho "lab $*" | sed "s/ *$//" >> {calls}\ncase "${{1:-}}" in\n'
      f'  check) exit $(cat {base}/labrc) ;;\n  add) echo 42 ;;\n  done) ;;\n  "") echo "BOARD: exclusive -x by another job" ;;\nesac\n')
    for x in ("date", "timedatectl", "lab"):
        os.chmod(os.path.join(bin_, x), 0o755)
    w(os.path.join(kit, "guard.py"), f'''import json, os, sys
a = sys.argv[1:]
mode = open({base!r} + "/guardmode").read().strip()
out = a[a.index("--out") + 1]
rec = {{"args": a, "env": sorted(k for k in os.environ if k.startswith("GUARD_") or k == "KITC_GUARD_NONCE"),
       "openssl": os.environ.get("OPENSSL"), "cwd": os.getcwd()}}
open({calls!r}, "a").write("guard " + json.dumps(rec) + "\\n")
os.makedirs(out, exist_ok=True)
open(out + "/probes.log", "a").write("x\\n")
res = {{"finish": "run finished cleanly. Next: ...", "stopped": "stopped by the watchdog; the run is truncated (exit 3)"}}.get(mode)
if res:
    open(out + "/guard.log", "a").write("2026-01-14T19:00:00Z [taipei x] RESULT: " + res + "\\n")
sys.exit({{"finish": 0, "stopped": 3, "zero-no-result": 0}}[mode])
''')
    src = open(LAUNCH).read()
    head, rest = src.split(BEGIN, 1)
    _, tail = rest.split(END, 1)

    def script(go=GO):
        settings = (f'{BEGIN} (test copy)\nPATH={bin_}:/usr/bin:/bin\nKIT={kit}\nBASE={runs}\nOUT_PREFIX=c1-\nTARGETS={GT}\n'
                    f'TARGETS_SHA256={GSHA}\nEXPECTED_EGRESS={EGR}\nEGRESS_PREFIX=140.116.\nVANTAGE_LABEL="test vantage"\nALLOWED_DATES={GDATE}\n'
                    f'SCAN_TZ=Asia/Taipei\nSCAN_WINDOW=02:00-08:00\nGO_PHRASES="{go}"\nFAMILIES=4\nWWW=add\nMODE=pinned\nRESOLVER=system\nPROTO=https\nEHLO_NAME=""\nMAX_MINUTES=360\nPYTHON={sys.executable}\n'
                    f'OPENSSL_BIN={OPENSSL}\nOPENSSL_CONF_FILE=/dev/null\nLAB_UNTIL=08:00\nLAB_DESC="scan test"\n')
        p = w(os.path.join(base, f"launch-{len(go)}.sh"), head + settings + END + tail)
        assert open(p).read().split(END, 1)[1] == tail and open(p).read().split(BEGIN, 1)[0] == head   # logic unchanged
        return p
    sc = script()
    logf = os.path.join(runs, f"launch-{GDATE}.log")

    def launch(now, labrc=0, ntp="yes", gmode="finish", env_extra=None, sc_=None):
        for k, v in (("now", now), ("labrc", str(labrc)), ("ntp", ntp), ("guardmode", gmode)):
            w(os.path.join(base, k), v + "\n")
        w(calls, "")
        n0 = os.path.getsize(logf) if os.path.exists(logf) else 0
        e = {k: v for k, v in os.environ.items() if not k.startswith("GUARD_")}
        e.update(env_extra or {})
        p = subprocess.run(["bash", sc_ or sc, GDATE], capture_output=True, text=True, env=e, timeout=60)
        new = open(logf).read()[n0:] if os.path.exists(logf) else ""
        return p.returncode, open(calls).read().splitlines(), new

    def T(hm, day=GDATE):
        return f"{day}T{hm}:00+08:00"
    guards = lambda c: [json.loads(x[6:]) for x in c if x.startswith("guard ")]
    # time of day: never start or resume at or after 07:00 (or before 02:00)
    for hm in ("07:00", "07:30", "01:59"):
        rc, c, lg = launch(T(hm))
        assert rc == 0 and c == [] and "EXIT: local time (Asia/Taipei)" in lg, (hm, c, lg)
    rc, c, lg = launch(T("03:00", "2026-01-16"))
    assert c == [] and "not 2026-01-15" in lg, lg
    # clock not synchronized: logged, nothing else
    rc, c, lg = launch(T("02:05"), ntp="no")
    assert c == ["timedatectl show -p NTPSynchronized --value"] and "clock not NTP-synchronized" in lg, (c, lg)
    # lab busy (exit 1): log the board and exit; next tick retries; other lab failures also stop
    rc, c, lg = launch(T("02:15"), labrc=1)
    assert [x for x in c if x.startswith(("lab", "guard"))] == ["lab check", "lab"] and "lab check exit 1" in lg and "BOARD" in lg, (c, lg)
    rc, c, lg = launch(T("02:15"), labrc=3)
    assert not guards(c) and "lab add" not in " ".join(c) and "lab check failed with exit 3" in lg, (c, lg)
    # not approved for this night
    rc, c, lg = launch(T("02:05"), sc_=script(go=""))
    assert c == [] and "not in GO_PHRASES" in lg, lg
    # fresh start at 02:05 with inherited GUARD_* variables: they are removed; lab registered and released; DONE written
    rc, c, lg = launch(T("02:05"), env_extra={"GUARD_NOW": IN_WIN, "GUARD_NTP_SYNC": "yes", "KITC_GUARD_NONCE": "x"})
    g = guards(c)
    assert rc == 0 and len(g) == 1 and g[0]["env"] == [] and "--resume" not in g[0]["args"], (c, lg)
    a = g[0]["args"]
    for flag, v in (("--date", GDATE), ("--allowed-dates", GDATE), ("--out", D), ("--go", GO), ("--www", "add"),
                    ("--targets-sha256", GSHA), ("--expected-egress", EGR), ("--families", "4"), ("--mode", "pinned"),
                    ("--tz", "Asia/Taipei"), ("--window", "02:00-08:00"), ("--resolver", "system"), ("--proto", "https"),
                    ("--egress-prefix", "140.116.")):
        assert a[a.index(flag) + 1] == v, (flag, a)
    assert a[0] == "run" and g[0]["openssl"] == OPENSSL and g[0]["cwd"] == kit and "--ehlo-name" not in a, g
    lab = [x for x in c if x.startswith("lab")]
    assert lab[0] == "lab check" and lab[1].startswith("lab add -u 08:00 -p ") and lab[1].endswith(" scan test"), lab
    assert lab[-1] == "lab done 42", lab
    assert "removed inherited" in lg and "GUARD_NOW" in lg and "starting guard.py run (fresh)" in lg and "DONE: wrote" in lg, lg
    assert os.path.exists(os.path.join(D, "DONE"))
    # finished: nothing else happens
    rc, c, lg = launch(T("02:15"))
    assert c == [] and "EXIT: run finished" in lg, (c, lg)
    # unfinished run (files present, no DONE): resume; exit 3 (watchdog) writes no DONE
    os.remove(os.path.join(D, "DONE"))
    rc, c, lg = launch(T("03:25"), gmode="stopped")
    g = guards(c)
    assert len(g) == 1 and g[0]["args"][-1] == "--resume" and "(resume)" in lg and "exited 3" in lg, (c, lg)
    assert not os.path.exists(os.path.join(D, "DONE"))
    rc, c, lg = launch(T("03:35"), gmode="zero-no-result")              # exit 0 without the RESULT line: no DONE
    assert len(guards(c)) == 1 and not os.path.exists(os.path.join(D, "DONE")), lg
    # an unfinished run is not resumed at or after 07:00
    rc, c, lg = launch(T("07:05"))
    assert c == [] and "not starting or resuming" in lg, lg
    # alive: a guard.py or run.py process for DIR
    for prog in ("/x/kit/guard.py", "/x/kit/run.py"):
        q = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", prog, "run", "--out", D, "--x"])
        try:
            time.sleep(0.3)
            rc, c, lg = launch(T("04:05"))
            assert c == [] and f"alive: {q.pid}" in lg, (prog, lg)
        finally:
            q.kill()
            q.wait()
    # another launcher instance holds the launcher lock (e.g. the one running the guard)
    q = subprocess.Popen([sys.executable, "-c", "import fcntl,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT)\n"
                          "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('locked',flush=True)\ntime.sleep(60)",
                          os.path.join(runs, f".launch-{GDATE}.lock")], stdout=subprocess.PIPE, text=True)
    try:
        assert q.stdout.readline().strip() == "locked"
        rc, c, lg = launch(T("04:15"))
        assert c == [] and "another launcher" in lg, lg
    finally:
        q.kill()
        q.wait()
    # STOP needs a person
    w(os.path.join(D, "STOP"), "guard watchdog: test\n")
    rc, c, lg = launch(T("04:25"))
    assert c == [] and "STOP exists" in lg and os.path.exists(os.path.join(D, "STOP")), lg
    # the shipped template refuses to run until its settings are filled in
    p = subprocess.run(["bash", LAUNCH, GDATE], capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "not filled in" in p.stderr, (p.returncode, p.stderr)
    p = subprocess.run(["bash", sc, "15.01.2026"], capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "usage" in p.stderr


def l02_crontab_example():
    lines = [l.split() for l in open(os.path.join(KIT, "launch", "crontab.example")) if l.strip() and not l.startswith("#")]
    assert len(lines) == 2, lines

    def expand(f, lo, hi):
        out = set()
        for part in f.split(","):
            rng, _, step = part.partition("/")
            a, _, b = rng.partition("-")
            a = lo if a == "*" else int(a)
            b = hi if rng == "*" else int(b) if b else a
            out |= set(range(a, b + 1, int(step) if step else 1))
        return out
    times = set()
    for f in lines:
        mins, hrs, dom, mon, dow, cmd, arg = f[:7]
        assert cmd.endswith("/kit-c/launch/launch-cron.sh") and dow == "*", f
        y, m, d = arg.split("-")
        assert int(dom) == int(d) and int(mon) == int(m), f
        times |= {(h, mi) for h in expand(hrs, 0, 23) for mi in expand(mins, 0, 59)}
    want = {(2, 5)} | {(h, mi) for h in range(2, 7) for mi in range(15, 60, 10)}
    assert times == want, sorted(times ^ want)
    assert max(times) == (6, 55) and min(times) == (2, 5)


def l03_launcher_other_time_zone():
    base = os.path.join(WORK, "l03")
    bin_, kit, runs = (os.path.join(base, x) for x in ("bin", "kit", "runs"))
    for d in (bin_, kit, runs):
        os.makedirs(d)
    calls = os.path.join(base, "calls.log")
    w(os.path.join(bin_, "date"), f'#!/bin/bash\nexec /usr/bin/date -d "$(cat {base}/now)" "$@"\n')
    w(os.path.join(bin_, "timedatectl"), "#!/bin/bash\necho yes\n")
    w(os.path.join(bin_, "lab"), f'#!/bin/bash\necho "lab $*" >> {calls}\n[ "${{1:-}}" = add ] && echo 7\nexit 0\n')
    for x in ("date", "timedatectl", "lab"):
        os.chmod(os.path.join(bin_, x), 0o755)
    w(os.path.join(kit, "guard.py"), f'import json, sys\nopen({calls!r}, "a").write("guard " + json.dumps(sys.argv[1:]) + "\\n")\n')
    src = open(LAUNCH).read()
    head, rest = src.split(BEGIN, 1)
    _, tail = rest.split(END, 1)

    def script(tz, window, proto="smtp", ehlo="scan.example.test"):
        settings = (f'{BEGIN} (test copy)\nPATH={bin_}:/usr/bin:/bin\nKIT={kit}\nBASE={runs}\nOUT_PREFIX=us-\nTARGETS={GT}\n'
                    f'TARGETS_SHA256={GSHA}\nEXPECTED_EGRESS=128.210.1.2\nEGRESS_PREFIX=128.210.\nVANTAGE_LABEL="test US vantage"\nALLOWED_DATES={GDATE}\n'
                    f'SCAN_TZ={tz}\nSCAN_WINDOW={window}\nGO_PHRASES="{GO}"\nFAMILIES=4\nWWW=off\nMODE=pinned\nRESOLVER=8.8.8.8\nPROTO={proto}\nEHLO_NAME="{ehlo}"\nMAX_MINUTES=300\n'
                    f'PYTHON={sys.executable}\nOPENSSL_BIN={OPENSSL}\nOPENSSL_CONF_FILE=/dev/null\nLAB_UNTIL=20:00\nLAB_DESC="scan test"\n')
        return w(os.path.join(base, "launch.sh"), head + settings + END + tail)

    logf = os.path.join(runs, f"launch-{GDATE}.log")

    def launch(now, tz="America/New_York", window="01:00-06:00", proto="smtp", ehlo="scan.example.test"):
        sc = script(tz, window, proto, ehlo)
        w(os.path.join(base, "now"), now + "\n")
        w(calls, "")
        n0 = os.path.getsize(logf) if os.path.exists(logf) else 0
        p = subprocess.run(["bash", sc, GDATE], capture_output=True, text=True, timeout=60,
                           env={k: v for k, v in os.environ.items() if not k.startswith("GUARD_")})
        new = open(logf).read()[n0:] if os.path.exists(logf) else ""
        return p.returncode, open(calls).read().splitlines(), new, p.stderr
    # 03:00 Taipei on GDATE is 14:00 of the previous day in New York: wrong local date
    rc, c, lg, _ = launch(IN_WIN)
    assert rc == 0 and c == [] and "local date (America/New_York) is 2026-01-14, not 2026-01-15" in lg, lg
    rc, c, lg, _ = launch(f"{GDATE}T00:30:00-05:00")
    assert c == [] and "is before the window start 01:00" in lg, lg
    rc, c, lg, _ = launch(f"{GDATE}T05:00:00-05:00")
    assert c == [] and "at or after 05:00 (one hour before the window end 06:00); not starting or resuming" in lg, lg
    rc, c, lg, _ = launch(f"{GDATE}T01:05:00-05:00")
    g = [json.loads(x[6:]) for x in c if x.startswith("guard ")]
    assert rc == 0 and len(g) == 1, (c, lg)
    a = g[0]
    for flag, v in (("--tz", "America/New_York"), ("--window", "01:00-06:00"), ("--date", GDATE),
                    ("--out", os.path.join(runs, f"us-{GDATE}")), ("--expected-egress", "128.210.1.2"), ("--egress-prefix", "128.210."),
                    ("--resolver", "8.8.8.8"), ("--proto", "smtp"), ("--ehlo-name", "scan.example.test"), ("--www", "off")):
        assert a[a.index(flag) + 1] == v, (flag, a)
    assert f"[local America/New_York {GDATE} 01:05:00]" in lg, lg
    # PROTO=quic (the launcher stays a template): guard gets --proto quic and no --ehlo-name
    shutil.rmtree(os.path.join(runs, f"us-{GDATE}"), ignore_errors=True)
    rc, c, lg, _ = launch(f"{GDATE}T01:15:00-05:00", proto="quic", ehlo="")
    g = [json.loads(x[6:]) for x in c if x.startswith("guard ")]
    assert rc == 0 and len(g) == 1 and g[0][g[0].index("--proto") + 1] == "quic" and "--ehlo-name" not in g[0], (c, lg)
    assert g[0][g[0].index("--www") + 1] == "off" and "--resume" not in g[0], g[0]
    # settings that cannot be used: refused before anything is logged or registered
    for tz, window, frag in (("Mars/Olympus_Mons", "01:00-06:00", "not an IANA time zone"),
                             ("../../etc/passwd", "01:00-06:00", "not an IANA time zone"),
                             ("America/New_York", "22:00-04:00", "must start before it ends"),
                             ("America/New_York", "1:00-6:00", "is not HH:MM-HH:MM"),
                             ("America/New_York", "FILL-ME", "SCAN_WINDOW is not filled in")):
        rc, c, lg, err = launch(f"{GDATE}T01:05:00-05:00", tz, window)
        assert rc == 2 and frag in err and c == [] and lg == "", (tz, window, rc, err, lg)


TESTS_ALL = [p01_no_application_data_server_trace, p02_slow_server_still_completes_without_data,
             r01_probe_set_and_cells, r02_cap_and_limits, r03_www_variants_and_csv, r04_families_and_pinning, r05_all_addresses_mode,
             r06_global_rate_default_18, r07_kill_switch_and_resume, r08_circuit_breaker, r09_max_minutes_in_runpy,
             r10_exclusions_names_suffixes_cidrs, r11_exclusion_reload_during_run, r12_real_resolver_path_with_stub_dns,
             r13_unguarded_refusals, r14_dry_run_sends_nothing, r15_load_estimate, r16_trace_modes,
             r17_resume_after_kill_caps_across_parts, d01_dns_client_against_fake_resolver, r18_resolver_option,
             s01_smtp_client_bytes_and_hrr_on_starttls, s02_smtp_scan_caps_and_refusals, s03_smtp_port_25_from_dns, m01_mxlist,
             q01_quic_handshake_sends_no_stream_data, q02_quic_unanswered_and_failed_handshakes,
             q03_quic_scan_probe_set_caps_and_refusals, q04_quic_port_443_from_dns_and_targets_helper,
             g01_baseline_all_pass, g02_window_boundaries, g03_dates, g04_egress_parameter, g05_ipv6_egress, g06_exit_node,
             g07_disk, g08_output_directory, g09_targets_hash_and_kit_integrity, g10_exclusion_file_invalid, g11_openssl,
             g12_other_scanner, g13_run_refusals, g14_test_mode_loopback_only, g15_max_minutes_required_and_capped,
             g16_happy_path, g17_watchdog_at_0800, g18_watchdog_max_minutes, g19_sigterm_to_guard, g20_plan_line_and_warning,
             g21_clock_check_pass_fail_missing, g22_clock_override_only_in_test_mode, g23_clock_recheck_immediately_before_start,
             g24_watchdog_stops_when_clock_unsynchronized, g25_resume_refusals, g26_resume_after_guard_and_runpy_killed,
             g27_resume_after_runpy_killed, g28_sigterm_when_runpy_chain_already_ended,
             g29_tz_and_window_options, g30_watchdog_at_window_end_in_other_zone, g31_resolver_option,
             g32_smtp_mode_in_guard, g33_quic_mode_in_guard,
             l01_launcher_decisions, l02_crontab_example, l03_launcher_other_time_zone]


def main():
    sel = sys.argv[1:]
    t0 = time.time()
    try:
        setup()
        gsetup()
        for t in TESTS_ALL:
            if not sel or any(t.__name__.startswith(s) for s in sel):
                test(t)
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                pass
    ev = os.environ.get("KITC_QUIC_EVIDENCE")
    if ev and EVID:
        write_quic_evidence(os.path.abspath(ev))
        print(f"QUIC evidence written to {os.path.abspath(ev)}")
    print(f"\nRESULT: {results['pass']} passed, {results['fail']} failed in {time.time() - t0:.0f}s"
          + (f" ({', '.join(failures)})" if failures else ""))
    sys.exit(1 if results["fail"] else 0)


if __name__ == "__main__":
    main()
