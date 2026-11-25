# Scanner

This is a rate-limited TLS 1.3 scanner that records which key-exchange group a server selects. It is
written in Python 3 with only the standard library, and it uses the OpenSSL 3.5 command-line tool
(`s_client`) as its TLS client. A scan that is interrupted can be resumed later.

## Files

| File | What it does |
|---|---|
| `run.py` | The scanner: resolves names, schedules probes under the rate limit, writes results and traces |
| `guard.py` | Pre-flight checks, watchdog and kill switch. Real scans only start through it |
| `probe_one.sh`, `probe_smtp.sh`, `probe_quic.sh` | One handshake each, for HTTPS, SMTP STARTTLS and QUIC |
| `dnsclient.py` | Small DNS client, used to resolve names through a chosen public resolver |
| `mxlist.py` | Builds the list of mail servers for a list of domains |
| `quic_targets.py` | Picks the hostnames for the QUIC scan from a finished web scan |
| `launch/` | Cron launcher template for unattended night-time runs |
| `tests/` | Offline test suite with local DNS, SMTP, TLS and QUIC test servers |
| `evidence/` | Loopback captures showing what the probes send (for example, no application data) |

## Running the tests

```bash
OPENSSL=/path/to/openssl-3.5/bin/openssl bash run_tests.sh
```

The tests run inside `unshare -Urnm`, so nothing leaves the machine. They need Linux, Python 3.9 or
newer, OpenSSL 3.5 or newer, and `gcc` to build the QUIC test server.

## Running a scan

When you run `run.py` on its own, it only connects to loopback addresses. A real scan has to go
through the guard, which first checks that it is safe to start:

```bash
python3 -I guard.py check --date YYYY-MM-DD --allowed-dates YYYY-MM-DD \
    --out runs/web-YYYY-MM-DD --targets hosts.txt --targets-sha256 HEX \
    --expected-egress A.B.C.D --egress-prefix A.B. \
    --vantage-label "University campus, AS64500, City" --max-minutes 360 --www add
```

The `check` command only reports what it finds. The `run` command takes the same arguments plus an
approval phrase for that date, and it refuses to start unless all of the following hold:

- the local time is inside the scan window (default 02:00 to 08:00) on an announced date;
- the source address is the one announced to the network operator;
- the clock is synchronized and there is enough free disk;
- the target list and the scanner files match their recorded hashes;
- no other scan is running.

## After a run

The output directory holds `results.tsv` (one row per hostname), `probes.log` (one line per
handshake), `traces.jsonl.xz` (the recorded handshake messages, with the duration of each handshake)
and the guard's log. To stop a run early, create a file named `STOP` in the output directory.

## Load limits

- At most 18 handshakes start per second.
- At most four handshakes per hostname, and eight per mail server address.
- A failed probe is not retried.
- A QUIC probe stops the client at its 40th datagram.
- Names and addresses in `exclude.txt` are never probed.
