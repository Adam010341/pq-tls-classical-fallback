# Scanner

A rate-limited, resumable TLS 1.3 key-share scanner. Python 3 standard library only; the TLS client
is the OpenSSL 3.5 command-line tool (`s_client`).

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

The tests run inside `unshare -Urnm`, so nothing leaves the machine. They need Linux, Python 3.9+,
OpenSSL 3.5 or newer, and `gcc` for the QUIC test server.

## Running a scan

Run on its own, `run.py` only connects to loopback addresses. A real scan goes through the guard:

```bash
python3 -I guard.py check --date YYYY-MM-DD --allowed-dates YYYY-MM-DD \
    --out runs/web-YYYY-MM-DD --targets hosts.txt --targets-sha256 HEX \
    --expected-egress A.B.C.D --egress-prefix A.B. \
    --vantage-label "University campus, AS64500, City" --max-minutes 360 --www add
```

`check` only reports. `run` takes the same arguments plus an approval phrase for that date, and
refuses to start if any check fails:

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
