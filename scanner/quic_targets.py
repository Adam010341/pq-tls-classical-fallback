#!/usr/bin/env python3
"""quic_targets.py: the --targets file of a `run.py --proto quic` campaign, made from a finished https run directory.

  python3 -I quic_targets.py --run DIR --out FILE [--allow-incomplete]

Reads DIR/results.tsv (14 columns, run.py emit()) and keeps every probed name (column 1: the listed name or its www.
variant) whose P1 cell completed on X25519MLKEM768 (run.py is_pq: "ok|...|grp=X25519MLKEM768") in any address family.
Files only: no DNS, no connection.
Output: --out, one "rank,name" line per name (each name once, with the lowest rank it had; sorted by rank, then name),
which run.py reads as a ranked list (the rank of the https campaign is kept); --out.sha256 in `sha256sum` format (the
value for guard.py --targets-sha256). Neither may exist already (nothing is overwritten). A summary goes to stderr and
a "QUICTARGETS-JSON {...}" line to stdout.
Refusals (exit 2, nothing written): DIR has no results.tsv; a run-meta.json line records a proto other than https (a
run-meta without "proto" is https); DIR holds a STOP file or guard-meta.json does not say "finished" (the https run is
incomplete), unless --allow-incomplete (then a WARNING line, and "complete": false in the JSON).
"""
import argparse, collections, hashlib, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_run():
    sys.dont_write_bytecode = True              # no __pycache__ in the kit directory
    spec = importlib.util.spec_from_file_location("kitc_run", os.path.join(HERE, "run.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", required=True, help="directory of a finished kit-c https run")
    ap.add_argument("--out", required=True, help="new targets file (rank,name per line)")
    ap.add_argument("--allow-incomplete", action="store_true", help="accept a run without guard-meta status finished, or with STOP")
    a = ap.parse_args()
    R = load_run()
    res = os.path.join(a.run, "results.tsv")
    for p in (a.out, a.out + ".sha256"):
        if os.path.lexists(p):
            ap.error(f"{p} exists; nothing is overwritten")
    if not os.path.isfile(res):
        ap.error(f"{res} not found")
    protos = []
    mp = os.path.join(a.run, "run-meta.json")
    if os.path.exists(mp):
        for i, l in enumerate(open(mp), 1):
            if l.strip():
                try:
                    protos.append(json.loads(l).get("proto") or "https")
                except ValueError:
                    ap.error(f"{mp} line {i} is not JSON")
    if any(p != "https" for p in protos):
        ap.error(f"{a.run} is not an https run (run-meta.json proto {sorted(set(protos))}); the QUIC targets come from an https run")
    probs = []
    if os.path.exists(os.path.join(a.run, "STOP")):
        probs.append("STOP file present")
    try:
        st = json.load(open(os.path.join(a.run, "guard-meta.json"))).get("status")
    except (OSError, ValueError, AttributeError) as e:
        st = f"unreadable ({type(e).__name__})"
    if st != "finished":
        probs.append(f"guard-meta.json status {st!r}, not 'finished'")
    if probs and not a.allow_incomplete:
        ap.error(f"{a.run}: the https run is not complete ({'; '.join(probs)}); --allow-incomplete accepts it")
    if probs:
        print(f"WARNING: {a.run}: incomplete https run accepted ({'; '.join(probs)})", file=sys.stderr)
    rank, rows, bad, pq_rows, by = {}, 0, 0, 0, collections.Counter()
    for l in open(res, errors="replace"):
        p = l.rstrip("\n").split("\t")
        if len(p) != 14:
            bad += 1
            continue
        rows += 1
        if not R.is_pq(p[3]):
            continue
        name = R.norm_name(p[0])
        if not R.valid_name(name):
            bad += 1
            continue
        pq_rows += 1
        by[(p[11], "ipv" + p[10])] += 1
        try:
            r = int(p[12])
        except ValueError:
            r = 10 ** 9
        rank[name] = min(rank.get(name, r), r)
    names = sorted(rank, key=lambda n: (rank[n], n))
    data = "".join(f"{rank[n]},{n}\n" for n in names).encode()
    tmp = a.out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, a.out)
    digest = hashlib.sha256(data).hexdigest()
    with open(a.out + ".sha256", "w") as f:
        f.write(f"{digest}  {os.path.basename(a.out)}\n")
    summ = {"run": os.path.abspath(a.run), "rows": rows, "malformed_or_invalid": bad, "pq_rows": pq_rows,
            "pq_rows_by_variant_family": {f"{v} {fam}": n for (v, fam), n in sorted(by.items())}, "names": len(names),
            "out": a.out, "sha256": digest, "complete": not probs}
    print(f"quic_targets: {rows} rows, {pq_rows} with P1 on {R.PQ_GROUP} -> {len(names)} names; {a.out} sha256 {digest}",
          file=sys.stderr)
    print("QUICTARGETS-JSON " + json.dumps(summ, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
