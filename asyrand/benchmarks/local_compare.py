#!/usr/bin/env python3
"""Sequential local comparison of existing implementations, not paper figures.
Each output log is emitted only after every node returns the same beacon.
Throughput uses 128 intervals after 128 warm-up outputs; skips fail the run.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]

def command(args, **kw):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kw).stdout.strip()

def stamp(raw):
    # Preserve Go's nanosecond timestamps instead of Python's microsecond truncation.
    match = re.fullmatch(r"(.+?)(?:\.(\d+))?Z", raw)
    base = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(base.timestamp()) * 10**9 + int((match[2] or "").ljust(9, "0"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", nargs="+", type=int, default=[4, 8])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--warmup", type=int, default=128)
    ap.add_argument("--intervals", type=int, default=128)
    ap.add_argument("--gomaxprocs", type=int, default=8)
    ap.add_argument("--parallel", action=argparse.BooleanOptionalAction, default=True, help="parallel AsyRand consumption (default enabled)")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    if args.intervals < 1 or args.warmup < 0 or args.repeats < 1 or any(n not in [4, 8] for n in args.nodes):
        ap.error("requires positive intervals/repeats and nodes 4 or 8")
    out = args.out or ROOT / "asyrand" / "benchmarks" / ("local_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "bin").mkdir()
    env = dict(os.environ, GOMAXPROCS=str(args.gomaxprocs))
    machine = {"platform": platform.platform(), "go": command(["go", "version"]),
               "gomaxprocs": args.gomaxprocs, "workers_per_node": 4, "transport": "memory",
               "warmup_outputs": args.warmup, "measured_intervals": args.intervals,
               "repeats": args.repeats, "asyrand_parallel": args.parallel,
               "startup_prefill_ms": 3000, "faults_injected": 0,
               "git_revision": command(["git", "rev-parse", "HEAD"], cwd=ROOT)}
    if platform.system() == "Darwin":
        machine["cpu"] = command(["sysctl", "-n", "machdep.cpu.brand_string"])
        machine["logical_cpus"] = command(["sysctl", "-n", "hw.logicalcpu"])
    (out / "environment.json").write_text(json.dumps(machine, indent=2) + "\n")
    names = ["asyrand", "grandline", "spurt"]
    fingerprints = {}
    for name in names:
        binary = out / "bin" / name
        command(["go", "build", "-o", str(binary), "./cmd/" + name], cwd=ROOT/name, env=env)
        h = hashlib.sha256()
        for path in sorted((ROOT/name).rglob("*.go")):
            h.update(str(path.relative_to(ROOT/name)).encode())
            h.update(path.read_bytes())
        fingerprints[name] = {"go_source_sha256": h.hexdigest(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    (out / "fingerprints.json").write_text(json.dumps(fingerprints, indent=2) + "\n")
    fields = ["protocol", "nodes", "f", "repeat", "warmup", "intervals", "elapsed_s", "beacon_s", "beacon_min", "p50_interval_ms", "p95_interval_ms", "wall_s", "status", "log"]
    rows = []
    with (out / "results.csv").open("w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields); writer.writeheader(); fp.flush()
        for n in args.nodes:
            for repeat in range(1, args.repeats + 1):
                # Rotate order to reduce systematic heating/order bias.
                order = names[(repeat-1)%3:] + names[:(repeat-1)%3]
                for name in order:
                    cfg = json.loads((ROOT/name/"configs/local_8.json").read_text())
                    ids = ["node" + str(i) for i in range(n)]
                    for key in ["cluster_index", "cluster_ips", "peers_p2p_port", "node_key_seed"]:
                        cfg[key] = {k: v for k, v in cfg[key].items() if k in ids}
                    cfg.update(name="bench-local-" + str(n), transport="memory", f=(n-1)//3,
                               round=args.warmup + args.intervals + 1, prefill_ms=3000,
                               epoch_timeout_ms=30000, report_interval_ms=60000, max_pool=4)
                    if name == "asyrand":
                        cfg.update(production_window=8, parallel_consumption=args.parallel,
                                   warmup_outputs=0, session_id=f"bench-{n}-{repeat}-{out.name}")
                    # Keep the Grandline deployment setting; its producer interval
                    # is unused by the current GRandLine steady-state implementation.
                    tag = f"{name}_n{n}_r{repeat}"
                    conf = out/(tag+".json"); conf.write_text(json.dumps(cfg, indent=2)+"\n")
                    start = time.monotonic(); log = out/(tag+".log")
                    with log.open("w") as lf:
                        try:
                            proc = subprocess.run([str(out/"bin"/name), "-config", str(conf)], cwd=ROOT/name,
                                                  env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=600)
                            code = proc.returncode
                        except subprocess.TimeoutExpired:
                            code = -1
                    wall = time.monotonic()-start; data = log.read_text()
                    packets = re.findall(r"^ts=(\S+) epoch=(\d+) .*random=", data, re.MULTILINE)
                    status = "ok"
                    if code or " skipped " in data or len(packets) != cfg["round"]:
                        status = f"failed(exit={code},outputs={len(packets)})"
                    if name == "asyrand" and "verification valid_epochs=" not in data:
                        status = "failed(public verification)"
                    row = dict(protocol=name, nodes=n, f=cfg["f"], repeat=repeat, warmup=args.warmup,
                               intervals=args.intervals, wall_s=f"{wall:.3f}", status=status, log=log.name)
                    if status == "ok":
                        epochs = [int(e) for _,e in packets]
                        if any(b != a+1 for a,b in zip(epochs,epochs[1:])):
                            status=row["status"]="failed(epoch gap)"
                        else:
                            times = [stamp(ts) for ts,_ in packets][args.warmup:]
                            elapsed = (times[-1]-times[0])/1e9
                            gaps = sorted((b-a)/1e6 for a,b in zip(times,times[1:]))
                            rps = args.intervals/elapsed
                            row.update(elapsed_s=f"{elapsed:.9f}", beacon_s=f"{rps:.6f}", beacon_min=f"{rps*60:.3f}",
                                       p50_interval_ms=f"{statistics.median(gaps):.3f}",
                                       p95_interval_ms=f"{gaps[min(len(gaps)-1,int(.95*len(gaps)))]:.3f}")
                    writer.writerow(row); fp.flush(); rows.append(row)
                    print(f"{tag}: {status} {row.get('beacon_s', '')} beacon/s (wall {wall:.1f}s)", flush=True)
                    if status != "ok":
                        raise RuntimeError(f"Benchmark failed; see {log}")
    summary = []
    for n in args.nodes:
        for name in names:
            vals = [float(r["beacon_s"]) for r in rows if r["nodes"]==n and r["protocol"]==name]
            summary.append(dict(protocol=name,nodes=n,repeats=len(vals),mean_beacon_s=statistics.mean(vals),
                                stdev_beacon_s=statistics.stdev(vals) if len(vals)>1 else 0,
                                min_beacon_s=min(vals),max_beacon_s=max(vals)))
    with (out/"summary.csv").open("w",newline="") as fp:
        writer=csv.DictWriter(fp,fieldnames=list(summary[0]));writer.writeheader();writer.writerows(summary)
    print("Saved " + str(out), flush=True)

if __name__=="__main__":
    main()
