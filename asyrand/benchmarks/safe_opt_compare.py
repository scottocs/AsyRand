#!/usr/bin/env python3
"""Compare two AsyRand binaries with matching post-warmup throughput/byte windows."""

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def stamp(value):
    match = re.fullmatch(r"(.+?)(?:\.(\d+))?Z", value)
    base = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(base.timestamp()) * 10**9 + int((match[2] or "").ljust(9, "0"))


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def source_hash():
    digest = hashlib.sha256()
    for path in sorted((ROOT / "asyrand").rglob("*.go")):
        digest.update(str(path.relative_to(ROOT / "asyrand")).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--nodes", type=int, nargs="+", choices=[4, 8], default=[4, 8])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=128)
    parser.add_argument("--intervals", type=int, default=128)
    parser.add_argument("--before-source-sha256")
    parser.add_argument("--parallel", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    if args.repeats < 1 or args.warmup < 0 or args.intervals < 1:
        parser.error("repeats/intervals must be positive and warmup nonnegative")
    binaries = {"before": args.before.resolve(), "after": args.after.resolve()}
    for binary in binaries.values():
        if not binary.is_file():
            parser.error(f"binary does not exist: {binary}")
    out = (args.out or ROOT / "asyrand/benchmarks" / datetime.now().strftime("safe_opt_%Y%m%d_%H%M%S")).resolve()
    out.mkdir(parents=True, exist_ok=False)
    environment = dict(
        protocol="asyrand-v2", transport="memory", gomaxprocs=8, workers_per_node=4,
        production_window=8, parallel_consumption=args.parallel, warmup=args.warmup,
        intervals=args.intervals, repeats=args.repeats, nodes=args.nodes,
        byte_window="runner counters from output warmup+1 through the last output",
        accounting="committee aggregate sent bytes, including loopback; no receive double count",
        before_byte_precision="rounded log KiB (0.01 KiB) if exact sent_bytes is unavailable",
        run_order="alternate before/after order each repetition",
        go=subprocess.check_output(["go", "version"], text=True).strip(),
        platform=platform.platform(), machine=platform.machine(),
        before_source_sha256=args.before_source_sha256, after_source_sha256=source_hash(),
        binary_sha256={name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
        paper_sha256=hashlib.sha256((ROOT / "paper/Asyrand.tex").read_bytes()).hexdigest(),
    )
    (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    env = dict(os.environ, GOMAXPROCS="8")
    rows, type_rows = [], []
    total_outputs = args.warmup + args.intervals + 1
    for nodes in args.nodes:
        for repeat in range(1, args.repeats + 1):
            order = ["before", "after"] if repeat % 2 else ["after", "before"]
            for variant in order:
                cfg = json.loads((ROOT / f"asyrand/configs/local_{nodes}.json").read_text())
                cfg.update(round=args.intervals + 1, warmup_outputs=args.warmup,
                           epoch_timeout_ms=30000, prefill_ms=3000, report_interval_ms=60000,
                           production_window=8, max_pool=4, parallel_consumption=args.parallel,
                           session_id=f"{out.name}-n{nodes}-r{repeat}")
                tag = f"{variant}_n{nodes}_r{repeat}"
                config_path, log = out / (tag + ".json"), out / (tag + ".log")
                config_path.write_text(json.dumps(cfg, indent=2) + "\n")
                started = time.monotonic()
                with log.open("w") as stream:
                    proc = subprocess.run([str(binaries[variant]), "-config", str(config_path)],
                                          cwd=ROOT / "asyrand", env=env, stdout=stream,
                                          stderr=subprocess.STDOUT, timeout=600)
                data = log.read_text()
                packets = re.findall(r"^ts=(\S+) epoch=(\d+) .*random=", data, re.M)
                if (proc.returncode or len(packets) != total_outputs or " skipped " in data
                        or f"verification valid_epochs={total_outputs}" not in data
                        or [int(e) for _, e in packets] != list(range(1, total_outputs + 1))):
                    raise RuntimeError(f"failed or unverified run: {log}")
                final = re.search(r"^final metrics (.+)$", data, re.M)
                fields = dict(item.split("=", 1) for item in final[1].split())
                if int(fields["beacons"]) != args.intervals:
                    raise RuntimeError(f"counter window differs from timestamp window: {log}")
                measured = [stamp(ts) for ts, _ in packets][args.warmup:]
                elapsed = (measured[-1] - measured[0]) / 1e9
                sent = int(fields["sent_bytes"]) if "sent_bytes" in fields else float(fields["sent"].removesuffix("KB")) * 1024
                recv = int(fields["recv_bytes"]) if "recv_bytes" in fields else float(fields["recv"].removesuffix("KB")) * 1024
                row = dict(variant=variant, nodes=nodes, repeat=repeat, warmup=args.warmup,
                           intervals=args.intervals, elapsed_s=elapsed, beacon_s=args.intervals / elapsed,
                           runner_elapsed_s=float(fields["elapsed_s"]), sent_bytes=sent, recv_bytes=recv,
                           sent_msgs=int(fields["sent_msgs"]), sent_kib_per_beacon=sent / 1024 / args.intervals,
                           wall_s=time.monotonic() - started, log=log.name)
                rows.append(row)
                write_csv(out / "results.csv", rows)
                types = re.search(r"^final message_metrics (.+)$", data, re.M)
                if types:
                    for name, counts in json.loads(types[1]).items():
                        type_rows.append(dict(variant=variant, nodes=nodes, repeat=repeat, message_type=name, **counts))
                    write_csv(out / "message_types.csv", type_rows)
                print(f"{tag}: {row['beacon_s']:.3f} beacon/s, {row['sent_kib_per_beacon']:.3f} KiB/beacon; history valid", flush=True)
    summary = []
    for nodes in args.nodes:
        for variant in binaries:
            values = [r for r in rows if r["nodes"] == nodes and r["variant"] == variant]
            throughput = [r["beacon_s"] for r in values]
            traffic = [r["sent_kib_per_beacon"] for r in values]
            summary.append(dict(variant=variant, nodes=nodes, repeats=len(values),
                                mean_beacon_s=statistics.mean(throughput),
                                stdev_beacon_s=statistics.stdev(throughput) if len(values) > 1 else 0,
                                mean_sent_kib_per_beacon=statistics.mean(traffic),
                                stdev_sent_kib_per_beacon=statistics.stdev(traffic) if len(values) > 1 else 0))
    write_csv(out / "summary.csv", summary)
    if source_hash() != environment["after_source_sha256"]:
        raise RuntimeError("Go source changed during the comparison; rebuild and rerun")
    print("Saved " + str(out), flush=True)


if __name__ == "__main__":
    main()
