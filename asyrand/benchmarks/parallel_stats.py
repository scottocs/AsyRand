#!/usr/bin/env python3
"""Measure AsyRand and count unique ABA instances; compare retained baselines."""

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
from collections import defaultdict
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


def fields(data, prefix):
    match = re.search(r"^" + re.escape(prefix) + r" (.+)$", data, re.M)
    if not match:
        raise RuntimeError("missing log record: " + prefix)
    return dict(item.split("=", 1) for item in match[1].split())


def source_hash():
    digest = hashlib.sha256()
    for path in sorted((ROOT / "asyrand").rglob("*.go")):
        digest.update(str(path.relative_to(ROOT / "asyrand")).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def column_stats(history, local_instances, members, warmup, final_epoch):
    union = defaultdict(list)
    for node_instances in local_instances.values():
        for instance in node_instances:
            union[instance["instance"]].append(instance)
    columns = {col["record"]["column"]: col for col in [history["genesis"], *history["columns"]]}
    outputs, measured = defaultdict(list), defaultdict(list)
    for entry in history["entries"]:
        record = entry["record"]
        outputs[record["column"]].append(record["epoch"])
        # The first post-warmup output establishes the counter/timestamp baseline.
        if warmup + 1 < record["epoch"] <= final_epoch:
            measured[record["column"]].append(record["epoch"])
    all_columns = set(columns)
    all_columns.update(int(instance.split("/")[1]) for instance in union)
    rows = []
    for column in sorted(all_columns):
        instances = {key: value for key, value in union.items() if int(key.split("/")[1]) == column}
        proposed = {key for key, value in instances.items() if any(item["proposed"] for item in value)}
        native = {key for key, value in instances.items() if any(item["internal_decided"] for item in value)}
        certified = {key for key, value in instances.items() if any(item["certified"] for item in value)}
        col = columns.get(column)
        accepted = len(col["record"]["accepted"]) if col else 0
        whole = col["record"]["whole"] if col else ""
        required = {f"col/{column}"} if col else set()
        if col and whole == 0:
            required.update(f"obj/{column}/{member}" for member in members)
        if col and (not required.issubset(certified) or not required.issubset(proposed)):
            raise RuntimeError(f"verified column {column} lacks actual native proposals/certification")
        if col and proposed != required:
            raise RuntimeError(f"unexpected proposed instances in verified column {column}")
        rows.append(dict(column=column, verified_column=bool(col), whole_bit=whole,
                         accepted_objects=accepted, created_unique=len(instances),
                         proposed_unique=len(proposed), whole_proposed=sum(key.startswith("col/") for key in proposed),
                         object_proposed=sum(key.startswith("obj/") for key in proposed),
                         native_decided_unique=len(native), certified_unique=len(certified),
                         local_created_copies=sum(len(value) for value in instances.values()),
                         local_proposals=sum(item["proposed"] for value in instances.values() for item in value),
                         fully_consumed=bool(col) and len(outputs[column]) == accepted,
                         complete_in_window=bool(col) and len(measured[column]) == accepted,
                         outputs_in_window=len(measured[column])))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--resume", action="store_true", help="reuse completed, verified logs in --out")
    parser.add_argument("--nodes", type=int, nargs="+", choices=[4, 8], default=[4, 8])
    parser.add_argument("--parallel", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=128)
    parser.add_argument("--intervals", type=int, default=128)
    parser.add_argument("--baselines", type=Path, default=ROOT / "asyrand/benchmarks/local_20261014_results")
    args = parser.parse_args()
    if args.resume and args.out is None:
        parser.error("--resume requires --out")
    if args.repeats < 1 or args.warmup < 0 or args.intervals < 1:
        parser.error("repeats/intervals must be positive and warmup nonnegative")
    baseline_runs = list(csv.DictReader((args.baselines / "results.csv").open()))
    for run in baseline_runs:
        if run["protocol"] in ("grandline", "spurt") and int(run["nodes"]) in args.nodes:
            if int(run["warmup"]) != args.warmup or int(run["intervals"]) != args.intervals:
                parser.error("requested throughput window differs from retained baseline measurements")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")
    out = (args.out or ROOT / "asyrand/benchmarks" / datetime.now().strftime("parallel_%Y%m%d_%H%M%S")).resolve()
    out.mkdir(parents=True, exist_ok=args.resume)
    env = dict(os.environ, GOMAXPROCS="8")
    environment = dict(protocol="asyrand-v2", parallel_consumption=args.parallel, transport="memory",
                       production_window=8, gomaxprocs=8, workers_per_node=4, repeats=args.repeats,
                       warmup_outputs=args.warmup, measured_intervals=args.intervals,
                       full_run_intervals=args.warmup + args.intervals, nodes=args.nodes,
                       go=subprocess.check_output(["go", "version"], text=True).strip(),
                       platform=platform.platform(), source_sha256=source_hash(),
                       binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                       paper_sha256=hashlib.sha256((ROOT / "paper/Asyrand.tex").read_bytes()).hexdigest(),
                       aba_accounting="PRE/VOTE/MAIN/FINAL + DECISION/CERT_REQUEST/CERT_RESPONSE + SYNC/REPLAY; HISTORY/REPLY not split",
                       instance_accounting="union of instance IDs across nodes; report creation, proposal and certification separately",
                       baselines=str(args.baselines.resolve()), baseline_note="retained historical runs; baselines not rerun")
    if args.resume:
        saved = json.loads((out / "environment.json").read_text())
        # The paper is provenance, not an input to the executable. Keep its
        # original fingerprint and record edits without discarding valid runs.
        if any(saved[key] != value for key, value in environment.items() if key != "paper_sha256"):
            raise RuntimeError("resume parameters, sources, binary or environment differ from saved run")
        if saved["paper_sha256"] != environment["paper_sha256"]:
            note = dict(initial_paper_sha256=saved["paper_sha256"], resume_paper_sha256=environment["paper_sha256"],
                        note="paper edited during collection; executable, Go sources and all run parameters unchanged")
            (out / "resume_metadata.json").write_text(json.dumps(note, indent=2) + "\n")
        environment = saved
    else:
        (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    rows, col_rows, type_rows = [], [], []
    total_outputs = args.warmup + args.intervals + 1
    for nodes in args.nodes:
        for repeat in range(1, args.repeats + 1):
            cfg = json.loads((ROOT / f"asyrand/configs/local_{nodes}.json").read_text())
            cfg.update(round=args.intervals + 1, warmup_outputs=args.warmup, prefill_ms=3000,
                       epoch_timeout_ms=30000, report_interval_ms=60000, production_window=8,
                       max_pool=4, parallel_consumption=args.parallel,
                       session_id=f"{out.name}-n{nodes}-r{repeat}")
            tag = f"asyrand_n{nodes}_r{repeat}"
            conf, log, history_path = [out / (tag + suffix) for suffix in (".json", ".log", ".history.json")]
            checkpoint = out / (tag + ".run.json")
            reused = args.resume and log.exists() and history_path.exists()
            if reused:
                if json.loads(conf.read_text()) != cfg:
                    raise RuntimeError("saved configuration differs: " + str(conf))
                execution = json.loads(checkpoint.read_text()) if checkpoint.exists() else dict(returncode=0, wall_s=None)
            else:
                conf.write_text(json.dumps(cfg, indent=2) + "\n")
                start = time.monotonic()
                with log.open("w") as stream:
                    proc = subprocess.run([str(binary), "-config", str(conf), "-history", str(history_path)],
                                          cwd=ROOT / "asyrand", env=env, stdout=stream,
                                          stderr=subprocess.STDOUT, timeout=600)
                execution = dict(returncode=proc.returncode, wall_s=time.monotonic() - start)
                checkpoint.write_text(json.dumps(execution, indent=2) + "\n")
            data = log.read_text()
            packets = re.findall(r"^ts=(\S+) epoch=(\d+) .*random=", data, re.M)
            if (execution["returncode"] or len(packets) != total_outputs or " skipped " in data
                    or f"verification valid_epochs={total_outputs}" not in data
                    or [int(epoch) for _, epoch in packets] != list(range(1, total_outputs + 1))):
                raise RuntimeError(f"failed, skipped or unverified run: {log}")
            final, full = fields(data, "final metrics"), fields(data, "run metrics")
            final_aba, full_aba = fields(data, "final aba_metrics"), fields(data, "run aba_metrics")
            if int(final["beacons"]) != args.intervals or int(full["beacons"]) != total_outputs - 1:
                raise RuntimeError(f"invalid byte counter window: {log}")
            times = [stamp(ts) for ts, _ in packets][args.warmup:]
            elapsed = (times[-1] - times[0]) / 1e9
            local = json.loads(re.search(r"^final aba_instances (.+)$", data, re.M)[1])
            columns = column_stats(json.loads(history_path.read_text()), local,
                                   sorted(cfg["cluster_index"]), args.warmup, total_outputs)
            complete = [c for c in columns if c["complete_in_window"]]
            verified = [c for c in columns if c["verified_column"]]
            if not complete:
                raise RuntimeError("measurement window has no complete consumed column")
            for col in columns:
                col_rows.append(dict(nodes=nodes, repeat=repeat, **col))
            write_csv(out / "aba_columns.csv", col_rows)
            for label in ("final", "run"):
                types = json.loads(re.search(r"^" + label + r" message_metrics (.+)$", data, re.M)[1])
                for name, counts in types.items():
                    type_rows.append(dict(nodes=nodes, repeat=repeat, window=label, message_type=name, **counts))
            write_csv(out / "message_types.csv", type_rows)
            row = dict(protocol="asyrand-parallel" if args.parallel else "asyrand-standard", nodes=nodes,
                       repeat=repeat, warmup=args.warmup, intervals=args.intervals,
                       elapsed_s=elapsed, beacon_s=args.intervals / elapsed,
                       postwarmup_sent_kib_per_beacon=int(final["sent_bytes"]) / 1024 / args.intervals,
                       full_sent_kib_per_beacon=int(full["sent_bytes"]) / 1024 / (total_outputs - 1),
                       aba_core_kib_per_beacon=int(final_aba["core_bytes"]) / 1024 / args.intervals,
                       aba_certificate_kib_per_beacon=int(final_aba["certificate_bytes"]) / 1024 / args.intervals,
                       aba_recovery_kib_per_beacon=int(final_aba["recovery_bytes"]) / 1024 / args.intervals,
                       aba_total_kib_per_beacon=int(final_aba["aba_bytes"]) / 1024 / args.intervals,
                       aba_sent_pct=float(final_aba["aba_sent_pct"]), full_aba_sent_pct=float(full_aba["aba_sent_pct"]),
                       complete_window_columns=len(complete), verified_columns=len(verified),
                       created_aba_per_column=statistics.mean(c["created_unique"] for c in complete),
                       proposed_aba_per_column=statistics.mean(c["proposed_unique"] for c in complete),
                       object_aba_per_column=statistics.mean(c["object_proposed"] for c in complete),
                       fallback_window_columns=sum(c["whole_bit"] == 0 for c in complete),
                       all_verified_aba_per_column=statistics.mean(c["proposed_unique"] for c in verified),
                       fallback_all_verified_columns=sum(c["whole_bit"] == 0 for c in verified),
                       wall_s=execution["wall_s"], reused_log=reused, log=log.name, history=history_path.name)
            rows.append(row)
            write_csv(out / "results.csv", rows)
            print(f"{tag}: {row['beacon_s']:.3f} beacon/s; post/full {row['postwarmup_sent_kib_per_beacon']:.3f}/{row['full_sent_kib_per_beacon']:.3f} KiB/beacon; ABA {row['aba_sent_pct']:.2f}%, {row['proposed_aba_per_column']:.3f}/column; history valid", flush=True)
    summary = []
    metrics = [key for key in rows[0] if key.endswith("_per_column") or key.endswith("_per_beacon") or key in ("beacon_s", "aba_sent_pct", "full_aba_sent_pct")]
    for nodes in args.nodes:
        values = [row for row in rows if row["nodes"] == nodes]
        row = dict(protocol=values[0]["protocol"], nodes=nodes, repeats=len(values))
        for metric in metrics:
            nums = [value[metric] for value in values]
            row["mean_" + metric] = statistics.mean(nums)
            row["stdev_" + metric] = statistics.stdev(nums) if len(nums) > 1 else 0
        summary.append(row)
    write_csv(out / "summary.csv", summary)
    # Match each metric's retained baseline window: throughput is post-warmup,
    # while the baseline byte counters cover the complete 256 intervals.
    baseline_summary = list(csv.DictReader((args.baselines / "summary.csv").open()))
    comparisons = []
    for nodes in args.nodes:
        current = next(row for row in summary if row["nodes"] == nodes)
        comparisons.append(dict(protocol=current["protocol"], nodes=nodes, source="current", repeats=args.repeats,
                                mean_beacon_s=current["mean_beacon_s"], stdev_beacon_s=current["stdev_beacon_s"],
                                mean_sent_kib_per_beacon=current["mean_full_sent_kib_per_beacon"],
                                stdev_sent_kib_per_beacon=current["stdev_full_sent_kib_per_beacon"],
                                byte_intervals=total_outputs - 1))
        for protocol in ("grandline", "spurt"):
            retained = next(row for row in baseline_summary if row["protocol"] == protocol and int(row["nodes"]) == nodes)
            traffic, intervals = [], set()
            for log in sorted(args.baselines.glob(f"{protocol}_n{nodes}_r*.log")):
                final = fields(log.read_text(), "final metrics")
                count = int(final["beacons"])
                intervals.add(count)
                traffic.append(float(final["sent"].removesuffix("KB")) / count)
            if not traffic or intervals != {total_outputs - 1}:
                raise RuntimeError("retained baseline byte window does not match this full run")
            comparisons.append(dict(protocol=protocol, nodes=nodes, source="historical", repeats=len(traffic),
                                    mean_beacon_s=float(retained["mean_beacon_s"]), stdev_beacon_s=float(retained["stdev_beacon_s"]),
                                    mean_sent_kib_per_beacon=statistics.mean(traffic),
                                    stdev_sent_kib_per_beacon=statistics.stdev(traffic) if len(traffic) > 1 else 0,
                                    byte_intervals=next(iter(intervals))))
    write_csv(out / "comparison.csv", comparisons)
    if source_hash() != environment["source_sha256"]:
        raise RuntimeError("Go source changed during measurements; rebuild and rerun")
    print("Saved " + str(out), flush=True)


if __name__ == "__main__":
    main()
