#!/usr/bin/env python3
"""Sequential comparison of current AsyRand modes, GRandLine and SPURT.

Preserves sources, binaries, configurations, logs, histories and exact counters.
Reports single-host fault-free performance under each implementation's CURRENT
signature policy, not a claim of published-paper or WAN reproduction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode = True
from parallel_stats import fields, window_timing, write_csv
from traffic_breakdown import classify, message_category

ROOT = Path(__file__).resolve().parents[2]
MODULES = ("asyrand", "grandline", "spurt", "utils")
VARIANTS = (("asyrand-standard", "asyrand", False), ("asyrand-parallel", "asyrand", True),
            ("grandline", "grandline", None), ("spurt", "spurt", None))


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def optional_file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def source_hash(module):
    h = hashlib.sha256()
    paths = list((ROOT/module).rglob("*.go"))
    paths += [ROOT/module/name for name in ("go.mod", "go.sum") if (ROOT/module/name).exists()]
    for path in sorted(paths):
        h.update(str(path.relative_to(ROOT/module)).encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def make_config(module, n, repeat, parallel, args, label):
    cfg = json.loads((ROOT/module/"configs/local_8.json").read_text())
    ids = [f"node{i}" for i in range(n)]
    old = cfg["node_key_seed"]
    cfg.update(cluster_index={id: i for i, id in enumerate(ids)},
               cluster_ips={id: "127.0.0.1" for id in ids},
               peers_p2p_port={id: 9000+i for i, id in enumerate(ids)},
               node_key_seed={id: old.get(id, hashlib.sha256(
                   ("Tyche/local-benchmark/TEST-ONLY/"+id).encode()).hexdigest()) for id in ids},
               name=f"bench-local-{n}", transport="memory", f=(n-1)//3,
               round=args.warmup+args.intervals+1, warmup_outputs=args.warmup,
               prefill_ms=3000, epoch_timeout_ms=60000, report_interval_ms=60000, max_pool=4)
    if module == "asyrand":
        cfg.update(round=args.intervals+1, production_window=8, parallel_consumption=parallel,
                   session_id=f"{label}-n{n}-r{repeat}-parallel{parallel}")
    elif module == "grandline":
        cfg.update(beacon_mode="standard", setup_file="")
    return cfg


def summary(rows):
    result = []
    for variant, n in dict.fromkeys((r["variant"], r["nodes"]) for r in rows):
        samples = [r for r in rows if (r["variant"], r["nodes"]) == (variant, n)]
        row = dict(variant=variant, nodes=n, f=samples[0]["f"], repeats=len(samples))
        for metric in ("beacon_s", "elapsed_s", "p50_interval_ms", "p95_interval_ms",
                       "post_sent_kib_per_beacon", "full_sent_kib_per_beacon",
                       "post_sent_msgs_per_beacon", "wall_s", "post_message_verifies",
                       "post_message_signs", "post_aba_sent_pct", "post_sent_kib_s", "post_sent_mib_s",
                       "post_producer_sent_pct", "post_consumer_sent_pct", "post_history_sent_pct"):
            values = [r[metric] for r in samples if isinstance(r.get(metric), (int, float))]
            row["mean_"+metric] = statistics.mean(values) if values else ""
            row["stdev_"+metric] = statistics.stdev(values) if len(values)>1 else (0 if values else "")
        result.append(row)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--nodes", nargs="+", type=int, choices=[4, 8, 16], default=[4, 8, 16])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--warmup", type=int, default=128)
    ap.add_argument("--intervals", type=int, default=128)
    ap.add_argument("--goarch", default="arm64")
    ap.add_argument("--variants", nargs="+", choices=[v[0] for v in VARIANTS],
                    default=[v[0] for v in VARIANTS])
    args = ap.parse_args()
    variants = tuple(v for v in VARIANTS if v[0] in args.variants)
    if min(args.intervals, args.repeats) < 1 or args.warmup < 0:
        ap.error("requires positive intervals/repeats and nonnegative warmup")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out/"bin").mkdir()
    env = dict(os.environ, GOMAXPROCS="8", GOARCH=args.goarch,
               GOCACHE="/private/tmp/tyche-crypto-go-cache")
    metadata = dict(platform=platform.platform(), go=command(["go", "version"]), target_goarch=args.goarch,
                    gomaxprocs=8, workers_per_node=4, transport="memory", nodes=args.nodes,
                    warmup_outputs=args.warmup, measured_intervals=args.intervals, repeats=args.repeats,
                    variants=[v[0] for v in variants], startup_prefill_ms=3000,
                    throughput_clock="Go monotonic final-metric elapsed_s; 1ms precision for GRandLine/SPURT, 1us for AsyRand",
                    percentile_clock="UTC output timestamps; suppressed for detected clock-step runs",
                    grandline_beacon_mode="standard: authenticated one-time online COMMIT, no outer signatures",
                    production_window=8, spurt_aggregation_lookahead=8, faults_injected=0,
                    spurt_quorum="n-f, equal to 2f+1 when n=3f+1; FINALIZE relay at f+1",
                    git_revision=command(["git", "rev-parse", "HEAD"], cwd=ROOT), command=sys.argv,
                    run_order="serial; rotate variants each repetition",
                    byte_accounting="committee-wide sent bytes including loopback, not sent+received",
                    asyrand_snapshot="total counters and component counters derived from the same frozen per-type snapshots",
                    byte_windows="same post-warmup and full-output intervals for all implementations",
                    bandwidth="committee sent bytes / monotonic elapsed; KiB/s and MiB/s; sent+received is not added",
                    asyrand_traffic_accounting={
                        "producer": "PVSS object RBC: VAL/ECHO/READY/REQUEST/REPLY",
                        "consumer": "ABA + reconstruction + history recovery; includes agreement",
                        "aba": "PRE/VOTE/MAIN/FINAL + DECISION/CERT_REQUEST/CERT_RESPONSE + SYNC/REPLAY",
                        "reconstruction": "beacon RECON",
                        "history_recovery": "beacon HISTORY/REPLY, including any embedded column/certificate evidence",
                        "aba_limit": "No payload splitting inside HISTORY/REPLY; ABA is directly attributable message traffic",
                        "partition": "producer + consumer = total; ABA is a consumer subset"},
                    ordinary_signatures={"asyrand": "omitted on authenticated memory; READY/DECISION retained",
                                         "grandline": "no outer signatures on authenticated channels; native DLEQ/pairing and signed APVSS contribution retained",
                                         "spurt": "no outer signatures on authenticated channels; native BEACON signature retained; verification cached per node"},
                    limitations=["Single-host memory transport, not WAN or published-paper results",
                                 "Different native proof/certificate policies; results include their costs",
                                 "GRandLine simulated offline setup is excluded from throughput",
                                 "SPURT full view change absent; no Byzantine faults injected"],
                    quorum_by_nodes={str(n): dict(f=(n-1)//3, asyrand_cert=n-(n-1)//3,
                                                 spurt_votes=n-(n-1)//3,
                                                 reconstruction=(n-1)//3+1) for n in args.nodes},
                    manuscript_sha256=optional_file_hash(ROOT/"paper/Asyrand.tex"),
                    source_sha256={m: source_hash(m) for m in MODULES})
    if platform.system() == "Darwin":
        metadata.update(cpu=command(["sysctl", "-n", "machdep.cpu.brand_string"]),
                        logical_cpus=int(command(["sysctl", "-n", "hw.logicalcpu"])),
                        memory_bytes=int(command(["sysctl", "-n", "hw.memsize"])))
    for module in ("asyrand", "grandline", "spurt"):
        command(["go", "build", "-o", str(out/"bin"/module), "./cmd/"+module], cwd=ROOT/module, env=env)
    metadata["binary_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (out/"bin").iterdir()}
    metadata["binary_formats"] = {p.name: command(["file", str(p)]) for p in (out/"bin").iterdir()}
    (out/"environment.json").write_text(json.dumps(metadata, indent=2)+"\n")
    (out/"runner.py").write_bytes(Path(__file__).read_bytes())
    (out/"parallel_stats.py").write_bytes((Path(__file__).parent/"parallel_stats.py").read_bytes())
    (out/"traffic_breakdown.py").write_bytes((Path(__file__).parent/"traffic_breakdown.py").read_bytes())
    with tarfile.open(out/"sources.tar.gz", "w:gz") as archive:
        for module in MODULES:
            for path in sorted((ROOT/module).rglob("*.go")):
                archive.add(path, arcname=str(path.relative_to(ROOT)))
            for name in ("go.mod", "go.sum"):
                if (ROOT/module/name).exists(): archive.add(ROOT/module/name, arcname=f"{module}/{name}")
    rows, metrics, traffic_rows, type_rows = [], [], [], []
    total = args.warmup+args.intervals+1
    for n in args.nodes:
        for repeat in range(1, args.repeats+1):
            shift = (repeat-1) % len(variants)
            for variant, module, parallel in variants[shift:]+variants[:shift]:
                tag = f"{variant}_n{n}_r{repeat}"
                cfg = make_config(module, n, repeat, parallel, args, out.name)
                conf, log, history = (out/(tag+suffix) for suffix in (".json", ".log", ".history.json"))
                conf.write_text(json.dumps(cfg, indent=2)+"\n")
                cmd = [str(out/"bin"/module), "-config", str(conf)]
                if module == "asyrand": cmd += ["-history", str(history)]
                print(f"START {tag} outputs={total}", flush=True)
                started = time.monotonic()
                with log.open("w") as stream:
                    try:
                        p = subprocess.run(cmd, cwd=ROOT/module, env=env, stdout=stream,
                                           stderr=subprocess.STDOUT, timeout=1800)
                        code = p.returncode
                    except subprocess.TimeoutExpired:
                        code = -1
                wall = time.monotonic()-started
                data = log.read_text()
                packets = re.findall(r"^ts=(\S+) epoch=(\d+) .*random=", data, re.M)
                first = 1 if module == "asyrand" else 0
                error = ""
                if code or " skipped " in data or [int(e) for _, e in packets] != list(range(first, first+total)):
                    error = f"failed(exit={code}, outputs={len(packets)})"
                if module == "asyrand" and f"verification valid_epochs={total}" not in data:
                    error += " failed(public verification)"
                if error:
                    (out/(tag+".failure.json")).write_text(json.dumps(dict(status=error, wall_s=wall), indent=2))
                    raise RuntimeError(f"{tag}: {error}; see {log}")
                final, full = fields(data, "final metrics"), fields(data, "run metrics")
                if int(final["beacons"]) != args.intervals or int(full["beacons"]) != total-1:
                    raise RuntimeError(f"mismatched byte/throughput window: {log}")
                if module in ("grandline", "spurt"):
                    for window in (final, full):
                        if int(window["message_signs"]) or int(window["message_verifies"]):
                            raise RuntimeError(f"unexpected outer signatures: {log}")
                    native = ("sign_avg", "verify_avg", "recover_avg") if module == "grandline" else ("beacon_sign_avg", "beacon_verify_avg")
                    if any(full[k] == "0s" for k in native):
                        raise RuntimeError(f"missing native cryptographic work: {log}")
                row = dict(variant=variant, nodes=n, f=cfg["f"], repeat=repeat, warmup=args.warmup,
                           intervals=args.intervals, **window_timing(data, args.warmup, args.intervals),
                           post_sent_bytes=int(final["sent_bytes"]),
                           post_sent_kib_per_beacon=int(final["sent_bytes"])/1024/args.intervals,
                           full_sent_bytes=int(full["sent_bytes"]),
                           full_sent_kib_per_beacon=int(full["sent_bytes"])/1024/(total-1),
                           post_sent_msgs=int(final["sent_msgs"]),
                           post_sent_msgs_per_beacon=int(final["sent_msgs"])/args.intervals,
                           post_message_signs=int(final["message_signs"]) if "message_signs" in final else "",
                           post_message_verifies=int(final["message_verifies"]) if "message_verifies" in final else "",
                           post_aba_sent_pct=float(fields(data, "final aba_metrics")["aba_sent_pct"]) if module == "asyrand" else "",
                           verified_epochs=total if module == "asyrand" else "", wall_s=wall, log=log.name)
                row.update(post_sent_kib_s=row["post_sent_bytes"]/1024/row["elapsed_s"],
                           post_sent_mib_s=row["post_sent_bytes"]/2**20/row["elapsed_s"],
                           post_producer_sent_pct="", post_consumer_sent_pct="", post_history_sent_pct="")
                if module == "asyrand":
                    h = json.loads(history.read_text())
                    if not all("ALBATROSS" in o["transcript"]["version"] for o in h["genesis"]["objects"]):
                        raise RuntimeError("unexpected AsyRand PVSS scheme")
                    for label, window in (("final", final), ("run", full)):
                        counts, types = classify(data, label, int(window["sent_bytes"]))
                        aba = fields(data, label+" aba_metrics")
                        if counts["aba"] != int(aba["aba_bytes"]):
                            raise RuntimeError("ABA accounting differs from runner counters")
                        elapsed = float(window["elapsed_s"])
                        for category, amount in counts.items():
                            traffic_rows.append(dict(variant=variant, nodes=n, repeat=repeat, window=label,
                                category=category, sent_bytes=amount, pct_of_total=100*amount/counts["total"],
                                sent_kib_s=amount/1024/elapsed, sent_mib_s=amount/2**20/elapsed,
                                sent_kib_per_beacon=amount/1024/int(window["beacons"])))
                        for name, values in types.items():
                            type_rows.append(dict(variant=variant, nodes=n, repeat=repeat, window=label,
                                message_type=name, category=message_category(name), **values))
                        if label == "final":
                            row.update(post_aba_sent_pct=100*counts["aba"]/counts["total"],
                                post_producer_sent_pct=100*counts["producer"]/counts["total"],
                                post_consumer_sent_pct=100*counts["consumer"]/counts["total"],
                                post_history_sent_pct=100*counts["history_recovery"]/counts["total"])
                rows.append(row)
                for label in ("final metrics", "run metrics"):
                    metrics += [dict(variant=variant, nodes=n, repeat=repeat, record=label, metric=k, value=v)
                                for k, v in fields(data, label).items()]
                write_csv(out/"results.csv", rows)
                write_csv(out/"summary.csv", summary(rows))
                write_csv(out/"runner_metrics.csv", metrics)
                if traffic_rows:
                    write_csv(out/"asyrand_traffic.csv", traffic_rows)
                    write_csv(out/"message_types.csv", type_rows)
                print(f"OK {tag}: {row['beacon_s']:.3f} beacon/s, {row['post_sent_kib_per_beacon']:.3f} post KiB/beacon, wall={wall:.1f}s", flush=True)
    if any(source_hash(m) != digest for m, digest in metadata["source_sha256"].items()):
        raise RuntimeError("Go sources changed during measurements")
    if optional_file_hash(ROOT/"paper/Asyrand.tex") != metadata["manuscript_sha256"]:
        raise RuntimeError("manuscript changed during measurements")
    (out/"validation.json").write_text(json.dumps(dict(successful_runs=len(rows), expected_runs=len(variants)*len(args.nodes)*args.repeats,
                                                    all_epochs_contiguous=True, all_members_agree=True,
                                                    public_verified_asyrand_epochs=sum(r["verified_epochs"] for r in rows if r["verified_epochs"]),
                                                    grandline_spurt_outer_signature_counts_zero=True,
                                                    native_cryptographic_operations_retained=True,
                                                    asyrand_classified_bytes_equal_total=True,
                                                    asyrand_producer_plus_consumer_equals_total=True,
                                                    asyrand_aba_classification_matches_runner=True,
                                                    throughput_uses_monotonic_clock=True,
                                                    suspect_utc_logs=[r["log"] for r in rows if r["wallclock_timing_suspect"]],
                                                    manuscript_unchanged=True, source_hashes_unchanged=True), indent=2)+"\n")
    print("Saved " + str(out), flush=True)


if __name__ == "__main__":
    main()
