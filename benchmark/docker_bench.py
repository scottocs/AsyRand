"""Docker beacon campaign; stdlib only. Run on the Linux Docker host.

One isolated container per node, Silk's exact uniform netem profile, bounded
resources, durable per-node logs, cross-node output validation, resumable cells.
"""
import argparse
import csv
import hashlib
import json
import ipaddress
import os
import re
import statistics
import subprocess
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LABEL = "tyche.benchmark"
NETWORK = dict(profile="docker-netem-uniform-v1", bandwidth_mbps=1000,
               delay_distribution="uniform", delay_min_ms=10, delay_max_ms=30,
               loss_percent=0, reorder_percent=0, duplicate_percent=0,
               seed_policy="run-seed-plus-node-id-v1")
RESOURCES = dict(cpu_cores_per_node=1, memory_mib_per_node=2048,
                 memory_swap_mib_per_node=2048, one_container_per_node=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def command(*args, check=True, timeout=120):
    p = subprocess.run([str(a) for a in args], text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{args[:3]}: {p.stderr[-3000:]} {p.stdout[-1000:]}")
    return p


def docker(*args, **kw):
    return command("docker", *args, **kw)


def netem_seed(seed, node):
    raw = f"run-seed-plus-node-id-v1:{seed}:{node}".encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:4], "big") or 1


def mac(ip):
    return "02:42:" + ":".join(f"{int(v):02x}" for v in ip.split("."))


def isolated_subnet(network, occupied):
    start = hashlib.sha256(network.encode()).digest()[0] % 224
    for offset in range(224):
        subnet = ipaddress.ip_network(f"172.30.{16+(start+offset)%224}.0/24")
        if not any(subnet.version == other.version and subnet.overlaps(other) for other in occupied):
            return str(subnet)
    raise RuntimeError("no unoccupied Silk /24 Docker subnet")


def config(protocol, n, epochs, seed, ips, epoch_timeout_ms, production_window=8):
    members = [f"node{i}" for i in range(n)]
    return dict(name=f"docker-{protocol}-n{n}-s{seed}", protocol={
        "spurt": "spurt-v1", "grandline": "grandline", "asyrand": "asyrand-v2"}[protocol],
        transport="tcp", authenticated_tcp=True, f=(n-1)//3, round=epochs,
        listen_ip="0.0.0.0", prefill_ms=3000, epoch_timeout_ms=epoch_timeout_ms,
        report_interval_ms=60000, linger_ms=86400000, max_pool=1,
        batch_size=1, warmup_outputs=0, aggregation_lookahead=8,
        production_window=production_window, parallel_consumption=True, transport_buffer=16384,
        log_level=1, session_id=f"docker-{n}-{seed}",
        seed=hashlib.sha256(f"benchmark-{n}-{seed}".encode()).hexdigest(),
        cluster_index={v:i for i,v in enumerate(members)},
        cluster_ips={v:ips[i] for i,v in enumerate(members)},
        peers_p2p_port={v:9000 for v in members},
        node_key_seed={v:hashlib.sha256(f"docker-node-{seed}-{i}".encode()).hexdigest()
                       for i,v in enumerate(members)})


def validate(logs, n, epochs, protocol):
    reports, reference, rates = [], None, []
    for i in range(n):
        text = logs[i]
        outputs = [(int(e), r) for e,r in re.findall(r"ts=\S+[^\n]*?epoch=(\d+)[^\n]*? random=([0-9a-f]+)", text)]
        first_epoch = 1 if protocol == "asyrand" else 0
        errors = []
        if [e for e,_ in outputs] != list(range(first_epoch, first_epoch+epochs)):
            errors.append("missing, duplicate or non-contiguous outputs")
        if reference is None:
            reference = outputs
        elif outputs != reference:
            errors.append("output mismatch across nodes")
        if f"benchmark_complete outputs={epochs}" not in text:
            errors.append("missing durable completion marker")
        if protocol == "asyrand" and f"verification valid_epochs={epochs} " not in text:
            errors.append("missing public history verification")
        final = re.findall(r"^final metrics (.+)$", text, re.M)
        metrics = dict(re.findall(r"(\w+)=([^\s]+)", final[-1])) if final else {}
        if not metrics or int(metrics.get("beacons", -1)) != epochs-1:
            errors.append("invalid inter-output measurement window")
        elapsed = float(metrics.get("elapsed_s", 0))
        rate = (epochs-1)/elapsed if elapsed > 0 else 0
        if rate <= 0:
            errors.append("nonpositive throughput")
        rates.append(rate)
        reports.append(dict(node=i, outputs=len(outputs), errors=errors,
                            metrics=metrics, throughput_outputs_per_second=rate))
    return dict(run_valid=all(not r["errors"] for r in reports), nodes=reports,
                requested_outputs_per_node=epochs, measured_intervals_per_node=epochs-1,
                throughput_median_node=statistics.median(rates),
                throughput_slowest_node=min(rates), checked_at=now())


def parallel(fn, items, workers=16):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


def cleanup(names, network):
    # Names are generated exclusively for this cell. Never prune shared Docker.
    if names:
        parallel(lambda name: docker("rm", "-f", name, check=False), names)
    docker("network", "rm", network, check=False)
    remaining = docker("ps", "-aq", "--filter", f"label={LABEL}.cell={network}").stdout.strip()
    net = docker("network", "ls", "-q", "--filter", f"label={LABEL}.cell={network}").stdout.strip()
    if remaining or net:
        raise RuntimeError("cell resources did not terminate")


def run_cell(args, campaign, protocol, n, rep):
    cell_id = f"{protocol}-n{n}-r{rep}"
    out = campaign / cell_id
    previous = out / "validation.json"
    if previous.exists() and json.loads(previous.read_text()).get("run_valid"):
        print(f"{now()} resume validated {cell_id}", flush=True)
        return json.loads(previous.read_text())
    if out.exists():
        raise RuntimeError(f"unvalidated existing cell {out}; preserve it and select a new campaign or archive the cell before retrying")
    out.mkdir(parents=True)
    token = hashlib.sha256(str(out).encode()).hexdigest()[:12]
    network = f"tyche-{token}"
    names = [f"{network}-node{i}" for i in range(n)]
    seed = rep
    # Match Silk's /24 address and fixed MAC assignment; labels isolate cleanup.
    ids = docker("network", "ls", "-q").stdout.split()
    networks = json.loads(docker("network", "inspect", *ids).stdout) if ids else []
    occupied = [ipaddress.ip_network(cfg["Subnet"]) for item in networks
                for cfg in (item.get("IPAM", {}).get("Config") or []) if cfg.get("Subnet")]
    subnet = isolated_subnet(network, occupied)
    octet = int(subnet.split(".")[2])
    ips = [f"172.30.{octet}.{10+i}" for i in range(n)]
    cfg = config(protocol, n, args.epochs, seed, ips, args.epoch_timeout_ms,
                 production_window=args.asyrand_production_window if protocol == "asyrand" else 8)
    if protocol == "asyrand" and args.asyrand_recovery_interval_ms:
        cfg["recovery_interval_ms"] = args.asyrand_recovery_interval_ms
    write_json(out / "config.json", cfg)
    manifest = dict(cell=cell_id, protocol=protocol, n=n, f=cfg["f"], seed=seed,
                    epochs=args.epochs, repetition=rep, image=args.image,
                    network=NETWORK, resources=RESOURCES, subnet=subnet,
                    transport="mutual-tls-1.3-pinned-ed25519", started_at=now(),
                    runtime_policy=dict(go_memory_limit=args.go_memory_limit or "default",
                        asyrand_recovery_interval_ms=cfg.get("recovery_interval_ms",1000)),
                    image_id=json.loads(docker("image", "inspect", args.image).stdout)[0]["Id"],
                    source=(json.loads((ROOT/"source-manifest.json").read_text())
                        if (ROOT/"source-manifest.json").exists() else
                        dict(git_commit=command("git", "-C", ROOT, "rev-parse", "HEAD", check=False).stdout.strip())),
                    completion_policy="all-participants-durable", status="preparing")
    if protocol == "asyrand":
        manifest["runtime_policy"]["asyrand_production_window"] = cfg["production_window"]
    write_json(out / "manifest.json", manifest)
    write_json(campaign/"status.json", dict(state="running", cell=cell_id, pid=os.getpid(), updated_at=now()))
    print(f"{now()} start {cell_id} outputs={args.epochs}", flush=True)
    created = []
    try:
        if protocol == "grandline":
            # Offline common setup is excluded from measured beacon execution.
            setup = docker("run", "--rm", "--network", "none", "--cpus", "4", "--memory", "8g",
                "--label", f"{LABEL}.campaign={campaign.name}",
                "-v", f"{out}:/results", "--entrypoint", "/opt/tyche/bin/grandline", args.image,
                "-config", "/results/config.json", "-write-setup", "/results/setup.json", timeout=7200)
            (out/"setup.log").write_text(setup.stdout+setup.stderr)
        docker("network", "create", "--subnet", subnet, "--label", f"{LABEL}.cell={network}", network)
        for i,name in enumerate(names):
            node = out/f"node{i}"
            node.mkdir()
            neighbors = "\n".join(f"{ip}|{mac(ip)}" for j,ip in enumerate(ips) if i != j)
            cmd = ["create", "--name", name, "--network", network, "--ip", ips[i],
                   "--mac-address", mac(ips[i]), "--label", f"{LABEL}.cell={network}",
                   "--label", f"{LABEL}.campaign={campaign.name}", "--cap-add", "NET_ADMIN",
                   "--cpus", "1", "--memory", "2048m", "--memory-swap", "2048m",
                   "--log-driver", "json-file", "--log-opt", "max-size=100m", "--log-opt", "max-file=3",
                   "-e", "GOMAXPROCS=1", "-e", f"NETEM_SEED={netem_seed(seed,i)}",
                   "-e", f"NODE_NEIGHBORS={neighbors}",
                   "-v", f"{node}:/results", "-v", f"{out}:/control:ro",
                   args.image, f"/opt/tyche/bin/{protocol}", "-config", "/control/config.json",
                   "-node", f"node{i}", "-transport", "tcp"]
            if protocol == "grandline":
                cmd += ["-setup-file", "/control/setup.json"]
            if protocol == "asyrand":
                cmd += ["-history", "/results/history.json"]
            if args.go_memory_limit:
                cmd[1:1] = ["-e", f"GOMEMLIMIT={args.go_memory_limit}"]
            docker(*cmd)
            created.append(name)
        parallel(lambda name: docker("start", name), names)
        ready_deadline = time.monotonic()+180
        while not all((out/f"node{i}"/"ready").exists() for i in range(n)):
            if time.monotonic() > ready_deadline:
                raise RuntimeError("netem/container readiness timeout")
            time.sleep(1)
        inspections = json.loads(docker("inspect", *names).stdout)
        write_json(out/"containers-start.json", inspections)
        for c in inspections:
            h = c["HostConfig"]
            if h["NanoCpus"] != 1000000000 or h["Memory"] != 2147483648 or h["MemorySwap"] != 2147483648:
                raise RuntimeError("Docker did not apply required resource limits")
        manifest["protocol_released_at"] = now()
        manifest["status"] = "running"
        write_json(out/"manifest.json", manifest)
        (out/"start").touch()
        deadline = time.monotonic()+args.timeout_seconds
        last_report = 0
        logs = []
        while True:
            logs = parallel(lambda name: docker("logs", name).stdout, names)
            done = sum(f"benchmark_complete outputs={args.epochs}" in s for s in logs)
            progress = [max([int(x) for x in re.findall(r"ts=\S+[^\n]*?epoch=(\d+)", s)] or [-1]) for s in logs]
            if done == n:
                break
            states = json.loads(docker("inspect", *names).stdout)
            failed = [(i,c["State"]) for i,c in enumerate(states) if not c["State"]["Running"]]
            if failed:
                raise RuntimeError(f"nodes exited before completion: {failed}")
            if time.monotonic() > deadline:
                raise RuntimeError(f"cell timeout; progress={progress}")
            if time.monotonic()-last_report >= 600:
                print(f"{now()} progress {cell_id} completed={done}/{n} epochs={min(progress)}..{max(progress)}", flush=True)
                write_json(out/"progress.json", dict(checked_at=now(), completed=done, epochs=progress))
                last_report = time.monotonic()
            # Smoke runs can opt into shorter polling than the formal matrix.
            time.sleep(args.poll_seconds)
        for i,s in enumerate(logs):
            (out/f"node{i}"/"stdout.log").write_text(s)
        evidence = parallel(lambda name: docker("exec", name, "sh", "-c",
            "tc -s -details qdisc show dev eth0; cat /sys/class/net/eth0/statistics/tx_bytes /sys/class/net/eth0/statistics/rx_bytes; cat /sys/fs/cgroup/cpu.stat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events", check=False).stdout, names)
        for i,s in enumerate(evidence):
            (out/f"node{i}"/"resource-network.txt").write_text(s)
        write_json(out/"containers-final.json", json.loads(docker("inspect", *names).stdout))
        report = validate(logs, n, args.epochs, protocol)
        report.update(protocol=protocol, n=n, repetition=rep)
        write_json(previous, report)
        if not report["run_valid"]:
            raise RuntimeError("node output validation failed; inspect validation.json")
        manifest.update(status="complete", finished_at=now())
        write_json(out/"manifest.json", manifest)
        print(f"{now()} valid {cell_id} rate={report['throughput_median_node']:.6f} output/s", flush=True)
        return report
    except Exception:
        manifest.update(status="failed", finished_at=now(), error=traceback.format_exc())
        write_json(out/"manifest.json", manifest)
        for i,name in enumerate(created):
            p = docker("logs", name, check=False)
            (out/f"node{i}"/"stdout.log").write_text(p.stdout)
            (out/f"node{i}"/"stderr.log").write_text(p.stderr)
        raise
    finally:
        cleanup(created, network)
        write_json(out/"cleanup.json", dict(verified_terminated=True, checked_at=now()))


def summarize(campaign):
    rows = []
    for f in sorted(campaign.glob("*/validation.json")):
        r = json.loads(f.read_text())
        if r.get("run_valid"):
            rows.append({k:r[k] for k in ("protocol", "n", "repetition", "throughput_median_node", "throughput_slowest_node", "requested_outputs_per_node")})
    if rows:
        with (campaign/"results.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--campaign", required=True)
    p.add_argument("--nodes", default="7,16,31,61")
    p.add_argument("--protocols", default="spurt,grandline,asyrand")
    p.add_argument("--epochs", type=int, default=200)
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--image", default="tyche-benchmark:latest")
    p.add_argument("--epoch-timeout-ms", type=int, default=600000)
    p.add_argument("--timeout-seconds", type=int, default=43200)
    p.add_argument("--poll-seconds", type=int, default=60)
    p.add_argument("--asyrand-production-window", type=int, default=8,
                   help="AsyRand producer look-ahead window W >= 2; default 8")
    p.add_argument("--asyrand-recovery-interval-ms", type=int, default=0,
                   help="AsyRand passive recovery polling interval; 0 uses protocol default")
    p.add_argument("--go-memory-limit", default="",
                   help="Go soft heap budget, e.g. 1400MiB; Docker hard quota stays 2 GiB")
    args = p.parse_args()
    ns = [int(v) for v in args.nodes.split(",")]
    ps = args.protocols.split(",")
    if not set(ps) <= {"spurt", "grandline", "asyrand"} or any(n < 7 or n > 190 for n in ns) or args.epochs < 2 or args.asyrand_production_window < 2:
        p.error("invalid protocol, node count or output count")
    campaign = (ROOT/"benchmark"/"runs"/args.campaign).resolve()
    campaign.mkdir(parents=True, exist_ok=True)
    # Lock is a live process lock, not a stale-state guess.
    import fcntl
    lock = (campaign/"campaign.lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    write_json(campaign/"campaign.json", dict(arguments=vars(args), started_at=now(),
        expected_cells=len(ns)*len(ps)*args.repetitions, pid=os.getpid(),
        network=NETWORK, resources=RESOURCES, docker_version=docker("version", "--format", "{{.Server.Version}}").stdout.strip()))
    try:
        for n in ns:
            for protocol in ps:
                for rep in range(1,args.repetitions+1):
                    run_cell(args, campaign, protocol, n, rep)
                    summarize(campaign)
        rows = summarize(campaign)
        write_json(campaign/"status.json", dict(state="complete", valid_cells=len(rows), updated_at=now(), pid=os.getpid()))
    except Exception:
        summarize(campaign)
        write_json(campaign/"status.json", dict(state="failed", error=traceback.format_exc(), updated_at=now(), pid=os.getpid()))
        raise


if __name__ == "__main__":
    main()
