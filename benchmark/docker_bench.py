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


def timestamp(value):
    value=re.sub(r"\.(\d+)",lambda m:"."+m[1][:6].ljust(6,"0"),value.replace("Z","+00:00"))
    return datetime.fromisoformat(value)


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


class CryptoBudget:
    """A task-only threaded CPU child; the Docker parent retains RAM/CPU limits."""
    def __init__(self, args, network, out):
        self.args, self.network, self.out = args, network, out
        self.enabled = args.crypto_cpu_percent > 0
        # A hyphen has hierarchy semantics in a systemd slice unit name.
        self.slice = network.replace('-', '')+'.slice'
        self.path = Path('/sys/fs/cgroup')/self.slice
        self.holder = f"{network}-budget-holder"
        self.children = []
        self.held = False
        self.quota = round(args.cpu_cores*args.crypto_cpu_percent/100*10000)

    def helper(self, script):
        return docker('run','--rm','--network','none','--cpus','0.2','--memory','64m',
            '--label',f'{LABEL}.maintenance={self.network}',
            '--mount',f'type=bind,src={self.path},dst=/budget',
            '--entrypoint','sh',self.args.image,'-ec',script).stdout

    def prepare(self):
        if not self.enabled: return
        if self.path.exists(): raise RuntimeError(f'preserve existing task slice {self.path}')
        docker('run','-d','--name',self.holder,'--network','none','--cpus','0.01','--memory','32m',
            '--cgroup-parent',self.slice,'--label',f'{LABEL}.maintenance={self.network}',
            '--entrypoint','sleep',self.args.image,'infinity')
        self.held = True
        if not self.path.is_dir(): raise RuntimeError('Docker did not create the dedicated task slice')

    def options(self, i):
        if not self.enabled: return []
        return ['--cgroup-parent',self.slice,
            '--mount',f'type=bind,src={self.path},dst=/tyche-cgroups',
            '-e',f'TYCHE_CRYPTO_CGROUP_CONFIG=/control/node{i}/crypto-group.json']

    def configure(self, containers):
        if not self.enabled: return
        records=[]
        for i,c in enumerate(containers):
            lines=Path(f'/proc/{c["State"]["Pid"]}/cgroup').read_text().splitlines()
            path=Path(next(line[3:] for line in lines if line.startswith('0::')))
            if path.parent != Path('/')/self.slice or path.name != f'docker-{c["Id"]}.scope':
                raise RuntimeError(f'unexpected container cgroup {path}')
            scope=path.name
            self.children.append(scope)
            self.helper(f'mkdir /budget/{scope}/crypto; echo threaded > /budget/{scope}/crypto/cgroup.type; '
                f'echo +cpu > /budget/{scope}/cgroup.subtree_control; '
                f'echo "{self.quota} 10000" > /budget/{scope}/crypto/cpu.max')
            base=f'/tyche-cgroups/{scope}'
            write_json(self.out/f'node{i}/crypto-group.json',dict(threads=base+'/crypto/cgroup.threads',
                parent_threads=base+'/cgroup.threads',stat=base+'/crypto/cpu.stat',max=base+'/crypto/cpu.max',workers=self.args.crypto_workers))
            records.append(dict(node=i,container_id=c['Id'],scope=scope,
                type=(self.path/scope/'cgroup.type').read_text().strip(),
                crypto_type=(self.path/scope/'crypto/cgroup.type').read_text().strip(),
                cpu_max=(self.path/scope/'crypto/cpu.max').read_text().strip()))
        if any(r['type']!='domain threaded' or r['crypto_type']!='threaded' or r['cpu_max']!=f'{self.quota} 10000' for r in records):
            raise RuntimeError('threaded crypto CPU quota was not applied')
        write_json(self.out/'crypto-budget-start.json',dict(percent=self.args.crypto_cpu_percent,
            cores=self.quota/10000,period_us=10000,nodes=records))

    def capture(self):
        if not self.enabled: return
        records=[]
        for i,scope in enumerate(self.children):
            base=self.path/scope/'crypto'
            records.append(dict(node=i,cpu_max=(base/'cpu.max').read_text().strip(),
                cpu_stat=(base/'cpu.stat').read_text(),threads=(base/'cgroup.threads').read_text()))
        if any(r['cpu_max']!=f'{self.quota} 10000' for r in records): raise RuntimeError('crypto quota changed')
        write_json(self.out/'crypto-budget-final.json',dict(nodes=records,checked_at=now()))

    def stop_children(self, names):
        if not self.enabled or not self.held: return
        parallel(lambda name:docker('stop','-t','2',name,check=False),names)
        for scope in self.children:
            self.helper(f'if [ -d /budget/{scope}/crypto ]; then rmdir /budget/{scope}/crypto; fi')

    def close(self):
        if not self.held: return
        docker('rm','-f',self.holder)
        self.held=False
        # systemd can retain an empty transient slice. Never remove a populated one.
        remaining=list(self.path.glob('docker-*.scope')) if self.path.exists() else []
        if remaining: raise RuntimeError('task CPU scopes remain after cleanup')
        write_json(self.out/'crypto-budget-cleanup.json',dict(verified_terminated=True,
            slice=self.slice,remaining_scopes=0,checked_at=now()))


def run_cell(args, campaign, protocol, n, rep):
    series = protocol
    window = args.asyrand_production_window
    adaptive=protocol=='asyrand-adaptive-w8'
    if protocol in ("asyrand-w2", "asyrand-w8",'asyrand-adaptive-w8'):
        window = int(protocol.rsplit("w",1)[1])
        protocol = "asyrand"
    cell_id = f"{series}-n{n}-r{rep}"
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
                 production_window=window if protocol == "asyrand" else 8)
    cfg["max_pool"] = args.crypto_workers
    if adaptive:cfg.update(adaptive_production_window=True,production_window_min=2)
    if protocol == "asyrand" and args.asyrand_recovery_interval_ms:
        cfg["recovery_interval_ms"] = args.asyrand_recovery_interval_ms
    write_json(out / "config.json", cfg)
    manifest = dict(cell=cell_id, protocol=protocol, series=series, n=n, f=cfg["f"], seed=seed,
                    epochs=args.epochs, repetition=rep, image=args.image,
                    network=NETWORK, resources=RESOURCES, subnet=subnet,
                    transport="mutual-tls-1.3-pinned-ed25519", started_at=now(),
                    runtime_policy=dict(go_memory_limit=args.go_memory_limit or "default",
                        gomaxprocs=args.go_max_procs, crypto_workers=args.crypto_workers,
                        asyrand_recovery_interval_ms=cfg.get("recovery_interval_ms",1000)),
                    image_id=json.loads(docker("image", "inspect", args.image).stdout)[0]["Id"],
                    source=(json.loads((ROOT/"source-manifest.json").read_text())
                        if (ROOT/"source-manifest.json").exists() else
                        dict(git_commit=command("git", "-C", ROOT, "rev-parse", "HEAD", check=False).stdout.strip())),
                    completion_policy="all-participants-durable", status="preparing")
    if protocol == "asyrand":
        manifest["runtime_policy"]["asyrand_production_window"] = cfg["production_window"]
    if args.measure_generation:
        start_count = args.warmup_outputs or 1
        manifest["measurement"] = dict(scope=f"output-{start_count}-to-output-{args.epochs}",
            start_output_count=start_count,end_output_count=args.epochs,
            warmup_outputs=args.warmup_outputs,intervals=args.epochs-start_count,
            communication="network-only application-frame Tx; excludes self-delivery and TLS/TCP overhead",
            cpu="cgroup usage_usec delta in the identical output window",profile_node="node0")
    write_json(out / "manifest.json", manifest)
    write_json(campaign/"status.json", dict(state="running", cell=cell_id, pid=os.getpid(), updated_at=now()))
    print(f"{now()} start {cell_id} outputs={args.epochs}", flush=True)
    created = []
    budget = CryptoBudget(args,network,out)
    try:
        budget.prepare()
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
                   "--cpus", str(args.cpu_cores), "--memory", f"{args.memory_mib}m", "--memory-swap", f"{args.memory_mib}m",
                   "--log-driver", "json-file", "--log-opt", "max-size=100m", "--log-opt", "max-file=3",
                   "-e", f"GOMAXPROCS={args.go_max_procs}",
                   "-e", f"TYCHE_CRYPTO_PARALLELISM={args.crypto_parallelism}", "-e", f"NETEM_SEED={netem_seed(seed,i)}",
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
            cmd[1:1] = budget.options(i)
            if args.measure_generation:
                cmd[1:1] = ["-e","TYCHE_BENCHMARK=1","-e","TYCHE_PROFILE_NODE=node0",
                    "-e",f"TYCHE_BENCHMARK_NODE=node{i}","-e","TYCHE_BENCHMARK_DIR=/results",
                    "-e","TYCHE_VERIFY_BARRIER=/control/verify-start"]
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
        budget.configure(inspections)
        for c in inspections:
            h = c["HostConfig"]
            if h["NanoCpus"] != round(args.cpu_cores*1e9) or h["Memory"] != args.memory_mib*2**20 or h["MemorySwap"] != args.memory_mib*2**20:
                raise RuntimeError("Docker did not apply required resource limits")
        manifest["protocol_released_at"] = now()
        manifest["status"] = "running"
        write_json(out/"manifest.json", manifest)
        (out/"start").touch()
        deadline = time.monotonic()+args.timeout_seconds
        last_report = 0
        last_poll = 0
        logs = []
        while True:
            if args.measure_generation and not (out/"verify-start").exists() and all((out/f"node{i}"/"generation-complete").exists() for i in range(n)):
                write_json(out/"generation-barrier.json",dict(all_nodes_measured=True,checked_at=now()))
                (out/"verify-start").touch()
            complete = args.measure_generation and all((out/f"node{i}"/"benchmark-complete").exists() for i in range(n))
            if not complete and time.monotonic()-last_poll < args.poll_seconds:
                # Local marker checks release the generation barrier promptly;
                # Docker/log inspection can remain at the ten-minute cadence.
                time.sleep(min(1, args.poll_seconds))
                continue
            last_poll = time.monotonic()
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
            time.sleep(min(1, args.poll_seconds))
        for i,s in enumerate(logs):
            (out/f"node{i}"/"stdout.log").write_text(s)
        evidence = parallel(lambda name: docker("exec", name, "sh", "-c",
            "tc -s -details qdisc show dev eth0; cat /sys/class/net/eth0/statistics/tx_bytes /sys/class/net/eth0/statistics/rx_bytes; cat /sys/fs/cgroup/cpu.stat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events", check=False).stdout, names)
        for i,s in enumerate(evidence):
            (out/f"node{i}"/"resource-network.txt").write_text(s)
        final_containers=json.loads(docker("inspect", *names).stdout)
        write_json(out/"containers-final.json", final_containers)
        budget.capture()
        if any(c["State"].get("OOMKilled") for c in final_containers):
            raise RuntimeError("OOM in completed cell")
        for i,text in enumerate(evidence):
            if not re.search(r"(?m)^usage_usec \d+$",text) or "netem" not in text or not re.search(r"(?m)^oom_kill 0$",text):
                raise RuntimeError(f"missing final CPU/network/OOM records at node{i}")
        report = validate(logs, n, args.epochs, protocol)
        report.update(protocol=protocol, series=series, n=n, repetition=rep)
        if args.measure_generation:
            # Protocol generation has stopped after the common barrier. Return
            # this cell's mounted output files to its invoking Linux user.
            docker("run","--rm","--network","none","--cpus","1","--memory","128m",
                "--label",f"{LABEL}.maintenance={campaign.name}","-v",f"{out}:/results",
                "--entrypoint","chown",args.image,"-R",f"{os.getuid()}:{os.getgid()}","/results")
            measured = generation_metrics(out,n,args.epochs)
            write_json(out/"generation-metrics.json",measured)
            report["measurement_scope"] = measured["scope"]
            # The protocol's legacy final line covers the whole run. Published
            # metrics use the same output-aligned post-warmup counters instead.
            rates = [m['throughput_outputs_per_second'] for m in measured['nodes']]
            report.update(measured_intervals_per_node=measured['nodes'][0]['intervals'],
                throughput_median_node=statistics.median(rates),throughput_slowest_node=min(rates),
                warmup_outputs=args.warmup_outputs,legacy_final_metrics_scope='output-1-to-output-N')
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
        # Capture OOM evidence before finally removes only this cell's resources.
        if created:
            snapshot = docker('inspect', *created, check=False)
            if snapshot.returncode == 0:
                states = json.loads(snapshot.stdout)
                write_json(out/'containers-failed.json', states)
                write_json(out/'failure-evidence.json', dict(
                    oom_killed=any(c['State'].get('OOMKilled',False) for c in states),
                    checked_at=now(), states=[c['State'] for c in states]))
        for i,name in enumerate(created):
            p = docker("logs", name, check=False)
            (out/f"node{i}"/"stdout.log").write_text(p.stdout)
            (out/f"node{i}"/"stderr.log").write_text(p.stderr)
        raise
    finally:
        try:
            budget.stop_children(created)
        finally:
            try: cleanup(created, network)
            finally: budget.close()
        write_json(out/"cleanup.json", dict(verified_terminated=True, checked_at=now()))


def summarize(campaign):
    rows = []
    for f in sorted(campaign.glob("*/validation.json")):
        r = json.loads(f.read_text())
        if r.get("run_valid"):
            rows.append({k:r[k] for k in ("protocol", "series", "n", "repetition", "throughput_median_node", "throughput_slowest_node", "requested_outputs_per_node")})
    if rows:
        with (campaign/"results.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    return rows


def generation_metrics(cell,n,epochs):
    rows=[]
    manifest=json.loads((cell/"manifest.json").read_text())
    cores=manifest["resources"]["cpu_cores_per_node"]
    start_count=manifest.get('measurement',{}).get('start_output_count',1)
    if not 1<=start_count<epochs:raise ValueError('invalid measurement boundary')
    for i in range(n):
        events=[json.loads(line) for line in (cell/f"node{i}/measurement.jsonl").read_text().splitlines()]
        expected=[1]+list(range(100,epochs,100))+[epochs]
        if [e["outputs"] for e in events]!=expected:
            raise ValueError(f"invalid measurement checkpoints at node{i}")
        a=next((e for e in events if e['outputs']==start_count),None)
        if a is None:raise ValueError(f'missing start checkpoint {start_count} at node{i}')
        b=events[-1]
        elapsed=(timestamp(b["time"])-timestamp(a["time"])).total_seconds()
        count=epochs-start_count;cpu=(b["cpu_usage_usec"]-a["cpu_usage_usec"])/1e6
        sent=b["traffic"]["SentBytes"]-a["traffic"]["SentBytes"]
        recv=b["traffic"]["RecvBytes"]-a["traffic"]["RecvBytes"]
        if min(elapsed,cpu,sent,recv)<=0:raise ValueError("invalid generation counters")
        rows.append(dict(node=i,outputs=epochs,intervals=count,elapsed_s=elapsed,throughput_outputs_per_second=count/elapsed,
            sent_kib_per_beacon_per_node=sent/count/1024,cpu_utilization_percent=cpu/elapsed*100/cores,
            cpu_ms_per_beacon=cpu/count*1000,received_kib_per_beacon_per_node=recv/count/1024,
            memory_peak_mib=int(b["memory_peak"])/2**20,memory_end_mib=int(b["memory_current"])/2**20))
        if a.get('crypto_cpu') is not None:
            crypto=b['crypto_cpu']['usage_usec']-a['crypto_cpu']['usage_usec']
            budget=json.loads((cell/'crypto-budget-start.json').read_text())['cores']
            if crypto <= 0 or crypto/1e6 > budget*elapsed+0.10 or crypto > cpu*1e6+20000:
                raise ValueError('invalid measured crypto CPU budget')
            rows[-1].update(crypto_cpu_ms_per_beacon=crypto/count/1000,
                crypto_cpu_percent=crypto/1e6/elapsed/cores*100,
                crypto_throttled_usec=b['crypto_cpu']['throttled_usec']-a['crypto_cpu']['throttled_usec'])
    scope=manifest.get('measurement',{}).get('scope','output-1-to-output-N')
    return dict(scope=scope,network_only=True,includes_self_delivery=False,nodes=rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--campaign", required=True)
    p.add_argument("--nodes", default="7,16,31,61")
    p.add_argument("--protocols", default="spurt,grandline,asyrand-w2,asyrand-w8")
    p.add_argument("--epochs", type=int, default=500)
    p.add_argument('--warmup-outputs',type=int,default=0,
                   help='Exclude the first W outputs using checkpoint W to N, W must be a multiple of 100')
    p.add_argument('--skip-oom-n80',action='store_true',help='Cancel remaining n80 cells after an n80 OOM')
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--image", default="tyche-benchmark:latest")
    p.add_argument("--epoch-timeout-ms", type=int, default=600000)
    p.add_argument("--timeout-seconds", type=int, default=43200)
    p.add_argument("--poll-seconds", type=int, default=60)
    p.add_argument("--cpu-cores",type=float,default=1,help="Per-node Docker CPU quota")
    p.add_argument("--memory-mib",type=int,default=2048,help="Per-node RAM quota; no extra swap")
    p.add_argument("--go-max-procs",type=int,default=1,help="Per-node Go scheduler parallelism")
    p.add_argument("--crypto-workers",type=int,default=1,help="Per-node cryptographic worker count")
    p.add_argument('--crypto-cpu-percent',type=float,default=0,help='Optional Linux threaded crypto CPU cap as percent of node quota')
    p.add_argument('--crypto-parallelism',type=int,default=1,help='Bounded independent proof partitions per cryptographic task')
    p.add_argument("--asyrand-production-window", type=int, default=8,
                   help="AsyRand producer look-ahead window W >= 2; default 8")
    p.add_argument("--measure-generation",action="store_true",
                   help="Record aligned online CPU/traffic checkpoints, node0 CPU profiles and an all-node verification barrier")
    p.add_argument("--asyrand-recovery-interval-ms", type=int, default=0,
                   help="AsyRand passive recovery polling interval; 0 uses protocol default")
    p.add_argument("--go-memory-limit", default="",
                   help="Go soft heap budget, e.g. 1400MiB; separate from Docker's RAM quota")
    args = p.parse_args()
    if args.warmup_outputs<0 or args.warmup_outputs>=args.epochs or args.warmup_outputs%100:
        p.error('warmup must be zero or a multiple of 100 smaller than total outputs')
    if not 0<=args.crypto_cpu_percent<=100 or not 1<=args.crypto_parallelism<=16:
        p.error('invalid crypto budget or parallelism')
    import math
    if not math.isfinite(args.cpu_cores) or args.cpu_cores<=0 or args.memory_mib<128 or min(args.go_max_procs,args.crypto_workers)<1:
        p.error("invalid CPU, memory or worker allocation")
    if args.poll_seconds < 1:
        p.error("poll interval must be positive")
    RESOURCES.update(cpu_cores_per_node=args.cpu_cores,memory_mib_per_node=args.memory_mib,memory_swap_mib_per_node=args.memory_mib)
    ns = [int(v) for v in args.nodes.split(",")]
    ps = args.protocols.split(",")
    if not set(ps) <= {"spurt", "grandline", "asyrand", "asyrand-w2", "asyrand-w8",'asyrand-adaptive-w8'} or any(n < 7 or n > 190 for n in ns) or args.epochs < 2 or args.asyrand_production_window < 2:
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
        skip80=False
        for n in ns:
            for rep in range(1,args.repetitions+1):
                offset=(rep-1)%len(ps)
                for protocol in ps[offset:]+ps[:offset]:
                    if n==80 and skip80:continue
                    try:
                        run_cell(args, campaign, protocol, n, rep)
                    except Exception:
                        failures=list(campaign.glob('*/failure-evidence.json'))
                        oom=any(json.loads(f.read_text()).get('oom_killed') and
                                json.loads((f.parent/'manifest.json').read_text())['n']==80 for f in failures)
                        if not (args.skip_oom_n80 and n==80 and oom):raise
                        skip80=True
                        write_json(campaign/'n80-cancelled.json',dict(reason='OOM',checked_at=now(),
                            policy='cancel all remaining n80 experiments; preserve failed evidence'))
                    summarize(campaign)
        rows = summarize(campaign)
        write_json(campaign/"status.json", dict(state="complete", valid_cells=len(rows),n80_cancelled=skip80,
            updated_at=now(), pid=os.getpid()))
    except Exception:
        summarize(campaign)
        write_json(campaign/"status.json", dict(state="failed", error=traceback.format_exc(), updated_at=now(), pid=os.getpid()))
        raise


if __name__ == "__main__":
    main()
