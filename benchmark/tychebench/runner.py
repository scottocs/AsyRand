import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from fabric import Connection

from .paths import REPO_ROOT, RUNS_DIR, ensure_layout
from .aws import load_settings, _instances
from .errors import BenchError


@dataclass(frozen=True)
class LocalOptions:
    n: int
    epochs: int
    protocols: list[str]
    out_root: Path
    fault_threshold: int
    grandline_fault_threshold: int
    queue_len: int = 8
    producer_ms: int = 250
    prefill_ms: int = 3000
    epoch_timeout_ms: int = 15000
    report_ms: int = 5000
    max_pool: int = 4
    aggregation_lookahead: int = 8
    gomaxprocs: int = 4


@dataclass(frozen=True)
class AwsHost:
    index: int
    region: str
    ip: str
    key_file: Path
    user: str


@dataclass(frozen=True)
class AwsOptions:
    n: int
    epochs: int
    protocols: list[str]
    out_root: Path
    generated_dir: Path
    local_bin_dir: Path
    key_file: Path
    remote_dir: str
    ssh_user: str | None
    fault_threshold: int
    grandline_fault_threshold: int
    base_port: int = 9000
    queue_len: int = 8
    producer_ms: int = 250
    prefill_ms: int = 8000
    epoch_timeout_ms: int = 60000
    report_ms: int = 5000
    linger_ms: int = 120000
    max_pool: int = 16
    aggregation_lookahead: int = 8
    gomaxprocs: int = 4
    startup_wait_sec: int | None = None
    ssh_connect_timeout: int = 30


def _split_csv(raw):
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def _timestamp():
    return time.strftime("%Y%m%d_%H%M%S")


def _go_executable():
    found = shutil.which("go")
    if not found:
        raise BenchError("go is required to run benchmarks, but it was not found on PATH")
    return found


def _run_env(module_name, gomaxprocs):
    env = os.environ.copy()
    env["GOSUMDB"] = "off"
    env["GOMAXPROCS"] = str(gomaxprocs)
    env["GOCACHE"] = str(Path(tempfile.gettempdir()) / f"{module_name}-go-cache")
    return env


def _tail(path, lines=80):
    try:
        content = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(content[-lines:])


def _run_logged(command, cwd, log_file, env):
    log_file.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with log_file.open("w", encoding="utf-8", errors="replace") as handle:
        proc = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    elapsed = time.perf_counter() - started
    if proc.returncode != 0:
        raise BenchError(
            f"command failed with exit code {proc.returncode}: {' '.join(map(str, command))}\n"
            f"log: {log_file}\n{_tail(log_file)}"
        )
    return elapsed


def _metric(line, key, default="0"):
    match = re.search(rf"(?:^|\s){re.escape(key)}=([^\s]+)", line)
    return match.group(1) if match else default


def _float_metric(line, key, default=0.0):
    raw = _metric(line, key, "")
    raw = raw.replace("beacon/min", "").replace("KB/s", "").replace("KB", "")
    try:
        return float(raw)
    except ValueError:
        return default


def _final_metrics(log_file):
    final = ""
    for line in log_file.read_text(errors="replace").splitlines():
        if "final metrics" in line:
            final = line
    if not final:
        raise BenchError(f"missing final metrics in {log_file}\n{_tail(log_file)}")
    return final


def _seed_hex(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _node_seed(node):
    return _seed_hex(f"tyche-node-{node:04d}")


def _protocol_fault_threshold(protocol, options):
    if protocol == "grandline" and hasattr(options, "grandline_fault_threshold"):
        return options.grandline_fault_threshold
    return options.fault_threshold


def _protocol_config(protocol, options):
    protocol_names = {
        "asyrand": "asyrand-v1",
        "grandline": "grandline",
        "spurt": "spurt-v1",
    }
    if protocol not in protocol_names:
        raise BenchError(f"no JSON config generator for protocol={protocol}")

    peers = [f"node{i}" for i in range(options.n)]
    cfg = {
        "name": f"local-{options.n}-{options.epochs}",
        "protocol": protocol_names[protocol],
        "transport": "memory",
        "f": _protocol_fault_threshold(protocol, options),
        "round": options.epochs,
        "queue_len": options.queue_len,
        "listen_ip": "0.0.0.0",
        "producer_interval_ms": options.producer_ms,
        "prefill_ms": options.prefill_ms,
        "epoch_timeout_ms": options.epoch_timeout_ms,
        "report_interval_ms": options.report_ms,
        "linger_ms": 15000,
        "batch_size": 1,
        "max_pool": options.max_pool,
        "log_level": 1,
        "seed": _seed_hex(f"{protocol}-{options.n}-{options.epochs}"),
        "cluster_index": {node: i for i, node in enumerate(peers)},
        "cluster_ips": {node: "127.0.0.1" for node in peers},
        "peers_p2p_port": {node: 9000 + i for i, node in enumerate(peers)},
        "node_key_seed": {node: _node_seed(i) for i, node in enumerate(peers)},
    }
    if protocol == "spurt":
        cfg["aggregation_lookahead"] = options.aggregation_lookahead
    return cfg


def _write_json_config(protocol, options):
    generated_dir = getattr(options, "generated_dir", options.out_root / "generated")
    path = generated_dir / f"{protocol}_local_{options.n}_rounds_{options.epochs}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_protocol_config(protocol, options), indent=2) + "\n", encoding="utf-8")
    return path


def _run_protocol(protocol, options):
    go = _go_executable()
    log_file = options.out_root / protocol / "local.log"

    if protocol in {"tyche", "tyche-scrape"}:
        command = [
            go,
            "run",
            "./cmd/tyche",
            "-n",
            str(options.n),
            "-f",
            str(options.fault_threshold),
            "-epochs",
            str(options.epochs),
            "-transport",
            "memory",
            "-queue-len",
            str(options.queue_len),
            "-producer-ms",
            str(options.producer_ms),
            "-prefill-ms",
            str(options.prefill_ms),
            "-epoch-timeout-ms",
            str(options.epoch_timeout_ms),
            "-report-ms",
            str(options.report_ms),
            "-max-pool",
            str(options.max_pool),
        ]
        if protocol == "tyche-scrape":
            command.extend(["-pvss", "scrape"])
        return _run_logged(command, REPO_ROOT / "Tyche", log_file, _run_env("tyche", options.gomaxprocs))

    if protocol in {"tyche-reconfig", "tyche-scrape-reconfig"}:
        env = _run_env("tyche", options.gomaxprocs)
        env.update(
            {
                "TYCHE_RECONFIG_BENCH_TEST": "1",
                "TYCHE_CHURN_PVSS": "scrape" if protocol == "tyche-scrape-reconfig" else "o1",
                "TYCHE_CHURN_EPOCHS": str(options.epochs),
                "TYCHE_CHURN_INITIAL_N": str(options.n),
                "TYCHE_CHURN_INITIAL_F": str(options.fault_threshold),
                "TYCHE_CHURN_RECONFIG_EVENTS": os.environ.get(
                    "TYCHE_RECONFIG_EVENTS", str(options.epochs // 20)
                ),
                "TYCHE_CHURN_PREFILL_MS": str(options.prefill_ms),
                "TYCHE_CHURN_MIN_N": os.environ.get(
                    "TYCHE_RECONFIG_MIN_N", str(options.n - options.fault_threshold)
                ),
                "TYCHE_CHURN_MAX_N": os.environ.get(
                    "TYCHE_RECONFIG_MAX_N", str(options.n + options.fault_threshold)
                ),
                "TYCHE_CHURN_EPOCH_TIMEOUT_MS": str(options.epoch_timeout_ms),
                "TYCHE_CHURN_SEED": os.environ.get("TYCHE_RECONFIG_SEED", "20260521"),
            }
        )
        command = [
            go,
            "test",
            "./protocol/tyche",
            "-run",
            "TestBeaconReconfigurationBenchmark200Epochs",
            "-count=1",
            "-v",
        ]
        return _run_logged(command, REPO_ROOT / "Tyche", log_file, env)

    if protocol in {"asyrand", "grandline", "spurt"}:
        cfg = _write_json_config(protocol, options)
        command = [
            go,
            "run",
            f"./cmd/{protocol}",
            "-config",
            str(cfg),
            "-transport",
            "memory",
        ]
        return _run_logged(command, REPO_ROOT / protocol, log_file, _run_env(protocol, options.gomaxprocs))

    raise BenchError(f"unknown protocol: {protocol}")


def _write_breakdown_row(writer, protocol, final, log_file):
    def pick(*keys):
        for key in keys:
            value = _metric(final, key, "0")
            if value != "0":
                return value
        return "0"

    writer.writerow(
        {
            "protocol": protocol,
            "node": "local",
            "host": "host0",
            "region": "local",
            "ip": "127.0.0.1",
            "crypto_share_avg": pick("pvss_share_avg"),
            "crypto_verify_avg": pick("pvss_verify_avg", "verify_avg"),
            "crypto_recon_avg": pick("pvss_recon_avg", "recover_avg"),
            "crypto_sign_avg": pick("sign_avg", "bls_sign_avg"),
            "crypto_aggregate_avg": pick("bls_agg_avg"),
            "agreement_avg": pick("spurt_vote_avg"),
            "rbc_avg": pick("rbc_avg"),
            "aba_avg": pick("aba_avg"),
            "log": str(log_file),
        }
    )


def _parse_results(options, elapsed_by_protocol):
    results_path = options.out_root / "results.csv"
    breakdown_path = options.out_root / "phase_crypto_breakdown.csv"
    final_log_path = options.out_root / "final_metrics.log"

    with results_path.open("w", newline="", encoding="utf-8") as handle, breakdown_path.open(
        "w", newline="", encoding="utf-8"
    ) as breakdown_handle, final_log_path.open("w", encoding="utf-8") as final_handle:
        results = csv.DictWriter(
            handle,
            fieldnames=[
                "protocol",
                "node",
                "host",
                "region",
                "ip",
                "throughput_beacon_min",
                "throughput_beacon_s",
                "bandwidth_kbps",
                "cpu_percent",
                "sent_msgs",
                "recv_msgs",
                "log",
            ],
        )
        breakdown = csv.DictWriter(
            breakdown_handle,
            fieldnames=[
                "protocol",
                "node",
                "host",
                "region",
                "ip",
                "crypto_share_avg",
                "crypto_verify_avg",
                "crypto_recon_avg",
                "crypto_sign_avg",
                "crypto_aggregate_avg",
                "agreement_avg",
                "rbc_avg",
                "aba_avg",
                "log",
            ],
        )
        results.writeheader()
        breakdown.writeheader()

        for protocol in options.protocols:
            log_file = options.out_root / protocol / "local.log"
            final = _final_metrics(log_file)
            throughput_min = _float_metric(final, "throughput")
            bandwidth = _float_metric(final, "bandwidth")
            elapsed = max(elapsed_by_protocol.get(protocol, 0.0), 1e-9)
            # Cross-platform child CPU time is not available without an extra dependency.
            # Keep the column for schema compatibility and report wall-clock normalized 0.
            cpu_percent = 0.0 if sys.platform.startswith("win") else 0.0

            results.writerow(
                {
                    "protocol": protocol,
                    "node": "local",
                    "host": "host0",
                    "region": "local",
                    "ip": "127.0.0.1",
                    "throughput_beacon_min": f"{throughput_min:.4f}",
                    "throughput_beacon_s": f"{throughput_min / 60:.4f}",
                    "bandwidth_kbps": f"{bandwidth:.4f}",
                    "cpu_percent": f"{cpu_percent:.2f}",
                    "sent_msgs": _metric(final, "sent_msgs"),
                    "recv_msgs": _metric(final, "recv_msgs"),
                    "log": str(log_file),
                }
            )
            _write_breakdown_row(breakdown, protocol, final, log_file)

            for line in log_file.read_text(errors="replace").splitlines():
                if any(token in line for token in ("bench_result", "final metrics", "compare", "message_type")):
                    final_handle.write(
                        f"protocol={protocol} node=local host=host0 region=local ip=127.0.0.1 {line}\n"
                    )

    (options.out_root / "breakdown_notes.md").write_text(
        "# Crypto/Phase Breakdown\n\n"
        "`phase_crypto_breakdown.csv` reports per-operation average costs parsed from final benchmark metrics.\n",
        encoding="utf-8",
    )
    return results_path


def run_local(n, epochs, protocols, out_root=None, fault_threshold=None):
    ensure_layout()
    if n <= 0:
        raise BenchError("nodes must be positive")
    if epochs <= 0:
        raise BenchError("epochs must be positive")

    protocol_list = _split_csv(protocols)
    if not protocol_list:
        raise BenchError("at least one protocol is required")

    output = Path(out_root) if out_root else RUNS_DIR / f"local_m1n{n}_{_timestamp()}"
    options = LocalOptions(
        n=n,
        epochs=epochs,
        protocols=protocol_list,
        out_root=output.resolve(),
        fault_threshold=(n - 1) // 3 if fault_threshold is None else fault_threshold,
        grandline_fault_threshold=int(os.environ.get("GRANDLINE_F", str((n - 1) // 2))),
        queue_len=int(os.environ.get("QUEUE_LEN", "8")),
        producer_ms=int(os.environ.get("PRODUCER_MS", "250")),
        prefill_ms=int(os.environ.get("PREFILL_MS", "3000")),
        epoch_timeout_ms=int(os.environ.get("EPOCH_TIMEOUT_MS", "15000")),
        report_ms=int(os.environ.get("REPORT_MS", "5000")),
        max_pool=int(os.environ.get("MAX_POOL", "4")),
        aggregation_lookahead=int(os.environ.get("AGGREGATION_LOOKAHEAD", "8")),
        gomaxprocs=int(os.environ.get("GOMAXPROCS_LOCAL", "4")),
    )
    options.out_root.mkdir(parents=True, exist_ok=True)

    elapsed_by_protocol = {}
    for protocol in options.protocols:
        print(
            f"[{time.strftime('%H:%M:%S')}] running {protocol} "
            f"n={options.n} epochs={options.epochs} max_pool={options.max_pool}"
        )
        elapsed_by_protocol[protocol] = _run_protocol(protocol, options)

    results = _parse_results(options, elapsed_by_protocol)
    print(f"results: {results}")


def _discover_aws_hosts(options, settings):
    if not options.key_file.exists():
        raise BenchError(f"local SSH key does not exist: {options.key_file}")
    candidates = []
    for region in settings.regions:
        for instance in _instances(region, ["running"]):
            ip = instance.get("PublicIpAddress")
            if ip:
                candidates.append((region, ip))
    if len(candidates) < options.n:
        raise BenchError(
            f"not enough running AWS hosts: found={len(candidates)} need={options.n}. "
            "Run `fab create --nodes=...` or `fab start` first."
        )
    hosts = []
    for index, (region, ip) in enumerate(candidates[: options.n]):
        user = _detect_ssh_user(ip, options.key_file, options)
        hosts.append(AwsHost(index=index, region=region, ip=ip, key_file=options.key_file, user=user))
    return hosts


def _connect(host, options):
    return Connection(
        host=host.ip,
        user=host.user,
        connect_timeout=options.ssh_connect_timeout,
        connect_kwargs={"key_filename": str(host.key_file)},
    )


def _detect_ssh_user(ip, key_file, options):
    users = []
    if options.ssh_user:
        users.append(options.ssh_user)
    users.extend(["ubuntu", "ec2-user", "admin"])

    last_error = None
    for user in dict.fromkeys(users):
        host = AwsHost(index=0, region="unknown", ip=ip, key_file=key_file, user=user)
        try:
            with _connect(host, options) as conn:
                conn.run("hostname >/dev/null", hide=True, warn=False)
            return user
        except Exception as exc:
            last_error = exc
    raise BenchError(f"cannot ssh to {ip} with key {key_file}: {last_error}")


def _remote_home(conn):
    return conn.run("printf %s \"$HOME\"", hide=True).stdout.strip()


def _remote_root(conn, options):
    return f"{_remote_home(conn)}/{options.remote_dir}"


def _remote_quote(path):
    return "'" + str(path).replace("'", "'\"'\"'") + "'"


def _aws_binary_targets(protocols):
    targets = {
        "tyche": ("Tyche", "./cmd/tyche", "tyche"),
        "asyrand": ("asyrand", "./cmd/asyrand", "asyrand"),
        "grandline": ("grandline", "./cmd/grandline", "grandline"),
        "spurt": ("spurt", "./cmd/spurt", "spurt"),
    }
    unknown = [protocol for protocol in protocols if protocol not in targets]
    if unknown:
        raise BenchError(f"unknown AWS protocol(s): {', '.join(unknown)}")
    return [targets[protocol] for protocol in dict.fromkeys(protocols)]


def _build_local_aws_binaries(options):
    go = _go_executable()
    options.local_bin_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "GOOS": os.environ.get("AWS_GOOS", "linux"),
            "GOARCH": os.environ.get("AWS_GOARCH", "amd64"),
            "CGO_ENABLED": os.environ.get("AWS_CGO_ENABLED", "0"),
            "GOSUMDB": "off",
            "GOCACHE": str(options.out_root / "go-cache"),
        }
    )
    for module_dir, package, binary_name in _aws_binary_targets(options.protocols):
        binary_path = options.local_bin_dir / binary_name
        log_file = options.out_root / "build" / f"{binary_name}.log"
        command = [go, "build", "-trimpath", "-o", str(binary_path), package]
        _run_logged(command, REPO_ROOT / module_dir, log_file, env)


def _upload_binaries_to_host(host, options):
    with _connect(host, options) as conn:
        remote_root = _remote_root(conn, options)
        remote_bin = f"{remote_root}/bin"
        conn.run(f"rm -rf {_remote_quote(remote_root)} && mkdir -p {_remote_quote(remote_bin)}", hide=True)
        for _, _, binary_name in _aws_binary_targets(options.protocols):
            local_file = options.local_bin_dir / binary_name
            if not local_file.is_file():
                raise BenchError(f"missing locally built binary: {local_file}")
            conn.put(str(local_file), remote=f"{remote_bin}/{binary_name}")
        conn.run(f"chmod +x {_remote_quote(remote_bin)}/*", hide=True)


def _run_host(host, options, command, hide=True, warn=False):
    with _connect(host, options) as conn:
        return conn.run(command, hide=hide, warn=warn)


def _install_remote_tools(host, options):
    command = (
        "set -e; "
        "if command -v /usr/bin/time >/dev/null 2>&1; then exit 0; fi; "
        "if command -v apt-get >/dev/null 2>&1; then "
        "sudo apt-get update -y && sudo apt-get install -y time; "
        "elif command -v yum >/dev/null 2>&1; then "
        "sudo yum install -y time; "
        "fi"
    )
    _run_host(host, options, command)


def _startup_wait_seconds(options):
    if options.startup_wait_sec is not None:
        return options.startup_wait_sec
    if options.n >= 128:
        return 15
    if options.n >= 64:
        return 10
    return 5


def _default_aws_epoch_timeout_ms(nodes):
    scale = max(1, (nodes + 3) // 4)
    return 60000 * scale


def _aws_config(protocol, options, hosts):
    cfg = _protocol_config(protocol, options)
    cfg["name"] = f"aws-n{options.n}"
    cfg["transport"] = "tcp"
    cfg["listen_ip"] = "0.0.0.0"
    cfg["prefill_ms"] = options.prefill_ms
    cfg["epoch_timeout_ms"] = options.epoch_timeout_ms
    cfg["report_interval_ms"] = options.report_ms
    cfg["linger_ms"] = options.linger_ms
    cfg["max_pool"] = options.max_pool
    peers = []
    cluster_ips = {}
    peer_ports = {}
    for node in range(options.n):
        host = hosts[node]
        node_id = f"node{node}"
        port = options.base_port + node
        peers.append({"id": node_id, "addr": f"{host.ip}:{port}"})
        cluster_ips[node_id] = host.ip
        peer_ports[node_id] = port
    cfg["peers"] = peers
    cfg["cluster_ips"] = cluster_ips
    cfg["peers_p2p_port"] = peer_ports
    return cfg


def _write_aws_configs(options, hosts):
    options.generated_dir.mkdir(parents=True, exist_ok=True)
    peers_file = options.generated_dir / "tyche_peers.txt"
    peer_items = []
    for node in range(options.n):
        host = hosts[node]
        peer_items.append(f"node{node}={host.ip}:{options.base_port + node}")
    peers_file.write_text(",".join(peer_items), encoding="utf-8")

    for protocol in options.protocols:
        if protocol == "tyche":
            continue
        if protocol not in {"asyrand", "grandline", "spurt"}:
            raise BenchError(f"unknown AWS protocol: {protocol}")
        path = options.generated_dir / f"{protocol}.json"
        path.write_text(json.dumps(_aws_config(protocol, options, hosts), indent=2) + "\n", encoding="utf-8")


def _upload_generated_configs(host, options):
    with _connect(host, options) as conn:
        remote_root = _remote_root(conn, options)
        remote_dir = f"{remote_root}/benchmark/generated/aws_n{options.n}"
        conn.run(f"rm -rf {_remote_quote(remote_dir)} && mkdir -p {_remote_quote(remote_dir)}", hide=True)
        for local_file in options.generated_dir.glob("*"):
            if local_file.is_file():
                conn.put(str(local_file), remote=f"{remote_dir}/{local_file.name}")


def _remote_command_for_node(protocol, node, options):
    port = options.base_port + node
    log_file = f"runlogs/{protocol}/node{node}.log"
    if protocol == "tyche":
        peers = (options.generated_dir / "tyche_peers.txt").read_text(encoding="utf-8")
        return (
            f"mkdir -p {_remote_quote('runlogs/' + protocol)} && "
            "export PATH=/usr/local/go/bin:$PATH "
            f"GOMAXPROCS={options.gomaxprocs} && "
            f"/usr/bin/time -v ./bin/tyche -transport tcp -node node{node} "
            f"-n {options.n} -f {options.fault_threshold} -epochs {options.epochs} "
            f"-peers {_remote_quote(peers)} -listen 0.0.0.0:{port} "
            f"-producer-ms {options.producer_ms} -prefill-ms {options.prefill_ms} "
            f"-epoch-timeout-ms {options.epoch_timeout_ms} -report-ms {options.report_ms} "
            f"> {_remote_quote(log_file)} 2>&1"
        )
    if protocol in {"asyrand", "grandline", "spurt"}:
        config_path = f"benchmark/generated/aws_n{options.n}/{protocol}.json"
        return (
            f"mkdir -p {_remote_quote('runlogs/' + protocol)} && "
            "export PATH=/usr/local/go/bin:$PATH "
            f"GOMAXPROCS={options.gomaxprocs} && "
            f"/usr/bin/time -v ./bin/{protocol} -config {_remote_quote(config_path)} "
            f"-transport tcp -node node{node} > {_remote_quote(log_file)} 2>&1"
        )
    raise BenchError(f"unknown protocol: {protocol}")


def _run_protocol_on_host(host, options, protocol):
    node_commands = []
    for node in range(options.n):
        if node == host.index:
            node_commands.append(f"( {_remote_command_for_node(protocol, node, options)} ) & pids=\"$pids $!\"")
    if not node_commands:
        return
    with _connect(host, options) as conn:
        root = _remote_root(conn, options)
        conn.run(
            f"cd {_remote_quote(root)} && rm -rf {_remote_quote('runlogs/' + protocol)} "
            f"&& mkdir -p {_remote_quote('runlogs/' + protocol)}",
            hide=True,
        )
        command = "set -u; pids=\"\"; failed=0; " + "; ".join(node_commands)
        command += "; for p in $pids; do wait \"$p\" || failed=1; done; exit \"$failed\""
        conn.run(f"cd {_remote_quote(root)} && {command}", hide=False)


def _fetch_node_log(host, options, protocol, node):
    local_log = options.out_root / protocol / f"node{node}.log"
    local_log.parent.mkdir(parents=True, exist_ok=True)
    with _connect(host, options) as conn:
        root = _remote_root(conn, options)
        conn.get(f"{root}/runlogs/{protocol}/node{node}.log", local=str(local_log))


def _stop_remote_processes(host, options):
    _run_host(
        host,
        options,
        f"pkill -f '{options.remote_dir}/bin/(tyche|asyrand|grandline|spurt)' >/dev/null 2>&1 || true",
        warn=True,
    )


def _parse_duration_seconds(raw):
    if not raw:
        return 0.0
    parts = raw.strip().split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        return float(parts[0])
    except ValueError:
        return 0.0


def _line_value(lines, prefix):
    for line in reversed(lines):
        if prefix in line:
            return line.split(": ", 1)[-1].strip()
    return ""


AWS_RESULT_FIELDS = [
    "protocol",
    "node",
    "host",
    "region",
    "ip",
    "throughput_beacon_min",
    "throughput_beacon_s",
    "latency_s",
    "bandwidth_kbps",
    "sent_kb",
    "recv_kb",
    "cpu_percent",
    "log",
]


def _aws_result_row(options, hosts, protocol, node):
    host = hosts[node]
    log_file = options.out_root / protocol / f"node{node}.log"
    final = _final_metrics(log_file)
    lines = log_file.read_text(errors="replace").splitlines()
    throughput = _float_metric(final, "throughput")
    bandwidth = _float_metric(final, "bandwidth")
    sent = _float_metric(final, "sent")
    recv = _float_metric(final, "recv")
    elapsed = _parse_duration_seconds(_line_value(lines, "Elapsed (wall clock) time"))
    user = float(_line_value(lines, "User time (seconds)") or 0)
    sys_time = float(_line_value(lines, "System time (seconds)") or 0)
    cpu_pct = ((user + sys_time) / elapsed * 100) if elapsed > 0 else 0
    return {
        "protocol": protocol,
        "node": f"node{node}",
        "host": f"host{host.index}",
        "region": host.region,
        "ip": host.ip,
        "throughput_beacon_min": f"{throughput:.4f}",
        "throughput_beacon_s": f"{throughput / 60:.4f}",
        "latency_s": f"{(60 / throughput) if throughput > 0 else 0:.4f}",
        "bandwidth_kbps": f"{bandwidth:.4f}",
        "sent_kb": f"{sent:.4f}",
        "recv_kb": f"{recv:.4f}",
        "cpu_percent": f"{cpu_pct:.2f}",
        "log": str(log_file),
    }


def _write_aws_failures(options, protocol_failures, parse_errors):
    failures_path = options.out_root / "failures.csv"
    if not protocol_failures and not parse_errors:
        if failures_path.exists():
            failures_path.unlink()
        return None
    with failures_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["protocol", "node", "stage", "error"])
        writer.writeheader()
        for protocol, error in protocol_failures.items():
            writer.writerow({"protocol": protocol, "node": "", "stage": "run", "error": error})
        for protocol, node, error in parse_errors:
            writer.writerow({"protocol": protocol, "node": f"node{node}", "stage": "parse", "error": error})
    return failures_path


def _read_env_file(path):
    values = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _result_protocol_counts(path):
    counts = {}
    if not path.exists():
        return counts
    with path.open("r", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            protocol = row.get("protocol", "")
            if protocol:
                counts[protocol] = counts.get(protocol, 0) + 1
    return counts


def _run_matches_request(path, nodes, epochs):
    state = _read_env_file(path / "aws_state.env")
    return state.get("N") == str(nodes) and state.get("EPOCHS") == str(epochs)


def _run_complete_for_protocols(path, protocols, nodes):
    if (path / "failures.csv").exists():
        return False
    counts = _result_protocol_counts(path / "results.csv")
    return all(counts.get(protocol, 0) >= nodes for protocol in protocols)


def _completed_protocols(path, nodes):
    if (path / "failures.csv").exists():
        failed = set()
        with (path / "failures.csv").open("r", newline="", encoding="utf-8") as handle:
            failed = {row.get("protocol", "") for row in csv.DictReader(handle)}
    else:
        failed = set()
    counts = _result_protocol_counts(path / "results.csv")
    return {protocol for protocol, count in counts.items() if count >= nodes and protocol not in failed}


def _find_resume_run(nodes, epochs, protocols):
    candidates = sorted(RUNS_DIR.glob(f"aws_n{nodes}_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates:
        if not path.is_dir() or not _run_matches_request(path, nodes, epochs):
            continue
        if not _run_complete_for_protocols(path, protocols, nodes):
            return path
    return None


def _parse_aws_results(options, hosts, protocol_failures=None):
    protocol_failures = protocol_failures or {}
    results_path = options.out_root / "results.csv"
    rows = []
    if results_path.exists():
        with results_path.open("r", newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row.get("protocol") not in set(options.protocols):
                    rows.append({field: row.get(field, "") for field in AWS_RESULT_FIELDS})

    parse_errors = []
    for protocol in options.protocols:
        for node in range(options.n):
            try:
                rows.append(_aws_result_row(options, hosts, protocol, node))
            except Exception as exc:
                parse_errors.append((protocol, node, str(exc)))

    with results_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=AWS_RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    _write_aws_failures(options, protocol_failures, parse_errors)
    return results_path


def _write_aws_state(options, hosts):
    state = options.out_root / "aws_state.env"
    lines = [
        f"M={options.n}",
        f"N={options.n}",
        f"EPOCHS={options.epochs}",
        f"BFT_F={options.fault_threshold}",
        f"GRANDLINE_F={options.grandline_fault_threshold}",
    ]
    for host in hosts:
        lines.extend(
            [
                f"SERVER_{host.index}_REGION={host.region}",
                f"SERVER_{host.index}_IP={host.ip}",
                f"SERVER_{host.index}_USER={host.user}",
                f"SERVER_{host.index}_KEY={host.key_file}",
            ]
        )
    state.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _hosts_from_state(path, options):
    state = _read_env_file(path)
    hosts = []
    for index in range(options.n):
        region = state.get(f"SERVER_{index}_REGION")
        ip = state.get(f"SERVER_{index}_IP")
        user = state.get(f"SERVER_{index}_USER")
        key = state.get(f"SERVER_{index}_KEY")
        if not region or not ip or not user:
            return []
        hosts.append(AwsHost(index=index, region=region, ip=ip, key_file=Path(key) if key else options.key_file, user=user))
    return hosts


def _parallel(label, items, fn, max_workers=None):
    workers = max_workers or max(1, min(16, len(items)))
    errors = []
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, item): item for item in items}
        for future in as_completed(futures):
            item = futures[future]
            try:
                future.result()
            except Exception as exc:
                with lock:
                    errors.append((item, exc))
    if errors:
        item, exc = errors[0]
        raise BenchError(f"{label} failed for {item}: {exc}") from exc


def run_aws(nodes, epochs, protocols, out_root=None, key_path=None, remote_dir="TycheBench", ssh_user=None):
    ensure_layout()
    if nodes <= 0:
        raise BenchError("nodes must be positive")
    protocol_list = _split_csv(protocols)
    if not protocol_list:
        raise BenchError("at least one protocol is required")
    settings = load_settings()
    key_file = (Path(key_path).resolve() if key_path else settings.key_path)

    resume_run = None if out_root else _find_resume_run(nodes, epochs, protocol_list)
    output = Path(out_root) if out_root else (resume_run or RUNS_DIR / f"aws_n{nodes}_{_timestamp()}")
    options = AwsOptions(
        n=nodes,
        epochs=epochs,
        protocols=protocol_list,
        out_root=output.resolve(),
        generated_dir=(REPO_ROOT / "benchmark" / "generated" / f"aws_n{nodes}").resolve(),
        local_bin_dir=(
            output
            / "bin"
            / f"{os.environ.get('AWS_GOOS', 'linux')}_{os.environ.get('AWS_GOARCH', 'amd64')}"
        ).resolve(),
        key_file=key_file,
        remote_dir=remote_dir,
        ssh_user=ssh_user,
        fault_threshold=int(os.environ.get("F", str((nodes - 1) // 3))),
        grandline_fault_threshold=int(os.environ.get("GRANDLINE_F", str((nodes - 1) // 2))),
        base_port=int(os.environ.get("BASE_PORT", "9000")),
        queue_len=int(os.environ.get("QUEUE_LEN", "8")),
        producer_ms=int(os.environ.get("PRODUCER_MS", "250")),
        prefill_ms=int(os.environ.get("PREFILL_MS", "8000")),
        epoch_timeout_ms=int(os.environ.get("EPOCH_TIMEOUT_MS", str(_default_aws_epoch_timeout_ms(nodes)))),
        report_ms=int(os.environ.get("REPORT_MS", "5000")),
        linger_ms=int(os.environ.get("LINGER_MS", "120000")),
        max_pool=int(os.environ.get("MAX_POOL", "16")),
        aggregation_lookahead=int(os.environ.get("AGGREGATION_LOOKAHEAD", "8")),
        gomaxprocs=int(os.environ.get("GOMAXPROCS_REMOTE", "4")),
        startup_wait_sec=int(os.environ["STARTUP_WAIT_SEC"]) if os.environ.get("STARTUP_WAIT_SEC") else None,
        ssh_connect_timeout=int(os.environ.get("SSH_CONNECT_TIMEOUT", "30")),
    )
    protocol_retries = int(os.environ.get("AWS_PROTOCOL_RETRIES", "4"))
    options.out_root.mkdir(parents=True, exist_ok=True)

    skip_protocols = set()
    if resume_run:
        print(f"[{time.strftime('%H:%M:%S')}] resuming AWS run: {options.out_root}")
        skip_protocols = _completed_protocols(options.out_root, nodes)
    hosts = _hosts_from_state(options.out_root / "aws_state.env", options)
    if hosts:
        print(f"[{time.strftime('%H:%M:%S')}] using AWS hosts from existing run state")
    else:
        hosts = _discover_aws_hosts(options, settings)
    _write_aws_configs(options, hosts)
    _write_aws_state(options, hosts)

    print(
        f"[{time.strftime('%H:%M:%S')}] building "
        f"{os.environ.get('AWS_GOOS', 'linux')}/{os.environ.get('AWS_GOARCH', 'amd64')} binaries locally"
    )
    _build_local_aws_binaries(options)
    print(f"[{time.strftime('%H:%M:%S')}] preparing {len(hosts)} AWS hosts")
    print(f"[{time.strftime('%H:%M:%S')}] installing remote tools on {len(hosts)} AWS hosts")
    _parallel("install remote tools", hosts, lambda host: _install_remote_tools(host, options))
    print(f"[{time.strftime('%H:%M:%S')}] uploading local binaries to {len(hosts)} AWS hosts")
    _parallel("upload local binaries", hosts, lambda host: _upload_binaries_to_host(host, options), max_workers=min(4, len(hosts)))
    print(f"[{time.strftime('%H:%M:%S')}] uploading generated configs to {len(hosts)} AWS hosts")
    _parallel("upload generated configs", hosts, lambda host: _upload_generated_configs(host, options))

    protocol_failures = {}
    for protocol in options.protocols:
        if protocol in skip_protocols:
            print(f"[{time.strftime('%H:%M:%S')}] skipping completed protocol {protocol}")
            continue
        run_error = None
        for attempt in range(protocol_retries + 1):
            suffix = f" attempt={attempt + 1}/{protocol_retries + 1}" if protocol_retries else ""
            print(f"[{time.strftime('%H:%M:%S')}] running {protocol} on N={nodes} epochs={epochs}{suffix}")
            _parallel("stop remote processes", hosts, lambda host: _stop_remote_processes(host, options))
            run_error = None
            with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
                futures = [pool.submit(_run_protocol_on_host, host, options, protocol) for host in hosts]
                wait_sec = _startup_wait_seconds(options)
                if wait_sec > 0:
                    print(f"[{time.strftime('%H:%M:%S')}] waiting {wait_sec}s for startup")
                    time.sleep(wait_sec)
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:
                        if run_error is None:
                            run_error = exc
            fetch_jobs = []
            for node in range(options.n):
                host = hosts[node]
                fetch_jobs.append((host, node))
            try:
                _parallel(
                    f"fetch {protocol} logs",
                    fetch_jobs,
                    lambda item: _fetch_node_log(item[0], options, protocol, item[1]),
                    max_workers=min(16, len(fetch_jobs)),
                )
            except BenchError as exc:
                if run_error is None:
                    run_error = exc
            if run_error is None:
                break
            if attempt < protocol_retries:
                print(f"[{time.strftime('%H:%M:%S')}] {protocol} failed; retrying")
        if run_error is not None:
            protocol_failures[protocol] = str(run_error)
            print(f"[{time.strftime('%H:%M:%S')}] {protocol} failed; continuing with remaining protocols")

    results = _parse_aws_results(options, hosts, protocol_failures)
    _parallel("stop remote processes", hosts, lambda host: _stop_remote_processes(host, options))
    print(f"results: {results}")
    failures = options.out_root / "failures.csv"
    if failures.exists():
        print(f"failures: {failures}")
    print(f"logs:    {options.out_root}")
    print(f"state:   {options.out_root / 'aws_state.env'}")
