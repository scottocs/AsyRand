import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .paths import REPO_ROOT, RUNS_DIR, ensure_layout


class BenchError(RuntimeError):
    pass


@dataclass(frozen=True)
class LocalOptions:
    n: int
    epochs: int
    protocols: list[str]
    out_root: Path
    fault_threshold: int
    queue_len: int = 8
    producer_ms: int = 250
    prefill_ms: int = 3000
    epoch_timeout_ms: int = 15000
    report_ms: int = 5000
    max_pool: int = 4
    aggregation_lookahead: int = 8
    gomaxprocs: int = 4


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
        "f": options.fault_threshold,
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
    path = options.out_root / "generated" / f"{protocol}_local_{options.n}_rounds_{options.epochs}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_protocol_config(protocol, options), indent=2) + "\n", encoding="utf-8")
    return path


def _run_protocol(protocol, options):
    go = _go_executable()
    log_file = options.out_root / protocol / "local.log"

    if protocol == "tyche":
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
        return _run_logged(command, REPO_ROOT / "Tyche", log_file, _run_env("tyche", options.gomaxprocs))

    if protocol == "tyche-reconfig":
        env = _run_env("tyche", options.gomaxprocs)
        env.update(
            {
                "TYCHE_RECONFIG_BENCH_TEST": "1",
                "TYCHE_CHURN_EPOCHS": str(options.epochs),
                "TYCHE_CHURN_RECONFIG_EVENTS": os.environ.get(
                    "TYCHE_RECONFIG_EVENTS", str(options.epochs // 20)
                ),
                "TYCHE_CHURN_MIN_N": os.environ.get("TYCHE_RECONFIG_MIN_N", "4"),
                "TYCHE_CHURN_MAX_N": os.environ.get("TYCHE_RECONFIG_MAX_N", "13"),
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


def run_aws(machines, nodes, epochs, protocols, out_root=None):
    raise BenchError(
        "fab aws is intentionally disabled until the AWS runner is ported to Python/Fabric. "
        "No scripts/*.sh fallback is used."
    )
