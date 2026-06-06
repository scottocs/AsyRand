import csv
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, replace
from datetime import datetime
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
    producer_ms: int = 50
    prefill_ms: int = 3000
    epoch_timeout_ms: int = 15000
    report_ms: int = 5000
    max_pool: int = 2
    transport_buffer: int = 0
    removal_expiration_ms: int = 0
    aggregation_lookahead: int = 8
    gomaxprocs: int = 8


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
    producer_ms: int = 50
    prefill_ms: int = 8000
    epoch_timeout_ms: int = 60000
    report_ms: int = 5000
    linger_ms: int = 5000
    max_pool: int = 2
    transport_buffer: int = 0
    removal_expiration_ms: int = 0
    reconfig_removal_expiration_ms: int = 1000
    aggregation_lookahead: int = 8
    gomaxprocs: int = 2
    startup_wait_sec: int | None = None
    ssh_connect_timeout: int = 6
    ssh_probe_retries: int = 1
    ssh_probe_delay_sec: int = 0


def _split_csv(raw):
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def _protocol_slug(protocols):
    value = "-".join(protocols)
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "protocols"


def _run_config_hash(config):
    payload = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _write_run_config(path, config):
    (path / "run_config.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _format_mtime(timestamp):
    return datetime.fromtimestamp(timestamp).isoformat(timespec="seconds")


def _safe_remove_run_dir(path):
    path = path.resolve()
    runs_root = RUNS_DIR.resolve()
    if path == runs_root or runs_root not in path.parents:
        raise BenchError(f"refusing to remove path outside benchmark runs: {path}")
    if path.exists():
        shutil.rmtree(path)


def _default_run_paths(config):
    name = f"{config['kind']}_n{config['nodes']}_e{config['epochs']}"
    final = RUNS_DIR / name
    running = RUNS_DIR / f".{name}.running"
    return final, running


def _prepare_default_run_dir(config, resume=False):
    final, running = _default_run_paths(config)
    if running.exists() and not resume:
        _safe_remove_run_dir(running)
    running.mkdir(parents=True, exist_ok=True)
    _write_run_config(running, config)
    return final.resolve(), running.resolve()


def _rewrite_run_paths(path, old_root, new_root):
    old_text = str(old_root)
    new_text = str(new_root)
    if old_text == new_text:
        return
    for file in path.rglob("*"):
        if not file.is_file() or file.suffix.lower() not in {".csv", ".log", ".md", ".json", ".env"}:
            continue
        try:
            content = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if old_text in content:
            file.write_text(content.replace(old_text, new_text), encoding="utf-8")


def _read_csv_rows(path):
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _write_csv_rows(path, rows):
    fieldnames = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _rows_protocols(rows):
    protocols = []
    for row in rows:
        protocol = row.get("protocol", "")
        if protocol and protocol not in protocols:
            protocols.append(protocol)
    return protocols


def _merge_run_config(final, staging, protocols):
    final_config_path = final / "run_config.json"
    staging_config_path = staging / "run_config.json"
    config = {}
    if final_config_path.exists():
        try:
            config = json.loads(final_config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            config = {}
    if not config and staging_config_path.exists():
        try:
            config = json.loads(staging_config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            config = {}
    existing = config.get("protocols") if isinstance(config.get("protocols"), list) else []
    config["protocols"] = existing + [protocol for protocol in protocols if protocol not in existing]
    if config:
        _write_run_config(final, config)


def _run_id_from_path(path):
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", path.name.strip(".")) or datetime.now().strftime("%Y%m%d_%H%M%S")


def _stamp_rows(rows, run_id, run_time, source_run=""):
    stamped = []
    for row in rows:
        updated = dict(row)
        updated["run_id"] = updated.get("run_id") or run_id
        updated["run_time"] = updated.get("run_time") or run_time
        updated["source_run"] = updated.get("source_run") or source_run
        stamped.append(updated)
    return stamped


def _latest_rows_per_protocol(rows):
    latest_key_by_protocol = {}
    for row in rows:
        protocol = row.get("protocol", "")
        if not protocol:
            continue
        run_key = row.get("run_id") or row.get("source_run") or "__legacy__"
        run_time = row.get("run_time") or ""
        current = latest_key_by_protocol.get(protocol)
        if current is None or (run_time, run_key) >= current:
            latest_key_by_protocol[protocol] = (run_time, run_key)
    return [
        row
        for row in rows
        if row.get("protocol", "")
        and (
            row.get("run_time") or "",
            row.get("run_id") or row.get("source_run") or "__legacy__",
        )
        == latest_key_by_protocol.get(row.get("protocol", ""))
    ]


def _copy_protocol_attempt(source, final, run_id, protocol):
    source_protocol = source / protocol
    if not source_protocol.exists():
        return None
    attempt_protocol = final / "attempts" / run_id / protocol
    if attempt_protocol.exists():
        shutil.rmtree(attempt_protocol)
    attempt_protocol.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_protocol, attempt_protocol)

    latest_protocol = final / protocol
    if latest_protocol.exists():
        shutil.rmtree(latest_protocol)
    shutil.copytree(attempt_protocol, latest_protocol)
    return attempt_protocol


def _publish_successful_run(staging, final):
    staging = staging.resolve()
    final = final.resolve()
    if final == staging:
        return final

    staging_rows = _read_csv_rows(staging / "results.csv")
    staging_protocols = _rows_protocols(staging_rows)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_time = _format_mtime(time.time())
    final.mkdir(parents=True, exist_ok=True)
    for protocol in staging_protocols:
        _copy_protocol_attempt(staging, final, run_id, protocol)
    for source_file in staging.iterdir():
        if source_file.is_dir() or source_file.name in {"results.csv", "protocol_run_log.csv", "run_config.json"}:
            continue
        shutil.copy2(source_file, final / source_file.name)

    attempt_root = final / "attempts" / run_id
    new_rows = _stamp_rows(
        _rewrite_rows_for_run(staging_rows, staging, attempt_root),
        run_id,
        run_time,
        staging.name,
    )
    merged_rows = [
        row for row in _read_csv_rows(final / "results.csv")
        if row.get("protocol", "") not in staging_protocols
    ] + new_rows
    if merged_rows:
        _write_csv_rows(final / "results.csv", merged_rows)
    _merge_run_config(final, staging, _rows_protocols(merged_rows))
    write_protocol_run_log(final)
    _safe_remove_run_dir(staging)
    return final


def _protocol_log_path(run_dir, row):
    raw = row.get("log") or ""
    if not raw:
        return None
    path = Path(raw)
    if path.exists():
        return path
    try:
        marker = f"{RUNS_DIR.name}\\"
        raw_norm = raw.replace("/", "\\")
        if marker in raw_norm:
            rel = raw_norm.split(marker, 1)[1].split("\\", 1)[1]
            candidate = run_dir / Path(rel)
            if candidate.exists():
                return candidate
    except IndexError:
        pass
    candidate = run_dir / raw
    return candidate if candidate.exists() else None


def write_protocol_run_log(run_dir, source_by_protocol=None):
    run_dir = Path(run_dir)
    results_path = run_dir / "results.csv"
    if not results_path.exists():
        return None
    source_by_protocol = source_by_protocol or {}
    rows = _read_csv_rows(results_path)
    latest_key_by_protocol = {}
    for row in rows:
        protocol = row.get("protocol", "")
        if not protocol:
            continue
        run_key = row.get("run_id") or row.get("source_run") or "__legacy__"
        run_time = row.get("run_time") or ""
        current = latest_key_by_protocol.get(protocol)
        if current is None or (run_time, run_key) >= current:
            latest_key_by_protocol[protocol] = (run_time, run_key)

    stats = {}
    for row in rows:
        protocol = row.get("protocol", "")
        if not protocol:
            continue
        run_key = row.get("run_id") or row.get("source_run") or "__legacy__"
        run_time = row.get("run_time") or ""
        if (run_time, run_key) != latest_key_by_protocol.get(protocol):
            continue
        entry = stats.setdefault(
            protocol,
            {"rows": 0, "latest_mtime": 0.0, "latest_log": "", "source": source_by_protocol.get(protocol, "")},
        )
        entry["rows"] += 1
        log_path = _protocol_log_path(run_dir, row)
        if log_path is not None:
            mtime = log_path.stat().st_mtime
            latest_log = str(log_path)
        else:
            mtime = results_path.stat().st_mtime
            latest_log = row.get("log", "")
        if mtime >= entry["latest_mtime"]:
            entry["latest_mtime"] = mtime
            entry["latest_log"] = latest_log
            entry["source"] = row.get("source_run") or row.get("run_id") or entry["source"]

    out = run_dir / "protocol_run_log.csv"
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["protocol", "latest_run_time", "rows", "source_run", "latest_log"],
        )
        writer.writeheader()
        for protocol in sorted(stats):
            entry = stats[protocol]
            writer.writerow(
                {
                    "protocol": protocol,
                    "latest_run_time": _format_mtime(entry["latest_mtime"]) if entry["latest_mtime"] else "",
                    "rows": entry["rows"],
                    "source_run": entry["source"],
                    "latest_log": entry["latest_log"],
                }
            )
    return out


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


def _protocol_elapsed_seconds(final):
    elapsed = _float_metric(final, "elapsed_s")
    if elapsed > 0:
        return elapsed
    throughput = _float_metric(final, "throughput")
    beacons = _float_metric(final, "beacons")
    if throughput > 0 and beacons > 0:
        return beacons * 60 / throughput
    return 0.0


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


def _protocol_success_threshold(protocol, options):
    return options.n - _protocol_fault_threshold(protocol, options)


def _default_protocol_success_threshold(protocol, nodes):
    if protocol == "grandline":
        fault_threshold = (nodes - 1) // 2
    else:
        fault_threshold = (nodes - 1) // 3
    return nodes - fault_threshold


def _aws_protocol_node_indices(protocol, options):
    return list(range(options.n))


def _tyche_queue_len_for_protocol(protocol, options):
    if protocol in {"tyche-reconfig", "tyche-scrape-reconfig"}:
        return int(os.environ.get("TYCHE_RECONFIG_QUEUE_LEN", "1"))
    return options.queue_len


def _default_reconfig_events(epochs):
    return max(1, epochs // 20)


def _reconfig_events_value(options):
    return os.environ.get("TYCHE_RECONFIG_EVENTS", str(_default_reconfig_events(options.epochs)))


def _reconfig_min_n_value(options):
    return os.environ.get("TYCHE_RECONFIG_MIN_N", str(options.n - options.fault_threshold))


def _reconfig_max_n_value(options):
    return os.environ.get("TYCHE_RECONFIG_MAX_N", str(options.n + options.fault_threshold))


def _reconfig_seed_value():
    return os.environ.get("TYCHE_RECONFIG_SEED", "20260521")


def _reconfig_crash_grace_ms_value():
    return os.environ.get("TYCHE_RECONFIG_CRASH_GRACE_MS", "2000")


def _reconfig_removal_expiration_ms_value():
    return os.environ.get("TYCHE_RECONFIG_REMOVAL_EXPIRATION_MS", "1000")


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
            "-transport-buffer",
            str(options.transport_buffer),
            "-removal-expiration-ms",
            str(options.removal_expiration_ms),
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
                "TYCHE_CHURN_RECONFIG_EVENTS": _reconfig_events_value(options),
                "TYCHE_CHURN_PREFILL_MS": str(options.prefill_ms),
                "TYCHE_CHURN_MIN_N": _reconfig_min_n_value(options),
                "TYCHE_CHURN_MAX_N": _reconfig_max_n_value(options),
                "TYCHE_CHURN_EPOCH_TIMEOUT_MS": str(options.epoch_timeout_ms),
                "TYCHE_CHURN_SEED": _reconfig_seed_value(),
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
                "elapsed_s",
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
            elapsed = _protocol_elapsed_seconds(final) or elapsed_by_protocol.get(protocol, 0.0)
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
                    "elapsed_s": f"{elapsed:.3f}",
                    "bandwidth_kbps": f"{bandwidth:.4f}",
                    "cpu_percent": f"{cpu_percent:.2f}",
                    "sent_msgs": _metric(final, "sent_msgs"),
                    "recv_msgs": _metric(final, "recv_msgs"),
                    "log": str(log_file),
                }
            )
            _write_breakdown_row(breakdown, protocol, final, log_file)

            for line in log_file.read_text(errors="replace").splitlines():
                if any(
                    token in line
                    for token in (
                        "bench_result",
                        "final metrics",
                        "compare",
                        "message_type",
                        "reconfig_schedule",
                        "reconfig_stop_producing",
                        "reconfig_removed",
                        "reconfig_membership_change",
                        "reconfig_final",
                    )
                ):
                    final_handle.write(
                        f"protocol={protocol} node=local host=host0 region=local ip=127.0.0.1 {line}\n"
                    )

    (options.out_root / "breakdown_notes.md").write_text(
        "# Crypto/Phase Breakdown\n\n"
        "`phase_crypto_breakdown.csv` reports per-operation average costs parsed from final benchmark metrics.\n",
        encoding="utf-8",
    )
    return results_path


def _local_run_config(n, epochs, protocol_list, fault_threshold):
    bft_f = (n - 1) // 3 if fault_threshold is None else fault_threshold
    return {
        "kind": "local",
        "nodes": n,
        "epochs": epochs,
        "protocols": protocol_list,
        "fault_threshold": bft_f,
        "grandline_fault_threshold": int(os.environ.get("GRANDLINE_F", str((n - 1) // 2))),
        "queue_len": int(os.environ.get("QUEUE_LEN", "8")),
        "producer_ms": int(os.environ.get("PRODUCER_MS", "250")),
        "prefill_ms": int(os.environ.get("PREFILL_MS", "3000")),
        "epoch_timeout_ms": int(os.environ.get("EPOCH_TIMEOUT_MS", "15000")),
        "report_ms": int(os.environ.get("REPORT_MS", "5000")),
        "max_pool": int(os.environ.get("MAX_POOL", "2")),
        "transport_buffer": int(os.environ.get("TYCHE_TRANSPORT_BUFFER", "0")),
        "removal_expiration_ms": int(os.environ.get("TYCHE_REMOVAL_EXPIRATION_MS", "0")),
        "aggregation_lookahead": int(os.environ.get("AGGREGATION_LOOKAHEAD", "8")),
        "gomaxprocs": int(os.environ.get("GOMAXPROCS_LOCAL", "8")),
        "tyche_reconfig_events": os.environ.get("TYCHE_RECONFIG_EVENTS", str(_default_reconfig_events(epochs))),
        "tyche_reconfig_min_n": os.environ.get("TYCHE_RECONFIG_MIN_N", str(n - bft_f)),
        "tyche_reconfig_max_n": os.environ.get("TYCHE_RECONFIG_MAX_N", str(n + bft_f)),
        "tyche_reconfig_seed": os.environ.get("TYCHE_RECONFIG_SEED", "20260521"),
        "tyche_reconfig_queue_len": os.environ.get("TYCHE_RECONFIG_QUEUE_LEN", "1"),
        "tyche_reconfig_crash_grace_ms": _reconfig_crash_grace_ms_value(),
    }


def run_local(n, epochs, protocols, out_root=None, fault_threshold=None):
    ensure_layout()
    if n <= 0:
        raise BenchError("nodes must be positive")
    if epochs <= 0:
        raise BenchError("epochs must be positive")

    protocol_list = _split_csv(protocols)
    if not protocol_list:
        raise BenchError("at least one protocol is required")

    config = _local_run_config(n, epochs, protocol_list, fault_threshold)
    final_output = None
    if out_root:
        output = Path(out_root).resolve()
    else:
        final_output, output = _prepare_default_run_dir(config)
    options = LocalOptions(
        n=n,
        epochs=epochs,
        protocols=protocol_list,
        out_root=Path(output).resolve(),
        fault_threshold=config["fault_threshold"],
        grandline_fault_threshold=config["grandline_fault_threshold"],
        queue_len=config["queue_len"],
        producer_ms=config["producer_ms"],
        prefill_ms=config["prefill_ms"],
        epoch_timeout_ms=config["epoch_timeout_ms"],
        report_ms=config["report_ms"],
        max_pool=config["max_pool"],
        transport_buffer=config["transport_buffer"],
        removal_expiration_ms=config["removal_expiration_ms"],
        aggregation_lookahead=config["aggregation_lookahead"],
        gomaxprocs=config["gomaxprocs"],
    )
    options.out_root.mkdir(parents=True, exist_ok=True)
    _write_run_config(options.out_root, config)

    elapsed_by_protocol = {}
    for protocol in options.protocols:
        print(
            f"[{time.strftime('%H:%M:%S')}] running {protocol} "
            f"n={options.n} epochs={options.epochs} max_pool={options.max_pool}"
        )
        elapsed_by_protocol[protocol] = _run_protocol(protocol, options)

    results = _parse_results(options, elapsed_by_protocol)
    write_protocol_run_log(options.out_root)
    if final_output is not None:
        published = _publish_successful_run(options.out_root, final_output)
        results = published / "results.csv"
        print(f"published: {published}")
    print(f"results: {results}")


def _discover_aws_hosts(options, settings):
    if not options.key_file.exists():
        raise BenchError(f"local SSH key does not exist: {options.key_file}")
    candidates_by_region = {}
    for region in settings.regions:
        region_candidates = []
        for instance in _instances(region, ["running"]):
            ip = instance.get("PublicIpAddress")
            if ip:
                region_candidates.append(ip)
        candidates_by_region[region] = region_candidates
    total_candidates = sum(len(items) for items in candidates_by_region.values())
    counts = ", ".join(f"{region}={len(candidates_by_region.get(region, []))}" for region in settings.regions)
    print(f"[{time.strftime('%H:%M:%S')}] found {total_candidates} running AWS host candidate(s): {counts}")
    if total_candidates < options.n:
        raise BenchError(
            f"not enough running AWS hosts: found={total_candidates} need={options.n}. "
            "Run `fab create --nodes=...` or `fab start` first."
        )
    targets = _region_host_targets(options.n, settings.regions)
    target_counts = ", ".join(f"{region}={targets[region]}" for region in settings.regions if targets[region] > 0)
    print(f"[{time.strftime('%H:%M:%S')}] target AWS host distribution: {target_counts}")
    for region, target in targets.items():
        available = len(candidates_by_region.get(region, []))
        if available < target:
            raise BenchError(
                f"not enough running AWS hosts in {region}: found={available} need={target}. "
                "Create more instances or reduce --nodes."
            )

    selected_by_region = {region: [] for region in settings.regions}
    cursor_by_region = {region: 0 for region in settings.regions}
    errors = []

    while any(len(selected_by_region[region]) < targets[region] for region in settings.regions):
        batch = []
        for region in settings.regions:
            if len(selected_by_region[region]) >= targets[region]:
                continue
            candidates = candidates_by_region.get(region, [])
            cursor = cursor_by_region[region]
            if cursor >= len(candidates):
                continue
            ip = candidates[cursor]
            cursor_by_region[region] = cursor + 1
            batch.append((region, ip))
        if not batch:
            break

        batch_label = ", ".join(f"{region} {ip}" for region, ip in batch)
        print(f"[{time.strftime('%H:%M:%S')}] probing SSH on {len(batch)} AWS host candidate(s): {batch_label}")
        with ThreadPoolExecutor(max_workers=len(batch)) as pool:
            futures = {
                pool.submit(_detect_ssh_user, ip, options.key_file, options): (region, ip)
                for region, ip in batch
            }
        for future in as_completed(futures):
            region, ip = futures[future]
            try:
                user = future.result()
            except BenchError as exc:
                errors.append(f"{region} {ip}: {exc}")
                print(f"[{time.strftime('%H:%M:%S')}] skipping unreachable AWS host {region} {ip}: {exc}")
                continue
            selected_by_region[region].append((ip, user))
            print(f"[{time.strftime('%H:%M:%S')}] SSH ready: {region} {ip} user={user}")

    missing = {
        region: targets[region] - len(selected_by_region[region])
        for region in settings.regions
        if len(selected_by_region[region]) < targets[region]
    }
    if missing:
        missing_counts = ", ".join(f"{region}={count}" for region, count in missing.items())
        detail = "\n".join(errors[-8:])
        raise BenchError(
            f"not enough SSH-ready AWS hosts for target distribution: missing {missing_counts}. "
            "Wait a minute and retry, or create extra backup instances in the affected region(s)."
            + (f"\nRecent SSH failures:\n{detail}" if detail else "")
        )

    hosts = []
    for slot in range(max(targets.values(), default=0)):
        for region in settings.regions:
            if slot >= len(selected_by_region[region]):
                continue
            ip, user = selected_by_region[region][slot]
            host = AwsHost(index=len(hosts), region=region, ip=ip, key_file=options.key_file, user=user)
            hosts.append(host)
            print(
                f"[{time.strftime('%H:%M:%S')}] selected AWS host "
                f"{len(hosts)}/{options.n}: {region} {ip}"
            )
    return hosts


def _region_host_targets(nodes, regions):
    base = nodes // len(regions)
    extra = nodes % len(regions)
    return {
        region: base + (1 if index < extra else 0)
        for index, region in enumerate(regions)
    }


def _connect(host, options):
    return Connection(
        host=host.ip,
        user=host.user,
        connect_timeout=options.ssh_connect_timeout,
        connect_kwargs={"key_filename": str(host.key_file)},
    )


def _detect_ssh_user(ip, key_file, options):
    users = [options.ssh_user or "ubuntu"]

    last_error = None
    for attempt in range(max(1, options.ssh_probe_retries)):
        for user in dict.fromkeys(users):
            host = AwsHost(index=0, region="unknown", ip=ip, key_file=key_file, user=user)
            try:
                with _connect(host, options) as conn:
                    conn.run("hostname >/dev/null", hide=True, warn=False, in_stream=False)
                return user
            except Exception as exc:
                last_error = exc
        if attempt + 1 < options.ssh_probe_retries:
            time.sleep(max(0, options.ssh_probe_delay_sec))
    raise BenchError(f"cannot ssh to {ip} with key {key_file}: {last_error}")


def _remote_home(conn):
    return conn.run("printf %s \"$HOME\"", hide=True, in_stream=False).stdout.strip()


def _remote_root(conn, options):
    return f"{_remote_home(conn)}/{options.remote_dir}"


def _remote_quote(path):
    return "'" + str(path).replace("'", "'\"'\"'") + "'"


def _aws_binary_targets(protocols):
    targets = {
        "tyche": ("Tyche", "./cmd/tyche", "tyche"),
        "tyche-scrape": ("Tyche", "./cmd/tyche", "tyche"),
        "tyche-reconfig": ("Tyche", "./cmd/tyche", "tyche"),
        "tyche-scrape-reconfig": ("Tyche", "./cmd/tyche", "tyche"),
        "asyrand": ("asyrand", "./cmd/asyrand", "asyrand"),
        "grandline": ("grandline", "./cmd/grandline", "grandline"),
        "spurt": ("spurt", "./cmd/spurt", "spurt"),
    }
    unknown = [protocol for protocol in protocols if protocol not in targets]
    if unknown:
        raise BenchError(f"unknown AWS protocol(s): {', '.join(unknown)}")
    return list(dict.fromkeys(targets[protocol] for protocol in protocols))


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
        if binary_name.endswith(".test"):
            command = [go, "test", "-c", "-o", str(binary_path), package]
        else:
            command = [go, "build", "-trimpath", "-o", str(binary_path), package]
        _run_logged(command, REPO_ROOT / module_dir, log_file, env)


def _upload_binaries_to_host(host, options):
    print(f"[{time.strftime('%H:%M:%S')}] uploading binaries to host{host.index} {host.region} {host.ip}")
    with _connect(host, options) as conn:
        remote_root = _remote_root(conn, options)
        remote_bin = f"{remote_root}/bin"
        conn.run(f"rm -rf {_remote_quote(remote_root)} && mkdir -p {_remote_quote(remote_bin)}", hide=True, in_stream=False)
        for _, _, binary_name in _aws_binary_targets(options.protocols):
            local_file = options.local_bin_dir / binary_name
            if not local_file.is_file():
                raise BenchError(f"missing locally built binary: {local_file}")
            print(f"[{time.strftime('%H:%M:%S')}] host{host.index}: put bin/{binary_name}")
            conn.put(str(local_file), remote=f"{remote_bin}/{binary_name}")
        conn.run(f"chmod +x {_remote_quote(remote_bin)}/*", hide=True, in_stream=False)


def _run_host(host, options, command, hide=True, warn=False):
    with _connect(host, options) as conn:
        return conn.run(command, hide=hide, warn=warn, in_stream=False)


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
    return 60000 * max(1, math.ceil(nodes / 4))


def _aws_epoch_timeout_ms(nodes):
    requested = int(os.environ.get("EPOCH_TIMEOUT_MS", str(_default_aws_epoch_timeout_ms(nodes))))
    return requested


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
        if protocol in {"tyche", "tyche-scrape", "tyche-reconfig", "tyche-scrape-reconfig"}:
            continue
        if protocol not in {"asyrand", "grandline", "spurt"}:
            raise BenchError(f"unknown AWS protocol: {protocol}")
        path = options.generated_dir / f"{protocol}.json"
        path.write_text(json.dumps(_aws_config(protocol, options, hosts), indent=2) + "\n", encoding="utf-8")


def _upload_generated_configs(host, options):
    print(f"[{time.strftime('%H:%M:%S')}] uploading configs to host{host.index} {host.region} {host.ip}")
    with _connect(host, options) as conn:
        remote_root = _remote_root(conn, options)
        remote_dir = f"{remote_root}/benchmark/generated/aws_n{options.n}"
        conn.run(f"rm -rf {_remote_quote(remote_dir)} && mkdir -p {_remote_quote(remote_dir)}", hide=True, in_stream=False)
        for local_file in options.generated_dir.glob("*"):
            if local_file.is_file():
                print(f"[{time.strftime('%H:%M:%S')}] host{host.index}: put generated/{local_file.name}")
                conn.put(str(local_file), remote=f"{remote_dir}/{local_file.name}")


def _upload_payload_to_host(host, options):
    _upload_binaries_to_host(host, options)
    _upload_generated_configs(host, options)


def _remote_command_for_node(protocol, node, options):
    port = options.base_port + node
    log_file = f"runlogs/{protocol}/node{node}.log"
    if protocol in {"tyche", "tyche-scrape", "tyche-reconfig", "tyche-scrape-reconfig"}:
        peers = (options.generated_dir / "tyche_peers.txt").read_text(encoding="utf-8")
        tyche_env = f"GOMAXPROCS={options.gomaxprocs}"
        if os.environ.get("TYCHE_EPOCH_ATTEMPT_MS"):
            tyche_env += f" TYCHE_EPOCH_ATTEMPT_MS={_remote_quote(os.environ['TYCHE_EPOCH_ATTEMPT_MS'])}"
        if os.environ.get("TYCHE_TCP_PEER_WAIT_MS"):
            tyche_env += f" TYCHE_TCP_PEER_WAIT_MS={_remote_quote(os.environ['TYCHE_TCP_PEER_WAIT_MS'])}"
        if os.environ.get("TYCHE_DEBUG"):
            tyche_env += f" TYCHE_DEBUG={_remote_quote(os.environ['TYCHE_DEBUG'])}"
        pvss_arg = " -pvss scrape" if protocol in {"tyche-scrape", "tyche-scrape-reconfig"} else ""
        reconfig_arg = ""
        if protocol in {"tyche-reconfig", "tyche-scrape-reconfig"}:
            reconfig_events = _reconfig_events_value(options)
            reconfig_min_n = _reconfig_min_n_value(options)
            reconfig_seed = _reconfig_seed_value()
            reconfig_crash_grace_ms = _reconfig_crash_grace_ms_value()
            reconfig_arg = (
                f" -reconfig-events {_remote_quote(reconfig_events)}"
                f" -reconfig-min-n {_remote_quote(reconfig_min_n)}"
                f" -reconfig-seed {_remote_quote(reconfig_seed)}"
                f" -reconfig-crash-grace-ms {_remote_quote(reconfig_crash_grace_ms)}"
            )
        queue_len = _tyche_queue_len_for_protocol(protocol, options)
        removal_expiration_ms = options.removal_expiration_ms
        if protocol in {"tyche-reconfig", "tyche-scrape-reconfig"}:
            removal_expiration_ms = options.reconfig_removal_expiration_ms
        return (
            f"mkdir -p {_remote_quote('runlogs/' + protocol)} && "
            "export PATH=/usr/local/go/bin:$PATH && "
            f"export {tyche_env} && "
            f"/usr/bin/time -v ./bin/tyche -transport tcp -node node{node} "
            f"-n {options.n} -f {options.fault_threshold} -epochs {options.epochs} "
            f"-peers {_remote_quote(peers)} -listen 0.0.0.0:{port} "
            f"-queue-len {queue_len} -max-pool {options.max_pool} "
            f"-transport-buffer {options.transport_buffer} "
            f"-removal-expiration-ms {removal_expiration_ms} "
            f"-producer-ms {options.producer_ms} -prefill-ms {options.prefill_ms} "
            f"-epoch-timeout-ms {options.epoch_timeout_ms} -report-ms {options.report_ms} "
            f"{pvss_arg}{reconfig_arg} "
            f"> {_remote_quote(log_file)} 2>&1"
        )
    if protocol in {"asyrand", "grandline", "spurt"}:
        config_path = f"benchmark/generated/aws_n{options.n}/{protocol}.json"
        return (
            f"mkdir -p {_remote_quote('runlogs/' + protocol)} && "
            "export PATH=/usr/local/go/bin:$PATH && "
            f"GOMAXPROCS={options.gomaxprocs} && "
            f"/usr/bin/time -v ./bin/{protocol} -config {_remote_quote(config_path)} "
            f"-transport tcp -node node{node} > {_remote_quote(log_file)} 2>&1"
        )
    raise BenchError(f"unknown protocol: {protocol}")


def _run_protocol_on_host(host, options, protocol):
    node_commands = []
    for node in _aws_protocol_node_indices(protocol, options):
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
            in_stream=False,
        )
        command = "set -u; pids=\"\"; failed=0; " + "; ".join(node_commands)
        command += "; for p in $pids; do wait \"$p\" || failed=1; done; exit \"$failed\""
        conn.run(f"cd {_remote_quote(root)} && {command}", hide=False, in_stream=False)


def _fetch_node_log(host, options, protocol, node):
    local_log = options.out_root / protocol / f"node{node}.log"
    local_log.parent.mkdir(parents=True, exist_ok=True)
    with _connect(host, options) as conn:
        root = _remote_root(conn, options)
        conn.get(f"{root}/runlogs/{protocol}/node{node}.log", local=str(local_log))


def _remote_node_log_tail(host, options, protocol, node):
    log_file = f"runlogs/{protocol}/node{node}.log"
    try:
        with _connect(host, options) as conn:
            root = _remote_root(conn, options)
            result = conn.run(
                f"cd {_remote_quote(root)} && "
                f"if [ -f {_remote_quote(log_file)} ]; then tail -n 1 {_remote_quote(log_file)}; fi",
                hide=True,
                warn=True,
                in_stream=False,
            )
    except Exception as exc:
        return f"progress unavailable: {exc}"
    return result.stdout.strip()


def _remote_node_completion(host, options, protocol, node):
    log_file = f"runlogs/{protocol}/node{node}.log"
    try:
        with _connect(host, options) as conn:
            root = _remote_root(conn, options)
            result = conn.run(
                f"cd {_remote_quote(root)} && "
                f"if [ ! -f {_remote_quote(log_file)} ]; then echo missing; exit 0; fi; "
                f"tail -n 1 {_remote_quote(log_file)}; "
                f"if grep -q 'Exit status: 0' {_remote_quote(log_file)} "
                f"&& grep -q '^final metrics ' {_remote_quote(log_file)}; then "
                f"echo __BENCH_DONE_OK__; "
                f"elif grep -q 'Exit status:' {_remote_quote(log_file)}; then "
                f"echo __BENCH_DONE_FAIL__; "
                f"fi",
                hide=True,
                warn=True,
                in_stream=False,
            )
    except Exception as exc:
        return False, False, f"progress unavailable: {exc}"
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    ok = "__BENCH_DONE_OK__" in lines
    failed = "__BENCH_DONE_FAIL__" in lines
    tail_lines = [line for line in lines if not line.startswith("__BENCH_DONE_")]
    tail = tail_lines[-1] if tail_lines else ""
    return ok or failed, ok, tail


def _remote_completed_hosts(hosts, options, protocol, pending_hosts):
    if not pending_hosts:
        return {}, {}
    completed = {}
    failed = {}
    workers = min(16, len(pending_hosts))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_remote_node_completion, host, options, protocol, host.index): host
            for host in pending_hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                done, ok, tail = future.result()
            except Exception:
                continue
            if not done:
                continue
            if ok:
                completed[host.index] = tail
            else:
                failed[host.index] = BenchError(tail or "remote command exited without final metrics")
    return completed, failed


def _stop_remote_processes(host, options):
    _run_host(
        host,
        options,
        "pkill -f '([./]|/)bin/(tyche|tyche-reconfig\\.test|asyrand|grandline|spurt)' >/dev/null 2>&1 || true",
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


def _line_token(line, key):
    match = re.search(rf'\b{re.escape(key)}=("[^"]*"|\S+)', line)
    if not match:
        return ""
    value = match.group(1)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _skip_summary(lines):
    skipped = [line for line in lines if " skipped " in f" {line} "]
    if not skipped:
        return 0, "", "", ""
    last = skipped[-1]
    return len(skipped), _line_token(last, "stage"), _line_token(last, "reason"), _line_token(last, "diag")


def _reconfig_summary(lines):
    final = ""
    schedule_count = 0
    stop_count = 0
    for line in lines:
        if line.startswith("reconfig_schedule "):
            schedule_count += 1
        if " reconfig_stop_producing " in f" {line} " or " reconfig_stop_node " in f" {line} ":
            stop_count += 1
        if line.startswith("reconfig_final "):
            final = line
    if not final:
        return {
            "reconfig_scheduled_events": str(schedule_count),
            "reconfig_local_stop_events": str(stop_count),
            "reconfig_membership_changes": "0",
            "reconfig_removed": "",
            "reconfig_completed_epochs": "",
            "reconfig_final_n": "",
            "reconfig_final_f": "",
            "reconfig_config_version": "",
            "reconfig_min_n": "",
            "reconfig_seed": "",
        }
    scheduled = _line_token(final, "scheduled_events") or str(schedule_count)
    local_stops = _line_token(final, "local_stop_events") or str(stop_count)
    return {
        "reconfig_scheduled_events": scheduled,
        "reconfig_local_stop_events": local_stops,
        "reconfig_membership_changes": _line_token(final, "membership_changes"),
        "reconfig_removed": _line_token(final, "removed"),
        "reconfig_completed_epochs": _line_token(final, "completed_epochs"),
        "reconfig_final_n": _line_token(final, "final_n"),
        "reconfig_final_f": _line_token(final, "final_f"),
        "reconfig_config_version": _line_token(final, "config_version"),
        "reconfig_min_n": _line_token(final, "min_n"),
        "reconfig_seed": _line_token(final, "seed"),
    }


AWS_RESULT_FIELDS = [
    "protocol",
    "node",
    "host",
    "region",
    "ip",
    "throughput_beacon_min",
    "throughput_beacon_s",
    "elapsed_s",
    "latency_s",
    "bandwidth_kbps",
    "sent_kb",
    "recv_kb",
    "cpu_percent",
    "skipped_epochs",
    "last_skip_stage",
    "last_skip_reason",
    "last_skip_diag",
    "reconfig_scheduled_events",
    "reconfig_local_stop_events",
    "reconfig_membership_changes",
    "reconfig_removed",
    "reconfig_completed_epochs",
    "reconfig_final_n",
    "reconfig_final_f",
    "reconfig_config_version",
    "reconfig_min_n",
    "reconfig_seed",
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
    protocol_elapsed = _protocol_elapsed_seconds(final) or elapsed
    user = float(_line_value(lines, "User time (seconds)") or 0)
    sys_time = float(_line_value(lines, "System time (seconds)") or 0)
    raw_cpu = _line_value(lines, "Percent of CPU this job got")
    cpu_match = re.search(r"([0-9.]+)", raw_cpu)
    if cpu_match:
        cpu_pct = float(cpu_match.group(1))
    else:
        cpu_pct = ((user + sys_time) / elapsed * 100) if elapsed > 0 else 0
    skipped_epochs, last_skip_stage, last_skip_reason, last_skip_diag = _skip_summary(lines)
    row = {
        "protocol": protocol,
        "node": f"node{node}",
        "host": f"host{host.index}",
        "region": host.region,
        "ip": host.ip,
        "throughput_beacon_min": f"{throughput:.4f}",
        "throughput_beacon_s": f"{throughput / 60:.4f}",
        "elapsed_s": f"{protocol_elapsed:.3f}",
        "latency_s": f"{(60 / throughput) if throughput > 0 else 0:.4f}",
        "bandwidth_kbps": f"{bandwidth:.4f}",
        "sent_kb": f"{sent:.4f}",
        "recv_kb": f"{recv:.4f}",
        "cpu_percent": f"{cpu_pct:.2f}",
        "skipped_epochs": str(skipped_epochs),
        "last_skip_stage": last_skip_stage,
        "last_skip_reason": last_skip_reason,
        "last_skip_diag": last_skip_diag,
    }
    row.update(_reconfig_summary(lines))
    row["log"] = str(log_file)
    return row


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


def _run_complete_for_protocols(path, protocols, nodes):
    if (path / "failures.csv").exists():
        return False
    counts = _result_protocol_counts(path / "results.csv")
    return all(counts.get(protocol, 0) >= _default_protocol_success_threshold(protocol, nodes) for protocol in protocols)


def _completed_protocols(path, nodes):
    if (path / "failures.csv").exists():
        failed = set()
        with (path / "failures.csv").open("r", newline="", encoding="utf-8") as handle:
            failed = {row.get("protocol", "") for row in csv.DictReader(handle)}
    else:
        failed = set()
    counts = _result_protocol_counts(path / "results.csv")
    return {
        protocol
        for protocol, count in counts.items()
        if count >= _default_protocol_success_threshold(protocol, nodes) and protocol not in failed
    }


def _parse_aws_results(options, hosts, protocol_failures=None, preserve_protocols=None, completed_nodes=None):
    protocol_failures = protocol_failures or {}
    preserve_protocols = preserve_protocols or set()
    completed_nodes = completed_nodes or {}
    results_path = options.out_root / "results.csv"
    rows = []
    if results_path.exists():
        with results_path.open("r", newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                protocol = row.get("protocol", "")
                if protocol in preserve_protocols or protocol not in set(options.protocols):
                    rows.append({field: row.get(field, "") for field in AWS_RESULT_FIELDS})

    parse_errors = []
    for protocol in options.protocols:
        if protocol in preserve_protocols:
            continue
        protocol_rows = []
        protocol_parse_errors = []
        nodes_to_parse = sorted(completed_nodes.get(protocol, _aws_protocol_node_indices(protocol, options)))
        for node in nodes_to_parse:
            try:
                row = _aws_result_row(options, hosts, protocol, node)
                protocol_rows.append(row)
                skipped_epochs = int(row.get("skipped_epochs") or "0")
                if skipped_epochs > 0:
                    protocol_parse_errors.append(
                        (
                            protocol,
                            node,
                            f"skipped_epochs={skipped_epochs} last_stage={row.get('last_skip_stage', '')} "
                            f"last_reason={row.get('last_skip_reason', '')} diag={row.get('last_skip_diag', '')}",
                        )
                    )
            except Exception as exc:
                protocol_parse_errors.append((protocol, node, str(exc)))
        rows.extend(protocol_rows)
        if len(protocol_rows) < _protocol_success_threshold(protocol, options) or protocol_parse_errors:
            parse_errors.extend(protocol_parse_errors)

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


def _aws_run_config(nodes, epochs, protocol_list, epoch_timeout_ms):
    bft_f = int(os.environ.get("F", str((nodes - 1) // 3)))
    return {
        "kind": "aws",
        "nodes": nodes,
        "epochs": epochs,
        "protocols": protocol_list,
        "fault_threshold": bft_f,
        "grandline_fault_threshold": int(os.environ.get("GRANDLINE_F", str((nodes - 1) // 2))),
        "base_port": int(os.environ.get("BASE_PORT", "9000")),
        "queue_len": int(os.environ.get("QUEUE_LEN", "8")),
        "producer_ms": int(os.environ.get("PRODUCER_MS", "250")),
        "prefill_ms": int(os.environ.get("PREFILL_MS", "8000")),
        "epoch_timeout_ms": epoch_timeout_ms,
        "report_ms": int(os.environ.get("REPORT_MS", "5000")),
        "linger_ms": int(os.environ.get("LINGER_MS", "5000")),
        "max_pool": int(os.environ.get("MAX_POOL", "2")),
        "transport_buffer": int(os.environ.get("TYCHE_TRANSPORT_BUFFER", "0")),
        "removal_expiration_ms": int(os.environ.get("TYCHE_REMOVAL_EXPIRATION_MS", "0")),
        "tyche_reconfig_removal_expiration_ms": _reconfig_removal_expiration_ms_value(),
        "aggregation_lookahead": int(os.environ.get("AGGREGATION_LOOKAHEAD", "8")),
        "gomaxprocs": int(os.environ.get("GOMAXPROCS_REMOTE", "2")),
        "startup_wait_sec": int(os.environ["STARTUP_WAIT_SEC"]) if os.environ.get("STARTUP_WAIT_SEC") else None,
        "ssh_connect_timeout": int(os.environ.get("SSH_CONNECT_TIMEOUT", "6")),
        "ssh_probe_retries": int(os.environ.get("SSH_PROBE_RETRIES", "1")),
        "ssh_probe_delay_sec": int(os.environ.get("SSH_PROBE_DELAY_SEC", "0")),
        "aws_goos": os.environ.get("AWS_GOOS", "linux"),
        "aws_goarch": os.environ.get("AWS_GOARCH", "amd64"),
        "aws_cgo_enabled": os.environ.get("AWS_CGO_ENABLED", "0"),
        "tyche_epoch_attempt_ms": os.environ.get("TYCHE_EPOCH_ATTEMPT_MS", ""),
        "tyche_tcp_peer_wait_ms": os.environ.get("TYCHE_TCP_PEER_WAIT_MS", ""),
        "tyche_debug": os.environ.get("TYCHE_DEBUG", ""),
        "tyche_reconfig_events": os.environ.get("TYCHE_RECONFIG_EVENTS", str(_default_reconfig_events(epochs))),
        "tyche_reconfig_min_n": os.environ.get("TYCHE_RECONFIG_MIN_N", str(nodes - bft_f)),
        "tyche_reconfig_max_n": os.environ.get("TYCHE_RECONFIG_MAX_N", str(nodes + bft_f)),
        "tyche_reconfig_seed": os.environ.get("TYCHE_RECONFIG_SEED", "20260521"),
        "tyche_reconfig_queue_len": os.environ.get("TYCHE_RECONFIG_QUEUE_LEN", "1"),
        "tyche_reconfig_crash_grace_ms": _reconfig_crash_grace_ms_value(),
    }


def _legacy_timestamp(path):
    match = re.search(r"_(\d{8})_(\d{6})$", path.name)
    if match:
        try:
            return datetime.strptime("".join(match.groups()), "%Y%m%d%H%M%S").timestamp()
        except ValueError:
            pass
    return path.stat().st_mtime


def _legacy_results_rows(path):
    results_path = path / "results.csv"
    if not results_path.exists():
        return []
    with results_path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _legacy_aws_config_from_state(path, rows):
    state = _read_env_file(path / "aws_state.env")
    nodes = int(state.get("N") or state.get("M") or 0)
    epochs = int(state.get("EPOCHS") or 0)
    if nodes <= 0 or epochs <= 0:
        match = re.match(r"aws_n(\d+)_", path.name)
        nodes = int(match.group(1)) if match else nodes
    protocols = []
    for row in rows:
        protocol = row.get("protocol", "")
        if protocol and protocol not in protocols:
            protocols.append(protocol)
    if nodes <= 0 or epochs <= 0 or not protocols:
        return None
    return {
        "kind": "aws",
        "nodes": nodes,
        "epochs": epochs,
        "protocols": protocols,
        "fault_threshold": int(state.get("BFT_F") or ((nodes - 1) // 3)),
        "grandline_fault_threshold": int(state.get("GRANDLINE_F") or ((nodes - 1) // 2)),
        "base_port": 9000,
        "queue_len": 8,
        "producer_ms": 250,
        "prefill_ms": 8000,
        "epoch_timeout_ms": 60000,
        "report_ms": 5000,
        "linger_ms": 5000,
        "max_pool": 16,
        "transport_buffer": 0,
        "removal_expiration_ms": 0,
        "tyche_reconfig_removal_expiration_ms": "1000",
        "aggregation_lookahead": 8,
        "gomaxprocs": 4,
        "startup_wait_sec": None,
        "ssh_connect_timeout": 6,
        "ssh_probe_retries": 1,
        "ssh_probe_delay_sec": 0,
        "aws_goos": "linux",
        "aws_goarch": "amd64",
        "aws_cgo_enabled": "0",
        "tyche_epoch_attempt_ms": "10000",
        "tyche_tcp_peer_wait_ms": "",
        "tyche_debug": "",
        "tyche_reconfig_events": "",
        "tyche_reconfig_min_n": "",
        "tyche_reconfig_max_n": "",
        "tyche_reconfig_seed": "20260521",
        "tyche_reconfig_crash_grace_ms": "2000",
    }


def _legacy_group_key(config):
    return (config["kind"], config["nodes"], config["epochs"])


def _config_from_run_dir(path, rows):
    config_path = path / "run_config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            if config.get("kind") and config.get("nodes") and config.get("epochs"):
                config["protocols"] = _rows_protocols(rows) or config.get("protocols", [])
                return config
        except (OSError, json.JSONDecodeError):
            pass
    return _legacy_aws_config_from_state(path, rows)


def _is_simple_run_dir(path):
    return re.fullmatch(r"(?:aws|local)_n\d+_e\d+", path.name) is not None


def _is_extended_run_dir(path):
    return re.fullmatch(r"(?:aws|local)_n\d+_e\d+_.+", path.name) is not None


def _run_entries_from_dir(path, rows):
    if path.name.startswith("."):
        return []
    attempts_dir = path / "attempts"
    if attempts_dir.exists():
        entries = []
        run_ids = []
        for row in rows:
            run_id = row.get("run_id") or row.get("source_run") or ""
            if run_id and run_id not in run_ids:
                run_ids.append(run_id)
        for run_id in run_ids:
            run_rows = [row for row in rows if (row.get("run_id") or row.get("source_run") or "") == run_id]
            attempt_path = attempts_dir / run_id
            source = attempt_path if attempt_path.exists() else path
            run_time = run_rows[0].get("run_time") if run_rows else ""
            try:
                latest = datetime.fromisoformat(run_time).timestamp() if run_time else _legacy_timestamp(source)
            except ValueError:
                latest = _legacy_timestamp(source)
            entries.append({"path": source, "rows": run_rows, "latest": latest, "source_name": run_id})
        return entries
    return [{"path": path, "rows": rows, "latest": _legacy_timestamp(path), "source_name": path.name}]


def _rewrite_rows_for_run(rows, old_root, new_root):
    old_text = str(old_root.resolve())
    new_text = str(new_root.resolve())
    rewritten = []
    for row in rows:
        updated = dict(row)
        if updated.get("log"):
            updated["log"] = updated["log"].replace(old_text, new_text)
        rewritten.append(updated)
    return rewritten


def _copy_protocol_payload(source, dest, protocol):
    protocol_dir = source / protocol
    if protocol_dir.exists():
        target = dest / protocol
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(protocol_dir, target)


def organize_existing_runs():
    ensure_layout()
    archive = RUNS_DIR / "_archive_legacy"
    source_dirs = [
        path
        for path in RUNS_DIR.iterdir()
        if path.is_dir()
        and (_is_simple_run_dir(path) or _is_extended_run_dir(path) or re.match(r"aws_n\d+_\d{8}_\d{6}$", path.name))
    ]
    if not source_dirs and archive.exists():
        source_dirs = [
            path
            for path in archive.iterdir()
            if path.is_dir() and re.match(r"aws_n\d+_\d{8}_\d{6}$", path.name)
        ]
    if not source_dirs:
        print("No run directories need organizing.")
        return

    groups = {}
    skipped = []
    for path in source_dirs:
        rows = _legacy_results_rows(path)
        config = _config_from_run_dir(path, rows)
        if config is None:
            skipped.append(path.name)
            continue
        group = groups.setdefault(_legacy_group_key(config), {"config": config, "runs": []})
        group["runs"].extend(_run_entries_from_dir(path, rows))
        for protocol in config["protocols"]:
            if protocol not in group["config"].get("protocols", []):
                group["config"].setdefault("protocols", []).append(protocol)

    archive.mkdir(parents=True, exist_ok=True)
    organized = []
    for group in groups.values():
        config = dict(group["config"])
        config["protocols"] = []
        final, staging = _default_run_paths(config)
        rebuild = RUNS_DIR / f".{final.name}.organizing"
        _safe_remove_run_dir(rebuild)
        rebuild.mkdir(parents=True, exist_ok=True)
        history_rows = []
        latest_by_protocol = {}
        for entry in sorted(group["runs"], key=lambda item: (item["latest"], item["path"].name)):
            source = entry["path"]
            run_id = entry.get("source_name") or _run_id_from_path(source)
            run_time = _format_mtime(entry["latest"])
            protocols = _rows_protocols(entry["rows"])
            for protocol in protocols:
                if protocol not in config["protocols"]:
                    config["protocols"].append(protocol)
                _copy_protocol_attempt(source, rebuild, run_id, protocol)
                latest = latest_by_protocol.get(protocol)
                if latest is None or entry["latest"] >= latest["latest"]:
                    latest_by_protocol[protocol] = {"latest": entry["latest"], "source": source, "run_id": run_id}
            rewritten = _rewrite_rows_for_run(entry["rows"], source, rebuild / "attempts" / run_id)
            history_rows.extend(_stamp_rows(rewritten, run_id, run_time, entry.get("source_name") or source.name))

        latest_rows = _latest_rows_per_protocol(history_rows)
        if latest_rows:
            _write_csv_rows(rebuild / "results.csv", latest_rows)

        newest_source = max((entry["path"] for entry in group["runs"]), key=_legacy_timestamp)
        for filename in ("aws_state.env", "spurt_remote_summary.txt"):
            source_file = newest_source / filename
            if source_file.exists():
                shutil.copy2(source_file, rebuild / filename)
        _write_run_config(rebuild, config)
        write_protocol_run_log(rebuild)
        if final.exists():
            _safe_remove_run_dir(final)
        shutil.copytree(rebuild, final)
        _safe_remove_run_dir(rebuild)
        _rewrite_run_paths(final, rebuild, final)
        write_protocol_run_log(final)
        organized.append(final.name)

    for path in source_dirs:
        if path.parent == archive or _is_simple_run_dir(path):
            continue
        target = archive / path.name
        if target.exists():
            suffix = 1
            while (archive / f"{path.name}_{suffix}").exists():
                suffix += 1
            target = archive / f"{path.name}_{suffix}"
        path.rename(target)

    print(f"organized {len(organized)} run configuration(s)")
    for name in organized:
        print(f"  {name}")
    if skipped:
        print(f"skipped {len(skipped)} legacy run(s): {', '.join(skipped)}")
    print(f"archived legacy directories under: {archive}")


def run_aws(nodes, epochs, protocols, out_root=None, key_path=None, remote_dir="TycheBench", ssh_user=None):
    ensure_layout()
    if nodes <= 0:
        raise BenchError("nodes must be positive")
    protocol_list = _split_csv(protocols)
    if not protocol_list:
        raise BenchError("at least one protocol is required")
    settings = load_settings()
    key_file = (Path(key_path).resolve() if key_path else settings.key_path)
    epoch_timeout_ms = _aws_epoch_timeout_ms(nodes)
    config = _aws_run_config(nodes, epochs, protocol_list, epoch_timeout_ms)

    final_output = None
    resume_run = None
    if out_root:
        output = Path(out_root).resolve()
    else:
        final_output, running_output = _default_run_paths(config)
        if (
            running_output.exists()
            and not (running_output / "failures.csv").exists()
            and not _run_complete_for_protocols(running_output, protocol_list, nodes)
        ):
            resume_run = running_output
        final_output, output = _prepare_default_run_dir(config, resume=resume_run is not None)
    options = AwsOptions(
        n=nodes,
        epochs=epochs,
        protocols=protocol_list,
        out_root=Path(output).resolve(),
        generated_dir=(REPO_ROOT / "benchmark" / "generated" / f"aws_n{nodes}").resolve(),
        local_bin_dir=(
            output
            / "bin"
            / f"{config['aws_goos']}_{config['aws_goarch']}"
        ).resolve(),
        key_file=key_file,
        remote_dir=remote_dir,
        ssh_user=ssh_user,
        fault_threshold=config["fault_threshold"],
        grandline_fault_threshold=config["grandline_fault_threshold"],
        base_port=config["base_port"],
        queue_len=config["queue_len"],
        producer_ms=config["producer_ms"],
        prefill_ms=config["prefill_ms"],
        epoch_timeout_ms=config["epoch_timeout_ms"],
        report_ms=config["report_ms"],
        linger_ms=config["linger_ms"],
        max_pool=config["max_pool"],
        transport_buffer=config["transport_buffer"],
        removal_expiration_ms=config["removal_expiration_ms"],
        reconfig_removal_expiration_ms=int(config["tyche_reconfig_removal_expiration_ms"]),
        aggregation_lookahead=config["aggregation_lookahead"],
        gomaxprocs=config["gomaxprocs"],
        startup_wait_sec=config["startup_wait_sec"],
        ssh_connect_timeout=config["ssh_connect_timeout"],
        ssh_probe_retries=config["ssh_probe_retries"],
        ssh_probe_delay_sec=config["ssh_probe_delay_sec"],
    )
    protocol_retries = int(os.environ.get("AWS_PROTOCOL_RETRIES", "2"))
    options.out_root.mkdir(parents=True, exist_ok=True)
    _write_run_config(options.out_root, config)

    skip_protocols = set()
    if resume_run:
        print(f"[{time.strftime('%H:%M:%S')}] resuming AWS run: {options.out_root}")
        skip_protocols = _completed_protocols(options.out_root, nodes)
    reuse_state_hosts = os.environ.get("AWS_REUSE_STATE_HOSTS", "").lower() in {"1", "true", "yes"}
    hosts = _hosts_from_state(options.out_root / "aws_state.env", options) if reuse_state_hosts else []
    if hosts:
        print(f"[{time.strftime('%H:%M:%S')}] using AWS hosts from existing run state")
    else:
        if resume_run:
            print(f"[{time.strftime('%H:%M:%S')}] discovering current running AWS hosts")
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
    print(f"[{time.strftime('%H:%M:%S')}] uploading binaries and configs to {len(hosts)} AWS hosts")
    _parallel("upload benchmark payload", hosts, lambda host: _upload_payload_to_host(host, options), max_workers=len(hosts))

    protocol_failures = {}
    completed_nodes = {}
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
            success_threshold = _protocol_success_threshold(protocol, options)
            successful_hosts = set()
            failed_hosts = {}
            protocol_hosts = [hosts[node] for node in _aws_protocol_node_indices(protocol, options)]
            pool = ThreadPoolExecutor(max_workers=len(protocol_hosts))
            try:
                future_hosts = {pool.submit(_run_protocol_on_host, host, options, protocol): host for host in protocol_hosts}
                wait_sec = _startup_wait_seconds(options)
                if wait_sec > 0:
                    print(f"[{time.strftime('%H:%M:%S')}] waiting {wait_sec}s for startup")
                    time.sleep(wait_sec)
                pending = set(future_hosts)
                while pending:
                    done, pending = wait(pending, timeout=30, return_when=FIRST_COMPLETED)
                    if not done and pending:
                        tail = _remote_node_log_tail(hosts[0], options, protocol, 0)
                        suffix = f"; node0: {tail}" if tail else ""
                        print(
                            f"[{time.strftime('%H:%M:%S')}] {protocol} still running: "
                            f"{len(pending)}/{len(future_hosts)} host command(s) pending{suffix}"
                        )
                        pending_hosts = [future_hosts[future] for future in pending]
                        remote_done, remote_failed = _remote_completed_hosts(hosts, options, protocol, pending_hosts)
                        if remote_done or remote_failed:
                            for future in list(pending):
                                host = future_hosts[future]
                                if host.index in remote_done:
                                    successful_hosts.add(host.index)
                                    pending.remove(future)
                                    future.cancel()
                                elif host.index in remote_failed:
                                    failed_hosts[host.index] = remote_failed[host.index]
                                    pending.remove(future)
                                    future.cancel()
                            print(
                                f"[{time.strftime('%H:%M:%S')}] {protocol} remote logs show completion: "
                                f"{len(successful_hosts)}/{len(future_hosts)} successful, "
                                f"{len(failed_hosts)} failed, {len(pending)} pending"
                            )
                            if len(successful_hosts) >= success_threshold:
                                if pending:
                                    stragglers = [future_hosts[future] for future in pending]
                                    print(
                                        f"[{time.strftime('%H:%M:%S')}] {protocol} reached quorum from remote logs: "
                                        f"{len(successful_hosts)}/{len(future_hosts)} host command(s) completed; "
                                        f"stopping {len(stragglers)} straggler(s)"
                                    )
                                    _parallel(
                                        "stop straggler processes",
                                        stragglers,
                                        lambda host: _stop_remote_processes(host, options),
                                    )
                                    for future in pending:
                                        future.cancel()
                                    pending = set()
                                break
                        continue
                    for future in done:
                        host = future_hosts[future]
                        try:
                            future.result()
                            successful_hosts.add(host.index)
                        except Exception as exc:
                            failed_hosts[host.index] = exc
                    if len(successful_hosts) >= success_threshold:
                        if pending:
                            stragglers = [future_hosts[future] for future in pending]
                            print(
                                f"[{time.strftime('%H:%M:%S')}] {protocol} reached quorum: "
                                f"{len(successful_hosts)}/{len(future_hosts)} host command(s) completed; "
                                f"stopping {len(stragglers)} straggler(s)"
                            )
                            _parallel("stop straggler processes", stragglers, lambda host: _stop_remote_processes(host, options))
                            stopped, pending = wait(pending, timeout=10)
                            for future in stopped:
                                host = future_hosts[future]
                                try:
                                    future.result()
                                    successful_hosts.add(host.index)
                                except Exception as exc:
                                    failed_hosts[host.index] = exc
                            for future in pending:
                                future.cancel()
                            pending = set()
                        break
                    if len(successful_hosts) + len(pending) < success_threshold:
                        if pending:
                            stragglers = [future_hosts[future] for future in pending]
                            _parallel("stop remote processes", stragglers, lambda host: _stop_remote_processes(host, options))
                            wait(pending, timeout=10)
                            for future in pending:
                                future.cancel()
                            pending = set()
                        break
                    if pending:
                        tail = _remote_node_log_tail(hosts[0], options, protocol, 0)
                        suffix = f"; node0: {tail}" if tail else ""
                        print(
                            f"[{time.strftime('%H:%M:%S')}] {protocol} progress: "
                            f"{len(pending)}/{len(future_hosts)} host command(s) pending{suffix}"
                        )
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
            if len(successful_hosts) < success_threshold:
                failures = ", ".join(f"node{node}: {exc}" for node, exc in sorted(failed_hosts.items())[:3])
                detail = f"; first failures: {failures}" if failures else ""
                run_error = BenchError(
                    f"{protocol} completed on {len(successful_hosts)}/{len(hosts)} hosts, "
                    f"need at least {success_threshold}{detail}"
                )
            fetch_jobs = [(hosts[node], node) for node in sorted(successful_hosts)]
            fetched_nodes = set()
            fetch_errors = []
            if fetch_jobs:
                with ThreadPoolExecutor(max_workers=min(16, len(fetch_jobs))) as pool:
                    fetch_futures = {
                        pool.submit(_fetch_node_log, host, options, protocol, node): node
                        for host, node in fetch_jobs
                    }
                    for future in as_completed(fetch_futures):
                        node = fetch_futures[future]
                        try:
                            future.result()
                            fetched_nodes.add(node)
                        except Exception as exc:
                            fetch_errors.append((node, exc))
            if len(fetched_nodes) >= success_threshold:
                successful_hosts = fetched_nodes
                completed_nodes[protocol] = set(fetched_nodes)
            elif run_error is None:
                failures = ", ".join(f"node{node}: {exc}" for node, exc in fetch_errors[:3])
                detail = f"; first fetch failures: {failures}" if failures else ""
                run_error = BenchError(
                    f"fetched logs for {len(fetched_nodes)}/{len(successful_hosts)} completed {protocol} hosts, "
                    f"need at least {success_threshold}{detail}"
                )
            if run_error is not None and failed_hosts:
                diagnostic_jobs = [
                    (hosts[node], node)
                    for node in sorted(failed_hosts)
                    if node not in fetched_nodes
                ]
                if diagnostic_jobs:
                    with ThreadPoolExecutor(max_workers=min(16, len(diagnostic_jobs))) as pool:
                        diagnostics = [
                            pool.submit(_fetch_node_log, host, options, protocol, node)
                            for host, node in diagnostic_jobs
                        ]
                        for future in as_completed(diagnostics):
                            try:
                                future.result()
                            except Exception:
                                pass
            if run_error is None and protocol in {"tyche-reconfig", "tyche-scrape-reconfig"} and failed_hosts:
                stopped_jobs = [
                    (hosts[node], node)
                    for node in sorted(failed_hosts)
                    if node not in fetched_nodes
                ]
                if stopped_jobs:
                    with ThreadPoolExecutor(max_workers=min(16, len(stopped_jobs))) as pool:
                        stopped_fetches = [
                            pool.submit(_fetch_node_log, host, options, protocol, node)
                            for host, node in stopped_jobs
                        ]
                        for future in as_completed(stopped_fetches):
                            try:
                                future.result()
                            except Exception:
                                pass
            if run_error is None:
                break
            if attempt < protocol_retries:
                print(f"[{time.strftime('%H:%M:%S')}] {protocol} failed; retrying")
        if run_error is not None:
            protocol_failures[protocol] = str(run_error)
            print(f"[{time.strftime('%H:%M:%S')}] {protocol} failed; continuing with remaining protocols")

    results = _parse_aws_results(
        options,
        hosts,
        protocol_failures,
        preserve_protocols=skip_protocols,
        completed_nodes=completed_nodes,
    )
    write_protocol_run_log(options.out_root)
    _parallel("stop remote processes", hosts, lambda host: _stop_remote_processes(host, options))
    if final_output is not None and not (options.out_root / "failures.csv").exists():
        published = _publish_successful_run(options.out_root, final_output)
        options = replace(
            options,
            out_root=published,
            local_bin_dir=(published / "bin" / f"{config['aws_goos']}_{config['aws_goarch']}").resolve(),
        )
        results = published / "results.csv"
        print(f"published: {published}")
    print(f"results: {results}")
    failures = options.out_root / "failures.csv"
    if failures.exists():
        print(f"failures: {failures}")
    print(f"logs:    {options.out_root}")
    print(f"state:   {options.out_root / 'aws_state.env'}")
