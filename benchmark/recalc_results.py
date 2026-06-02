import argparse
import csv
import json
import re
import sys
from pathlib import Path


FIELDS = [
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
    "log",
]


KNOWN_PROTOCOLS = {
    "asyrand",
    "grandline",
    "spurt",
    "tyche",
    "tyche-scrape",
    "tyche-reconfig",
    "tyche-scrape-reconfig",
}


SCRIPT_DIR = Path(__file__).resolve().parent


def metric(line, key, default="0"):
    match = re.search(rf"(?:^|\s){re.escape(key)}=([^\s]+)", line)
    return match.group(1) if match else default


def float_metric(line, key, default=0.0):
    raw = metric(line, key, "")
    raw = raw.replace("beacon/min", "").replace("KB/s", "").replace("KB", "")
    try:
        return float(raw)
    except ValueError:
        return default


def line_value(lines, prefix):
    for line in reversed(lines):
        if prefix in line:
            return line.split(": ", 1)[-1].strip()
    return ""


def parse_duration_seconds(raw):
    raw = raw.strip()
    if not raw:
        return 0.0
    parts = raw.split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        return float(parts[0])
    except ValueError:
        return 0.0


def protocol_elapsed_seconds(final):
    elapsed = float_metric(final, "elapsed_s")
    if elapsed > 0:
        return elapsed
    throughput = float_metric(final, "throughput")
    beacons = float_metric(final, "beacons")
    if throughput > 0 and beacons > 0:
        return beacons * 60 / throughput
    return 0.0


def parse_cpu_percent(lines, fallback_elapsed):
    raw_cpu = line_value(lines, "Percent of CPU this job got")
    if raw_cpu:
        match = re.search(r"([0-9.]+)", raw_cpu)
        if match:
            return float(match.group(1))

    try:
        user = float(line_value(lines, "User time (seconds)") or 0)
        sys_time = float(line_value(lines, "System time (seconds)") or 0)
    except ValueError:
        return 0.0
    return ((user + sys_time) / fallback_elapsed * 100) if fallback_elapsed > 0 else 0.0


def line_token(line, key):
    match = re.search(rf'\b{re.escape(key)}=("[^"]*"|\S+)', line)
    if not match:
        return ""
    value = match.group(1)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def skip_summary(lines):
    skipped = [line for line in lines if " skipped " in f" {line} "]
    if not skipped:
        return 0, "", "", ""
    last = skipped[-1]
    return len(skipped), line_token(last, "stage"), line_token(last, "reason"), line_token(last, "diag")


def final_metrics(lines):
    for line in reversed(lines):
        if "final metrics" in line:
            return line
    return ""


def node_index_from_path(path):
    match = re.search(r"node(\d+)\.log$", path.name)
    return int(match.group(1)) if match else -1


def parse_node_and_host(lines, log_file, regions):
    node_index = node_index_from_path(log_file)
    node = f"node{node_index}"
    host = ""
    region = ""
    ip = ""

    command = line_value(lines, "Command being timed")
    node_match = re.search(r"(?:-node\s+)(node\d+)", command)
    if node_match:
        node = node_match.group(1)

    host_match = re.search(r"[\\/](node\d+)\.log$", str(log_file))
    if host_match:
        host = "host" + host_match.group(1).replace("node", "")
    if regions and node_index >= 0:
        region = regions[node_index % len(regions)]

    peers_line = next((line for line in lines if " peers=map[" in line), "")
    if peers_line:
        peer_match = re.search(rf"{re.escape(node)}:([0-9.]+):\d+", peers_line)
        if peer_match:
            ip = peer_match.group(1)

    return node, host, region, ip


def parse_log(protocol, log_file, regions):
    lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    final = final_metrics(lines)
    if not final:
        raise ValueError("missing final metrics")

    throughput = float_metric(final, "throughput")
    bandwidth = float_metric(final, "bandwidth")
    sent = float_metric(final, "sent")
    recv = float_metric(final, "recv")
    protocol_elapsed = protocol_elapsed_seconds(final)
    wall_elapsed = parse_duration_seconds(line_value(lines, "Elapsed (wall clock) time"))
    elapsed = protocol_elapsed or wall_elapsed
    cpu_elapsed = wall_elapsed or elapsed
    cpu_percent = parse_cpu_percent(lines, cpu_elapsed)
    skipped_epochs, last_skip_stage, last_skip_reason, last_skip_diag = skip_summary(lines)
    node, host, region, ip = parse_node_and_host(lines, log_file, regions)

    return {
        "protocol": protocol,
        "node": node,
        "host": host,
        "region": region,
        "ip": ip,
        "throughput_beacon_min": f"{throughput:.4f}",
        "throughput_beacon_s": f"{throughput / 60:.4f}",
        "elapsed_s": f"{elapsed:.3f}",
        "latency_s": f"{(60 / throughput) if throughput > 0 else 0:.4f}",
        "bandwidth_kbps": f"{bandwidth:.4f}",
        "sent_kb": f"{sent:.4f}",
        "recv_kb": f"{recv:.4f}",
        "cpu_percent": f"{cpu_percent:.2f}",
        "skipped_epochs": str(skipped_epochs),
        "last_skip_stage": last_skip_stage,
        "last_skip_reason": last_skip_reason,
        "last_skip_diag": last_skip_diag,
        "log": str(log_file.resolve()),
    }


def configured_protocols(run_dir):
    config_path = run_dir / "run_config.json"
    if not config_path.exists():
        return []
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [protocol for protocol in config.get("protocols", []) if protocol in KNOWN_PROTOCOLS]


def settings_regions(run_dir):
    settings_path = run_dir.parents[1] / "settings.json"
    if not settings_path.exists():
        return []
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    regions = settings.get("instances", {}).get("regions", [])
    return [region for region in regions if isinstance(region, str) and region]


def protocol_dirs(run_dir, source):
    candidates = []
    protocols = configured_protocols(run_dir)
    if not protocols:
        protocols = sorted(path.name for path in run_dir.iterdir() if path.is_dir() and path.name in KNOWN_PROTOCOLS)

    for protocol in protocols:
        direct = run_dir / protocol
        if direct.is_dir() and source in {"root", "latest"}:
            candidates.append((protocol, direct))

    if source in {"attempts", "latest"}:
        attempts_dir = run_dir / "attempts"
        if attempts_dir.is_dir():
            for attempt in sorted(attempts_dir.iterdir(), key=lambda path: path.stat().st_mtime):
                if not attempt.is_dir():
                    continue
                for protocol in protocols:
                    path = attempt / protocol
                    if path.is_dir():
                        candidates.append((protocol, path))

    if source in {"root", "attempts"}:
        return candidates

    latest = {}
    for protocol, path in candidates:
        logs = list(path.glob("node*.log"))
        if not logs:
            continue
        mtime = max(log.stat().st_mtime for log in logs)
        if protocol not in latest or mtime >= latest[protocol][0]:
            latest[protocol] = (mtime, path)
    return [(protocol, path) for protocol, (_, path) in latest.items()]


def write_protocol_run_log(rows, out_path):
    stats = {}
    for row in rows:
        protocol = row["protocol"]
        log_file = Path(row["log"])
        entry = stats.setdefault(protocol, {"rows": 0, "latest_mtime": 0.0, "latest_log": ""})
        entry["rows"] += 1
        try:
            mtime = log_file.stat().st_mtime
        except OSError:
            mtime = 0.0
        if mtime >= entry["latest_mtime"]:
            entry["latest_mtime"] = mtime
            entry["latest_log"] = row["log"]

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["protocol", "rows", "latest_log"])
        writer.writeheader()
        for protocol in sorted(stats):
            writer.writerow(
                {
                    "protocol": protocol,
                    "rows": stats[protocol]["rows"],
                    "latest_log": stats[protocol]["latest_log"],
                }
            )


def main():
    parser = argparse.ArgumentParser(description="Recalculate benchmark results.csv from node logs.")
    parser.add_argument("run_dir", nargs="?", default=str(SCRIPT_DIR / "runs" / "aws_n96_e100"))
    parser.add_argument("--output", default="", help="Output CSV path. Defaults to <run_dir>/results.csv.")
    parser.add_argument(
        "--source",
        choices=["root", "attempts", "latest"],
        default="root",
        help=(
            "Log source. root uses <run>/<protocol> only, which is the normal latest published layout; "
            "attempts uses every attempts/*/<protocol>; latest picks the newest protocol directory across both."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print rows and do not write files.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.is_absolute():
        run_dir = (Path.cwd() / run_dir).resolve()
    else:
        run_dir = run_dir.resolve()
    if not run_dir.exists():
        raise SystemExit(f"run directory does not exist: {run_dir}")
    out_path = Path(args.output).resolve() if args.output else run_dir / "results.csv"
    rows = []
    errors = []
    regions = settings_regions(run_dir)

    for protocol, path in protocol_dirs(run_dir, args.source):
        for log_file in sorted(path.glob("node*.log"), key=node_index_from_path):
            try:
                rows.append(parse_log(protocol, log_file, regions))
            except ValueError as exc:
                errors.append((protocol, log_file, str(exc)))

    if args.dry_run:
        writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        if out_path == run_dir / "results.csv":
            write_protocol_run_log(rows, run_dir / "protocol_run_log.csv")

    print(f"parsed rows: {len(rows)}")
    print(f"output: {out_path}")
    if errors:
        print(f"parse errors: {len(errors)}")
        for protocol, log_file, error in errors[:20]:
            print(f"{protocol} {log_file}: {error}")


if __name__ == "__main__":
    main()
