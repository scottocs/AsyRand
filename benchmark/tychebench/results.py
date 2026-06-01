import csv
from pathlib import Path

from .paths import RUNS_DIR


def _latest_run():
    if not RUNS_DIR.exists():
        return None
    candidates = [path for path in RUNS_DIR.iterdir() if path.is_dir() and not path.name.startswith(".")]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _format_float(raw, digits=2):
    try:
        return f"{float(raw):.{digits}f}"
    except (TypeError, ValueError):
        return raw or "0"


def print_latest_summary(run_dir=None):
    run_path = Path(run_dir) if run_dir else _latest_run()
    if not run_path:
        print(f"No benchmark runs found under {RUNS_DIR}")
        return

    csv_path = run_path / "results.csv"
    if not csv_path.exists():
        print(f"No results.csv found in {run_path}")
        return

    print(f"Run: {run_path}")
    with csv_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if not rows:
        print("results.csv is empty")
        return

    headers = ("protocol", "node", "elapsed_s", "throughput_beacon_s", "bandwidth_kbps", "cpu_percent")
    print(",".join(headers))
    for row in rows:
        print(
            ",".join(
                [
                    row.get("protocol", ""),
                    row.get("node", ""),
                    _format_float(row.get("elapsed_s"), 3),
                    _format_float(row.get("throughput_beacon_s"), 4),
                    _format_float(row.get("bandwidth_kbps"), 2),
                    _format_float(row.get("cpu_percent"), 2),
                ]
            )
        )
