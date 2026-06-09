#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


EVENT_KEYS = ("stop_produce", "aba_deleted", "joining_proposal", "joined")
RECONFIG_LOG_DIRS = ("tyche-reconfig", "tyche-scrape-reconfig")
PROTOCOL_TITLES = {
    "tyche-reconfig": "Tyche AWS reconfiguration timeline",
    "tyche-scrape-reconfig": "Tyche-Scrape AWS reconfiguration timeline",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot a Tyche reconfiguration timeline SVG.")
    parser.add_argument(
        "path",
        type=Path,
        help="Run directory or tyche-reconfig log directory.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output SVG path. Defaults to <run>/reconfig_timeline_<protocol>.svg.",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        help="Epoch span to draw on the x-axis. Defaults to the log/config epoch count.",
    )
    parser.add_argument(
        "--membership-output",
        type=Path,
        help="Output SVG path for membership size timeline. Defaults next to the event timeline.",
    )
    parser.add_argument(
        "--events-csv",
        type=Path,
        help="Output CSV path for parsed reconfiguration events.",
    )
    parser.add_argument(
        "--membership-csv",
        type=Path,
        help="Output CSV path for membership size changes.",
    )
    parser.add_argument(
        "--summary-csv",
        type=Path,
        help="Output CSV path for aggregate reconfiguration stats.",
    )
    return parser.parse_args()


def resolve_dirs(path: Path) -> tuple[Path, Path]:
    path = path.resolve()
    for name in RECONFIG_LOG_DIRS:
        if (path / name).is_dir():
            return path, path / name
    if path.name in RECONFIG_LOG_DIRS and path.is_dir():
        return path.parent, path
    raise SystemExit(f"could not find reconfig logs under {path}")


def default_output_path(run_dir: Path, log_dir: Path) -> Path:
    protocol = log_dir.name.replace("-", "_")
    return run_dir / f"reconfig_timeline_{protocol}.svg"


def default_sidecar_path(output: Path, suffix: str) -> Path:
    return output.with_name(f"{output.stem}_{suffix}{output.suffix}")


def default_csv_path(output: Path, suffix: str) -> Path:
    return output.with_name(f"{output.stem}_{suffix}.csv")


def node_sort_key(item: tuple[int, str]) -> tuple[int, int | str]:
    epoch, node = item
    match = re.fullmatch(r"node(\d+)", node)
    return epoch, int(match.group(1)) if match else node


def node_label(node: str) -> str:
    return node.removeprefix("node")


def parse_int_field(line: str, name: str) -> int | None:
    match = re.search(rf"\b{re.escape(name)}=(\d+)\b", line)
    return int(match.group(1)) if match else None


def parse_members_field(line: str) -> list[str]:
    match = re.search(r"\bmembers=\[([^\]]*)\]", line)
    if not match:
        return []
    return [item for item in match.group(1).split() if item]


def event_dedupe_key(kind: str, epoch: int, node: str, line: str) -> tuple[object, ...]:
    if kind == "joined":
        config_version = parse_int_field(line, "config_version")
        if config_version is not None:
            return kind, node, config_version
        completed = parse_int_field(line, "completed")
        if completed is not None:
            return kind, node, completed + 1
    if kind == "joining_proposal":
        return kind, epoch, node
    if kind == "aba_deleted":
        config_version = parse_int_field(line, "config_version")
        if config_version is not None:
            return kind, node, config_version
    return kind, epoch, node


def add_event(
    events: dict[str, dict[tuple[object, ...], tuple[int, str]]],
    kind: str,
    epoch: int,
    node: str,
    line: str = "",
) -> None:
    key = event_dedupe_key(kind, epoch, node, line)
    current = events[kind].get(key)
    if current is None or node_sort_key((epoch, node)) < node_sort_key(current):
        events[kind][key] = (epoch, node)


def extract_log_events(log_dir: Path) -> tuple[dict[str, list[tuple[int, str]]], dict[str, int]]:
    events: dict[str, dict[tuple[object, ...], tuple[int, str]]] = {key: {} for key in EVENT_KEYS}
    meta: dict[str, int] = {}
    max_seen_epoch = 0

    event_pattern = re.compile(r"event=(stop_produce|aba_deleted|joining_proposal|joined)")
    event_epoch_pattern = re.compile(r"\bepoch=(\d+)\b")
    event_node_pattern = re.compile(r"\bnode=([^ ]+)\b")
    schedule_pattern = re.compile(r"reconfig_schedule epoch=(\d+) action=stop_producing node=([^ ]+)")
    config_pattern = re.compile(
        r"config protocol=.*?nodes=(\d+)(?:\s+initial_n=(\d+))?.*?epochs=(\d+).*?queue_len=(\d+).*?"
        r"removal_expiration_ms=(\d+).*?lookahead_expiration_ms=(\d+)"
    )
    epoch_pattern = re.compile(r"\bepoch=(\d+)\b")

    for log in sorted(log_dir.glob("*.log")):
        for line in log.read_text(errors="replace").splitlines():
            if match := config_pattern.search(line):
                nodes_raw, initial_n_raw, epochs_raw, queue_len_raw, removal_ms_raw, lookahead_ms_raw = match.groups()
                nodes = int(nodes_raw)
                initial_n = int(initial_n_raw) if initial_n_raw else nodes
                epochs = int(epochs_raw)
                queue_len = int(queue_len_raw)
                removal_ms = int(removal_ms_raw)
                lookahead_ms = int(lookahead_ms_raw)
                meta.setdefault("nodes", nodes)
                meta.setdefault("initial_n", initial_n)
                meta.setdefault("epochs", epochs)
                meta.setdefault("queue_len", queue_len)
                meta.setdefault("removal_expiration_ms", removal_ms)
                meta.setdefault("lookahead_expiration_ms", lookahead_ms)

            if match := schedule_pattern.search(line):
                add_event(events, "stop_produce", int(match.group(1)), match.group(2), line)

            if match := event_pattern.search(line):
                kind = match.group(1)
                epoch_match = event_epoch_pattern.search(line)
                node_match = event_node_pattern.search(line)
                if epoch_match and node_match:
                    add_event(events, kind, int(epoch_match.group(1)), node_match.group(1), line)

            if "reconfig_final " in line:
                for key in (
                    "scheduled_events",
                    "membership_changes",
                    "removed",
                    "completed_epochs",
                    "final_n",
                    "final_f",
                    "config_version",
                    "min_n",
                    "seed",
                ):
                    if value := parse_int_field(line, key):
                        if key in {"final_n", "final_f", "config_version", "min_n", "seed"}:
                            meta[key] = value
                        else:
                            meta[key] = max(meta.get(key, 0), value)
                if members := parse_members_field(line):
                    meta["final_members_count"] = len(members)
                    meta["final_members"] = " ".join(members)

            for match in epoch_pattern.finditer(line):
                max_seen_epoch = max(max_seen_epoch, int(match.group(1)))

    if max_seen_epoch:
        meta["max_seen_epoch"] = max_seen_epoch

    return {key: sorted(value.values(), key=node_sort_key) for key, value in events.items()}, meta


def node_universe(meta: dict[str, int | str]) -> list[str]:
    n = meta.get("initial_n") or meta.get("nodes")
    if isinstance(n, int) and n > 0:
        return [f"node{i}" for i in range(n)]
    final_members = str(meta.get("final_members", "")).split()
    return sorted(final_members, key=lambda value: int(value.removeprefix("node")) if value.startswith("node") and value.removeprefix("node").isdigit() else value)


def fault_threshold(n: int) -> int:
    return max(0, (n - 1) // 3)


def membership_series(events: dict[str, list[tuple[int, str]]], meta: dict[str, int | str]) -> list[dict[str, int | str]]:
    active = set(node_universe(meta))
    rows: list[dict[str, int | str]] = [
        {"epoch": 0, "event": "initial", "node": "", "active_n": len(active), "active_f": fault_threshold(len(active))}
    ]
    changes: list[tuple[int, int, str, str]] = []
    for epoch, node in events["aba_deleted"]:
        changes.append((epoch, 0, "removal", node))
    for epoch, node in events["joined"]:
        changes.append((epoch, 1, "join", node))
    for epoch, _, event, node in sorted(changes, key=lambda item: (item[0], item[1], node_sort_key((item[0], item[3]))[1])):
        if event == "removal":
            active.discard(node)
        elif event == "join":
            active.add(node)
        rows.append(
            {
                "epoch": epoch,
                "event": event,
                "node": node,
                "active_n": len(active),
                "active_f": fault_threshold(len(active)),
            }
        )
    return rows


def visible_event_count(events: dict[str, list[tuple[int, str]]], kind: str, max_epoch: int) -> int:
    return sum(1 for epoch, _ in events[kind] if epoch <= max_epoch)


def resolved_epoch_limit(events: dict[str, list[tuple[int, str]]], meta: dict[str, int | str], epoch_limit: int | None) -> int:
    event_epochs = [epoch for values in events.values() for epoch, _ in values]
    if epoch_limit is not None:
        if epoch_limit <= 0:
            raise SystemExit("--epochs must be positive")
        return epoch_limit
    int_values = [value for value in (meta.get("epochs", 0), meta.get("completed_epochs", 0), meta.get("max_seen_epoch", 0)) if isinstance(value, int)]
    max_epoch = max(event_epochs + int_values + [200])
    return max(200, ((max_epoch + 99) // 100) * 100)


def render_svg(
    events: dict[str, list[tuple[int, str]]],
    meta: dict[str, int],
    title: str,
    epoch_limit: int | None = None,
) -> str:
    max_epoch = resolved_epoch_limit(events, meta, epoch_limit)

    width, height = 1280, 305
    left, right = 145, 35
    rows = {
        "stop_produce": 75,
        "aba_deleted": 125,
        "joining_proposal": 175,
        "joined": 225,
    }
    labels = {
        "stop_produce": "scheduled stop",
        "aba_deleted": "removal applied",
        "joining_proposal": "join proposal (not active)",
        "joined": "join activated",
    }
    colors = {
        "stop_produce": "#d97706",
        "aba_deleted": "#dc2626",
        "joining_proposal": "#2563eb",
        "joined": "#16a34a",
    }

    def x(epoch: int) -> float:
        return left + (width - left - right) * epoch / max_epoch

    final_removed = meta.get("removed", "?")
    subtitle = (
        f"N={meta.get('nodes', '?')} queue_len={meta.get('queue_len', '?')} "
        f"epochs={max_epoch} scheduled={visible_event_count(events, 'stop_produce', max_epoch)} "
        f"removals={visible_event_count(events, 'aba_deleted', max_epoch)} final_removed={final_removed} "
        f"join_proposals={visible_event_count(events, 'joining_proposal', max_epoch)} "
        f"activated_joins={visible_event_count(events, 'joined', max_epoch)} final_n={meta.get('final_n', '?')}"
    )

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">']
    svg.append('<rect width="100%" height="100%" fill="white"/>')
    svg.append(f'<text x="145" y="30" font-family="Arial" font-size="20" font-weight="700">{title}</text>')
    svg.append(f'<text x="145" y="52" font-family="Arial" font-size="12" fill="#4b5563">{subtitle}</text>')

    tick_step = max(20, max_epoch // 10)
    for tick in range(0, max_epoch + 1, tick_step):
        xx = x(tick)
        svg.append(f'<line x1="{xx:.1f}" y1="60" x2="{xx:.1f}" y2="255" stroke="#e5e7eb"/>')
        svg.append(f'<text x="{xx:.1f}" y="280" text-anchor="middle" font-family="Arial" font-size="11">{tick}</text>')

    for kind, y in rows.items():
        svg.append(f'<text x="12" y="{y+4}" font-family="Arial" font-size="12">{labels[kind]}</text>')
        svg.append(f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#d1d5db"/>')
        for epoch, node in events[kind]:
            if epoch > max_epoch:
                continue
            xx = x(epoch)
            title = f"<title>{labels[kind]} epoch {epoch}: {node}</title>"
            if kind == "stop_produce":
                points = f"{xx:.1f},{y-7} {xx-6:.1f},{y+5} {xx+6:.1f},{y+5}"
                svg.append(f'<polygon points="{points}" fill="{colors[kind]}">{title}</polygon>')
                svg.append(f'<text x="{xx+8:.1f}" y="{y+4}" font-family="Arial" font-size="10" fill="{colors[kind]}">{node_label(node)}</text>')
            elif kind == "aba_deleted":
                svg.append(f'<g stroke="{colors[kind]}" stroke-width="2.5" stroke-linecap="round">{title}<line x1="{xx-5:.1f}" y1="{y-5}" x2="{xx+5:.1f}" y2="{y+5}"/><line x1="{xx+5:.1f}" y1="{y-5}" x2="{xx-5:.1f}" y2="{y+5}"/></g>')
            elif kind == "joining_proposal":
                svg.append(f'<circle cx="{xx:.1f}" cy="{y}" r="5" fill="white" stroke="{colors[kind]}" stroke-width="2">{title}</circle>')
                svg.append(f'<text x="{xx+8:.1f}" y="{y+4}" font-family="Arial" font-size="10" fill="{colors[kind]}">{node_label(node)}</text>')
            else:
                svg.append(f'<circle cx="{xx:.1f}" cy="{y}" r="5" fill="{colors[kind]}">{title}</circle>')

    svg.append("</svg>")
    return "\n".join(svg)


def render_membership_svg(
    series: list[dict[str, int | str]],
    events: dict[str, list[tuple[int, str]]],
    meta: dict[str, int | str],
    title: str,
    epoch_limit: int | None = None,
) -> str:
    max_epoch = resolved_epoch_limit(events, meta, epoch_limit)
    width, height = 1280, 300
    left, right, top, bottom = 80, 35, 65, 45
    plot_w = width - left - right
    plot_h = height - top - bottom
    max_n = max([int(row["active_n"]) for row in series] + [int(meta.get("nodes", 0) or 0), 1])
    min_n = min([int(row["active_n"]) for row in series] + [max_n])
    y_min = max(0, min_n - 1)
    y_max = max_n + 1
    if y_max == y_min:
        y_max += 1

    def x(epoch: int) -> float:
        return left + plot_w * min(epoch, max_epoch) / max_epoch

    def y(n: int) -> float:
        return top + plot_h * (y_max - n) / (y_max - y_min)

    visible_series = [row for row in series if int(row["epoch"]) <= max_epoch]
    points: list[tuple[int, int]] = []
    for row in visible_series:
        points.append((int(row["epoch"]), int(row["active_n"])))
    if not points or points[-1][0] < max_epoch:
        last_n = points[-1][1] if points else int(meta.get("nodes", 0) or 0)
        points.append((max_epoch, last_n))

    path_parts = []
    for idx, (epoch, active_n) in enumerate(points):
        xx, yy = x(epoch), y(active_n)
        if idx == 0:
            path_parts.append(f"M {xx:.1f} {yy:.1f}")
        else:
            prev_x = x(points[idx - 1][0])
            path_parts.append(f"L {xx:.1f} {y(points[idx - 1][1]):.1f} L {xx:.1f} {yy:.1f}")

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">']
    svg.append('<rect width="100%" height="100%" fill="white"/>')
    svg.append(f'<text x="{left}" y="30" font-family="Arial" font-size="20" font-weight="700">{title} membership size</text>')
    svg.append(
        f'<text x="{left}" y="52" font-family="Arial" font-size="12" fill="#4b5563">'
        f'epochs={max_epoch} initial_n={meta.get("initial_n", meta.get("nodes", "?"))} final_n={meta.get("final_n", "?")} final_f={meta.get("final_f", "?")} '
        f'membership_changes={meta.get("membership_changes", "?")}</text>'
    )
    for tick in range(y_min, y_max + 1):
        yy = y(tick)
        svg.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{width-right}" y2="{yy:.1f}" stroke="#eef2f7"/>')
        svg.append(f'<text x="{left-10}" y="{yy+4:.1f}" text-anchor="end" font-family="Arial" font-size="11">{tick}</text>')
    tick_step = max(20, max_epoch // 10)
    for tick in range(0, max_epoch + 1, tick_step):
        xx = x(tick)
        svg.append(f'<line x1="{xx:.1f}" y1="{top}" x2="{xx:.1f}" y2="{height-bottom}" stroke="#e5e7eb"/>')
        svg.append(f'<text x="{xx:.1f}" y="{height-18}" text-anchor="middle" font-family="Arial" font-size="11">{tick}</text>')
    svg.append(f'<path d="{" ".join(path_parts)}" fill="none" stroke="#111827" stroke-width="2.5"/>')
    for row in visible_series[1:]:
        epoch = int(row["epoch"])
        active_n = int(row["active_n"])
        color = "#dc2626" if row["event"] == "removal" else "#16a34a"
        svg.append(
            f'<circle cx="{x(epoch):.1f}" cy="{y(active_n):.1f}" r="5" fill="{color}">'
            f'<title>{row["event"]} epoch {epoch}: {row["node"]}, n={active_n}</title></circle>'
        )
    svg.append("</svg>")
    return "\n".join(svg)


def summary_rows(events: dict[str, list[tuple[int, str]]], meta: dict[str, int | str], max_epoch: int, series: list[dict[str, int | str]]) -> list[tuple[str, int | str]]:
    visible = {
        key: [(epoch, node) for epoch, node in values if epoch <= max_epoch]
        for key, values in events.items()
    }
    active_ns = [int(row["active_n"]) for row in series if int(row["epoch"]) <= max_epoch]
    rows: list[tuple[str, int | str]] = [
        ("epochs_drawn", max_epoch),
        ("initial_n", meta.get("initial_n", meta.get("nodes", ""))),
        ("queue_len", meta.get("queue_len", "")),
        ("scheduled_stop_count", len(visible["stop_produce"])),
        ("removal_count", len(visible["aba_deleted"])),
        ("joining_proposal_count", len(visible["joining_proposal"])),
        ("join_activated_count", len(visible["joined"])),
        ("membership_changes_reported", meta.get("membership_changes", "")),
        ("removed_reported", meta.get("removed", "")),
        ("completed_epochs_reported", meta.get("completed_epochs", "")),
        ("final_n_reported", meta.get("final_n", "")),
        ("final_f_reported", meta.get("final_f", "")),
        ("config_version_reported", meta.get("config_version", "")),
        ("min_n_reported", meta.get("min_n", "")),
        ("active_n_min_observed", min(active_ns) if active_ns else ""),
        ("active_n_max_observed", max(active_ns) if active_ns else ""),
        ("active_n_final_observed", active_ns[-1] if active_ns else ""),
        ("final_members", meta.get("final_members", "")),
    ]
    return rows


def write_events_csv(path: Path, events: dict[str, list[tuple[int, str]]], max_epoch: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["kind", "epoch", "node"])
        writer.writeheader()
        for kind in EVENT_KEYS:
            for epoch, node in events[kind]:
                if epoch <= max_epoch:
                    writer.writerow({"kind": kind, "epoch": epoch, "node": node})


def write_membership_csv(path: Path, series: list[dict[str, int | str]], max_epoch: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["epoch", "event", "node", "active_n", "active_f"])
        writer.writeheader()
        for row in series:
            if int(row["epoch"]) <= max_epoch:
                writer.writerow(row)


def write_summary_csv(path: Path, rows: list[tuple[str, int | str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["metric", "value"])
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    run_dir, log_dir = resolve_dirs(args.path)
    events, meta = extract_log_events(log_dir)
    output = args.output.resolve() if args.output else default_output_path(run_dir, log_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    title = PROTOCOL_TITLES.get(log_dir.name, f"{log_dir.name} AWS reconfiguration timeline")
    output.write_text(render_svg(events, meta, title, args.epochs), encoding="utf-8")
    series = membership_series(events, meta)
    max_epoch = resolved_epoch_limit(events, meta, args.epochs)
    membership_output = args.membership_output.resolve() if args.membership_output else default_sidecar_path(output, "membership")
    membership_output.parent.mkdir(parents=True, exist_ok=True)
    membership_output.write_text(render_membership_svg(series, events, meta, title, args.epochs), encoding="utf-8")
    events_csv = args.events_csv.resolve() if args.events_csv else default_csv_path(output, "events")
    membership_csv = args.membership_csv.resolve() if args.membership_csv else default_csv_path(output, "membership")
    summary_csv = args.summary_csv.resolve() if args.summary_csv else default_csv_path(output, "summary")
    write_events_csv(events_csv, events, max_epoch)
    write_membership_csv(membership_csv, series, max_epoch)
    summary = summary_rows(events, meta, max_epoch, series)
    write_summary_csv(summary_csv, summary)

    print(output)
    print(membership_output)
    print(events_csv)
    print(membership_csv)
    print(summary_csv)
    print(
        "scheduled={scheduled} removals={removals} joins={joins} final_removed={final_removed} final_n={final_n}".format(
            scheduled=visible_event_count(events, "stop_produce", max_epoch),
            removals=visible_event_count(events, "aba_deleted", max_epoch),
            joins=visible_event_count(events, "joined", max_epoch),
            final_removed=meta.get("removed", "?"),
            final_n=meta.get("final_n", "?"),
        )
    )


if __name__ == "__main__":
    main()
