import csv
import html
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path


RUNS_DIR = Path(__file__).parent / "runs"
PROTOCOLS = ["tyche", "asyrand", "grandline", "spurt"]
COLORS = {
    "tyche": "#2563eb",
    "asyrand": "#059669",
    "grandline": "#d97706",
    "spurt": "#dc2626",
}
EXPECTED_NODES = list(range(8, 97, 8))


def read_results():
    data = defaultdict(lambda: defaultdict(list))
    run_counts = defaultdict(lambda: defaultdict(int))

    for run_dir in sorted(RUNS_DIR.glob("aws_n*")):
        match = re.match(r"aws_n(\d+)_", run_dir.name)
        if not match:
            continue
        node_count = int(match.group(1))
        results_path = run_dir / "results.csv"
        if not results_path.exists():
            continue
        with results_path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                protocol = (row.get("protocol") or "").strip()
                if protocol not in PROTOCOLS:
                    continue
                try:
                    throughput = float(row.get("throughput_beacon_min") or 0)
                except ValueError:
                    continue
                if throughput <= 0:
                    continue
                data[protocol][node_count].append(throughput)
                run_counts[protocol][node_count] += 1

    return data, run_counts


def summarize(data):
    rows = []
    for protocol in PROTOCOLS:
        for node_count in sorted(data.get(protocol, {})):
            values = data[protocol][node_count]
            if not values:
                continue
            rows.append(
                {
                    "protocol": protocol,
                    "nodes": node_count,
                    "samples": len(values),
                    "mean": statistics.mean(values),
                    "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
                    "min": min(values),
                    "max": max(values),
                }
            )
    return rows


def write_summary_csv(rows):
    out_path = RUNS_DIR / "throughput_summary.csv"
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["protocol", "nodes", "samples", "mean", "stdev", "min", "max"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "protocol": row["protocol"],
                    "nodes": row["nodes"],
                    "samples": row["samples"],
                    "mean": f"{row['mean']:.6f}",
                    "stdev": f"{row['stdev']:.6f}",
                    "min": f"{row['min']:.6f}",
                    "max": f"{row['max']:.6f}",
                }
            )
    return out_path


def nice_upper(value):
    if value <= 0:
        return 1
    magnitude = 10 ** math.floor(math.log10(value))
    normalized = value / magnitude
    if normalized <= 1:
        nice = 1
    elif normalized <= 2:
        nice = 2
    elif normalized <= 5:
        nice = 5
    else:
        nice = 10
    return nice * magnitude


def build_svg(rows):
    width = 1120
    height = 680
    left = 86
    right = 32
    top = 54
    bottom = 92
    plot_w = width - left - right
    plot_h = height - top - bottom

    if not rows:
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1120\" height=\"680\"></svg>"

    max_y = max(row["mean"] + row["stdev"] for row in rows)
    y_max = nice_upper(max_y * 1.08)
    x_min = min(EXPECTED_NODES)
    x_max = max(EXPECTED_NODES)

    def x_scale(value):
        return left + (value - x_min) / (x_max - x_min) * plot_w

    def y_scale(value):
        return top + plot_h - (value / y_max) * plot_h

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#111827}",
        ".axis{stroke:#374151;stroke-width:1.4}",
        ".grid{stroke:#e5e7eb;stroke-width:1}",
        ".label{font-size:14px}",
        ".tick{font-size:12px;fill:#4b5563}",
        ".title{font-size:22px;font-weight:700}",
        ".legend{font-size:14px}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="30" text-anchor="middle" class="title">Beacon Throughput vs Cluster Size</text>',
    ]

    y_ticks = 6
    for i in range(y_ticks + 1):
        value = y_max * i / y_ticks
        y = y_scale(value)
        parts.append(f'<line x1="{left}" y1="{y:.2f}" x2="{width - right}" y2="{y:.2f}" class="grid"/>')
        parts.append(f'<text x="{left - 10}" y="{y + 4:.2f}" text-anchor="end" class="tick">{value:.0f}</text>')

    for node_count in EXPECTED_NODES:
        x = x_scale(node_count)
        parts.append(f'<line x1="{x:.2f}" y1="{top}" x2="{x:.2f}" y2="{height - bottom}" class="grid"/>')
        parts.append(f'<text x="{x:.2f}" y="{height - bottom + 24}" text-anchor="middle" class="tick">{node_count}</text>')

    parts.append(f'<line x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}" class="axis"/>')
    parts.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height - bottom}" class="axis"/>')
    parts.append(f'<text x="{left + plot_w / 2}" y="{height - 30}" text-anchor="middle" class="label">Number of Nodes</text>')
    parts.append(
        f'<text transform="translate(24 {top + plot_h / 2}) rotate(-90)" text-anchor="middle" class="label">'
        "Avg Throughput (beacons/min per node)</text>"
    )

    by_protocol = defaultdict(list)
    for row in rows:
        by_protocol[row["protocol"]].append(row)

    for protocol in PROTOCOLS:
        points = sorted(by_protocol.get(protocol, []), key=lambda row: row["nodes"])
        if not points:
            continue
        color = COLORS[protocol]
        polyline = " ".join(f'{x_scale(row["nodes"]):.2f},{y_scale(row["mean"]):.2f}' for row in points)
        parts.append(f'<polyline points="{polyline}" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for row in points:
            x = x_scale(row["nodes"])
            y = y_scale(row["mean"])
            y_top = y_scale(row["mean"] + row["stdev"])
            y_bottom = y_scale(max(0, row["mean"] - row["stdev"]))
            parts.append(f'<line x1="{x:.2f}" y1="{y_top:.2f}" x2="{x:.2f}" y2="{y_bottom:.2f}" stroke="{color}" stroke-width="1.4"/>')
            parts.append(f'<line x1="{x - 5:.2f}" y1="{y_top:.2f}" x2="{x + 5:.2f}" y2="{y_top:.2f}" stroke="{color}" stroke-width="1.4"/>')
            parts.append(f'<line x1="{x - 5:.2f}" y1="{y_bottom:.2f}" x2="{x + 5:.2f}" y2="{y_bottom:.2f}" stroke="{color}" stroke-width="1.4"/>')
            parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4.6" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')

    legend_x = left + 8
    legend_y = top + 8
    for index, protocol in enumerate(PROTOCOLS):
        if protocol not in by_protocol:
            continue
        y = legend_y + index * 24
        color = COLORS[protocol]
        parts.append(f'<line x1="{legend_x}" y1="{y}" x2="{legend_x + 24}" y2="{y}" stroke="{color}" stroke-width="2.5"/>')
        parts.append(f'<circle cx="{legend_x + 12}" cy="{y}" r="4" fill="{color}"/>')
        parts.append(f'<text x="{legend_x + 34}" y="{y + 5}" class="legend">{html.escape(protocol)}</text>')

    missing = [str(n) for n in EXPECTED_NODES if not any(row["nodes"] == n for row in rows)]
    if missing:
        note = "Missing runs: N=" + ", ".join(missing)
        parts.append(f'<text x="{width - right}" y="{height - 12}" text-anchor="end" class="tick">{html.escape(note)}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def write_html(svg, rows):
    out_path = RUNS_DIR / "throughput_summary.html"
    table_rows = []
    for row in rows:
        table_rows.append(
            "<tr>"
            f"<td>{html.escape(row['protocol'])}</td>"
            f"<td>{row['nodes']}</td>"
            f"<td>{row['samples']}</td>"
            f"<td>{row['mean']:.4f}</td>"
            f"<td>{row['stdev']:.4f}</td>"
            f"<td>{row['min']:.4f}</td>"
            f"<td>{row['max']:.4f}</td>"
            "</tr>"
        )
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Beacon Throughput vs Cluster Size</title>
<style>
body {{ font-family: Arial, Helvetica, sans-serif; margin: 28px; color: #111827; }}
.chart {{ max-width: 1120px; }}
table {{ border-collapse: collapse; margin-top: 18px; font-size: 13px; }}
th, td {{ border: 1px solid #d1d5db; padding: 6px 9px; text-align: right; }}
th:first-child, td:first-child {{ text-align: left; }}
th {{ background: #f3f4f6; }}
</style>
</head>
<body>
<div class="chart">{svg}</div>
<table>
<thead>
<tr><th>protocol</th><th>nodes</th><th>samples</th><th>mean</th><th>stdev</th><th>min</th><th>max</th></tr>
</thead>
<tbody>
{''.join(table_rows)}
</tbody>
</table>
</body>
</html>"""
    out_path.write_text(page, encoding="utf-8")
    return out_path


def main():
    data, _ = read_results()
    rows = summarize(data)
    csv_path = write_summary_csv(rows)
    svg = build_svg(rows)
    svg_path = RUNS_DIR / "throughput_summary.svg"
    svg_path.write_text(svg, encoding="utf-8")
    html_path = write_html(svg, rows)

    available_nodes = sorted({row["nodes"] for row in rows})
    print(f"Loaded node counts: {available_nodes}")
    print(f"Saved CSV:  {csv_path}")
    print(f"Saved SVG:  {svg_path}")
    print(f"Saved HTML: {html_path}")


if __name__ == "__main__":
    main()
