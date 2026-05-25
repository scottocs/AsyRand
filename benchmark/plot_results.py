import csv
import json
import re
from pathlib import Path
from collections import defaultdict

RUNS_DIR = Path(__file__).parent / "runs"

data = defaultdict(lambda: defaultdict(list))

for run_dir in sorted(RUNS_DIR.glob("aws_n*")):
    m = re.match(r"aws_n(\d+)_", run_dir.name)
    if not m:
        continue
    node_count = int(m.group(1))
    results_path = run_dir / "results.csv"
    if not results_path.exists():
        continue
    with open(results_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            proto = row["protocol"].strip()
            tpm = float(row["throughput_beacon_min"])
            data[proto][node_count].append(tpm)

import statistics

PROTOCOLS = ["tyche", "asyrand", "grandline", "spurt"]

datasets = []
for proto in PROTOCOLS:
    if proto not in data:
        continue
    xs = sorted(data[proto].keys())
    ys = [statistics.mean(data[proto][n]) for n in xs]
    stdevs = [statistics.stdev(data[proto][n]) if len(data[proto][n]) > 1 else 0 for n in xs]
    datasets.append({
        "label": proto,
        "x": xs,
        "y": ys,
        "stdev": stdevs,
    })

chart_data = json.dumps(datasets, indent=2)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Beacon Throughput vs Cluster Size</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<h2>Beacon Throughput vs Cluster Size</h2>
<canvas id="chart" width="800" height="500"></canvas>
<script>
const datasets = {chart_data};

const colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'];
const markers = ['circle', 'rect', 'rectRounded', 'triangle'];

const chartDatasets = datasets.map((ds, i) => ({{
    label: ds.label,
    data: ds.x.map((x, j) => ({{ x: x, y: ds.y[j] }})),
    borderColor: colors[i],
    backgroundColor: colors[i] + '20',
    borderWidth: 2,
    pointRadius: 5,
    pointBackgroundColor: colors[i],
    showLine: true,
    tension: 0,
    errorBars: ds.stdev,
}}));

// Compute error bar plugin
const errorBarPlugin = {{
    id: 'errorBars',
    afterDraw(chart) {{
        const ctx = chart.ctx;
        const xAxis = chart.scales.x;
        const yAxis = chart.scales.y;
        chart.data.datasets.forEach((ds, i) => {{
            const meta = chart.getDatasetMeta(i);
            if (!meta.visible) return;
            const stdevs = datasets[i].stdev;
            meta.data.forEach((pt, j) => {{
                const yVal = ds.data[j].y;
                const sd = stdevs[j];
                const yTop = yAxis.getPixelForValue(yVal + sd);
                const yBot = yAxis.getPixelForValue(yVal - sd);
                const x = pt.x;
                ctx.save();
                ctx.strokeStyle = colors[i];
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.moveTo(x, yTop);
                ctx.lineTo(x, yBot);
                ctx.stroke();
                // caps
                ctx.beginPath();
                ctx.moveTo(x - 4, yTop);
                ctx.lineTo(x + 4, yTop);
                ctx.moveTo(x - 4, yBot);
                ctx.lineTo(x + 4, yBot);
                ctx.stroke();
                ctx.restore();
            }});
        }});
    }}
}};

new Chart(document.getElementById('chart'), {{
    type: 'scatter',
    data: {{ datasets: chartDatasets }},
    plugins: [errorBarPlugin],
    options: {{
        responsive: false,
        plugins: {{
            title: {{
                display: true,
                text: 'Beacon Throughput vs Cluster Size',
                font: {{ size: 16 }}
            }}
        }},
        scales: {{
            x: {{
                type: 'linear',
                title: {{
                    display: true,
                    text: 'Number of Nodes',
                    font: {{ size: 13 }}
                }},
                ticks: {{ stepSize: 4 }},
                min: 2,
                max: 18
            }},
            y: {{
                title: {{
                    display: true,
                    text: 'Avg Throughput (beacons/min per node)',
                    font: {{ size: 13 }}
                }}
            }}
        }}
    }}
}});
</script>
</body>
</html>"""

out_path = RUNS_DIR / "throughput_summary.html"
out_path.write_text(html, encoding="utf-8")
print(f"Saved to {out_path}")
