# Tyche

This repository contains prototype Go implementations for Tyche and comparison protocols.

## Layout

- `Tyche/`: Tyche implementation.
- `asyrand/`: AsyRand implementation.
- `spurt/`: SPURT implementation.
- `grandline/`: Grandline implementation.
- `utils/`: shared transport and utility code.

## Test

```sh
cd Tyche
GOSUMDB=off go test ./...
```

## Comparative Benchmark

Use the same machine, Go version, `n`, `epochs`, fault threshold, producer interval, epoch timeout, and transport for every protocol. The local comparison uses in-memory transport and one beacon output as one completed epoch.

Set CPU parallelism explicitly before running:

```sh
# macOS
export GOMAXPROCS=$(sysctl -n hw.logicalcpu)

# Linux
export GOMAXPROCS=$(getconf _NPROCESSORS_ONLN)
```

### Runner Commands

The preferred experiment entrypoint is the Fabric workspace under `benchmark/`:

Windows PowerShell:

```powershell
cd benchmark
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

macOS/Linux:

```sh
cd benchmark
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Run an 8-node local in-memory comparison for all default protocols:

```powershell
cd benchmark
.\.venv\Scripts\fab local --nodes=8 --epochs=1000
.\.venv\Scripts\fab logs
```

```sh
cd benchmark
.venv/bin/fab local --nodes=8 --epochs=1000
.venv/bin/fab logs
```

Run a specific protocol set, including reconfiguration variants:

```sh
cd benchmark
.venv/bin/fab local --nodes=8 --epochs=200 --protocols=tyche,tyche-scrape,tyche-reconfig,tyche-scrape-reconfig,asyrand,grandline,spurt
```

For Tyche reconfiguration benchmarks, tune churn with Fabric options:

```sh
cd benchmark
.venv/bin/fab local --nodes=8 --epochs=200 --protocols=tyche-reconfig --reconfig-events=16
```

The reconfiguration benchmark starts with `--nodes` members and then injects churn events during the run. A stalled-source event disables one active producer; the protocol then observes that the selected source cannot supply a usable next object, drives the consume-or-mark ABA, and eventually applies the removal marker for that member. A joining proposal creates a new node and exercises the JOIN certificate path until the join activation boundary. Event choices are pseudo-random but deterministic for a given seed. By default the seed is `20260521`; override it with `--reconfig-seed`. The membership bounds default to `min_n = n - f` and `max_n = n + f`, and can be overridden with `--reconfig-min-n` and `--reconfig-max-n`.

The runner writes detailed churn events to the protocol log, including `event=stop_produce`, `event=aba_deleted`, `event=joining_proposal`, and `event=joined`. To make a horizontal epoch timeline from one run, parse those lines from the latest log under `benchmark/runs/<run>/tyche-reconfig/local.log` and draw each event at its epoch. The example below draws the same no-title timeline style used in the paper figure:

```sh
cd benchmark
.venv/bin/fab local --nodes=8 --epochs=200 --protocols=tyche-reconfig --reconfig-events=16
python - <<'PY'
from pathlib import Path
import re

run = Path("runs/local_n8_e200")
protocol_dir = run / "tyche-reconfig"
log = protocol_dir / "local.log"
events = {"stop_produce": [], "aba_deleted": [], "joining_proposal": [], "joined": []}
for line in log.read_text(errors="replace").splitlines():
    for kind in events:
        if f"event={kind} " in line:
            epoch = int(re.search(r"epoch=(\d+)", line).group(1))
            node = re.search(r"node=([^ ]+)", line).group(1)
            events[kind].append((epoch, node))

max_epoch = max((epoch for values in events.values() for epoch, _ in values), default=200)
max_epoch = max(200, ((max_epoch + 99) // 100) * 100)
width, height = 1400, 250
left, right = 125, 35
rows = {"stop_produce": 46, "aba_deleted": 88, "joining_proposal": 148, "joined": 190}
labels = {
    "stop_produce": "stalled source",
    "aba_deleted": "removal applied",
    "joining_proposal": "joining proposal",
    "joined": "join activated",
}
colors = {
    "stop_produce": "#d97706",
    "aba_deleted": "#dc2626",
    "joining_proposal": "#2563eb",
    "joined": "#16a34a",
}
def node_label(node): return node.removeprefix("node")
def x(epoch): return left + (width - left - right) * epoch / max_epoch

svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">']
svg.append('<rect width="100%" height="100%" fill="white"/>')
tick_step = max(20, max_epoch // 10)
for tick in range(0, max_epoch + 1, tick_step):
    xx = x(tick)
    svg.append(f'<line x1="{xx:.1f}" y1="25" x2="{xx:.1f}" y2="212" stroke="#e5e7eb"/>')
    svg.append(f'<text x="{xx:.1f}" y="238" text-anchor="middle" font-family="Arial" font-size="15">{tick}</text>')
for kind, y in rows.items():
    svg.append(f'<text x="10" y="{y+5}" font-family="Arial" font-size="16">{labels[kind]}</text>')
    svg.append(f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#d1d5db"/>')
    for epoch, node in events[kind]:
        xx = x(epoch)
        title = f"<title>epoch {epoch}: {node}</title>"
        if kind == "stop_produce":
            points = f"{xx:.1f},{y-14} {xx-12:.1f},{y+10} {xx+12:.1f},{y+10}"
            svg.append(f'<polygon points="{points}" fill="{colors[kind]}">{title}</polygon>')
            svg.append(f'<text x="{xx+15:.1f}" y="{y+5}" font-family="Arial" font-size="14" fill="{colors[kind]}" font-weight="700">{node_label(node)}</text>')
        elif kind == "aba_deleted":
            svg.append(f'<g stroke="{colors[kind]}" stroke-width="3.5" stroke-linecap="round">{title}<line x1="{xx-7:.1f}" y1="{y-7}" x2="{xx+7:.1f}" y2="{y+7}"/><line x1="{xx+7:.1f}" y1="{y-7}" x2="{xx-7:.1f}" y2="{y+7}"/></g>')
        else:
            svg.append(f'<circle cx="{xx:.1f}" cy="{y}" r="10" fill="{colors[kind]}">{title}</circle>')
            if kind == "joining_proposal":
                svg.append(f'<text x="{xx+15:.1f}" y="{y+5}" font-family="Arial" font-size="14" fill="{colors[kind]}" font-weight="700">{node_label(node)}</text>')
svg.append('</svg>')
out = protocol_dir / "reconfig_timeline.svg"
out.write_text("\n".join(svg), encoding="utf-8")
print(out)
PY
```

Generated configs and run outputs are stored under `benchmark/generated/` and `benchmark/runs/` by default. The local and AWS Fabric runners start Go directly from Python/Fabric; the legacy shell benchmark scripts have been removed.

### AWS Multi-Node Benchmark

AWS runs use one EC2 instance per Tyche benchmark node. Configure `benchmark/settings.json` with AWS regions, instance type, key name, and local private key path before creating or discovering instances.

Create, inspect, stop/start, and destroy AWS benchmark nodes through Fabric:

```powershell
cd benchmark
.\.venv\Scripts\fab create --nodes=8
.\.venv\Scripts\fab info
.\.venv\Scripts\fab stop
.\.venv\Scripts\fab start --max=100
.\.venv\Scripts\fab destroy
```

```sh
cd benchmark
.venv/bin/fab create --nodes=8
.venv/bin/fab info
.venv/bin/fab stop
.venv/bin/fab start --max=100
.venv/bin/fab destroy
```

Run all default protocols on 8 AWS nodes for 200 epochs:

```sh
cd benchmark
.venv/bin/fab aws --nodes=8 --epochs=200
```

Run a specific AWS protocol set:

```sh
cd benchmark
.venv/bin/fab aws --nodes=8 --epochs=200 --protocols=tyche,tyche-scrape,asyrand,grandline,spurt
```

Run AWS Tyche reconfiguration:

```sh
cd benchmark
.venv/bin/fab aws --nodes=8 --epochs=200 --protocols=tyche-reconfig,tyche-scrape-reconfig --reconfig-events=10
```

Each runner prints a final line like:

```text
final metrics beacons=1000 throughput=...beacon/min sent_msgs=... recv_msgs=... sent=...KB recv=...KB bandwidth=...KB/s
```

### CPU

Measure CPU with the same wrapper for each command:

```sh
/usr/bin/time -l go run ./cmd/tyche -n 8 -epochs 1000 -transport memory
```

Use `user CPU seconds + system CPU seconds` and the runner elapsed time:

```text
cpu_percent = (user_cpu_seconds + system_cpu_seconds) / elapsed_seconds * 100
cpu_percent_per_core = cpu_percent / logical_cpu_count
```

### Result Table

Run each protocol at least three times and report the median.

| Protocol | n | epochs | throughput (beacon/s) | bandwidth (KB/s) | CPU % | CPU % / core |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Tyche |  |  |  |  |  |  |
| AsyRand |  |  |  |  |  |  |
| SPURT |  |  |  |  |  |  |
| Grandline |  |  |  |  |  |  |

Convert throughput with:

```text
beacon/s = beacon/min / 60
```

## Public TCP Deployment

Open the chosen TCP port on every machine's firewall/security group. Use public addresses for peer dialing and `0.0.0.0` for local listening.

Tyche starts one node per machine with flags:

```sh
cd Tyche
PEERS='node0=PUBLIC_IP_0:9000,node1=PUBLIC_IP_1:9000,node2=PUBLIC_IP_2:9000,node3=PUBLIC_IP_3:9000'

go run ./cmd/tyche -transport tcp -node node0 -n 4 -epochs 100 -peers "$PEERS" -listen 0.0.0.0:9000
```

Run the same command on every machine, changing only `-node` and `-listen` when ports differ.

AsyRand, SPURT, and Grandline use TCP configs:

```json
{
  "transport": "tcp",
  "listen_ip": "0.0.0.0",
  "peers": [
    {"id": "node0", "addr": "PUBLIC_IP_0:9000"},
    {"id": "node1", "addr": "PUBLIC_IP_1:9000"}
  ]
}
```

Start one process per machine:

```sh
go run ./cmd/asyrand -config configs/aws_8.json -node node0 -transport tcp
go run ./cmd/spurt -config configs/aws_8.json -node node0 -transport tcp
go run ./cmd/grandline -config configs/aws_8.json -node node0 -transport tcp
```
