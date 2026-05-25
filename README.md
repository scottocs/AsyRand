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

```powershell
cd benchmark
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\fab local --nodes=8 --epochs=1000
.\.venv\Scripts\fab logs
```

Generated configs and run outputs are stored under `benchmark/generated/` and `benchmark/runs/` by default. The local and AWS Fabric runners start Go directly from Python/Fabric and do not call `scripts/*.sh`.

AWS node lifecycle commands are also exposed through Fabric:

```powershell
cd benchmark
.\.venv\Scripts\fab create --nodes=1
.\.venv\Scripts\fab info
.\.venv\Scripts\fab stop
.\.venv\Scripts\fab start --max=10
.\.venv\Scripts\fab destroy
```

Tyche uses flags for `n` and `epochs`:

```sh
cd Tyche
go run ./cmd/tyche -n 8 -epochs 1000 -transport memory
```

AsyRand, SPURT, and Grandline use JSON configs. Adjust `round` for `epochs`, and adjust the member list for `n`:

```sh
cd asyrand
go run ./cmd/asyrand -config configs/local_8_rounds_1000.json -transport memory

cd ../spurt
go run ./cmd/spurt -config configs/local_8_rounds_1000.json -transport memory

cd ../grandline
go run ./cmd/grandline -config configs/local_8_rounds_1000.json -transport memory
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
