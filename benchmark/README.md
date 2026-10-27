# Tyche Benchmark

## Docker simulation on a Linux host

`docker_bench.py` runs SPURT, Grandline and AsyRand sequentially, with one
container per node and pinned Ed25519 mutual TLS 1.3. The Silk network profile
uses 1 Gbit/s, uniform one-way 10–30 ms delay, reproducible per-node netem seeds
and static neighbor entries. By default, each node has 1 vCPU, 2048 MiB RAM, no extra swap,
`GOMAXPROCS=1` and one crypto worker. Cleanup only removes the current cell.

Build the Linux binaries from the repository root:

```sh
mkdir -p bin
(cd spurt && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/spurt ./cmd/spurt)
(cd grandline && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/grandline ./cmd/grandline)
(cd asyrand && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/asyrand ./cmd/asyrand)
docker build -f benchmark/docker/Dockerfile -t tyche-benchmark:latest .
```

The default base image is the Silk runtime with seeded `tc netem`. Override
`--build-arg BASE_IMAGE=...` only with a compatible image containing `sh`, `ip`
and the same netem support.

```sh
python3 -u benchmark/docker_bench.py --campaign smoke --nodes 7 --epochs 5 --repetitions 1 --poll-seconds 3
python3 -u benchmark/docker_bench.py --campaign comparison --nodes 7,16,31,61 --epochs 500 --repetitions 3 --measure-generation --go-memory-limit 1400MiB
```

The defaults are n=7,16,31,61, three repetitions, 500 outputs, and four series:
SPURT, Grandline, AsyRand W=2 and AsyRand W=8. AsyRand uses parallel consumption;
SPURT uses lookahead 8. Grandline generates a
common offline setup before each run. Use `--asyrand-production-window 2` for a
separate W=2 campaign, `--go-memory-limit 1400MiB` for a Go soft heap limit, and
`--asyrand-recovery-interval-ms` to override the default 1000 ms recovery period.
Record and compare these settings consistently across campaigns.

Resource and execution limits can be selected explicitly. For a 2 vCPU / 4 GiB
comparison with two Go execution threads and two crypto workers:

```sh
python3 -u benchmark/docker_bench.py --campaign comparison-2cpu --nodes 16,31 --protocols grandline,asyrand-w8 --epochs 500 --repetitions 3 --measure-generation --cpu-cores 2 --memory-mib 4096 --go-max-procs 2 --crypto-workers 2 --go-memory-limit 2800MiB
```

The Docker memory and memory-plus-swap limits are equal, so no extra swap is
allowed. CPU quota, Go parallelism and crypto workers are independent options;
increasing the quota alone does not increase a single-worker crypto pool.
`--crypto-parallelism 2` also partitions independent equations within a proof;
it applies with or without `--crypto-cpu-percent`. The latter is an optional
separate crypto cgroup quota and adds a resident dispatch service. Leave it at
zero when measuring the ordinary Go scheduler under the node's Docker quota.

For long measured runs, `--poll-seconds 600` checks Docker state and logs at
ten-minute intervals. Lightweight local completion markers release the shared
generation barrier and collect successful cells promptly, without repeatedly
reading all node logs. AsyRand publishes its completion marker only after fresh
public-history verification and durable history export.

Results are saved under `benchmark/runs/<campaign>/`: configurations, image ID,
container limits, full node logs, network/CPU counters, validation and a summary
CSV. Every node must produce the complete matching output sequence and a
completion marker; AsyRand also verifies and exports its public history. The
first output establishes the measurement baseline, so 500 outputs provide 499
measured intervals. Nodes remain available until every participant completes.
With `--measure-generation`, every node records aligned CPU/network checkpoints
at output 1, each 100 outputs, and the final output. Node0 records a CPU profile.
All nodes continue helping peers until every node finishes generation, then
stop protocol work before independent public-history verification. The profile
stops before this barrier wait. Results retain both application traffic totals
and network-only counters, which exclude local self-delivery. These opt-in
measurements require Linux cgroup v2. Protocol order rotates across repetitions.

For 600 outputs with the first 100 excluded as warmup, pass
`--epochs 600 --warmup-outputs 100 --measure-generation`. This selects the
completion-100 to completion-600 checkpoints for time, CPU and network counters:
exactly 500 intervals, covering outputs 101–600. It does not use the 499 intervals
between outputs 101 and 600. Warmup must be a multiple of 100 because checkpoints
are recorded every 100 outputs. Protocol execution still emits all 600 outputs;
the legacy final log line describes the whole run and is not the published
post-warmup statistic. Manifests and generation-metrics record the selected scope.

Restarting a campaign skips validated cells and refuses to overwrite incomplete
cells. `status.json` records progress and the controller PID.

### Combined figure

```sh
python3 -m pip install -r benchmark/requirements-plot.txt
python3 benchmark/plot_docker_results.py benchmark/runs/comparison --output benchmark/runs/comparison/figures
```

The PNG/PDF/SVG figure contains throughput, sent KiB/beacon/node and CPU.
Values are averaged across nodes, then equally across the
three repetitions. Logs are checked against the saved measurements before
plotting. Existing artifact inventories are checked when available.

For generation-measured campaigns, all three panels use the same configured
output window: by default 500 outputs give 499 intervals; with 600 outputs and
100 warmup outputs, completion 100→600 gives 500 intervals. Sent data excludes self-delivery
and TLS/TCP/IP overhead. CPU uses the cgroup CPU delta in that same window and
excludes startup, public verification and completion waits. CPU percent is
normalized to the allocated quota: 100% means all allocated vCPUs are busy.
CPU ms/beacon sums CPU time across those vCPUs without normalization. It and
memory also appear in the CSV. Historical campaigns without these checkpoints
retain their original whole-container CPU approximation and traffic convention;
their plot explicitly states those limits.

To add W=2 as a fourth series, pass `--asyrand-w2-campaign <campaign-path>` and
choose a separate output directory. The original AsyRand series must use W=8.
Run values, summary CSVs and plot settings accompany the combined figure.

This directory is the default benchmark workspace. Fabric tasks live here, while generated configs and run outputs are written under `generated/` and `runs/`.

## Setup

```powershell
cd benchmark
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

On macOS/Linux:

```sh
cd benchmark
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

```powershell
cd benchmark
.\.venv\Scripts\fab local --nodes=8 --epochs=1000
.\.venv\Scripts\fab logs
```

AWS orchestration builds Linux binaries locally, uploads only those binaries plus generated configs to the EC2 nodes, and runs them over TCP:

```powershell
cd benchmark
.\.venv\Scripts\fab aws --nodes=4 --epochs=200
```

The `local` and `aws` Fabric tasks are Python runners and do not call `scripts/*.sh`. The AWS runner uses `settings.json` for `key.name`, `key.path`, instance type, and regions.
By default, `fab aws` cross-compiles with `GOOS=linux`, `GOARCH=amd64`, and `CGO_ENABLED=0`. Override these with `AWS_GOOS`, `AWS_GOARCH`, and `AWS_CGO_ENABLED` if your EC2 fleet uses a different target.
By default, benchmark output uses a stable directory name based only on mode, nodes, and epochs, such as `runs/aws_n8_e200`. A run writes into a hidden `.running` directory first, then appends successful protocol results into that shared configuration directory. Pass `--out=...` to force a specific directory and bypass this publish step.
Each published run also writes `protocol_run_log.csv`, which records the latest run time and source log for every protocol in that configuration. Older results for the same protocol remain under `attempts/`, while plots use the latest run by default. To migrate older timestamped or hash-suffixed run directories into the stable layout:

```powershell
cd benchmark
.\.venv\Scripts\fab organize-runs
```

AWS per-epoch timeout defaults to `60s * ceil(nodes / 4)`, so larger deployments do not fail on the old fixed 60s timeout. Override with `EPOCH_TIMEOUT_MS` when you need a specific value.
Large AWS runs can put enough CPU pressure on remote nodes that `sshd` is slow to send its SSH banner. If Paramiko reports `Error reading SSH protocol banner`, increase the SSH control-plane timeouts before running the benchmark:

```powershell
$env:SSH_CONNECT_TIMEOUT = "20"
$env:SSH_BANNER_TIMEOUT = "90"
$env:SSH_AUTH_TIMEOUT = "60"
$env:AWS_REMOTE_PROGRESS_POLL = "0"
.\.venv\Scripts\fab aws --nodes=96 --epochs=100 --protocols=tyche-scrape
```

For CPU-heavy SCRAPE runs, also keep remote worker settings below the instance's vCPU count, leaving headroom for `sshd` and kernel networking. For example, use lower `MAX_POOL`/`GOMAXPROCS_REMOTE` or a larger instance type if the remote logs show sustained crypto queues and high CPU. Set `AWS_REMOTE_PROGRESS_POLL=0` on small instances to avoid opening extra SSH sessions while the protocol is running.

## AWS Nodes

AWS node lifecycle tasks use `settings.json` by default:

```powershell

cd benchmark
.\.venv\Scripts\fab create --nodes=1
.\.venv\Scripts\fab info
.\.venv\Scripts\fab stop
.\.venv\Scripts\fab start --max=10
.\.venv\Scripts\fab destroy


fab create --nodes=7;fab aws --nodes=8 --epochs=400 --protocols=tyche-scrape;fab aws --nodes=16 --epochs=300 --protocols=tyche-scrape;fab aws --nodes=32 --epochs=200 --protocols=tyche-scrape;fab aws --nodes=64 --epochs=100 --protocols=tyche-scrape;fab create --nodes=4;fab aws --nodes=96 --epochs=100 --protocols=tyche-scrape;fab destroy;


fab create --nodes=7;fab aws --nodes=8 --epochs=400;fab aws --nodes=16 --epochs=300;fab aws --nodes=32 --epochs=200;fab destroy;

fab create --nodes=16;fab aws --nodes=64 --epochs=100;fab aws --nodes=96 --epochs=100;fab destroy;

fab create --nodes=7;fab aws --nodes=8 --epochs=400;fab aws --nodes=16 --epochs=300;fab aws --nodes=32 --epochs=200;fab create --nodes=9;fab aws --nodes=64 --epochs=100;fab aws --nodes=96 --epochs=100;fab destroy;  

# n=96 tyche-scrape config.
$env:TYCHE_REMOVAL_EXPIRATION_MS = "120000"
$env:TYCHE_TRANSPORT_BUFFER = "32768"
$env:PRODUCER_MS = "1000"
$env:PREFILL_MS = "3000"
$env:MAX_POOL = "2"
$env:GOMAXPROCS_REMOTE = "2"
$env:QUEUE_LEN = "2"

# reconfig timeline
python plot_reconfig_timeline.py runs/reconfig/aws_n16_e500/tyche-reconfig --epochs 500
```

`create --nodes=1` means one EC2 instance per region listed in `settings.json`. It waits for the instances to reach `running` and pass AWS status checks. The AWS `KeyName` must already exist in every configured region, and `key.path` must point to its local private key.
