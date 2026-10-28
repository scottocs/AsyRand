# Beacon benchmarks

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

## Python environment

Install the AWS and plotting dependencies from the repository root:

```powershell
python -m venv benchmark/.venv
benchmark/.venv/Scripts/python.exe -m pip install -r benchmark/requirements.txt -r benchmark/requirements-plot.txt
```

Native AWS runs also require the system OpenSSH client. Keep AWS credentials
and the private key referenced by `settings.json` local.

## Current AWS repeat workflow

`aws_bench.py --scenario repeat` runs two additional no-fault repetitions of SPURT,
Grandline and AsyRand at n=16,31,61,91,121. Each node produces 600 outputs;
the first 200 are warmup. CPU, application Tx and wall time use the same
completion-200 to completion-600 boundaries and a denominator of 400.

The runner uses `aws_common.py` for the shared native EC2/security framework,
`docker_bench.py` for configuration helpers and `bench_results.py` for node
evidence, offline baseline conversion and shared JSON/CSV/SHA operations.
The repeat workflow injects zero faults and
preserves full n membership, f=(n-1)/3 and every cryptographic check.

All protocols and both new repetitions run serially on a fixed committee for
each size, using fresh protocol processes and per-run setup. Workers validate
the complete output sequence and AsyRand history before compact collection.
After bastion-side validation, all workers and their volumes are released
before the compact result package is downloaded locally. The dedicated
bastion never participates in a protocol. Unused qualification instances are
reclaimed as soon as the committee is fixed.

The completed campaign is `runs/aws-repeat23-20261028-600/`:

- `results.csv`: 45 individual run rows, without mean rows.
- `per-node.csv`: 2880 node rows, with raw boundary evidence in compact JSON packages.
- `mean.csv`: 15 arithmetic means of the three run-level node means.
- `combined.png`, `combined.pdf`, `combined.svg`: throughput, application Tx and CPU panels.
- `report.txt`, `results.zip`: methodology, compact node results, provenance and audits.

Each run averages all n honest nodes. CPU100% means the full two-vCPU quota;
CPU milliseconds per output and outputs per CPU-second are retained alongside
utilization. Application Tx excludes self-delivery and TLS/TCP overhead.
Run1 is an independent earlier campaign; runs2/3 share instances at each size.
Real WAN, shared SMT, T3a CPU credits and execution order limit causal inference.
The figure is a descriptive mean of three runs without a significance claim.

All AWS operations use the single `aws_bench.py` entry point. Select
`--scenario single` for the original one-run comparison, `--scenario silent`
for one silent AsyRand member, or `--scenario repeat` for two new no-fault runs.
The original single-run mode retains its 100-output warmup; silent and repeat
use 200. Preparation records the scenario and dependency SHAs, and mismatches
are rejected before AWS initialization. Remote jobs retain the selected scenario.

```powershell
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py --help
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py --scenario repeat --help
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py compact-baseline --help
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py compact-node --help
```

Controller actions are `prepare`, `run`, `resume`, `remote`, `inspect`, `bundle`
and `analyze`, with the existing `--out`, `--settings`, `--campaign` and related
options. `compact-baseline` requires `--source` and `--out`; `compact-node`
requires `--folder`, `--protocol`, `--nodes` and `--repetition`.
`aws_common.py` is the infrastructure library. `bench_results.py` uses only the
standard library and can run on workers without cloud-controller dependencies.
Controller archives include all required modules; compact worker payloads
include just the result collector and verified protocol binaries.

Use each completed campaign's frozen controller and offline verification tools
to reproduce its analysis. Its `WORK.md`, manifests and audit receipts record
the executed version. Do not resume a completed campaign or edit its frozen
sources, manifests or delivered result package.

## Other retained workflows

`aws_bench.py --scenario silent` is the separate AsyRand one-silent-member workflow.
It keeps the complete n-member committee and thresholds while the last member's
protocol process remains stopped. Its results belong to a separate campaign.

`docker_bench.py`, `plot_docker_results.py` and their measurement regression
checks remain available for native Linux Docker comparisons. The standalone
AsyRand optimization tools live under `../asyrand/benchmarks/`.

The retired Fabric tasks, `tychebench` package, original Tyche/reconfiguration
plots and direct log-fetch shell entry point have been removed. Historical
run directories, archives and their frozen sources remain preserved.

## Original single-run AWS workflow


`aws_bench.py` runs SPURT, Grandline and adaptive-window AsyRand at
n=16,31,61,91,121, one fresh 600-output run per point, with the first 100
outputs excluded. It uses the eight-region `t3a.medium` settings from
`settings.json`, native processes and direct authenticated peer TCP; there is
no Docker or netem. A dedicated EC2 bastion distributes verified binaries,
launches the nodes and collects complete evidence. It never joins a committee.

The spare budgets match Silk: 24/24/32/32/40 instances by size, including the
bastion, for at most 161 simultaneous instances. Instances use unlimited CPU
credits and 24-GiB gp3 volumes. These are billable AWS resources. Every resource
is campaign tagged; cleanup terminates only that campaign's instances and
checks its volumes and security groups. Instance shutdown watchdogs provide a
separate lifetime backstop.

```powershell
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py prepare --settings benchmark/settings.json --campaign tyche-aws-20261027-600 --out benchmark/runs/aws-20261027-600
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py run --out benchmark/runs/aws-20261027-600
benchmark/.venv/Scripts/python.exe benchmark/aws_bench.py inspect --out benchmark/runs/aws-20261027-600
```

Run these commands from the repository root. Preparation verifies the current
protocol sources against the validated frozen Linux binaries, then records
source, payload and controller hashes. Preserve and execute a frozen controller
copy for a long campaign. `resume` requires an explicitly reconciled stopped
controller and an existing owned fleet; never use it to start a second controller.
Native runs set post-completion linger to zero, after all-node measurement and
fresh history verification. The bastion uses exclusive job claims and durable
PID/exit files, so management reconnects do not duplicate protocol execution.

The user's private key and AWS credentials remain local. An ephemeral campaign
SSH key is installed on the bastion and excluded from evidence archives. SSH
ingress uses observed exact `/32` sources; split-tunnel VPNs can expose different
HTTPS and raw-SSH exit addresses. The controller reconciles those sources on
transport failure without opening world ingress.

Each protocol has its own native systemd cgroup, mapped into a private mount
namespace for the unchanged measurement binary. CPU, application Tx and time
use the completion-100 to completion-600 window: exactly 500 intervals. All
nodes finish measurement before independent public-history verification starts.
Full histories are retained in node archives; streamed per-size archives and
all nested hashes, logs and metrics are independently checked locally before
continuing. A separate n4/110-output qualification smoke is excluded from the
15 formal samples. One run per point does not support replication SD or a
performance-significance claim.
