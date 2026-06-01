# Tyche Benchmark

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

## AWS Nodes

AWS node lifecycle tasks use `settings.json` by default:

```powershell
cd benchmark
.\.venv\Scripts\fab create --nodes=1
.\.venv\Scripts\fab info
.\.venv\Scripts\fab stop
.\.venv\Scripts\fab start --max=10
.\.venv\Scripts\fab destroy


fab create --nodes=4;fab aws --nodes=8 --epochs=200 --protocols=tyche-scrape;fab aws --nodes=16 --epochs=200 --protocols=tyche-scrape;fab create --nodes=7;fab aws --nodes=32 --epochs=200 --protocols=tyche-scrape;fab aws --nodes=64 --epochs=100 --protocols=tyche-scrape;fab create --nodes=4;fab aws --nodes=96 --epochs=100 --protocols=tyche-scrape;fab destroy;
```

`create --nodes=1` means one EC2 instance per region listed in `settings.json`. It waits for the instances to reach `running` and pass AWS status checks. The AWS `KeyName` must already exist in every configured region, and `key.path` must point to its local private key.
