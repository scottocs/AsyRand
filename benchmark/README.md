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

AWS orchestration is not ported yet. The task is present, but it fails explicitly instead of calling a shell runner:

```powershell
cd benchmark
.\.venv\Scripts\fab aws --machines=4 --nodes=8 --epochs=200
```

The `local` Fabric task is a Python runner and does not call `scripts/*.sh`. The `aws` Fabric task intentionally fails until the AWS runner is ported, so it does not silently fall back to shell scripts.
