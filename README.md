# SPURT, Grandline and AsyRand

This repository contains Go implementations and comparative benchmarks for
SPURT, Grandline and AsyRand.

## Layout

- `spurt/`, `grandline/`, `asyrand/`: protocol implementations and command-line programs.
- `utils/`: shared transport, pairing and cryptographic execution helpers.
- `benchmark/`: native AWS orchestration, compact result collection and Docker comparison tools.
- `asyrand/benchmarks/`: standalone AsyRand optimization measurements.

## Tests

Each Go module can be tested from the repository root:

```sh
go -C utils test ./...
go -C spurt test ./...
go -C grandline test ./...
go -C asyrand test ./...
```

## Benchmarks

See [benchmark/README.md](benchmark/README.md) for dependencies, native AWS
campaigns, measurement boundaries and Docker comparisons.

The latest no-fault campaign compares all three protocols at
n=16,31,61,91,121, with three runs per point. Each run produces 600 outputs,
uses the first 200 as warmup and measures the shared completion-200 to
completion-600 CPU/Tx/wall-time window over 400 outputs.

Results are under `benchmark/runs/aws-repeat23-20261028-600/`:
`results.csv` contains 45 individual run rows, `per-node.csv` contains 2880 node
rows, and `mean.csv` contains 15 three-run means. The `combined` PNG/PDF/SVG
figure presents throughput, application Tx and CPU utilization. `results.zip`
preserves the compact node results, provenance and audits.

The dedicated AWS bastion validates compact results before workers and volumes
are released; local downloads begin only after that release. All task resources
were independently verified as removed after completion. Private keys and AWS
credentials stay local and are excluded from result packages.

Completed campaigns preserve their own frozen sources and audit receipts.
The original Tyche/Fabric and reconfiguration experiment entry points have
been retired; the current experiment guide covers the three protocols above.
