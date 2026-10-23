# Local beacon benchmarks

The comparison entry point is `latest_compare.py`. It builds the AsyRand,
GRandLine and SPURT Go programs, runs each configuration serially with a rotated
protocol order, and saves configurations, source snapshots, binaries, logs,
public AsyRand histories and CSV summaries in a new output directory.

Run commands below from the repository root, except for the curve benchmark.
Requirements are Python 3, Go 1.24 or newer, and the Go module dependencies.
The report scripts additionally require Matplotlib:

```sh
python3 -m pip install -r asyrand/benchmarks/requirements.txt
```

## End-to-end comparison

```sh
python3 asyrand/benchmarks/latest_compare.py \
  --out asyrand/benchmarks/local_compare_new \
  --variants asyrand-parallel grandline spurt \
  --nodes 4 8 16 --repeats 3 --warmup 128 --intervals 128

python3 asyrand/benchmarks/latest_report.py \
  asyrand/benchmarks/local_compare_new

python3 asyrand/benchmarks/bandwidth_report.py \
  asyrand/benchmarks/local_compare_new
```

`--out` must not exist. The default target is native `arm64`; pass
`--goarch amd64` on an x86-64 host. Omit `--variants` to also measure
`asyrand-standard`. The bandwidth report supports the three variants shown
above; the general report supports both AsyRand modes.

`results.csv` stores individual runs and `summary.csv` stores means and sample
standard deviations. `runner_metrics.csv` retains runner counters;
`asyrand_traffic.csv` and `message_types.csv` retain the communication breakdown.
`validation.json` records output consistency, public-history verification and
byte-accounting checks. `parallel_stats.py` supplies shared parsers and
`traffic_breakdown.py` classifies traffic without double counting.

The manuscript is optional. If `paper/Asyrand.tex` exists, its hash is checked
before and after the experiment; a fresh clone can run without that file.
Generated experiment directories and binaries remain ignored by Git.

These are single-host, fault-free memory-transport measurements. All nodes
share `GOMAXPROCS=8`, with four crypto workers per node. The measurement excludes
setup, a three-second prefill and post-run independent public verification.
Throughput uses the Go monotonic clock. Communication counts committee-wide
sent bytes, including loopback, over the same output window. GRandLine uses
simulated offline setup; SPURT does not implement full view change.

## Curve-operation microbenchmark

```sh
cd asyrand
GOARCH=arm64 GOCACHE=/private/tmp/tyche-crypto-go-cache \
  go test ./crypto -run '^$' -bench '^BenchmarkCurve' \
  -benchmem -benchtime=1s -count=5 -cpu=1
```

Use the host's native `GOARCH`. The source is
`crypto/curve_operations_bench_test.go`. It measures Edwards25519 scalar
multiplication, BLS12-381 G1/G2 scalar multiplication, GT exponentiation,
complete pairing and a two-term pairing product. The local GRandLine source
group scalar multiplication corresponds to physical BLS12-381 G2.

Each case rotates through 32 full-size scalar/point pairs generated outside
the timed section. Timings include output and backend allocations and exclude
input generation, decoding, encoding and input subgroup validation. A single
benchmark thread and five repetitions match the local measurement method.
These primitive timings are separate from end-to-end throughput.
