# AsyRand

AsyRand is a publicly verifiable asynchronous randomness beacon for `n > 3f`
parties. It combines ALBATROSS PVSS with local-coin WaterBear Quadratic-ABA,
without an external common coin or shared-key DKG. This repository also includes
SPURT and GRandLine implementations for comparison.

## Quick start

Requires Go 1.24 or newer. Run a four-party local committee:

```sh
go -C asyrand run ./cmd/asyrand -config configs/local_4.json
```

Test all modules:

```sh
go -C utils test ./...
go -C asyrand test ./...
go -C grandline test ./...
go -C spurt test ./...
```

## Code and experiments

- `asyrand/`: beacon implementation and configuration.
- `spurt/`, `grandline/`: comparison implementations.
- `utils/`: shared transport and cryptographic helpers.
- `benchmark/`: AWS and Docker experiments.
- `asyrand/benchmarks/`: local comparison scripts.

Historical results describe their recorded source versions. GRandLine uses
simulated offline setup; SPURT does not implement full view change.
