# GRandline (Go Implementation)

This module contains the Go implementation that follows the `grandline` beacon design and reuses the Tyche/SPurt code structure for transport, PVSS, DKG and test scaffolding.

## Run

Single-machine memory cluster (8 nodes, default `configs/local_8.json`):
```bash
cd grandline
go run ./cmd/grandline -config configs/local_8.json -duration 300s
```

Start one TCP node (use config with `transport: "tcp"`):
```bash
cd grandline
go run ./cmd/grandline -config configs/aws_8.json -node node0
```

## Output

The reporter prints periodic throughput and bandwidth:
- beacon count and beacon/min
- sent/received message counts
- sent/received traffic in KB
- total bandwidth KB/s
- queue backlog
- signature, verification, recovery, and PVSS timings

## Notes

- `ComQ` is implemented as an array of maps: `ComQ[i][seq]` stores commitments produced by member `i`.
- The implementation has no special-case “optimistic fast path” toggle; every epoch uses source-driven signing and recovery.
