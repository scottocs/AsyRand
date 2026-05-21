# Spurt Implementation (Go)

This directory contains a Go implementation of the Spurt beacon protocol described in `paper/Spurt.pdf`.

The implementation reuses the same transport/crypto/pvss/rbc foundations as the Tyche codebase:

- `config`: JSON config loading and key/peer parsing.
- `../utils/p2p`: shared memory/TCP transport layer with byte/message metrics.
- `crypto`: Ed25519 and BLS primitives.
- `crypto`: pairing-free PVSS commitment generation/verification/reconstruction.
- `protocol/rbc`: Bracha-style reliable broadcast.
- `protocol`: Spurt state machine, producer/consumer flow, source selection, beacon collection, and metrics.

## Directory Layout

- `cmd/spurt`: command entry for local memory cluster and single-node TCP mode.
- `configs/local_8.json`: local 8-node memory benchmark config.
- `configs/aws_8.json`: 8-node TCP/deployment template.
- `protocol`: Spurt protocol logic.

## Protocol Flow

1. Each node continuously runs a producer and continuously issues PVSS commitments.
2. A commitment from dealer `i` is stored in `ComQ[i][seq]`.
3. At each epoch, nodes select a deterministic **source** from the source-candidate ordering.
4. The source candidate’s commitment set is proposed for the epoch.
5. Nodes exchange Spurt phases (`PROPOSAL`, `PREPARE`, `PRECOMMIT`, `COMMIT`, `FINALIZE`) and, once committed, recover shares from the selected commitments.
6. Nodes derive beacon randomness and threshold aggregate BLS shares into a certificate.

The implementation keeps the source/passive-consumer structure used in Spurt: a selected source is the object of each epoch’s consumption.

## Run a Local 8-Node Memory Cluster

```bash
cd /path/to/Tyche/spurt
GOCACHE=/private/tmp/spurt-go-cache go run ./cmd/spurt -config configs/local_8.json
```

Useful config fields:

- `round`: number of epochs to run (default rounds in config).
- `f`: tolerated Byzantine faults.
- `queue_len`: max pending commitments per `ComQ[i]`.
- `producer_interval_ms`: per-node producer interval.
- `prefill_ms`: warmup period before epoch start.
- `epoch_timeout_ms`: per-epoch timeout.
- `report_interval_ms`: metrics print interval.

The runner prints per-epoch source/digest/random and periodic metrics including throughput and bandwidth.

## TCP Topology

Use `configs/aws_8.json` for multi-host TCP deployment. Set `-node` and `-transport tcp` when launching individual nodes.

```bash
cd /path/to/Tyche/spurt
GOCACHE=/private/tmp/spurt-go-cache go run ./cmd/spurt -config configs/aws_8.json -transport tcp -node node0
```

TCP peers must be reachable from each host according to `cluster_ips` and `peers_p2p_port`.

## Notes

- `go test ./...` will compile all packages; in constrained sandboxes, TCP transport tests may fail if local listeners are not allowed.
- `go test ./../utils/p2p -run TestDoesNotExist` is a useful option to compile-only the package when socket creation is blocked.
