# AsyRand

This repository contains the AsyRand paper and prototype implementations.

- `paper/AsyRand.tex`: current paper source.
- `paper/AsyRand.pdf`: compiled paper.
- `asyrand/`: Go implementation of AsyRand v1.
- Root-level Python files such as `peer.py`, `node.py`, and `pvss.py`: earlier experimental prototype code for the v0 design.
- `octopus/`: reference code used during the Go refactor for networking, ABA, and signature-related structure.

The active implementation is the Go code in `asyrand/`.

## Go Implementation

The Go implementation follows the v1 protocol structure:

- PVSS producer broadcasts commitments through Bracha RBC.
- `ComQ[i][seq]` stores the PVSS commitments produced by party `i`, indexed by sequence number.
- Each epoch selects a passive `source` from the source candidate list.
- ABA decides whether the source should be consumed or removed.
- ABA has an optimistic path when at least `2f+1` parties input `true`, and a threshold-coin path otherwise.
- The consumer runs `RECON -> ECHO -> READY` and outputs a beacon with a BLS aggregate signature.
- The implementation includes local and TCP transports, DKG setup for ABA coin material, and performance metrics.

## Quick Start

```sh
cd asyrand
GOSUMDB=off go test ./...
go run ./cmd/asyrand -config configs/local_8.json
```

The local config starts an in-memory 8-node cluster.

Typical output includes epoch results and periodic metrics:

```text
config protocol=asyrand-v1 transport=memory nodes=8 f=2 rounds=3 queue_len=8 producer_ms=250 epoch_ms=15000 report_ms=5000
epoch=0 source=node5 fast=8/8 commit=... random=...
periodic metrics beacons=... throughput=... bandwidth=... queue_total=... rbc_avg=... aba_avg=...
```

## TCP Deployment

Use `asyrand/configs/aws_8.json` as the TCP template. Set:

- `transport`: `tcp`
- `listen_ip`: usually `0.0.0.0`
- `cluster_ips`: public or private IPs reachable by the other nodes
- `peers_p2p_port`: listening ports
- `node_key_seed`: deterministic node key seeds used by the demo setup

Run one process per node:

```sh
cd asyrand
go run ./cmd/asyrand -config configs/aws_8.json -node node0
go run ./cmd/asyrand -config configs/aws_8.json -node node1
```

Repeat for all configured nodes.

## Important Notes

The Go implementation is a research prototype, not a hardened production deployment. The current DKG setup path derives threshold material from configuration seed material for reproducible experiments; the `internal/dkg` package also contains a Pedersen DKG implementation and tests.

The Python implementation is kept as historical v0 prototype code. New experiments should use `asyrand/`.
