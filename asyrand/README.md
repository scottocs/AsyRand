# AsyRand Go Implementation

This directory contains the Go implementation of AsyRand v1.

The code is organized around the protocol components in the paper: producer, consumer, source selection, ABA-based consume/remove decisions, PVSS commitments, RBC dissemination, DKG-backed threshold coins, and BLS beacon certification.

## Directory Layout

- `cmd/asyrand`: command-line runner for local memory clusters and TCP deployments.
- `configs/local_8.json`: local 8-node in-memory configuration.
- `configs/aws_8.json`: 8-node TCP deployment template.
- `internal/asyrand`: AsyRand v1 state machine, producer, consumer, source removal, queue state, and performance counters.
- `internal/protocol/rbc`: Bracha reliable broadcast used by the producer to disseminate PVSS commitments.
- `internal/protocol/aba`: asynchronous binary agreement with optimistic fast path and threshold-coin fallback.
- `internal/pvss`: PVSS commitment generation, verification, decryption proof, and threshold reconstruction.
- `internal/crypto`: Ed25519 signatures, BLS signatures, BLS aggregation, hashing, and threshold coin shares.
- `internal/dkg`: reproducible setup from seed plus Pedersen DKG support for threshold coin material.
- `internal/p2p`: memory and TCP transports with message and bandwidth metrics.
- `internal/config`: JSON configuration loading, key derivation, and peer address construction.

## Protocol Flow

1. Every node continuously acts as a producer.
2. A producer creates PVSS commitments and broadcasts each commitment with RBC.
3. Delivered commitments are stored in `ComQ[i][seq]`, where `i` is the producer/source member index.
4. Each epoch deterministically selects a passive `source` from the source candidate list.
5. Nodes run ABA on whether the source has a consumable head commitment.
6. If ABA outputs `true`, the consumer pops the source commitment and runs `RECON -> ECHO -> READY`.
7. READY votes are BLS signature shares. A threshold set is aggregated into the beacon certificate.
8. If ABA outputs `false`, the selected source is removed from the candidate set.

## Requirements

- Go 1.24 or newer, as declared in `go.mod`.
- Network access is only needed if dependencies are not already available in the module cache.

For sandboxed environments where the default Go cache is not writable, set `GOCACHE` explicitly:

```sh
export GOCACHE=/private/tmp/asyrand-go-cache
```

## Test

```sh
cd asyrand
GOSUMDB=off go test ./...
```

The TCP transport test binds a local `127.0.0.1` port. If your sandbox blocks local socket binding, run the same command in an environment that allows local TCP listeners.

## Run A Local 8-Node Cluster

```sh
cd asyrand
go run ./cmd/asyrand -config configs/local_8.json
```

This starts all 8 nodes in one process using the memory transport.

Useful config fields:

- `round`: number of beacon epochs to produce.
- `f`: Byzantine fault threshold. Use `0` explicitly for no-fault local benchmarks.
- `queue_len`: maximum pending PVSS commitments per `ComQ[i]`.
- `producer_interval_ms`: delay between local producer attempts.
- `prefill_ms`: time to let producers fill queues before epochs start.
- `epoch_timeout_ms`: timeout per epoch.
- `report_interval_ms`: periodic metrics interval.

The runner prints:

- config summary
- per-epoch source, fast-path count, commitment id, and beacon prefix
- throughput in beacon/min
- sent/received message counts and bytes
- aggregate bandwidth
- `queue_total` and `queue_max`
- average timings for PVSS, RBC, ABA, BLS verification, and BLS aggregation

Example metric line:

```text
periodic metrics beacons=70 throughput=839.94beacon/min sent_msgs=38296 recv_msgs=38296 sent=16236.54KB recv=16236.54KB bandwidth=6494.13KB/s queue_total=184 queue_max=3 pvss_share_avg=4.79ms pvss_verify_avg=784us pvss_prerecon_avg=1.40ms pvss_recon_avg=7us rbc_avg=9us aba_avg=3us bls_verify_avg=3.63ms bls_agg_avg=3.65ms
```

## Run TCP Nodes

Use `configs/aws_8.json` or a copy of it.

Set `cluster_ips` to IPs reachable by other nodes. Keep `listen_ip` as `0.0.0.0` when each node should listen on all interfaces.

Run one process per node:

```sh
cd asyrand
go run ./cmd/asyrand -config configs/aws_8.json -node node0
go run ./cmd/asyrand -config configs/aws_8.json -node node1
go run ./cmd/asyrand -config configs/aws_8.json -node node2
```

Continue for all configured nodes.

You can override transport without editing the config:

```sh
go run ./cmd/asyrand -config configs/local_8.json -transport tcp -node node0
```

## Configuration Model

The JSON config supports two peer-address styles:

- `cluster_index`, `cluster_ips`, and `peers_p2p_port`
- explicit `peers` entries with `id` and `addr`

The current demo derives Ed25519, PVSS, BLS, and DKG setup material from deterministic seeds so benchmark runs are reproducible. For production-style deployment, replace seed-derived setup with a real distributed key generation and secure key distribution process.

## Current Implementation Notes

- `source` is passive; it is not a BFT proposer. It is the party whose next agreed PVSS commitment is consumed.
- `ComQ` is implemented as a dictionary array: `ComQ[i][seq]`.
- ABA fast path decides `true` without using the threshold coin when `2f+1` true inputs are observed.
- ABA slow path uses threshold coin shares initialized by the DKG setup.
- Consumer messages received before local consumer state exists are buffered and drained after the matching commitment is popped.
- The implementation is a research prototype and does not yet include adversarial fault injection, persistent key storage, production observability, or online deployment automation.
