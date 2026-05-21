# AsyRand Go Implementation

This directory contains the Go implementation of AsyRand v1.

The code is organized around the protocol components in the paper: producer, consumer, source selection, PVSS commitments, RBC dissemination, reconstruction, and BLS beacon certification.

## Directory Layout

- `cmd/asyrand`: command-line runner for local memory clusters and TCP deployments.
- `protocol`: AsyRand v1 state machine, producer, consumer, source removal, queue state, and performance counters.
- `protocol/rbc`: Bracha reliable broadcast used by the producer to disseminate PVSS commitments.
- `crypto`: PVSS commitment generation, decryption proofs, threshold reconstruction, Ed25519 signatures, BLS signatures, BLS aggregation, and hashing.
- `../utils/p2p`: shared memory and TCP transports with message and bandwidth metrics.
- `config`: JSON configuration loading, key derivation, and peer address construction.

## Protocol Flow

1. Every node continuously acts as a producer.
2. A producer creates PVSS commitments and broadcasts each commitment with RBC.
3. Delivered commitments are stored in `ComQ[i][seq]`, where `i` is the producer/source member index.
4. Each epoch deterministically selects a passive `source` from the source candidate list.
5. If the selected source has a consumable head commitment, the consumer pops it and runs `RECON -> ECHO -> READY`.
6. READY votes are BLS signature shares. A threshold set is aggregated into the beacon certificate.
7. If the selected source has no consumable commitment, it is removed from the candidate set.

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

## Run A Local Cluster

```sh
cd asyrand
go run ./cmd/asyrand -config path/to/config.json
```

With `transport` set to `memory`, this starts all configured nodes in one process.

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
- per-epoch source, consumed-node count, commitment id, and beacon prefix
- throughput in beacon/min
- sent/received message counts and bytes
- aggregate bandwidth
- `queue_total` and `queue_max`
- average timings for PVSS, RBC, BLS verification, and BLS aggregation

Example metric line:

```text
periodic metrics beacons=70 throughput=839.94beacon/min sent_msgs=38296 recv_msgs=38296 sent=16236.54KB recv=16236.54KB bandwidth=6494.13KB/s queue_total=184 queue_max=3 pvss_share_avg=4.79ms pvss_verify_avg=784us pvss_prerecon_avg=1.40ms pvss_recon_avg=7us rbc_avg=9us bls_verify_avg=3.63ms bls_agg_avg=3.65ms
```

## Run TCP Nodes

Set `cluster_ips` to IPs reachable by other nodes. Keep `listen_ip` as `0.0.0.0` when each node should listen on all interfaces.

Run one process per node:

```sh
cd asyrand
go run ./cmd/asyrand -config path/to/config.json -node node0
go run ./cmd/asyrand -config path/to/config.json -node node1
go run ./cmd/asyrand -config path/to/config.json -node node2
```

Continue for all configured nodes.

You can override transport without editing the config:

```sh
go run ./cmd/asyrand -config path/to/config.json -transport tcp -node node0
```

## Configuration Model

The JSON config supports two peer-address styles:

- `cluster_index`, `cluster_ips`, and `peers_p2p_port`
- explicit `peers` entries with `id` and `addr`

The current demo derives Ed25519, PVSS, and BLS material from deterministic seeds so benchmark runs are reproducible. For production-style deployment, replace seed-derived setup with secure key distribution.

## Current Implementation Notes

- `source` is passive; it is not a BFT proposer. It is the party whose next agreed PVSS commitment is consumed.
- `ComQ` is implemented as a dictionary array: `ComQ[i][seq]`.
- Source consumption is direct: nodes consume the selected source head when present, otherwise they remove that source from the candidate set.
- Consumer messages received before local consumer state exists are buffered and drained after the matching commitment is popped.
- The implementation is a research prototype and does not yet include adversarial fault injection, persistent key storage, production observability, or online deployment automation.
