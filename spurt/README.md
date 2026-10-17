# Spurt Implementation (Go)

This directory contains a Go port of the steady-state SPURT beacon protocol in
[`paper/refs/Spurt.pdf`](../paper/refs/Spurt.pdf). The inherited HotStuff view-change
protocol is not implemented; this is not a complete fault-tolerant reproduction.

The implementation reuses the same transport/crypto/pvss/rbc foundations as the Tyche codebase:

- `config`: JSON config loading and key/peer parsing.
- `../utils/p2p`: shared memory/TCP transport layer with byte/message metrics.
- `crypto`: native Ed25519 BEACON signatures; legacy BLS helpers are outside the beacon path.
- `crypto`: pairing-based SPURT PVSS on BLS12-381 with knowledge proofs and reconstruction checks.
- `protocol/rbc`: legacy helpers outside the SPURT beacon path.
- `protocol`: Spurt state machine, epoch-local PVSS aggregation, beacon collection, and metrics.

## Directory Layout

- `cmd/spurt`: command entry for local memory cluster and single-node TCP mode.
- `configs/local_8.json`: local 8-node memory benchmark config.
- `configs/aws_8.json`: 8-node TCP/deployment template.
- `protocol`: Spurt protocol logic.

## Protocol Flow

1. Nodes send PVSS commitments over authenticated channels to the leaders of the current and lookahead epochs.
2. The leader caches at most one commitment per dealer for that epoch.
3. Once the leader has collected `t=f+1` valid commitments, it deterministically selects `t` of them and aggregates them into one aggregate PVSS commitment.
4. Nodes exchange Spurt phases (`PROPOSAL`, `PREPARE`, `PRECOMMIT`, `COMMIT`, `FINALIZE`) and, once committed, recover shares from the selected aggregate.
5. Nodes output the reconstructed GT element and send signed BEACON notifications. A node lacking the proposal or reconstruction data may output after f+1 matching notifications from distinct members.

Agreement phase quorums use `n-f`, equal to the paper's `2f+1` when
`n=3f+1`. This preserves an honest quorum intersection for configurations such
as `n=8, f=2`, where the quorum is six. FINALIZE also relays after `f+1`
matching FINALIZE messages, following the paper's Bracha amplification rule;
decision still requires the full `n-f` quorum.

SPURT does not maintain a producer-consumer queue. Each leader/epoch caches only the current epoch-local PVSS inputs needed to form one aggregate; different epoch leaders may collect their inputs independently.

## Run a Local 8-Node Memory Cluster

```bash
cd /path/to/Tyche/spurt
GOCACHE=/private/tmp/spurt-go-cache go run ./cmd/spurt -config configs/local_8.json
```

Useful config fields:

- `round`: number of epochs to run (default rounds in config).
- `f`: tolerated Byzantine faults.
- `prefill_ms`: warmup period before epoch start.
- `epoch_timeout_ms`: per-epoch timeout.
- `report_interval_ms`: metrics print interval.

The runner prints per-epoch source/digest/random and periodic metrics including throughput and bandwidth.

## TCP Topology

The raw TCP adapter does not authenticate sender identities. Without outer
message signatures it is rejected before deployment; reachability or a configured
sender name is insufficient. Currently use the authenticated memory transport.

## Notes

- `go test ./...` will compile all packages; in constrained sandboxes, TCP transport tests may fail if local listeners are not allowed.
- `go test ./../utils/p2p -run TestDoesNotExist` is a useful option to compile-only the package when socket creation is blocked.

## Authenticated-channel baseline

The hot path no longer generates BLS output signatures or waits for an aggregate
output certificate. BEACON fallback notifications use Ed25519 and bind epoch,
digest and output. One notification never sets the local output; fallback needs
f+1 distinct matching signers. Sender identity must match the signature.

PVSS, PROPOSAL, PVSS_DATA, PREPARE, PRECOMMIT, COMMIT, FINALIZE and RECON
have no outer message signatures or envelope verification. Transport-origin
authentication is required at node construction and packet ingress; this uses
authenticated channels in place of Section II-A's general message-signing
implementation. BEACON retains its native transferable signature and verifier;
no second outer signature or BLS aggregate is added. The wire protocol is now
`spurt/authenticated-v1`.

PVSS uses `../utils/pairing` and an independent hash-to-curve h1. Leaders check
DLEQ knowledge proofs and the RS condition; their redundant pairing check is
omitted as in Section V-B. Exact transcript/holder/value bindings cache successful
reconstruction-share checks. Verifiers freshly sample the RS dual-code vector.
Both RS checks and reconstruction use native source-group multi-exponentiation
(Section V-E). Lookahead leaders aggregate and send private data immediately;
the digest has no preceding-beacon dependency. PREPARE and share release still
wait for the epoch to become current. Proposal gossip has been removed: the
paper's leader sends the proposal, while the agreement phases multicast votes.
Progress is event driven, without a 50 ms ticker or artificial proposal delay.

`Node.BeaconCertificate` retrieves f+1 signed BEACONs once available, and
`VerifyBeaconCertificate` checks them for external users (Section VI). Local
output does not wait for this certificate. The GT output is serialized directly;
there is no extra hash chain over the preceding beacon.

Each local node advances independently; the runner only observes matching common
output prefixes. Timeouts fail and never manufacture skip values. Integer byte
counters and warmup_outputs distinguish run/final measurement windows. BEACON
metrics are beacon_sign_avg/beacon_verify_avg. Legacy message_signs/message_verifies
and message_sign_avg/message_verify_avg fields remain for log compatibility and
are always zero. Native signature/proof bytes and work remain included in results.
Full faulty-leader HotStuff view change remains outside this baseline, so it must
not be labeled a strict full-protocol reproduction. Historical measurements are
not results for this version; the Go/kilic and JSON wire format also differ from
the paper's Quorum/gnark implementation.

## Verification reuse within a node

The node and its PVSS scheme share an owner-local verification cache. Successful
BEACON signatures, complete PVSS transcripts, DLEQ column
proofs and reconstruction shares are checked once; concurrent duplicates join
the same check. `Node.VerifyBeaconCertificate` reuses the BEACON signatures
already checked by that node. The standalone certificate API accepts an optional
cache; an external verifier must use its own cache, not another node's results.

Keys cover full inputs and public parameters. In particular, a PVSS SecretID alone
does not cover all DLEQ proof fields and is never sufficient as a cache key.
Membership, context, quorum and protocol-state checks still run. Only successes
persist for the owner's lifetime; failed inputs may be retried. The cache grows
with retained evidence and is released with its owner. BEACON verification
counters count actual Ed25519 operations, excluding cache hits.
