# GRandline (Go Implementation)

This module implements the GRandLine beacon and its offline APVSS setup, using
the shared transport, verification cache and BLS12-381 arithmetic packages.

## Run

Single-machine memory cluster (8 nodes, default `configs/local_8.json`):
```bash
cd grandline
go run ./cmd/grandline -config configs/local_8.json -duration 300s
```

Ordinary packets require an authenticated sender-bound transport. Currently the
memory transport supplies it; the raw TCP adapter does not and is rejected.

## Output

The reporter prints periodic throughput and bandwidth:
- beacon count and beacon/min
- sent/received message counts
- sent/received traffic in KB
- total bandwidth KB/s
- signature, verification, recovery, and PVSS timings

## Notes

- Every epoch generates native beacon shares and reconstructs from verified shares.
- There is no producer queue, source rotation, BN256 coin, Pedersen DKG example,
  or separate BLS output certificate in this module. Offline setup uses APVSS.
- Legacy queue/PVSS timing fields remain zero in logs for experiment-parser compatibility.

## Authenticated-channel baseline

COMMIT and SHARE carry their native payloads without an outer signature envelope.
Receivers require transport authentication before parsing or buffering messages;
sender, epoch, membership, commitment and proof checks remain mandatory. This
implements the authenticated-channel abstraction instead of Section 2's general
per-message signing assumption. The APVSS NIZK contribution remains separately signed with Ed25519, as described in
Section 5.1; it is not replaced with a pairing-based BLS signature.

The beacon/APVSS path uses BLS12-381. H1 uses hash-to-curve. As in Section 5.1,
encrypted shares/secret key shares use physical G1 (48 bytes), while commitments,
CM1 and sigma1 use physical G2 (96 bytes). The crypto code keeps Figures 1/5's
logical group names and reverses pairing arguments in its suite adapter.
Polynomials, proof nonces and RS verifier challenges are freshly sampled. Epoch input binds
the setup key and canonical epoch, without a preceding-beacon dependency. Original
DLEQ proofs and pairing equations remain mandatory for received shares.

Locally generated shares enter a private verified path. Duplicate/in-flight
verification is suppressed; failed checks release their slot. Nodes advance
independently; the runner passively checks common output prefixes. Timeouts fail
rather than generating skip beacons. Integer byte counters and warmup_outputs
provide matching measurement windows. No extra output certificate is generated.

Setup remains an offline simulation, as explicitly used for the paper's
Section 5.1 evaluation; this does not implement the full recursive GRand DKG
of Figures 3/4. The beacon path implements Figure 5's one-time commitment,
per-epoch DLEQ and two-pairing check, local interpolation and responsive output.
The Go/kilic implementation and JSON wire format differ from the paper's
Rust/arkworks prototype, so numerical reproduction of its evaluation is not claimed.
Memory runs can reuse the same validated setup snapshot:

```sh
go run ./cmd/grandline -config configs/local_8.json -write-setup /tmp/grand-setup.json
go run ./cmd/grandline -config configs/local_8.json -setup-file /tmp/grand-setup.json
```

This snapshot contains private shares and is written owner-only. It belongs to
the existing test-key scaffolding, not production provisioning. Committee, proof,
public key and secret-share consistency are verified before loading it. Older
performance results are historical and must not be reused for this version.

Legacy message_signs/message_verifies and message_sign_avg/message_verify_avg
fields remain for log compatibility and are always zero. Native share/proof
timings remain separate. The standard wire protocol is
`grandline/authenticated-v1`; the mathematical epoch domain remains unchanged.
AsyRand and its manuscript are outside these changes.

## Reference beacon mode and arithmetic optimizations

The default `standard` mode authenticates the one-time online COMMIT through the
channel. The legacy config name `signed` is an alias for `standard` and never
enables outer signatures. The explicit `reference` mode follows DiPa0123/GRandLine commit
`b3e40bee70a2bb59a9832aa92e8bcf015f69233e`'s structure: fixed commitments are loaded
from the private setup, there is no online COMMIT, and SHARE has its native DLEQ
and pairing checks without a second Ed25519 envelope.
Both modes require authenticated delivery at both transport construction and
message ingress. Currently only the memory transport supplies that capability;
TCP fails closed. A configured sender name alone does not authenticate a packet.

```sh
go run ./cmd/grandline -config configs/local_8.json -beacon-mode reference
go run ./cmd/grandline -config configs/local_8.json -beacon-mode reference -write-setup /tmp/grand-reference.json
go run ./cmd/grandline -config configs/local_8.json -beacon-mode reference -setup-file /tmp/grand-reference.json
```

The fixed setup is validated, including each node's private alpha/secret binding.
Nodes receive public commitments and only their own secret and alpha. The shared
snapshot remains private test scaffolding. The public commitment equation alone
does not authenticate its sender, so reference mode never accepts online COMMIT.

Both modes now combine pairing products into one final exponentiation, hash the
epoch input to the curve once per node, decode the local secret once, and retain
verified decoded GT shares through interpolation. Subgroup, DLEQ, membership and
epoch/setup binding checks remain in place. Invalid in-flight candidates release
their slot and distinct queued candidates can be checked next. Hashes, JSON
encoding and ordinary GT interpolation remain the Go implementation's existing
choices; this is not byte-for-byte Rust reproduction or the full recursive DKG.
Comparison uses the same f and reconstruction threshold across variants, rather
than substituting the reference prototype's larger default fault threshold.

## Verification reuse within a node

The node and its APVSS scheme share one `utils/verification.Cache`. Successful
signed contribution proofs, full APVSS transcripts,
decrypted shares, the one-time beacon commitment equation and per-epoch
DLEQ/pairing checks are retained for the owner's lifetime. Repeated/in-flight
copies reuse the result even when reached through a different verification API.
Every key includes the complete verification input and public parameters;
changing a proof, public key, message or commitment requires a new check.

Shape, signer, membership and protocol-state checks remain mandatory. Failed
inputs are not cached as successes. Caches grow with retained valid evidence,
are released with their owner, and are not shared between nodes or independent
external verifiers. Stateless crypto helpers accept an optional owner cache;
omitting it intentionally performs an independent check.
