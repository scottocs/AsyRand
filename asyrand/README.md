# AsyRand implementation

This module implements the individual-object AsyRand construction in
`paper/Tyche/main.tex`. The previous copied SPURT command/state machine has been
replaced. The current wire/config version is `asyrand-v2`: it follows the
shared-column Producer and BEACON-only Consumer history. Version 1 archives
and mixed-version peers cannot be reused under this version. It uses contextual single-secret ALBATROSS PVSS and local-coin Quadratic-ABA;
beacon generation has no external common-coin service.

## Run

```sh
cd asyrand
go run ./cmd/asyrand -config configs/local_4.json
go run ./cmd/asyrand -config configs/local_8.json
```

The default local deployment starts the complete committee in one process
using `../utils/p2p` memory transports. Each logged output has matching beacon
records at every local node. Timeouts abort the run and do not produce skipped
beacons. `-duration 60s` is a run watchdog, not a consensus timeout.

TCP supports either one local process holding the committee or one process per
member, with the existing `cluster_ips`, `peers_p2p_port` and `node_key_seed`
layout:

```sh
go run ./cmd/asyrand -config configs/local_4.json -transport tcp
go run ./cmd/asyrand -config configs/aws_8.json -node node0
```

Use the same public committee, fault bound, session identifier and consumption
mode at every peer. Choose a fresh common `session_id` for each independent
run. Production deployments must provision each member's private keys privately;
the existing JSON templates deliberately contain all deterministic test seeds.
The current archive is in memory; stopping and restarting with the same session
requires persistent producer reservations and signed history, which this runner
does not implement.

## Parameters

All parameters are defined in `config/config.go`:

| JSON field | Meaning |
| --- | --- |
| `cluster_index`, `node_key_seed` | Ordered committee and test key material |
| `f` | Static Byzantine fault bound; requires `n > 3f` |
| `production_window` | Producer window W; minimum 2, default 8 |
| `parallel_consumption` | First-f-output overlap variant; JSON default true; explicit false selects standard mode |
| `session_id` | Common authenticated run context |
| `round`, `warmup_outputs` | Measured target and excluded warm-up output count |
| `max_pool` | Crypto workers per member |
| `transport`, `transport_buffer` | Memory/TCP deployment and inbox capacity |
| `prefill_ms` | Producer prefill before enabling local consumers |
| `epoch_timeout_ms`, `linger_ms` | Runner watchdog and final TCP service time |
| `send_retry_ms`, `recovery_interval_ms` | Channel retries and initial passive recovery polling delay |
| `aba_future_round_window` | Bounded ABA future-round admission; default 8 |
| `history_batch_size` | Maximum entries per history pull; default 8 |

The certificate quorum is `n-f`, the reconstruction threshold is `f+1`, and
RSQ capacity is `f+1`; these are derived parameters. `production_window` is
separate from the per-round ABA admission window. Genesis randomness is derived
from the verified first-column record and the public context, rather than a
fixed configuration seed. The old `aggregation_lookahead` has been replaced by
`production_window`.

## Protocol and public verification

- Producers reserve a sequence once, sample fresh PVSS objects, and broadcast
  at most the positions p_i <= k+W-1, using the shared consumption column k. Every ready object has a verified PVSS
  transcript and an `n-f`-signature RBC READY certificate.
- Each column uses a certified whole-column ABA. A zero decision enables one
  object ABA per source. Input zero is gated by `n-f` certified one decisions;
  the final column retains **all** object decisions, including rejections.
- The default parallel consumer starts the successor ABA in the background,
  uniformly omits the next-column hash for its first f outputs, and applies the
  complete-successor barrier before output f+1's share. Standard mode applies
  that barrier before the first output.
- Selection uses sorted eligible sources and a persistent RSQ across columns.
  Every output verifies f+1 distinct decryption proofs and
  directly installs the resulting record and witness. Exhausting the accepted
  set advances k and U in that same transition; no CLOSE record is appended.
- Full column/history/ABA evidence is retained and served on request. Records
  and witnesses are assembled locally without an output-vote phase. An early
  witness receiver still emits its own RECON before installation. Future ABA
  packets beyond the admission window are recovered
  from authenticated sender archives; they do not allocate unbounded rounds.
  A future RECON can trigger one immediate predecessor pull when column
  prerequisites are missing; a stalled native reconstruction uses periodic
  recovery. Periodic history pulls rotate through the membership and advertise
  the contiguous column evidence already retained locally, avoiding multiple
  full copies. Unavailable responders do not prevent later peers being tried.
  Certificate pulls and authenticated core replay use the same rotating peer;
  native ABA messages and decision votes keep their original dissemination.
  Repeated recovery within an unchanged epoch uses exponential backoff capped
  at max(4s, the configured base interval); output progress resets the delay.
  SYNC serves retained core messages without triggering an additional
  membership-wide certificate query. Timers only retrieve evidence.
- State updates and signing run on one actor. Expensive crypto callbacks recheck
  the captured epoch/history/selection before changing state. ABA handlers stay
  available after decision for entered-round relay and certificate recovery.

Normal-path scheduling preserves all proposal, delivery, verification and
share-release gates. A received RBC value awaiting PVSS validation suppresses
payload retrieval without counting as a validated value or permitting ECHO.
Genuinely missing values are requested from one holder at a time, with retries
covering the full membership; validation failure resumes retrieval. Crypto
workers prioritize reconstruction, schedule only the share checks needed for a
valid threshold subset, and skip obsolete queued checks. Invalid shares free a
slot for remaining candidates. Identical recovery packets queued for the same
peer are coalesced, while later retries and distinct evidence remain enabled.
An estimated 16 MiB outgoing-queue watermark pauses only production beyond the
current and successor columns. This is producer backpressure, not a hard memory
bound on all retained history or protocol queues.

`protocol.NewVerifier`, `AddColumn`, `Initialize`, `CheckEntry`, `Apply` and
`VerifyHistory` need public keys only. Verification replays genesis, decisions,
RBC delivery, PVSS, selection/RSQ, reconstruction and implicit column advancement. Its
cache avoids repeating PVSS checks for the same immutable object. Use
`-history output.json` to export the public transcript; the command verifies it
after the timed local run.

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests cover 4/8 members, both consumption modes, f silent members, delayed
member recovery, TCP deployment, RBC/ABA certificate forgery, duplicate reconstruction
holders and transcript/history tampering. ALBATROSS sharing uses LDEI with
exactly t response coefficients. Decryption publishes the paper's (d,a,b,z)
DLEQ transcript and recomputes its challenge during verification. The node,
setup fingerprint and public verifier all select ALBATROSS; old SCRAPE histories
have a different setup context and are not accepted by this verifier. See
[PVSS interfaces and encodings](crypto/PVSS.md).

## ALBATROSS migration (2026-10-17)

The running protocol and public history verifier now use ALBATROSS, including
the paper's expanded reconstruction proofs. SCRAPE remains available in the
crypto package for controlled comparisons. The setup fingerprint separates
the two schemes, so old SCRAPE archives require the saved SCRAPE verifier.

Matched n=4/8 experiments cover both consumption modes, fresh Grandline/SPURT
baselines, throughput, output intervals, traffic, message types and actual ABA
instances. Each group repeats three times with 128 warm-up outputs and 128
measured intervals. See the [complete comparison](benchmarks/albatross_e2e_20261017/README.md)
for results, source snapshots, exact configurations and public histories.
The older tables below are historical SCRAPE measurements.

## Local comparison

From the repository root:

```sh
python3 asyrand/benchmarks/local_compare.py --nodes 4 8 --repeats 3 --warmup 128 --intervals 128 --gomaxprocs 8
```

The current benchmark defaults to parallel AsyRand. Pass `--no-parallel` when
reproducing the historical standard-mode tables below. Archived run configs
retain their original consumption mode.

The script builds and runs the current `asyrand`, `grandline` and `spurt`
modules serially, rotates run order, and stores exact configs, logs, source/binary
fingerprints, environment metadata and CSV results. It counts a global beacon
once, rejects skipped/failed runs, and computes throughput from the same
post-warm-up timestamp interval for all three runners. Startup/setup and
post-run public verification are outside that interval. AsyRand's verification
cost during generation remains included.

These are single-host measurements of the repository implementations. They do
not reproduce published paper experiments or WAN latency. The current Grandline
runner establishes APVSS/GRand keys during setup and performs only its share /
verification / recovery path per epoch; its producer interval is unused. The
SPURT runner used by the archived tables had a pairing-based PVSS and BLS
certificate path. The corrected runner uses the output conditions described below.
Benchmark results alone do not establish equal security assumptions or validate
the baseline implementations.

### Measured local results (2026-10-14)

Historical **version 1** measurements, before the shared-column Consumer
synchronization below. These values are retained for reproducibility and are
not measurements of the current version 2 source. Mean ± sample standard
deviation over three runs, in global beacon/s:

| Implementation | 4 nodes, f=1 | 8 nodes, f=2 |
| --- | ---: | ---: |
| AsyRand | 89.21 ± 2.01 | 20.43 ± 3.96 |
| Grandline | 62.61 ± 3.66 | 24.16 ± 3.13 |
| SPURT | 8.46 ± 0.01 | 6.32 ± 0.70 |

Apple M4, Go 1.25.4 darwin/amd64, memory transport, GOMAXPROCS=8,
4 crypto workers/member, W=8, standard consumption mode. Each run discards
128 outputs and measures the next 128 intervals. All 18 runs succeeded without
skips; all 1,542 AsyRand outputs passed public history verification. The short
measurement windows and implementation differences limit statistical and
protocol-level conclusions. SPURT uses a 50ms polling ticker; its existing PVSS
also has a public generator-relation secrecy problem described in the report.

See [report and limitations](benchmarks/local_20261014_results/report.txt),
[per-run measurements](benchmarks/local_20261014_results/results.csv) and
[summary](benchmarks/local_20261014_results/summary.csv). Exact configs, logs,
environment and source/binary fingerprints are retained in the same directory.
Interrupted debugging runs are marked `SUPERSEDED.txt` and excluded.

### Consumer synchronization and verification reuse (version 2)

The shared k replenishes production only when a column is exhausted. The
runtime and its internal verifier share one consumption state and one immutable
verified-column cache. RSQ remains across boundaries; the predecessor hash is
always the previous BEACON or genesis, with no additional CLOSE hash. The
optional parallel mode derives its position from the remaining accepted set.

The reconstruction context and record template are prepared once per epoch.
Callbacks still recheck that context before release or commit. Successful PVSS
checks are reused across RBC and column verification, with the exact transcript
hash bound to its dealer and sequence, including packets received during an
in-flight check. External public verifiers perform their own checks. Public
witnesses contain exactly t shares; ReconTrusted verifies their distinct holders
and proofs once, so a malformed or duplicate share cannot be skipped in favor
of additional inputs. Runtime individual share screening remains in place.

ABA decision certificates are cached after first adoption; native help remains
active independently of that cache. Evidence is copied once on verification
and once when exported to an external caller. Serving history and core replay
continues after local progress.

Historical measurements after Consumer synchronization, before the traffic
and cache optimizations below (three runs):

| Nodes | Global beacon/s, mean ± sample stdev |
| --- | ---: |
| 4 | 145.47 ± 1.90 |
| 8 | 36.35 ± 0.67 |

See [v2 report](benchmarks/consumer_v2_20261014/report.txt) and exact configs/logs
in that directory. The v1 comparison above is historical, not a simultaneous
A/B test; v2 also changes column/producer semantics.

### Traffic and bounded verification caches (version 2)

New ABA instances rely on native DECISION messages to assemble their result.
Certificate requests are issued during recovery, including for instances with
no local proposal, instead of making every node request and receive full
certificates on the normal path. Adoption still retains the native core and
its mandatory next-round help. A future RECON triggers immediate history pull
when column prerequisites are missing; an existing native reconstruction waits
for its share checks and uses periodic recovery if it stalls.

PVSS caches successful decryption-share verification under the full share
encoding and exact transcript ID, after checking the complete transcript
header. Changing any holder, value, proof, object position or setup misses or
fails the cache. This avoids repeating DLEQ checks in ReconTrusted for shares
already screened by the runtime. Generated curve points and local proofs are
retained by construction. Both point and share caches use bounded FIFO
replacement (4096 entries each); an evicted share undergoes full verification.
Retrieved points are cloned, so callers cannot mutate cached values.

An alternating comparison of the saved pre-optimization v2 binary and the
updated binary uses the same configuration and the same post-warmup window
for throughput and aggregate sent bytes. Three runs per variant and size:

| Nodes | Before, beacon/s | After, beacon/s | Before, KiB/beacon | After, KiB/beacon |
| --- | ---: | ---: | ---: | ---: |
| 4 | 146.12 ± 4.71 | 196.57 ± 0.66 | 95.41 ± 3.21 | 58.45 ± 0.45 |
| 8 | 35.83 ± 0.73 | 49.48 ± 0.74 | 471.87 ± 4.36 | 198.16 ± 2.06 |

Mean ± sample standard deviation. Each run excludes 128 outputs and measures
128 following intervals (257 verified outputs total). Communication counts
committee-wide serialized messages including loopback, using sent bytes only;
it includes pipeline production during that window and excludes setup/prefill.
The earlier bandwidth estimates used 256 intervals and are not the baseline
for this comparison. Grandline/SPURT were not rerun here. The command now logs
exact byte counters and message-type breakdowns; their snapshots can differ
slightly because traffic continues while counters are collected.

`go test ./...`, `go test -race ./...` and `go vet ./...` pass. Tests cover
deferred certificate pull without a proposal, stalled native reconstruction
recovery, cache binding/eviction, and the existing healthy/fault/recovery cases.
All twelve benchmark histories verify publicly. Wire formats, signature
statements, PVSS proofs, thresholds and output/history rules remain version 2.

See [comparison report](benchmarks/safe_opt_20261014/report.md),
[summary](benchmarks/safe_opt_20261014/summary.csv), and
[exact optimization patch](benchmarks/safe_opt_20261014/optimization.patch).
Reproduce using built before/after binaries:

```sh
python3 asyrand/benchmarks/safe_opt_compare.py --before /path/to/asyrand-before --after /path/to/asyrand-after
```

Add `--no-parallel` to reproduce the standard-mode optimization comparison.

### Parallel default and ABA accounting

JSON loading now defaults `parallel_consumption` to true and all deployment
templates enable it. An explicit false remains supported. Consumption mode is
bound into public setup, so all peers and the history verifier must use the
same mode.

The runner records two byte windows: `final` excludes `warmup_outputs`, while
`run` counts from the first output through the last. Both retain raw sent and
received bytes, per-message-type counters and ABA communication breakdowns.
ABA core means PRE/VOTE/MAIN/FINAL; certificate traffic means DECISION and
CERT_REQUEST/CERT_RESPONSE; dedicated recovery means SYNC/REPLAY. Combined
ABA share uses these sent bytes divided by all sent bytes in the same type
snapshot, including loopback. Mixed HISTORY/REPLY evidence is counted as
history traffic rather than split into embedded signature categories.

`Node.ABAStatistics()` reports created/proposed/native-decided/certified local
instances. Union instance IDs across nodes to count logical ABA instances;
node copies are reported separately. Each verified whole=1 column requires
one ABA, and whole=0 requires one whole-column plus n object ABAs. Counts for
fully consumed columns inside the measured window exclude boundary and
incomplete future columns, which remain visible in the raw CSV.

```sh
cd asyrand
go build -o /private/tmp/asyrand-parallel ./cmd/asyrand
cd ..
python3 asyrand/benchmarks/parallel_stats.py --binary /private/tmp/asyrand-parallel
```

This script measures only current AsyRand and compares retained Grandline/SPURT
data. For comparison, throughput uses the post-warmup 128 intervals and
communication uses the full 256 intervals for all protocols. Post-warmup
AsyRand traffic and ABA counts are additionally preserved. Each current run
exports and verifies its full public history.

The final parallel measurements and actual ABA counts are in
[parallel report](benchmarks/parallel_20261014/report.md),
[protocol comparison](benchmarks/parallel_20261014/comparison.csv), and
[per-column ABA data](benchmarks/parallel_20261014/aba_columns.csv).
Three-run means: 181.76 / 47.73 beacon/s and 57.69 / 198.20 KiB/beacon
(4/8 nodes; comparison bytes cover 256 intervals). In the post-warmup window,
ABA accounts for 23.71% / 13.30% of sent bytes and each fully consumed column
uses one whole-column ABA. The startup column uses n+1 ABAs.

## Authenticated-channel comparison mode

The memory transport binds each packet to the sending transport identity and
supplies non-serializable authentication provenance. Ordinary RECON/history
packets, ABA core/requests, and non-READY RBC packets omit redundant message
signatures only on this authenticated transport. Other transports retain the
application signatures. RBC READY and ABA DECISION always remain signed;
exported history verification still checks their complete certificates.
Replay inherits authentication only when served by the original sender. A
serialized packet cannot manufacture channel authentication.

The pairing baselines now use BLS12-381 and their original output conditions.
Earlier baseline numbers are historical, not results for the corrected code.
Normal output has no additional beacon voting certificate. Code changes do not
change the paper or its stated security assumptions.

## Verification reuse within a node

Each node owns one `utils/verification.Cache`, shared by RBC reception and
certificate checks, ABA reception and decision certificates, the runtime PVSS
scheme and its history verifier. A successful signature/proof check is retained
for that owner's lifetime; concurrent copies join the same in-flight check.
Signature keys bind public key, complete signed statement and signature bytes.
PVSS keys bind the immutable setup and complete transcript/share/proof, not just
an object identifier. Quorum, membership, context and state-transition checks
still run on every use. Invalid inputs are not retained as successful results.

Caches are not shared between committee members. A new independent public
history verifier starts with an empty cache and performs its own checks. The
success cache grows with retained evidence and is released with its node/verifier;
it is not the bounded point-decoding memo. Signature requirements are unchanged.
