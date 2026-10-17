# PVSS implementations

`NewPVSSScheme` / `NewPVSSVerifier` select the existing SCRAPE-DDH implementation.
`NewALBATROSSPVSSScheme` / `NewALBATROSSPVSSVerifier` select single-secret
[ALBATROSS](https://iacr.org/archive/asiacrypt2020/12491371/12491371.pdf),
Sections 3.2 and 4.1. Both implement `PVSSScheme`. AsyRand's node, public setup
and history verifier now explicitly select ALBATROSS; SCRAPE constructors remain
available for reference tests and controlled comparisons.

```go
keys, err := crypto.GeneratePVSSKeyPair()
// Assemble the fixed map public[member] from each member's public key.
pvss, err := crypto.NewALBATROSSPVSSScheme(id, threshold, keys.Private, public)
commitment, expectedZ, err := pvss.Share(id, seq, members)
// Each shareholder independently verifies commitment and calls PreRecon.
share, err := pvss.PreRecon(commitment, id)
// Collect threshold distinct valid decryption shares before calling Recon.
z, err := pvss.Recon(commitment, shares, threshold)
```

Handle every returned error in application code. `expectedZ` is dealer-local
data, not part of the published sharing transcript. Both schemes protect and
reconstruct a **group element** `h^s`, not a scalar secret `s`.

## ALBATROSS representation

For threshold `t`, the dealer samples `F(X)` of degree less than `t` and publishes
`Cipher[i] = pk_i * F(alpha_i)` in additive group notation. To prove LDEI it
samples an independent polynomial `F'` of degree less than `t`, publishes
`Commit[i] = pk_i * F'(alpha_i)`, hashes the statement and commitments to `c`,
and publishes the `t` coefficients of `F' + cF`. Verification checks
`pk_i * (F' + cF)(alpha_i) = Commit[i] + c * Cipher[i]` for every shareholder.
In SCRAPE, the same `Commit` field instead stores public share commitments;
the version determines its meaning.

Membership is sorted by node ID, with evaluation points `alpha_i = i+1`.
The setup fingerprint binds the generators, subgroup order, threshold, ordered
keys and evaluation points. Fiat–Shamir challenges additionally bind the
protocol version, setup, dealer, sequence, membership and ciphertexts.
The transcript ID also binds the complete proof. The schemes use different
setup and proof domains, so their transcripts cannot be interchanged.

Both implementations use Kyber's Edwards25519 prime-order subgroup and the
same existing shareholder keys. Decoding enforces canonical scalars, canonical
points and prime-subgroup membership. ALBATROSS verification requires exactly
`t` response coefficients; accepting an arbitrary-length polynomial would
invalidate the degree bound. No pairing is used.

Decryption and interpolation share code, with version-specific proof encoding.
ALBATROSS follows the paper's expanded `(d,a,b,z)` transcript: the verifier
recomputes the challenge and checks both equations. Its payload is three group
elements and one scalar (128 bytes). SCRAPE retains compact Fiat–Shamir
`(d,challenge,response)` encoding, with one group element and two scalars
(96 bytes). Counts exclude IDs and serialization overhead. The different
proof formats are rejected across versions.

`PreRecon` and `Recon` verify the sharing proof. Their `Trusted` variants may
only be used after the exact, immutable transcript has been verified.
`VerifyShare` validates the decryption proof; sharing verification remains a
separate obligation. `ReconTrusted` still validates the shares it uses.
Successful exact share proofs and decoded subgroup points are cached in bounded
caches. Aggregation is unsupported for both schemes.

## Comparison

Run from `asyrand/`, selecting the machine's native architecture:

```sh
GOARCH=arm64 go test ./crypto -run '^$' -bench '^BenchmarkPVSSComparison$' \
  -benchmem -benchtime=300ms -count=5 -cpu=1
```

The benchmark uses identical key sets and `t = floor((n-1)/3)+1` for both
schemes. It checks fixture correctness before timing. Setup and key validation,
fixture creation, and explicit cache resets are excluded. API-level hashing,
canonical serialization used internally, randomness and cache updates are
included; network transport and JSON reception/decoding are excluded.

| Phase | Measured work |
| --- | --- |
| Share | Fresh sharing, sharing proof, transcript ID and dealer-local `h^s` |
| VerifyCold | Full sharing verification, including decoding and subgroup checks of all transcript points |
| VerifyWarm | Full sharing verification with decoded points cached; sharing proof equations are always checked |
| PreReconTrusted | One holder's decryption and proof, after sharing verification |
| VerifyShareWarm | One full decryption-proof check with decoded points cached; successful-proof cache reset before every iteration |
| ReconChecked | `ReconTrusted` on `t` shares, with decoded points cached and every decryption proof checked anew |
| ReconCached | `ReconTrusted` on the same `t` already verified shares; includes header checks, exact proof-cache lookups and interpolation |

`transcript_B` is the complete JSON transcript size for sequence 1. `crypto_B`
counts only 32-byte points and scalars: SCRAPE has `2n` points and `n+1` scalars;
ALBATROSS has `2n` points and `t+1` scalars. JSON hex strings, field names, node
IDs and context account for the larger serialized sizes.

The original microbenchmarks in
[`../benchmarks/pvss_albatross_scrape_20261017/`](../benchmarks/pvss_albatross_scrape_20261017/)
used compact decryption proofs for both schemes. They are retained as historical
measurements. The paper-aligned expanded-proof measurements for `n=4,8`, plus
matched end-to-end comparisons and baseline reruns, are in
[`../benchmarks/albatross_e2e_20261017/`](../benchmarks/albatross_e2e_20261017/).
