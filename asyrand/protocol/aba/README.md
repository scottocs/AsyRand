# Quadratic-ABA

This package implements the local-coin core in the WaterBear appendix of
`paper/Asyrand.tex` and AsyRand's signed decision-certificate wrapper. It does
not invoke RBC, threshold signatures, DKG, or beacon-derived randomness.

Each `Instance` owns one unique identifier and is safe for concurrent calls.
Whole-column and per-object agreements should use distinct identifiers, such
as `col/2` and `obj/2/node0`. Never reuse an identifier for a new agreement.

## Setup and interface

```go
instance, err := aba.New(aba.Config{
    PublicConfig: aba.PublicConfig{
        SetupID: pvssSetupID, // Canonical public PVSS setup/key fingerprint.
        Members: members,
        F:       faults,
        Public:  signingPublicKeys,
    },
    ID:       localID,
    Instance: "col/2",
    Private:  signingPrivateKey,
})
```

The constructor validates `n > 3f`, distinct member identities, the exact
signing-key set, and the local key pair. The committee fingerprint binds these
parameters and the supplied PVSS setup fingerprint. External verifiers use
`NewVerifier` and `VerifyCertificate` without a private key.

The application keeps a dispatcher and an outbound queue:

```go
// Register the instance before proposing, so early messages can be buffered.
enqueue(instance.RequestCertificate()) // Independent of proposal submission.

messages, err := instance.Propose(aba.One) // At most one guarded input.
enqueue(messages)
// Handle err; an existing certificate may make proposing unnecessary.

// In the existing dispatcher, route by message.Protocol and message.Instance:
messages, err = instance.Handle(message)
enqueue(messages)
// Reject malformed/unauthenticated messages; handle other errors explicitly.

// Wait in a separate task while the dispatcher continues running.
decision, err := instance.Wait(ctx)
```

Every returned message must eventually be transmitted. `To == ""` denotes
broadcast to the configured membership; a nonempty `To` denotes unicast.
Local core messages and decision votes are already counted, so transport
loopback is optional. Schedule sends so an unavailable recipient does not
block other recipients or the protocol dispatcher. These methods deliberately
do not consume a transport inbox, allowing many instances and other protocols
to share the application's existing dispatcher.

`Wait` observes a certified decision. It does not initiate network traffic;
route `RequestCertificate` before waiting, including when no input is ready.
Requests received before certification are retained and answered once a
certificate becomes available. Certificates are retained locally and served
on demand; complete certificates are not automatically rebroadcast.

## Core and certificate behavior

- PRE relays after `f+1` distinct senders and accepts a bit after `2f+1`.
- VOTE, MAIN and FINAL batches use `ceil((n+f+1)/2)` distinct senders.
- Pending messages wait for the paper's local validation predicates. Future
  rounds wait for entry. Equivocation never counts one sender twice per batch.
- The coin branch uses a fresh `crypto/rand` byte per invocation. A custom
  `Coin` reader is for deterministic tests or an independent secure local
  entropy source. Entropy failure returns an error without advancing the
  round; `Progress` retries enabled work after recovery.
- A native internal decision signs once and executes one additional round
  through FINAL transmission. Certificate adoption does not replace that
  decision or cancel the additional round. **Keep dispatching after `Wait`
  returns**, including after the core stops, to serve evidence and maintain
  entered-round PRE relay/validation handlers.
- Decision certificates require `n-f` distinct valid Ed25519 signatures. Their
  statement binds the committee, instance and bit, and excludes the core round.

Each party emits at most two PREs and one message of each later core phase per
round, giving quadratic message count after broadcast fanout. Local-coin
worst-case expected rounds remain exponential. Signature votes and certificate
retrieval are separate from the per-round core; on-demand full-certificate
traffic is charged as recovery traffic under the paper's accounting.

The AsyRand consumer in `protocol/node.go` wires these instances to its
whole-column and per-object input guards. Its runtime bounds far-future round
admission and pulls deferred core packets from authenticated sender archives.
The standalone component retains future rounds unless its caller applies that
admission policy. Stopped cores continue serving entered rounds and certificates
but do not request new future rounds.
