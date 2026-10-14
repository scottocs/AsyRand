package aba

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	asig "Tyche/asyrand/crypto"
	"Tyche/utils/p2p"
)

type testCoin struct {
	rng   *rand.Rand
	reads int
}

func (r *testCoin) Read(p []byte) (int, error) {
	r.reads++
	for i := range p {
		p[i] = byte(r.rng.Intn(256))
	}
	return len(p), nil
}

type fixture struct {
	public PublicConfig
	keys   map[p2p.NodeID]ed25519.PrivateKey
	nodes  map[p2p.NodeID]*Instance
	coins  map[p2p.NodeID]*testCoin
}

func newFixture(t *testing.T, n, f int, instance string) *fixture {
	t.Helper()
	x := &fixture{public: PublicConfig{SetupID: strings.Repeat("a", 64), F: f, Public: make(map[string]ed25519.PublicKey)}, keys: make(map[p2p.NodeID]ed25519.PrivateKey), nodes: make(map[p2p.NodeID]*Instance), coins: make(map[p2p.NodeID]*testCoin)}
	for i := 0; i < n; i++ {
		id := p2p.NodeID(fmt.Sprintf("n%02d", i))
		x.public.Members = append(x.public.Members, id)
		private := ed25519.NewKeyFromSeed(asig.HashBytes([]byte("test-only ABA key/" + string(id))))
		x.keys[id] = private
		x.public.Public[string(id)] = private.Public().(ed25519.PublicKey)
	}
	for i, id := range x.public.Members {
		coin := &testCoin{rng: rand.New(rand.NewSource(int64(i + 37)))}
		x.coins[id] = coin
		node, err := New(Config{PublicConfig: x.public, ID: id, Instance: instance, Private: x.keys[id], Coin: coin})
		if err != nil {
			t.Fatal(err)
		}
		x.nodes[id] = node
	}
	return x
}

type delivery struct {
	to  p2p.NodeID
	msg p2p.Message
}

type scheduler struct {
	t               *testing.T
	x               *fixture
	rng             *rand.Rand
	queue           []delivery
	silent          map[p2p.NodeID]bool
	dropDecisionFor map[p2p.NodeID]bool
	counts          map[string]int
	steps           int
}

func newScheduler(t *testing.T, x *fixture, seed int64) *scheduler {
	return &scheduler{t: t, x: x, rng: rand.New(rand.NewSource(seed)), silent: make(map[p2p.NodeID]bool), dropDecisionFor: make(map[p2p.NodeID]bool), counts: make(map[string]int)}
}
func (s *scheduler) enqueue(messages []p2p.Message) {
	s.t.Helper()
	for _, msg := range messages {
		if msg.Type == PRE || msg.Type == VOTE || msg.Type == MAIN || msg.Type == FINAL {
			body, err := p2p.DecodePayload[CoreMessage](msg)
			if err != nil {
				s.t.Fatal(err)
			}
			key := fmt.Sprintf("%s/%d/%s", msg.From, body.Round, msg.Type)
			s.counts[key]++
			limit := 1
			if msg.Type == PRE {
				limit = 2
			}
			if s.counts[key] > limit {
				s.t.Fatalf("core transmitted %s too often", key)
			}
		}
		for _, id := range s.x.public.Members {
			if id == msg.From || (msg.To != "" && msg.To != id) || s.silent[id] {
				continue
			}
			if msg.Type == DECISION && s.dropDecisionFor[id] {
				continue
			}
			copy := msg
			copy.To = id
			copy.Payload = append(json.RawMessage(nil), msg.Payload...)
			s.queue = append(s.queue, delivery{id, copy})
			// Delivery duplication is permitted, unlike honest retransmission of phases.
			if s.rng.Intn(7) == 0 {
				s.queue = append(s.queue, delivery{id, copy})
			}
		}
	}
}
func (s *scheduler) step() bool {
	s.t.Helper()
	if len(s.queue) == 0 {
		return false
	}
	i := s.rng.Intn(len(s.queue))
	d := s.queue[i]
	s.queue[i] = s.queue[len(s.queue)-1]
	s.queue = s.queue[:len(s.queue)-1]
	s.steps++
	if s.steps > 60000 {
		s.t.Fatal("test schedule exhausted; this is not a protocol round deadline")
	}
	if s.silent[d.to] {
		return true
	}
	out, err := s.x.nodes[d.to].Handle(d.msg)
	if err != nil {
		s.t.Fatal(err)
	}
	s.enqueue(out)
	return true
}
func (s *scheduler) drain() {
	s.t.Helper()
	for s.step() {
	}
}
func (s *scheduler) propose(id p2p.NodeID, bit Value) {
	s.t.Helper()
	out, err := s.x.nodes[id].Propose(bit)
	if err != nil {
		s.t.Fatal(err)
	}
	s.enqueue(out)
}
func (s *scheduler) check(active []p2p.NodeID, want *Value) {
	s.t.Helper()
	var bit Value
	for i, id := range active {
		node := s.x.nodes[id]
		result, ok := node.Result()
		if !ok {
			s.t.Fatalf("%s lacks a certified decision: %+v", id, node.Status())
		}
		if i == 0 {
			bit = result.Bit
		} else if result.Bit != bit {
			s.t.Fatal("honest certified decisions disagree")
		}
		if want != nil && result.Bit != *want {
			s.t.Fatal("unanimous honest input validity violated")
		}
		if err := node.Verifier().VerifyCertificate(result.Certificate, node.instance); err != nil {
			s.t.Fatal(err)
		}
		status := node.Status()
		if !status.InternalDecided || !status.Stopped || status.InternalDecision != result.Bit {
			s.t.Fatalf("native decision/help incomplete at %s: %+v", id, status)
		}
		stop := node.rounds[node.stopRound]
		if stop == nil || !stop.finalSent {
			s.t.Fatal("core stopped before next-round FINAL")
		}
	}
}

func TestQuadraticABAAgreementWithAsyncScheduling(t *testing.T) {
	cases := []struct {
		n, f, silent int
		inputs       []Value
	}{
		{1, 0, 0, []Value{Zero}},
		{4, 1, 1, []Value{Zero, Zero, Zero}},
		{4, 1, 1, []Value{One, One, One}},
		{4, 1, 0, []Value{Zero, One, Zero, One}},
		{6, 1, 1, []Value{Zero, One, Zero, One, One}},
		{7, 2, 2, []Value{One, Zero, One, Zero, One}},
		{9, 2, 2, []Value{Zero, One, One, Zero, One, Zero, One}},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("n%d-f%d-silent%d", tc.n, tc.f, tc.silent), func(t *testing.T) {
			x := newFixture(t, tc.n, tc.f, "col/1")
			s := newScheduler(t, x, int64(97+i))
			active := x.public.Members[:tc.n-tc.silent]
			for _, id := range x.public.Members[tc.n-tc.silent:] {
				s.silent[id] = true
			}
			for j, id := range active {
				s.propose(id, tc.inputs[j])
			}
			s.drain()
			var want *Value
			unanimous := tc.inputs[0]
			same := true
			for _, b := range tc.inputs {
				if b != unanimous {
					same = false
				}
			}
			if same {
				want = &unanimous
			}
			s.check(active, want)
		})
	}
}

func TestQuadraticABAStaggeredProposals(t *testing.T) {
	x := newFixture(t, 4, 1, "obj/2/n00")
	s := newScheduler(t, x, 9)
	s.propose("n00", Zero)
	s.propose("n01", One)
	s.drain() // Below core quorum: two honest parties have not yet proposed.
	for _, id := range x.public.Members {
		if _, ok := x.nodes[id].Result(); ok {
			t.Fatal("formed certificate below quorum")
		}
	}
	s.propose("n02", Zero)
	s.propose("n03", One)
	s.drain()
	s.check(x.public.Members, nil)
}

func signCore(t *testing.T, x *fixture, receiver *Instance, from p2p.NodeID, phase string, round uint64, value Value) p2p.Message {
	t.Helper()
	body := CoreMessage{CommitteeID: receiver.verifier.committeeID, Round: round, Value: value, SigHex: hex.EncodeToString(asig.Sign(x.keys[from], receiver.coreStatement(from, phase, round, value)))}
	msg, err := p2p.NewMessage(Protocol, phase, receiver.instance, from, receiver.id, body)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
func handleCore(t *testing.T, x *fixture, a *Instance, from p2p.NodeID, phase string, round uint64, value Value) []p2p.Message {
	t.Helper()
	out, err := a.Handle(signCore(t, x, a, from, phase, round, value))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestQuadraticABAValidationBuffersAndDistinctSenders(t *testing.T) {
	x := newFixture(t, 4, 1, "validation")
	a := x.nodes["n00"]
	if _, err := a.Propose(Zero); err != nil {
		t.Fatal(err)
	}
	// One faulty sender cannot introduce a bit, wildcard or premature phase.
	for i := 0; i < 10; i++ {
		handleCore(t, x, a, "n03", PRE, 0, One)
		handleCore(t, x, a, "n03", VOTE, 0, One)
		handleCore(t, x, a, "n03", MAIN, 0, One)
		handleCore(t, x, a, "n03", MAIN, 0, Wildcard)
		handleCore(t, x, a, "n03", FINAL, 0, One)
		handleCore(t, x, a, "n03", FINAL, 0, Wildcard)
	}
	r := a.rounds[0]
	if len(r.pre[One]) != 1 || r.preSent[One] || r.binary[One] || len(r.vote.accepted) != 0 || len(r.main.accepted) != 0 || len(r.final.accepted) != 0 {
		t.Fatal("unsupported Byzantine messages passed validation")
	}
	// MAIN and FINAL arrive before the supporting VOTE; they must wait.
	handleCore(t, x, a, "n01", MAIN, 0, Zero)
	handleCore(t, x, a, "n01", FINAL, 0, Zero)
	handleCore(t, x, a, "n01", VOTE, 0, One) // Invalid first candidate from this sender.
	handleCore(t, x, a, "n01", VOTE, 0, Zero)
	if len(r.main.accepted) != 0 || len(r.final.accepted) != 0 {
		t.Fatal("accepted unsupported binary phases")
	}
	handleCore(t, x, a, "n01", PRE, 0, Zero)
	handleCore(t, x, a, "n02", PRE, 0, Zero)
	if r.vote.accepted["n01"] != Zero || len(r.vote.accepted) != 2 {
		t.Fatal("unsupported first vote suppressed a later valid vote")
	}
	if r.main.accepted["n01"] != Zero {
		t.Fatal("pending MAIN was not revalidated")
	}
	handleCore(t, x, a, "n02", VOTE, 0, Zero)
	if r.final.accepted["n01"] != Zero {
		t.Fatal("pending FINAL was not revalidated after MAIN support")
	}
	if a.Status().InternalDecided {
		t.Fatal("one FINAL sender caused a decision")
	}
}

func TestQuadraticABAFutureRoundsWaitForEntry(t *testing.T) {
	x := newFixture(t, 4, 1, "future")
	a := x.nodes["n00"]
	for _, from := range []p2p.NodeID{"n01", "n02"} {
		out := handleCore(t, x, a, from, PRE, 5, One)
		if len(out) != 0 {
			t.Fatal("unentered round relayed PRE")
		}
		handleCore(t, x, a, from, VOTE, 5, One)
	}
	if a.rounds[5].entered || len(a.rounds[5].vote.accepted) != 0 {
		t.Fatal("future-round validation ran prematurely")
	}
	if _, err := a.Propose(Zero); err != nil {
		t.Fatal(err)
	}
	if a.rounds[5].entered || a.rounds[5].preSent[One] {
		t.Fatal("proposal activated a future round")
	}
}

func TestQuadraticABAHonestInputSupportAgainstFaultyBit(t *testing.T) {
	x := newFixture(t, 4, 1, "support")
	s := newScheduler(t, x, 13)
	s.silent["n03"] = true
	for _, id := range x.public.Members[:3] {
		s.propose(id, Zero)
		a := x.nodes[id]
		for _, phase := range []string{PRE, VOTE, MAIN, FINAL} {
			out := handleCore(t, x, a, "n03", phase, 0, One)
			s.enqueue(out)
		}
		for _, phase := range []string{MAIN, FINAL} {
			out := handleCore(t, x, a, "n03", phase, 0, Wildcard)
			s.enqueue(out)
		}
	}
	s.drain()
	want := Zero
	s.check(x.public.Members[:3], &want)
	for _, id := range x.public.Members[:3] {
		if x.coins[id].reads != 0 {
			t.Fatal("coin branch reachable with only one honest input bit")
		}
	}
}

func makeCertificate(t *testing.T, x *fixture, a *Instance, bit Value, signers []p2p.NodeID) Certificate {
	t.Helper()
	cert := Certificate{CommitteeID: a.verifier.committeeID, Instance: a.instance, Bit: bit}
	ids := append([]p2p.NodeID(nil), signers...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		cert.Signatures = append(cert.Signatures, Signature{Signer: id, SigHex: hex.EncodeToString(asig.Sign(x.keys[id], a.verifier.decisionStatement(a.instance, bit)))})
	}
	return cert
}

func TestQuadraticABACertificateValidationAndQuorums(t *testing.T) {
	x := newFixture(t, 6, 1, "certificate")
	a := x.nodes["n00"]
	if a.verifier.CoreQuorum() != 4 || a.verifier.CertificateQuorum() != 5 {
		t.Fatal("native and wrapper quorums conflated")
	}
	cert := makeCertificate(t, x, a, One, x.public.Members[:5])
	if err := a.verifier.VerifyCertificate(cert, a.instance); err != nil {
		t.Fatal(err)
	}
	if err := a.verifier.VerifyCertificate(cert, "different"); err == nil {
		t.Fatal("cross-instance replay accepted")
	}
	cases := []struct {
		name   string
		change func(*Certificate)
	}{
		{"core-quorum-only", func(c *Certificate) { c.Signatures = c.Signatures[:4] }},
		{"wrong-bit", func(c *Certificate) { c.Bit = Zero }},
		{"wildcard", func(c *Certificate) { c.Bit = Wildcard }},
		{"wrong-committee", func(c *Certificate) { c.CommitteeID = strings.Repeat("0", 64) }},
		{"duplicate-signer", func(c *Certificate) { c.Signatures[1] = c.Signatures[0] }},
		{"unordered", func(c *Certificate) { c.Signatures[0], c.Signatures[1] = c.Signatures[1], c.Signatures[0] }},
		{"unknown-signer", func(c *Certificate) { c.Signatures[4].Signer = "unknown" }},
		{"bad-signature", func(c *Certificate) { c.Signatures[4].SigHex = strings.Repeat("0", 128) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := cloneCertificate(cert)
			tc.change(&bad)
			if err := a.verifier.VerifyCertificate(bad, a.instance); err == nil {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
	changed := x.public
	changed.F = 0
	v, err := NewVerifier(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyCertificate(cert, a.instance); err == nil {
		t.Fatal("certificate survived a fault threshold change")
	}
	changed = x.public
	changed.SetupID = strings.Repeat("b", 64)
	v, err = NewVerifier(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyCertificate(cert, a.instance); err == nil {
		t.Fatal("certificate survived a PVSS setup change")
	}
}

func TestQuadraticABACertificateRecoveryWithoutProposal(t *testing.T) {
	x := newFixture(t, 4, 1, "recovery")
	s := newScheduler(t, x, 81)
	s.silent["n03"] = true
	for _, id := range x.public.Members[:3] {
		s.propose(id, One)
	}
	s.drain()
	want := One
	s.check(x.public.Members[:3], &want)
	late := x.nodes["n03"]
	if late.Status().Proposed || late.Status().InternalDecided {
		t.Fatal("late receiver participated in core")
	}
	s.silent["n03"] = false
	s.enqueue(late.RequestCertificate())
	s.drain()
	result, ok := late.Result()
	if !ok || result.Bit != One {
		t.Fatal("passive recovery failed")
	}
	if status := late.Status(); status.Proposed || status.InternalDecided || late.decisionSent {
		t.Fatal("certificate adoption manufactured an input, internal decision or signature")
	}
	if _, err := late.Propose(One); !errors.Is(err, ErrAlreadyCertified) {
		t.Fatal("proposal not serialized with prior adoption")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := late.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	// Returned certificate slices must not alias retained evidence.
	result.Certificate.Signatures[0].SigHex = "tampered"
	again, _ := late.Result()
	if err := late.verifier.VerifyCertificate(again.Certificate, late.instance); err != nil {
		t.Fatal("caller mutated retained certificate")
	}
}

func TestQuadraticABAPendingRecoveryRequestIsServed(t *testing.T) {
	x := newFixture(t, 4, 1, "pending-recovery")
	s := newScheduler(t, x, 26)
	late := x.nodes["n03"]
	s.enqueue(late.RequestCertificate())
	s.drain()
	for _, id := range x.public.Members[:3] {
		if !x.nodes[id].waiters["n03"] {
			t.Fatal("pre-certificate request not retained")
		}
	}
	// Keep DECISION votes away from n03: the previously retained request must
	// trigger certificate responses, without a new request or local proposal.
	s.dropDecisionFor["n03"] = true
	for _, id := range x.public.Members[:3] {
		s.propose(id, Zero)
	}
	s.drain()
	if result, ok := late.Result(); !ok || result.Bit != Zero {
		t.Fatal("retained result was not served")
	}
	for _, id := range x.public.Members[:3] {
		if len(x.nodes[id].waiters) != 0 {
			t.Fatal("completed request retained unnecessarily")
		}
	}
}

func TestQuadraticABANativeDecisionIsNotCertifiedEarly(t *testing.T) {
	x := newFixture(t, 6, 1, "native-versus-certificate")
	s := newScheduler(t, x, 93)
	for _, id := range x.public.Members[:4] {
		s.propose(id, Zero)
	}
	s.drain()
	for _, id := range x.public.Members[:4] {
		status := x.nodes[id].Status()
		if !status.InternalDecided || !status.Stopped || status.Certified {
			t.Fatalf("four native decisions must not satisfy five-signature wrapper: %+v", status)
		}
	}
	s.propose("n04", Zero)
	s.drain()
	for _, id := range x.public.Members {
		result, ok := x.nodes[id].Result()
		if !ok || result.Bit != Zero || len(result.Certificate.Signatures) != 5 {
			t.Fatal("fifth signed native decision did not certify the result")
		}
	}
	if x.nodes["n05"].Status().Proposed || x.nodes["n05"].Status().InternalDecided {
		t.Fatal("passive vote collector manufactured core participation")
	}
}

func TestQuadraticABAMemoryTransportIntegration(t *testing.T) {
	x := newFixture(t, 4, 1, "memory-network")
	network := p2p.NewMemoryNetwork()
	transports := make(map[p2p.NodeID]p2p.Transport)
	for _, id := range x.public.Members {
		transports[id] = network.NewTransport(id, 4096)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		for _, transport := range transports {
			_ = transport.Close()
		}
	}()
	errorsCh := make(chan error, 8)
	route := func(from p2p.NodeID, messages []p2p.Message) error {
		for _, msg := range messages {
			var err error
			if msg.To == "" {
				err = transports[from].Broadcast(ctx, msg)
			} else {
				err = transports[from].Send(ctx, msg.To, msg)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	initial := make(map[p2p.NodeID][]p2p.Message)
	for i, id := range x.public.Members {
		messages, err := x.nodes[id].Propose(Value(i % 2))
		if err != nil {
			t.Fatal(err)
		}
		initial[id] = messages
	}
	for _, id := range x.public.Members {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case msg := <-transports[id].Inbox():
					messages, err := x.nodes[id].Handle(msg)
					if err == nil {
						err = route(id, messages)
					}
					if err != nil {
						if ctx.Err() == nil {
							errorsCh <- err
						}
						return
					}
				}
			}
		}()
	}
	for id, messages := range initial {
		if err := route(id, messages); err != nil {
			t.Fatal(err)
		}
	}
	var agreed Value
	for i, id := range x.public.Members {
		result, err := x.nodes[id].Wait(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			agreed = result.Bit
		} else if result.Bit != agreed {
			t.Fatal("network results disagree")
		}
	}
	// Dispatch continues after certified delivery until native help completes.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		allStopped := true
		for _, id := range x.public.Members {
			allStopped = allStopped && x.nodes[id].Status().Stopped
		}
		if allStopped {
			break
		}
		select {
		case err := <-errorsCh:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal("network help did not complete within test budget")
		case <-ticker.C:
		}
	}
}

func TestQuadraticABAAdoptionDoesNotCancelCoreHelp(t *testing.T) {
	x := newFixture(t, 4, 1, "adopt-active")
	s := newScheduler(t, x, 77)
	a := x.nodes["n00"]
	s.propose("n00", Zero)
	cert := makeCertificate(t, x, a, Zero, x.public.Members[:3])
	out, err := a.Adopt(cert)
	if err != nil {
		t.Fatal(err)
	}
	s.enqueue(out)
	if status := a.Status(); status.InternalDecided || status.Stopped {
		t.Fatal("early adoption replaced the native core")
	}
	for _, id := range x.public.Members[1:] {
		s.propose(id, Zero)
	}
	s.drain()
	want := Zero
	s.check(x.public.Members, &want)
	if !a.decisionSent || a.rounds[a.stopRound] == nil || !a.rounds[a.stopRound].finalSent {
		t.Fatal("adoption skipped required signature or help")
	}
}

func TestQuadraticABAOldRoundRelayRemainsActiveAfterStop(t *testing.T) {
	x := newFixture(t, 4, 1, "old-relay")
	s := newScheduler(t, x, 19)
	for _, id := range x.public.Members {
		s.propose(id, Zero)
	}
	s.drain()
	a := x.nodes["n00"]
	if !a.stopped {
		t.Fatal("test core did not stop")
	}
	handleCore(t, x, a, "n01", PRE, 0, One)
	out := handleCore(t, x, a, "n02", PRE, 0, One)
	found := false
	for _, msg := range out {
		body, err := p2p.DecodePayload[CoreMessage](msg)
		if err == nil && msg.Type == PRE && body.Round == 0 && body.Value == One {
			found = true
		}
	}
	if !found || !a.rounds[0].binary[One] {
		t.Fatal("entered-round PRE handlers were cancelled after stop")
	}
}

type retryCoin struct {
	fail  bool
	next  byte
	reads int
}

func (r *retryCoin) Read(p []byte) (int, error) {
	r.reads++
	if r.fail {
		return 0, io.ErrUnexpectedEOF
	}
	for i := range p {
		p[i] = r.next
	}
	r.next ^= 1
	return len(p), nil
}

func wildcardRound(t *testing.T, x *fixture, a *Instance, round uint64) error {
	t.Helper()
	for _, value := range []Value{Zero, One} {
		for _, from := range []p2p.NodeID{"n01", "n02"} {
			handleCore(t, x, a, from, PRE, round, value)
		}
	}
	own := a.rounds[round].vote.accepted[a.id]
	opposite := One
	if own == One {
		opposite = Zero
	}
	for _, from := range []p2p.NodeID{"n01", "n02"} {
		handleCore(t, x, a, from, VOTE, round, opposite)
	}
	for _, from := range []p2p.NodeID{"n01", "n02"} {
		handleCore(t, x, a, from, MAIN, round, Wildcard)
	}
	handleCore(t, x, a, "n01", FINAL, round, Wildcard)
	_, err := a.Handle(signCore(t, x, a, "n02", FINAL, round, Wildcard))
	return err
}

func TestQuadraticABAFreshLocalCoinsAndReadFailure(t *testing.T) {
	x := newFixture(t, 4, 1, "coins")
	a := x.nodes["n00"]
	coin := &retryCoin{fail: true}
	a.coin = coin
	if _, err := a.Propose(Zero); err != nil {
		t.Fatal(err)
	}
	if err := wildcardRound(t, x, a, 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("missing coin read error: %v", err)
	}
	if a.round != 0 || a.internal != nil {
		t.Fatal("entropy failure advanced the round or decided")
	}
	coin.fail = false
	out, err := a.Progress()
	if err != nil {
		t.Fatal(err)
	}
	if a.round != 1 || a.estimate != Zero || len(out) == 0 {
		t.Fatal("coin retry did not resume the core")
	}
	if err := wildcardRound(t, x, a, 1); err != nil {
		t.Fatal(err)
	}
	if a.round != 2 || a.estimate != One || coin.reads != 3 {
		t.Fatal("local coin was reused across invocations")
	}
}

func TestQuadraticABARejectsSpoofingAndContextReplay(t *testing.T) {
	x := newFixture(t, 4, 1, "auth")
	a := x.nodes["n00"]
	valid := signCore(t, x, a, "n01", PRE, 0, One)
	cases := []p2p.Message{}
	bad := valid
	bad.From = "n02"
	cases = append(cases, bad)
	bad = valid
	bad.Instance = "other"
	cases = append(cases, bad)
	bad = valid
	bad.Protocol = "rbc"
	cases = append(cases, bad)
	bad = valid
	bad.Type = VOTE
	cases = append(cases, bad)
	bad = valid
	bad.To = "n03"
	cases = append(cases, bad)
	bad = valid
	body, _ := p2p.DecodePayload[CoreMessage](bad)
	body.Round++
	bad.Payload = encode(body)
	cases = append(cases, bad)
	bad = valid
	body, _ = p2p.DecodePayload[CoreMessage](bad)
	body.Value = Zero
	bad.Payload = encode(body)
	cases = append(cases, bad)
	bad = valid
	bad.Payload = json.RawMessage("{")
	cases = append(cases, bad)
	for _, msg := range cases {
		if _, err := a.Handle(msg); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("invalid message accepted: %v", err)
		}
	}
	if len(a.rounds) != 0 {
		t.Fatal("unauthenticated messages allocated protocol state")
	}
	if _, err := a.Propose(Wildcard); err == nil {
		t.Fatal("wildcard input accepted")
	}
	if _, err := a.Propose(One); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Propose(Zero); !errors.Is(err, ErrAlreadyProposed) {
		t.Fatal("second input accepted")
	}
}

func TestQuadraticABAConcurrentProposalAndAdoption(t *testing.T) {
	x := newFixture(t, 4, 1, "serialize")
	a := x.nodes["n00"]
	cert := makeCertificate(t, x, a, Zero, x.public.Members[:3])
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := a.Propose(Zero)
		if err != nil && !errors.Is(err, ErrAlreadyCertified) {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := a.Adopt(cert)
		if err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	if _, ok := a.Result(); !ok {
		t.Fatal("certificate not installed")
	}
	if a.internal != nil || a.decisionSent {
		t.Fatal("adoption manufactured a native decision")
	}
}

func TestQuadraticABAInvalidConfiguration(t *testing.T) {
	x := newFixture(t, 4, 1, "config")
	configs := []PublicConfig{x.public, x.public, x.public, x.public, x.public}
	configs[0].F = -1
	configs[1].F = 2
	configs[2].SetupID = ""
	configs[3].Members = []p2p.NodeID{"n00", "n00", "n02", "n03"}
	configs[4].SetupID = strings.ToUpper(x.public.SetupID)
	for _, cfg := range configs {
		if _, err := NewVerifier(cfg); err == nil {
			t.Fatal("invalid public configuration accepted")
		}
	}
	if _, err := New(Config{PublicConfig: x.public, ID: "n00", Instance: "", Private: x.keys["n00"]}); err == nil {
		t.Fatal("empty instance accepted")
	}
	if _, err := New(Config{PublicConfig: x.public, ID: "n00", Instance: "other", Private: x.keys["n01"]}); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	// Caller-owned setup data cannot mutate a live verifier.
	original := x.nodes["n00"].verifier.committeeID
	x.public.Public["n00"][0] ^= 1
	x.public.Members[0] = "changed"
	if x.nodes["n00"].verifier.committeeID != original || bytes.Equal(x.nodes["n00"].verifier.public["n00"], x.public.Public["n00"]) {
		t.Fatal("public setup was not copied")
	}
}
