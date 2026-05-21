package tyche

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/Tyche/protocol/aba"
	"github.com/scottocs/Tyche/Tyche/protocol/rbc"
	"github.com/scottocs/Tyche/utils/p2p"
)

func TestPVSSOperationProfile(t *testing.T) {
	if os.Getenv("TYCHE_PROFILE") != "1" {
		t.Skip("set TYCHE_PROFILE=1 to profile PVSS operations")
	}
	ids := profileIDs(8)
	pp, keys, err := crypto.Setup("profile-pvss", 3, ids)
	if err != nil {
		t.Fatal(err)
	}
	schemes := make(map[p2p.NodeID]*crypto.SilentSetupScheme, len(ids))
	for _, id := range ids {
		s, err := crypto.NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		schemes[id] = s
	}

	const rounds = 100
	var shareDur, verifyDur, preReconDur, verifyShareDur, reconDur time.Duration
	for r := 0; r < rounds; r++ {
		seq := uint64(r + 1)
		start := time.Now()
		c, _, err := schemes[ids[0]].Share(ids[0], seq, nil)
		shareDur += time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			start = time.Now()
			if !schemes[id].Verify(c) {
				t.Fatal("PVSS verify failed")
			}
			verifyDur += time.Since(start)
		}
		shares := make([]crypto.DecryptedShare, 0, c.Threshold)
		for _, id := range ids {
			start = time.Now()
			sh, err := schemes[id].PreRecon(c, id)
			preReconDur += time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			start = time.Now()
			if !schemes[ids[0]].VerifyShare(c, sh) {
				t.Fatal("PVSS share verify failed")
			}
			verifyShareDur += time.Since(start)
			if len(shares) < c.Threshold {
				shares = append(shares, sh)
			}
		}
		start = time.Now()
		if _, err := schemes[ids[0]].Recon(c, shares); err != nil {
			t.Fatal(err)
		}
		reconDur += time.Since(start)
	}
	t.Logf("pvss profile: rounds=%d share_avg=%s verify_avg=%s pre_recon_avg=%s verify_share_avg=%s recon_avg=%s",
		rounds, shareDur/rounds, verifyDur/time.Duration(rounds*len(ids)), preReconDur/time.Duration(rounds*len(ids)),
		verifyShareDur/time.Duration(rounds*len(ids)), reconDur/rounds)
}

func TestRBCProfile(t *testing.T) {
	if os.Getenv("TYCHE_PROFILE") != "1" {
		t.Skip("set TYCHE_PROFILE=1 to profile RBC")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ids := profileIDs(8)
	net := p2p.NewMemoryNetwork()
	nodes := make([]*rbc.Broadcaster, 0, len(ids))
	transports := make([]p2p.Transport, 0, len(ids))
	for _, id := range ids {
		transport := net.NewTransport(id, 8192)
		b := rbc.New(id, len(ids), 2, transport)
		nodes = append(nodes, b)
		transports = append(transports, transport)
		go func(b *rbc.Broadcaster, transport p2p.Transport) {
			for {
				select {
				case msg := <-transport.Inbox():
					_ = b.Handle(ctx, msg)
				case <-ctx.Done():
					return
				}
			}
		}(b, transport)
	}

	const rounds = 100
	payload := make([]byte, 4096)
	before := aggregateMetrics(transports)
	start := time.Now()
	for r := 0; r < rounds; r++ {
		if err := nodes[r%len(nodes)].Broadcast(ctx, uint64(r+1), payload); err != nil {
			t.Fatal(err)
		}
		for _, b := range nodes {
			select {
			case <-b.Deliveries:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	elapsed := time.Since(start)
	after := aggregateMetrics(transports)
	t.Logf("rbc profile: nodes=%d rounds=%d elapsed=%s throughput=%.2f deliveries/s sent_messages=%d sent_bytes=%d bandwidth=%.2f MiB/s",
		len(ids), rounds, elapsed, float64(rounds)/elapsed.Seconds(),
		after.SentMessages-before.SentMessages, after.SentBytes-before.SentBytes,
		float64(after.SentBytes-before.SentBytes)/(1024*1024)/elapsed.Seconds())
}

func TestABAProfile(t *testing.T) {
	if os.Getenv("TYCHE_PROFILE") != "1" {
		t.Skip("set TYCHE_PROFILE=1 to profile ABA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ids := profileIDs(8)
	net := p2p.NewMemoryNetwork()
	nodes := make([]*aba.Agreement, 0, len(ids))
	transports := make([]p2p.Transport, 0, len(ids))
	for _, id := range ids {
		transport := net.NewTransport(id, 8192)
		a := aba.New(id, len(ids), 2, transport)
		nodes = append(nodes, a)
		transports = append(transports, transport)
		go func(a *aba.Agreement, transport p2p.Transport) {
			for {
				select {
				case msg := <-transport.Inbox():
					_ = a.Handle(ctx, msg)
				case <-ctx.Done():
					return
				}
			}
		}(a, transport)
	}

	const rounds = 100
	before := aggregateMetrics(transports)
	start := time.Now()
	for r := 0; r < rounds; r++ {
		instance := fmt.Sprintf("profile-aba/%d", r)
		for _, a := range nodes {
			if err := a.Propose(ctx, instance, true); err != nil {
				t.Fatal(err)
			}
		}
		for _, a := range nodes {
			select {
			case dec := <-a.Decisions:
				if !dec.Value {
					t.Fatal("unexpected false ABA decision")
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	elapsed := time.Since(start)
	after := aggregateMetrics(transports)
	t.Logf("aba profile: nodes=%d rounds=%d elapsed=%s throughput=%.2f decisions/s sent_messages=%d sent_bytes=%d bandwidth=%.2f MiB/s",
		len(ids), rounds, elapsed, float64(rounds)/elapsed.Seconds(),
		after.SentMessages-before.SentMessages, after.SentBytes-before.SentBytes,
		float64(after.SentBytes-before.SentBytes)/(1024*1024)/elapsed.Seconds())
}

func profileIDs(n int) []p2p.NodeID {
	ids := make([]p2p.NodeID, n)
	for i := range ids {
		ids[i] = p2p.NodeID(fmt.Sprintf("n%d", i))
	}
	return ids
}
