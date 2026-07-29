package tyche

import (
	"bytes"
	"context"
	"testing"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

func TestLegacyPVSSRecoveryCompletesBeforeKeyErasure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodes := newTestNodes(t, ctx)
	dealer := nodes[1]
	commitment, secret, err := dealer.PVSS.Share(dealer.ID, 77, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := nodes[0]
	object := Object{ConfigVersion: 0, Producer: dealer.ID, Seq: 77, Commitment: commitment}
	key := retirementKey(0, commitment.SecretID)
	target.mu.Lock()
	target.PVSSContexts[0].Status = PVSSRetiring
	target.Retirement[key] = &RetirementObligation{
		Reference: RetirementReference{ConfigVersion: 0, TargetEpoch: 1, ObjectID: commitment.SecretID, Object: object},
		Shares:    make(map[p2p.NodeID]crypto.DecryptedShare),
	}
	target.mu.Unlock()

	for _, holder := range nodes[:commitment.Threshold] {
		share, err := holder.PVSS.PreReconVerified(commitment, holder.ID)
		if err != nil {
			t.Fatal(err)
		}
		body := RetirementShareMessage{ConfigVersion: 0, ObjectID: commitment.SecretID, Share: share}
		body.Signature, err = crypto.SignTranscript(string(holder.ID), holder.IdentityPrivate, retirementShareTranscript(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := target.HandleRetirementShare(body, holder.ID); err != nil {
			t.Fatal(err)
		}
	}

	target.mu.Lock()
	obligation := target.Retirement[key]
	if obligation == nil || !obligation.Complete || !bytes.Equal(obligation.Secret, secret) {
		target.mu.Unlock()
		t.Fatalf("legacy secret was not recovered: %+v", obligation)
	}
	if target.PVSSContexts[0].Scheme == nil {
		target.mu.Unlock()
		t.Fatal("legacy PVSS key erased before recovered entropy was consumed")
	}
	mixed := target.mixRetirementEntropyLocked([]byte("previous"), []byte("current"), 1)
	target.consumeRetirementEntropyLocked(1)
	status := target.PVSSContexts[0].Status
	scheme := target.PVSSContexts[0].Scheme
	target.mu.Unlock()
	if bytes.Equal(mixed, crypto.DomainHash("Tyche/BeaconEntropy/v2", []byte("previous"), []byte("current"))) {
		t.Fatal("recovered legacy secret did not contribute to entropy")
	}
	if status != PVSSErased || scheme != nil {
		t.Fatalf("legacy key not erased after consumption: status=%s scheme=%v", status, scheme)
	}
}
