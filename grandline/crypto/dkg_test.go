package crypto

import (
	"testing"

	"Tyche/utils/p2p"
)

func TestPedersenDKGFeedsThresholdCoin(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	seeds := make(map[p2p.NodeID][]byte)
	for _, id := range ids {
		seeds[id] = HashBytes([]byte(id))
	}
	result, err := RunPedersenDKG(ids, seeds, 2)
	if err != nil {
		t.Fatal(err)
	}
	shares := make([]CoinShare, 0, len(ids))
	for _, id := range ids {
		coin := NewThresholdCoin(string(id), result.Shares[id], result.Public, 2, len(ids))
		shares = append(shares, coin.Share("instance", 0))
	}
	coin := NewThresholdCoin("n0", result.Shares["n0"], result.Public, 2, len(ids))
	if _, err := coin.Combine("instance", 0, shares[:2]); err != nil {
		t.Fatalf("threshold coin did not combine with two DKG shares: %v", err)
	}
	if _, err := coin.Combine("other-instance", 0, shares[:2]); err == nil {
		t.Fatal("threshold coin accepted shares for a different message")
	}
}
