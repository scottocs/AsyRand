package crypto

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/scottocs/Tyche/utils/p2p"
)

func TestPVSSShareVerifyCostScales(t *testing.T) {
	if os.Getenv("TYCHE_PVSS_COST") != "1" {
		t.Skip("set TYCHE_PVSS_COST=1 to run PVSS cost measurements")
	}
	sizes := []int{4, 8, 16, 32, 64, 128}
	backends := []string{PVSSO1, PVSSScrape}
	t.Log("pvss_cost backend n threshold share_avg verify_avg rounds")
	for _, backend := range backends {
		for _, n := range sizes {
			f := (n - 1) / 3
			threshold := f + 1
			members := make([]p2p.NodeID, n)
			for i := range members {
				members[i] = p2p.NodeID(fmt.Sprintf("node%d", i))
			}
			params, keys, err := SetupPVSS(backend, fmt.Sprintf("pvss-cost-%s-n%d", backend, n), threshold, members)
			if err != nil {
				t.Fatal(err)
			}
			scheme, err := NewPVSSScheme(members[0], keys[members[0]].Private, params)
			if err != nil {
				t.Fatal(err)
			}
			rounds := pvssCostRounds(n)
			var shareTotal, verifyTotal time.Duration
			for i := 0; i < rounds; i++ {
				start := time.Now()
				commitment, _, err := scheme.Share(members[0], uint64(i+1), nil)
				shareTotal += time.Since(start)
				if err != nil {
					t.Fatal(err)
				}
				start = time.Now()
				if !scheme.Verify(commitment) {
					t.Fatalf("valid %s PVSS commitment did not verify at n=%d", backend, n)
				}
				verifyTotal += time.Since(start)
			}
			t.Logf("pvss_cost backend=%s n=%d threshold=%d share_avg=%s verify_avg=%s rounds=%d",
				backend, n, threshold, shareTotal/time.Duration(rounds), verifyTotal/time.Duration(rounds), rounds)
		}
	}
}

func pvssCostRounds(n int) int {
	switch {
	case n <= 16:
		return 20
	case n <= 64:
		return 10
	default:
		return 5
	}
}
