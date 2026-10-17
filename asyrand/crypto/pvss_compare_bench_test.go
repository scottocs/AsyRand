package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

// BenchmarkPVSSComparison uses identical keys, group and threshold for both
// schemes. Constructors and fixture validation are outside measured regions.
// Warm means decoded subgroup points are cached, never a cached sharing proof.
func BenchmarkPVSSComparison(b *testing.B) {
	for _, n := range []int{4, 8, 16, 32, 64} {
		threshold := (n-1)/3 + 1
		public := make(map[p2p.NodeID]kyber.Point, n)
		keys := make(map[p2p.NodeID]PVSSKeyPair, n)
		members := make([]p2p.NodeID, n)
		for i := range members {
			id := p2p.NodeID(fmt.Sprintf("n%03d", i))
			members[i] = id
			keys[id] = PVSSKeyPairFromSeed([]byte("benchmark-only private seed/" + string(id)))
			public[id] = keys[id].Public
		}
		for _, scheme := range []struct{ name, version string }{{"SCRAPE", pvssVersion}, {"ALBATROSS", albatrossPVSSVersion}} {
			b.Run(fmt.Sprintf("%s/n=%d/t=%d", scheme.name, n, threshold), func(b *testing.B) {
				dealer, err := newPVSSScheme(scheme.version, members[0], threshold, keys[members[0]].Private, public)
				if err != nil {
					b.Fatal(err)
				}
				c, secret, err := dealer.Share(members[0], 1, members)
				if err != nil {
					b.Fatal(err)
				}
				verifier, err := newPVSSVerifier(scheme.version, threshold, public)
				if err != nil || !verifier.Verify(c) {
					b.Fatalf("invalid fixture: %v", err)
				}
				shares := make([]PVSSDecryptedShare, threshold)
				for i := range shares {
					holder, err := newPVSSScheme(scheme.version, members[i], threshold, keys[members[i]].Private, public)
					if err != nil {
						b.Fatal(err)
					}
					shares[i], err = holder.PreRecon(c, members[i])
					if err != nil {
						b.Fatal(err)
					}
				}
				if z, err := verifier.ReconTrusted(c, shares, threshold); err != nil || !bytes.Equal(z, secret) {
					b.Fatalf("fixture reconstruction failed: %v", err)
				}
				encoded, err := json.Marshal(c)
				if err != nil {
					b.Fatal(err)
				}
				responseCount := n
				if scheme.version == albatrossPVSSVersion {
					responseCount = threshold
				}
				b.Run("Share", func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, _, err := dealer.Share(members[0], uint64(i)+2, members); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					b.ReportMetric(float64(len(encoded)), "transcript_B")
					b.ReportMetric(float64(32*(2*n+responseCount+1)), "crypto_B")
				})
				b.Run("VerifyCold", func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						resetPVSSBenchmarkCache(verifier, true)
						b.StartTimer()
						if !verifier.Verify(c) {
							b.Fatal("sharing verification failed")
						}
					}
				})
				b.Run("VerifyWarm", func(b *testing.B) {
					if !verifier.Verify(c) {
						b.Fatal("sharing verification failed")
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if !verifier.Verify(c) {
							b.Fatal("sharing verification failed")
						}
					}
				})
				b.Run("PreReconTrusted", func(b *testing.B) {
					if !dealer.Verify(c) {
						b.Fatal("sharing verification failed")
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := dealer.PreReconTrusted(c, members[0]); err != nil {
							b.Fatal(err)
						}
					}
				})
				b.Run("VerifyShareWarm", func(b *testing.B) {
					if !verifier.VerifyShare(c, shares[0]) {
						b.Fatal("share verification failed")
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						resetPVSSBenchmarkCache(verifier, false)
						b.StartTimer()
						if !verifier.VerifyShare(c, shares[0]) {
							b.Fatal("share verification failed")
						}
					}
				})
				b.Run("ReconChecked", func(b *testing.B) {
					if _, err := verifier.ReconTrusted(c, shares, threshold); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						resetPVSSBenchmarkCache(verifier, false)
						b.StartTimer()
						if _, err := verifier.ReconTrusted(c, shares, threshold); err != nil {
							b.Fatal(err)
						}
					}
				})
				b.Run("ReconCached", func(b *testing.B) {
					if _, err := verifier.ReconTrusted(c, shares, threshold); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := verifier.ReconTrusted(c, shares, threshold); err != nil {
							b.Fatal(err)
						}
					}
				})
			})
		}
	}
}

func resetPVSSBenchmarkCache(s *PVSSPairingFreeScheme, points bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	clear(s.verifiedShares)
	s.shareKeys = s.shareKeys[:0]
	s.shareNext = 0
	if points {
		clear(s.points)
		s.pointKeys = s.pointKeys[:0]
		s.pointNext = 0
	}
}
