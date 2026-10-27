package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"go.dedis.ch/kyber/v3"
)

// BenchmarkPVSSComparison uses identical keys, group and threshold for both
// schemes. Constructors and fixture validation are outside measured regions.
// Warm means decoded subgroup points are cached, never a cached sharing proof.
func BenchmarkSubgroupCheck(b *testing.B) {
	point := suite().Point().Mul(suite().Scalar().SetBytes([]byte("public benchmark point")), pvssGeneratorG)
	for _, method := range []string{"integer-binary", "order-minus-one", "native-order-minus-one"} {
		b.Run(method, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var result kyber.Point
				if method == "integer-binary" {
					result = referenceIntegerOrder(point)
				} else if method == "native-order-minus-one" {
					result = publicPointMul(pvssOrderMinusOne, point)
					result.Add(result, point)
				} else {
					result = suite().Point()
					if variable, ok := result.(kyber.AllowsVarTime); ok {
						variable.AllowVarTime(true)
					}
					result.Mul(pvssOrderMinusOne, point)
					result.Add(result, point)
				}
				if !result.Equal(suite().Point().Null()) {
					b.Fatal("subgroup check failed")
				}
			}
		})
	}
}

func BenchmarkPublicProofEquation(b *testing.B) {
	g := suite()
	r := g.XOF([]byte("public-proof-equation benchmark"))
	a, c := g.Scalar().Pick(r), g.Scalar().Pick(r)
	A, B := g.Point().Mul(g.Scalar().Pick(r), nil), g.Point().Mul(g.Scalar().Pick(r), nil)
	for _, method := range []string{"kyber-separate", "native-separate", "native-joint"} {
		b.Run(method, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				switch method {
				case "kyber-separate":
					x, y := g.Point(), g.Point()
					x.(kyber.AllowsVarTime).AllowVarTime(true)
					y.(kyber.AllowsVarTime).AllowVarTime(true)
					operationBenchmarkPoint = g.Point().Add(x.Mul(a, A), y.Mul(c, B))
				case "native-separate":
					operationBenchmarkPoint = g.Point().Add(publicPointMul(a, A), publicPointMul(c, B))
				case "native-joint":
					operationBenchmarkPoint = publicPointDoubleMul(a, A, c, B)
				}
			}
		})
	}
}

// A verified object retains its ciphertext points; every timed iteration uses
// fresh foreign point decoding and proof checks, then reuses those checked
// shares for interpolation. Fixture/cache resets are outside the timed region.
func BenchmarkPreparedConsumption(b *testing.B) {
	for _, n := range []int{31, 61} {
		t := (n-1)/3 + 1
		ids := make([]p2p.NodeID, n)
		keys := make([]PVSSKeyPair, n)
		pub := map[p2p.NodeID]kyber.Point{}
		for i := range ids {
			ids[i] = p2p.NodeID(fmt.Sprintf("node%03d", i))
			keys[i] = PVSSKeyPairFromSeed([]byte(string(ids[i])))
			pub[ids[i]] = keys[i].Public
		}
		holders := make([]*PVSSPairingFreeScheme, t)
		for i := range holders {
			var err error
			holders[i], err = NewALBATROSSPVSSScheme(ids[i], t, keys[i].Private, pub)
			if err != nil {
				b.Fatal(err)
			}
		}
		object, _, err := holders[0].Share(ids[0], 1, ids)
		if err != nil {
			b.Fatal(err)
		}
		parts := make([]PVSSDecryptedShare, t)
		for i, s := range holders {
			parts[i], err = s.PreReconTrusted(object, ids[i])
			if err != nil {
				b.Fatal(err)
			}
		}
		s := holders[0]
		prepared, valid := s.Prepare(object)
		if !valid {
			b.Fatal("invalid fixture")
		}
		b.Run(fmt.Sprintf("n%d/FreshForeignPoints", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				resetPVSSBenchmarkCache(s, true)
				prepared.mu.Lock()
				clear(prepared.shares)
				prepared.shareKeys = nil
				prepared.shareNext = 0
				prepared.mu.Unlock()
				b.StartTimer()
				own, err := s.PreReconPrepared(prepared, ids[0])
				if err != nil {
					b.Fatal(err)
				}
				shares := append([]PVSSDecryptedShare{own}, parts[1:]...)
				for _, sh := range shares[1:] {
					if !s.VerifyPreparedShare(prepared, sh) {
						b.Fatal("invalid share")
					}
				}
				if _, err = s.ReconPrepared(prepared, shares, t); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

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
					before := verifier.headerChecks.Load()
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
					b.StopTimer()
					if verifier.headerChecks.Load()-before != uint64(b.N) {
						b.Fatal("cold verification benchmark reused a successful proof")
					}
				})
				b.Run("VerifyWarm", func(b *testing.B) {
					if !verifier.Verify(c) {
						b.Fatal("sharing verification failed")
					}
					before := verifier.headerChecks.Load()
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						resetPVSSBenchmarkCache(verifier, false)
						b.StartTimer()
						if !verifier.Verify(c) {
							b.Fatal("sharing verification failed")
						}
					}
					b.StopTimer()
					if verifier.headerChecks.Load()-before != uint64(b.N) {
						b.Fatal("warm-decoding benchmark reused a successful proof")
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
	// A cold proof must clear the successful boolean verification cache too.
	// Keeping it made VerifyCold/VerifyWarm measure JSON keys and cache hits.
	s.checks = verification.New()
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
