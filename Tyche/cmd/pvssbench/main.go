package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
)

type sampleResult struct {
	Backend     string
	N           int
	Threshold   int
	Sample      int
	Rounds      int
	Share       time.Duration
	Verify      time.Duration
	PreRecon    time.Duration
	VerifyShare time.Duration
	Recon       time.Duration
	Setup       time.Duration
	SchemeInit  time.Duration
}

type summaryResult struct {
	Backend     string
	N           int
	Threshold   int
	Samples     int
	Rounds      int
	Share       time.Duration
	Verify      time.Duration
	PreRecon    time.Duration
	VerifyShare time.Duration
	Recon       time.Duration
}

func main() {
	var (
		sizeList    = flag.String("sizes", "8,16,32,64,96", "comma-separated node counts")
		backendList = flag.String("backends", "o1,scrape", "comma-separated PVSS backends: o1,scrape")
		samples     = flag.Int("samples", 5, "measurement samples per backend and size")
		rounds      = flag.Int("rounds", 1, "fresh PVSS objects per measurement sample")
		warmups     = flag.Int("warmups", 1, "warmup rounds per backend and size, excluded from output")
		outDir      = flag.String("out", "pvssbench-out", "output directory")
	)
	flag.Parse()

	sizes, err := parseInts(*sizeList)
	if err != nil {
		fatal(err)
	}
	backends := parseStrings(*backendList)
	if len(backends) == 0 {
		fatal(fmt.Errorf("at least one backend is required"))
	}
	if *samples <= 0 || *rounds <= 0 || *warmups < 0 {
		fatal(fmt.Errorf("samples and rounds must be positive; warmups must be non-negative"))
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	var samplesOut []sampleResult
	var summaries []summaryResult
	for _, backend := range backends {
		for _, n := range sizes {
			if n <= 0 {
				fatal(fmt.Errorf("invalid n=%d", n))
			}
			fmt.Printf("pvssbench backend=%s n=%d samples=%d rounds=%d\n", backend, n, *samples, *rounds)
			measured, summary, err := runCase(backend, n, *samples, *rounds, *warmups)
			if err != nil {
				fatal(err)
			}
			samplesOut = append(samplesOut, measured...)
			summaries = append(summaries, summary)
			fmt.Printf("  share=%s verify=%s prerecon=%s recon=%s\n",
				formatDuration(summary.Share), formatDuration(summary.Verify),
				formatDuration(summary.PreRecon), formatDuration(summary.Recon))
		}
	}

	if err := writeSamples(filepath.Join(*outDir, "pvss_phase_samples.csv"), samplesOut); err != nil {
		fatal(err)
	}
	if err := writeSummaryCSV(filepath.Join(*outDir, "pvss_phase_summary.csv"), summaries); err != nil {
		fatal(err)
	}
	if err := writeMarkdown(filepath.Join(*outDir, "pvss_phase_summary.md"), summaries); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s\n", *outDir)
}

func runCase(backend string, n, samples, rounds, warmups int) ([]sampleResult, summaryResult, error) {
	threshold := (n-1)/3 + 1
	members := nodeIDs(n)

	setupStart := time.Now()
	params, keys, err := crypto.SetupPVSS(backend, fmt.Sprintf("pvssbench-%s-n%d", backend, n), threshold, members)
	setupElapsed := time.Since(setupStart)
	if err != nil {
		return nil, summaryResult{}, err
	}

	schemeStart := time.Now()
	schemes := make(map[p2p.NodeID]crypto.PVSSScheme, len(members))
	for _, id := range members {
		scheme, err := crypto.NewPVSSScheme(id, keys[id].Private, params)
		if err != nil {
			return nil, summaryResult{}, err
		}
		schemes[id] = scheme
	}
	schemeElapsed := time.Since(schemeStart)

	seq := uint64(1)
	for i := 0; i < warmups; i++ {
		if _, err := measureRound(schemes, members, seq); err != nil {
			return nil, summaryResult{}, err
		}
		seq++
	}

	out := make([]sampleResult, 0, samples)
	var total sampleResult
	for sample := 1; sample <= samples; sample++ {
		var acc sampleResult
		for round := 0; round < rounds; round++ {
			roundResult, err := measureRound(schemes, members, seq)
			if err != nil {
				return nil, summaryResult{}, err
			}
			seq++
			acc.Share += roundResult.Share
			acc.Verify += roundResult.Verify
			acc.PreRecon += roundResult.PreRecon
			acc.VerifyShare += roundResult.VerifyShare
			acc.Recon += roundResult.Recon
		}
		acc.Backend = backend
		acc.N = n
		acc.Threshold = threshold
		acc.Sample = sample
		acc.Rounds = rounds
		acc.Setup = setupElapsed
		acc.SchemeInit = schemeElapsed
		acc.Share /= time.Duration(rounds)
		acc.Verify /= time.Duration(rounds)
		acc.PreRecon /= time.Duration(rounds)
		acc.VerifyShare /= time.Duration(rounds)
		acc.Recon /= time.Duration(rounds)
		out = append(out, acc)
		total.Share += acc.Share
		total.Verify += acc.Verify
		total.PreRecon += acc.PreRecon
		total.VerifyShare += acc.VerifyShare
		total.Recon += acc.Recon
	}

	divisor := time.Duration(samples)
	summary := summaryResult{
		Backend: backend, N: n, Threshold: threshold, Samples: samples, Rounds: rounds,
		Share:       total.Share / divisor,
		Verify:      total.Verify / divisor,
		PreRecon:    total.PreRecon / divisor,
		VerifyShare: total.VerifyShare / divisor,
		Recon:       total.Recon / divisor,
	}
	return out, summary, nil
}

type roundResult struct {
	Share       time.Duration
	Verify      time.Duration
	PreRecon    time.Duration
	VerifyShare time.Duration
	Recon       time.Duration
}

func measureRound(schemes map[p2p.NodeID]crypto.PVSSScheme, members []p2p.NodeID, seq uint64) (roundResult, error) {
	dealer := members[0]
	verifier := schemes[dealer]
	start := time.Now()
	commitment, _, err := schemes[dealer].Share(dealer, seq, nil)
	shareElapsed := time.Since(start)
	if err != nil {
		return roundResult{}, err
	}

	start = time.Now()
	if !verifier.Verify(commitment) {
		return roundResult{}, fmt.Errorf("valid %s commitment did not verify", commitment.Scheme)
	}
	verifyElapsed := time.Since(start)

	shares := make([]crypto.DecryptedShare, 0, commitment.Threshold)
	var preReconTotal, verifyShareTotal time.Duration
	for _, holder := range members {
		start = time.Now()
		share, err := schemes[holder].PreReconVerified(commitment, holder)
		preReconTotal += time.Since(start)
		if err != nil {
			return roundResult{}, err
		}

		start = time.Now()
		if !verifier.VerifyShare(commitment, share) {
			return roundResult{}, fmt.Errorf("valid %s decrypted share did not verify", commitment.Scheme)
		}
		verifyShareTotal += time.Since(start)

		if len(shares) < commitment.Threshold {
			shares = append(shares, share)
		}
	}

	start = time.Now()
	if _, err := verifier.ReconFromVerifiedShares(commitment, shares); err != nil {
		return roundResult{}, err
	}
	reconElapsed := time.Since(start)

	return roundResult{
		Share:       shareElapsed,
		Verify:      verifyElapsed,
		PreRecon:    preReconTotal / time.Duration(len(members)),
		VerifyShare: verifyShareTotal / time.Duration(len(members)),
		Recon:       reconElapsed,
	}, nil
}

func nodeIDs(n int) []p2p.NodeID {
	out := make([]p2p.NodeID, n)
	for i := range out {
		out[i] = p2p.NodeID(fmt.Sprintf("node%d", i))
	}
	return out
}

func parseInts(raw string) ([]int, error) {
	parts := parseStrings(raw)
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q", part)
		}
		out = append(out, value)
	}
	return out, nil
}

func parseStrings(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func writeSamples(path string, rows []sampleResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	header := []string{
		"backend", "n", "threshold", "sample", "rounds",
		"share_ms", "verify_ms", "prerecon_ms", "verify_share_ms", "recon_ms",
		"setup_ms", "scheme_init_ms",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write([]string{
			row.Backend, strconv.Itoa(row.N), strconv.Itoa(row.Threshold),
			strconv.Itoa(row.Sample), strconv.Itoa(row.Rounds),
			ms(row.Share), ms(row.Verify), ms(row.PreRecon), ms(row.VerifyShare), ms(row.Recon),
			ms(row.Setup), ms(row.SchemeInit),
		}); err != nil {
			return err
		}
	}
	return writer.Error()
}

func writeSummaryCSV(path string, rows []summaryResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{
		"backend", "n", "threshold", "samples", "rounds",
		"share_ms", "verify_ms", "prerecon_ms", "verify_share_ms", "recon_ms",
	}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write([]string{
			row.Backend, strconv.Itoa(row.N), strconv.Itoa(row.Threshold),
			strconv.Itoa(row.Samples), strconv.Itoa(row.Rounds),
			ms(row.Share), ms(row.Verify), ms(row.PreRecon), ms(row.VerifyShare), ms(row.Recon),
		}); err != nil {
			return err
		}
	}
	return writer.Error()
}

func writeMarkdown(path string, rows []summaryResult) error {
	var b strings.Builder
	b.WriteString("| backend | n | threshold | PVSSShare | PVSSVerify | PVSSPreRecon | PVSSRecon |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %s | %s |\n",
			row.Backend, row.N, row.Threshold,
			formatDuration(row.Share), formatDuration(row.Verify),
			formatDuration(row.PreRecon), formatDuration(row.Recon))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.6f", float64(d.Nanoseconds())/1e6)
}

func formatDuration(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d.Nanoseconds())/1e6)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "pvssbench: %v\n", err)
	os.Exit(1)
}
