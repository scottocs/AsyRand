package asyrand

import (
	"Tyche/utils/p2p"
	"errors"
	"math/big"
)

// consumptionState is touched only by the node actor or a sequential verifier.
type consumptionState struct {
	Epoch, Column                uint64
	PreviousHash, PreviousRandom string
	Remaining, RSQ               []p2p.NodeID
}

func genesis(s PublicSetup, c Column) consumptionState {
	r := digest("init", struct{ Context, Column string }{s.Context, c.Hash()})
	previousHash := digest("history", struct{ Type, Column, Random string }{"GENESIS", c.Hash(), r})
	return consumptionState{Epoch: 1, Column: 1, PreviousHash: previousHash, PreviousRandom: r, Remaining: sources(c)}
}
func sources(c Column) []p2p.NodeID {
	x := make([]p2p.NodeID, len(c.Record.Accepted))
	for i, a := range c.Record.Accepted {
		x[i] = a.Source
	}
	return x
}
func (s consumptionState) selected() (p2p.NodeID, error) {
	var eligible []p2p.NodeID
	for _, id := range s.Remaining {
		blocked := false
		for _, old := range s.RSQ {
			if id == old {
				blocked = true
				break
			}
		}
		if !blocked {
			eligible = append(eligible, id)
		}
	}
	if len(eligible) == 0 {
		return "", errors.New("empty eligible set")
	}
	h := digest("select", struct {
		Epoch    uint64
		Previous string
	}{s.Epoch, s.PreviousRandom})
	n, _ := new(big.Int).SetString(h, 16)
	n.Mod(n, big.NewInt(int64(len(eligible))))
	return eligible[n.Int64()], nil
}
func (s consumptionState) needsNext(setup PublicSetup, columns map[uint64]Column) bool {
	return !setup.Parallel || len(columns[s.Column].Record.Accepted)-len(s.Remaining) >= setup.F
}
func (s *consumptionState) install(setup PublicSetup, r BeaconRecord, columns map[uint64]Column) error {
	index := -1
	for i, id := range s.Remaining {
		if id == r.Source {
			index = i
			break
		}
	}
	if index < 0 || r.Epoch != s.Epoch || r.Column != s.Column || r.PreviousHash != s.PreviousHash {
		return errors.New("beacon does not extend the current consumption state")
	}
	var successor []p2p.NodeID
	if len(s.Remaining) == 1 {
		next, ok := columns[s.Column+1]
		if !ok {
			return errors.New("column advancement requires the verified successor")
		}
		successor = sources(next)
	}
	// Check every fallible condition before the single atomic transition. The
	// predecessor is always the last BEACON; advancement adds no history record.
	s.PreviousHash = r.Hash()
	s.PreviousRandom = r.Random
	s.Epoch++
	s.Remaining = append(s.Remaining[:index], s.Remaining[index+1:]...)
	if len(s.RSQ) == setup.F+1 {
		s.RSQ = s.RSQ[1:]
	}
	s.RSQ = append(s.RSQ, r.Source)
	if len(s.Remaining) == 0 {
		s.Column++
		s.Remaining = successor
	}
	return nil
}
