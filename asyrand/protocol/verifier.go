package asyrand

import (
	"Tyche/asyrand/crypto"
	"Tyche/asyrand/protocol/aba"
	"Tyche/asyrand/protocol/rbc"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"errors"
	"fmt"
)

// Verifier checks public transcripts without any shareholder private key.
// It is sequential; callers serialize AddColumn and Apply.
type Verifier struct {
	checks  *verification.Cache
	setup   PublicSetup
	pvss    *crypto.PVSSPairingFreeScheme
	aba     *aba.Verifier
	columns map[uint64]Column
	objects map[string]verifiedPVSS
	state   *consumptionState
}

// A cache hit binds the exact canonical transcript hash to its dealer/position.
// The node actor may reuse a successful check under the same fixed PVSS setup.
type verifiedPVSS struct {
	dealer   p2p.NodeID
	seq      uint64
	prepared *crypto.VerifiedPVSS
}

func NewVerifier(s PublicSetup, caches ...*verification.Cache) (*Verifier, error) {
	checks := verification.Select(caches...)
	pv, err := crypto.NewALBATROSSPVSSVerifier(s.F+1, s.PVSS, checks)
	if err != nil {
		return nil, err
	}
	acfg := s.ABA()
	acfg.Verification = checks
	av, err := aba.NewVerifier(acfg)
	if err != nil {
		return nil, err
	}
	return &Verifier{checks: checks, setup: s, pvss: pv, aba: av, columns: make(map[uint64]Column), objects: make(map[string]verifiedPVSS)}, nil
}
func (v *Verifier) AddColumn(c Column) error {
	if old, ok := v.columns[c.Record.Column]; ok {
		if old.Hash() != c.Hash() {
			return errors.New("conflicting column")
		}
		// Keep the previously verified evidence. The description hash excludes
		// signatures and witness encodings, so redundant evidence is ignored.
		return nil
	}
	r := c.Record
	n := len(v.setup.Members)
	if r.Column == 0 || len(r.Decisions) != n || len(r.Accepted) < n-v.setup.F || len(r.Accepted) > n || len(c.Objects) != len(r.Accepted) || c.Whole.Bit != r.Whole {
		return errors.New("invalid column shape")
	}
	if err := v.aba.VerifyCertificate(c.Whole, columnID(r.Column)); err != nil {
		return err
	}
	if r.Whole == aba.One {
		if len(c.Decisions) != 0 {
			return errors.New("unexpected per-object certificates")
		}
	} else if len(c.Decisions) != n {
		return errors.New("missing object decisions")
	}
	accepted := 0
	for i, id := range v.setup.Members {
		d := r.Decisions[i]
		if d.Source != id || (d.Bit != aba.Zero && d.Bit != aba.One) {
			return errors.New("invalid decision order or bit")
		}
		if r.Whole == aba.One && d.Bit != aba.One {
			return errors.New("whole-column decision requires all objects")
		}
		if r.Whole == aba.Zero {
			if c.Decisions[i].Bit != d.Bit {
				return errors.New("object decision mismatch")
			}
			if err := v.aba.VerifyCertificate(c.Decisions[i], objectID(r.Column, id)); err != nil {
				return err
			}
		}
		if d.Bit == aba.One {
			if accepted >= len(r.Accepted) {
				return errors.New("missing accepted object")
			}
			a := r.Accepted[accepted]
			o := c.Objects[accepted]
			h := rbc.Hash(encode(o.Transcript))
			if a.Source != id || o.Transcript.Dealer != id || o.Transcript.Seq != r.Column || a.Hash != h || o.Delivery.Hash != h || o.Delivery.Dealer != id || o.Delivery.Seq != r.Column || !rbc.VerifyCertificate(v.setup.Context, v.setup.Signing, v.setup.F, o.Delivery, v.checks) {
				return errors.New("invalid object binding or delivery certificate")
			}
			if _, verified := v.objects[h]; !verified {
				prepared, valid := v.pvss.Prepare(o.Transcript)
				if !valid {
					return errors.New("invalid PVSS transcript")
				}
				v.objects[h] = verifiedPVSS{o.Transcript.Dealer, o.Transcript.Seq, prepared}
			}
			accepted++
		}
	}
	if accepted != len(r.Accepted) {
		return errors.New("accepted set mismatch")
	}
	v.columns[r.Column] = clone(c)
	return nil
}
func (v *Verifier) Initialize(c Column) error {
	if v.state != nil {
		return errors.New("already initialized")
	}
	if c.Record.Column != 1 {
		return errors.New("genesis must use column one")
	}
	if err := v.AddColumn(c); err != nil {
		return err
	}
	s := genesis(v.setup, c)
	v.state = &s
	return nil
}
func objectFor(c Column, id p2p.NodeID) (Object, bool) {
	for i, a := range c.Record.Accepted {
		if a.Source == id {
			return c.Objects[i], true
		}
	}
	return Object{}, false
}
func (v *Verifier) recordTemplate() (BeaconRecord, Object, error) {
	if v.state == nil {
		return BeaconRecord{}, Object{}, errors.New("missing genesis")
	}
	s := v.state
	id, err := s.selected()
	if err != nil {
		return BeaconRecord{}, Object{}, err
	}
	c := v.columns[s.Column]
	next := ""
	if s.needsNext(v.setup, v.columns) {
		nc, ok := v.columns[s.Column+1]
		if !ok {
			return BeaconRecord{}, Object{}, errors.New("look-ahead barrier incomplete")
		}
		next = nc.Hash()
	}
	o, ok := objectFor(c, id)
	if !ok {
		return BeaconRecord{}, Object{}, errors.New("missing selected object")
	}
	r := BeaconRecord{Type: "BEACON", Epoch: s.Epoch, PreviousHash: s.PreviousHash, Column: s.Column, Source: id, ObjectHash: o.Delivery.Hash, CurrentColumnHash: c.Hash(), NextColumnHash: next}
	return r, o, nil
}
func (v *Verifier) checkRecord(r BeaconRecord) (Object, error) {
	expected, o, err := v.recordTemplate()
	if err != nil {
		return Object{}, err
	}
	expected.Random = r.Random // Reconstruction checks the remaining field.
	if r != expected {
		return Object{}, errors.New("invalid beacon history, selection or look-ahead binding")
	}
	return o, nil
}
func (v *Verifier) CheckEntry(e Entry) error {
	o, err := v.checkRecord(e.Record)
	if err != nil {
		return err
	}
	if len(e.Shares) != v.setup.F+1 {
		return errors.New("reconstruction witness requires exactly t shares")
	}
	// ReconTrusted verifies shares and distinct holders itself. With exactly t
	// inputs it cannot ignore an invalid or duplicate share and still succeed.
	prepared, err := v.preparedObject(e.Record.ObjectHash, o.Transcript)
	if err != nil {
		return err
	}
	z, err := v.pvss.ReconPrepared(prepared, e.Shares, v.setup.F+1)
	if err != nil {
		return err
	}
	if e.Record.Random != randomValue(e.Record.Epoch, v.state.PreviousRandom, z) {
		return errors.New("incorrect beacon randomness")
	}
	return nil
}

// Only call for an object already bound into a checked, privately owned column.
func (v *Verifier) preparedObject(hash string, object crypto.PVSSCommitment) (*crypto.VerifiedPVSS, error) {
	known := v.objects[hash]
	if known.prepared == nil {
		prepared, valid := v.pvss.Prepare(object)
		if !valid {
			return nil, errors.New("invalid prepared object")
		}
		known = verifiedPVSS{object.Dealer, object.Seq, prepared}
		v.objects[hash] = known
	}
	return known.prepared, nil
}
func (v *Verifier) Apply(e Entry) error {
	if err := v.CheckEntry(e); err != nil {
		return fmt.Errorf("epoch %d: %w", e.Record.Epoch, err)
	}
	return v.state.install(v.setup, e.Record, v.columns)
}
func VerifyHistory(s PublicSetup, h History) error {
	v, err := NewVerifier(s)
	if err != nil {
		return err
	}
	if err = v.Initialize(h.Genesis); err != nil {
		return err
	}
	for _, c := range h.Columns {
		if err = v.AddColumn(c); err != nil {
			return err
		}
	}
	for _, e := range h.Entries {
		if err = v.Apply(e); err != nil {
			return err
		}
	}
	return nil
}
