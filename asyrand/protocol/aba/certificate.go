// Package aba implements the contextual local-coin Quadratic-ABA core and
// decision-certificate wrapper in paper/Asyrand.tex, Appendix WaterBear
// Quadratic-ABA. The application routes returned messages over authenticated,
// eventually reliable channels and continues Handle after receiving a result.
package aba

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sort"
	"unicode/utf8"

	asig "Tyche/asyrand/crypto"
	"Tyche/utils/p2p"
)

const Protocol = "asyrand/quadratic-aba/v1"

// Value is a binary estimate or a wildcard used only by MAIN and FINAL.
type Value uint8

const (
	Zero Value = iota
	One
	Wildcard
)

func (v Value) binary() bool { return v == Zero || v == One }

type Signature struct {
	Signer p2p.NodeID `json:"signer"`
	SigHex string     `json:"sig_hex"`
}

// Certificate signatures bind the committee, instance and bit, not the round.
type Certificate struct {
	CommitteeID string      `json:"committee_id"`
	Instance    string      `json:"instance"`
	Bit         Value       `json:"bit"`
	Signatures  []Signature `json:"signatures"`
}

type Decision struct {
	Bit         Value
	Certificate Certificate
}

// PublicConfig is the immutable setup used by nodes and external verifiers.
// SetupID is the canonical SHA-256 fingerprint of the beacon's public PVSS
// parameters and shareholder keys (e.g. PVSSCommitment.SetupID).
type PublicConfig struct {
	SetupID string
	Members []p2p.NodeID
	F       int
	Public  map[string]ed25519.PublicKey
}

type Verifier struct {
	committeeID                      string
	members                          []p2p.NodeID
	public                           map[p2p.NodeID]ed25519.PublicKey
	f, coreQuorum, certificateQuorum int
}

func NewVerifier(cfg PublicConfig) (*Verifier, error) {
	n := len(cfg.Members)
	if n == 0 || cfg.F < 0 || cfg.F > (n-1)/3 || len(cfg.Public) != n || !canonicalHex(cfg.SetupID, 32) {
		return nil, errors.New("ABA requires n>3f, the exact member keys and a canonical public setup fingerprint")
	}
	v := &Verifier{members: append([]p2p.NodeID(nil), cfg.Members...), public: make(map[p2p.NodeID]ed25519.PublicKey, n), f: cfg.F, coreQuorum: (n+cfg.F)/2 + 1, certificateQuorum: n - cfg.F}
	sort.Slice(v.members, func(i, j int) bool { return v.members[i] < v.members[j] })
	type memberKey struct {
		ID  p2p.NodeID
		Key string
	}
	keys := make([]memberKey, n)
	for i, id := range v.members {
		pub := cfg.Public[string(id)]
		if id == "" || !utf8.ValidString(string(id)) || (i > 0 && id == v.members[i-1]) || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ABA identity, duplicate member or signing public key")
		}
		v.public[id] = append(ed25519.PublicKey(nil), pub...)
		keys[i] = memberKey{id, hex.EncodeToString(pub)}
	}
	v.committeeID = hex.EncodeToString(asig.HashBytes(encode(struct {
		Domain, SetupID string
		N, F            int
		Keys            []memberKey
	}{Protocol + "/setup", cfg.SetupID, n, cfg.F, keys})))
	return v, nil
}

func (v *Verifier) CommitteeID() string    { return v.committeeID }
func (v *Verifier) CoreQuorum() int        { return v.coreQuorum }
func (v *Verifier) CertificateQuorum() int { return v.certificateQuorum }

func validInstance(instance string) bool { return instance != "" && utf8.ValidString(instance) }

func (v *Verifier) decisionStatement(instance string, bit Value) []byte {
	return encode(struct {
		Domain, CommitteeID, Instance string
		Bit                           Value
	}{Protocol + "/decision", v.committeeID, instance, bit})
}

func (v *Verifier) verifySignature(from p2p.NodeID, statement []byte, sigHex string) bool {
	pub := v.public[from]
	if pub == nil || !canonicalHex(sigHex, ed25519.SignatureSize) {
		return false
	}
	sig, _ := hex.DecodeString(sigHex)
	return asig.Verify(pub, statement, sig)
}

// VerifyCertificate verifies ALL listed signatures from distinct members.
// expectedInstance is mandatory to prevent cross-instance replay.
func (v *Verifier) VerifyCertificate(cert Certificate, expectedInstance string) error {
	if !validInstance(expectedInstance) || cert.Instance != expectedInstance || cert.CommitteeID != v.committeeID || !cert.Bit.binary() ||
		len(cert.Signatures) < v.certificateQuorum || len(cert.Signatures) > len(v.members) {
		return errors.New("invalid ABA certificate context, bit or quorum")
	}
	statement := v.decisionStatement(cert.Instance, cert.Bit)
	for i, sig := range cert.Signatures {
		if (i > 0 && sig.Signer <= cert.Signatures[i-1].Signer) || !v.verifySignature(sig.Signer, statement, sig.SigHex) {
			return errors.New("ABA certificate has a duplicate, unordered, unknown or invalid signer")
		}
	}
	return nil
}

func cloneCertificate(cert Certificate) Certificate {
	cert.Signatures = append([]Signature(nil), cert.Signatures...)
	return cert
}

func canonicalHex(raw string, size int) bool {
	if len(raw) != 2*size {
		return false
	}
	b, err := hex.DecodeString(raw)
	return err == nil && hex.EncodeToString(b) == raw
}

func encode(value any) []byte {
	b, err := asig.CanonicalBytes(value)
	if err != nil {
		panic(err)
	} // All internal statement types are plain JSON data.
	return b
}

func validPrivate(private ed25519.PrivateKey, public ed25519.PublicKey) bool {
	if len(private) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	return bytes.Equal(private, derived) && bytes.Equal(derived[ed25519.SeedSize:], public)
}
