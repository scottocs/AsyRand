package tyche

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

func GenesisBeaconHead(configVersion uint64, random []byte, members []p2p.NodeID) string {
	var versionBytes [8]byte
	binary.BigEndian.PutUint64(versionBytes[:], configVersion)
	return hex.EncodeToString(crypto.DomainHash(
		"Tyche/BeaconGenesis/v1", versionBytes[:], random,
		canonicalJSON(normalizeMembers(members)),
	))
}

func BeaconHeaderHash(configVersion, epoch uint64, parentHash string, source p2p.NodeID, seq uint64, random []byte) string {
	return hex.EncodeToString(crypto.DomainHash(
		"Tyche/BeaconHeader/v1",
		BeaconVoteTranscript(configVersion, epoch, parentHash, source, seq, random),
	))
}

// BeaconQC is the certificate carried by P_e.  It certifies exactly the
// BEACON tuple from the paper; it is not a certificate for a local state
// snapshot.
type BeaconQC struct {
	ConfigVersion uint64                         `json:"config_version"`
	Epoch         uint64                         `json:"epoch"`
	ParentHash    string                         `json:"parent_hash"`
	Source        p2p.NodeID                     `json:"source"`
	Seq           uint64                         `json:"seq"`
	Random        []byte                         `json:"random"`
	Signature     crypto.SignedQuorumCertificate `json:"signature"`
}

func BeaconVoteTranscript(configVersion, epoch uint64, parentHash string, source p2p.NodeID, seq uint64, random []byte) []byte {
	var versionBytes, epochBytes, seqBytes [8]byte
	binary.BigEndian.PutUint64(versionBytes[:], configVersion)
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	return crypto.DomainHash(
		"Tyche/BeaconVote/v1",
		versionBytes[:], epochBytes[:], []byte(parentHash), []byte(source),
		seqBytes[:], random,
	)
}

func SignBeaconVote(signer p2p.NodeID, private ed25519.PrivateKey, config Configuration, epoch uint64, parentHash string, source p2p.NodeID, seq uint64, random []byte) (crypto.SignedVote, error) {
	if !config.Contains(signer) {
		return crypto.SignedVote{}, errors.New("beacon signer is not in the active configuration")
	}
	return crypto.SignTranscript(
		string(signer), private,
		BeaconVoteTranscript(config.Version, epoch, parentHash, source, seq, random),
	)
}

func BuildBeaconQC(config Configuration, epoch uint64, parentHash string, source p2p.NodeID, seq uint64, random []byte, votes []crypto.SignedVote) (BeaconQC, error) {
	transcript := BeaconVoteTranscript(config.Version, epoch, parentHash, source, seq, random)
	certificate, err := crypto.BuildSignedQuorumCertificate(votes, config.PublicKeys(), config.Q, transcript)
	if err != nil {
		return BeaconQC{}, err
	}
	return BeaconQC{
		ConfigVersion: config.Version,
		Epoch:         epoch, ParentHash: parentHash, Source: source, Seq: seq,
		Random: append([]byte(nil), random...), Signature: certificate,
	}, nil
}

func VerifyBeaconQC(config Configuration, qc BeaconQC) error {
	if qc.ConfigVersion != config.Version || qc.Epoch == 0 || qc.ParentHash == "" ||
		qc.Source == "" || qc.Seq == 0 || len(qc.Random) == 0 {
		return errors.New("invalid beacon certificate header")
	}
	return crypto.VerifySignedQuorumCertificate(
		qc.Signature, config.PublicKeys(), config.Q,
		BeaconVoteTranscript(qc.ConfigVersion, qc.Epoch, qc.ParentHash, qc.Source, qc.Seq, qc.Random),
	)
}
