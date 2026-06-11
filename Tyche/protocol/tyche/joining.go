package tyche

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"tyche.local/Tyche/Tyche/crypto"
	"tyche.local/Tyche/Tyche/protocol/aba"
	"tyche.local/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type JoinRequest struct {
	ConfigVersion   uint64            `json:"config_version"`
	ContextEpoch    uint64            `json:"context_epoch"`
	Joiner          p2p.NodeID        `json:"joiner"`
	PublicKey       string            `json:"public_key"`
	CandidateParams crypto.PVSSParams `json:"candidate_params,omitempty"`
	Object          Object            `json:"object"`
	FirstCoinEpoch  uint64            `json:"first_coin_epoch"`
	ActivationEpoch uint64            `json:"activation_epoch"`
}

type TransitionIndex struct {
	ConfigVersion uint64 `json:"config_version"`
	Seq           uint64 `json:"seq"`
}

func (t TransitionIndex) String() string {
	return fmt.Sprintf("%d/%d", t.ConfigVersion, t.Seq)
}

type JoinAck struct {
	Transition    TransitionIndex  `json:"transition"`
	RequestDigest string           `json:"request_digest"`
	Signer        p2p.NodeID       `json:"signer"`
	Signature     crypto.VoteShare `json:"signature"`
}

type JoinCommit struct {
	Transition      TransitionIndex  `json:"transition"`
	RequestDigest   string           `json:"request_digest"`
	ActivationEpoch uint64           `json:"activation_epoch"`
	Signer          p2p.NodeID       `json:"signer"`
	Signature       crypto.VoteShare `json:"signature"`
}

type JoinArm struct {
	Request JoinRequest `json:"request"`
	Cert1   []JoinAck   `json:"cert1"`
}

type JoinCertificate struct {
	Request JoinRequest  `json:"request"`
	Cert1   []JoinAck    `json:"cert1"`
	Cert2   []JoinCommit `json:"cert2"`
}

type CatchupSnapshot struct {
	ConfigVersion uint64                           `json:"config_version"`
	Members       []p2p.NodeID                     `json:"members"`
	SCL           []p2p.NodeID                     `json:"scl"`
	RSQ           []p2p.NodeID                     `json:"rsq"`
	Seqs          map[p2p.NodeID]uint64            `json:"seqs"`
	RmMark        map[p2p.NodeID]int64             `json:"rm_mark"`
	Epoch         uint64                           `json:"epoch"`
	Random        []byte                           `json:"random"`
	Queued        map[p2p.NodeID]map[uint64]Object `json:"queued"`
}

func (n *Node) ProposeJoin(ctx context.Context, req JoinRequest) error {
	if err := n.verifyJoinRequest(req); err != nil {
		return err
	}
	raw, err := jsonMarshal(envelope{Kind: "join", Join: &req})
	if err != nil {
		return err
	}
	return n.RBC.Broadcast(ctx, req.Object.Seq, raw)
}

func (n *Node) HandleJoinRequest(ctx context.Context, req JoinRequest) error {
	if err := n.verifyJoinRequest(req); err != nil {
		return nil
	}
	rho := JoinDigest(req)
	n.mu.Lock()
	if req.ConfigVersion != n.State.ConfigVersion || !n.noPendingRemovalLocked() {
		n.mu.Unlock()
		return nil
	}
	tau := TransitionIndex{ConfigVersion: n.State.ConfigVersion, Seq: n.State.TransitionSeq + 1}
	key := tau.String()
	if existing := n.State.PendingReconf[key]; existing != "" && existing != rho {
		n.mu.Unlock()
		return nil
	}
	n.State.PendingReconf[key] = rho
	n.joinRequests[rho] = req
	n.mu.Unlock()
	sig, err := crypto.NewVoteShare(string(n.ID))
	if err != nil {
		return err
	}
	ack := JoinAck{Transition: tau, RequestDigest: rho, Signer: n.ID, Signature: sig}
	msg, err := p2p.NewMessage(Protocol, "JOIN_ACK", key+"/"+rho, n.ID, "", ack)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) HandleJoinAck(ctx context.Context, ack JoinAck) error {
	if !n.validJoinAck(ack) {
		return nil
	}
	key := ack.Transition.String() + "/" + ack.RequestDigest
	n.mu.Lock()
	if n.joinAcks[key] == nil {
		n.joinAcks[key] = make(map[p2p.NodeID]JoinAck)
	}
	n.joinAcks[key][ack.Signer] = ack
	req, hasReq := n.joinRequests[ack.RequestDigest]
	ready := len(n.joinAcks[key]) >= 2*n.State.F+1 && hasReq && !n.armSent[key]
	var cert []JoinAck
	if ready {
		n.armSent[key] = true
		cert = collectAcks(n.joinAcks[key], 2*n.State.F+1)
	}
	n.mu.Unlock()
	if !ready {
		return nil
	}
	arm := JoinArm{Request: req, Cert1: cert}
	msg, err := p2p.NewMessage(Protocol, "JOIN_ARM", key, n.ID, "", arm)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) HandleJoinArm(ctx context.Context, arm JoinArm) error {
	if err := n.verifyJoinRequest(arm.Request); err != nil {
		return nil
	}
	rho := JoinDigest(arm.Request)
	if len(arm.Cert1) < 2*n.State.F+1 || !n.verifyAckCert(arm.Cert1, rho) {
		return nil
	}
	tau := arm.Cert1[0].Transition
	key := tau.String() + "/" + rho
	n.mu.Lock()
	n.joinRequests[rho] = arm.Request
	rebroadcast := !n.armSent[key]
	n.armSent[key] = true
	n.mu.Unlock()
	if rebroadcast {
		msg, err := p2p.NewMessage(Protocol, "JOIN_ARM", key, n.ID, "", arm)
		if err == nil {
			_ = n.Transport.Broadcast(ctx, msg)
		}
	}
	return n.ABA.Propose(ctx, aba.JoinInstance(tau.String(), rho, arm.Request.FirstCoinEpoch), true)
}

func (n *Node) HandleJoinCommit(ctx context.Context, commit JoinCommit) error {
	if !n.validJoinCommit(commit) {
		debugf("node=%s ignore join_commit signer=%s transition=%s reason=invalid", n.ID, commit.Signer, commit.Transition.String())
		return nil
	}
	key := commit.Transition.String() + "/" + commit.RequestDigest + "/" + fmt.Sprint(commit.ActivationEpoch)
	n.mu.Lock()
	if n.joinCommits[key] == nil {
		n.joinCommits[key] = make(map[p2p.NodeID]JoinCommit)
	}
	n.joinCommits[key][commit.Signer] = commit
	req, hasReq := n.joinRequests[commit.RequestDigest]
	commitCount := len(n.joinCommits[key])
	certNeed := 2*n.State.F + 1
	ackCount := len(n.joinAcks[commit.Transition.String()+"/"+commit.RequestDigest])
	ready := commitCount >= certNeed && ackCount >= certNeed && hasReq
	cert2 := collectCommits(n.joinCommits[key], certNeed)
	cert1 := collectAcks(n.joinAcks[commit.Transition.String()+"/"+commit.RequestDigest], certNeed)
	n.mu.Unlock()
	if !ready {
		debugf("node=%s join_commit_wait transition=%s digest=%s commits=%d acks=%d has_req=%t need=%d", n.ID, commit.Transition.String(), commit.RequestDigest, commitCount, ackCount, hasReq, certNeed)
		return nil
	}
	cert := JoinCertificate{Request: req, Cert1: cert1, Cert2: cert2}
	n.relayJoinCertificate(ctx, cert)
	return n.InstallJoinCertificate(cert)
}

func (n *Node) InstallJoinCertificate(cert JoinCertificate) error {
	rho := JoinDigest(cert.Request)
	n.mu.Lock()
	if contains(n.State.Members, cert.Request.Joiner) {
		debugf("node=%s ignore join_cert joiner=%s reason=already_member version=%d epoch=%d activation=%d", n.ID, cert.Request.Joiner, n.State.ConfigVersion, n.State.Epoch, cert.Request.ActivationEpoch)
		n.mu.Unlock()
		return nil
	}
	if cert.Request.ConfigVersion != n.State.ConfigVersion {
		debugf("node=%s discard join_cert joiner=%s reason=config_mismatch cert_version=%d local_version=%d epoch=%d activation=%d", n.ID, cert.Request.Joiner, cert.Request.ConfigVersion, n.State.ConfigVersion, n.State.Epoch, cert.Request.ActivationEpoch)
		n.discardStaleJoinLocked(cert)
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	if err := n.verifyJoinRequest(cert.Request); err != nil {
		debugf("node=%s reject join_cert joiner=%s reason=verify_request err=%v", n.ID, cert.Request.Joiner, err)
		return err
	}
	if len(cert.Cert2) == 0 || !n.verifyAckCert(cert.Cert1, rho) || !n.verifyCommitCert(cert.Cert2, rho, cert.Request.ActivationEpoch) {
		n.mu.Lock()
		if contains(n.State.Members, cert.Request.Joiner) || cert.Request.ConfigVersion != n.State.ConfigVersion {
			n.discardStaleJoinLocked(cert)
			n.mu.Unlock()
			return nil
		}
		n.mu.Unlock()
		debugf("node=%s reject join_cert joiner=%s reason=invalid_cert cert1=%d cert2=%d activation=%d", n.ID, cert.Request.Joiner, len(cert.Cert1), len(cert.Cert2), cert.Request.ActivationEpoch)
		return fmt.Errorf("invalid join certificate: cert1=%d cert2=%d activation=%d", len(cert.Cert1), len(cert.Cert2), cert.Request.ActivationEpoch)
	}
	n.relayJoinCertificate(context.Background(), cert)
	scheme, err := n.schemeForCandidate(cert.Request.CandidateParams)
	if err != nil {
		debugf("node=%s reject join_cert joiner=%s reason=scheme err=%v", n.ID, cert.Request.Joiner, err)
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if cert.Request.ConfigVersion != n.State.ConfigVersion || !n.noPendingRemovalLocked() {
		debugf("node=%s defer_discard join_cert joiner=%s reason=state_changed cert_version=%d local_version=%d no_pending=%t epoch=%d activation=%d", n.ID, cert.Request.Joiner, cert.Request.ConfigVersion, n.State.ConfigVersion, n.noPendingRemovalLocked(), n.State.Epoch, cert.Request.ActivationEpoch)
		n.discardStaleJoinLocked(cert)
		return nil
	}
	if n.State.Epoch+1 < cert.Request.ActivationEpoch {
		debugf("node=%s store_pending_join joiner=%s epoch=%d activation=%d version=%d", n.ID, cert.Request.Joiner, n.State.Epoch, cert.Request.ActivationEpoch, n.State.ConfigVersion)
		key := transitionCertKey(cert)
		n.pendingJoins[key] = cert
		if n.lockedFrom == 0 || cert.Request.ActivationEpoch < n.lockedFrom {
			n.lockedFrom = cert.Request.ActivationEpoch
		}
		return nil
	}
	if n.State.Epoch+1 > cert.Request.ActivationEpoch {
		debugf("node=%s discard join_cert joiner=%s reason=past_activation epoch=%d activation=%d version=%d", n.ID, cert.Request.Joiner, n.State.Epoch, cert.Request.ActivationEpoch, n.State.ConfigVersion)
		n.discardStaleJoinLocked(cert)
		return nil
	}
	if contains(n.State.Members, cert.Request.Joiner) {
		return nil
	}
	debugf("node=%s install_join joiner=%s epoch=%d activation=%d version=%d", n.ID, cert.Request.Joiner, n.State.Epoch, cert.Request.ActivationEpoch, n.State.ConfigVersion)
	return n.installJoinCertificateLocked(cert, scheme)
}

func (n *Node) installJoinCertificateLocked(cert JoinCertificate, scheme crypto.PVSSScheme) error {
	n.State.Members = append(n.State.Members, cert.Request.Joiner)
	sort.Slice(n.State.Members, func(i, j int) bool { return n.State.Members[i] < n.State.Members[j] })
	if !contains(n.State.SCL, cert.Request.Joiner) {
		n.State.SCL = append(n.State.SCL, cert.Request.Joiner)
	}
	n.State.ComQ[cert.Request.Joiner] = map[uint64]Object{cert.Request.Object.Seq: cert.Request.Object}
	n.State.Seqs[cert.Request.Joiner] = 0
	n.State.RmMark[cert.Request.Joiner] = -1
	n.State.ConfigVersion++
	if len(cert.Cert2) > 0 && cert.Cert2[0].Transition.Seq > n.State.TransitionSeq {
		n.State.TransitionSeq = cert.Cert2[0].Transition.Seq
	}
	n.PVSS = scheme
	if n.ID == cert.Request.Joiner {
		n.producing = true
	}
	n.State.F = (len(n.State.Members) - 1) / 3
	n.RBC.N, n.RBC.F = len(n.State.Members), n.State.F
	n.ABA.N, n.ABA.F = len(n.State.Members), n.State.F
	n.resetConfigurationCachesLocked()
	delete(n.pendingJoins, transitionCertKey(cert))
	if n.lockedFrom == cert.Request.ActivationEpoch {
		n.lockedFrom = 0
	}
	select {
	case n.Joins <- cert:
	default:
	}
	return nil
}

func (n *Node) relayJoinCertificate(ctx context.Context, cert JoinCertificate) {
	key := transitionCertKey(cert)
	if key == "" {
		return
	}
	n.mu.Lock()
	if n.joinCertSent[key] {
		n.mu.Unlock()
		return
	}
	n.joinCertSent[key] = true
	recipients := append([]p2p.NodeID(nil), n.State.Members...)
	if cert.Request.Joiner != "" && !contains(recipients, cert.Request.Joiner) {
		recipients = append(recipients, cert.Request.Joiner)
	}
	n.mu.Unlock()
	msg, err := p2p.NewMessage(Protocol, "JOIN_CERT", key, n.ID, "", cert)
	if err != nil {
		return
	}
	for _, recipient := range recipients {
		if recipient == n.ID {
			continue
		}
		_ = n.Transport.Send(ctx, recipient, msg)
	}
}

func (n *Node) noPendingRemovalLocked() bool {
	for _, marker := range n.State.RmMark {
		if marker != -1 {
			return false
		}
	}
	return true
}

func (n *Node) discardStaleJoinLocked(cert JoinCertificate) {
	delete(n.pendingJoins, transitionCertKey(cert))
	if n.lockedFrom == cert.Request.ActivationEpoch {
		n.lockedFrom = 0
	}
}

func (n *Node) activatePendingJoins(ctx context.Context, epoch uint64) error {
	n.mu.Lock()
	var due []JoinCertificate
	for key, cert := range n.pendingJoins {
		if cert.Request.ActivationEpoch <= epoch {
			due = append(due, cert)
			delete(n.pendingJoins, key)
		}
	}
	n.mu.Unlock()
	for _, cert := range due {
		if err := n.InstallJoinCertificate(cert); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) RegisterPVSSKey(paramsEpoch string, private kyber.Scalar) {
	if paramsEpoch == "" || private == nil {
		return
	}
	n.mu.Lock()
	n.pvssKeys[paramsEpoch] = private.Clone()
	n.mu.Unlock()
}

func (n *Node) ActivatePendingJoins(ctx context.Context, epoch uint64) error {
	return n.activatePendingJoins(ctx, epoch)
}

func (n *Node) schemeForCandidate(pp crypto.PVSSParams) (crypto.PVSSScheme, error) {
	if pp.Epoch() == "" {
		return nil, errors.New("join candidate pvss parameters are required")
	}
	n.mu.Lock()
	private := n.pvssKeys[pp.Epoch()]
	n.mu.Unlock()
	if private == nil {
		return nil, errors.New("missing local pvss key for candidate configuration")
	}
	return crypto.NewPVSSScheme(n.ID, private, pp)
}

func transitionCertKey(cert JoinCertificate) string {
	rho := JoinDigest(cert.Request)
	var tau TransitionIndex
	if len(cert.Cert2) > 0 {
		tau = cert.Cert2[0].Transition
	} else if len(cert.Cert1) > 0 {
		tau = cert.Cert1[0].Transition
	}
	return tau.String() + "/" + rho + "/" + fmt.Sprint(cert.Request.ActivationEpoch)
}

func (n *Node) broadcastJoinCommit(ctx context.Context, req JoinRequest) error {
	rho := JoinDigest(req)
	n.mu.Lock()
	if req.ConfigVersion != n.State.ConfigVersion || req.ActivationEpoch <= n.State.Epoch || !n.noPendingRemovalLocked() || (n.lockedFrom != 0 && req.ActivationEpoch >= n.lockedFrom) {
		n.mu.Unlock()
		return nil
	}
	var tau TransitionIndex
	for _, acks := range n.joinAcks {
		for _, ack := range acks {
			if ack.RequestDigest == rho {
				tau = ack.Transition
				break
			}
		}
	}
	key := tau.String() + "/" + rho + "/" + fmt.Sprint(req.ActivationEpoch)
	if tau.ConfigVersion == 0 && tau.Seq == 0 || n.commitSent[key] {
		n.mu.Unlock()
		return nil
	}
	n.commitSent[key] = true
	n.lockedFrom = req.ActivationEpoch
	n.mu.Unlock()
	sig, err := crypto.NewVoteShare(string(n.ID))
	if err != nil {
		return err
	}
	commit := JoinCommit{Transition: tau, RequestDigest: rho, ActivationEpoch: req.ActivationEpoch, Signer: n.ID, Signature: sig}
	msg, err := p2p.NewMessage(Protocol, "JOIN_COMMIT", key, n.ID, "", commit)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) verifyJoinRequest(req JoinRequest) error {
	n.mu.Lock()
	version := n.State.ConfigVersion
	currentMembers := append([]p2p.NodeID(nil), n.State.Members...)
	n.mu.Unlock()
	if req.ConfigVersion != version || req.Joiner == "" || req.PublicKey == "" || req.FirstCoinEpoch >= req.ActivationEpoch {
		return errors.New("invalid join request metadata")
	}
	if contains(currentMembers, req.Joiner) {
		return errors.New("joiner already belongs to current configuration")
	}
	targetMembers := normalizeMembers(append(currentMembers, req.Joiner))
	targetF := (len(targetMembers) - 1) / 3
	if req.CandidateParams.Epoch() == "" || !crypto.VerifyPVSSSetup(req.CandidateParams) {
		return errors.New("invalid candidate pvss parameters")
	}
	if !sameMembers(req.CandidateParams.Members(), targetMembers) || req.CandidateParams.Threshold() != targetF+1 {
		return errors.New("candidate pvss parameters do not match target configuration")
	}
	if req.Object.ConfigVersion != version+1 || req.Object.Producer != req.Joiner || req.Object.Commitment.Dealer != req.Joiner || req.Object.Seq != 1 {
		return errors.New("invalid join object")
	}
	if req.Object.Commitment.Epoch != req.CandidateParams.Epoch() ||
		req.Object.Commitment.Threshold != req.CandidateParams.Threshold() ||
		!sameMembers(req.Object.Commitment.Members, req.CandidateParams.Members()) {
		return errors.New("join pvss object is not bound to candidate parameters")
	}
	kp := crypto.KeyPairFromSeed(crypto.HashBytes([]byte("Tyche-v1/join/verifier"), []byte(n.ID)))
	verifier, err := crypto.NewPVSSScheme(n.ID, kp.Private, req.CandidateParams)
	if err != nil {
		return err
	}
	if !verifier.Verify(req.Object.Commitment) {
		return errors.New("invalid join pvss object")
	}
	return nil
}

func (n *Node) validJoinAck(ack JoinAck) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ack.Signer == "" || contains(n.State.Members, ack.Signer) == false || ack.Transition.ConfigVersion != n.State.ConfigVersion {
		return false
	}
	if ack.Signature.Signer != string(ack.Signer) {
		return false
	}
	return crypto.VerifyVoteShare(ack.Signature, n.memberSetLocked())
}

func (n *Node) validJoinCommit(c JoinCommit) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if c.Signer == "" || contains(n.State.Members, c.Signer) == false || c.Transition.ConfigVersion != n.State.ConfigVersion {
		return false
	}
	if c.Signature.Signer != string(c.Signer) {
		return false
	}
	return crypto.VerifyVoteShare(c.Signature, n.memberSetLocked())
}

func (n *Node) verifyAckCert(cert []JoinAck, rho string) bool {
	seen := make(map[p2p.NodeID]bool)
	var tau TransitionIndex
	for i, ack := range cert {
		if !n.validJoinAck(ack) || ack.RequestDigest != rho || seen[ack.Signer] {
			return false
		}
		if i == 0 {
			tau = ack.Transition
		} else if ack.Transition != tau {
			return false
		}
		seen[ack.Signer] = true
	}
	return len(seen) >= 2*n.State.F+1
}

func (n *Node) verifyCommitCert(cert []JoinCommit, rho string, activation uint64) bool {
	seen := make(map[p2p.NodeID]bool)
	var tau TransitionIndex
	for i, c := range cert {
		if !n.validJoinCommit(c) || c.RequestDigest != rho || c.ActivationEpoch != activation || seen[c.Signer] {
			return false
		}
		if i == 0 {
			tau = c.Transition
		} else if c.Transition != tau {
			return false
		}
		seen[c.Signer] = true
	}
	return len(seen) >= 2*n.State.F+1
}

func (n *Node) joinRequestByInstanceLocked(instance string) (JoinRequest, bool) {
	for rho, req := range n.joinRequests {
		for _, acks := range n.joinAcks {
			for _, ack := range acks {
				if ack.RequestDigest == rho && instance == aba.JoinInstance(ack.Transition.String(), rho, req.FirstCoinEpoch) {
					return req, true
				}
			}
		}
	}
	return JoinRequest{}, false
}

func JoinDigest(req JoinRequest) string {
	return hex.EncodeToString(crypto.HashBytes([]byte("Tyche-v1/join/request"), canonicalJSON(req)))
}

func joinAckBytes(tau TransitionIndex, rho string) []byte {
	return crypto.HashBytes(
		[]byte("Tyche-v1/JOIN_ACK"),
		[]byte(fmt.Sprintf("%d", tau.ConfigVersion)),
		[]byte(fmt.Sprintf("%d", tau.Seq)),
		[]byte(rho),
	)
}

func joinCommitBytes(tau TransitionIndex, rho string, activation uint64) []byte {
	return crypto.HashBytes(
		[]byte("Tyche-v1/JOIN_COMMIT"),
		[]byte(fmt.Sprintf("%d", tau.ConfigVersion)),
		[]byte(fmt.Sprintf("%d", tau.Seq)),
		[]byte(rho),
		[]byte(fmt.Sprintf("%d", activation)),
	)
}

func collectAcks(in map[p2p.NodeID]JoinAck, limit int) []JoinAck {
	out := make([]JoinAck, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Signer < out[j].Signer })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func collectCommits(in map[p2p.NodeID]JoinCommit, limit int) []JoinCommit {
	out := make([]JoinCommit, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Signer < out[j].Signer })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func jsonMarshal(v any) ([]byte, error) {
	return canonicalJSON(v), nil
}
