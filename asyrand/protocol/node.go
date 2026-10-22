package asyrand

import (
	"Tyche/asyrand/config"
	"Tyche/asyrand/crypto"
	"Tyche/asyrand/protocol/aba"
	"Tyche/asyrand/protocol/rbc"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type columnTask struct {
	whole         *aba.Instance
	objects       map[p2p.NodeID]*aba.Instance
	wholeDecision *aba.Decision
	decisions     map[p2p.NodeID]aba.Decision
}
type reconHeader struct {
	Epoch      uint64
	Previous   string
	Column     uint64
	Source     p2p.NodeID
	ObjectHash string
}
type reconPacket struct {
	Header reconHeader
	Share  crypto.PVSSDecryptedShare
}
type request struct {
	Epoch             uint64
	Instance          string
	Round             uint64
	HaveThroughColumn uint64 `json:",omitempty"`
}
type response struct {
	Columns []Column
	Entries []Entry
	Core    []p2p.Message
}
type envelope struct {
	Context   string
	Body      json.RawMessage
	Signature string
}
type pendingRecon struct {
	header                                   reconHeader
	object                                   Object
	record                                   BeaconRecord
	previousRandom                           string
	shares                                   map[p2p.NodeID]crypto.PVSSDecryptedShare
	verifying                                map[p2p.NodeID]bool
	candidates                               map[p2p.NodeID]reconPacket
	done                                     chan struct{}
	releasePending, released, reconstructing bool
	entry                                    *Entry
}

// Node owns a single serialized consumer/ABA/RBC actor. Crypto jobs return
// captured-state completions to that actor; they never sign or install history.
// Archives remain available for passive pull while old ABA relay handlers live.
type Node struct {
	checks            *verification.Cache
	ID                p2p.NodeID
	Config            config.Config
	Transport         p2p.Transport
	Public            PublicSetup
	Perf              Perf
	private           ed25519.PrivateKey
	pvss              *crypto.PVSSPairingFreeScheme
	verifier          *Verifier
	rbc               *rbc.Broadcaster
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	start             sync.Once
	events            chan func()
	jobs              chan func()
	urgentJobs        chan func()
	outgoingBytes     atomic.Int64
	senders           map[p2p.NodeID]*sender
	ready             map[uint64]map[p2p.NodeID]Object
	tasks             map[uint64]*columnTask
	instances         map[string]*aba.Instance
	coreArchive       map[string]map[uint64][]p2p.Message
	validationPending map[string][]p2p.Message
	begun             map[uint64]bool
	columns           map[uint64]Column
	state             *consumptionState
	recon             *pendingRecon
	nextSeq           uint64
	producing         bool
	consuming         bool
	lastInstall       time.Time
	pullEpoch         uint64
	recoveryEpoch     uint64
	recoveryDelay     time.Duration
	nextRecovery      time.Time
	historyPeer       uint64
	earlyShares       map[uint64]map[p2p.NodeID]reconPacket
	witnesses         map[uint64]Entry
	mu                sync.RWMutex
	history           map[uint64]Entry
	columnArchive     map[uint64]Column
	notify            chan struct{}
	fatal             error
}

func New(cfg config.Config, id p2p.NodeID, t p2p.Transport) (*Node, error) {
	setup, err := Setup(cfg)
	if err != nil {
		return nil, err
	}
	keys, _, err := cfg.KeyPairs()
	if err != nil {
		return nil, err
	}
	kp, ok := keys[id]
	if !ok || t.ID() != id {
		return nil, errors.New("unknown node or transport identity")
	}
	seeds, err := cfg.NodeSeedBytes()
	if err != nil {
		return nil, err
	}
	checks := verification.New()
	pvkp := crypto.PVSSKeyPairFromSeed(seeds[id])
	pv, err := crypto.NewALBATROSSPVSSScheme(id, cfg.Threshold(), pvkp.Private, setup.PVSS, checks)
	if err != nil {
		return nil, err
	}
	v, err := NewVerifier(setup, checks)
	if err != nil {
		return nil, err
	}
	n := &Node{checks: checks, ID: id, Config: cfg, Transport: t, Public: setup, private: kp.Private, pvss: pv, verifier: v, events: make(chan func(), cfg.TransportBuffer), jobs: make(chan func(), cfg.TransportBuffer), senders: make(map[p2p.NodeID]*sender), ready: make(map[uint64]map[p2p.NodeID]Object), tasks: make(map[uint64]*columnTask), instances: make(map[string]*aba.Instance), coreArchive: make(map[string]map[uint64][]p2p.Message), validationPending: make(map[string][]p2p.Message), begun: make(map[uint64]bool), columns: v.columns, nextSeq: 1, history: make(map[uint64]Entry), columnArchive: make(map[uint64]Column), notify: make(chan struct{}), earlyShares: make(map[uint64]map[p2p.NodeID]reconPacket), witnesses: make(map[uint64]Entry)}
	n.rbc = rbc.New(rbc.Config{Verification: checks, ID: id, F: cfg.F, Members: setup.Members, Context: setup.Context, Private: kp.Private, Public: setup.Signing, Authenticated: p2p.AuthenticatedDelivery(t)})
	n.urgentJobs = make(chan func(), cfg.TransportBuffer)
	return n, nil
}
func (n *Node) Start(ctx context.Context) error {
	var err error
	n.start.Do(func() {
		n.ctx, n.cancel = context.WithCancel(ctx)
		err = n.Transport.Start(n.ctx)
		if err != nil {
			return
		}
		n.lastInstall = time.Now()
		for _, id := range n.Public.Members {
			s := &sender{wake: make(chan struct{}, 1), total: &n.outgoingBytes}
			n.senders[id] = s
			n.wg.Add(1)
			go n.sendLoop(id, s)
		}
		for i := 0; i < n.Config.MaxPool; i++ {
			n.wg.Add(1)
			go func() {
				defer n.wg.Done()
				for {
					// Reconstruction is on the output critical path; ahead-of-time
					// sharing/validation uses otherwise available worker capacity.
					select {
					case <-n.ctx.Done():
						return
					case job := <-n.urgentJobs:
						job()
						continue
					default:
					}
					select {
					case <-n.ctx.Done():
						return
					case job := <-n.urgentJobs:
						job()
					case job := <-n.jobs:
						job()
					}
				}
			}()
		}
		n.wg.Add(1)
		go n.run()
	})
	return err
}

// Stop waits for actor/crypto/senders before transport shutdown; peers should
// be cancelled together when shutting down a memory cluster.
func (n *Node) Stop() {
	if n.cancel != nil {
		n.cancel()
		n.wg.Wait()
	}
}
func (n *Node) sendLoop(id p2p.NodeID, s *sender) {
	defer n.wg.Done()
	for {
		m, ok := s.pop()
		if !ok {
			select {
			case <-n.ctx.Done():
				return
			case <-s.wake:
				continue
			}
		}
		for {
			if n.ctx.Err() != nil {
				return
			}
			ctx, cancel := context.WithTimeout(n.ctx, 3*time.Second)
			err := n.Transport.Send(ctx, id, m)
			cancel()
			if err == nil {
				break
			}
			timer := time.NewTimer(time.Duration(n.Config.SendRetryMS) * time.Millisecond)
			select {
			case <-n.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}
func (n *Node) emit(messages []p2p.Message) {
	for _, m := range messages {
		if m.Protocol == aba.Protocol && (m.Type == aba.PRE || m.Type == aba.VOTE || m.Type == aba.MAIN || m.Type == aba.FINAL) {
			b, _ := p2p.DecodePayload[aba.CoreMessage](m)
			if n.coreArchive[m.Instance] == nil {
				n.coreArchive[m.Instance] = make(map[uint64][]p2p.Message)
			}
			n.coreArchive[m.Instance][b.Round] = append(n.coreArchive[m.Instance][b.Round], m)
		}
		if m.To != "" {
			if s := n.senders[m.To]; s != nil {
				s.push(m)
			}
		} else {
			for _, id := range n.Public.Members {
				n.senders[id].push(m)
			}
		}
	}
}
func (n *Node) post(f func()) {
	select {
	case n.events <- f:
	case <-n.ctx.Done():
	}
}
func (n *Node) work(f func()) {
	select {
	case n.jobs <- f:
	case <-n.ctx.Done():
	}
}
func (n *Node) workUrgent(f func()) {
	select {
	case n.urgentJobs <- f:
	case <-n.ctx.Done():
	}
}
func (n *Node) fail(err error) {
	n.mu.Lock()
	if n.fatal == nil {
		n.fatal = err
		close(n.notify)
		n.notify = make(chan struct{})
	}
	n.mu.Unlock()
	n.cancel()
}
func (n *Node) run() {
	defer n.wg.Done()
	poll := time.Duration(n.Config.RecoveryMS) * time.Millisecond
	if poll > 250*time.Millisecond {
		poll = 250 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	n.ensureColumn(1)
	n.drive()
	for {
		select {
		case <-n.ctx.Done():
			return
		case f := <-n.events:
			f()
			n.drive()
		case m, ok := <-n.Transport.Inbox():
			if !ok {
				return
			}
			n.handle(m)
			n.drive()
		case now := <-ticker.C:
			n.emit(n.rbc.RetryPayloads(now))
			n.recoverAt(now)
			n.drive()
		}
	}
}
func (n *Node) WaitBeacon(ctx context.Context, e uint64) (Entry, error) {
	for {
		n.mu.RLock()
		b, ok := n.history[e]
		fatal := n.fatal
		wake := n.notify
		n.mu.RUnlock()
		if ok {
			return clone(b), nil
		}
		if fatal != nil {
			return Entry{}, fatal
		}
		select {
		case <-ctx.Done():
			return Entry{}, ctx.Err()
		case <-n.ctx.Done():
			n.mu.RLock()
			fatal = n.fatal
			n.mu.RUnlock()
			if fatal != nil {
				return Entry{}, fatal
			}
			return Entry{}, n.ctx.Err()
		case <-wake:
		}
	}
}
func (n *Node) Export(through uint64) History {
	n.mu.RLock()
	defer n.mu.RUnlock()
	h := History{Genesis: n.columnArchive[1]}
	var ids []uint64
	for k := range n.columnArchive {
		if k > 1 {
			ids = append(ids, k)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, k := range ids {
		h.Columns = append(h.Columns, n.columnArchive[k])
	}
	for e := uint64(1); e <= through; e++ {
		if b, ok := n.history[e]; ok {
			h.Entries = append(h.Entries, b)
		}
	}
	return clone(h)
}
func (n *Node) currentColumn() uint64 {
	if n.state == nil {
		return 1
	}
	return n.state.Column
}
func (n *Node) newABA(id string) *aba.Instance {
	if a := n.instances[id]; a != nil {
		return a
	}
	acfg := n.Public.ABA()
	acfg.Verification = n.checks
	a, err := aba.New(aba.Config{PublicConfig: acfg, ID: n.ID, Instance: id, Private: n.private, Authenticated: p2p.AuthenticatedDelivery(n.Transport)})
	if err != nil {
		n.fail(err)
		return nil
	}
	n.mu.Lock()
	n.instances[id] = a
	n.mu.Unlock()
	// Native DECISION messages already deliver a certificate. Pull only when
	// recovery is needed; eager requests make every peer send a full copy to
	// every other peer as soon as the instance decides.
	return a
}
func (n *Node) ensureColumn(c uint64) *columnTask {
	t := n.tasks[c]
	if t == nil {
		t = &columnTask{whole: n.newABA(columnID(c)), objects: make(map[p2p.NodeID]*aba.Instance), decisions: make(map[p2p.NodeID]aba.Decision)}
		n.tasks[c] = t
	}
	return t
}
func (n *Node) ensureObject(c uint64, id p2p.NodeID) *aba.Instance {
	t := n.ensureColumn(c)
	if t.objects[id] == nil {
		t.objects[id] = n.newABA(objectID(c, id))
	}
	return t.objects[id]
}
func (n *Node) routeABA(m p2p.Message) {
	a := n.instances[m.Instance]
	if a == nil {
		var c uint64
		var source string
		if strings.HasPrefix(m.Instance, "col/") {
			if _, err := fmt.Sscanf(m.Instance, "col/%d", &c); err != nil || m.Instance != columnID(c) {
				return
			}
		} else if strings.HasPrefix(m.Instance, "obj/") {
			parts := strings.SplitN(m.Instance, "/", 3)
			if len(parts) != 3 {
				return
			}
			if _, err := fmt.Sscanf(parts[1], "%d", &c); err != nil {
				return
			}
			source = parts[2]
			if n.Public.Signing[source] == nil || m.Instance != objectID(c, p2p.NodeID(source)) {
				return
			}
		} else {
			return
		}
		// A peer may close the current column before this receiver. Retain
		// its next-column ABA packets across the full production window,
		// rather than dropping them until a periodic replay request.
		if c < n.currentColumn() || c > n.currentColumn()+uint64(n.Config.ProductionWindow) {
			return
		}
		if source == "" {
			a = n.ensureColumn(c).whole
		} else {
			a = n.ensureObject(c, p2p.NodeID(source))
		}
	}
	if m.Type == aba.PRE || m.Type == aba.VOTE || m.Type == aba.MAIN || m.Type == aba.FINAL {
		body, err := p2p.DecodePayload[aba.CoreMessage](m)
		if err != nil {
			return
		}
		status := a.Status()
		if status.Stopped && body.Round > status.Round {
			// A stopped helper still serves entered rounds and certificates,
			// but has no reason to request new rounds. Requesting them would
			// repeatedly pull the same future packet from an advanced peer.
			return
		}
		if body.Round > status.Round && body.Round-status.Round > n.Config.ABAFutureRounds {
			if a.VerifyCoreMessage(m) {
				n.send("SYNC", m.From, request{Instance: m.Instance, Round: status.Round})
			}
			return
		}
	}
	out, err := a.Handle(m)
	n.emit(out)
	if err != nil && !errors.Is(err, aba.ErrInvalidMessage) {
		n.fail(err)
	}
}
func (n *Node) handle(m p2p.Message) {
	if m.To != "" && m.To != n.ID {
		return
	}
	switch m.Protocol {
	case aba.Protocol:
		n.routeABA(m)
	case rbc.Protocol:
		n.handleRBC(m)
	case Protocol:
		n.handleBeacon(m)
	}
}
func (n *Node) handleRBC(m p2p.Message) {
	p, ok := rbc.Authenticate(n.Public.Context, n.Public.Signing, m, n.checks)
	if !ok {
		n.Perf.Invalid.Add(1)
		return
	}
	if !n.rbc.Admit(m, p) {
		return
	}
	// Historical requests are served from the archive. Far-ahead data is pulled
	// after history catch-up instead of allocating unbounded protocol state.
	if m.Type != "REQUEST" && p.Seq > n.currentColumn()+uint64(n.Config.ProductionWindow) {
		return
	}
	if m.Type == "VAL" || m.Type == "REPLY" {
		known, verified := n.verifier.objects[p.Hash]
		if verified && (known.dealer != p.Dealer || known.seq != p.Seq) {
			n.Perf.Invalid.Add(1)
			return // A cached object cannot change RBC position.
		}
		if !verified {
			if pending, ok := n.validationPending[p.Hash]; ok {
				if len(pending) < 2 {
					n.validationPending[p.Hash] = append(pending, m)
				}
				return
			}
			// One concurrent payload check per dealer/position; missing certified values
			// are retried by recovery, so overload never changes an ABA input.
			if len(n.validationPending) >= len(n.Public.Members)*n.Config.ProductionWindow*2 {
				return
			}
			n.validationPending[p.Hash] = []p2p.Message{m}
			n.rbc.PayloadPending(p, true)
			value := append([]byte(nil), p.Value...)
			n.work(func() {
				var o crypto.PVSSCommitment
				ok := json.Unmarshal(value, &o) == nil && o.Dealer == p.Dealer && o.Seq == p.Seq && string(encode(o)) == string(value) && n.pvss.Verify(o)
				n.Perf.VerifyCount.Add(1)
				n.post(func() {
					pending := n.validationPending[p.Hash]
					delete(n.validationPending, p.Hash)
					if !ok {
						n.Perf.Invalid.Add(1)
						n.emit(n.rbc.PayloadPending(p, false))
						return
					}
					n.verifier.objects[p.Hash] = verifiedPVSS{o.Dealer, o.Seq}
					for _, old := range pending {
						packet, _ := p2p.DecodePayload[rbc.Packet](old)
						n.acceptRBC(old, packet)
					}
					n.emit(n.rbc.PayloadPending(p, false))
				})
			})
			return
		}
	}
	n.acceptRBC(m, p)
}
func (n *Node) acceptRBC(m p2p.Message, p rbc.Packet) {
	if m.Type == "VAL" || m.Type == "REPLY" {
		known, verified := n.verifier.objects[p.Hash]
		if !verified || known.dealer != p.Dealer || known.seq != p.Seq {
			// Check pending packets too: they may have arrived under another
			// dealer/position while the first copy was being verified.
			n.Perf.Invalid.Add(1)
			return
		}
	}
	out, del := n.rbc.Handle(m, p)
	n.emit(out)
	for _, d := range del {
		var o crypto.PVSSCommitment
		if json.Unmarshal(d.Value, &o) != nil {
			continue
		}
		if n.ready[d.Seq] == nil {
			n.ready[d.Seq] = make(map[p2p.NodeID]Object)
		}
		if _, ok := n.ready[d.Seq][d.Dealer]; !ok {
			n.ready[d.Seq][d.Dealer] = Object{o, d.Certificate}
		}
	}
}
func (n *Node) drive() {
	if n.ctx.Err() != nil {
		return
	}
	n.produce()
	c := n.currentColumn()
	n.advanceColumn(c)
	if n.begun[c] {
		n.advanceColumn(c + 1)
	}
	if n.state == nil && !n.initializeGenesis() {
		return
	}
	if !n.consuming {
		return
	}
	c = n.state.Column
	if !n.begun[c] {
		n.begun[c] = true
		n.ensureColumn(c + 1)
		n.advanceColumn(c + 1)
	}
	if n.state.needsNext(n.Public, n.columns) {
		if _, ok := n.columns[c+1]; !ok {
			return
		}
	}
	n.consume()
}
func (n *Node) initializeGenesis() bool {
	first, ok := n.columns[1]
	if !ok {
		return false
	}
	if err := n.verifier.Initialize(first); err != nil {
		n.fail(err)
		return false
	}
	// Native execution and recovery share the same actor-owned replay state.
	n.state = n.verifier.state
	return true
}
func (n *Node) produce() {
	if n.producing || n.nextSeq > n.currentColumn()+uint64(n.Config.ProductionWindow)-1 {
		return
	}
	// Backpressure only speculative production. Current/successor positions
	// remain enabled, so congestion cannot create a look-ahead dependency cycle.
	if n.nextSeq > n.currentColumn()+1 && n.outgoingBytes.Load() > 16<<20 {
		return
	}

	seq := n.nextSeq
	n.nextSeq++
	n.producing = true
	n.work(func() {
		o, _, err := n.pvss.Share(n.ID, seq, n.Public.Members)
		n.Perf.ShareCount.Add(1)
		n.post(func() {
			n.producing = false
			if err != nil {
				n.fail(err)
				return
			}
			value := encode(o)
			n.verifier.objects[rbc.Hash(value)] = verifiedPVSS{o.Dealer, o.Seq}
			n.emit(n.rbc.Broadcast(seq, value))
		})
	})
}
func (n *Node) propose(a *aba.Instance, bit aba.Value) {
	out, err := a.Propose(bit)
	n.emit(out)
	if err != nil && !errors.Is(err, aba.ErrAlreadyProposed) && !errors.Is(err, aba.ErrAlreadyCertified) {
		n.fail(err)
	}
}
func (n *Node) advanceColumn(c uint64) {
	if _, done := n.columns[c]; done {
		return
	}
	t := n.ensureColumn(c)
	if t.wholeDecision == nil {
		if d, ok := t.whole.Result(); ok {
			t.wholeDecision = &d
		}
	}
	if t.wholeDecision == nil {
		if !t.whole.Status().Proposed && (len(n.ready[c]) == len(n.Public.Members) || ((c == 1 || n.begun[c-1]) && len(n.ready[c]) >= 2*n.Config.F+1)) {
			bit := aba.Zero
			if len(n.ready[c]) == len(n.Public.Members) {
				bit = aba.One
			}
			n.propose(t.whole, bit)
		}
		if d, ok := t.whole.Result(); ok {
			t.wholeDecision = &d
		} else {
			return
		}
	}
	whole := *t.wholeDecision
	record := ColumnRecord{Column: c, Whole: whole.Bit}
	certs := []aba.Certificate(nil)
	if whole.Bit == aba.Zero {
		ones := 0
		for _, id := range n.Public.Members {
			a := n.ensureObject(c, id)
			if _, cached := t.decisions[id]; !cached {
				if d, ok := a.Result(); ok {
					t.decisions[id] = d
				}
			}
			if d, ok := t.decisions[id]; ok && d.Bit == aba.One {
				ones++
			}
		}
		for _, id := range n.Public.Members {
			a := t.objects[id]
			if _, ok := t.decisions[id]; !ok && !a.Status().Proposed {
				if _, ready := n.ready[c][id]; ready {
					n.propose(a, aba.One)
				} else if ones >= n.Config.Quorum() {
					n.propose(a, aba.Zero)
				}
			}
		}
		if len(t.decisions) != len(n.Public.Members) {
			return
		}
		for _, id := range n.Public.Members {
			d := t.decisions[id]
			record.Decisions = append(record.Decisions, ObjectDecision{id, d.Bit})
			certs = append(certs, d.Certificate)
		}
	} else {
		for _, id := range n.Public.Members {
			record.Decisions = append(record.Decisions, ObjectDecision{id, aba.One})
		}
	}
	col := Column{Record: record, Whole: whole.Certificate, Decisions: certs}
	for _, d := range record.Decisions {
		if d.Bit == aba.One {
			o, ok := n.ready[c][d.Source]
			if !ok {
				return
			}
			col.Record.Accepted = append(col.Record.Accepted, Accepted{d.Source, o.Delivery.Hash})
			col.Objects = append(col.Objects, o)
		}
	}
	if len(col.Objects) < n.Config.Quorum() {
		n.fail(errors.New("ABA column has fewer than n-f accepted objects"))
		return
	}
	n.saveColumn(col)
}
func (n *Node) saveColumn(c Column) bool {
	if old, ok := n.columns[c.Record.Column]; ok {
		// A trusted immutable description already has complete evidence.
		// Ignore redundant encodings instead of rechecking all signatures on
		// every history response; a different description remains rejected.
		return old.Hash() == c.Hash()
	}
	if err := n.verifier.AddColumn(c); err != nil {
		n.Perf.Invalid.Add(1)
		return false
	}
	n.mu.Lock()
	// AddColumn owns one immutable copy; Export copies it for external callers.
	n.columnArchive[c.Record.Column] = n.columns[c.Record.Column]
	n.mu.Unlock()
	return true
}
func (n *Node) live(h reconHeader) bool {
	return n.state != nil && n.recon != nil && h == n.recon.header &&
		h.Epoch == n.state.Epoch && h.Previous == n.state.PreviousHash && h.Column == n.state.Column
}
func (n *Node) consume() {
	if n.recon == nil {
		record, object, err := n.verifier.recordTemplate()
		if err != nil {
			n.fail(err)
			return
		}
		h := reconHeader{record.Epoch, record.PreviousHash, record.Column, record.Source, record.ObjectHash}
		n.recon = &pendingRecon{header: h, object: object, record: record, previousRandom: n.state.PreviousRandom, shares: make(map[p2p.NodeID]crypto.PVSSDecryptedShare), verifying: make(map[p2p.NodeID]bool), candidates: make(map[p2p.NodeID]reconPacket), done: make(chan struct{})}
	}

	r := n.recon
	h := r.header
	if pending := n.earlyShares[h.Epoch]; pending != nil {
		delete(n.earlyShares, h.Epoch)
		for from, p := range pending {
			if p.Header == h {
				n.acceptShare(from, p)
			}
		}
	}
	if witness, ok := n.witnesses[h.Epoch]; ok && r.entry == nil {
		delete(n.witnesses, h.Epoch)
		if err := n.verifier.CheckEntry(witness); err == nil {
			r.entry = &witness
		} else {
			n.Perf.Invalid.Add(1)
		}
	}

	if !r.releasePending {
		r.releasePending = true
		n.workUrgent(func() {
			sh, err := n.pvss.PreReconTrusted(r.object.Transcript, n.ID)
			n.post(func() {
				if !n.live(h) {
					return
				}
				if err != nil {
					n.fail(err)
					return
				}
				n.recon.released = true
				n.recon.shares[n.ID] = sh
				n.send("RECON", "", reconPacket{h, sh})
				n.finishEpoch()
			})
		})
	}
	if r.entry == nil && !r.reconstructing && len(r.shares) >= n.Config.Threshold() {
		r.reconstructing = true
		var holders []p2p.NodeID
		for id := range r.shares {
			holders = append(holders, id)
		}
		sort.Slice(holders, func(i, j int) bool { return holders[i] < holders[j] })
		shares := make([]crypto.PVSSDecryptedShare, n.Config.Threshold())
		for i := range shares {
			shares[i] = r.shares[holders[i]]
		}
		n.workUrgent(func() {
			z, err := n.pvss.ReconTrusted(r.object.Transcript, shares, n.Config.Threshold())
			n.Perf.ReconCount.Add(1)
			n.post(func() {
				if !n.live(h) {
					return
				}
				if err != nil {
					n.fail(err)
					return
				}
				record := r.record
				record.Random = randomValue(h.Epoch, r.previousRandom, z)
				e := Entry{Record: record, Shares: shares}
				n.recon.entry = &e
				n.finishEpoch()
			})
		})
	}
	if r.entry != nil {
		n.finishEpoch()
	}
}
func (n *Node) acceptShare(from p2p.NodeID, p reconPacket) {
	if !n.live(p.Header) || p.Share.Holder != from || n.Public.Signing[string(from)] == nil || n.recon == nil {
		return
	}
	r := n.recon
	if _, ok := r.shares[from]; ok || r.verifying[from] {
		return
	}
	if r.candidates == nil {
		r.candidates = make(map[p2p.NodeID]reconPacket)
	}
	if _, queued := r.candidates[from]; !queued {
		r.candidates[from] = p
	}
	n.checkShares()
}

// Keep surplus distinct shares available, but schedule only enough checks to
// reach t valid shares. Invalid checks free a slot for another candidate.
func (n *Node) checkShares() {
	r := n.recon
	if r == nil || r.entry != nil {
		return
	}
	for from, p := range r.candidates {
		if len(r.shares)+len(r.verifying) >= n.Config.Threshold() {
			break
		}
		delete(r.candidates, from)
		r.verifying[from] = true
		from, p := from, p
		n.workUrgent(func() {
			select {
			case <-r.done:
				return
			default:
			}
			ok := n.pvss.VerifyShare(r.object.Transcript, p.Share)
			n.post(func() {
				if !n.live(p.Header) {
					return
				}
				delete(r.verifying, from)
				if ok {
					r.shares[from] = p.Share
				} else {
					n.Perf.Invalid.Add(1)
				}
				n.checkShares()
			})
		})
	}
}

// finishEpoch is the sole installation handler for native reconstruction and
// recovered witnesses. Own RECON must already have been emitted for this state.
func (n *Node) finishEpoch() {
	r := n.recon
	if r == nil || r.entry == nil || !r.released || !n.live(r.header) {
		return
	}
	e := *r.entry
	if err := n.state.install(n.Public, e.Record, n.columns); err != nil {
		n.fail(err)
		return
	}
	n.mu.Lock()
	n.history[e.Record.Epoch] = clone(e)
	close(n.notify)
	n.notify = make(chan struct{})
	n.mu.Unlock()
	if r.done != nil {
		close(r.done)
	}
	n.recon = nil
	delete(n.earlyShares, e.Record.Epoch)
	delete(n.witnesses, e.Record.Epoch)
	n.lastInstall = time.Now()
}
func envelopeStatement(context, typ string, from p2p.NodeID, body json.RawMessage) []byte {
	return encode(struct {
		Domain, Context, Type string
		From                  p2p.NodeID
		Body                  json.RawMessage
	}{Protocol + "/packet", context, typ, from, body})
}
func (n *Node) send(typ string, to p2p.NodeID, body any) {
	raw := json.RawMessage(encode(body))
	p := envelope{Context: n.Public.Context, Body: raw}
	if !p2p.AuthenticatedDelivery(n.Transport) {
		p.Signature = hex.EncodeToString(ed25519.Sign(n.private, envelopeStatement(n.Public.Context, typ, n.ID, raw)))
	}
	m, _ := p2p.NewMessage(Protocol, typ, n.Public.Context, n.ID, to, p)
	n.emit([]p2p.Message{m})
}
func (n *Node) handleBeacon(m p2p.Message) {
	p, err := p2p.DecodePayload[envelope](m)
	pub := n.Public.Signing[string(m.From)]
	sig, err2 := hex.DecodeString(p.Signature)
	if err != nil || err2 != nil || len(pub) != 32 || p.Context != n.Public.Context || m.Instance != n.Public.Context || !(p.Signature == "" && m.Authenticated() || p.Signature != "" && n.checks.Ed25519(pub, envelopeStatement(p.Context, m.Type, m.From, p.Body), sig)) {
		n.Perf.Invalid.Add(1)
		return
	}
	switch m.Type {
	case "RECON":
		var x reconPacket
		if json.Unmarshal(p.Body, &x) == nil {
			if n.state != nil && n.recon == nil && x.Header.Epoch > n.state.Epoch && n.pullEpoch != n.state.Epoch {
				// Missing column prerequisites can benefit from immediate pull.
				// A native reconstruction already in progress normally just needs
				// its queued share checks; do not pull full history on every small
				// scheduling skew. Periodic recovery still covers a stalled epoch.
				n.pullEpoch = n.state.Epoch
				n.requestHistory(m.From, n.state.Epoch)
			}
			if n.recon != nil && n.live(x.Header) {
				n.acceptShare(m.From, x)
			} else if n.bufferEpoch(x.Header.Epoch) {
				if n.earlyShares[x.Header.Epoch] == nil {
					n.earlyShares[x.Header.Epoch] = make(map[p2p.NodeID]reconPacket)
				}
				if _, ok := n.earlyShares[x.Header.Epoch][m.From]; !ok {
					n.earlyShares[x.Header.Epoch][m.From] = x
				}
			}
		}
	case "HISTORY":
		var x request
		if json.Unmarshal(p.Body, &x) != nil || x.Epoch == 0 {
			return
		}
		resp := response{}
		needed := make(map[uint64]bool)
		for e := x.Epoch; e < x.Epoch+uint64(n.Config.HistoryBatch); e++ {
			n.mu.RLock()
			b, ok := n.history[e]
			n.mu.RUnlock()
			if !ok {
				break
			}
			resp.Entries = append(resp.Entries, b)
			needed[b.Record.Column] = true
			needed[b.Record.Column+1] = true
		}
		if n.state == nil || x.Epoch == 1 {
			needed[1] = true
		}
		var cols []uint64
		for c := range needed {
			cols = append(cols, c)
		}
		sort.Slice(cols, func(i, j int) bool { return cols[i] < cols[j] })
		for _, c := range cols {
			if col, ok := n.columns[c]; ok && c > x.HaveThroughColumn {
				resp.Columns = append(resp.Columns, col)
			}
		}
		if len(resp.Entries) > 0 || len(resp.Columns) > 0 {
			n.send("REPLY", m.From, resp)
		}
	case "SYNC":
		var x request
		if json.Unmarshal(p.Body, &x) != nil {
			return
		}
		archive := n.coreArchive[x.Instance]
		if archive == nil {
			return
		}
		resp := response{}
		for offset := uint64(0); offset <= n.Config.ABAFutureRounds; offset++ {
			if x.Round+offset < x.Round {
				break
			}
			resp.Core = append(resp.Core, archive[x.Round+offset]...)
		}
		if len(resp.Core) > 0 {
			n.send("REPLAY", m.From, resp)
		}
		// The requester independently pulls certificates during recovery.
		// Do not turn each peer's SYNC into another membership-wide query:
		// unresolved instances would amplify periodic recovery traffic.
	case "REPLAY":
		var x response
		if json.Unmarshal(p.Body, &x) != nil || len(x.Core) > int(n.Config.ABAFutureRounds+1)*5 {
			return
		}
		for _, core := range x.Core {
			if core.Type != aba.PRE && core.Type != aba.VOTE && core.Type != aba.MAIN && core.Type != aba.FINAL {
				continue
			}
			if core.From != m.From {
				continue
			}
			if trusted, ok := m.AuthenticateReplay(core); ok {
				core = trusted
			}
			n.routeABA(core)
		}
	case "REPLY":
		var x response
		if json.Unmarshal(p.Body, &x) != nil || len(x.Entries) > n.Config.HistoryBatch || len(x.Columns) > n.Config.HistoryBatch+2 {
			return
		}
		for _, c := range x.Columns {
			if c.Record.Column <= n.currentColumn()+uint64(n.Config.HistoryBatch)+1 {
				n.saveColumn(c)
			}
		}
		if n.state == nil {
			n.initializeGenesis()
		}
		for _, e := range x.Entries {
			if n.state == nil {
				continue
			}
			if n.bufferEpoch(e.Record.Epoch) {
				if _, ok := n.witnesses[e.Record.Epoch]; !ok {
					n.witnesses[e.Record.Epoch] = clone(e)
				}
			}
		}
	}
}
func (n *Node) recover() {
	n.recoverAt(time.Now())
}

func (n *Node) recoverAt(now time.Time) {
	base := time.Duration(n.Config.RecoveryMS) * time.Millisecond
	if now.Sub(n.lastInstall) < base {
		return
	}
	epoch := uint64(1)
	if n.state != nil {
		epoch = n.state.Epoch
	}
	if n.recoveryEpoch != epoch {
		n.recoveryEpoch, n.recoveryDelay, n.nextRecovery = epoch, base, time.Time{}
	}
	if now.Before(n.nextRecovery) {
		return
	}
	// Polling must not crowd out native ABA traffic when crypto or network
	// service is slow. Retry forever with bounded exponential backoff, reset
	// by output progress; no timer supplies a decision or skips a protocol step.
	n.nextRecovery = now.Add(n.recoveryDelay)
	limit := 4 * time.Second
	if base > limit {
		limit = base
	}
	if n.recoveryDelay < limit {
		if n.recoveryDelay >= limit/2 {
			n.recoveryDelay = limit
		} else {
			n.recoveryDelay *= 2
		}
	}
	n.Perf.Recoveries.Add(1)
	// Rotate peers instead of soliciting n copies of the same history. Every
	// member is eventually tried; all returned evidence is still verified.
	var peer p2p.NodeID
	for range n.Public.Members {
		index := (uint64(n.Config.ClusterIndex[n.ID]) + 1 + n.historyPeer) % uint64(len(n.Public.Members))
		n.historyPeer++
		if peer = n.Public.Members[index]; peer != n.ID {
			n.requestHistory(peer, epoch)
			break
		}
	}
	for c := n.currentColumn(); c <= n.currentColumn()+1; c++ {
		if _, ok := n.columns[c]; ok {
			continue
		}
		t := n.ensureColumn(c)
		active := map[string]*aba.Instance{columnID(c): t.whole}
		for source, a := range t.objects {
			active[objectID(c, source)] = a
		}
		for instance, a := range active {
			if peer == n.ID {
				continue
			}
			n.emit(a.RequestCertificateFrom(peer))
			status := a.Status()
			if status.Proposed && !status.Stopped {
				n.send("SYNC", peer, request{Instance: instance, Round: status.Round})
			}
		}
	}

}

func (n *Node) requestHistory(peer p2p.NodeID, epoch uint64) {
	through := uint64(0)
	for {
		if _, ok := n.columns[through+1]; !ok {
			break
		}
		through++
	}
	n.send("HISTORY", peer, request{Epoch: epoch, HaveThroughColumn: through})
}

func (n *Node) bufferEpoch(e uint64) bool {
	current := uint64(1)
	if n.state != nil {
		current = n.state.Epoch
	}
	return e >= current && e-current <= uint64(n.Config.ProductionWindow*len(n.Public.Members))
}

// Begin releases the consumer after deployment prefill; it changes no consensus rule.
func (n *Node) Begin() { n.post(func() { n.consuming = true }) }
