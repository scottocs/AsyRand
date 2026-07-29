package tyche

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

func TestBeaconChurnCrashAndJoin10000Epochs(t *testing.T) {
	if os.Getenv("TYCHE_CHURN_TEST") != "1" {
		t.Skip("set TYCHE_CHURN_TEST=1 to run the 8-node/f=2 crash-and-join churn test")
	}
	epochs := envInt("TYCHE_CHURN_EPOCHS", 10000)
	reportEvery := envInt("TYCHE_CHURN_REPORT_EVERY", 1000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(epochs)*2*time.Second)
	defer cancel()

	cluster := newChurnCluster(t, ctx, 8, 2)
	failures := map[int]p2p.NodeID{
		max(2, epochs/4): "node6",
		max(3, epochs/2): "node7",
	}
	joins := map[int]p2p.NodeID{
		max(2, epochs/4) + 1: "node8",
		max(3, epochs/2) + 1: "node9",
	}

	start := time.Now()
	for epoch := 1; epoch <= epochs; epoch++ {
		if failed := failures[epoch]; failed != "" {
			t.Logf("epoch=%d event=delete node=%s active_before=%v members_before=%v", epoch, failed, cluster.activeIDs(), cluster.members())
			cluster.crashAndRemove(t, failed)
			t.Logf("epoch=%d event=deleted node=%s active_after=%v members_after=%v", epoch, failed, cluster.activeIDs(), cluster.members())
		}
		if joiner := joins[epoch]; joiner != "" {
			t.Logf("epoch=%d event=joining_proposal node=%s active_before=%v members_before=%v", epoch, joiner, cluster.activeIDs(), cluster.members())
			if cluster.join(t, ctx, joiner) {
				t.Logf("epoch=%d event=join_admitted node=%s active_after=%v members_after=%v", epoch, joiner, cluster.activeIDs(), cluster.members())
			} else {
				joins[epoch+1] = joiner
				t.Logf("epoch=%d event=join_deferred node=%s reason=pending_removal", epoch, joiner)
			}
		}
		cluster.reconcilePendingJoins(t, ctx, uint64(epoch))
		cluster.runEpoch(t, ctx, uint64(epoch), 10*time.Second)
		cluster.reconcileProtocolRemovals(t, uint64(epoch))
		if reportEvery > 0 && epoch%reportEvery == 0 {
			t.Logf("completed %d/%d churn epochs in %s active=%v members=%v", epoch, epochs, time.Since(start), cluster.activeIDs(), cluster.members())
		}
	}
}

func TestBeaconRandomChurn1000Epochs(t *testing.T) {
	if os.Getenv("TYCHE_RANDOM_CHURN_TEST") != "1" {
		t.Skip("set TYCHE_RANDOM_CHURN_TEST=1 to run the random crash-and-join churn test")
	}
	epochs := envInt("TYCHE_CHURN_EPOCHS", 1000)
	reportEvery := envInt("TYCHE_CHURN_REPORT_EVERY", 100)
	eventEvery := envInt("TYCHE_CHURN_EVENT_EVERY", 10)
	epochTimeout := time.Duration(envInt("TYCHE_CHURN_EPOCH_TIMEOUT_MS", 10000)) * time.Millisecond
	minN := envInt("TYCHE_CHURN_MIN_N", 4)
	maxN := envInt("TYCHE_CHURN_MAX_N", 13)
	seed := int64(envInt("TYCHE_CHURN_SEED", 20260521))
	rng := rand.New(rand.NewSource(seed))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(epochs)*2*time.Second)
	defer cancel()

	cluster := newChurnCluster(t, ctx, 8, 2)
	nextJoin := 8
	start := time.Now()
	t.Logf("random churn seed=%d epochs=%d initial_n=8 min_n=%d max_n=%d event_every=%d", seed, epochs, minN, maxN, eventEvery)
	for epoch := 1; epoch <= epochs; epoch++ {
		if eventEvery > 0 && epoch%eventEvery == 0 {
			if cluster.randomChurn(t, ctx, rng, uint64(epoch), minN, maxN, &nextJoin) {
				cluster.assertMembershipBounds(t, minN, maxN)
			}
		}
		cluster.assertMembershipBounds(t, minN, maxN)
		cluster.runEpoch(t, ctx, uint64(epoch), epochTimeout)
		cluster.reconcileProtocolRemovals(t, uint64(epoch))
		if reportEvery > 0 && epoch%reportEvery == 0 {
			t.Logf("completed %d/%d random churn epochs in %s active=%v members=%v", epoch, epochs, time.Since(start), cluster.activeIDs(), cluster.members())
		}
	}
}

func TestBeaconReconfigurationBenchmark200Epochs(t *testing.T) {
	if os.Getenv("TYCHE_RECONFIG_BENCH_TEST") != "1" {
		t.Skip("set TYCHE_RECONFIG_BENCH_TEST=1 to run the reconfiguration benchmark")
	}
	epochs := envInt("TYCHE_CHURN_EPOCHS", 200)
	initialN := envInt("TYCHE_CHURN_INITIAL_N", 8)
	totalN := envInt("TYCHE_CHURN_TOTAL_N", initialN+max(1, initialN/2))
	if totalN < initialN {
		totalN = initialN
	}
	initialF := envInt("TYCHE_CHURN_INITIAL_F", (initialN-1)/3)
	reconfigTarget := envInt("TYCHE_CHURN_RECONFIG_EVENTS", max(1, int(float64(epochs)/16.0+0.5)))
	epochTimeout := time.Duration(envInt("TYCHE_CHURN_EPOCH_TIMEOUT_MS", 10000)) * time.Millisecond
	prefill := time.Duration(envInt("TYCHE_CHURN_PREFILL_MS", 0)) * time.Millisecond
	minN := envInt("TYCHE_CHURN_MIN_N", initialN-initialF)
	maxN := envInt("TYCHE_CHURN_MAX_N", totalN)
	if maxN < initialN {
		maxN = initialN
	}
	seed := int64(envInt("TYCHE_CHURN_SEED", 20260521))

	runChurnBenchmarkCase(t, "reconfig", epochs, reconfigTarget, epochTimeout, prefill, minN, maxN, seed, initialN, totalN, initialF)
}

type churnCluster struct {
	net           *p2p.MemoryNetwork
	nodes         map[p2p.NodeID]*Node
	active        map[p2p.NodeID]bool
	stopped       map[p2p.NodeID]bool
	cancels       map[p2p.NodeID]context.CancelFunc
	pendingJoins  map[p2p.NodeID]pendingChurnJoin
	pvssEpoch     uint64
	pvss          string
	queueLen      int
	cryptoWorkers int
}

type churnResult struct {
	beacon Beacon
	err    error
}

type pendingChurnJoin struct {
	activation uint64
}

type churnBenchmarkResult struct {
	label              string
	elapsed            time.Duration
	throughputPerSec   float64
	bandwidthKBPerSec  float64
	sentMessages       uint64
	recvMessages       uint64
	sentBytes          uint64
	recvBytes          uint64
	finalN             int
	finalF             int
	reconfigurationOps int
}

func runChurnBenchmarkCase(t *testing.T, label string, epochs int, reconfigTarget int, epochTimeout time.Duration, prefill time.Duration, minN int, maxN int, seed int64, initialN int, totalN int, initialF int) churnBenchmarkResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(epochs)*2*time.Second+prefill)
	defer cancel()
	cluster := newChurnCluster(t, ctx, initialN, initialF)
	rng := rand.New(rand.NewSource(seed))
	schedule := buildChurnReconfigSchedule(rng, initialN, totalN, epochs, reconfigTarget, minN, maxN)
	before := aggregateMetrics(cluster.transports())
	beforeTypes := aggregateMessageTypeMetrics(cluster.transports())
	start := time.Now()
	if prefill > 0 {
		time.Sleep(prefill)
	}
	reconfigs := 0
	localStops := 0
	for epoch := 1; epoch <= epochs; epoch++ {
		if event, ok := schedule[epoch]; ok {
			if cluster.applyScheduledReconfiguration(t, ctx, event, uint64(epoch), minN, maxN) {
				reconfigs++
				if event.action == "stop" {
					localStops++
				}
				cluster.assertMembershipBounds(t, minN, maxN)
			}
		}
		cluster.reconcilePendingJoins(t, ctx, uint64(epoch))
		cluster.assertMembershipBounds(t, minN, maxN)
		cluster.runEpoch(t, ctx, uint64(epoch), epochTimeout)
		cluster.reconcileProtocolRemovals(t, uint64(epoch))
	}
	elapsed := time.Since(start)
	after := aggregateMetrics(cluster.transports())
	afterTypes := aggregateMessageTypeMetrics(cluster.transports())
	sentMessages := after.SentMessages - before.SentMessages
	recvMessages := after.RecvMessages - before.RecvMessages
	sentBytes := after.SentBytes - before.SentBytes
	recvBytes := after.RecvBytes - before.RecvBytes
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	result := churnBenchmarkResult{
		label:              label,
		elapsed:            elapsed,
		throughputPerSec:   float64(epochs) / seconds,
		bandwidthKBPerSec:  float64(sentBytes+recvBytes) / 1024 / seconds,
		sentMessages:       sentMessages,
		recvMessages:       recvMessages,
		sentBytes:          sentBytes,
		recvBytes:          recvBytes,
		finalN:             len(cluster.members()),
		finalF:             cluster.currentF(t),
		reconfigurationOps: reconfigs,
	}
	finalMembers := cluster.members()
	t.Logf("reconfig_final scheduled_events=%d local_stop_events=%d membership_changes=%d removed=%d completed_epochs=%d final_n=%d final_f=%d config_version=%d min_n=%d seed=%d members=%v",
		len(schedule),
		localStops,
		cluster.currentConfigVersion(t),
		initialRemovedCount(finalMembers, initialN),
		epochs,
		len(finalMembers),
		cluster.currentF(t),
		cluster.currentConfigVersion(t),
		minN,
		seed,
		finalMembers,
	)
	t.Logf("bench_result label=%s epochs=%d elapsed=%s throughput=%.4f/s bandwidth=%.2fKB/s sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB final_n=%d final_f=%d reconfig_ops=%d",
		result.label,
		epochs,
		result.elapsed,
		result.throughputPerSec,
		result.bandwidthKBPerSec,
		result.sentMessages,
		result.recvMessages,
		float64(result.sentBytes)/1024,
		float64(result.recvBytes)/1024,
		result.finalN,
		result.finalF,
		result.reconfigurationOps,
	)
	t.Logf("final metrics label=%s beacons=%d throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s final_n=%d final_f=%d reconfig_ops=%d",
		result.label,
		epochs,
		result.throughputPerSec*60,
		result.sentMessages,
		result.recvMessages,
		float64(result.sentBytes)/1024,
		float64(result.recvBytes)/1024,
		result.bandwidthKBPerSec,
		result.finalN,
		result.finalF,
		result.reconfigurationOps,
	)
	logMessageTypeMetricsDiff(t, afterTypes, beforeTypes)
	return result
}

func aggregateMessageTypeMetrics(transports []p2p.Transport) map[string]p2p.MessageTypeMetrics {
	out := make(map[string]p2p.MessageTypeMetrics)
	for _, transport := range transports {
		typed, ok := transport.(interface {
			MessageTypeMetrics() map[string]p2p.MessageTypeMetrics
		})
		if !ok {
			continue
		}
		for key, stats := range typed.MessageTypeMetrics() {
			current := out[key]
			current.SentMessages += stats.SentMessages
			current.SentBytes += stats.SentBytes
			current.RecvMessages += stats.RecvMessages
			current.RecvBytes += stats.RecvBytes
			out[key] = current
		}
	}
	return out
}

func logMessageTypeMetricsDiff(t *testing.T, current map[string]p2p.MessageTypeMetrics, before map[string]p2p.MessageTypeMetrics) {
	t.Helper()
	types := subtractChurnMessageTypeMetrics(current, before)
	if len(types) == 0 {
		return
	}
	logMessageCategoryMetrics(t, types)
	keys := make([]string, 0, len(types))
	for key := range types {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stats := types[key]
		t.Logf("message_type type=%s sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB", key, stats.SentMessages, stats.RecvMessages, float64(stats.SentBytes)/1024, float64(stats.RecvBytes)/1024)
	}
}

func subtractChurnMessageTypeMetrics(current map[string]p2p.MessageTypeMetrics, before map[string]p2p.MessageTypeMetrics) map[string]p2p.MessageTypeMetrics {
	out := make(map[string]p2p.MessageTypeMetrics, len(current))
	for key, stats := range current {
		prev := before[key]
		out[key] = p2p.MessageTypeMetrics{
			SentMessages: stats.SentMessages - prev.SentMessages,
			SentBytes:    stats.SentBytes - prev.SentBytes,
			RecvMessages: stats.RecvMessages - prev.RecvMessages,
			RecvBytes:    stats.RecvBytes - prev.RecvBytes,
		}
	}
	return out
}

func logMessageCategoryMetrics(t *testing.T, types map[string]p2p.MessageTypeMetrics) {
	t.Helper()
	categories := make(map[string]p2p.MessageTypeMetrics)
	for key, stats := range types {
		category := churnMessageCategory(key)
		current := categories[category]
		current.SentMessages += stats.SentMessages
		current.SentBytes += stats.SentBytes
		current.RecvMessages += stats.RecvMessages
		current.RecvBytes += stats.RecvBytes
		categories[category] = current
	}
	keys := make([]string, 0, len(categories))
	for key := range categories {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stats := categories[key]
		t.Logf("message_category category=%s sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB", key, stats.SentMessages, stats.RecvMessages, float64(stats.SentBytes)/1024, float64(stats.RecvBytes)/1024)
	}
}

func churnMessageCategory(key string) string {
	switch {
	case key == "rbc/VAL":
		return "producer_rbc_value"
	case strings.HasPrefix(key, "rbc/"):
		return "rbc_control"
	case key == "tyche/RECON":
		return "consumer_recon"
	case key == "tyche/RECON_ECHO":
		return "consumer_echo"
	case key == "tyche/RECON_READY":
		return "recon_ready"
	case key == "tyche/BEACON_CERT":
		return "beacon_cert"
	case strings.HasPrefix(key, "aba/"):
		return "aba"
	case strings.HasPrefix(key, "tyche/JOIN"):
		return "reconfig_join"
	case strings.HasPrefix(key, "tyche/"):
		return "tyche_other"
	default:
		return "other"
	}
}

func shouldRunReconfiguration(rng *rand.Rand, epoch int, epochs int, completed int, target int) bool {
	if target <= 0 || completed >= target || epochs <= 0 {
		return false
	}
	remainingEpochs := epochs - epoch + 1
	remainingEvents := target - completed
	if remainingEvents >= remainingEpochs {
		return true
	}
	return rng.Float64() < float64(remainingEvents)/float64(remainingEpochs)
}

type scheduledChurnReconfiguration struct {
	action string
	node   p2p.NodeID
	race   string
}

func buildChurnReconfigSchedule(rng *rand.Rand, initialN int, totalN int, epochs int, target int, minN int, maxN int) map[int]scheduledChurnReconfiguration {
	schedule := make(map[int]scheduledChurnReconfiguration)
	if target <= 0 || epochs <= 0 {
		return schedule
	}
	if target > epochs {
		target = epochs
	}
	planningEpochs := epochs - churnJoinDelay()
	if planningEpochs < 1 {
		planningEpochs = epochs
	}
	latestStopEpoch := epochs - 2*churnRemovalDelay(initialN)
	if latestStopEpoch < churnInitialQuietEpoch() {
		latestStopEpoch = churnInitialQuietEpoch()
	}
	members := make(map[p2p.NodeID]bool, initialN)
	initialIDs := make([]p2p.NodeID, 0, initialN)
	for i := 0; i < initialN; i++ {
		id := p2p.NodeID(fmt.Sprintf("node%d", i))
		members[id] = true
		initialIDs = append(initialIDs, id)
	}
	standby := make([]p2p.NodeID, 0, max(0, totalN-initialN))
	for i := initialN; i < totalN; i++ {
		standby = append(standby, p2p.NodeID(fmt.Sprintf("node%d", i)))
	}
	rng.Shuffle(len(standby), func(i, j int) { standby[i], standby[j] = standby[j], standby[i] })

	stopQuota := target / 2
	joinQuota := target - stopQuota
	nextEpoch := churnInitialQuietEpoch()
	if target >= 4 && len(standby) > 0 && stopQuota > 0 && joinQuota > 1 {
		joiner := popChurnNode(&standby)
		joinEpoch := findOpenChurnEpoch(schedule, nextEpoch, planningEpochs)
		schedule[joinEpoch] = scheduledChurnReconfiguration{action: "join", node: joiner, race: "proposal_before_remove"}
		joinQuota--

		stopEpoch := findOpenChurnEpoch(schedule, joinEpoch+max(2, churnJoinDelay()/2), planningEpochs)
		victim := randomChurnMember(rng, initialIDs, members)
		if victim != "" {
			delete(members, victim)
			schedule[stopEpoch] = scheduledChurnReconfiguration{action: "stop", node: victim, race: "remove_before_join_activation"}
			stopQuota--
			followEpoch := findOpenChurnEpoch(schedule, stopEpoch+churnRemovalDelay(initialN), planningEpochs)
			members[joiner] = true
			schedule[followEpoch] = scheduledChurnReconfiguration{action: "join", node: joiner, race: "join_after_remove"}
			joinQuota--
			nextEpoch = followEpoch + churnQuietEpochs()
		}
	}

	for len(schedule) < target && nextEpoch <= planningEpochs {
		remainingSlots := max(1, planningEpochs-nextEpoch+1)
		remainingEvents := target - len(schedule)
		stride := max(1, remainingSlots/remainingEvents)
		epoch := findOpenChurnEpoch(schedule, nextEpoch+rng.Intn(stride), planningEpochs)
		canStop := stopQuota > 0 && epoch <= latestStopEpoch && len(members) > minN
		canJoin := joinQuota > 0 && len(members) < maxN && len(standby) > 0
		if !canStop && !canJoin {
			break
		}
		action := "stop"
		if canStop && canJoin {
			if rng.Intn(stopQuota+joinQuota) >= stopQuota {
				action = "join"
			}
		} else if canJoin {
			action = "join"
		}
		switch action {
		case "stop":
			victim := randomChurnMember(rng, initialIDs, members)
			if victim == "" {
				nextEpoch = epoch + 1
				continue
			}
			delete(members, victim)
			schedule[epoch] = scheduledChurnReconfiguration{action: "stop", node: victim}
			stopQuota--
			nextEpoch = epoch + churnRemovalDelay(initialN)
		case "join":
			joiner := popChurnNode(&standby)
			if joiner == "" {
				nextEpoch = epoch + 1
				continue
			}
			members[joiner] = true
			schedule[epoch] = scheduledChurnReconfiguration{action: "join", node: joiner}
			joinQuota--
			nextEpoch = epoch + churnJoinDelay() + churnQuietEpochs()
		}
	}
	backfillAttempts := 0
	for len(schedule) < target && backfillAttempts < target*4 {
		if nextEpoch > planningEpochs {
			break
		}
		backfillAttempts++
		span := max(1, planningEpochs-churnInitialQuietEpoch()+1)
		bucket := max(1, span/target)
		epoch := churnInitialQuietEpoch() + (len(schedule)*span)/target + rng.Intn(bucket)
		if epoch < nextEpoch {
			epoch = nextEpoch
		}
		var ok bool
		epoch, ok = findOpenChurnEpochAtOrAfter(schedule, epoch, planningEpochs)
		if !ok {
			break
		}
		canStop := stopQuota > 0 && epoch <= latestStopEpoch && len(members) > minN
		canJoin := joinQuota > 0 && len(members) < maxN && len(standby) > 0
		if !canStop && !canJoin {
			break
		}
		action := "stop"
		if canStop && canJoin {
			if rng.Intn(stopQuota+joinQuota) >= stopQuota {
				action = "join"
			}
		} else if canJoin {
			action = "join"
		}
		switch action {
		case "stop":
			victim := randomChurnMember(rng, initialIDs, members)
			if victim == "" {
				continue
			}
			delete(members, victim)
			schedule[epoch] = scheduledChurnReconfiguration{action: "stop", node: victim}
			stopQuota--
			nextEpoch = epoch + churnRemovalDelay(initialN)
		case "join":
			joiner := popChurnNode(&standby)
			if joiner == "" {
				continue
			}
			members[joiner] = true
			schedule[epoch] = scheduledChurnReconfiguration{action: "join", node: joiner}
			joinQuota--
			nextEpoch = epoch + churnJoinDelay() + churnQuietEpochs()
		}
	}
	return schedule
}

func popChurnNode(ids *[]p2p.NodeID) p2p.NodeID {
	if len(*ids) == 0 {
		return ""
	}
	id := (*ids)[0]
	*ids = (*ids)[1:]
	return id
}

func randomChurnMember(rng *rand.Rand, ordered []p2p.NodeID, members map[p2p.NodeID]bool) p2p.NodeID {
	var candidates []p2p.NodeID
	for _, id := range ordered {
		if members[id] {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	return candidates[rng.Intn(len(candidates))]
}

func findOpenChurnEpoch(schedule map[int]scheduledChurnReconfiguration, epoch int, maxEpoch int) int {
	if epoch < 1 {
		epoch = 1
	}
	if epoch > maxEpoch {
		epoch = maxEpoch
	}
	for candidate := epoch; candidate <= maxEpoch; candidate++ {
		if _, ok := schedule[candidate]; !ok {
			return candidate
		}
	}
	for candidate := epoch - 1; candidate >= 1; candidate-- {
		if _, ok := schedule[candidate]; !ok {
			return candidate
		}
	}
	return epoch
}

func findOpenChurnEpochAtOrAfter(schedule map[int]scheduledChurnReconfiguration, epoch int, maxEpoch int) (int, bool) {
	if epoch < 1 {
		epoch = 1
	}
	if epoch > maxEpoch {
		epoch = maxEpoch
	}
	for candidate := epoch; candidate <= maxEpoch; candidate++ {
		if _, ok := schedule[candidate]; !ok {
			return candidate, true
		}
	}
	return 0, false
}

func churnJoinDelay() int {
	return 10
}

func churnRemovalDelay(initialN int) int {
	return max(6, initialN+4)
}

func churnQuietEpochs() int {
	return 4
}

func churnInitialQuietEpoch() int {
	return 12
}

func newChurnCluster(t *testing.T, parent context.Context, n int, f int) *churnCluster {
	t.Helper()
	ids := make([]p2p.NodeID, n)
	for i := range ids {
		ids[i] = p2p.NodeID(fmt.Sprintf("node%d", i))
	}
	pvss := os.Getenv("TYCHE_CHURN_PVSS")
	if pvss == "" {
		pvss = crypto.PVSSO1
	}
	queueLen := envInt("TYCHE_CHURN_QUEUE_LEN", 0)
	initialQueueLen := queueLen
	if initialQueueLen <= 0 {
		initialQueueLen = n + 64
	}
	cryptoWorkers := envInt("TYCHE_CHURN_MAX_POOL", 0)
	pp, keys, err := crypto.SetupPVSS(pvss, "churn-config-0", f+1, ids)
	if err != nil {
		t.Fatal(err)
	}
	c := &churnCluster{
		net:           p2p.NewMemoryNetwork(),
		nodes:         make(map[p2p.NodeID]*Node, n),
		active:        make(map[p2p.NodeID]bool, n),
		stopped:       make(map[p2p.NodeID]bool, n),
		cancels:       make(map[p2p.NodeID]context.CancelFunc, n),
		pendingJoins:  make(map[p2p.NodeID]pendingChurnJoin),
		pvss:          pvss,
		queueLen:      queueLen,
		cryptoWorkers: cryptoWorkers,
	}
	for _, id := range ids {
		scheme, err := crypto.NewPVSSScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{ID: id, Members: ids, F: f, QueueLen: initialQueueLen, PVSS: scheme, PVSSBackend: pvss, CryptoWorkers: cryptoWorkers, Transport: c.net.NewTransport(id, 32768), InsecureDeterministicIdentity: true})
		if err != nil {
			t.Fatal(err)
		}
		nodeCtx, cancel := context.WithCancel(parent)
		node.Start(nodeCtx)
		c.nodes[id] = node
		c.active[id] = true
		c.cancels[id] = cancel
	}
	return c
}

func (c *churnCluster) crashAndRemove(t *testing.T, id p2p.NodeID) {
	t.Helper()
	if !c.active[id] {
		return
	}
	c.active[id] = false
	c.stopped[id] = true
	c.cancels[id]()
	if err := c.nodes[id].Transport.Close(); err != nil {
		t.Fatal(err)
	}
}

func (c *churnCluster) reconcileProtocolRemovals(t *testing.T, epoch uint64) {
	t.Helper()
	for _, id := range c.stoppedActiveIDs() {
		if !c.protocolRemovedByAnyActiveNode(id) {
			continue
		}
		beforeActive := c.activeIDs()
		c.closeProtocolRemovedNode(t, id)
		members := c.members()
		t.Logf("epoch=%d event=aba_deleted node=%s n_after=%d f_after=%d stopped=%v active_before=%v members_after=%v", epoch, id, len(members), c.currentF(t), c.stoppedActiveIDs(), beforeActive, members)
		c.active[id] = false
		delete(c.stopped, id)
		if cancel := c.cancels[id]; cancel != nil {
			cancel()
		}
		if node := c.nodes[id]; node != nil {
			if err := node.Transport.Close(); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("epoch=%d event=aba_delete_closed node=%s active_after=%v members_after=%v", epoch, id, c.activeIDs(), members)
	}
}

func (c *churnCluster) protocolRemovedByAnyActiveNode(id p2p.NodeID) bool {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		removed := !contains(node.State.Members, id)
		node.mu.Unlock()
		if removed {
			return true
		}
	}
	return false
}

func (c *churnCluster) closeProtocolRemovedNode(t *testing.T, id p2p.NodeID) {
	t.Helper()
	if c.protocolRemovedReference(id) == nil {
		t.Fatalf("no certified removal state for %s", id)
	}
}

func (c *churnCluster) protocolRemovedReference(id p2p.NodeID) *Node {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		removed := !contains(node.State.Members, id)
		node.mu.Unlock()
		if removed {
			return node
		}
	}
	return nil
}

func (c *churnCluster) randomChurn(t *testing.T, parent context.Context, rng *rand.Rand, epoch uint64, minN int, maxN int, nextJoin *int) bool {
	t.Helper()
	n := len(c.members())
	pendingStop := len(c.stoppedActiveIDs()) > 0
	pendingJoin := len(c.pendingJoins) > 0
	canDelete := n > minN && !pendingStop
	canJoin := n < maxN && !pendingStop && !pendingJoin
	if !canDelete && !canJoin {
		return false
	}
	deleteNode := canDelete && (!canJoin || rng.Intn(2) == 0)
	if deleteNode {
		ids := c.producingActiveIDs()
		victim := ids[rng.Intn(len(ids))]
		beforeMembers := c.members()
		beforeF := c.currentF(t)
		t.Logf("epoch=%d event=stop_produce node=%s n_before=%d f_before=%d active_before=%v members_before=%v", epoch, victim, len(beforeMembers), beforeF, c.activeIDs(), beforeMembers)
		c.stopProducer(victim)
		afterMembers := c.members()
		t.Logf("epoch=%d event=stopped_produce node=%s n_after=%d f_after=%d stopped=%v active_after=%v members_after=%v", epoch, victim, len(afterMembers), c.currentF(t), c.stoppedActiveIDs(), c.activeIDs(), afterMembers)
		return true
	}
	joiner := p2p.NodeID(fmt.Sprintf("node%d", *nextJoin))
	(*nextJoin)++
	beforeMembers := c.members()
	beforeF := c.currentF(t)
	t.Logf("epoch=%d event=joining_proposal node=%s n_before=%d f_before=%d active_before=%v members_before=%v", epoch, joiner, len(beforeMembers), beforeF, c.activeIDs(), beforeMembers)
	joined := c.join(t, parent, joiner)
	afterMembers := c.members()
	if !joined {
		t.Logf("epoch=%d event=join_stale node=%s n_after=%d f_after=%d active_after=%v members_after=%v", epoch, joiner, len(afterMembers), c.currentF(t), c.activeIDs(), afterMembers)
		return true
	}
	return true
}

func (c *churnCluster) applyScheduledReconfiguration(t *testing.T, parent context.Context, event scheduledChurnReconfiguration, epoch uint64, minN int, maxN int) bool {
	t.Helper()
	switch event.action {
	case "stop":
		if len(c.stoppedActiveIDs()) > 0 || len(c.members()) <= minN {
			t.Logf("epoch=%d event=stop_deferred node=%s reason=pending_or_min_n stopped=%v active=%v members=%v race=%s", epoch, event.node, c.stoppedActiveIDs(), c.activeIDs(), c.members(), event.race)
			return false
		}
		victim := event.node
		if event.race == "remove_before_join_activation" {
			source, _ := nextSourceSeq(c.reference(t))
			if source != "" {
				victim = source
			}
		}
		if !c.active[victim] || c.stopped[victim] {
			t.Logf("epoch=%d event=stop_deferred node=%s race=%s active=%v members=%v", epoch, victim, event.race, c.activeIDs(), c.members())
			return false
		}
		beforeMembers := c.members()
		beforeF := c.currentF(t)
		t.Logf("epoch=%d event=stop_produce node=%s n_before=%d f_before=%d active_before=%v members_before=%v race=%s", epoch, victim, len(beforeMembers), beforeF, c.activeIDs(), beforeMembers, event.race)
		c.stopProducer(victim)
		afterMembers := c.members()
		t.Logf("epoch=%d event=stopped_produce node=%s n_after=%d f_after=%d stopped=%v active_after=%v members_after=%v race=%s", epoch, victim, len(afterMembers), c.currentF(t), c.stoppedActiveIDs(), c.activeIDs(), afterMembers, event.race)
		return true
	case "join":
		if len(c.stoppedActiveIDs()) > 0 || len(c.pendingJoins) > 0 || len(c.members()) >= maxN {
			t.Logf("epoch=%d event=join_deferred node=%s reason=pending_or_max_n stopped=%v pending_joins=%d active=%v members=%v race=%s", epoch, event.node, c.stoppedActiveIDs(), len(c.pendingJoins), c.activeIDs(), c.members(), event.race)
			return false
		}
		if contains(c.members(), event.node) {
			t.Logf("epoch=%d event=join_stale node=%s reason=already_member active=%v members=%v race=%s", epoch, event.node, c.activeIDs(), c.members(), event.race)
			return false
		}
		beforeMembers := c.members()
		beforeF := c.currentF(t)
		t.Logf("epoch=%d event=joining_proposal node=%s n_before=%d f_before=%d active_before=%v members_before=%v race=%s", epoch, event.node, len(beforeMembers), beforeF, c.activeIDs(), beforeMembers, event.race)
		joined := c.join(t, parent, event.node)
		afterMembers := c.members()
		if !joined {
			t.Logf("epoch=%d event=join_stale node=%s n_after=%d f_after=%d active_after=%v members_after=%v race=%s", epoch, event.node, len(afterMembers), c.currentF(t), c.activeIDs(), afterMembers, event.race)
		}
		return true
	default:
		return false
	}
}

func (c *churnCluster) stopProducer(id p2p.NodeID) {
	if c.active[id] {
		c.stopped[id] = true
		c.nodes[id].SetProducing(false)
	}
}

func (c *churnCluster) assertMembershipBounds(t *testing.T, minN int, maxN int) {
	t.Helper()
	refMembers := c.members()
	n := len(refMembers)
	if n < minN || n > maxN {
		t.Fatalf("membership size out of bounds: n=%d min=%d max=%d members=%v active=%v", n, minN, maxN, refMembers, c.activeIDs())
	}
	f := c.currentF(t)
	if f >= n {
		t.Fatalf("invalid failure threshold: f=%d n=%d members=%v", f, n, refMembers)
	}
	if 3*f+1 > n {
		t.Fatalf("invalid BFT threshold: f=%d n=%d members=%v", f, n, refMembers)
	}
	active := c.activeIDs()
	if len(active) != n {
		t.Fatalf("active/member mismatch: active=%v members=%v", active, refMembers)
	}
	if !sameNodeIDs(active, refMembers) {
		t.Fatalf("active/member mismatch: active=%v members=%v", active, refMembers)
	}
	refVersion := c.currentConfigVersion(t)
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		nodeMembers := append([]p2p.NodeID(nil), node.State.Members...)
		nodeF := node.State.F
		nodeVersion := node.State.ConfigVersion
		node.mu.Unlock()
		if !sameNodeIDs(refMembers, nodeMembers) || nodeF != f {
			t.Fatalf("membership mismatch on %s: ref_members=%v ref_f=%d node_members=%v node_f=%d", node.ID, refMembers, f, nodeMembers, nodeF)
		}
		if nodeVersion != refVersion {
			t.Fatalf("config version mismatch on %s: ref=%d got=%d", node.ID, refVersion, nodeVersion)
		}
	}
}

func (c *churnCluster) currentF(t *testing.T) int {
	t.Helper()
	ref := c.reference(t)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.F
}

func (c *churnCluster) currentConfigVersion(t *testing.T) uint64 {
	t.Helper()
	ref := c.reference(t)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.ConfigVersion
}

func sameNodeIDs(a []p2p.NodeID, b []p2p.NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]p2p.NodeID(nil), a...)
	bb := append([]p2p.NodeID(nil), b...)
	sort.Slice(aa, func(i, j int) bool { return aa[i] < aa[j] })
	sort.Slice(bb, func(i, j int) bool { return bb[i] < bb[j] })
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func initialRemovedCount(members []p2p.NodeID, initialN int) int {
	present := make(map[int]bool, len(members))
	for _, id := range members {
		raw := strings.TrimPrefix(string(id), "node")
		if raw == string(id) {
			continue
		}
		index, err := strconv.Atoi(raw)
		if err == nil {
			present[index] = true
		}
	}
	removed := 0
	for i := 0; i < initialN; i++ {
		if !present[i] {
			removed++
		}
	}
	return removed
}

func (c *churnCluster) join(t *testing.T, parent context.Context, joiner p2p.NodeID) bool {
	t.Helper()
	ref := c.reference(t)
	currentMembers := c.members()
	for _, member := range currentMembers {
		if c.stopped[member] {
			return false
		}
	}
	targetMembers := append(append([]p2p.NodeID(nil), currentMembers...), joiner)
	sort.Slice(targetMembers, func(i, j int) bool { return targetMembers[i] < targetMembers[j] })
	checkpoint := ref.Checkpoint()
	ref.mu.Lock()
	version := ref.State.ConfigVersion
	contextEpoch := ref.State.Epoch
	ref.mu.Unlock()
	targetF := (len(targetMembers) - 1) / 3

	c.pvssEpoch++
	pp, keys, err := crypto.SetupPVSS(c.pvss, fmt.Sprintf("churn-config-%d", c.pvssEpoch), targetF+1, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewPVSSScheme(joiner, keys[joiner].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	commitment, _, err := joinerScheme.Share(joiner, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	identitySeed := crypto.DomainHash("Tyche/InsecureTestIdentity/v1", []byte(joiner))
	identity, err := crypto.IdentityKeyPairFromSeed(identitySeed[:32])
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   version,
		ParentHash:      HashCertifiedState(checkpoint.State),
		Joiner:          joiner,
		PublicKey:       hex.EncodeToString(identity.Public),
		CandidateParams: pp,
		Object:          Object{ConfigVersion: version + 1, Producer: joiner, Seq: 1, Commitment: commitment},
		Checkpoint:      checkpoint,
	}
	req, err = SignLearnerReady(req, identity.Private)
	if err != nil {
		t.Fatal(err)
	}
	ref.mu.Lock()
	currentSetup := ref.ConfigurationSetups[version]
	currentConfiguration := ref.Configurations[version]
	historical := make([]Configuration, 0, len(ref.Configurations))
	for _, configuration := range ref.Configurations {
		historical = append(historical, configuration)
	}
	ref.mu.Unlock()
	observerPrivate := crypto.KeyPairFromSeed(crypto.DomainHash("Tyche/ChurnLearnerPVSS/v1", []byte(joiner))).Private
	observerScheme, err := crypto.NewPVSSScheme(joiner, observerPrivate, currentSetup.Params)
	if err != nil {
		t.Fatal(err)
	}
	identityKeys := identityKeysForMembers(currentConfiguration, currentMembers)
	identityKeys[joiner] = identity.Public
	learner, err := NewNode(Config{
		ID: joiner, Members: currentMembers, Learner: true, F: currentConfiguration.F,
		ConfigVersion: version, QueueLen: c.queueLen, PVSS: observerScheme,
		PVSSBackend: c.pvss, CryptoWorkers: c.cryptoWorkers,
		Transport:       c.net.NewTransport(joiner, 32768),
		IdentityPrivate: identity.Private, IdentityPublicKeys: identityKeys,
		BootstrapCheckpoint: &checkpoint, HistoricalConfigurations: historical,
	})
	if err != nil {
		t.Fatal(err)
	}
	learner.RegisterPVSSKey(pp.Epoch(), keys[joiner].Private)
	learnerCtx, learnerCancel := context.WithCancel(parent)
	learner.Start(learnerCtx)
	c.nodes[joiner] = learner
	c.active[joiner] = false
	c.cancels[joiner] = learnerCancel
	if err := learner.HandleJoinRequest(parent, req); err != nil {
		t.Fatal(err)
	}
	for _, node := range c.activeNodes() {
		node.RegisterPVSSKey(pp.Epoch(), keys[node.ID].Private)
	}
	if err := ref.ProposeJoin(parent, req); err != nil {
		t.Fatal(err)
	}
	c.pendingJoins[joiner] = pendingChurnJoin{activation: contextEpoch + 1}
	return true
}

func (c *churnCluster) reconcilePendingJoins(t *testing.T, parent context.Context, epoch uint64) {
	t.Helper()
	for id, pending := range c.pendingJoins {
		if epoch < pending.activation {
			continue
		}
		learner := c.nodes[id]
		if learner == nil {
			t.Fatalf("missing running learner %s", id)
		}
		checkpoint := c.reference(t).Checkpoint()
		if checkpoint.State.JReady == nil || checkpoint.State.JReady.Joiner != id {
			continue
		}
		if err := learner.InstallCheckpoint(checkpoint); err != nil {
			t.Fatal(err)
		}
		active := c.activeNodes()
		results := make(chan error, len(active))
		for _, node := range active {
			go func(node *Node) {
				results <- node.activatePendingJoins(parent, epoch)
			}(node)
		}
		for range active {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		if !contains(c.members(), id) {
			continue
		}
		waitUntil(t, parent, func() bool {
			learner.mu.Lock()
			defer learner.mu.Unlock()
			return contains(learner.Certified.Members, id) && learner.RBC != nil && learner.ABA != nil
		})
		learner.SetProducing(true)
		c.active[id] = true
		delete(c.pendingJoins, id)
		t.Logf("epoch=%d event=joined node=%s active_after=%v members_after=%v", epoch, id, c.activeIDs(), c.members())
	}
}

func (c *churnCluster) runEpoch(t *testing.T, parent context.Context, epoch uint64, timeout time.Duration) {
	t.Helper()
	c.refillCandidateLists()
	source, seq := nextSourceSeq(c.reference(t))
	removingStoppedSource := c.stopped[source] && c.isMarkedForRemovalAt(source, seq)
	sourceNode := c.nodes[source]
	if sourceNode == nil || (!c.active[source] && !c.stopped[source]) {
		t.Fatalf("selected inactive source %s at epoch %d active=%v members=%v", source, epoch, c.activeIDs(), c.members())
	}
	c.ensureStored(t, parent, sourceNode, source, seq, epoch, timeout)
	c.waitStoredCurrent(t, parent, source, seq)
	if !c.stopped[source] {
		c.ensureStored(t, parent, sourceNode, source, seq+1, epoch, timeout)
		c.waitStoredCurrent(t, parent, source, seq+1)
	}

	epochCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	active := c.activeNodes()
	required := active
	if removingStoppedSource {
		required = make([]*Node, 0, len(active)-1)
		for _, node := range active {
			if node.ID != source {
				required = append(required, node)
			}
		}
	}
	results := make(chan churnResult, len(required))
	for _, node := range required {
		go func(node *Node) {
			beacon, err := node.RunEpochAt(epochCtx, epoch)
			results <- churnResult{beacon: beacon, err: err}
		}(node)
	}
	var first Beacon
	received := 0
	for received < len(required) {
		select {
		case res := <-results:
			if res.err != nil {
				t.Fatalf("epoch %d failed: %v\n%s", epoch, res.err, dumpNodes(active))
			}
			if received == 0 {
				first = res.beacon
				received++
				continue
			}
			if !bytes.Equal(first.Random, res.beacon.Random) || first.Source != res.beacon.Source || first.Seq != res.beacon.Seq {
				t.Fatalf("epoch %d beacon mismatch: first=%+v got=%+v", epoch, first, res.beacon)
			}
			received++
		case <-time.After(10 * time.Millisecond):
			if removingStoppedSource && c.protocolRemovedByAnyActiveNode(source) {
				return
			}
		case <-epochCtx.Done():
			t.Fatalf("epoch %d timed out\n%s", epoch, dumpNodes(active))
		}
	}
}

func (c *churnCluster) isMarkedForRemoval(id p2p.NodeID) bool {
	ref := c.reference(nil)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.RmMark[id] != -1
}

func (c *churnCluster) isMarkedForRemovalAt(id p2p.NodeID, seq uint64) bool {
	ref := c.reference(nil)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.RmMark[id] != -1 && uint64(ref.State.RmMark[id]) == seq
}

func (c *churnCluster) refillCandidateLists() {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		if len(node.State.SCL) == 0 {
			node.refillSCLLocked()
		}
		node.mu.Unlock()
	}
}

func (c *churnCluster) ensureStored(t *testing.T, ctx context.Context, producer *Node, source p2p.NodeID, seq uint64, epoch uint64, timeout time.Duration) {
	t.Helper()
	if c.allActiveStored(source, seq) {
		return
	}
	if c.copyStoredObjectToMissing(source, seq) && c.allActiveStored(source, seq) {
		return
	}
	storeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	producer.mu.Lock()
	version := producer.State.ConfigVersion
	if producer.State.ProducerSeq < seq {
		producer.State.ProducerSeq = seq
	}
	producer.mu.Unlock()
	obj, err := producer.produceSeq(storeCtx, seq, version)
	if err != nil {
		t.Fatalf("produce source=%s seq=%d epoch=%d: %v", source, seq, epoch, err)
	}
	if err := producer.storeObject(obj); err != nil {
		t.Logf("store produced object source=%s seq=%d epoch=%d on producer=%s failed: %v", source, seq, epoch, producer.ID, err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.copyStoredObjectToMissing(source, seq) && c.allActiveStored(source, seq) {
			return
		}
		select {
		case <-ticker.C:
		case <-storeCtx.Done():
			t.Fatalf("object source=%s seq=%d epoch=%d was not stored on all active nodes\n%s", source, seq, epoch, c.dumpObjectState(source, seq))
		}
	}
}

func (c *churnCluster) dumpObjectState(source p2p.NodeID, seq uint64) string {
	out := ""
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		q := node.State.ComQ[source]
		obj, ok := q[seq]
		version := node.State.ConfigVersion
		consumed := node.State.Seqs[source]
		members := append([]p2p.NodeID(nil), node.State.Members...)
		node.mu.Unlock()
		if ok {
			out += fmt.Sprintf("node=%s version=%d consumed=%d has=true obj_version=%d members=%v\n", node.ID, version, consumed, obj.ConfigVersion, members)
		} else {
			out += fmt.Sprintf("node=%s version=%d consumed=%d has=false queue_nil=%t members=%v\n", node.ID, version, consumed, q == nil, members)
		}
	}
	return out
}

func (c *churnCluster) copyStoredObjectToMissing(source p2p.NodeID, seq uint64) bool {
	var obj Object
	found := false
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		candidate, ok := node.State.ComQ[source][seq]
		version := node.State.ConfigVersion
		node.mu.Unlock()
		if ok && candidate.ConfigVersion == version {
			obj = candidate
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		if node.State.ComQ[source] == nil {
			node.State.ComQ[source] = make(map[uint64]Object)
		}
		existing, ok := node.State.ComQ[source][seq]
		if (!ok || existing.ConfigVersion != obj.ConfigVersion) && obj.ConfigVersion == node.State.ConfigVersion {
			node.State.ComQ[source][seq] = obj
		}
		node.mu.Unlock()
	}
	return true
}

func (c *churnCluster) allActiveStored(source p2p.NodeID, seq uint64) bool {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		obj, ok := node.State.ComQ[source][seq]
		version := node.State.ConfigVersion
		node.mu.Unlock()
		if !ok || obj.ConfigVersion != version {
			return false
		}
	}
	return true
}

func (c *churnCluster) waitStoredCurrent(t *testing.T, ctx context.Context, source p2p.NodeID, seq uint64) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.allActiveStored(source, seq) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for current stored object %s/%d", source, seq)
		}
	}
}

func (c *churnCluster) activeNodes() []*Node {
	ids := c.activeIDs()
	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, c.nodes[id])
	}
	return nodes
}

func (c *churnCluster) transports() []p2p.Transport {
	ids := make([]p2p.NodeID, 0, len(c.nodes))
	for id := range c.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	transports := make([]p2p.Transport, 0, len(ids))
	for _, id := range ids {
		if node := c.nodes[id]; node != nil && node.Transport != nil {
			transports = append(transports, node.Transport)
		}
	}
	return transports
}

func (c *churnCluster) activeIDs() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.active))
	for id, active := range c.active {
		if active {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *churnCluster) producingActiveIDs() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.active))
	for id, active := range c.active {
		if active && !c.stopped[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *churnCluster) stoppedActiveIDs() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.stopped))
	for id, stopped := range c.stopped {
		if stopped && c.active[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *churnCluster) members() []p2p.NodeID {
	ref := c.reference(nil)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return append([]p2p.NodeID(nil), ref.State.Members...)
}

func (c *churnCluster) reference(t *testing.T) *Node {
	for _, id := range c.activeIDs() {
		if node := c.nodes[id]; node != nil {
			return node
		}
	}
	if t != nil {
		t.Fatal("no active nodes")
	}
	panic("no active nodes")
}
