package p2p

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const defaultMaxMessageBytes = 64 << 20
const minTCPBuffer = 1 << 20
const maxTCPBuffer = 8 << 20
const tcpSocketBuffer = 16 << 20

func TCPBufferForPeers(peers int) int {
	buffer := peers * peers * 1024
	if buffer < minTCPBuffer {
		return minTCPBuffer
	}
	if buffer > maxTCPBuffer {
		return maxTCPBuffer
	}
	return buffer
}

type TCPTransport struct {
	id           NodeID
	addr         string
	peers        map[NodeID]string
	inbox        chan Message
	listener     net.Listener
	mu           sync.RWMutex
	closed       bool
	conns        map[NodeID]*tcpPeerConn
	statsMu      sync.Mutex
	typeStats    map[string]MessageTypeMetrics
	networkStats map[string]MessageTypeMetrics
	tlsConfig    *tls.Config
	peerIdentity func(tls.ConnectionState) (NodeID, error)

	maxMessageBytes uint32
	dialTimeout     time.Duration
	dialRetries     int
	retryDelay      time.Duration

	sentMessages atomic.Uint64
	sentBytes    atomic.Uint64
	recvMessages atomic.Uint64
	recvBytes    atomic.Uint64
}

type tcpPeerConn struct {
	mu    sync.Mutex
	conn  net.Conn
	frame []byte // Reused under mu; large recovery frames are not retained.
}

func NewTCPTransport(id NodeID, addr string, peers map[NodeID]string, buffer int) *TCPTransport {
	cp := make(map[NodeID]string, len(peers))
	for id, addr := range peers {
		cp[id] = addr
	}
	return &TCPTransport{
		id: id, addr: addr, peers: cp, inbox: make(chan Message, buffer), conns: make(map[NodeID]*tcpPeerConn),
		maxMessageBytes: defaultMaxMessageBytes,
		dialTimeout:     3 * time.Second,
		dialRetries:     5,
		retryDelay:      200 * time.Millisecond,
	}
}

func (t *TCPTransport) ID() NodeID            { return t.id }
func (t *TCPTransport) Inbox() <-chan Message { return t.inbox }

func (t *TCPTransport) AuthenticatedDelivery() bool { return t.tlsConfig != nil }

func (t *TCPTransport) InboxStats() (int, int) {
	return len(t.inbox), cap(t.inbox)
}

func (t *TCPTransport) Start(ctx context.Context) error {
	if t.addr == "" {
		t.addr = t.peers[t.id]
	}
	if t.addr == "" {
		return errors.New("tcp listen address is empty")
	}
	ln, err := net.Listen("tcp", t.addr)
	if err != nil {
		return err
	}
	t.listener = ln
	go func() {
		<-ctx.Done()
		_ = t.Close()
	}()
	go t.acceptLoop()
	return nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			t.mu.Lock()
			closed := t.closed
			t.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		go t.handleConn(conn)
	}
}

func (t *TCPTransport) handleConn(conn net.Conn) {
	defer conn.Close()
	tuneTCPConn(conn)
	var sender NodeID
	if t.tlsConfig != nil {
		secure := tls.Server(conn, t.tlsConfig)
		_ = secure.SetDeadline(time.Now().Add(30 * time.Second))
		if err := secure.Handshake(); err != nil {
			return
		}
		var err error
		sender, err = t.peerIdentity(secure.ConnectionState())
		if err != nil {
			return
		}
		_ = secure.SetDeadline(time.Time{})
		conn = secure
	}
	r := bufio.NewReader(conn)
	for {
		var size uint32
		if err := binary.Read(r, binary.BigEndian, &size); err != nil {
			return
		}
		if size == 0 || size > t.maxMessageBytes {
			return
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if t.tlsConfig != nil {
			if msg.From != sender || msg.To != t.id {
				return
			}
			msg.authenticated = true
		}
		sizeWithFrame := uint64(size) + 4
		t.recvMessages.Add(1)
		t.recvBytes.Add(sizeWithFrame)
		t.recordRecvTypeStats(msg, sizeWithFrame)
		t.inbox <- msg
	}
}

func (t *TCPTransport) Send(ctx context.Context, to NodeID, msg Message) error {
	if t.tlsConfig != nil {
		if msg.From != t.id {
			return errors.New("TLS sender does not match transport identity")
		}
		msg.authenticated = true
	}
	msg.To = to
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > int(t.maxMessageBytes) {
		return errors.New("message exceeds tcp max message size")
	}
	if to == t.id {
		select {
		case t.inbox <- msg:
			size := uint64(len(data)) + 4
			t.sentMessages.Add(1)
			t.sentBytes.Add(size)
			t.recordSentTypeStats(msg, size)
			t.recvMessages.Add(1)
			t.recvBytes.Add(size)
			t.recordRecvTypeStats(msg, size)
			return nil
		default:
			go t.enqueueSelf(ctx, msg, uint64(len(data))+4)
			return nil
		}
	}
	addr, ok := t.peers[to]
	if !ok {
		return errors.New("unknown peer: " + string(to))
	}
	var last error
	attempts := t.dialRetries
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(t.retryDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		sendCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
		last = t.sendOnce(sendCtx, to, addr, data)
		cancel()
		if last == nil {
			size := uint64(len(data)) + 4
			t.sentMessages.Add(1)
			t.sentBytes.Add(size)
			t.recordSentTypeStats(msg, size)
			return nil
		}
	}
	return last
}

func (t *TCPTransport) enqueueSelf(ctx context.Context, msg Message, size uint64) {
	select {
	case t.inbox <- msg:
		t.sentMessages.Add(1)
		t.sentBytes.Add(size)
		t.recordSentTypeStats(msg, size)
		t.recvMessages.Add(1)
		t.recvBytes.Add(size)
		t.recordRecvTypeStats(msg, size)
	case <-ctx.Done():
	}
}

func (t *TCPTransport) Broadcast(ctx context.Context, msg Message) error {
	type result struct {
		err error
	}
	results := make(chan result, len(t.peers))
	var wg sync.WaitGroup
	for id := range t.peers {
		msgCopy := msg
		wg.Add(1)
		go func(id NodeID) {
			defer wg.Done()
			results <- result{err: t.Send(ctx, id, msgCopy)}
		}(id)
	}
	wg.Wait()
	close(results)
	var last error
	sent := 0
	for res := range results {
		if res.err != nil {
			last = res.err
			continue
		}
		sent++
	}
	if sent == 0 && last != nil {
		return last
	}
	return nil
}

func (t *TCPTransport) Metrics() Metrics {
	return Metrics{
		SentMessages: t.sentMessages.Load(),
		SentBytes:    t.sentBytes.Load(),
		RecvMessages: t.recvMessages.Load(),
		RecvBytes:    t.recvBytes.Load(),
	}
}

func (t *TCPTransport) MessageTypeMetrics() map[string]MessageTypeMetrics {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	out := make(map[string]MessageTypeMetrics, len(t.typeStats))
	for k, v := range t.typeStats {
		out[k] = v
	}
	return out
}

// NetworkMessageTypeMetrics excludes local self-delivery. Bytes are framed
// application plaintext, consistently excluding TLS/TCP/IP overhead.
func (t *TCPTransport) NetworkMessageTypeMetrics() map[string]MessageTypeMetrics {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	out := make(map[string]MessageTypeMetrics, len(t.networkStats))
	for key, value := range t.networkStats {
		out[key] = value
	}
	return out
}

func (t *TCPTransport) recordSentTypeStats(msg Message, size uint64) {
	key := msg.Protocol + "/" + msg.Type
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	if t.typeStats == nil {
		t.typeStats = make(map[string]MessageTypeMetrics)
	}
	stats := t.typeStats[key]
	stats.SentMessages++
	stats.SentBytes += size
	t.typeStats[key] = stats
	if msg.To != t.id {
		if t.networkStats == nil {
			t.networkStats = make(map[string]MessageTypeMetrics)
		}
		network := t.networkStats[key]
		network.SentMessages++
		network.SentBytes += size
		t.networkStats[key] = network
	}
}

func (t *TCPTransport) recordRecvTypeStats(msg Message, size uint64) {
	key := msg.Protocol + "/" + msg.Type
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	if t.typeStats == nil {
		t.typeStats = make(map[string]MessageTypeMetrics)
	}
	stats := t.typeStats[key]
	stats.RecvMessages++
	stats.RecvBytes += size
	t.typeStats[key] = stats
	if msg.From != t.id {
		if t.networkStats == nil {
			t.networkStats = make(map[string]MessageTypeMetrics)
		}
		network := t.networkStats[key]
		network.RecvMessages++
		network.RecvBytes += size
		t.networkStats[key] = network
	}
}

func (t *TCPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	listener := t.listener
	conns := make([]*tcpPeerConn, 0, len(t.conns))
	for _, pc := range t.conns {
		conns = append(conns, pc)
	}
	t.mu.Unlock()
	for _, pc := range conns {
		pc.mu.Lock()
		if pc.conn != nil {
			_ = pc.conn.Close()
			pc.conn = nil
		}
		pc.mu.Unlock()
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (t *TCPTransport) sendOnce(ctx context.Context, to NodeID, addr string, data []byte) error {
	pc := t.peerConn(to)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.conn == nil {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		tuneTCPConn(conn)
		if t.tlsConfig != nil {
			cfg := t.tlsConfig.Clone()
			cfg.VerifyConnection = func(state tls.ConnectionState) error {
				id, err := t.peerIdentity(state)
				if err != nil {
					return err
				}
				if id != to {
					return errors.New("TLS peer identity does not match destination")
				}
				return nil
			}
			secure := tls.Client(conn, cfg)
			if err := secure.HandshakeContext(ctx); err != nil {
				conn.Close()
				return err
			}
			conn = secure
		}
		pc.conn = conn
	}
	_ = pc.conn.SetWriteDeadline(time.Now().Add(t.dialTimeout))
	// One complete application frame per TLS write. Separate header/body
	// writes created two TLS records and socket writes for every small packet.
	// Keep the wire format and byte counters identical, with no batching delay.
	size := len(data) + 4
	var frame []byte
	if size <= 256<<10 {
		if cap(pc.frame) < size {
			pc.frame = make([]byte, size)
		}
		frame = pc.frame[:size]
	} else {
		frame = make([]byte, size)
	}
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	if err := writeFull(pc.conn, frame); err != nil {
		_ = pc.conn.Close()
		pc.conn = nil
		return err
	}
	return nil
}

func tuneTCPConn(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetReadBuffer(tcpSocketBuffer)
	_ = tcp.SetWriteBuffer(tcpSocketBuffer)
}

func (t *TCPTransport) peerConn(to NodeID) *tcpPeerConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	pc := t.conns[to]
	if pc == nil {
		pc = &tcpPeerConn{}
		t.conns[to] = pc
	}
	return pc
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
