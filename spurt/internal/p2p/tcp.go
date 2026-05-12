package p2p

import (
	"bufio"
	"context"
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

type TCPTransport struct {
	id       NodeID
	addr     string
	peers    map[NodeID]string
	inbox    chan Message
	listener net.Listener
	mu       sync.RWMutex
	closed   bool

	maxMessageBytes uint32
	dialTimeout     time.Duration
	dialRetries     int
	retryDelay      time.Duration

	sentMessages atomic.Uint64
	sentBytes    atomic.Uint64
	recvMessages atomic.Uint64
	recvBytes    atomic.Uint64
}

func NewTCPTransport(id NodeID, addr string, peers map[NodeID]string, buffer int) *TCPTransport {
	cp := make(map[NodeID]string, len(peers))
	for id, addr := range peers {
		cp[id] = addr
	}
	return &TCPTransport{
		id: id, addr: addr, peers: cp, inbox: make(chan Message, buffer),
		maxMessageBytes: defaultMaxMessageBytes,
		dialTimeout:     3 * time.Second,
		dialRetries:     5,
		retryDelay:      200 * time.Millisecond,
	}
}

func (t *TCPTransport) ID() NodeID            { return t.id }
func (t *TCPTransport) Inbox() <-chan Message { return t.inbox }

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
		t.recvMessages.Add(1)
		t.recvBytes.Add(uint64(size) + 4)
		t.inbox <- msg
	}
}

func (t *TCPTransport) Send(ctx context.Context, to NodeID, msg Message) error {
	addr, ok := t.peers[to]
	if !ok {
		return errors.New("unknown peer: " + string(to))
	}
	msg.To = to
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > int(t.maxMessageBytes) {
		return errors.New("message exceeds tcp max message size")
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
		last = t.sendOnce(sendCtx, addr, data)
		cancel()
		if last == nil {
			t.sentMessages.Add(1)
			t.sentBytes.Add(uint64(len(data)) + 4)
			return nil
		}
	}
	return last
}

func (t *TCPTransport) Broadcast(ctx context.Context, msg Message) error {
	var last error
	success := 0
	for id := range t.peers {
		if err := t.Send(ctx, id, msg); err != nil {
			last = err
			continue
		}
		success++
	}
	if success == 0 && last != nil {
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

func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func (t *TCPTransport) sendOnce(ctx context.Context, addr string, data []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(t.dialTimeout))
	if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	return writeFull(conn, data)
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
