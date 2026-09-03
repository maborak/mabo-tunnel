package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// localConnQueue bounds how far a local socket may fall behind the tunnel
// before the connection is torn down.
const localConnQueue = 256

// localWriteTimeout bounds a single write to a local socket.
const localWriteTimeout = 30 * time.Second

// localConn serializes writes to a local socket through one goroutine.
//
// Two problems this solves. The tunnel read loop must never block on a slow or
// wedged local server — one stalled socket would stall every tunnel message.
// And frames for a single logical connection must be written in the order they
// arrived; a goroutine per frame reorders a byte stream.
//
// A localConn may be created before its socket is dialed. Bytes queued in the
// meantime are delivered once Attach runs, so a second frame for a connection
// still being dialed queues behind the first instead of racing it.
type localConn struct {
	ch        chan []byte
	done      chan struct{}
	closeOnce sync.Once

	mu   sync.Mutex
	conn net.Conn

	// onWrite, when set, observes every chunk written to the local socket —
	// used by WebSocket passthrough to feed the dashboard's frame inspector.
	onWrite func([]byte)
}

// SetOnWrite installs an observer invoked with each chunk before it goes to
// the local socket. It must be called before Attach; the callback runs on the
// writer goroutine and should be fast.
func (lc *localConn) SetOnWrite(fn func([]byte)) {
	lc.mu.Lock()
	lc.onWrite = fn
	lc.mu.Unlock()
}

func newLocalConn() *localConn {
	return &localConn{
		ch:   make(chan []byte, localConnQueue),
		done: make(chan struct{}),
	}
}

// Attach binds a dialed socket and starts draining the queue into it.
func (lc *localConn) Attach(conn net.Conn) {
	lc.mu.Lock()
	lc.conn = conn
	lc.mu.Unlock()
	go lc.run()
}

// Conn returns the underlying socket, or nil if it has not been dialed yet.
func (lc *localConn) Conn() net.Conn {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.conn
}

func (lc *localConn) run() {
	conn := lc.Conn()
	lc.mu.Lock()
	hook := lc.onWrite
	lc.mu.Unlock()

	defer conn.Close()
	for {
		select {
		case b := <-lc.ch:
			if hook != nil {
				hook(b)
			}
			conn.SetWriteDeadline(time.Now().Add(localWriteTimeout))
			_, err := conn.Write(b)
			conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
		case <-lc.done:
			return
		}
	}
}

// Send queues bytes without blocking the caller. It returns false if the
// connection is closed or the queue is full. A full queue closes the
// connection: dropping bytes from the middle of a stream would corrupt it
// silently, and a broken transfer is the honest outcome.
func (lc *localConn) Send(b []byte) bool {
	select {
	case <-lc.done:
		return false
	default:
	}
	select {
	case lc.ch <- b:
		return true
	default:
		lc.Close()
		return false
	}
}

// Close tears down the writer and its socket.
func (lc *localConn) Close() {
	lc.closeOnce.Do(func() {
		close(lc.done)
		if c := lc.Conn(); c != nil {
			c.Close()
		}
	})
}

// ── request bodies ──────────────────────────────────────────────────────────

// bodyQueue bounds how many request body chunks may wait to be handed to the
// local server.
const bodyQueue = 64

// ErrBodyOverflow means the local server could not keep up with an upload.
var ErrBodyOverflow = errors.New("request body overflow: local server too slow")

// bodyPipe feeds a streamed request body into the outgoing proxy request.
//
// The tunnel delivers body chunks on the read loop, which must not block; the
// HTTP transport pulls from an io.Reader at its own pace. A bounded queue sits
// between them. Overflow fails the request rather than silently truncating the
// upload — a short body delivered as a complete one is the same class of bug as
// a truncated response.
//
// Read is called only by the HTTP transport, so the leftover chunk needs no
// lock; every other field is guarded by mu.
type bodyPipe struct {
	ch  chan []byte
	cur []byte

	mu     sync.Mutex
	closed bool
	err    error

	// captured holds the leading bytes of the body, for the inspector.
	captured bytes.Buffer
	limit    int
}

func newBodyPipe(captureLimit int) *bodyPipe {
	return &bodyPipe{
		ch:    make(chan []byte, bodyQueue),
		limit: captureLimit,
	}
}

// Read implements io.Reader over the queued chunks.
func (bp *bodyPipe) Read(p []byte) (int, error) {
	for len(bp.cur) == 0 {
		b, ok := <-bp.ch
		if !ok {
			bp.mu.Lock()
			err := bp.err
			bp.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		bp.cur = b
	}
	n := copy(p, bp.cur)
	bp.cur = bp.cur[n:]
	return n, nil
}

// Send queues a body chunk without blocking. Returns false if the body has
// ended or the local server has fallen too far behind.
func (bp *bodyPipe) Send(b []byte) bool {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.closed {
		return false
	}

	if remaining := bp.limit - bp.captured.Len(); remaining > 0 {
		if len(b) > remaining {
			bp.captured.Write(b[:remaining])
		} else {
			bp.captured.Write(b)
		}
	}

	select {
	case bp.ch <- b:
		return true
	default:
		bp.err = ErrBodyOverflow
		bp.closed = true
		close(bp.ch)
		return false
	}
}

// Captured returns the leading body bytes recorded for the inspector.
func (bp *bodyPipe) Captured() []byte {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return append([]byte(nil), bp.captured.Bytes()...)
}

// Close signals a clean end of body.
func (bp *bodyPipe) Close() {
	bp.closeWith(nil)
}

// CloseWithError aborts the body, failing the in-flight request.
func (bp *bodyPipe) CloseWithError(err error) {
	bp.closeWith(err)
}

func (bp *bodyPipe) closeWith(err error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.closed {
		return
	}
	bp.err = err
	bp.closed = true
	close(bp.ch)
}
