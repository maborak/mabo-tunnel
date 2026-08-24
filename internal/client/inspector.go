package client

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	// maxRequestsPerTunnel is the ring buffer size for captured requests.
	maxRequestsPerTunnel = 100
	// maxBodyCapture is the max body size stored for inspection (64 KB).
	maxBodyCapture = 64 * 1024
)

// CapturedRequest holds a captured HTTP request/response pair.
type CapturedRequest struct {
	ID              string              `json:"id"`
	TunnelID        string              `json:"tunnel_id"`
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	FullURL         string              `json:"full_url"`
	Host            string              `json:"host,omitempty"`
	RequestHeaders  map[string][]string `json:"request_headers"`
	RequestBody     string              `json:"request_body,omitempty"`
	ResponseStatus  int                 `json:"response_status"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty"`
	Duration        time.Duration       `json:"duration_ns"`
	DurationMs      float64             `json:"duration_ms"`
	Timestamp       time.Time           `json:"timestamp"`
	RemoteAddr      string              `json:"remote_addr"`
}

// ringBuffer is a fixed-size circular buffer for captured requests.
type ringBuffer struct {
	items []*CapturedRequest
	head  int
	count int
	cap   int
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{
		items: make([]*CapturedRequest, capacity),
		cap:   capacity,
	}
}

func (rb *ringBuffer) push(item *CapturedRequest) {
	rb.items[rb.head] = item
	rb.head = (rb.head + 1) % rb.cap
	if rb.count < rb.cap {
		rb.count++
	}
}

// all returns items in chronological order (oldest first).
func (rb *ringBuffer) all() []*CapturedRequest {
	result := make([]*CapturedRequest, 0, rb.count)
	start := rb.head - rb.count
	if start < 0 {
		start += rb.cap
	}
	for i := 0; i < rb.count; i++ {
		idx := (start + i) % rb.cap
		result = append(result, rb.items[idx])
	}
	return result
}

// find returns a request by ID.
func (rb *ringBuffer) find(id string) *CapturedRequest {
	for i := 0; i < rb.count; i++ {
		start := rb.head - rb.count
		if start < 0 {
			start += rb.cap
		}
		idx := (start + i) % rb.cap
		if rb.items[idx].ID == id {
			return rb.items[idx]
		}
	}
	return nil
}

// Inspector captures and stores recent requests per tunnel.
type Inspector struct {
	mu      sync.RWMutex
	buffers map[string]*ringBuffer // tunnelID -> ring buffer
}

// NewInspector creates a new Inspector.
func NewInspector() *Inspector {
	return &Inspector{
		buffers: make(map[string]*ringBuffer),
	}
}

// Record stores a captured request for a tunnel.
func (insp *Inspector) Record(tunnelID string, r *http.Request, reqBody []byte, responseStatus int, duration time.Duration) {
	reqID, err := generateRequestID()
	if err != nil {
		return
	}

	// Truncate body if too large.
	bodyStr := string(reqBody)
	if len(bodyStr) > maxBodyCapture {
		bodyStr = bodyStr[:maxBodyCapture]
	}

	// Copy headers.
	headers := make(map[string][]string, len(r.Header))
	for k, v := range r.Header {
		headers[k] = v
	}

	captured := &CapturedRequest{
		ID:             reqID,
		TunnelID:       tunnelID,
		Method:         r.Method,
		Path:           r.URL.Path,
		RequestHeaders: headers,
		RequestBody:    bodyStr,
		ResponseStatus: responseStatus,
		Duration:       duration,
		DurationMs:     float64(duration.Microseconds()) / 1000.0,
		Timestamp:      time.Now(),
		RemoteAddr:     r.RemoteAddr,
	}

	insp.mu.Lock()
	defer insp.mu.Unlock()

	buf, ok := insp.buffers[tunnelID]
	if !ok {
		buf = newRingBuffer(maxRequestsPerTunnel)
		insp.buffers[tunnelID] = buf
	}
	buf.push(captured)
}

// GetRequests returns all captured requests for a tunnel (oldest first).
func (insp *Inspector) GetRequests(tunnelID string) []*CapturedRequest {
	insp.mu.RLock()
	defer insp.mu.RUnlock()

	buf, ok := insp.buffers[tunnelID]
	if !ok {
		return nil
	}
	return buf.all()
}

// GetRequest returns a single captured request by tunnel and request ID.
func (insp *Inspector) GetRequest(tunnelID, requestID string) *CapturedRequest {
	insp.mu.RLock()
	defer insp.mu.RUnlock()

	buf, ok := insp.buffers[tunnelID]
	if !ok {
		return nil
	}
	return buf.find(requestID)
}

// ReassignTunnel moves captured requests from an old tunnel ID to a new one
// when a tunnel reconnects. The server hands out a fresh ID per connection;
// without this, every reconnect strands the previous ID's ring buffer (and
// its captured bodies) with no remaining reader. Entries keep chronological
// order and the ring cap drops the oldest when the merge overflows.
func (insp *Inspector) ReassignTunnel(oldID, newID string) {
	if oldID == "" || oldID == newID {
		return
	}
	insp.mu.Lock()
	defer insp.mu.Unlock()
	old, ok := insp.buffers[oldID]
	if !ok {
		return
	}
	dst, ok := insp.buffers[newID]
	merged := newRingBuffer(maxRequestsPerTunnel)
	for _, item := range old.all() {
		merged.push(item)
	}
	if ok {
		for _, item := range dst.all() {
			merged.push(item)
		}
	}
	insp.buffers[newID] = merged
	delete(insp.buffers, oldID)
}

// RequestCount returns the number of captured requests for a tunnel.
func (insp *Inspector) RequestCount(tunnelID string) int {
	insp.mu.RLock()
	defer insp.mu.RUnlock()
	buf, ok := insp.buffers[tunnelID]
	if !ok {
		return 0
	}
	return buf.count
}

// RecordFull stores a captured request with full headers and body.
func (insp *Inspector) RecordFull(c *CapturedRequest) {
	if c.ID == "" {
		id, err := generateRequestID()
		if err != nil {
			return
		}
		c.ID = id
	}
	if c.Timestamp.IsZero() {
		c.Timestamp = time.Now()
	}
	c.DurationMs = float64(c.Duration.Microseconds()) / 1000.0

	// Truncate bodies if too large.
	if len(c.RequestBody) > maxBodyCapture {
		c.RequestBody = c.RequestBody[:maxBodyCapture]
	}
	if len(c.ResponseBody) > maxBodyCapture {
		c.ResponseBody = c.ResponseBody[:maxBodyCapture]
	}

	insp.mu.Lock()
	defer insp.mu.Unlock()

	buf, ok := insp.buffers[c.TunnelID]
	if !ok {
		buf = newRingBuffer(maxRequestsPerTunnel)
		insp.buffers[c.TunnelID] = buf
	}
	buf.push(c)
}

func generateRequestID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
