package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Protocol version.
const Version = 1

// MaxIPListEntries bounds the allowed_ips / denied_ips lists a client may
// attach to the auth handshake, so a hostile client cannot make the server
// parse an unbounded filter list on every connect.
const MaxIPListEntries = 32

// Message types for the tunnel protocol.
const (
	TypeAuthRequest    = "auth_request"
	TypeAuthResponse   = "auth_response"
	TypeTunnelRequest  = "tunnel_request"
	TypeTunnelResponse = "tunnel_response"
	TypeData           = "data"
	TypeTCPData        = "tcp_data"
	TypeClose          = "close"
	TypePing           = "ping"
	TypePong           = "pong"
	TypeNotice         = "notice"

	// Streaming HTTP response frames (client → server). These replace the
	// legacy single-shot TypeData response so that long-lived responses
	// (SSE, chunked, LLM streaming) are forwarded chunk-by-chunk instead
	// of being fully buffered by the tunnel client.
	TypeRespHeader = "resp_header"
	TypeRespBody   = "resp_body"
	TypeRespEnd    = "resp_end"

	// Streaming HTTP request frames (server → client). TypeData carries the
	// request head (method, URL, headers) and these carry the body, so a large
	// upload starts reaching the local server before it has finished arriving
	// at the edge.
	TypeReqBody = "req_body"
	TypeReqEnd  = "req_end"
)

// Notice codes.
const (
	NoticeCodeBodyTooLarge = "body_too_large"
)

// Payload size limits for data-carrying frames, enforced by the receiving
// peer. The queues that drain these frames are sized for chunks of this
// order (requests at 32 KiB, responses at 16 KiB), so a frame that massively
// exceeds its limit can pin orders of magnitude more memory per queue slot
// than the design accounts for. A peer that sends one is broken or hostile,
// and the receiver tears down the tunnel rather than buffer it.
const (
	// MaxStreamChunkBytes bounds one resp_body / req_body / tcp_data chunk.
	// Every peer in this project chunks these at 32 KiB or less; 64 KiB
	// leaves headroom without reopening the amplification.
	MaxStreamChunkBytes = 64 * 1024

	// MaxDataFrameBytes bounds a data frame a client sends to the server:
	// WebSocket passthrough chunks in both directions, and — on the legacy
	// pre-streaming path — a whole buffered HTTP response, which may be
	// large. Larger than any response the byte-bounded queues can hold.
	MaxDataFrameBytes = 8 * 1024 * 1024

	// MaxRequestHeadBytes bounds the request head a server sends as the
	// first data frame of a proxied request (client-side limit). Net/http's
	// default header limit is 1 MiB; this leaves room for it.
	MaxRequestHeadBytes = 2 * 1024 * 1024
)

// HopByHopHeaders are the headers removed from proxied messages in both
// directions. A tunnel is a chain of HTTP hops (public caller → edge → local
// app); these headers describe one hop, not the message, so forwarding them
// lets a tunnel peer dictate connection semantics to a socket it does not
// own. Keys are in net/http canonical form; look up with
// http.CanonicalHeaderKey.
var HopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// Close reasons for CloseFrame.
const (
	CloseReasonCancel = "cancel"  // server → client: public caller disconnected, abort upstream
	CloseReasonTCPEOF = "tcp_eof" // either direction: TCP half-close
)

// Protocol identifiers for tunnel types.
const (
	ProtocolHTTP = "http"
	ProtocolTCP  = "tcp"
)

// ── Binary frames ───────────────────────────────────────────────────────────
//
// Bulk data — request and response bodies, TCP bytes, WebSocket passthrough
// bytes — travels as websocket.BinaryMessage rather than inside a JSON
// envelope. encoding/json serializes a []byte field as base64, which costs
// +33% on the wire plus a full encode and decode pass on each end for every
// chunk. Control messages (auth, headers, close, notice) stay JSON, where the
// structure is worth more than the bytes.
//
// Layout:
//
//	[0]        version   (BinaryVersion)
//	[1]        frame type (BinType*)
//	[2]        conn ID length, in bytes
//	[3:3+n]    conn ID
//	[3+n:]     payload
//
// The payload length is implicit — one logical frame per WebSocket message.
//
// Binary framing is negotiated at auth time (AuthRequest.Binary /
// AuthResponse.Binary). A peer that does not advertise support keeps receiving
// the JSON frames above, so older clients keep working.
const BinaryVersion = 1

// Binary frame types. These parallel the JSON message types that carry a
// []byte payload.
const (
	BinTypeData     byte = 1 // request head (S→C) and WebSocket passthrough bytes (both ways)
	BinTypeRespBody byte = 2 // response body chunk (C→S)
	BinTypeTCPData  byte = 3 // raw TCP bytes (both ways)
	BinTypeReqBody  byte = 4 // request body chunk (S→C)
	BinTypeReqEnd   byte = 5 // end of request body (S→C), empty payload
)

// binHeaderSize is the fixed part of a binary frame header, before the conn ID.
const binHeaderSize = 3

// ErrBadBinaryFrame is returned when a binary frame cannot be decoded.
var ErrBadBinaryFrame = fmt.Errorf("malformed binary frame")

// EncodeBinaryFrame builds a binary frame in a single allocation. connID must
// be at most 255 bytes; every ID this project generates is 32 hex characters.
func EncodeBinaryFrame(frameType byte, connID string, payload []byte) ([]byte, error) {
	if len(connID) > 255 {
		return nil, fmt.Errorf("conn ID too long: %d bytes", len(connID))
	}
	buf := make([]byte, binHeaderSize+len(connID)+len(payload))
	buf[0] = BinaryVersion
	buf[1] = frameType
	buf[2] = byte(len(connID))
	copy(buf[binHeaderSize:], connID)
	copy(buf[binHeaderSize+len(connID):], payload)
	return buf, nil
}

// DecodeBinaryFrame parses a binary frame. The returned payload aliases the
// input buffer, so callers that retain it past the read loop must copy it.
func DecodeBinaryFrame(msg []byte) (frameType byte, connID string, payload []byte, err error) {
	if len(msg) < binHeaderSize {
		return 0, "", nil, ErrBadBinaryFrame
	}
	if msg[0] != BinaryVersion {
		return 0, "", nil, fmt.Errorf("unsupported binary frame version %d", msg[0])
	}
	idLen := int(msg[2])
	if len(msg) < binHeaderSize+idLen {
		return 0, "", nil, ErrBadBinaryFrame
	}
	return msg[1], string(msg[binHeaderSize : binHeaderSize+idLen]), msg[binHeaderSize+idLen:], nil
}

// Envelope wraps all control messages with a type discriminator.
type Envelope struct {
	Type    string          `json:"type"`
	Version int             `json:"version,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// AuthRequest is sent by the client to authenticate.
type AuthRequest struct {
	Token        string   `json:"token"`
	Subdomain    string   `json:"subdomain,omitempty"`
	SessionID    string   `json:"session_id,omitempty"` // persistent across reconnects
	Name         string   `json:"name,omitempty"`       // named tunnel (e.g. "ui" → username_ui subdomain)
	Graceful     bool     `json:"graceful,omitempty"`   // true on clean shutdown (Ctrl+C) — clears reservation
	Protocol     string   `json:"protocol,omitempty"`   // "http" (default) or "tcp"
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	DeniedIPs    []string `json:"denied_ips,omitempty"`
	BasicAuth    string   `json:"basic_auth,omitempty"`    // "user:pass" — HTTP Basic Auth on the tunnel
	CustomDomain string   `json:"custom_domain,omitempty"` // serve this tunnel under its own hostname
	Binary       bool     `json:"binary,omitempty"`        // client understands binary data frames
}

// CustomDomainChallenge is the TXT value proving control of a custom domain:
// sha256("<token-hash-hex>.<domain>"). Both sides derive it without storing or
// transmitting anything extra — the client knows the raw token, the server
// knows the stored hash, and a leaked challenge reveals neither.
const CustomDomainTXTLabel = "_mabo-challenge"

func CustomDomainChallenge(tokenHashHex, domain string) string {
	sum := sha256.Sum256([]byte(tokenHashHex + "." + strings.ToLower(strings.TrimSuffix(domain, "."))))
	return hex.EncodeToString(sum[:])
}

// AuthResponse is sent by the server after authentication.
type AuthResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	TunnelID  string `json:"tunnel_id,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	URL       string `json:"url,omitempty"`
	Username  string `json:"username,omitempty"`
	Protocol  string `json:"protocol,omitempty"` // "http" or "tcp"
	TCPPort   int    `json:"tcp_port,omitempty"` // assigned TCP port (only for TCP tunnels)
	Binary    bool   `json:"binary,omitempty"`   // server will use binary data frames
}

// TunnelRequest is sent by the client to open a new tunnel.
type TunnelRequest struct {
	TunnelID  string `json:"tunnel_id"`
	Protocol  string `json:"protocol"`
	LocalPort int    `json:"local_port"`
}

// TunnelResponse confirms tunnel creation.
type TunnelResponse struct {
	Success  bool   `json:"success"`
	TunnelID string `json:"tunnel_id"`
	URL      string `json:"url,omitempty"`
	Message  string `json:"message,omitempty"`
}

// DataFrame carries proxied request/response data.
type DataFrame struct {
	ConnID   string `json:"conn_id"`
	TunnelID string `json:"tunnel_id"`
	Data     []byte `json:"data"`
}

// RespHeaderFrame is the first frame of a streaming HTTP response. The client
// sends it as soon as the local backend returns response headers, before the
// body has been read. The server uses it to write status + headers to the
// public caller and begin flushing body chunks as they arrive.
type RespHeaderFrame struct {
	ConnID     string              `json:"conn_id"`
	TunnelID   string              `json:"tunnel_id"`
	StatusCode int                 `json:"status"`
	Headers    map[string][]string `json:"headers"`
}

// CloseFrame signals that a logical connection should be closed.
type CloseFrame struct {
	ConnID   string `json:"conn_id"`
	TunnelID string `json:"tunnel_id"`
	Reason   string `json:"reason,omitempty"`
}

// Notice is an out-of-band message from the server to the client, typically
// used to surface warnings (e.g. a request was rejected at the edge) that
// would otherwise be invisible to the tunnel owner.
type Notice struct {
	Level   string `json:"level"`            // "warn" | "error" | "info"
	Code    string `json:"code,omitempty"`   // machine-readable code, e.g. "body_too_large"
	Message string `json:"message"`          // human-readable description
	Method  string `json:"method,omitempty"` // HTTP method of the offending request
	Path    string `json:"path,omitempty"`   // URL path of the offending request
	Size    int64  `json:"size,omitempty"`   // actual body size, when known
	Limit   int64  `json:"limit,omitempty"`  // configured limit
}

// NewEnvelope creates an Envelope from a typed message.
func NewEnvelope(msgType string, payload any) (*Envelope, error) {
	env := &Envelope{
		Type:    msgType,
		Version: Version,
	}
	// Ping/pong have no payload.
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		env.Payload = data
	}
	return env, nil
}

// ParsePayload deserializes the envelope payload into the given target.
func (e *Envelope) ParsePayload(target any) error {
	if e.Payload == nil {
		return nil
	}
	return json.Unmarshal(e.Payload, target)
}

// Marshal serializes the envelope to JSON bytes.
func (e *Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// ParseEnvelope deserializes bytes into an Envelope.
func ParseEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}

// NormalizeIPList validates a list of IPs/CIDRs from the auth handshake and
// returns canonical CIDR strings: bare IPs become /32 (or /128 for IPv6).
// Invalid entries or an oversized list return an error, so a bad value is
// rejected at the handshake instead of silently mis-filtering later.
func NormalizeIPList(list []string, what string) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) > MaxIPListEntries {
		return nil, fmt.Errorf("%s: too many entries (%d, max %d)", what, len(list), MaxIPListEntries)
	}
	out := make([]string, 0, len(list))
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return nil, fmt.Errorf("%s: invalid CIDR %q", what, entry)
			}
			out = append(out, entry)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("%s: invalid IP %q", what, entry)
		}
		if ip.To4() != nil {
			out = append(out, entry+"/32")
		} else {
			out = append(out, entry+"/128")
		}
	}
	return out, nil
}
