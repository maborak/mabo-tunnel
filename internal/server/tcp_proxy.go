package server

import (
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/maborak/mabo-tunnel/internal/protocol"
)

// TCPProxy manages a TCP listener for a tunnel and forwards data bidirectionally
// through the WebSocket tunnel to the client.
type TCPProxy struct {
	tunnel *Tunnel
	logger *slog.Logger
}

// NewTCPProxy creates a new TCPProxy for the given tunnel.
func NewTCPProxy(tunnel *Tunnel, logger *slog.Logger) *TCPProxy {
	return &TCPProxy{
		tunnel: tunnel,
		logger: logger,
	}
}

// Serve accepts TCP connections on the tunnel's listener and proxies them.
// Blocks until the listener is closed or an error occurs.
func (tp *TCPProxy) Serve() {
	defer tp.logger.Info("TCP proxy stopped",
		"tunnel_id", tp.tunnel.ID,
		"port", tp.tunnel.TCPPort,
	)

	for {
		conn, err := tp.tunnel.tcpListener.Accept()
		if err != nil {
			// Check if tunnel is shutting down.
			select {
			case <-tp.tunnel.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			tp.logger.Error("TCP accept error",
				"error", err,
				"tunnel_id", tp.tunnel.ID,
			)
			return
		}

		go tp.handleConnection(conn)
	}
}

// handleConnection manages a single TCP connection through the tunnel.
func (tp *TCPProxy) handleConnection(conn net.Conn) {
	connID, err := generateTunnelID()
	if err != nil {
		tp.logger.Error("failed to generate TCP conn ID", "error", err)
		conn.Close()
		return
	}

	tp.logger.Debug("TCP connection accepted",
		"conn_id", connID,
		"tunnel_id", tp.tunnel.ID,
		"remote_addr", conn.RemoteAddr().String(),
	)

	// Wrap the connection in a serialized writer so frames arriving from the
	// tunnel are written in order and never block the tunnel's read loop.
	writer := newConnWriter(conn)
	tp.tunnel.tcpConns.Store(connID, writer)
	defer func() {
		tp.tunnel.tcpConns.Delete(connID)
		writer.Close()
		// Send a close frame to inform the client this connection ended.
		tp.sendCloseFrame(connID)
		tp.logger.Debug("TCP connection closed",
			"conn_id", connID,
			"tunnel_id", tp.tunnel.ID,
		)
	}()

	// Read from the TCP connection and forward to the client via WebSocket.
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-tp.tunnel.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := tp.tunnel.WriteData(protocol.BinTypeTCPData, protocol.TypeTCPData, connID, buf[:n]); sendErr != nil {
				tp.logger.Error("failed to send TCP data to client",
					"error", sendErr,
					"conn_id", connID,
				)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				tp.logger.Debug("TCP read ended",
					"error", err,
					"conn_id", connID,
				)
			}
			return
		}
	}
}

// sendCloseFrame sends a close frame to the client for a TCP connection.
func (tp *TCPProxy) sendCloseFrame(connID string) {
	_ = tp.tunnel.WriteControl(protocol.TypeClose, &protocol.CloseFrame{
		ConnID:   connID,
		TunnelID: tp.tunnel.ID,
		Reason:   protocol.CloseReasonTCPEOF,
	})
}

// HandleTCPDataFromClient writes data received from the client back to the
// appropriate TCP connection. The write is handed to that connection's writer
// goroutine, so this never blocks the tunnel read loop.
func HandleTCPDataFromClient(tunnel *Tunnel, connID string, data []byte, logger *slog.Logger) {
	val, ok := tunnel.tcpConns.Load(connID)
	if !ok {
		logger.Warn("received TCP data for unknown connection",
			"conn_id", connID,
			"tunnel_id", tunnel.ID,
		)
		return
	}

	writer, ok := val.(*connWriter)
	if !ok {
		return
	}
	if !writer.Send(data) {
		logger.Warn("TCP connection closed: consumer fell behind or connection ended",
			"conn_id", connID,
			"tunnel_id", tunnel.ID,
		)
		tunnel.tcpConns.Delete(connID)
	}
}
