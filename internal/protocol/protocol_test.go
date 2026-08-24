package protocol

import (
	"bytes"
	"testing"
)

func TestBinaryFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		frameType byte
		connID    string
		payload   []byte
	}{
		{"typical", BinTypeRespBody, "0123456789abcdef0123456789abcdef", bytes.Repeat([]byte("x"), 32*1024)},
		{"empty payload", BinTypeReqEnd, "abc", nil},
		{"empty conn id", BinTypeData, "", []byte("body")},
		{"binary safe payload", BinTypeTCPData, "id", []byte{0x00, 0xff, 0x1b, '\n', '"', '\\'}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := EncodeBinaryFrame(tc.frameType, tc.connID, tc.payload)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			frameType, connID, payload, err := DecodeBinaryFrame(buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if frameType != tc.frameType {
				t.Errorf("frameType = %d, want %d", frameType, tc.frameType)
			}
			if connID != tc.connID {
				t.Errorf("connID = %q, want %q", connID, tc.connID)
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Errorf("payload mismatch: got %d bytes, want %d", len(payload), len(tc.payload))
			}
		})
	}
}

// A binary frame must not be larger than its payload plus a small fixed header.
// This is the whole point of the format: the JSON path base64-encodes the same
// bytes, costing a third more.
func TestBinaryFrameOverheadIsFixed(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 32*1024)
	connID := "0123456789abcdef0123456789abcdef"

	buf, err := EncodeBinaryFrame(BinTypeRespBody, connID, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	want := binHeaderSize + len(connID) + len(payload)
	if len(buf) != want {
		t.Errorf("frame size = %d, want %d (no per-byte expansion allowed)", len(buf), want)
	}
}

func TestDecodeBinaryFrameRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated header", []byte{BinaryVersion, BinTypeData}},
		{"conn id longer than frame", []byte{BinaryVersion, BinTypeData, 40, 'a', 'b'}},
		{"unsupported version", []byte{BinaryVersion + 9, BinTypeData, 0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := DecodeBinaryFrame(tc.in); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

func TestEncodeBinaryFrameRejectsOversizeConnID(t *testing.T) {
	long := string(bytes.Repeat([]byte("a"), 256))
	if _, err := EncodeBinaryFrame(BinTypeData, long, nil); err == nil {
		t.Error("expected an error for a conn ID longer than 255 bytes")
	}
}
