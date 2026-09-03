package client

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecordWSSessionAndFrameCaps(t *testing.T) {
	insp := NewInspector()
	req := insp.RecordWSSession("tun-1", "/ws")
	if req == nil {
		t.Fatal("session entry missing")
	}

	for i := 0; i < maxWSFramesPerSession+10; i++ {
		insp.AppendWSFrame(req, "to_local", []byte("chunk"))
	}

	got := insp.GetRequest("tun-1", req.ID)
	if got == nil {
		t.Fatal("captured session not found by ID")
	}
	if len(got.WSFrames) != maxWSFramesPerSession {
		t.Errorf("frames = %d, want %d", len(got.WSFrames), maxWSFramesPerSession)
	}
	if got.WSDropped != 10 {
		t.Errorf("dropped = %d, want 10", got.WSDropped)
	}
	for _, f := range got.WSFrames {
		if f.Size != 5 || f.Direction != "to_local" || f.Binary {
			t.Fatalf("unexpected frame %+v", f)
		}
	}
}

func TestAppendWSFrameDetectsBinary(t *testing.T) {
	insp := NewInspector()
	req := insp.RecordWSSession("tun-1", "/ws")
	insp.AppendWSFrame(req, "from_local", []byte{0x00, 0x01, 0x02})

	got := insp.GetRequest("tun-1", req.ID)
	if !got.WSFrames[0].Binary {
		t.Error("binary chunk not detected")
	}
	if got.WSFrames[0].Text == string([]byte{0, 1, 2}) {
		t.Error("binary chunk stored as raw text")
	}
}

func TestBuildHARShape(t *testing.T) {
	insp := NewInspector()
	wsReq := insp.RecordWSSession("tun-1", "/ws")
	insp.AppendWSFrame(wsReq, "to_local", []byte(`hello`))
	httpReq := &CapturedRequest{
		ID: "r2", TunnelID: "tun-1", Method: "GET", Path: "/x?a=b",
		RequestHeaders: map[string][]string{"Content-Type": {"text/html"}},
		ResponseStatus: 200,
		Duration:       1500 * time.Microsecond,
		Timestamp:      time.Now(),
		FullURL:        "https://t.example/x?a=b",
	}
	insp.RecordFull(httpReq)

	har := BuildHAR(insp.GetRequests("tun-1"), "test")
	logMap := har["log"].(map[string]any)
	if logMap["version"] != "1.2" {
		t.Errorf("HAR version = %v", logMap["version"])
	}
	entries := logMap["entries"].([]map[string]any)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}

	// WS entry: 101 + one send message.
	wsEntry := entries[0]
	if wsEntry["response"].(map[string]any)["status"] != 101 {
		t.Errorf("WS response status = %v", wsEntry["response"].(map[string]any)["status"])
	}
	msgs := wsEntry["_webSocketMessages"].([]map[string]any)
	if msgs[0]["type"] != "send" || msgs[0]["data"] != "hello" {
		t.Errorf("WS message wrong: %+v", msgs[0])
	}

	// HTTP entry: method/url/query/rounded timing survive the round trip.
	raw, _ := json.Marshal(har)
	doc := string(raw)
	for _, want := range []string{`"method":"GET"`, `"url":"https://t.example/x?a=b"`, `{"name":"a","value":"b"}`, `"text/html"`, `"wait":1.5`} {
		if !strings.Contains(doc, want) {
			t.Errorf("HAR document missing %s:\n%s", want, doc)
		}
	}
}
