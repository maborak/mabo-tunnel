package client

import (
	"net/url"
	"time"
)

// harNameValue converts a header map into the HAR name/value array format.
func harNameValue(headers map[string][]string) []map[string]string {
	out := make([]map[string]string, 0, len(headers))
	for k, vs := range headers {
		for _, v := range vs {
			out = append(out, map[string]string{"name": k, "value": v})
		}
	}
	return out
}

// harMimeType picks a content type for an entry body from its headers.
func harMimeType(headers map[string][]string) string {
	if ct := headers["Content-Type"]; len(ct) > 0 {
		return ct[0]
	}
	if ct := headers["content-type"]; len(ct) > 0 {
		return ct[0]
	}
	return "application/octet-stream"
}

// BuildHAR renders captured requests as a HAR 1.2 document (as JSON-ready
// data), so they can be imported into browser devtools and every HAR-aware
// tool. WebSocket passthrough sessions appear as 101 entries carrying the
// Chrome-style _webSocketMessages extension.
func BuildHAR(entries []*CapturedRequest, creatorVersion string) map[string]any {
	logEntries := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		query := make([]map[string]string, 0)
		if u, err := url.Parse(e.Path); err == nil {
			for k, vs := range u.Query() {
				for _, v := range vs {
					query = append(query, map[string]string{"name": k, "value": v})
				}
			}
			e.Path = u.Path
		}

		fullURL := e.FullURL
		if fullURL == "" {
			fullURL = e.Path
		}

		reqHeaders := harNameValue(e.RequestHeaders)
		respHeaders := harNameValue(e.ResponseHeaders)

		entry := map[string]any{
			"startedDateTime": e.Timestamp.UTC().Format(time.RFC3339Nano),
			"time":            float64(e.Duration.Microseconds()) / 1000.0,
			"_resourceType":   "tunnel",
			"cache":           map[string]any{},
			"request": map[string]any{
				"method":      e.Method,
				"url":         fullURL,
				"httpVersion": "HTTP/1.1",
				"headers":     reqHeaders,
				"queryString": query,
				"cookies":     []any{},
				"headersSize": -1,
				"bodySize":    len(e.RequestBody),
				"postData": map[string]any{
					"mimeType": harMimeType(e.RequestHeaders),
					"text":     e.RequestBody,
				},
			},
			"response": map[string]any{
				"status":      e.ResponseStatus,
				"statusText":  "",
				"httpVersion": "HTTP/1.1",
				"headers":     respHeaders,
				"cookies":     []any{},
				"headersSize": -1,
				"bodySize":    len(e.ResponseBody),
				"redirectURL": "",
				"content": map[string]any{
					"size":     len(e.ResponseBody),
					"mimeType": harMimeType(e.ResponseHeaders),
					"text":     e.ResponseBody,
				},
			},
			"timings": map[string]any{
				"send":    0,
				"wait":    float64(e.Duration.Microseconds()) / 1000.0,
				"receive": 0,
			},
		}

		if e.Method == "WS" {
			msgs := make([]map[string]any, 0, len(e.WSFrames))
			for i, f := range e.WSFrames {
				mtype := "receive"
				if f.Direction == "to_local" {
					// Bytes heading to the local app are what the public
					// client sent: HAR's websocket convention is send/receive
					// relative to the page.
					mtype = "send"
				}
				msgs = append(msgs, map[string]any{
					"type": mtype,
					"time": f.Timestamp.UnixMilli(),
					// "data" prefers readable text; binary chunks carry hex.
					"data":       f.Text,
					"opcode":     frameOpcode(f.Binary),
					"_index":     i,
					"_size":      f.Size,
					"_binary":    f.Binary,
					"_direction": f.Direction,
				})
			}
			entry["_webSocketMessages"] = msgs
			if e.WSDropped > 0 {
				entry["_webSocketMessagesDropped"] = e.WSDropped
			}
		}

		logEntries = append(logEntries, entry)
	}

	return map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"creator": map[string]any{"name": "mabo-tunnel", "version": creatorVersion},
			"entries": logEntries,
		},
	}
}

func frameOpcode(binary bool) int {
	if binary {
		return 2 // RFC 6455 binary frame opcode, best-effort label
	}
	return 1 // text
}
