// HAR (HTTP Archive) 1.2 export/import for captured traffic, so traffic
// captured in SentryBench can be opened in browser devtools / other
// tooling, and HAR files from those tools can be brought in here for
// scanning and replay. The CapturedRequest model already carries every
// field HAR 1.2 needs, so this is purely a format translation, not a
// data-model change.
package capture

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sentrybench/core/internal/models"
)

type harLog struct {
	Log harLogBody `json:"log"`
}

type harLogBody struct {
	Version string      `json:"version"`
	Creator harCreator  `json:"creator"`
	Entries []harEntry  `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Timings         harTimings  `json:"timings"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	QueryString []harHeader `json:"queryString"`
	PostData    *harPostData `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Content     harContent  `json:"content"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// WriteHAR serializes captured requests as a HAR 1.2 document.
func WriteHAR(requests []models.CapturedRequest) ([]byte, error) {
	entries := make([]harEntry, 0, len(requests))
	for _, cr := range requests {
		entries = append(entries, toHAREntry(cr))
	}
	doc := harLog{Log: harLogBody{
		Version: "1.2",
		Creator: harCreator{Name: "SentryBench", Version: "1"},
		Entries: entries,
	}}
	return json.MarshalIndent(doc, "", "  ")
}

func toHAREntry(cr models.CapturedRequest) harEntry {
	reqHeaders := toHARHeaders(cr.RequestHeaders)
	respHeaders := toHARHeaders(cr.ResponseHeaders)

	entry := harEntry{
		StartedDateTime: cr.CapturedAt.Format(time.RFC3339Nano),
		Time:            float64(cr.DurationMs),
		Request: harRequest{
			Method:      cr.Method,
			URL:         cr.URL,
			HTTPVersion: "HTTP/1.1",
			Headers:     reqHeaders,
			HeadersSize: -1,
			BodySize:    len(cr.RequestBody),
		},
		Response: harResponse{
			Status:      cr.ResponseStatus,
			StatusText:  "",
			HTTPVersion: "HTTP/1.1",
			Headers:     respHeaders,
			Content: harContent{
				Size:     len(cr.ResponseBody),
				MimeType: headerValueFromList(respHeaders, "Content-Type"),
				Text:     cr.ResponseBody,
			},
			HeadersSize: -1,
			BodySize:    len(cr.ResponseBody),
		},
		Timings: harTimings{Send: 0, Wait: float64(cr.DurationMs), Receive: 0},
	}
	if cr.RequestBody != "" {
		entry.Request.PostData = &harPostData{
			MimeType: headerValueFromList(reqHeaders, "Content-Type"),
			Text:     cr.RequestBody,
		}
	}
	return entry
}

func toHARHeaders(m map[string]string) []harHeader {
	out := make([]harHeader, 0, len(m))
	for k, v := range m {
		out = append(out, harHeader{Name: k, Value: v})
	}
	return out
}

func headerValueFromList(headers []harHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// ParseHAR reads a HAR 1.2 document and returns the equivalent
// CapturedRequests, ready to insert (WorkspaceID and ID are left for the
// caller to fill in).
func ParseHAR(data []byte) ([]models.CapturedRequest, error) {
	var doc harLog
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid HAR: %w", err)
	}

	out := make([]models.CapturedRequest, 0, len(doc.Log.Entries))
	for _, e := range doc.Log.Entries {
		capturedAt, err := time.Parse(time.RFC3339Nano, e.StartedDateTime)
		if err != nil {
			capturedAt, err = time.Parse(time.RFC3339, e.StartedDateTime)
			if err != nil {
				capturedAt = time.Now().UTC()
			}
		}

		reqBody := ""
		if e.Request.PostData != nil {
			reqBody = e.Request.PostData.Text
		}

		host, path := splitURL(e.Request.URL)

		out = append(out, models.CapturedRequest{
			Method:          e.Request.Method,
			URL:             e.Request.URL,
			Host:            host,
			Path:            path,
			RequestHeaders:  fromHARHeaders(e.Request.Headers),
			RequestBody:     reqBody,
			ResponseStatus:  e.Response.Status,
			ResponseHeaders: fromHARHeaders(e.Response.Headers),
			ResponseBody:    e.Response.Content.Text,
			DurationMs:      int64(e.Time),
			CapturedAt:      capturedAt,
		})
	}
	return out, nil
}

func fromHARHeaders(headers []harHeader) map[string]string {
	out := map[string]string{}
	for _, h := range headers {
		out[h.Name] = h.Value
	}
	return out
}

func splitURL(raw string) (host, path string) {
	// Lightweight parse — avoids pulling in net/url just for this; good
	// enough for the host/path fields, which are informational (the full
	// URL is still stored verbatim in cr.URL).
	rest := raw
	if idx := strings.Index(rest, "://"); idx != -1 {
		rest = rest[idx+3:]
	}
	if idx := strings.IndexAny(rest, "/?"); idx != -1 {
		return rest[:idx], rest[idx:]
	}
	return rest, "/"
}
