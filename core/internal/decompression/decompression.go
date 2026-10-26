// Package decompression implements the Decompression Inspector: a chain of
// reversible transforms (decode a layer, show the result, optionally feed it
// into the next layer). Nothing here ever executes decoded content — it is
// treated as inert bytes/text throughout.
package decompression

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type Method string

const (
	MethodGzip        Method = "gzip"
	MethodDeflate     Method = "deflate"
	MethodZlib        Method = "zlib"
	MethodBrotli      Method = "brotli"
	MethodZstd        Method = "zstd"
	MethodBase64      Method = "base64"
	MethodBase64URL   Method = "base64url"
	MethodURLDecode   Method = "urldecode"
	MethodHexDecode   Method = "hexdecode"
	MethodJSONPretty  Method = "json-pretty"
	MethodJSONMinify  Method = "json-minify"
)

type StepResult struct {
	Method         Method `json:"method"`
	OutputPreview  string `json:"outputPreview"` // truncated for UI
	OutputFull     string `json:"outputFull"`
	InputSize      int    `json:"inputSize"`
	OutputSize     int    `json:"outputSize"`
	Error          string `json:"error,omitempty"`
}

const previewLimit = 2000

// Apply runs a single transform step on input.
func Apply(method Method, input string) StepResult {
	res := StepResult{Method: method, InputSize: len(input)}

	out, err := apply(method, input)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	res.OutputFull = out
	res.OutputSize = len(out)
	if len(out) > previewLimit {
		res.OutputPreview = out[:previewLimit] + "... (truncated)"
	} else {
		res.OutputPreview = out
	}
	return res
}

// Chain runs an ordered list of methods, feeding each step's output into the next.
func Chain(methods []Method, input string) []StepResult {
	results := make([]StepResult, 0, len(methods))
	current := input
	for _, m := range methods {
		step := Apply(m, current)
		results = append(results, step)
		if step.Error != "" {
			break
		}
		current = step.OutputFull
	}
	return results
}

func apply(method Method, input string) (string, error) {
	switch method {
	case MethodGzip:
		r, err := gzip.NewReader(strings.NewReader(input))
		if err != nil {
			return "", fmt.Errorf("gzip: %w", err)
		}
		defer r.Close()
		b, err := io.ReadAll(r)
		return string(b), err

	case MethodDeflate:
		r := flate.NewReader(strings.NewReader(input))
		defer r.Close()
		b, err := io.ReadAll(r)
		return string(b), err

	case MethodZlib:
		r, err := zlib.NewReader(strings.NewReader(input))
		if err != nil {
			return "", fmt.Errorf("zlib: %w", err)
		}
		defer r.Close()
		b, err := io.ReadAll(r)
		return string(b), err

	case MethodBrotli:
		r := brotli.NewReader(strings.NewReader(input))
		b, err := io.ReadAll(r)
		return string(b), err

	case MethodZstd:
		r, err := zstd.NewReader(strings.NewReader(input))
		if err != nil {
			return "", fmt.Errorf("zstd: %w", err)
		}
		defer r.Close()
		b, err := io.ReadAll(r)
		return string(b), err

	case MethodBase64:
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
		if err != nil {
			// Try padding-less / raw variants before giving up.
			b, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(input))
		}
		return string(b), err

	case MethodBase64URL:
		b, err := base64.URLEncoding.DecodeString(strings.TrimSpace(input))
		if err != nil {
			b, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(input))
		}
		return string(b), err

	case MethodURLDecode:
		s, err := url.QueryUnescape(input)
		return s, err

	case MethodHexDecode:
		b, err := hex.DecodeString(strings.TrimSpace(input))
		return string(b), err

	case MethodJSONPretty:
		var v interface{}
		if err := json.Unmarshal([]byte(input), &v); err != nil {
			return "", fmt.Errorf("invalid JSON: %w", err)
		}
		b, err := json.MarshalIndent(v, "", "  ")
		return string(b), err

	case MethodJSONMinify:
		var v interface{}
		if err := json.Unmarshal([]byte(input), &v); err != nil {
			return "", fmt.Errorf("invalid JSON: %w", err)
		}
		b, err := json.Marshal(v)
		return string(b), err

	default:
		return "", fmt.Errorf("unknown method: %s", method)
	}
}

// Detect offers a best-effort guess at applicable methods, used by the UI's
// "auto-detect" button. It never silently applies a guess — the caller
// still has to confirm it.
func Detect(input string) []Method {
	trimmed := strings.TrimSpace(input)
	var guesses []Method

	if len(trimmed) >= 2 && trimmed[0] == '{' || len(trimmed) >= 2 && trimmed[0] == '[' {
		guesses = append(guesses, MethodJSONPretty)
	}
	if isLikelyBase64(trimmed) {
		guesses = append(guesses, MethodBase64)
	}
	if isLikelyHex(trimmed) {
		guesses = append(guesses, MethodHexDecode)
	}
	if strings.Contains(trimmed, "%") {
		guesses = append(guesses, MethodURLDecode)
	}
	if bytes.HasPrefix([]byte(trimmed), []byte{0x1f, 0x8b}) {
		guesses = append(guesses, MethodGzip)
	}
	return guesses
}

func isLikelyBase64(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

func isLikelyHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}
