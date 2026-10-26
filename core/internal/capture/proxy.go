// Package capture implements the local intercepting proxy used for traffic
// capture (implementation-plan.md §6.1).
//
// Plain HTTP requests routed through the proxy are captured directly.
// HTTPS requests are intercepted by terminating TLS at the proxy using a
// leaf certificate signed by the local root CA (see ca.go), decrypting
// the request/response for capture, then re-encrypting on to the real
// destination — standard MITM-proxy design (mitmproxy, Burp, Charles all
// work this way). This only decrypts traffic from clients that have been
// pointed at this proxy AND told to trust ca-cert.pem; everything else is
// unaffected. If no CA is configured on the Proxy (CA == nil), or a host
// is in ExcludedDomains, HTTPS falls back to a plain CONNECT tunnel with
// no inspection.
package capture

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sentrybench/core/internal/models"
)

// Recorder is implemented by whatever should persist/broadcast captured
// traffic (the SQLite-backed store, plus a websocket broadcaster for live
// updates in milestone work beyond this slice).
type Recorder interface {
	Record(models.CapturedRequest)
}

type Proxy struct {
	Addr            string
	WorkspaceID     string
	// TabID, when set, tags every captured request with the originating
	// Browser tab (see cmd/workbench's browser-tabs endpoints) so traffic
	// from logging in as different users in different tabs stays
	// attributable instead of mixing into one workspace-wide stream.
	TabID           string
	Recorder        Recorder
	ExcludedDomains []string

	// CA, when set, enables HTTPS interception: a leaf certificate signed
	// by this CA is presented to the client for each intercepted host.
	// Leave nil to fall back to CONNECT passthrough (no HTTPS capture).
	CA *CA

	mu      sync.Mutex
	server  *http.Server
	paused  bool
	running bool
}

func New(addr, workspaceID string, recorder Recorder) *Proxy {
	return &Proxy{Addr: addr, WorkspaceID: workspaceID, Recorder: recorder}
}

func (p *Proxy) Status() (running, paused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running, p.paused
}

func (p *Proxy) SetPaused(paused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = paused
}

func (p *Proxy) isPaused() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paused
}

// Start binds the proxy's listener synchronously — so that if Addr ends in
// ":0" (an ephemeral port, used for per-tab proxies), p.Addr reflects the
// actual assigned port by the time Start returns, and callers never race
// trying to read it — then serves in the background.
func (p *Proxy) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}

	listener, err := net.Listen("tcp", p.Addr)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	p.Addr = listener.Addr().String()
	p.server = &http.Server{Handler: http.HandlerFunc(p.handle)}
	p.running = true
	srv := p.server
	p.mu.Unlock()

	go srv.Serve(listener) //nolint:errcheck — Stop() closes it deliberately
	return nil
}

func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running || p.server == nil {
		return nil
	}
	err := p.server.Close()
	p.running = false
	return err
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

func (p *Proxy) isExcluded(host string) bool {
	for _, d := range p.ExcludedDomains {
		if strings.Contains(host, d) {
			return true
		}
	}
	return false
}

// handleConnect decides between MITM interception and plain tunneling.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.CA == nil || p.isExcluded(r.Host) {
		p.passthroughTunnel(w, r)
		return
	}
	p.mitmTunnel(w, r)
}

// passthroughTunnel relays bytes between client and destination
// uninspected — used when no CA is configured, or a host is excluded.
func (p *Proxy) passthroughTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		destConn.Close()
		return
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// mitmTunnel terminates TLS at the proxy using a CA-signed leaf cert for
// the requested host, decrypts each request/response for capture, and
// forwards on to the real destination over its own TLS connection.
func (p *Proxy) mitmTunnel(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		return
	}

	hostname := r.Host
	if h, _, splitErr := net.SplitHostPort(r.Host); splitErr == nil {
		hostname = h
	}

	leaf, err := p.CA.LeafFor(hostname)
	if err != nil {
		clientConn.Close()
		return
	}

	tlsClientConn := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	defer tlsClientConn.Close()
	if err := tlsClientConn.Handshake(); err != nil {
		// Most commonly: the client doesn't trust our CA yet. Nothing
		// useful to record — the handshake itself carries no application
		// data — so just close.
		return
	}

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // tunnel closed or client done
		}
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		shouldClose := req.Close
		p.proxyAndRecord(tlsClientConn, req, r.Host)
		if shouldClose {
			return
		}
	}
}

// proxyAndRecord forwards a decrypted (or plain-HTTP) request to its real
// destination, writes the response back to dst, and records the pair.
func (p *Proxy) proxyAndRecord(dst io.Writer, req *http.Request, host string) {
	paused := p.isPaused() || p.isExcluded(host)
	start := time.Now()

	reqBody, _ := io.ReadAll(req.Body)
	req.Body.Close()

	outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(reqBody))
	if err != nil {
		return
	}
	outReq.Header = req.Header.Clone()
	// ReadRequest leaves Host unset on outReq's URL in some edge cases;
	// RoundTrip needs it on the request itself for the TLS SNI/Host header.
	outReq.Host = req.Host

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	resp.Header.Del("Content-Encoding") // body above is already decompressed by the transport
	_ = resp.Write(dst)

	if !paused && p.Recorder != nil {
		p.Recorder.Record(models.CapturedRequest{
			WorkspaceID:     p.WorkspaceID,
			TabID:           tabIDPtr(p.TabID),
			Method:          req.Method,
			URL:             req.URL.String(),
			Host:            host,
			Path:            req.URL.Path,
			RequestHeaders:  flattenHeader(req.Header),
			RequestBody:     string(reqBody),
			ResponseStatus:  resp.StatusCode,
			ResponseHeaders: flattenHeader(resp.Header),
			ResponseBody:    string(respBody),
			DurationMs:      time.Since(start).Milliseconds(),
			CapturedAt:      time.Now().UTC(),
		})
	}
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

// handlePlainHTTP handles a non-CONNECT request made directly through the
// proxy (plain HTTP, no TLS involved at all).
func (p *Proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	paused := p.isPaused() || p.isExcluded(r.Host)
	start := time.Now()

	reqBody, _ := io.ReadAll(r.Body)
	r.Body.Close()

	outReq, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	outReq.Header = r.Header.Clone()

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	if !paused && p.Recorder != nil {
		p.Recorder.Record(models.CapturedRequest{
			WorkspaceID:     p.WorkspaceID,
			TabID:           tabIDPtr(p.TabID),
			Method:          r.Method,
			URL:             r.URL.String(),
			Host:            r.Host,
			Path:            r.URL.Path,
			RequestHeaders:  flattenHeader(r.Header),
			RequestBody:     string(reqBody),
			ResponseStatus:  resp.StatusCode,
			ResponseHeaders: flattenHeader(resp.Header),
			ResponseBody:    string(respBody),
			DurationMs:      time.Since(start).Milliseconds(),
			CapturedAt:      time.Now().UTC(),
		})
	}
}

func tabIDPtr(tabID string) *string {
	if tabID == "" {
		return nil
	}
	return &tabID
}

func flattenHeader(h http.Header) map[string]string {
	out := map[string]string{}
	for k := range h {
		out[k] = h.Get(k)
	}
	return out
}
