// CA implements SentryBench's local MITM root certificate: generated once
// per machine, persisted to disk, and used to sign short-lived per-host
// leaf certificates on the fly so the proxy can terminate TLS, record the
// decrypted request/response, and re-encrypt on to the real destination.
//
// This only works once the user explicitly installs and trusts
// ca-cert.pem in their OS/browser trust store — which is the correct
// bar for a MITM capability like this: it requires a deliberate,
// visible, undoable action, never a silent one. The CA private key
// never leaves this machine and is written with 0600 permissions.
package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreateCA loads an existing root CA from dataDir, or generates and
// persists a new one. Call this once at startup and share the result
// across every Proxy instance so the same root (and leaf cert cache)
// survives starting/stopping the proxy.
func LoadOrCreateCA(dataDir string) (*CA, error) {
	certPath := filepath.Join(dataDir, "ca-cert.pem")
	keyPath := filepath.Join(dataDir, "ca-key.pem")

	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err2 := os.ReadFile(keyPath); err2 == nil {
			if ca, err3 := parseCA(certPEM, keyPEM); err3 == nil {
				return ca, nil
			}
			// Fall through to regenerate if the stored files are corrupt —
			// better to mint a new CA (user re-trusts it once) than to
			// crash the core service on a bad file.
		}
	}

	ca, certPEM, keyPEM, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	return ca, nil
}

func generateCA() (*CA, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SentryBench Local Root CA",
			Organization: []string{"SentryBench (generated locally — do not distribute the key)"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return &CA{cert: cert, certPEM: certPEM, key: key, cache: map[string]*tls.Certificate{}}, certPEM, keyPEM, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{cert: cert, certPEM: certPEM, key: key, cache: map[string]*tls.Certificate{}}, nil
}

// CertPEM returns the root CA certificate (not the key) for the user to
// download and trust.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// LeafFor returns a TLS certificate for host (hostname only, no port),
// generating and caching a fresh one signed by the root CA on first use.
func (ca *CA) LeafFor(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cached, ok := ca.cache[host]; ok {
		return cached, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  leafKey,
	}
	ca.cache[host] = tlsCert
	return tlsCert, nil
}
