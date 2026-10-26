// Command workbench is the SentryBench core service: a localhost-only Go
// HTTP API that the Electron desktop app talks to. It currently serves
// health/version plus login, profiles, and workspaces. Traffic capture,
// replay, identities, JWT, decompression, and scanning modules attach to
// the same router as they're implemented — see README.md.
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sentrybench/core/internal/api"
	"github.com/sentrybench/core/internal/auth"
	"github.com/sentrybench/core/internal/capture"
	"github.com/sentrybench/core/internal/database"
)

func main() {
	// In a packaged build, Electron sets these two env vars when it spawns
	// this binary (see apps/desktop/electron/main.ts):
	//   SENTRYBENCH_RESOURCES_DIR — where VERSION/CHANGELOG.md were bundled
	//   as extraResources alongside this binary, so /version keeps working
	//   after packaging instead of only in a git checkout.
	//   SENTRYBENCH_DATA_DIR — a writable, per-user directory
	//   (app.getPath("userData")) for the SQLite DB and session key, since
	//   a signed/notarized app's own install directory is read-only.
	// Without them (plain `go run ./cmd/workbench` in dev), both fall back
	// to walking up from the working directory for VERSION, matching the
	// pre-packaging behavior.
	versionDir := os.Getenv("SENTRYBENCH_RESOURCES_DIR")
	if versionDir == "" {
		versionDir = findRepoRoot()
	}

	dataDir := os.Getenv("SENTRYBENCH_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join(findRepoRoot(), ".sentrybench")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("could not create data dir: %v", err)
	}

	db, err := database.Open(filepath.Join(dataDir, "sentrybench.db"))
	if err != nil {
		log.Fatalf("could not open database: %v", err)
	}
	defer db.Close()

	secret, err := loadOrCreateSessionSecret(dataDir)
	if err != nil {
		log.Fatalf("could not load session secret: %v", err)
	}

	// The MITM root CA is loaded (or generated, on first run) once here and
	// shared across every proxy start/stop in this process, so its cache of
	// per-host leaf certs — and the CA itself — survive the user toggling
	// the proxy on and off. It only actually intercepts HTTPS once the user
	// downloads ca-cert.pem (GET /proxy/ca-cert) and trusts it themselves.
	ca, err := capture.LoadOrCreateCA(dataDir)
	if err != nil {
		log.Fatalf("could not load/create MITM CA: %v", err)
	}

	srv := &api.Server{
		DB:       db,
		Auth:     auth.NewService(secret),
		RepoRoot: versionDir,
		CA:       ca,
	}
	router := api.NewRouter(srv)

	addr := "127.0.0.1:4317"
	if v := os.Getenv("SENTRYBENCH_CORE_ADDR"); v != "" {
		addr = v
	}

	log.Printf("sentrybench-core: data dir %s, version dir %s", dataDir, versionDir)
	log.Printf("sentrybench-core listening on http://%s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatal(err)
	}
}

// findRepoRoot walks up from the binary's working directory looking for
// VERSION, so `go run ./cmd/workbench` from core/ still finds the repo
// root for version.Read and the SQLite data directory.
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "VERSION")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// loadOrCreateSessionSecret keeps a 32-byte random JWT signing key in
// dataDir/session.key (0600). In a later milestone this moves into the OS
// keychain via go-keyring, per the plan's secrets-storage requirement.
func loadOrCreateSessionSecret(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "session.key")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("write secret: %w", err)
	}
	return secret, nil
}
