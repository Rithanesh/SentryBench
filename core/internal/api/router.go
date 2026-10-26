package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	"github.com/sentrybench/core/internal/auth"
	"github.com/sentrybench/core/internal/capture"
	"github.com/sentrybench/core/internal/decompression"
	"github.com/sentrybench/core/internal/jwtutil"
	"github.com/sentrybench/core/internal/models"
	"github.com/sentrybench/core/internal/replay"
	"github.com/sentrybench/core/internal/report"
	"github.com/sentrybench/core/internal/scan"
	"github.com/sentrybench/core/internal/version"
)

type Server struct {
	DB       *sql.DB
	Auth     *auth.Service
	RepoRoot string // for version.Read
	CA       *capture.CA // local MITM root CA; nil disables HTTPS interception

	proxyMu sync.Mutex
	proxy   *capture.Proxy

	// tabProxiesMu/tabProxies back the embedded Browser feature: one
	// short-lived proxy per open tab, each on its own ephemeral port, so
	// concurrent tabs logged in as different users never mix traffic.
	tabProxiesMu sync.Mutex
	tabProxies   map[string]*capture.Proxy
}

// sqlRecorder persists captured traffic into the captured_requests table.
type sqlRecorder struct{ db *sql.DB }

func (r *sqlRecorder) Record(cr models.CapturedRequest) {
	cr.ID = uuid.NewString()
	reqHeaders, _ := json.Marshal(cr.RequestHeaders)
	respHeaders, _ := json.Marshal(cr.ResponseHeaders)
	_, _ = r.db.Exec(
		`INSERT INTO captured_requests (id, workspace_id, tab_id, method, url, host, path, request_headers, request_body, response_status, response_headers, response_body, duration_ms, captured_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cr.ID, cr.WorkspaceID, cr.TabID, cr.Method, cr.URL, cr.Host, cr.Path, string(reqHeaders), cr.RequestBody,
		cr.ResponseStatus, string(respHeaders), cr.ResponseBody, cr.DurationMs, cr.CapturedAt.Format(time.RFC3339),
	)
}

func NewRouter(s *Server) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// Electron renderer talks to this service over localhost only.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:*", "app://*"},
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	r.Get("/health", s.handleHealth)
	r.Get("/version", s.handleVersion)

	r.Post("/auth/register", s.handleRegister)
	r.Post("/auth/login", s.handleLogin)

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Get("/me", s.handleMe)
		r.Get("/workspaces", s.handleListWorkspaces)
		r.Post("/workspaces", s.handleCreateWorkspace)
		r.Patch("/workspaces/{id}", s.handleUpdateWorkspace)
		r.Delete("/workspaces/{id}", s.handleDeleteWorkspace)

		// Identity vault
		r.Get("/workspaces/{id}/identities", s.handleListIdentities)
		r.Post("/workspaces/{id}/identities", s.handleCreateIdentity)
		r.Patch("/identities/{id}", s.handleUpdateIdentity)
		r.Delete("/identities/{id}", s.handleDeleteIdentity)

		// Replay workspace
		r.Get("/workspaces/{id}/requests", s.handleListRequests)
		r.Post("/workspaces/{id}/requests", s.handleCreateRequest)
		r.Patch("/requests/{id}", s.handleUpdateRequest)
		r.Delete("/requests/{id}", s.handleDeleteRequest)
		r.Post("/requests/{id}/send", s.handleSendRequest)
		r.Post("/requests/{id}/send-as-identities", s.handleSendAsIdentities)
		r.Get("/requests/{id}/snippets", s.handleRequestSnippets)

		// Traffic capture (proxy)
		r.Post("/workspaces/{id}/proxy/start", s.handleProxyStart)
		r.Post("/proxy/stop", s.handleProxyStop)
		r.Get("/proxy/status", s.handleProxyStatus)
		r.Get("/proxy/ca-cert", s.handleDownloadCACert)
		r.Get("/workspaces/{id}/traffic", s.handleListTraffic)
		r.Delete("/traffic/{id}", s.handleDeleteTraffic)
		r.Get("/workspaces/{id}/traffic/export", s.handleExportHAR)
		r.Post("/workspaces/{id}/traffic/import", s.handleImportHAR)

		// Embedded Browser: isolated per-tab sessions for logging in as
		// multiple users on the same site and capturing their tokens.
		r.Post("/workspaces/{id}/browser-tabs", s.handleCreateBrowserTab)
		r.Delete("/browser-tabs/{tabId}", s.handleCloseBrowserTab)
		r.Get("/browser-tabs/{tabId}/suggested-identity", s.handleSuggestedIdentity)

		// JWT inspector
		r.Post("/jwt/decode", s.handleJWTDecode)
		r.Post("/jwt/verify", s.handleJWTVerify)
		r.Post("/jwt/check-weak-secret", s.handleJWTWeakSecret)

		// Decompression inspector
		r.Post("/decompression/inspect", s.handleDecompressionInspect)
		r.Post("/decompression/chain", s.handleDecompressionChain)

		// Scanning (passive checks over captured traffic / saved requests)
		r.Post("/workspaces/{id}/scans", s.handleStartScan)
		r.Get("/workspaces/{id}/scans", s.handleListScans)
		r.Get("/workspaces/{id}/findings", s.handleListFindings)

		// Reporting / export
		r.Get("/workspaces/{id}/report", s.handleGenerateReport)
	})

	return r
}

// --- health / version -------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	info, err := version.Read(s.RepoRoot)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read version info")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// --- auth ---------------------------------------------------------------

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || len(req.Password) < 8 || req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "email, displayName, and a password of at least 8 characters are required")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}

	u := models.User{
		ID:           uuid.NewString(),
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		AvatarColor:  pickAvatarColor(req.DisplayName),
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}

	_, err = s.DB.Exec(
		`INSERT INTO users (id, email, display_name, avatar_color, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.DisplayName, u.AvatarColor, u.PasswordHash, u.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		writeError(w, http.StatusConflict, "an account with that email already exists")
		return
	}

	// Give every new user a default workspace, mirroring Postman's "My Workspace".
	ws := models.Workspace{
		ID:        uuid.NewString(),
		OwnerID:   u.ID,
		Name:      "My Workspace",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_, _ = s.DB.Exec(
		`INSERT INTO workspaces (id, owner_id, name, description, target_hosts, created_at, updated_at) VALUES (?, ?, ?, '', '[]', ?, ?)`,
		ws.ID, ws.OwnerID, ws.Name, ws.CreatedAt.Format(time.RFC3339), ws.UpdatedAt.Format(time.RFC3339),
	)

	token, err := s.Auth.IssueToken(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue session token")
		return
	}
	writeJSON(w, http.StatusCreated, models.AuthResponse{Token: token, User: u})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))

	row := s.DB.QueryRow(
		`SELECT id, email, display_name, avatar_color, password_hash, created_at FROM users WHERE email = ?`,
		email,
	)
	var u models.User
	var createdAt string
	if err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.AvatarColor, &u.PasswordHash, &createdAt); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if !auth.CheckPassword(u.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	token, err := s.Auth.IssueToken(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue session token")
		return
	}
	writeJSON(w, http.StatusOK, models.AuthResponse{Token: token, User: u})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxUserID).(string)
	row := s.DB.QueryRow(
		`SELECT id, email, display_name, avatar_color, created_at FROM users WHERE id = ?`,
		userID,
	)
	var u models.User
	var createdAt string
	if err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.AvatarColor, &createdAt); err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	writeJSON(w, http.StatusOK, u)
}

// --- workspaces -----------------------------------------------------------

func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxUserID).(string)
	rows, err := s.DB.Query(
		`SELECT id, owner_id, name, description, target_hosts, created_at, updated_at FROM workspaces WHERE owner_id = ? ORDER BY created_at ASC`,
		userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list workspaces")
		return
	}
	defer rows.Close()

	workspaces := []models.Workspace{}
	for rows.Next() {
		var ws models.Workspace
		var targetHostsJSON, createdAt, updatedAt string
		if err := rows.Scan(&ws.ID, &ws.OwnerID, &ws.Name, &ws.Description, &targetHostsJSON, &createdAt, &updatedAt); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(targetHostsJSON), &ws.TargetHosts)
		ws.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		ws.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		workspaces = append(workspaces, ws)
	}
	writeJSON(w, http.StatusOK, workspaces)
}

type createWorkspaceRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TargetHosts []string `json:"targetHosts"`
}

func (s *Server) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxUserID).(string)
	var req createWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "a workspace name is required")
		return
	}
	hostsJSON, _ := json.Marshal(req.TargetHosts)
	ws := models.Workspace{
		ID:          uuid.NewString(),
		OwnerID:     userID,
		Name:        req.Name,
		Description: req.Description,
		TargetHosts: req.TargetHosts,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	_, err := s.DB.Exec(
		`INSERT INTO workspaces (id, owner_id, name, description, target_hosts, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ws.ID, ws.OwnerID, ws.Name, ws.Description, string(hostsJSON), ws.CreatedAt.Format(time.RFC3339), ws.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create workspace")
		return
	}
	writeJSON(w, http.StatusCreated, ws)
}

func (s *Server) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxUserID).(string)
	id := chi.URLParam(r, "id")

	var req createWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	hostsJSON, _ := json.Marshal(req.TargetHosts)
	res, err := s.DB.Exec(
		`UPDATE workspaces SET name = ?, description = ?, target_hosts = ?, updated_at = ? WHERE id = ? AND owner_id = ?`,
		req.Name, req.Description, string(hostsJSON), time.Now().UTC().Format(time.RFC3339), id, userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update workspace")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxUserID).(string)
	id := chi.URLParam(r, "id")
	_, err := s.DB.Exec(`DELETE FROM workspaces WHERE id = ? AND owner_id = ?`, id, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete workspace")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- identity vault ---------------------------------------------------------

func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	rows, err := s.DB.Query(
		`SELECT id, workspace_id, name, role, auth_type, headers, cookies, created_at FROM identities WHERE workspace_id = ? ORDER BY created_at ASC`,
		workspaceID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list identities")
		return
	}
	defer rows.Close()

	identities := []models.Identity{}
	for rows.Next() {
		var id models.Identity
		var headersJSON, cookiesJSON, createdAt string
		if err := rows.Scan(&id.ID, &id.WorkspaceID, &id.Name, &id.Role, &id.AuthType, &headersJSON, &cookiesJSON, &createdAt); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(headersJSON), &id.Headers)
		_ = json.Unmarshal([]byte(cookiesJSON), &id.Cookies)
		id.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		// Token intentionally omitted from list responses — fetch-by-id (not
		// implemented here) would be the place to reveal it, behind an
		// explicit "reveal secret" action in the UI.
		identities = append(identities, id)
	}
	writeJSON(w, http.StatusOK, identities)
}

type identityRequest struct {
	Name     string            `json:"name"`
	Role     string            `json:"role"`
	AuthType string            `json:"authType"`
	Token    string            `json:"token"`
	Headers  map[string]string `json:"headers"`
	Cookies  map[string]string `json:"cookies"`
}

func (s *Server) handleCreateIdentity(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	var req identityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "a name and authType are required")
		return
	}
	headersJSON, _ := json.Marshal(req.Headers)
	cookiesJSON, _ := json.Marshal(req.Cookies)
	identity := models.Identity{
		ID:          uuid.NewString(),
		WorkspaceID: workspaceID,
		Name:        req.Name,
		Role:        req.Role,
		AuthType:    req.AuthType,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := s.DB.Exec(
		`INSERT INTO identities (id, workspace_id, name, role, auth_type, token, headers, cookies, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		identity.ID, identity.WorkspaceID, identity.Name, identity.Role, identity.AuthType, req.Token, string(headersJSON), string(cookiesJSON), identity.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create identity")
		return
	}
	writeJSON(w, http.StatusCreated, identity) // token withheld from response on purpose
}

func (s *Server) handleUpdateIdentity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req identityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	headersJSON, _ := json.Marshal(req.Headers)
	cookiesJSON, _ := json.Marshal(req.Cookies)
	_, err := s.DB.Exec(
		`UPDATE identities SET name = ?, role = ?, auth_type = ?, token = ?, headers = ?, cookies = ? WHERE id = ?`,
		req.Name, req.Role, req.AuthType, req.Token, string(headersJSON), string(cookiesJSON), id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update identity")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := s.DB.Exec(`DELETE FROM identities WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete identity")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadIdentity(id string) (*models.Identity, string) {
	row := s.DB.QueryRow(`SELECT id, workspace_id, name, role, auth_type, token, headers, cookies, created_at FROM identities WHERE id = ?`, id)
	var ident models.Identity
	var headersJSON, cookiesJSON, createdAt string
	if err := row.Scan(&ident.ID, &ident.WorkspaceID, &ident.Name, &ident.Role, &ident.AuthType, &ident.Token, &headersJSON, &cookiesJSON, &createdAt); err != nil {
		return nil, ""
	}
	_ = json.Unmarshal([]byte(headersJSON), &ident.Headers)
	_ = json.Unmarshal([]byte(cookiesJSON), &ident.Cookies)
	ident.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &ident, ident.WorkspaceID
}

// --- replay workspace (saved requests) --------------------------------------

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	rows, err := s.DB.Query(
		`SELECT id, workspace_id, name, method, url, headers, query, body, identity_id, created_at, updated_at FROM saved_requests WHERE workspace_id = ? ORDER BY created_at ASC`,
		workspaceID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list requests")
		return
	}
	defer rows.Close()

	requests := []models.SavedRequest{}
	for rows.Next() {
		req, err := scanSavedRequest(rows)
		if err != nil {
			continue
		}
		requests = append(requests, req)
	}
	writeJSON(w, http.StatusOK, requests)
}

type savedRequestInput struct {
	Name       string            `json:"name"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Query      map[string]string `json:"query"`
	Body       string            `json:"body"`
	IdentityID *string           `json:"identityId"`
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	var req savedRequestInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.URL) == "" {
		writeError(w, http.StatusBadRequest, "a url is required")
		return
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.Name == "" {
		req.Name = req.Method + " " + req.URL
	}
	headersJSON, _ := json.Marshal(req.Headers)
	queryJSON, _ := json.Marshal(req.Query)

	sr := models.SavedRequest{
		ID:          uuid.NewString(),
		WorkspaceID: workspaceID,
		Name:        req.Name,
		Method:      req.Method,
		URL:         req.URL,
		Headers:     req.Headers,
		Query:       req.Query,
		Body:        req.Body,
		IdentityID:  req.IdentityID,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	_, err := s.DB.Exec(
		`INSERT INTO saved_requests (id, workspace_id, name, method, url, headers, query, body, identity_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sr.ID, sr.WorkspaceID, sr.Name, sr.Method, sr.URL, string(headersJSON), string(queryJSON), sr.Body, sr.IdentityID,
		sr.CreatedAt.Format(time.RFC3339), sr.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create request")
		return
	}
	writeJSON(w, http.StatusCreated, sr)
}

func (s *Server) handleUpdateRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req savedRequestInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	headersJSON, _ := json.Marshal(req.Headers)
	queryJSON, _ := json.Marshal(req.Query)
	_, err := s.DB.Exec(
		`UPDATE saved_requests SET name = ?, method = ?, url = ?, headers = ?, query = ?, body = ?, identity_id = ?, updated_at = ? WHERE id = ?`,
		req.Name, req.Method, req.URL, string(headersJSON), string(queryJSON), req.Body, req.IdentityID, time.Now().UTC().Format(time.RFC3339), id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := s.DB.Exec(`DELETE FROM saved_requests WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSendRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sr, err := s.loadSavedRequest(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	var identity *models.Identity
	if sr.IdentityID != nil {
		identity, _ = s.loadIdentity(*sr.IdentityID)
	}

	result := replay.Send(sr, identity)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSendAsIdentities(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sr, err := s.loadSavedRequest(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	var body struct {
		IdentityIDs []string `json:"identityIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	identities := make([]models.Identity, 0, len(body.IdentityIDs))
	for _, idID := range body.IdentityIDs {
		if ident, _ := s.loadIdentity(idID); ident != nil {
			identities = append(identities, *ident)
		}
	}

	results := replay.SendAsIdentities(sr, identities)
	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleRequestSnippets(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sr, err := s.loadSavedRequest(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"curl":       replay.GenerateCurl(sr),
		"powershell": replay.GeneratePowerShell(sr),
		"python":     replay.GeneratePython(sr),
		"javascript": replay.GenerateJavaScript(sr),
	})
}

func (s *Server) loadSavedRequest(id string) (models.SavedRequest, error) {
	row := s.DB.QueryRow(
		`SELECT id, workspace_id, name, method, url, headers, query, body, identity_id, created_at, updated_at FROM saved_requests WHERE id = ?`,
		id,
	)
	return scanSavedRequest(row)
}

// rowScanner lets scanSavedRequest accept both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSavedRequest(row rowScanner) (models.SavedRequest, error) {
	var sr models.SavedRequest
	var headersJSON, queryJSON, createdAt, updatedAt string
	var identityID sql.NullString
	if err := row.Scan(&sr.ID, &sr.WorkspaceID, &sr.Name, &sr.Method, &sr.URL, &headersJSON, &queryJSON, &sr.Body, &identityID, &createdAt, &updatedAt); err != nil {
		return models.SavedRequest{}, err
	}
	_ = json.Unmarshal([]byte(headersJSON), &sr.Headers)
	_ = json.Unmarshal([]byte(queryJSON), &sr.Query)
	if identityID.Valid {
		sr.IdentityID = &identityID.String
	}
	sr.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	sr.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return sr, nil
}

// --- traffic capture (proxy) -------------------------------------------------

type proxyStartRequest struct {
	Addr            string   `json:"addr"`
	ExcludedDomains []string `json:"excludedDomains"`
	// InterceptHTTPS defaults to true (when a CA is configured): set it to
	// false to run CONNECT-passthrough only, e.g. while the user hasn't
	// trusted the CA yet and wants plain-HTTP capture in the meantime.
	InterceptHTTPS *bool `json:"interceptHttps"`
}

func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	var req proxyStartRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Addr == "" {
		req.Addr = "127.0.0.1:8080"
	}

	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()

	if s.proxy != nil {
		if running, _ := s.proxy.Status(); running {
			writeError(w, http.StatusConflict, "proxy already running — stop it first")
			return
		}
	}

	p := capture.New(req.Addr, workspaceID, &sqlRecorder{db: s.DB})
	p.ExcludedDomains = req.ExcludedDomains
	if req.InterceptHTTPS == nil || *req.InterceptHTTPS {
		p.CA = s.CA // nil CA (shouldn't happen — main.go always loads one) falls back to passthrough
	}
	if err := p.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start proxy: "+err.Error())
		return
	}
	s.proxy = p
	writeJSON(w, http.StatusOK, map[string]string{"status": "started", "addr": req.Addr})
}

func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request) {
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "not running"})
		return
	}
	_ = s.proxy.Stop()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"running": false, "paused": false})
		return
	}
	running, paused := s.proxy.Status()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"running":        running,
		"paused":         paused,
		"addr":           s.proxy.Addr,
		"interceptHttps": s.proxy.CA != nil,
	})
}

func (s *Server) handleDownloadCACert(w http.ResponseWriter, r *http.Request) {
	if s.CA == nil {
		writeError(w, http.StatusNotFound, "no CA configured on this core service")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"sentrybench-ca.pem\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.CA.CertPEM())
}

func (s *Server) handleListTraffic(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	traffic := s.loadTraffic(workspaceID)
	if traffic == nil {
		traffic = []models.CapturedRequest{}
	}
	// Most-recent-first for the UI; loadTraffic (shared with HAR export,
	// which wants chronological order) returns oldest-first.
	for i, j := 0, len(traffic)-1; i < j; i, j = i+1, j-1 {
		traffic[i], traffic[j] = traffic[j], traffic[i]
	}
	if len(traffic) > 500 {
		traffic = traffic[:500]
	}
	writeJSON(w, http.StatusOK, traffic)
}

func (s *Server) handleDeleteTraffic(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := s.DB.Exec(`DELETE FROM captured_requests WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- HAR export / import --------------------------------------------------------

func (s *Server) handleExportHAR(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	traffic := s.loadTraffic(workspaceID)

	body, err := capture.WriteHAR(traffic)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate HAR: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"sentrybench-traffic.har\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleImportHAR(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20) // 50MB cap on an imported HAR file
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}

	entries, err := capture.ParseHAR(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	recorder := &sqlRecorder{db: s.DB}
	for i := range entries {
		entries[i].WorkspaceID = workspaceID
		recorder.Record(entries[i])
	}

	writeJSON(w, http.StatusOK, map[string]int{"imported": len(entries)})
}

func (s *Server) loadTraffic(workspaceID string) []models.CapturedRequest {
	rows, err := s.DB.Query(
		`SELECT id, workspace_id, tab_id, method, url, host, path, request_headers, request_body, response_status, response_headers, response_body, duration_ms, captured_at
		 FROM captured_requests WHERE workspace_id = ? ORDER BY captured_at ASC`,
		workspaceID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var traffic []models.CapturedRequest
	for rows.Next() {
		var cr models.CapturedRequest
		var reqHeaders, respHeaders, capturedAt string
		var tabID sql.NullString
		if err := rows.Scan(&cr.ID, &cr.WorkspaceID, &tabID, &cr.Method, &cr.URL, &cr.Host, &cr.Path, &reqHeaders, &cr.RequestBody, &cr.ResponseStatus, &respHeaders, &cr.ResponseBody, &cr.DurationMs, &capturedAt); err != nil {
			continue
		}
		if tabID.Valid {
			cr.TabID = &tabID.String
		}
		_ = json.Unmarshal([]byte(reqHeaders), &cr.RequestHeaders)
		_ = json.Unmarshal([]byte(respHeaders), &cr.ResponseHeaders)
		cr.CapturedAt, _ = time.Parse(time.RFC3339, capturedAt)
		traffic = append(traffic, cr)
	}
	return traffic
}

// --- embedded browser tabs ------------------------------------------------------

func (s *Server) handleCreateBrowserTab(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	var body struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	tabID := uuid.NewString()
	p := capture.New("127.0.0.1:0", workspaceID, &sqlRecorder{db: s.DB})
	p.TabID = tabID
	p.CA = s.CA // same MITM CA as the main proxy — one cert to trust covers both
	if err := p.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start tab proxy: "+err.Error())
		return
	}

	s.tabProxiesMu.Lock()
	if s.tabProxies == nil {
		s.tabProxies = map[string]*capture.Proxy{}
	}
	s.tabProxies[tabID] = p
	s.tabProxiesMu.Unlock()

	writeJSON(w, http.StatusCreated, models.BrowserTab{
		ID:          tabID,
		WorkspaceID: workspaceID,
		ProxyAddr:   p.Addr,
		Label:       body.Label,
		CreatedAt:   time.Now().UTC(),
	})
}

func (s *Server) handleCloseBrowserTab(w http.ResponseWriter, r *http.Request) {
	tabID := chi.URLParam(r, "tabId")

	s.tabProxiesMu.Lock()
	p, ok := s.tabProxies[tabID]
	if ok {
		delete(s.tabProxies, tabID)
	}
	s.tabProxiesMu.Unlock()

	if ok {
		_ = p.Stop()
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSuggestedIdentity scans everything captured on this tab's proxy
// and returns candidate credentials — an Authorization header, a
// JWT-looking value anywhere, or cookies that look session-like — for the
// user to review. Nothing here is saved as an Identity automatically;
// this only ever proposes candidates.
func (s *Server) handleSuggestedIdentity(w http.ResponseWriter, r *http.Request) {
	tabID := chi.URLParam(r, "tabId")

	rows, err := s.DB.Query(
		`SELECT url, request_headers, response_headers, captured_at FROM captured_requests WHERE tab_id = ? ORDER BY captured_at DESC LIMIT 200`,
		tabID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read tab traffic")
		return
	}
	defer rows.Close()

	seen := map[string]bool{} // dedupe identical (name, value) candidates
	var candidates []models.TokenCandidate

	for rows.Next() {
		var url, reqHeadersJSON, respHeadersJSON, capturedAt string
		if err := rows.Scan(&url, &reqHeadersJSON, &respHeadersJSON, &capturedAt); err != nil {
			continue
		}
		seenAt, _ := time.Parse(time.RFC3339, capturedAt)

		var reqHeaders, respHeaders map[string]string
		_ = json.Unmarshal([]byte(reqHeadersJSON), &reqHeaders)
		_ = json.Unmarshal([]byte(respHeadersJSON), &respHeaders)

		// 1. An Authorization header the browser sent — the strongest
		// signal: this is a token the site itself issued and is using.
		if auth, ok := headerCI(reqHeaders, "Authorization"); ok && auth != "" {
			addCandidate(&candidates, seen, models.TokenCandidate{
				Source: "header", Name: "Authorization", Value: auth,
				SuggestedAuthType: "bearer", IsJWT: looksLikeJWT(auth), SeenAt: seenAt, FromURL: url,
			})
		}
		// 2. Custom API-key-shaped request headers.
		for name, value := range reqHeaders {
			if apiKeyHeaderPattern.MatchString(name) && value != "" {
				addCandidate(&candidates, seen, models.TokenCandidate{
					Source: "header", Name: name, Value: value,
					SuggestedAuthType: "apiKey", IsJWT: looksLikeJWT(value), SeenAt: seenAt, FromURL: url,
				})
			}
		}
		// 3. Cookies the server set that look session/auth-related.
		if setCookie, ok := headerCI(respHeaders, "Set-Cookie"); ok {
			for _, name := range sessionCookiePattern.FindAllString(setCookie, -1) {
				addCandidate(&candidates, seen, models.TokenCandidate{
					Source: "cookie", Name: strings.TrimSuffix(name, "="), Value: extractCookieValue(setCookie, name),
					SuggestedAuthType: "cookie", SeenAt: seenAt, FromURL: url,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, candidates)
}

var apiKeyHeaderPattern = regexp.MustCompile(`(?i)^x-(api-?key|auth-?token|access-?token)$`)
var sessionCookiePattern = regexp.MustCompile(`(?i)(session[a-z_-]*|auth[a-z_-]*|token|jwt|sid)=`)

func headerCI(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func looksLikeJWT(s string) bool {
	s = strings.TrimPrefix(s, "Bearer ")
	return strings.Count(s, ".") == 2 && strings.HasPrefix(strings.TrimSpace(s), "eyJ")
}

func extractCookieValue(setCookie, nameEquals string) string {
	idx := strings.Index(setCookie, nameEquals)
	if idx == -1 {
		return ""
	}
	rest := setCookie[idx+len(nameEquals):]
	if semi := strings.Index(rest, ";"); semi != -1 {
		rest = rest[:semi]
	}
	return rest
}

func addCandidate(list *[]models.TokenCandidate, seen map[string]bool, c models.TokenCandidate) {
	key := c.Name + "\x00" + c.Value
	if seen[key] {
		return
	}
	seen[key] = true
	*list = append(*list, c)
}

// --- JWT inspector ------------------------------------------------------------

func (s *Server) handleJWTDecode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	decoded, err := jwtutil.Decode(strings.TrimSpace(body.Token))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, decoded)
}

func (s *Server) handleJWTVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token     string `json:"token"`
		Algorithm string `json:"algorithm"` // HS256/384/512, RS256/384/512, ES256/384/512
		Secret    string `json:"secret,omitempty"`
		PublicKey string `json:"publicKeyPem,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	switch {
	case strings.HasPrefix(body.Algorithm, "HS"):
		writeJSON(w, http.StatusOK, jwtutil.VerifyHMAC(body.Token, body.Secret))
	case strings.HasPrefix(body.Algorithm, "RS"):
		key, err := parseRSAPublicKeyPEM(body.PublicKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid RSA public key: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, jwtutil.VerifyRSA(body.Token, key))
	case strings.HasPrefix(body.Algorithm, "ES"):
		key, err := parseECDSAPublicKeyPEM(body.PublicKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ECDSA public key: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, jwtutil.VerifyECDSA(body.Token, key))
	default:
		writeError(w, http.StatusBadRequest, "unsupported or missing algorithm")
	}
}

func (s *Server) handleJWTWeakSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token      string   `json:"token"`
		Candidates []string `json:"candidates"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(body.Candidates) == 0 {
		writeError(w, http.StatusBadRequest, "candidates wordlist is required — this check only runs against a list you supply")
		return
	}
	writeJSON(w, http.StatusOK, jwtutil.CheckWeakSecret(body.Token, body.Candidates))
}

// --- decompression inspector --------------------------------------------------

func (s *Server) handleDecompressionInspect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Method string `json:"method"`
		Input  string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Method == "" {
		guesses := decompression.Detect(body.Input)
		writeJSON(w, http.StatusOK, map[string]interface{}{"detected": guesses})
		return
	}
	writeJSON(w, http.StatusOK, decompression.Apply(decompression.Method(body.Method), body.Input))
}

func (s *Server) handleDecompressionChain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Methods []string `json:"methods"`
		Input   string   `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	methods := make([]decompression.Method, len(body.Methods))
	for i, m := range body.Methods {
		methods[i] = decompression.Method(m)
	}
	writeJSON(w, http.StatusOK, decompression.Chain(methods, body.Input))
}

// --- scanning ------------------------------------------------------------------

type startScanRequest struct {
	Source string `json:"source"` // "traffic" | "requests" | "both" — defaults to "traffic"
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	var req startScanRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Source == "" {
		req.Source = "traffic"
	}

	scanRow := models.Scan{
		ID:          uuid.NewString(),
		WorkspaceID: workspaceID,
		Status:      "running",
		Source:      req.Source,
		StartedAt:   time.Now().UTC(),
	}
	_, err := s.DB.Exec(
		`INSERT INTO scans (id, workspace_id, status, source, findings_count, started_at, completed_at, error) VALUES (?, ?, ?, ?, 0, ?, NULL, '')`,
		scanRow.ID, scanRow.WorkspaceID, scanRow.Status, scanRow.Source, scanRow.StartedAt.Format(time.RFC3339),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create scan")
		return
	}

	// Runs in the background: "requests"/"both" sources send one live
	// request per saved request, which on a slow or rate-limited target
	// can take a while — blocking the HTTP response on that would make the
	// UI look hung and risks the client timing out the request entirely.
	// The frontend polls GET /workspaces/{id}/scans (status flips from
	// "running" to "completed"/"failed") instead of waiting on this call.
	go s.runScan(scanRow.ID, workspaceID, req.Source)

	writeJSON(w, http.StatusAccepted, scanRow)
}

func (s *Server) runScan(scanID, workspaceID, source string) {
	defer func() {
		if r := recover(); r != nil {
			_, _ = s.DB.Exec(`UPDATE scans SET status = 'failed', error = ? WHERE id = ?`, fmt.Sprintf("panic: %v", r), scanID)
		}
	}()

	var subjects []scan.Subject
	if source == "traffic" || source == "both" {
		subjects = append(subjects, s.subjectsFromTraffic(workspaceID)...)
	}
	if source == "requests" || source == "both" {
		subjects = append(subjects, s.subjectsFromSavedRequests(workspaceID)...)
	}

	findings := scan.Run(subjects)
	now := time.Now().UTC()
	for i := range findings {
		findings[i].ID = uuid.NewString()
		findings[i].WorkspaceID = workspaceID
		findings[i].ScanID = scanID
		findings[i].CreatedAt = now
		s.insertFinding(findings[i])
	}

	_, _ = s.DB.Exec(
		`UPDATE scans SET status = 'completed', findings_count = ?, completed_at = ? WHERE id = ?`,
		len(findings), now.Format(time.RFC3339), scanID,
	)
}

func (s *Server) subjectsFromTraffic(workspaceID string) []scan.Subject {
	rows, err := s.DB.Query(
		`SELECT method, url, request_headers, request_body, response_status, response_headers, response_body FROM captured_requests WHERE workspace_id = ? ORDER BY captured_at DESC LIMIT 500`,
		workspaceID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var subjects []scan.Subject
	for rows.Next() {
		var subj scan.Subject
		var reqHeadersJSON, respHeadersJSON string
		if err := rows.Scan(&subj.Method, &subj.URL, &reqHeadersJSON, &subj.RequestBody, &subj.ResponseStatus, &respHeadersJSON, &subj.ResponseBody); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(reqHeadersJSON), &subj.RequestHeaders)
		_ = json.Unmarshal([]byte(respHeadersJSON), &subj.ResponseHeaders)
		subjects = append(subjects, subj)
	}
	return subjects
}

func (s *Server) subjectsFromSavedRequests(workspaceID string) []scan.Subject {
	rows, err := s.DB.Query(
		`SELECT id FROM saved_requests WHERE workspace_id = ?`,
		workspaceID,
	)
	if err != nil {
		return nil
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	var subjects []scan.Subject
	for _, id := range ids {
		sr, err := s.loadSavedRequest(id)
		if err != nil {
			continue
		}
		var identity *models.Identity
		if sr.IdentityID != nil {
			identity, _ = s.loadIdentity(*sr.IdentityID)
		}
		result := replay.Send(sr, identity)
		if result.Error != "" {
			continue
		}
		subjects = append(subjects, scan.Subject{
			Method:          sr.Method,
			URL:             sr.URL,
			RequestHeaders:  sr.Headers,
			RequestBody:     sr.Body,
			ResponseStatus:  result.Status,
			ResponseHeaders: result.Headers,
			ResponseBody:    result.Body,
		})
	}
	return subjects
}

func (s *Server) insertFinding(f models.Finding) {
	_, _ = s.DB.Exec(
		`INSERT INTO findings (id, workspace_id, scan_id, check_id, title, severity, description, evidence, method, url, remediation, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.WorkspaceID, f.ScanID, f.CheckID, f.Title, f.Severity, f.Description, f.Evidence, f.Method, f.URL, f.Remediation, f.CreatedAt.Format(time.RFC3339),
	)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	rows, err := s.DB.Query(
		`SELECT id, workspace_id, status, source, findings_count, started_at, completed_at, error FROM scans WHERE workspace_id = ? ORDER BY started_at DESC`,
		workspaceID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list scans")
		return
	}
	defer rows.Close()

	scans := []models.Scan{}
	for rows.Next() {
		var sc models.Scan
		var startedAt string
		var completedAt sql.NullString
		if err := rows.Scan(&sc.ID, &sc.WorkspaceID, &sc.Status, &sc.Source, &sc.FindingsCount, &startedAt, &completedAt, &sc.Error); err != nil {
			continue
		}
		sc.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			sc.CompletedAt = &t
		}
		scans = append(scans, sc)
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	scanID := r.URL.Query().Get("scanId")

	query := `SELECT id, workspace_id, scan_id, check_id, title, severity, description, evidence, method, url, remediation, created_at FROM findings WHERE workspace_id = ?`
	args := []interface{}{workspaceID}
	if scanID != "" {
		query += ` AND scan_id = ?`
		args = append(args, scanID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list findings")
		return
	}
	defer rows.Close()

	findings, err := scanFindings(rows)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read findings")
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func scanFindings(rows *sql.Rows) ([]models.Finding, error) {
	findings := []models.Finding{}
	for rows.Next() {
		var f models.Finding
		var createdAt string
		if err := rows.Scan(&f.ID, &f.WorkspaceID, &f.ScanID, &f.CheckID, &f.Title, &f.Severity, &f.Description, &f.Evidence, &f.Method, &f.URL, &f.Remediation, &createdAt); err != nil {
			return nil, err
		}
		f.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		findings = append(findings, f)
	}
	return findings, nil
}

// --- reporting / export ---------------------------------------------------------

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "id")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	var ws models.Workspace
	row := s.DB.QueryRow(`SELECT id, owner_id, name, description, created_at FROM workspaces WHERE id = ?`, workspaceID)
	var createdAt string
	if err := row.Scan(&ws.ID, &ws.OwnerID, &ws.Name, &ws.Description, &createdAt); err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}
	ws.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	rows, err := s.DB.Query(
		`SELECT id, workspace_id, scan_id, check_id, title, severity, description, evidence, method, url, remediation, created_at FROM findings WHERE workspace_id = ? ORDER BY created_at DESC`,
		workspaceID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load findings")
		return
	}
	findings, err := scanFindings(rows)
	rows.Close()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read findings")
		return
	}

	data := report.Data{Workspace: ws, Findings: findings, GeneratedAt: time.Now().UTC()}

	var (
		body        []byte
		contentType string
		filename    string
	)
	switch format {
	case "json":
		body, err = report.GenerateJSON(data)
		contentType, filename = "application/json", "sentrybench-report.json"
	case "csv":
		body, err = report.GenerateCSV(data)
		contentType, filename = "text/csv", "sentrybench-report.csv"
	case "html":
		body, err = report.GenerateHTML(data)
		contentType, filename = "text/html", "sentrybench-report.html"
	default:
		writeError(w, http.StatusBadRequest, "format must be one of: json, csv, html")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate report: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// --- helpers --------------------------------------------------------------

type contextKey string

const ctxUserID contextKey = "userID"

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		userID, err := s.Auth.VerifyToken(tokenStr)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func pickAvatarColor(seed string) string {
	palette := []string{"#6366f1", "#ec4899", "#14b8a6", "#f59e0b", "#8b5cf6", "#22c55e"}
	sum := 0
	for _, c := range seed {
		sum += int(c)
	}
	return palette[sum%len(palette)]
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func parseRSAPublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := pub.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PEM block is not an RSA public key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	return nil, fmt.Errorf("could not parse RSA public key")
}

func parseECDSAPublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM block is not an ECDSA public key")
	}
	return ecKey, nil
}
