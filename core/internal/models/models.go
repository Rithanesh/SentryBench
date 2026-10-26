package models

import "time"

// User is a local account. Passwords are never stored in plaintext — only
// PasswordHash (bcrypt) is persisted.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"displayName"`
	AvatarColor  string    `json:"avatarColor"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

// Workspace is a Postman-style container a user works in. A user can belong
// to / own several workspaces and switch between them from the UI.
type Workspace struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"ownerId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	TargetHosts []string  `json:"targetHosts"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// AuthResponse is returned by /auth/register and /auth/login.
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// Identity is a stored credential set — a user, role, API key, or token —
// used to replay requests "as" someone for authorization testing.
// Token/cookie/header values are the secret fields: redacted in list views,
// never logged, and destined for the OS keychain rather than plain SQLite
// once secrets storage (core/internal/secrets) lands.
type Identity struct {
	ID          string            `json:"id"`
	WorkspaceID string            `json:"workspaceId"`
	Name        string            `json:"name"`
	Role        string            `json:"role"`
	AuthType    string            `json:"authType"` // bearer | apiKey | cookie | basic | custom | none
	Token       string            `json:"token,omitempty"`
	Headers     map[string]string `json:"headers"`
	Cookies     map[string]string `json:"cookies"`
	CreatedAt   time.Time         `json:"createdAt"`
}

// SavedRequest is a user-curated, editable request — the Postman-style
// collection entry.
type SavedRequest struct {
	ID          string            `json:"id"`
	WorkspaceID string            `json:"workspaceId"`
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Query       map[string]string `json:"query"`
	Body        string            `json:"body"`
	IdentityID  *string           `json:"identityId"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

// RequestResult is what sending a SavedRequest returns.
type RequestResult struct {
	Status          int               `json:"status"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	DurationMs      int64             `json:"durationMs"`
	SizeBytes       int               `json:"sizeBytes"`
	IdentityID      *string           `json:"identityId,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// Severity levels for Finding, ordered low to high.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding is one issue a scan check raised against a piece of captured
// traffic or a saved request/response pair.
type Finding struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspaceId"`
	ScanID      string    `json:"scanId"`
	CheckID     string    `json:"checkId"`   // e.g. "missing-security-headers"
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`  // the specific header/value/snippet that triggered it
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Remediation string    `json:"remediation"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Scan is one run of the check suite against a workspace's captured
// traffic and/or saved requests.
type Scan struct {
	ID            string    `json:"id"`
	WorkspaceID   string    `json:"workspaceId"`
	Status        string    `json:"status"` // running | completed | failed
	Source        string    `json:"source"` // "traffic" | "requests" | "both"
	FindingsCount int       `json:"findingsCount"`
	StartedAt     time.Time `json:"startedAt"`
	CompletedAt   *time.Time `json:"completedAt,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// CapturedRequest is one entry recorded by the local proxy.
type CapturedRequest struct {
	ID              string            `json:"id"`
	WorkspaceID     string            `json:"workspaceId"`
	TabID           *string           `json:"tabId,omitempty"` // set when captured via an embedded Browser tab's own proxy
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	RequestHeaders  map[string]string `json:"requestHeaders"`
	RequestBody     string            `json:"requestBody"`
	ResponseStatus  int               `json:"responseStatus"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	ResponseBody    string            `json:"responseBody"`
	DurationMs      int64             `json:"durationMs"`
	CapturedAt      time.Time         `json:"capturedAt"`
}

// BrowserTab is one embedded-browser session: its own cookie jar (via an
// isolated Electron session partition on the frontend) and its own
// short-lived capture proxy on a dedicated port, so traffic from logging
// in as "User A" in one tab never mixes with "User B" in another — each
// tab's captured requests are precisely attributable via TabID above.
type BrowserTab struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspaceId"`
	ProxyAddr   string    `json:"proxyAddr"`
	Label       string    `json:"label"`
	CreatedAt   time.Time `json:"createdAt"`
}

// TokenCandidate is one auto-detected possible credential found in a
// browser tab's captured traffic — surfaced for the user to confirm or
// edit, never saved as an Identity automatically.
type TokenCandidate struct {
	Source      string `json:"source"`      // "header" | "cookie"
	Name        string `json:"name"`        // e.g. "Authorization", "session_id"
	Value       string `json:"value"`
	SuggestedAuthType string `json:"suggestedAuthType"` // "bearer" | "cookie" | "apiKey"
	IsJWT       bool   `json:"isJwt"`
	SeenAt      time.Time `json:"seenAt"`
	FromURL     string `json:"fromUrl"`
}
